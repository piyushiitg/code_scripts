#!/usr/bin/python
#
# Copyright (C) 2013 ScaleArc, Inc., all rights reserved.
#
"""This file implements the daemon for SOCKET_CLIENT
    Now we will gathering following information:
        type                    refresh Interval
    memory_utilization                60 seconds
    disk IO counters                    60 seconds
    disk space                         300 seconds
    cpu utilization                    1 second
    bandwidth utilization              1 second
Try to get all these using psutil only.


Network:
    >>> psutil.network_io_counters()
iostat(bytes_sent=5491466873, bytes_recv=7713025564, packets_sent=46899798, packets_recv=43479259, errin=0, errout=0, dropin=0, dropout=0)
>>> psutil.network_io_counters(pernic=True)
{'lo': iostat(bytes_sent=4536464, bytes_recv=4536464, packets_sent=8051, packets_recv=8051, errin=0, errout=0, dropin=0, dropout=0), 'eth0': iostat(bytes_sent=5487308485, bytes_recv=7708987885, packets_sent=46895463, packets_recv=43474486, errin=0, errout=0, dropin=0, dropout=0)}
>>> bw_usage = psutil.network_io_counters(pernic=True)
>>> bw_usage['eth0']
iostat(bytes_sent=5487430164, bytes_recv=7709146155, packets_sent=46896201, packets_recv=43475240, errin=0, errout=0, dropin=0, dropout=0)
>>> bw_usage['eth0'][0]
5487430164
>>> bw_usage['eth0'][1]
7709146155

db: sys_stats.sqlite
tables:
    mem_usage in KB
    mem_stats for idb_analytics + idblb will be added together.

    mem_usage : {record_type: 0/1 - 0: system_level, 1: idb_main, 2: idb_analytics + idblb
                cluster_id: <cluster_id> , will be-1 for record_type = 0 or 1
                status = 1: active, 9: deleted, 0:stopped
                mem_total =
                mem_perc_used =
                mem_free =
                mem_buffered =
                mem_cached
                }
    disk_usage = { <per partition>
                    total_size =
                    used
                    free
                    perc
                    }
    disk_io = {read_count =
                write_count =
                read_bytes =
                write_bytes =
                }

"""
import getopt
import os
import sys
import traceback
import time
import ConfigParser
import sqlite3, socket
import multiprocessing
import decimal
import threading
import atexit
try:
    import psutil
except:
    pass

from signal import SIGTERM
from collections import defaultdict
#
# import modules from site-packages. iDB pacakge has to be installed before
# the following modules can be imported
#
import idb.log as log
import idb.daemon as daemon
import idb.util as util

# ###### Global variables ########
_debug = False
_config = None

SCRIPT_VERSION = "1.0"
IDB_DIR_ETC = '/opt/idb/conf/'
SOCKET_CLIENT_CONF = 'socket_client.conf'
GLOBAL_LB_DB_FILE = "/system/lb.sqlite"
LB_DB_FILE = "/system/lb_%s.sqlite"
GLOBAL_STATS_DB_FILE  = "/system/lbstats.sqlite"
STATS_DB_FILE  = "/system/lbstats_%s.sqlite"
BWMNG_BINARY = "/usr/local/bin/bwm-ng ."
TOP_BINARY = "/usr/bin/top"
NO_SAFETY_NET_FILE = "/opt/idb/.idb_utils_no_safety_net"
MAX_RETRY = 10
MEM_STATS_COLLECTOR_MARKER = '/var/run/mem_stats_collector.file'
RESET_STATS_MARKER_FILE = "/tmp/idb_reset_stats"
MAX_CHILD_PROCESS_LIMIT = 10
# #############################

# Initialize logging
log.set_logging_prefix("socket_client")
_logger = log.get_logger("socket_client")

def _usage(msg=None):
    """Display the program's usage on stderr and exit
    """
    if msg:
        print >> sys.stderr, msg
    print >> sys.stderr, """
Usage: %s [options] [stop|restart]

Options:
    -v, --version         : Report version and exit
    -d, --debug           : Run the program in debug mode
    -h, --help            : Display help
""" % (os.path.basename(sys.argv[0]))
    sys.exit(1)

def get_config_parser(config_file, options={ }):
    """Get a config parser for the given configuration file
    """
    if not os.path.isabs(config_file):
        config_file = IDB_DIR_ETC + config_file

    if not os.path.exists(config_file):
        raise Exception('File not found: %s' % config_file)

    # NOTE: Use SafeConfigParser instead of ConfigParser to support
    # escaping of format strings e.g. % as %%
    config = ConfigParser.SafeConfigParser(options)
    config.read(config_file)
    return config

class SocketClientUtils():
    '''
    Class which implements routines for socket_cliient service.
    '''
    def __init__(self):
        self._dbuserid2dbid_maps = []

    def get_sleep_val_from_config(self):
        sleep_interval = _config.getfloat("general", "sleep")
        if sleep_interval == 0.0:
            sleep_interval = 30 # default

        return sleep_interval

    def get_stats_collection_intervals(self):
        '''
        Returns a list of intervals to be used in collecting different types of
        statistics.
        '''
        stats_interval = {'mem_stats':60, 'disk_io':60, 'disk_usage':300}
        try:
            stats_interval['mem_stats'] = _config.getint("stats_collector_interval", \
                                                         "mem_stats")
            stats_interval['disk_io'] = _config.getint("stats_collector_interval", \
                                                       "disk_io")
            stats_interval['disk_interval'] = _config.getint("stats_collector_interval", \
                                                             "disk_usage")
        except Exception, ex:
            _logger.error("Problem while reading config values: %s. Using " \
                          "default" % ex)
        return stats_interval

    def _get_dbid_from_internal_cache(self, dbuserid):
        '''
        Return dbid if this dbuserid is in our list. if not then return -1.
        '''
        for entry in self._dbuserid2dbid_maps:
            if entry['dbuserid'] == dbuserid:
                return entry['dbid']
        return -1

    def _add_dbid_to_internal_cache(self, dbuserid, dbid):
        '''
        Add an entry to internal cache of maps between dbuserid and dbid.
        '''
        self._dbuserid2dbid_maps.append({'dbuserid':dbuserid, 'dbid':dbid})

    def _get_dbid(self, dbuserid, cluster_id):
        '''
        Find the corresponding dbid for the queried dbuserid. Since sqlite db
        looks are costly, we will maintain a transparent map between every
        dbuserid and dbid. If request comes for a dbuserid which is known to us
        then simply by our look up, we can send it without accessing the db.
        '''
        dbid =  self._get_dbid_from_internal_cache(dbuserid)
        if dbid != -1:
            return dbid
        NEW_LB_DB_FILE = LB_DB_FILE % cluster_id

        if os.path.exists(NEW_LB_DB_FILE) == False:
            _logger.error("%s does not exist." % NEW_LB_DB_FILE)
            return -1

        db_handle = util.get_sqlite_handle(NEW_LB_DB_FILE)
        cursor = db_handle.cursor()
        query = "select dbid from lb_dbusers where (status=1 or status=99) and dbuserid= %s" \
                % dbuserid
        dbid = -1
        try:
            cursor.execute(query)
            result = cursor.fetchone()
            dbid = int(result['dbid'])
        except Exception, ex:
            _logger.error("SocketClientChild(%d): Failed to get dbid. : %s" \
                          % (os.getpid(), ex, ))
        cursor.close()
        db_handle.close()

        if dbid != -1:
            self._add_dbid_to_internal_cache(dbuserid, dbid)

        return dbid

    def create_list(self, msg_string, stats_list, dbid_list=None):
        '''
        Create a list of dicts sorted by their cluster_ids. Something like
        stats_list = [<dict_item>,<dict_item>,...]
        dict_item = {'cluster_id':cid,cluster_stats = [<type1>,<type1>,...],
                                      cache_stats = [<type2>,<type2>,....],
                                      dbserver_stats = [<type3>,<type3>,...]
                                      }
        type1 = list of items obtained by splitting msg_string beginning with CL
        type2 = list of items obtained by splitting msg_string beginning with CA
        type3 = list of items obtained by splitting msg_string beginning with SR
        '''
        if len(msg_string) == 0:
            return

        msg_type = msg_string[0:2]
        cols = msg_string.split("|")
        cluster_id = int(cols[1].strip())

        # create a basic empty dict
        stats_dict = defaultdict(list)
        # per cluster stats
        stats_dict = {'cluster_id':cluster_id, 'cache_size':0, 'cluster_stats':[], \
                      'cache_stats':[], 'dbserver_stats':[] }

        # cache_stats[] = <db_id><cache_size><cache_hit>
        #
        # if stats_list is not empty then we navigate to find the dict which
        # have same cluster_id as the one in msg_string
        #
        temp_stats = []
        cur_stats_dict = defaultdict(list)

        for cur_stats_dict in stats_list:
            if cur_stats_dict['cluster_id'] == cluster_id:
                #
                # now matter which type of msg this is, we split it and store
                # in a temporary list.
                #
                for i in range(2, len(cols)):
                    temp_stats.append(int(cols[i]))

                # depending upon msg_type store values in lists
                if msg_type == "CL":
                    cur_stats_dict['cluster_stats'].append(temp_stats)
                elif msg_type == "CA":
                    cur_stats_dict['cache_size'] = cur_stats_dict['cache_size']\
                                         + int(cols[3])
                    #
                    # when dealing with CA messages ,values <dbid>,<cache_size>,
                    # <cache_hit> entries will be unique. When same dbid is
                    # encountered then its status cache_size and cache_hit are
                    # added with the current dbid
                    #
                    # find corresponding dbid of the cols[5] dbuserid that we have
                    #
                    dbuserid = int(cols[5])
                    # now get its corresponding dbid
                    dbid = self._get_dbid(dbuserid, cluster_id)
                    if dbid == -1:
                        # skip this entry
                        continue

                    #
                    # find if dbid is already in the list, if yes then we will
                    # add cols[3] and cols[4] to list[1] and list[2]
                    #
                    entry_found = False
                    for item in cur_stats_dict['cache_stats']:
                        if int(item[0]) == dbid:
                            item[1] = item[1] + int(cols[3])
                            item[2] = item[2] + int(cols[4])
                            entry_found = True
                            break

                    if entry_found == False:
                        # this dbid has not yet been added
                        cur_stats_dict['cache_stats'].append([dbid, int(cols[3]), \
                                                               int(cols[4])])

                elif msg_type == "SR":
                    #
                    # dbserver_stats is a list of form
                    # <dbserver_id><total_readcount><total_writecount><replicationlag>
                    # as in CA these dbserver_id will be unique and when msg_string
                    # will have same dbserver_id then item[1] and item[2] will be
                    # summed with cols[4] and cols[5]
                    #
                    dbserver_id = int(cols[2])
                    entry_found = False

                    for item in cur_stats_dict['dbserver_stats']:
                        if int(item[0]) == dbserver_id:
                            item[1] = item[1] + int(cols[3]) # total_query_count
                            item[2] = item[2] + int(cols[4]) # total_readcount
                            item[3] = item[3] + int(cols[5]) #  total_writecount
                            item[4] = item [4] + int(cols[6]) # for replication lag
                            entry_found = True
                            break

                    if entry_found == False:
                        # this dbid has not yet been added
                        cur_stats_dict['dbserver_stats'].append([dbserver_id, \
                                                                int(cols[3]),\
                                                                int(cols[4]), \
                                                                int(cols[5]), \
                                                                int(cols[6])])
                # return now
                return
        #
        # no entry for cluster_id so far -- either stats_list is empty or
        # this is new entry
        #
        if msg_type == "CL":
            for i in range(2, len(cols)):
                temp_stats.append(int(cols[i]))

            stats_dict['cluster_stats'].append(temp_stats)
        elif msg_type == "CA":
            stats_dict['cache_size'] = int(cols[3])

            dbuserid = int(cols[5])
            dbid = self._get_dbid(dbuserid, cluster_id)
            if dbid == -1:
                return

            stats_dict['cache_stats'].append([dbid, int(cols[3]), int(cols[4])])

        elif msg_type == "SR":
            stats_dict['dbserver_stats'].append([int(cols[2]), int(cols[3]), \
                                                 int(cols[4]), int(cols[5]), \
                                                 int(cols[6])])

        # now append stats_dict to stats_list
        stats_list.append(stats_dict)
        _logger.info("Socket_Client: stats_list is %s" % stats_list)

    def print_server_stats(self, server_stats):
        '''
        Print what we have got in server response
        '''
        for item in server_stats:
            _logger.info("For cluster: %d"%item["cluster_id"])
            _logger.info("\tcache_size: %d"%item['cache_size'])
            _logger.info("\tcache_stats: " )
            _logger.info("\t\t<dbid><cache_size><cache_hit>")
            for cstats in item['cache_stats']:
                _logger.info("\t\t%s"%cstats)
            _logger.info("\tcluster_stats: " )
            for clstats in item['cluster_stats']:
                _logger.info("\t\t%s"%clstats)
            _logger.info("\tdbserver_stats: " )
            _logger.info("\t\t<dbserver_id><total_readcount><total_writecount>"\
                         "<replication_lag>")
            for dbstats in item['dbserver_stats']:
                _logger.info("\t\t%s"%dbstats)

    def generate_sql_queries(self, server_stats, cpu_bw_stats):
        '''
        Generate required queries using relevant information.
        '''
        query_dict = {}
        params_list = []
        # stage1 : queries for lb_scpu
        params = (cpu_bw_stats['update_time'],str(cpu_bw_stats['conn_cpu']),\
                str(cpu_bw_stats['cache_cpu']),str(cpu_bw_stats['query_cpu']),\
                str(cpu_bw_stats['lb_cpu']),str(cpu_bw_stats['bw_in']),\
                str(cpu_bw_stats['bw_out']))
        query = "insert into lb_scpu(updatetime, conn_cpu, cache_cpu, query_cpu,"\
                 "lb_cpu, eth0_in, eth0_out) values (?,?,?,?,?,?,?)"
        query_dict['GLOBAL'] = [(query,params),]
        for cluster in server_stats:
            # stage2: queries for lb_connections
            # cluster is the dict
            cid = cluster['cluster_id']
            for item in cluster['cluster_stats']:
                params = [str(cluster['cluster_id']),cpu_bw_stats['update_time'],
                            str(item[0]),str(item[1]),str(item[2]),str(item[3]),\
                            str(item[4]),str(cluster['cache_size']),str(item[5]),\
                            str(item[6]),str(item[7]),str(item[8]),str(item[9]),\
                            str(item[10]),str(item[11]),str(item[12]),str(item[13]),
                            str(item[14]), str(item[15]), str(item[16]) if len(item) > 16 else 0, 
                            str(item[17]) if len(item) > 17 else 0, str(item[18]),]
                params_list.append(params)
                query = "insert into lb_cconnections (clusterid, updatetime," \
                        "client, server, queue, read, write, cachesize,cachehit,"\
                        "block, pclient, queryerror, connerror,passthrough,"\
                        "passthrough_conn, readqueue, writequeue,"\
                        "readintentqueue, alldbqueue, invalidation_cachesize," \
                        "invalidation_counter, readonly)" \
                        "values (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)"
                if cid in query_dict:
                    query_dict[cid].append((query, params))
                else:
                    query_dict[cid] = [(query, params)]
#               _logger.info(query)

            #stage 3: quqries for lb_dbstats
            for item in cluster['cache_stats']:
                params = [str(cluster['cluster_id']),str(item[0]),\
                         cpu_bw_stats['update_time'],str(item[1]),str(item[2])]
                         
                query = "insert into lb_dbstats (clusterid,"\
                        " dbid, updatetime, cachesize, cachehit) values (?,?,?,?,?)"
                if cid in query_dict:
                    query_dict[cid].append((query, params))
                else:
                    query_dict[cid] = [(query,params),]

            # stage3: queries for db_srvstats
            for item in cluster['dbserver_stats']:
                params = [str(cluster['cluster_id']),str(item[0]), 
                         cpu_bw_stats['update_time'], str(item[1]),str(item[2]),
                         str(item[3]),str(item[4])]
                query = "insert into lb_srvstats (clusterid, serverid, updatetime,"\
                        " querycnt,read, write,replicationlag) values (?,?,?,?,?,?,?)" 

                if cid in query_dict:
                    query_dict[cid].append((query, params))
                else:
                    query_dict[cid] = [(query, params)]

        sum_list = SocketClientUtils.find_cumulative_results(params_list)
        query = "insert into lb_cconnections (updatetime, "\
                        "client, server, queue, read, write, cachesize,cachehit,"\
                        "block, pclient, queryerror, connerror,passthrough,"\
                        "passthrough_conn, readqueue, writequeue,"\
                        "readintentqueue, alldbqueue, invalidation_cachesize, "\
                        "invalidation_counter, readonly) "\
                        "values (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)"
        query_dict['GLOBAL'].append((query, sum_list))
        return query_dict

    @classmethod
    def find_cumulative_results(cls, params_list):
        import operator, copy
        _logger.info("Socket_Client: Finding Cumulative results for params list is %s" % params_list)
        copy_list = copy.deepcopy(params_list)
        sum_list = None
        for params in copy_list:
            cluster_id = params.pop(0)
            update_time = params.pop(0)
            if sum_list is None:
                sum_list = params
            else:
                sum_list = map(operator.add, sum_list, params)
        
        sum_list.insert(0, update_time)
        _logger.info("Socket_Client: Cumulative sum list is %s" % sum_list)
        return sum_list
    
    def execute_queries(self, query_list, clusterid=None):
        '''
        Execute a list of queries. Retry only if there are exceptions other than
        integrity errors.
        '''
        if len(query_list) == 0:
            _logger.warn("SocketClientChild(%d): Query list is empty." % (os.getpid()))
            return
        if clusterid:
            NEW_DB_STATS_FILE = STATS_DB_FILE % clusterid
        else:
            NEW_DB_STATS_FILE = GLOBAL_STATS_DB_FILE
        dbhandle = util.get_sqlite_handle(NEW_DB_STATS_FILE)
        db_cursor = dbhandle.cursor()

        retry = 0
        trans_active = False
        while retry < MAX_RETRY:
            try:
                if trans_active == False:
                    db_cursor.execute("BEGIN TRANSACTION")
                    for item  in query_list:
                        db_cursor.execute(item[0], item[1])
                    trans_active = True

                dbhandle.commit()
                break
            except (Exception, sqlite3.Error) as e:
                # we will retry only if we have database locked issue
                # else we quit
                if str(e).find('database is locked') == -1:
                    _logger.error("SocketClientChild(%d): Failed to save " \
                                  "stats: %s" % (os.getpid(), e))
                    break

                retry = retry + 1
                if retry >= MAX_RETRY:
                    _logger.error("SocketClientChild(%d): Failed to save "\
                                        "stats %s. Database is locked. Max retry" \
                                        " limit reached:" % (os.getpid(), NEW_DB_STATS_FILE))
                else:
                    time.sleep(0.1)
        util.close_sqlite_resources(dbhandle,db_cursor)


def cpu_bw_collector(update_time):

    '''
    Work area where a newly spwaned process will start its processing.
    '''
    try:
        sc_utils = SocketClientUtils()
        sleep_interval = sc_utils.get_sleep_val_from_config()

        cpu_bw_stats = {'conn_cpu':0.0, 'cache_cpu':0.0, 'query_cpu':0.0, \
                            'lb_cpu':0.0, 'bw_in':0.0, 'bw_out':0.0, \
                            'update_time':''}
        cpu_bw_stats['update_time'] = update_time

#             prereq_except = prerequisite_checks()
        prereq_except = True
        if prereq_except != True:
            _logger.error("SocketClientChild(%d): Prerequisite checks "\
                              "failed: %s" % (os.getpid(), prereq_except))
            sys.exit(1)
        else:
            cmd = "show_stat_status"
#             t1 = time.time()
            server_response = util.socket_cmd_runner(unix_sock="/tmp/lb_sock",  \
                                                     command=cmd)

            _logger.info("SocketClientChild(%d): show_stat_status output is "\
                                  " %s." % (os.getpid(), server_response))
            
            if (server_response[:5] == "ERROR"):
                time.sleep(sleep_interval)
                _logger.error("SocketClientChild(%d): Invalid server "\
                                  "response: %s" % (os.getpid(), \
                                                    server_response))
                sys.exit(1)

            if server_response == "":
                _logger.error("SocketClientChild(%d): Server returned "\
                                  "empty response." % (os.getpid()))
                sys.exit(1)
                    #
                    # server might return a status code instead of stats. In this case
                    # msg will have 'STATUS' as initial substring
                    # we will not go up but we will write empty values. idea is
                    # atleast bandwidth info should get collected.
                    #
            invalid_response = False
            if (server_response[:6]) == "STATUS":
                _logger.warn("SocketClientChild(%d): %s." % (os.getpid(), \
                                                                server_response))
                sys.exit(1)

#                 dbid_list = []
#                 dbid_list = sc_utils.get_dbids_list()

                # run bwm-ng and capture its output
            bw_arr = []
            cmd = BWMNG_BINARY + " -o csv -c 1 -t2000"
            _logger.debug("SocketClientChild(%d): Gathering bandwidth data" % os.getpid())
            if (util.cmd_runner(cmd, bw_arr)!= -9999):
                        # expected output in form
                bandwidthin = 0.0
                bandwidthout = 0.0

                for row in bw_arr:
                    row = row.strip()
                    cols = row.split(";")
                    if cols[1][0:4] == "bond":
                        bandwidthin  = bandwidthin  - float(cols[3])*8
                        bandwidthout = bandwidthout - float(cols[2])*8
                    if cols[1] == "total":
                        bandwidthin  = bandwidthin  + float(cols[3])*8
                        bandwidthout = bandwidthout + float(cols[2])*8

                cpu_bw_stats['bw_in'] = float(bandwidthin)
                cpu_bw_stats['bw_out'] = float(bandwidthout)

            else:
                _logger.error("SocketClientChild: Failed to run command %s\
                                    " % cmd)
                sys.exit(1)

            # deal with server's response
            lines = server_response.split()
                    #
                    # server response has 4 types of info.
                    # 1. <LB>: related to pids of core idb processes, per cluster
                    # 2. <CL>: get cluster related stats, per clusetr
                    # 3. <CA>: info about cache rules set, per cluster
                    # 4. <SR>: db_servers (mysql,oracle etc), per cluster
                    # see lb_protocol.c for data format returned by server
                    #
            server_stats = []
            query_list = [] # list of queries which will be executed
                # ########## data-parsing phase ###################
            if invalid_response == False:
                for line in lines:
                    cols = line.split("|")
                    if line[0:2] == "LB":
                                #
                                # if line starts with LB
                                # line : LB|6|4723|4692|4812|4697
                                # interpret it as : LB|<cluster_id>|<connection_manager_cpu_usage>|
                                # <cache_manager_cpu_usage>|<query_manager_cpu_usage>|
                                # <overall_load_balancer_cpu_usage>
                                #

                        cmd = TOP_BINARY + " -H -b -n1 "

                        top_output = []
                        # should not we run this before we enter the loop
                        util.cmd_runner(cmd, top_output)

                            # skip the first header line from the output
                        start = False
                        for top_line in top_output:
                            top_line = top_line.strip()
                            if top_line[0:3] == "PID":
                                start = True
                            elif start == True:
                                if len(top_line) > 0:
                                    top_cols = top_line.split()

                                    if int(top_cols[0]) == int(cols[2]):
                                        cpu_bw_stats['conn_cpu'] = cpu_bw_stats['conn_cpu'] \
                                                        + float(top_cols[8])
                                    elif int(top_cols[0]) == int(cols[3]):
                                        cpu_bw_stats['cache_cpu'] = cpu_bw_stats['cache_cpu'] \
                                                        + float(top_cols[8])
                                    elif int(top_cols[0]) == int(cols[4]):
                                        cpu_bw_stats['query_cpu'] = cpu_bw_stats['query_cpu'] \
                                                        + float(top_cols[8])
                                    elif int(top_cols[0]) == int(cols[5]):
                                        cpu_bw_stats['lb_cpu'] = cpu_bw_stats['lb_cpu'] \
                                                        + float(top_cols[8])

                    elif line[0:2] == "CL":
                        sc_utils.create_list(line, server_stats)
                    elif line[0:2] == "CA":
                        sc_utils.create_list(line, server_stats)
                    elif line[0:2] == "SR":
                        sc_utils.create_list(line, server_stats)

            else:
                _logger.warn("Could not find cpu usage. Using empty values.")

            _logger.debug("SocketClientChild(%d): Collected cpu usage: "\
                              "conn %f cache %f query %f lb %f bw_in: [%f] "\
                              "bw_out: [%f]"%(os.getpid(), cpu_bw_stats['conn_cpu'], \
                                              cpu_bw_stats['cache_cpu'], \
                                              cpu_bw_stats['query_cpu'], \
                                              cpu_bw_stats['lb_cpu'], \
                                              cpu_bw_stats['bw_in'], \
                                              cpu_bw_stats['bw_out']))
            _logger.info("Socket_CLient: server_stats is %s and cpu_bw_stats is %s" %(server_stats, cpu_bw_stats))
            query_dict = sc_utils.generate_sql_queries(server_stats, \
                                                       cpu_bw_stats)
            _logger.info("Socket_Client: Query dict genrated that is %s" % query_dict)
            t2 = time.time()
            for cid, query_list in query_dict.iteritems():
                if cid == 'GLOBAL':
                    sc_utils.execute_queries(query_list)
                else:
                    sc_utils.execute_queries(query_list, cid)
                    
                # send this query on the message_q that we got and exit

            _logger.debug("SocketClientChild(%d): Query execution took %f "\
                              "seconds" % (os.getpid(), time.time()-t2))
#                 execution_time_for_this_instance = time.time()- t1
#                 _logger.debug("SocketClientChild(%d): Took: %f seconds to "\
#                               "complete." % (os.getpid(), \
#                                            execution_time_for_this_instance))

                # successful exit
            sys.exit(0)
    except Exception, ex:
        _logger.error("SocketClient(%d): Child instance exited abnormally, "\
                          "Error: %s" % (os.getpid(), ex))
        _logger.error("%s" % (traceback.format_exc(), ))


class MemStatsCollectorUtils():
    '''
    Implements functionality of mem_stats collector process.
    '''
    def __init(self, stats_interval, parent_pid):
        self._stats_interval = stats_interval
        self._parent_pid = parent_pid
        self._active_cluster_ids = []

    def _is_parent_alive(self, ):
        '''
        Returns True/false
        '''
        if os.path.exists("/var/run/socket_client.pid") == False :
            return False

        pid_file = "/proc/" + str(self._parent_pid)
        if os.path.exists(pid_file):
            return True
        return False


    def _collect_mem_stats(self):
        '''
        Routine to collect memory statistics. Both system level as well per idb
        processes including (idblb, idb_main and idb_analytics)

        Find pids of idblb and idb_analytics belonging to a given cluster.
        ps aux | grep 'idb_analytics 6\|idblb_6' | grep -v grep

        We also need to take care of clusters which have been deleted. We will
        execute all queries in one transaction.
        '''
        # 1. Calculate system level stats

        # 2. get memory consumption of idb_main

        # 3. Form query to remove rows belonging to deleted clusters

        # 4. Calculate per clusters stats for active clusters ie.e status=1

        # Fid
        pass


    def _collect_disk_io_counters(self):
        '''
        Collect disk io counters.
        '''
    def _collect_disk_usage(self):
        '''
        Collect disk usage per partition.
        '''

    def collect_stats(self):
        '''
        Go in a forever loop to collect stats. return when parent is gone away.

        Note that our notion of timer is not accurate here.  We assume for now,
        that even if all three routines get called they happen in unit time
        (which is not true).

        FIXME: Provide a correct way to access timer. We need timer because
        mem_stats, disk_io and disk_usage all might need to be calculated at
        completely different intervals.
        '''
        timer = 0
        while True:
            if not self._is_parent_alive():
                return

            if timer % self._stats_interval['mem_stats'] == 0:
                self._collect_mem_stats()
            if timer % self._stats_interval['disk_io'] == 0:
                self._collect_disk_io_counters()
            if timer % self._stats_interval['disk_usage'] == 0:
                self._collect_disk_usage()

            time.sleep(1)
            timer = timer + 1

def mem_stats_collector_cleanup():
    '''
    Cleanup routine for memory stats collector process. It will be called when
    this process exits/crashes.
    '''
    if os.path.exists(MEM_STATS_COLLECTOR_MARKER):
        try:
            os.unlink(MEM_STATS_COLLECTOR_MARKER)
        except Exception, ex:
            _logger.error('MemStatsCollector: Failed to remove marker file: %s' \
                          % MEM_STATS_COLLECTOR_MARKER)

def mem_stats_collector(stats_interval, parent_pid):
    '''
    Target routine of process which collects memory usage (per idb processes as
    well as for whole system), disk usage and disk IO counters.
    '''
    atexit.register(mem_stats_collector_cleanup)
    msc_utils = MemStatsCollectorUtils(stats_interval, parent_pid)
    msc_utils.collect_stats()

    # if we are here then parent is gone away so we quit.
    sys.exit(0)


class SocketClientDaemon(daemon.Daemon):
    """This class runs SOCKET_CLIENT as a daemon
    """
    def run(self):

        _logger.info("SocketClientParent(%d) started.." % (os.getpid()))
        #
        # Fix  for IDB-5393
        #
        while not os.path.exists('/system/lb.sqlite'):
            _logger.warn("LogsBackup(%d): '/system/lb.sqlite' "\
                            "does not exist " % (os.getpid(),))
            time.sleep(1)
        #sc_utils = SocketClientUtils()
#         self._stats_interval = sc_utils.get_stats_collection_intervals()
        while True:
            if os.path.exists(RESET_STATS_MARKER_FILE):
                _logger.info("SocketClient: Going to reset stats")
                self._reset_stats()
            
            # Fix for IDB-6690
            # cleanup any finished children
            plist = []
            plist = multiprocessing.active_children()
            if len(plist) > 10:
                time.sleep(1)
                continue
            
            update_time = time.strftime("%Y-%m-%d %H:%M:%S")
            p = multiprocessing.Process(target = cpu_bw_collector, args = (update_time, ))
            try:
                p.start()
            except Exception, ex:
                _logger.error("SOCKET_CLIENT: Parent run failed: %s" % ex)
                _logger.error("%s" % (traceback.format_exc(), ))
                #
                # after spwaninng a new process sleep a while to prevent
                # proceses from competing with each other
                #
            time.sleep(1)

    def get_cluster_ids(self):
        cluster_ids = []
        sqlite_handle = util.get_sqlite_handle(GLOBAL_LB_DB_FILE)
        db_cursor = sqlite_handle.cursor()
        query = "select cluster_id,status from lb_clusters_summary"
        retry = 0
        while retry < MAX_RETRY:
            try:
                db_cursor.execute(query)
                for row in db_cursor.fetchall():
                    cluster_ids.append(int(row['cluster_id']), int(row['status']))
                break
            except Exception, ex:
                retry = retry + 1
                if retry >= MAX_RETRY:
                    _logger.error("UserCredsMonitor: Failed to find list of " \
                                  "running clusters: %s" % ex)
                else:
                    time.sleep(0.1)

        sqlite_handle.close()
        return cluster_ids
    
    def _vacuum_lbstats(self, db_file_path):
        '''
        Run sqlite vacuum command on lbstats after this cycle has been
        completed.
        '''
        dbhandle = sqlite3.connect(db_file_path, timeout = 0.1)
        db_cursor = dbhandle.cursor()

        retry = 0
        trans_active = False
        while retry < MAX_RETRY:
            try:
                if trans_active == False:
                    db_cursor.execute("vacuum;")
                    trans_active = True

                dbhandle.commit()
                break
            except (Exception, sqlite3.Error) as e:
                # we will retry only if we have database locked issue
                # else we quit
                if str(e).find('database is locked') == -1:
                    _logger.error("Failed to run vacuum " \
                                  "command: %s" % (e, ))
                    break

                retry = retry + 1
                if retry >= MAX_RETRY:
                    _logger.error("Failed to run vacuum command:")
                else:
                    time.sleep(0.1)

        db_cursor.close()
        dbhandle.close()

    def _truncate_tables(self, query_list, db_file_path):
        '''
        Truncate all tables in lbstats.sqlite
        '''
        dbhandle = sqlite3.connect(db_file_path, timeout = 0.1)
        db_cursor = dbhandle.cursor()

        retry = 0
        trans_active = False
        while retry < MAX_RETRY:
            try:
                if not trans_active:
                    db_cursor.execute("BEGIN TRANSACTION")
                    for item in query_list:
                        db_cursor.execute(item)
                    trans_active = True

                dbhandle.commit()
                break
            except (Exception, sqlite3.Error) as e:
                # we will retry only if we have database locked issue
                # else we quit
                if str(e).find('database is locked') == -1:
                    _logger.error("SocketClient(%d): Failed to erase " \
                                  "tables: %s" % (os.getpid(), e))
                    break

                retry = retry + 1
                if retry >= MAX_RETRY:
                    _logger.error("SocketClient(%d): Failed to erase "\
                                    "tables. Max retry" \
                                    " limit reached:" % (os.getpid()))
                else:
                    time.sleep(0.1)

        db_cursor.close()
        dbhandle.close()

        # before quitting run vacuum command on sqlite to compact the db
        self._vacuum_lbstats(db_file_path)

    def _reset_stats(self):
        '''
        If stats_reset file is present, we need to reset the stats from all tables
        however, note that to be more consistent we will wait for all child
        processes to finish before we start to truncate all tables.
        After we are done truncating all tables, we will remove this marker
        file.
        '''
        # wait in a loop untill all children are finished
        _logger.info("SocketClient: Killing active children")
#         while len(multiprocessing.active_children()):
#             time.sleep(1)
        plist = []
        plist = multiprocessing.active_children()

        if len(plist) > 0:
            for p in plist:
                try:
                    p.terminate()
                except Exception, ex:
                    _logger.info("SocketClient: Problem terminating child " \
                                 "process: %s" % ex)

        cluster_ids = self.get_cluster_ids() 
        _logger.info("SocketClient: Truncating tables")
        for clusterid in cluster_ids:
            query_list = []
            query_list.append('delete from lb_cconnections')
            query_list.append('delete from lb_dbstats')
            query_list.append('delete from lb_srvstats')
            db_file_path = STATS_DB_FILE % str(clusterid)
            self._truncate_tables(query_list, db_file_path)
        query_list = []
        query_list.append('delete from lb_cconnections')
        query_list.append('delete from lb_scpu')
        self._truncate_tables(query_list, GLOBAL_STATS_DB_FILE)
        _logger.info("SocketClient: Cleanup marker file")
        try:
            os.unlink(RESET_STATS_MARKER_FILE)
        except:
            pass
        _logger.info("SocketClient: Reset stats complete")

def main():
    # Go away if you are not root
    if not os.geteuid()==0:
        sys.exit("socket_client: You must be root to run this script\n")

    # Parse the command line options
    try:
        opts, args = getopt.getopt(sys.argv[1:],
                            'hdv',
                            ["help", "debug", "version"])
    except:
        _usage("error parsing options")
    for opt in opts:
        if opt[0] == '-v' or opt[0] == '--version':
            print "%s: version %s" % (os.path.basename(sys.argv[0]), \
                                      SCRIPT_VERSION)
            sys.exit(0)
        elif opt[0] == '-h' or opt[0] == '--help':
            _usage()
        elif opt[0] == '-d' or opt[0] == '--debug':
            global _debug
            _debug = True

    if len(args) > 2:
        _usage('Invalid args %s' % args)

    # Initialize the logger
    log.config_logging()

    # Read the config file
    global _config
    _config = get_config_parser(SOCKET_CLIENT_CONF)

    socket_client_daemon = SocketClientDaemon('/var/run/socket_client.pid')
    if args:
        if 'stop' == args[0]:
            _logger.info("****************** SOCKET_CLIENT stopping ********************")
            socket_client_daemon.stop()
        elif 'restart' == args[0]:
            _logger.info("***************** SOCKET_CLIENT restarting *******************")
            socket_client_daemon.restart()
        else:
            err_msg = "Invalid command %s" % (repr(args[0]),)
            print >> sys.stderr, err_msg
            _logger.error("%s" % (err_msg,))
            sys.exit(2)
        sys.exit(0)

    if _debug:
        _logger.info("************ SOCKET_CLIENT starting (debug mode)**************")
        socket_client_daemon.foreground()
    else:
        _logger.info("****************** SOCKET_CLIENT starting ********************")
        socket_client_daemon.start()

if __name__ == "__main__":
    main()
