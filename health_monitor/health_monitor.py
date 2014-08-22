import gevent.monkey
gevent.monkey.patch_all()
from copy import deepcopy
import os
import sys
import getopt
import sqlite3
import socket
import gevent
import time
import idb.util as util
from idb import log, daemon
from gevent.pool import Group
from datetime import datetime
from factory import DatabaseFactory
from config import database_configuration

############# Constant File Name ##########
GLOBAL_LB_DB_FILE = "/system/lb.sqlite"
LOCAL_SQLITE_FILE = "/system/lb_%s.sqlite"
###########################################

########## Code COnstants Value ###########
PLATFORM_TYPES = ('ORACLE', )
MAX_RETRY = 3
SLEEP_INTERVAL = 5
SCRIPT_VERSION = 1.0
##########################################

########## Service Constants #############
_debug = False
log.set_logging_prefix("health_monitor")
_logger = log.get_logger("health_monitor")
##########################################
 
class GroupOfGreenlet(Group):
    def __init__(self, *args):
        super(GroupOfGreenlet, self).__init__(*args)
        self.greenlet_and_checkin_time = []
        self.all_groups = []
        self.health_status = 'Healthy' # TimeOut, Not Healthy, Partial Healthy, Error, Retry

    def spawn(self, func, *args, **kwargs):
        parent = super(GroupOfGreenlet, self)
        p = parent.spawn(func, *args, **kwargs)
        t = datetime.now()
        self.greenlet_and_checkin_time.append((p, t))
        return p

class ClusterInfo(object):
    def __init__(self, data):
        self.cluster_id = data['cluster_id']
        self.db_file_name = data['db_file_name'] 
        self.servers_list = data['servers_list']
        self.cluster_type = data['cluster_type']
        self.db_obj = data['db_obj']
        self.servers_health = data['servers_health']
        self.servers_old_health = data['servers_old_health']
        self._is_stop = data['is_stop']
        self.parent_greenlet = None
        self.group_gevent = None
        
class HealthMonitor(daemon.Daemon):
    ''' HealthMonitor Class
    '''
    def __init__(self, pidfile):
        self._all_serverids = [] 
        self.all_clusters_info = []
        super(HealthMonitor, self).__init__(pidfile)

    def get_cluster_object(self, cluster_id):
        ''' Get cluster object
        '''
        _logger.info("HealthMonitor: getting cluster info object %s clusterid"\
                      %(cluster_id))
        cluster_obj = None
        for ci in self.all_clusters_info:
            if ci.cluster_id == cluster_id:
                cluster_obj = ci
        _logger.info("HealthMonitor: got cluster info object %s for clusterid %s"\
                      %(cluster_obj, cluster_id))
        return cluster_obj

    def check_cluster_greenlet_running(self, cluster_id):
        ''' Get cluster object
        '''
        is_running = False
        running_cluster_obj = None
        _logger.info("HealthMonitor: checking greenlet is running for %s clusterid"\
                      %(cluster_id))
        for ci in self.all_clusters_info:
            if ci.cluster_id == cluster_id:
                is_running = True
                running_cluster_obj = ci
                break
        _logger.info("HealthMonitor: cluster id %s greenlet running %s and obj is %s"\
                      %(cluster_id, is_running, running_cluster_obj))
        return is_running, running_cluster_obj

    def read_all_clusterids(self):
        '''
        Read a list of all server_ids with the status field.
        '''
        _logger.info("HealthMonitor: Reading all cluster ids")
        cluster_ids = []
        sqlite_handle = util.get_sqlite_handle(GLOBAL_LB_DB_FILE)
        if sqlite_handle:
            db_cursor = sqlite_handle.cursor()
            query = "select cluster_id, status, type from lb_clusters_summary where \
                     status <> 9 and status <> 5 and type in %s " % str(PLATFORM_TYPES)
            _logger.info("HealthMonitor: executing query  %s for all cluster ids"\
                         %(query))
            retry = 0
            while retry < MAX_RETRY:
                try:
                    db_cursor.execute(query)
                    for row in db_cursor.fetchall():
                        d = {}
                        d['clusterid'] = int(row['cluster_id'])
                        d['status'] = int(row['status'])
                        d['type'] = row['type']
                        cluster_ids.append(d.copy())
                    break
                except Exception, ex:
                    retry = retry + 1
                    if retry >= MAX_RETRY:
                        _logger.error("Failed to find list of all clusters: %s" % ex)
                    else:
                        time.sleep(0.1)

            _logger.info("HealthMonitor: all cluster ids %s" %(cluster_ids))
            util.close_sqlite_resources(sqlite_handle, db_cursor)
        return cluster_ids

    def execute_capability(self, inputdata, cluster_id, name):
        ''' Execute capability like socket monitoring or 
            query monitoring
        '''
        _logger.info("HealthMonitor(%s): Running child gevent name %s" %(cluster_id, name))
        db_obj = inputdata['db_obj']
        func_cap = db_obj.function
        result = []
        for func in func_cap:
            _logger.info("HealthMonitor(%s): name %s executing function %s"\
                          %(cluster_id, name, func))
            response = getattr(db_obj, "%s_monitor"%func)(inputdata)
            _logger.info("HealthMonitor(%s): name %s function %s and response %s"\
                          %(cluster_id, name, func, response))
            result.append((func, response))
            time.sleep(.1)
        return result
    
    def find_stopped_cluster_ids(self):
        '''
        Return a list of cluster ids for clusters which have been stopped.
        '''
        cluster_ids = []
        _logger.info("HealthMonitor: Reading all stopped cluster ids from all clusterids %s"\
                      %(self._all_serverids))
        
        for item in self._all_serverids:
            if item['status'] == 0 :
                cluster_ids.append(item['clusterid'])
        _logger.info("HealthMonitor: all stopped cluster ids are %s"\
                      %(cluster_ids))
        return cluster_ids

    def find_running_cluster_ids(self):
        '''
        Returns the list of clusters that are running
        '''
        cluster_type_ids = {}
        _logger.info("HealthMonitor: Reading all running cluster ids and type from all clusterids %s"\
                      %(self._all_serverids))
        for item in self._all_serverids:
            if item['status'] == 1:
                cluster_type_ids[item['clusterid']] = item['type']
        _logger.info("HealthMonitor: all running cluster ids and their types are %s"\
                      %(cluster_type_ids))
        return cluster_type_ids


    def check_servers_health(self, cluster_id):
        ''' Check health of all the servers
        '''
        #gg = GroupOfGreenlet()
        while True:
            try:
                _logger.info("HealthMonitor(%s): Running Parent gevent" % cluster_id)
                cluster_info = self.get_cluster_object(cluster_id)
                if cluster_info._is_stop == True:
                    _logger.info("HealthMonitor(%s): cluster is stopped now %s"%(cluster_id))
                    break
                servers_list = cluster_info.servers_list
                old_health = cluster_info.servers_old_health
                db_obj = cluster_info.db_obj
                gg = cluster_info.group_gevent
                greenlets_dict = {}
                i = 0
                for server_ip, server_port, serverid in servers_list:
                    _logger.info("HealthMonitor(%s): Starting gevent for server info %s %s"\
                                 % (cluster_id, server_ip, server_port))
                    i = i + 1
                    inputdata = {'server_ip':server_ip, 'server_port': int(server_port), 
                                 'db_obj': db_obj}
                    gevent_name = "gevent%s" % str(i)
                    g1 = gg.spawn(self.execute_capability, inputdata, cluster_id, gevent_name) 
                    _logger.info("HealthMonitor(%s): spawning gevent name %s for serverip %s and port %s"\
                                 %(cluster_id, gevent_name, server_ip, server_port))
                    greenlets_dict[server_ip] = g1
                # Timeout change to number of servers and previous results of health store
                gg.join(timeout=10)
                temp_dict = {}
                for ip, g in greenlets_dict.iteritems():
                    temp_dict[ip] = g.value 
                _logger.info("HealthMonitor(%s): cluster specific servers health %s"%(cluster_id, temp_dict))
                cluster_info.servers_health = temp_dict
                
                _logger.info("HealthMonitor(%s):oldserver health %s new server health %s"
                             %(cluster_id, cluster_info.servers_old_health, cluster_info.servers_health))

                if not cluster_info.servers_old_health:
                    _logger.info("HealthMonitor(%s): first time reached "%(cluster_id))
                    cluster_info.servers_old_health = deepcopy(cluster_info.servers_health)
                    inform_core = True
                else:
                    _logger.info("HealthMonitor(%s): check old health and new health "%(cluster_id))
                    inform_core = False if cluster_info.servers_old_health == cluster_info.servers_health else True
                    
                _logger.info("HealthMonitor(%s): inform to core is %s "%(cluster_id, inform_core))
                if inform_core:
                    _logger.info("HealthMonitor(%s): informing to core "%(cluster_id))
                    is_success = self._inform_core_about_health_change(cluster_id, cluster_info.servers_old_health, \
                                 cluster_info.servers_health, cluster_info.servers_list)
                    _logger.info("HealthMonitor(%s): core about health %s"%(cluster_id, is_success))
                    if is_success:
                        cluster_info.servers_old_health = deepcopy(cluster_info.servers_health)
                else:
                    _logger.info("HealthMonitor(%s): Doning Nothing no change in Health "%(cluster_id))
                    
                time.sleep(1)
            except Exception, ex:
                _logger.error("HealthMonitor(%s): Exception in check servers Health %s" %ex)

    def _inform_core_about_health_change(self, cluster_id, old_health, new_health, servers_list):
        '''
        database_health|<clusterid>|<database id>|<health>
        '''
        response = ''
        is_success = True
        header = "database_health|%d|%d|%d"
        _msg_for_core = ''
        _logger.info("HealthMonitor(%s):Inside INFORMCORE "%(cluster_id))
        for ip, port, serverid in servers_list:
            _logger.info("HealthMonitor(%s): INFORMCORE checking for %s %s %s"%(cluster_id, ip, port, serverid))
            if old_health[ip] != new_health[ip]:
                _logger.info("HealthMonitor(%s): INFORMCORE Health change %s %s %s"\
                            %(cluster_id, old_health[ip], new_health[ip], ip))

                new_result = new_health[ip][1]
                _msg_for_core = header % (cluster_id, serverid, int(new_result))
                _logger.info("HealthMonitor(%s): INFORMCORE msg for core is %s"\
                            %(cluster_id, _msg_for_core))
                response = util.socket_cmd_runner(unix_sock="/tmp/lb_sock_%s"%cluster_id,
                                            command=_msg_for_core)
                _logger.info("HealthMonitor(%s): INFORMCORE response form core is %s"\
                            %(cluster_id, response))

                if response != "SUCCESS":
                    _logger.error("Failed to inform core : %s" % (response))
                    is_success = False
        return is_success

    def read_db_specific_config(self, cluster_id, cluster_type):
        ''' Read cluster specific config from config file
        '''
        db_config = database_configuration[cluster_type] 
        db_obj = DatabaseFactory(db_config)
        db_file_name = LOCAL_SQLITE_FILE % cluster_id
        servers_list = db_obj.get_servers_from_sqlite(db_file_name, cluster_id)
        clusterwise_info = { 
                             'cluster_id' : cluster_id,
                             'cluster_type' : cluster_type,
                             'db_file_name' : db_file_name,
                             'servers_list' : servers_list,
                             'db_obj' : db_obj,
                             'servers_health' : {},
                             'servers_old_health' : {},
                             'is_stop': False,
                           } 
        ci = ClusterInfo(clusterwise_info)
        return ci
        
    def spawn_monitor_children(self):
        ''' This will start greenlets to monitor
            child process
        '''
        stopped_clusters = []
        cluster_type_ids = {}
        self._all_serverids = self.read_all_clusterids()
        _logger.info("HealthMonitor: All cluster ids and type is %s" %self._all_serverids)
        stopped_clusters_type_ids = self.find_stopped_cluster_ids()
        running_cluster_type_ids = self.find_running_cluster_ids()
        _logger.info("HealthMonitor: Running Cluster id's are %s \
                      and Stopped Cluster id's are %s" \
                     %(running_cluster_type_ids, stopped_clusters_type_ids))

        for cluster_id in stopped_clusters_type_ids:
            _logger.info("HealthMonitor: Checking Stopped cluster greenlet %s" %(cluster_id))
            cluster_running, c_obj = self.check_cluster_greenlet_running(cluster_id)
            # FIXME if no stopped c_obj
            if cluster_running and c_obj:
                _logger.info("HealthMonitor(%s): STOPPING Cluster greenlet is running %s and object is %s \
                         " % (cluster_id, cluster_running, c_obj))
                self.all_clusters_info.remove(c_obj)
                c_obj._is_stop = True
            
        for cluster_id, cluster_type in running_cluster_type_ids.iteritems():
            if self.check_cluster_greenlet_running(cluster_id)[0]:
                _logger.info("HealthMonitor(%s): Cluster Greenlet already running SKIP this id" %(cluster_id))
                continue
            
            _logger.info("HealthMonitor(%s): cluster type is %s" %(cluster_id, str(cluster_type)))
            cluster_obj = self.read_db_specific_config(cluster_id, cluster_type)

            # convert all_Cluster info into dict
            self.all_clusters_info.append(cluster_obj)
            _logger.info("HealthMonitor(%s): starting gevent for cluster id"%cluster_id)                                      
            parent_greenlet = gevent.spawn(self.check_servers_health, cluster_id)
            cluster_obj.parent_greenlet = parent_greenlet
            cluster_obj.group_gevent = GroupOfGreenlet()
            parent_greenlet.start()
        #time.sleep(SLEEP_INTERVAL)

    def run(self):
        ''' Start health monitor daemon
        '''
        while True:
            try:
                _logger.info("HealtorMonitor: Spawning Monitor Children")
                self.spawn_monitor_children()
            except Exception, ex:
                import traceback
                _logger.error("HealthMonitorParent: run failed: %s" % ex)
                _logger.error("HealthMonitorParent ex: %s" % (traceback.format_exc(),))
            finally:
                _logger.debug("HealthMonitorParent: Sleeping for %f seconds" \
                              % (SLEEP_INTERVAL))
                time.sleep(SLEEP_INTERVAL)

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


def main():
    # Go away if you are not root
    if not os.geteuid()==0:
        sys.exit("Health-Monitor: You must be root to run this script\n")

    # Parse the command line options
    try:
        opts, args = getopt.getopt(sys.argv[1:],
                            'hdv',
                            ["help", "debug", "version"])
    except:
        _usage("error parsing options")
    for opt in opts:
        if opt[0] == '-v' or opt[0] == '--version':
            print "%s: version %s" % (os.path.basename(sys.argv[0]), SCRIPT_VERSION)
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
    hm_daemon = HealthMonitor('/var/run/health_monitor.pid')
    if args:
        if 'stop' == args[0]:
            _logger.info("****************** Health Monitor stopping ********************")
            hm_daemon.stop()
        elif 'restart' == args[0]:
            _logger.info("***************** Health Monitor restarting *******************")
            hm_daemon.restart()
        else:
            err_msg = "Invalid command %s" % (repr(args[0]),)
            print >> sys.stderr, err_msg
            _logger.error("%s" % (err_msg,))
            sys.exit(2)
        sys.exit(0)

    if _debug:
        _logger.info("************ Health Monitor starting (debug mode)**************")
        hm_daemon.foreground()
    else:
        _logger.info("****************** Health Monitor starting ********************")
        hm_daemon.start()

                                                    
if __name__ == '__main__':
    main()
