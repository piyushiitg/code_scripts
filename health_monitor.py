import gevent.monkey
gevent.monkey.patch_all()
from copy import deepcopy
import os
import sys
import signal
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
from idb.cmd.alert_engine.publisher import publisher
import traceback
import time
############# Constant File Name ##########
GLOBAL_LB_DB_FILE = "/system/lb.sqlite"
LOCAL_SQLITE_FILE = "/system/lb_%s.sqlite"
###########################################

########## Code COnstants Value ###########
PLATFORM_TYPES = 'ORACLE'
MAX_RETRY = 3
SLEEP_INTERVAL = 5
SCRIPT_VERSION = 1.0
REFRESH_TIME = 5
LB_REFRESH_TIME = 30
POOL_TIMEOUT = 10
##########################################

########## Service Constants #############
_debug = False
log.set_logging_prefix("health_monitor")
_logger = log.get_logger("health_monitor")
##########################################
 
class GroupOfGreenlet(Group):
    def __init__(self, *args):
        super(GroupOfGreenlet, self).__init__(*args)

    def spawn(self, func, *args, **kwargs):
        parent = super(GroupOfGreenlet, self)
        p = parent.spawn(func, *args, **kwargs)
        return p

class ClusterInfo(object):
    def __init__(self, data):
        self.cluster_id = data['cluster_id']
        self.db_file_name = data['db_file_name'] 
        self.servers_list = data['servers_list']
        self.cluster_type = data['cluster_type']
        self.db_obj = data['db_obj']
        self.servers_health = data['servers_health']
        self.root_user_info = data['root_user_info']
        self.dbdownretry = data['dbdownretry']
        self.retry = 0
        self.servers_old_health = data['servers_old_health']
        self._is_stop = data['is_stop']
        self.parent_greenlet = None
        self.group_gevent = None
        self.refresh_time = REFRESH_TIME 
        self.last_state_updated = None 
        
class HealthMonitor(daemon.Daemon):
    ''' HealthMonitor Class
    '''
    def __init__(self, pidfile):
        self._all_serverids = [] 
        self.all_clusters_info = []
        self.last_state_updated = None 
        self.refresh_time = LB_REFRESH_TIME 
        super(HealthMonitor, self).__init__(pidfile)

    def get_cluster_object(self, cluster_id):
        ''' Get cluster object
        '''
        cluster_obj = None
        for ci in self.all_clusters_info:
            if ci.cluster_id == cluster_id:
                cluster_obj = ci
        return cluster_obj

    def check_cluster_greenlet_running(self, cluster_id):
        ''' Get cluster object
        '''
        is_running = False
        running_cluster_obj = None
        for ci in self.all_clusters_info:
            if ci.cluster_id == cluster_id:
                is_running = True
                running_cluster_obj = ci
                break
        _logger.debug("HealthMonitor: cluster id %s greenlet running %s"\
                      %(cluster_id, is_running))
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
                     status <> 9 and status <> 5 and type = '%s'" % PLATFORM_TYPES
            _logger.debug("HealthMonitor: executing query  %s for all cluster ids"\
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

            _logger.debug("HealthMonitor: all cluster ids %s" %(cluster_ids))
            util.close_sqlite_resources(sqlite_handle, db_cursor)
        return cluster_ids

    def execute_capability(self, inputdata, cluster_id, name):
        ''' Execute capability like socket monitoring or 
            query monitoring
        '''
        db_obj = inputdata['db_obj']
        func_cap = db_obj.function
        result = []
        for func in func_cap:
            _logger.debug("HealthMonitor(%s): name %s executing function %s"\
                          %(cluster_id, name, func))
            response = getattr(db_obj, "%s_monitor"%func)(inputdata)
            _logger.debug("HealthMonitor(%s): name %s function %s and response %s"\
                          %(cluster_id, name, func, response))
            result.append((func, response))
            time.sleep(.1)
        return result
    
    def find_stopped_cluster_ids(self):
        '''
        Return a list of cluster ids for clusters which have been stopped.
        '''
        cluster_ids = []
        for item in self._all_serverids:
            if item['status'] == 0 :
                cluster_ids.append(item['clusterid'])
        return cluster_ids

    def find_running_cluster_ids(self):
        '''
        Returns the list of clusters that are running
        '''
        cluster_type_ids = {}
        for item in self._all_serverids:
            if item['status'] == 1:
                cluster_type_ids[item['clusterid']] = item['type']
        return cluster_type_ids

    def read_sqlite_data(self, cluster_id, cluster_info):
        ''' Read Sqlite data
        '''
        if ((cluster_info.last_state_updated == None) or ((time.time() - cluster_info.last_state_updated) >= cluster_info.refresh_time)):
            _logger.debug("Refreshing sqlite information  %s" %cluster_info.last_state_updated)
            servers_list = cluster_info.db_obj.get_servers_from_sqlite(cluster_info.db_file_name, cluster_id)
            root_user_info = cluster_info.db_obj._find_root_user_info(cluster_id, cluster_info.db_file_name)
            dbdownretry = cluster_info.db_obj.get_dbdownretry_from_sqlite(cluster_info.db_file_name, cluster_id)
            cluster_info.last_state_updated = time.time()
            return servers_list, root_user_info, dbdownretry
        else:
            return cluster_info.servers_list, cluster_info.root_user_info, cluster_info.dbdownretry

    def check_servers_health(self, cluster_id):
        ''' Check health of all the servers
        '''
        while True:
            try:
                _logger.debug("HealthMonitor(%s): *** Started Running Parent gevent *** " % cluster_id)
                cluster_info = self.get_cluster_object(cluster_id)
                if not cluster_info:
                    break

                if cluster_info._is_stop == True:
                    self.all_clusters_info.remove(cluster_info)
                    _logger.info("HealthMonitor(%s): Cluster is Stopped. Exiting now " % (cluster_id))
                    break
                cluster_info.servers_list,\
                cluster_info.root_user_info,\
                cluster_info.dbdownretry = self.read_sqlite_data(cluster_id, cluster_info)
                servers_list = cluster_info.servers_list
                old_health = cluster_info.servers_old_health
                db_obj = cluster_info.db_obj
                gg = cluster_info.group_gevent
                greenlets_dict = {}
                i = 0
                _logger.debug("HealthMonitor(%s): Servers list are %s" % (cluster_id, servers_list))
                for server_ip, server_port, serverid, service_name, sid_name, sid_type in servers_list:
                    i = i + 1
                    inputdata = {
                                 'server_ip':server_ip, 'server_port': int(server_port), 
                                 'service_name': service_name, 'db_obj': db_obj,
                                 'sid_name' : sid_name, 'sid_type': sid_type, 
                                 'username' : cluster_info.root_user_info['username'], 
                                 'password':  cluster_info.root_user_info['password'],
                                }
                    gevent_name = "gevent%s" % str(i)
                    g1 = gg.spawn(self.execute_capability, inputdata, cluster_id, gevent_name) 
                    _logger.debug("HealthMonitor(%s): spawning gevent name %s for serverip %s and port %s"\
                                 %(cluster_id, gevent_name, server_ip, server_port))
                    greenlets_dict[server_ip] = g1
                # Timeout change to number of servers and previous results of health store
                gg.join(timeout=POOL_TIMEOUT)
                temp_dict = {}
                for ip, g in greenlets_dict.iteritems():
                    if g.value:
                        temp_dict[ip] = g.value
                    else:
                        values = cluster_info.servers_old_health.get(ip)
                        new_result = [('query', True)]
                        if values:
                            new_result = values

                        temp_dict[ip] = new_result
                            
                cluster_info.servers_health = temp_dict
                _logger.info("HealthMonitor(%s): Oldserver health %s new server health %s"
                             %(cluster_id, cluster_info.servers_old_health, cluster_info.servers_health))

                inform_core = False

                if not cluster_info.servers_old_health:
                    inform_core = True
                    _logger.debug("HealthMonitor(%s): Inform core is %s because old health not present "%(cluster_id, inform_core))
                else:
                    consolidated_servers_health, is_any_server_down = self.overall_health_status(cluster_info.servers_health)
                    if is_any_server_down:
                        if cluster_info.retry < cluster_info.dbdownretry:
                            cluster_info.retry = cluster_info.retry + 1
                            _logger.debug("HealthMonitor(%s):Retry Count %s"%(cluster_id,cluster_info.retry))
                            time.sleep(1)
                            continue
                        else:
                            inform_core = True
                            _logger.debug("HealthMonitor(%s): Inform core is %s because retry is exceed then dbdownretry "%(cluster_id, inform_core))
                    else:
                        inform_core = False if cluster_info.servers_old_health == cluster_info.servers_health else True
                        _logger.debug("HealthMonitor(%s): Inform core is %s in Change in Health"%(cluster_id, inform_core))

                if inform_core:
                    _logger.info("HealthMonitor(%s): Change in health Inform to core is %s "\
                                             %(cluster_id, inform_core))
                    is_success = self.report_health_change(cluster_id, cluster_info.servers_old_health, \
                                 cluster_info.servers_health, cluster_info.servers_list)
                    if is_success:
                        cluster_info.retry = 0
                        _logger.debug("HealthMonitor(%s): Send Command to core about health change sucessfully"%(cluster_id))
                        cluster_info.servers_old_health = deepcopy(cluster_info.servers_health)
                    else:
                        _logger.debug("HealthMonitor(%s): Failed in report health change " % (cluster_id))
                else:
                    cluster_info.retry = 0
                time.sleep(1)
            except Exception, ex:
                import traceback
                _logger.error("HealthMonitor(%s): Exception in check servers Health %s" %(cluster_id,traceback.format_exc()))
   
    def overall_health_status(self, new_health):
        '''
        Check all the servers health
        return servers_health and if any server is down
        ''' 
        servers_health = {}
        is_any_server_down = False
        for server_ip, values in new_health.iteritems():
            new_result = True
            if values:
                for health in values:
                    new_result = new_result and health[1]
            else:
                new_result = False
            servers_health[server_ip] = new_result
            if not new_result:
                is_any_server_down = True
        return servers_health, is_any_server_down

    def publish_health_to_redis(self, cluster_id, new_health, servers_list):
        '''
        Using Redis Publisher Module to Publish the health
        {'cluster_id': <1>, 'server_id': <2>, 'health': <1> }
        '''
        _logger.info("HealthMonitor(%s):Preparing Publish health dict %s"%(cluster_id, new_health))
        try:
            health_data = {}
            for ip, port, serverid, service_name, sid_name, sid_type in servers_list:
                _logger.debug("HealthMonitor(%s): checking for %s %s %s"\
                             %(cluster_id, ip, port, serverid))
                new_result = True
                if new_health.has_key(ip):
                    if new_health and new_health[ip]:
                        for health in new_health[ip]:
                            new_result = new_result and health[1]
                    else:
                        new_result = 0
                else:
                    new_result = 0
                if health_data.has_key(cluster_id):
                    health_data[cluster_id].append({'serverid': serverid,     
                                      'health': int(new_result),
                                      'ip': ip})
                else:
                    health_data[cluster_id] = [{'serverid': serverid, 
                                           'health': int(new_result),
                                           'ip': ip}]

            _logger.debug("HealthMonitor(%s): Publishing health dict to redis %s"\
                              %(cluster_id, health_data))
            publisher().publish('health_monitor', health_data)
            _logger.debug("HealthMonitor(%s): Published health dict to redis %s"\
                              %(cluster_id, health_data))
            return True
        except Exception, ex:
            _logger.error("Exception in publishing health in redis %s" %traceback.format_exc())
            return False

    def report_health_change(self, cluster_id, old_health, new_health, servers_list):
        '''
        database_health|<clusterid>|<database id>|<health>
        '''
        is_success = True
        response = ''
        _msg_for_core = ''
        _logger.debug("HealthMonitor(%s):Calculate Health change "%(cluster_id))
        try:
            for ip, port, serverid, service_name, sid_name, sid_type in servers_list:
                _logger.info("HealthMonitor(%s): In report health change checking for ip %s port %s serverid %s new health %s"\
                             %(cluster_id, ip, port, serverid, new_health))
                new_result = True
                # FIXME If ip not present in new health
                if new_health.has_key(ip):
                    if new_health and new_health[ip]:
                        for health in new_health[ip]:
                            new_result = new_result and health[1]
                    else:
                        new_result = 0
                else:
                    _logger.error("HealthMonitor(%s): IP not found in new health %s"\
                             %(cluster_id, ip))
                    new_result = 0
                _logger.debug("HealthMonitor(%s): Reporting his health to core ip is %s"\
                             "new_health info %s health status %s"\
                              %(cluster_id, ip, new_health[ip], new_result))

                _msg_for_core = _msg_for_core + str(serverid) + ":" + str(int(new_result)) + "|" 
            
            if _msg_for_core:
                if self._writeback_changes_to_sqlite(cluster_id, _msg_for_core):
                    _logger.info("HealthMonitor(%d): Write Health Status Sucessfully in sqlite that is %s"\
                                     %(cluster_id, _msg_for_core))
                    response = self._inform_core(cluster_id, _msg_for_core)
                    #NOTE Publishing the Health to Redis
                    try:
                        _logger.debug("HealthMonitor(%s): Preparing health data for publishing in Redis "%(cluster_id))
                        result = self.publish_health_to_redis(cluster_id, new_health, servers_list)
                    except Exception,ex:
                        _logger.error("HealthMonitor(%s): Exception in publishing servers Health %s" %(cluster_id,ex))

                    if response == False:
                        _logger.error("HealthMonitor(%d): Failed to Inform core about health changes in" %(cluster_id))
                        is_success = False
                else:
                    _logger.error("HealthMonitor(%d): Failed to Write Health Status in sqlite " %(cluster_id))
            return is_success
        except Exception, ex:
            _logger.error("Exception in informing core %s" %traceback.format_exc())
            return False

    def _inform_core(self, cluster_id, _msg_for_core):
        '''
        database_health|<clusterid>|<database id>|<health>
        '''
        response = ''
        is_success = True
        core_command = "set|database_health|%s|" %cluster_id + _msg_for_core
        response = util.socket_cmd_runner(command=core_command)
        _logger.info("HealthMonitor(%s): msg response form core is %s for command %s"\
                     %(cluster_id, response, core_command))

        if response != "SUCCESS":
            _logger.error("Failed to inform core : %s" % (response))
            is_success = False
        return is_success

    def _writeback_changes_to_sqlite(self, cluster_id, _msg_for_core):
        '''
        Before informing about change we will first write the changes that we
        have into the sqlite file. Return true/false depending upon whether
        this operation was successful.
        '''

        db_file_name = LOCAL_SQLITE_FILE % cluster_id
       
        _logger.debug("HealthMonitor(%d): Inside writeback msg_for_core %s" \
               % (cluster_id, _msg_for_core))
        
        # lets split the message string and for list of queries
        sub_msg_list = _msg_for_core.split('|')
        query_list = []
        for item in sub_msg_list:
            if item != '':
                t = item.split(':') # t = ['1', '0'], serverid and health_status

                query = "update lb_servers set health_status=%s where clusterid=%d"\
                        " and status=1 and serverid=%s" \
                        % (int(t[1]), cluster_id, int(t[0]))
                query_list.append(query)
        _logger.debug("HealthMonitor(%d): Update Queries are %s" \
               % (cluster_id, query_list))
        db_handle = util.get_sqlite_handle(db_file_name, timeout = 1)
        if db_handle:
            db_cursor = db_handle.cursor()
            retry = 0
            trans_active = False
            while retry < MAX_RETRY:
                try:
                    if not trans_active:
                        db_cursor.execute("BEGIN TRANSACTION")
                        for item in query_list:
                            db_cursor.execute(item)
                        trans_active = True

                    db_handle.commit()
                    break
                except (Exception, sqlite3.Error) as e:
                    # we will retry only if we have database locked issue
                    # else we quit
                    if str(e).find('database is locked') == -1:
                        _logger.error("HealthMonitor(%d): Failed to update servers health " \
                                      "change in sqlite: %s" % (cluster_id, e))
                        break

                    retry = retry + 1
                    if retry >= MAX_RETRY:
                        _logger.error("HealthMonitor(%d): Failed to update " \
                                      "servers Health. Database is locked. " \
                                      "Max retry limit reached:" % (cluster_id))
                        return False
                    else:
                        time.sleep(0.1)
            util.close_sqlite_resources(db_handle, db_cursor)
            return True
        else:
            return False

    def read_db_specific_config(self, cluster_id, cluster_type):
        ''' Read cluster specific config from config file
        '''
        db_config = database_configuration[cluster_type] 
        db_obj = DatabaseFactory(db_config)
        db_file_name = LOCAL_SQLITE_FILE % cluster_id
        #servers_list = db_obj.get_servers_from_sqlite(db_file_name, cluster_id)
        clusterwise_info = { 
                             'cluster_id' : cluster_id,
                             'cluster_type' : cluster_type,
                             'db_file_name' : db_file_name,
                             'servers_list' : [],
                             'db_obj' : db_obj,
                             'servers_health' : {},
                             'servers_old_health' : {},
                             'root_user_info' : {},
                             'dbdownretry': 3, 
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
        if ((self.last_state_updated == None) or ((time.time() - self.last_state_updated) >= self.refresh_time)):
            self._all_serverids = self.read_all_clusterids()
            _logger.debug("HealthMonitorParent: Refresh All cluster ids and their type is %s" %self._all_serverids)
            self.last_state_updated = time.time()
        stopped_clusters_type_ids = self.find_stopped_cluster_ids()
        running_cluster_type_ids = self.find_running_cluster_ids()
        _logger.debug("HealthMonitorParent: Running Cluster id's are %s \
                      and Stopped Cluster id's are %s" \
                     %(running_cluster_type_ids, stopped_clusters_type_ids))

        for cluster_id in stopped_clusters_type_ids:
            _logger.debug("HealthMonitorParent: Checking Stopped cluster greenlet %s" %(cluster_id))
            cluster_running, c_obj = self.check_cluster_greenlet_running(cluster_id)
            # FIXME if no stopped c_obj
            if cluster_running and c_obj:
                _logger.info("HealthMonitorParent: STOPPING Cluster %s greenlet is running %s and object is %s \
                         " % (cluster_id, cluster_running, c_obj))
                #self.all_clusters_info.remove(c_obj)
                c_obj._is_stop = True
            
        for cluster_id, cluster_type in running_cluster_type_ids.iteritems():
            cluster_running, c_obj = self.check_cluster_greenlet_running(cluster_id)
            if cluster_running:
                _logger.debug("HealthMonitorParent: Cluster %s Greenlet already running SKIP this id" %(cluster_id))
                continue
            
            cluster_obj = self.read_db_specific_config(cluster_id, cluster_type)
            # convert all_Cluster info into dict
            self.all_clusters_info.append(cluster_obj)
            _logger.info("HealthMonitorParent: starting gevent for cluster id %s"%cluster_id)                                      
            parent_greenlet = gevent.spawn(self.check_servers_health, cluster_id)
            parent_greenlet.link_exception(self.handle_exception)
            cluster_obj.parent_greenlet = parent_greenlet
            cluster_obj.group_gevent = GroupOfGreenlet()
            parent_greenlet.start()

    def run(self):
        ''' Start health monitor daemon
        '''

        while True:
            try:
                _logger.debug("HealtorMonitorParent: Execution of Main Process")
                self.spawn_monitor_children()
            except Exception, ex:
                _logger.error("HealthMonitorParent: run failed: %s" % ex)
                _logger.error("HealthMonitorParent ex: %s" % (traceback.format_exc(),))
            finally:
                _logger.debug("HealthMonitorParent: Sleeping for %f seconds" \
                              % (SLEEP_INTERVAL))
                time.sleep(SLEEP_INTERVAL)

    def handle_exception(self, greenlet):
        '''
        Greenlet Exception handling  
        '''
        cluster_id = ''
        _logger.error("********Greenlet Exception Handling %s *****" %(greenlet.exception)) 
        _logger.info("Restart the Greenlet by fetching cluster info object")
        for cluster_info in self.all_clusters_info:
            if cluster_info.parent_greenlet == greenlet:
                _logger.info("Recived a cluster info with greenlet %s" % cluster_info.cluster_id)
                cluster_id = cluster_info.cluster_id
                cluster_info._is_stop = True
                self.all_clusters_info.remove(cluster_info)
                break
        _logger.debug("New Greenlet will start for cluster id %s" %cluster_id)

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
