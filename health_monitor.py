import os
import sys
import getopt
import sqlite3
import socket
import gevent
import time
import gevent.monkey
import idb.util as util
from idb import log, daemon
from gevent.pool import Group
from datetime import datetime
from sqlite import SqliteHandler
from factory import DatabaseFactory
from config import database_configuration
gevent.monkey.patch_all()

############# Constant File Name ##########
GLOBAL_LB_DB_FILE = "/system/lb.sqlite"
LOCAL_SQLITE_FILE = "/system/lb_%s.sqlite"
###########################################

########## Code COnstants Value ###########
PLATFORM_TYPES = ('MSSQL', 'ORACLE', )
MAX_RETRY = 3
SLEEP_INTERVAL = 5
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
        self.cluster_type = data['cluster_type']
        self.db_file_name = data['db_file_name'] 
        self.servers_list = data['servers_list']
        self.cluster_type = data['cluster_type']
        self.db_obj = data['db_obj']
        self.servers_health = data['servers_health']
        self._is_stop = data['is_stop']
        self.parent_greenlet = None
        
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
        for ci in self.all_clusters_info:
            if ci.cluster_id == cluster_id:
                return ci
        return None

    def check_cluster_greenlet_running(self, cluster_id):
        ''' Get cluster object
        '''
        for ci in self.all_clusters_info:
            if ci.cluster_id == cluster_id:
                return True, ci
        return False, None

    def read_all_clusterids(self):
        '''
        Read a list of all server_ids with the status field.
        '''
        cluster_ids = []
        sqlite_handle = util.get_sqlite_handle(GLOBAL_LB_DB_FILE)
        if sqlite_handle:
            db_cursor = sqlite_handle.cursor()
            query = "select cluster_id, status, type from lb_clusters_summary where \
                     status <> 9 and type in %s " % str(PLATFORM_TYPES)
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

            util.close_sqlite_resources(sqlite_handle, db_cursor)
        return cluster_ids

    def execute_capability(self, inputdata, name):
        _logger.info("Running child gevent")
        db_obj = inputdata['db_obj']
        func_cap = db_obj.function
        result = []
        for func in func_cap:
            response = getattr(db_obj, "%s_monitor"%func)(inputdata)
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


    def check_servers_health(self, cluster_id):
        ''' Check health of all the servers
        '''
        gg = GroupOfGreenlet()
        while True:
            try:
                i = 0
                temp_dict = {}
                greenlets_dict = {}
                _logger.info("Running Parent gevent with cluster id is %s" % cluster_id)

                cluster_info = self.get_cluster_object(cluster_id)
                if cluster_info._is_stop == True:
                    _logger.info("HealthMonitor(%s): cluster is stopped now %s"%(cluster_id))
                    break

                servers_list = cluster_info.servers_list
                db_obj = cluster_info.db_obj
                for server_ip, server_port in servers_list:
                    i = i + 1
                    inputdata = {'server_ip':server_ip, 'server_port': int(server_port), 
                                 'db_obj': db_obj}
                    g1 = gg.spawn(self.execute_capability, inputdata, "g%s"%str(i)) 
                    greenlets_dict[server_ip] = g1
                gg.join(timeout=10)
                for ip, g in greenlets_dict.iteritems():
                    temp_dict[ip] = g.value 
                #_logger.info("HealthMonitor(%s): servers health %s"%(cluster_id, temp_dict))
                cluster_info.servers_health = temp_dict
                time.sleep(15)
            except Exception, ex:
                _logger.error("Exception in gevent %s" %ex)

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
                             'cluster_type': cluster_type,
                             'db_obj' : db_obj,
                             'servers_health' : {},
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
        stopped_clusters_type_ids = self.find_stopped_cluster_ids()
        running_cluster_type_ids = self.find_running_cluster_ids()
        for cluster_id, cluster_type in stopped_clusters_type_ids:
            cluster_running, c_obj = self.check_cluster_greenlet_running(cluster_id)
            if cluster_running:
                c_obj._is_stop = True
            
                
            
        #FIXME handling stopped cluster related greenlet
        #for cid in stopped_clusters:
        #    marker_file = "/var/run/health_onitor_%d.file" % cid
        #    if os.path.exists(marker_file):
        #        self._stop_monitor_process_for_cluster(cid)

        for cluster_id, cluster_type in running_cluster_type_ids.iteritems():
            if self.check_cluster_greenlet_running(cluster_id)[0]:
                _logger.info("HealthMonitor(%s): Cluster Greenlet already running SKIP this id")
                continue
            _logger.info("HealthMonitor(%s): cluster type is  %s" %(cluster_id, str(cluster_type)))
            cluster_obj = self.read_db_specific_config(cluster_id, cluster_type)
            self.all_clusters_info.append(cluster_obj)
            _logger.info("HealthMonitor(%s): starting gevent for cluster id"%cluster_id)                                      
            parent_greenlet = gevent.spawn(self.check_servers_health, cluster_id)
            cluster_obj.parent_greenlet = parent_greenlet
            parent_greenlet.start()

        #while True:
        #    _logger.info("************************************************************************")
        #    time.sleep(20)
        #    for cluster_obj in self.all_clusters_info:
        #        _logger.info("cluster wise info %s %s" %(cluster_obj.cluster_id, cluster_obj.servers_health))
       

    def run(self):
        ''' Start health monitor daemon
        '''
        while True:
            try:
                _logger.info("Health Monitor service is start")
                self.spawn_monitor_children()
                _logger.info("************************************************************************")
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
