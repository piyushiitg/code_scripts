#!/usr/bin/python
#
# Copyright (C) 2012 ScalArc, Inc., all rights reserved.
#   
    
"""This file implements the daemon for DB_MONITOR
""" 
import os 
import sys
import time
import getopt 
import traceback
import ConfigParser
from idb.cluster_util import PasswordUtils
from .database import database
from .core import core
from .common import HealthStatus

# The configuration file for DB_MONITOR service
IDB_DIR_ETC = '/opt/idb/conf'
DB_MONITOR_CONF = 'db_monitor.conf'
NO_SAFETY_NET_FILE = "/opt/idb/.idb_utils_no_safety_net"
LB_DB_FILE = "/system/lb.sqlite"

# The global variable for the configuration parser
_config = None
        
# These can be overriden via command-line options
_debug = False

# Initialize logging
from idb import log, daemon, util
from idb.cmd.alert_engine.publisher import publisher
from idb.cmd.alert_engine.core.db import sqlite

log.set_logging_prefix("db_monitor")
_logger = log.get_logger("db_monitor")

# Set the script version
SCRIPT_VERSION = 1.0

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
        config_file = IDB_DIR_ETC + '/' + config_file

    if not os.path.exists(config_file):
        raise Exception('File not found: %s' % config_file)

    # NOTE: Use SafeConfigParser instead of ConfigParser to support
    # escaping of format strings e.g. % as %%
    config = ConfigParser.SafeConfigParser(options)
    config.read(config_file)
    return config

class Cluster(object):
    """This class represent a cluster
    """
    def __init__(self, cid, cluster_type):
        self._db_list = []
        self._cluster = None

        self._cid = cid
        self._cluster_type = cluster_type

    def get_id(self):
        """This method returns the cluster id
        """
        return self._cid

    def get_db(self, id):
        """This method returns the database object corresponding to the id
        """
        for db in self._db_list:
            if db.get_id() == id:
                return db
        return None

    def set_attr(self, ip_addr, port, username, password, databases,
                    logical_db=None, query=None, max_failure=5, max_replication_lag=30):
        if not self._cluster:
            _logger.info("Created new cluster configuration: CID: %s, "\
                "IPaddress: %s, Port: %s, Username: %s, Password: <hidden>, "
                "logical_db: %s, query: %s, max_failure: %s" % (self._cid,
                ip_addr, port, username, logical_db, query, max_failure))
            self._cluster = database(self._cid, self._cluster_type, 0)

        self._cluster.set_attr(ip_addr, port, username, password,
                                logical_db, query, max_failure,
                                max_replication_lag)

        # Remove/Update database
        for db in self._db_list:
            if db.get_id() not in databases.keys():
                self._db_list.remove(db)
    
        # Add/Update the database
        for new_db_id, new_db in databases.iteritems():
            db = self.get_db(new_db_id)
            if not db:
                db = database(self._cid, self._cluster_type, new_db_id)
                self._db_list.append(db)

            db.set_attr(new_db['ip'], new_db['port'], username, password,
                        logical_db, query, max_failure, max_replication_lag)

    def monitor_health(self, core_status=None):
        """This method sart monitoring the cluster and its databases
        """
        db_status = {}
        try: 
            self._cluster.monitor_health(core_status)
            db_status = core.get_server_status(self._cid)
        except Exception, ex:
            _logger.error("Failed to monitor health of cluster %s: %s" % \
                (self._cid, ex))        
            _logger.error("%s" % (traceback.format_exc(),))

        db_replication_lag = core.get_stat_status()
        monitor_variable_dict = {}
        for db in self._db_list:
            try:
                core_status = db_status.get(db.get_id(), None)
                db_lag = db_replication_lag.get(db.get_id(), -1)
                if core_status == HealthStatus.UP and db._db_type.lower() == 'mysql': 
                    res = db.monitor_health(core_status, db_lag, variable_monitor = True)
                    if res and type(res) == dict:
                        res.update({'server_ip': db._ip_addr, 'server_port': db._port})
                    else:
                        res = {'server_ip': db._ip_addr, 'server_port': db._port}
                    monitor_variable_dict[db.get_id()] = res
                else:
                    res = db.monitor_health(core_status, db_lag, variable_monitor = False)
            except Exception, ex:
                _logger.error("Failed to monitor health of database %s: %s" % \
                        (db.get_id(), ex))
                _logger.error("%s" % (traceback.format_exc(),))
        return monitor_variable_dict
        

class DB_Monitor_Daemon(daemon.Daemon):
    """This class runs DB_MONITOR as a daemon
    """
    _default_username = None
    _default_password = None
    _default_port = None
    _default_database = ''
    _default_query = ''
    _default_max_failure= 3
    _default_max_replication_lag = 30
    _default_wait = 5
    # List of databases configured in the db_monitor.conf file
    _db_list = []

    # List of clusters configured on the idb
    _cluster_list = []

    def run(self):
        #
        # Fix  for IDB-5393
        #
        while not os.path.exists('/system/lb.sqlite'):
            _logger.warn("DBMonitor(%d): '/system/lb.sqlite' "\
                            "does not exist " % (os.getpid(),))
            time.sleep(1)

        try:
            #
            # Read if there are any databases listed in the config
            # file (used for debugging)
            #
            for section in _config.sections():
                if section == 'default':
                    self.get_default_options()
        except Exception, ex:
                _logger.error("DBMonitor : Service Initialization failed: %s" % ex)        
                _logger.error("%s" % (traceback.format_exc(),))

        data = {'op': 'check'}
        while True:
#            data['status'] = 'begin'
#            publisher().publish('db_monitor', data)
            # Refresh the cluster configuration
            self.read_cluster_configuration()

            clusterwise_monitor_variable_dict = {}
            db_monitor_variable_dict = {}
            try:
                if len(self._cluster_list) == 0:
                    _logger.info("No cluster found for monitoring")
                else: 
                    lb_status = core.get_lb_status()
                    for cluster in self._cluster_list:
                        core_status = lb_status.get(cluster.get_id(), None)
                        monitor_variable_dict = cluster.monitor_health(core_status)
                        if monitor_variable_dict:
                            clusterwise_monitor_variable_dict[cluster.get_id()] = {"servers_info": monitor_variable_dict}
                    _logger.info("Cluster wise dict %s" %clusterwise_monitor_variable_dict)
            except Exception, ex:
                _logger.error("Failed to monitor specified cluster: %s" % ex)
                _logger.error("%s" % (traceback.format_exc(),))
                if os.path.exists(NO_SAFETY_NET_FILE):
                    #
                    # If the debug file is present, we break out the service so
                    # that we can catch this condition in QA/Development,
                    # otherwise we loop forever.
                    #
                    break

            try:
                if len(self._db_list) == 0:
                    _logger.info("No database specified for monitoring "
                        "in db_monitor.conf")
                else: 
                    for db in self._db_list:
                        _logger.info("Before db monitor health and type is %s" %(db))
                        db.monitor_health()
                        _logger.info("After db monitor health")
            except Exception, ex:
                _logger.error("Failed to monitor specified database: %s" % ex)
                _logger.error("%s" % (traceback.format_exc(),))
                if os.path.exists(NO_SAFETY_NET_FILE):
                    #
                    # If the debug file is present, we break out the service so
                    # that we can catch this condition in QA/Development,
                    # otherwise we loop forever.
                    #
                    break
            
#            data['status'] = 'complete'
#            publisher().publish('db_monitor', data)
            # Sleep for the wait interval, before the next monitoring cycle
            _logger.debug("Sleeping for %f seconds"%self._default_wait)
            time.sleep(self._default_wait)

    def read_cluster_configuration(self):
        """This method reads the cluster configuration form sqlite file
        """
        # Read the configuration of the databases from our config
        try:
            running_cluster_ids = self.get_running_clusters()
            #
            # Remove tthe clusters from monitoring that are not running
            # or refresh their configuration if something changed.
            #
            for cluster in self._cluster_list:
                if cluster.get_id() not in running_cluster_ids.keys():
                    self._cluster_list.remove(cluster)
                else:
                    self.load_cluster_config(cluster)

            # Add any new clusters that has been started/created
            cid_list  = [ cluster.get_id() for cluster in self._cluster_list ]
            for cid, cluster_type in running_cluster_ids.iteritems():
                if cid not in cid_list:
                    cluster = Cluster(cid, cluster_type)
                    self.load_cluster_config(cluster)
                    self._cluster_list.append(cluster)
        except Exception, ex:
                _logger.error("DBMonitor: Failed to find cluster information: "
                    ": %s" % ex)        
                _logger.error("%s" % (traceback.format_exc(),))

    def get_running_clusters(self):
        cluster_ids = {}
        for c in sqlite.get(['cluster_id', 'type'], 'lb_clusters_summary', 'status=1'):
            cluster_ids[c['cluster_id']] = c['type']
        _logger.info("Running clusters list: %s" % cluster_ids)
        return cluster_ids

    def max_replication_lag(self, cid):
        tmp = sqlite.get(['laggtime'], 'lb_advsettings', clusterid=cid)
        if tmp and len(tmp):
            return tmp[0]['laggtime']
        return self._default_max_replication_lag

    def get_cluster_ip_port(self, cid):
        ipaddr = None
        port = None
        c = sqlite.get(['ipaddress', 'port'], 'lb_clusters', clusterid=cid)
        if c and len(c):
            ipaddr = c[0]['ipaddress']
            port = c[0]['port']

        return ipaddr, port

    def get_cluster_user(self, cid):
        user = {'username': '', 'password': ''}
        c = sqlite.get(['username', 'encpassword'], 'lb_users', 'type=1', clusterid=cid)
        if c and len(c):
            user['username'] = c[0]['username']
            user['password'] =  PasswordUtils.decrypt(c[0]['encpassword'])
        _logger.info("User name and password is %s" %user)
        return user

    def get_cluster_databases(self, cid):
        databases = {}
        columns = ['serverid', 'ipaddress', 'port']
        for c in sqlite.get(columns, 'lb_servers', 'status=1', clusterid=cid):
            databases[c['serverid']] = {'ip': c['ipaddress'], 'port': c['port']}

        return databases

    def load_cluster_config(self, cluster):
        cid = cluster.get_id()

        ipaddr, port = self.get_cluster_ip_port(cid)
        _logger.debug("Configured ipaddr:port for cluster %s: " \
                 "ipaddr: %s, port: %s" % (cid, ipaddr, port))

        user = self.get_cluster_user(cid)
        _logger.debug("Configured user for cluster %s: " \
                 "User: %s, Password: <hidden>" % (cid, \
                user['username']))

        databases = self.get_cluster_databases(cid)
        _logger.debug("DB list for cluster %s : %s" % (cid, databases))

        _max_replication_lag = self.max_replication_lag(cid)

        cluster.set_attr(ipaddr, port, user['username'],
                    user['password'], databases, '',
                    self._default_query,
                    self._default_max_failure,
                    _max_replication_lag)

    def get_default_options(self):
        # Read configuration file and extract default options
        try:
            self._default_username = _config.get('default', 'default_username')
            _logger.info("Default username specified: %s" %
                             self._default_username)
        except Exception, ex:
            _logger.info("No default username specified: %s" % ex)

        try:
            self._default_password = _config.get('default', 'default_password')
            _logger.info("Default password specified: %s" % "<hidden>")
        except Exception, ex:
            _logger.info("No default password specified: %s" % ex)

        try:
            self._default_port = _config.get('default', 'default_port')
            _logger.info("Default port specified: %s" % self._default_port)
        except Exception, ex:
            _logger.info("No default port specified: %s" % ex)

        try:
            self._default_database = _config.get('default', 'default_database')
            _logger.info("Default database specified: %s" %
                             self._default_database)
        except Exception, ex:
            _logger.info("No default database specified: %s" % ex)

        try:
            self._default_query = _config.get('default', 'default_query')
            _logger.info("Default query specified: %s" %
                             self._default_query)
        except Exception, ex:
            _logger.info("No default query specified: %s" % ex)

        try:
            self._default_wait = _config.getfloat('default', 'default_wait')
            _logger.info("Default wait specified: %f" %
                             self._default_wait)
        except Exception, ex:
            _logger.info("No default wait specified (will use %f sec)" %
                                     (self._default_wait))

        try:
            self._default_max_failure = _config.get('default', 'default_max_failure')
            _logger.info("Default max failure specified: %s" %
                             self._default_max_failure)
        except Exception, ex:
            _logger.info("No default max failure specified (will use %s)" %
                                     (self._default_max_failure))

def main():
    # Go away if you are not root
    if not os.geteuid()==0:
        sys.exit("DBMonitor: You must be root to run this script\n")

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
    #import logging
    #logging.basicConfig()
    #_logger = logging.getLogger()  

    # Read the configuration file
    global _config
    _config = get_config_parser(DB_MONITOR_CONF)

    db_monitor_daemon = DB_Monitor_Daemon('/var/run/db_monitor.pid')
    if args:
        if 'stop' == args[0]:
            _logger.info("*********** DB_MONITOR stopping **************")
            db_monitor_daemon.stop()
        elif 'restart' == args[0]:
            _logger.info("********** DB_MONITOR restarting ************")
            db_monitor_daemon.restart()
        else:
            err_msg = "Invalid command %s" % (repr(args[0]),)
            print >> sys.stderr, err_msg
            _logger.error("%s" % (err_msg,))
            sys.exit(2)
        sys.exit(0)

    if _debug:
        _logger.info("******** DB_MONITOR starting (debug mode)**********")
        db_monitor_daemon.foreground()
    else:
        _logger.info("************** DB_MONITOR starting ****************")
        db_monitor_daemon.start()

if __name__ == "__main__":
    main()
