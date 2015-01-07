
#!/usr/bin/python
#
# Copyright (C) 2014 ScalArc, Inc., all rights reserved.
##
# Revision : 1.4 (Release)
# Author   : Piyush Singhai
# Date     : 24/11/2014
#
#
# Revision : 1.3 (Release)
# Author   : Piyush Singhai
# Date     : 20/08/2014
#
#
# Revision : 1.2 (Release)
# Author   : Piyush Singhai
# Date     : 13/03/2014
#
# Revision : 1.1 (Release)
# Author   : Tej Narayan Kunwar
# Date     : 19/07/2013
#
# Author   : Tapas Sharma
# Revision : 1.0 (Beta)
# Date     : 6/6/2013 (Last Modified)
#

"""This file implements the daemon for AlwaysOnMonitor
"""
from gevent import monkey
monkey.patch_all()
import getopt
import os
import sys, socket
import traceback
import time
import multiprocessing
import pyodbc
import sqlite3
import base64
import binascii
import hashlib
import signal
import glob
import random
from copy import deepcopy
import json
import httplib
#
# import modules from site-packages. iDB pacakge has to be installed before
# the following modules can be imported
#

import idb.log as log
import idb.daemon as daemon
import idb.util as util
from idb.cluster_util import PasswordUtils 
import gevent
from gevent import Timeout
from gevent import queue
import ConfigParser
from idb import events
from idb.cmd.system_monitor.constants import SystemMonitorStat

####### Global Variables ##########
_debug = False
APIKEY = ""
SCRIPT_VERSION = 1.0
GLOBAL_LB_SQLITE_FILE = '/system/lb.sqlite'
LB_SQLITE_FILE = '/system/lb_%s.sqlite'
SLEEP_INTERVAL = 5
MAX_RETRY = 10
CONN_RETRY = 1
MSSQL_LOGIN_TIMEOUT = 3
QUERY_TIMEOUT = 5
SOCKET_TIMEOUT = 1
PLATFORM_TYPE = 'MSSQL'
# connection types used when talking with core
PRIMARY = 0
SECONDARY = 1

# role types used when talking with core
PRIMARY_ROLE_MAP = {}
PRIMARY_ROLE_MAP['READ_WRITE'] = 2
PRIMARY_ROLE_MAP['ALL'] = 1

SECONDARY_ROLE_MAP = {}
SECONDARY_ROLE_MAP['ALL'] = 4
SECONDARY_ROLE_MAP['READ_ONLY'] = 5
SECONDARY_ROLE_MAP['NO'] = 6

gSignalChildToQuit = False
gMonitoredClusters = {}
gMonitorProcessMarkerFile = '' # used by child monitor process
TIME_TO_WAIT_FOR_CHILD_JOIN = 60 # in seconds

STATUS_UP = 1
STATUS_DOWN = 0
################Always On 2014 ####################
ALWAYS_ON_2014 = "Microsoft SQL Server 2014"
ALWAYS_ON_2012 = "Microsoft SQL Server 2012"
RESOLVING_ROLE = 0
OFFLINE = 3
UP = 1
DOWN = 0
HEALTH_DOWN_OP_STATE = [0, 1, 4, 5]
HEALTH_UP_OP_STATE = [2, 3] 

OPERATION_STATE_DICT = { 
                        0 : 'PENDING_FAILOVER',
                        1 : 'PENDING',
                        2 : 'ONLINE',
                        3 : 'OFFLINE',
                        4 : 'FAILED',
                        5 : 'FAILED_NO_QUORUM'
                       }

# Initialize logging
log.set_logging_prefix("always_on_monitor")
_logger = log.get_logger("always_on_monitor")

# The configuration file for Always on service
IDB_DIR_ETC = '/opt/idb/conf'
ALWAYS_ON_MONITOR_CONF = 'always_on_monitor.conf'

# The global variable for the configuration parser
_config = None

def get_config_parser(config_file, options = {}):
    """Get a config parser for the given configuration file
    """
    if not os.path.isabs(config_file):
        config_file = IDB_DIR_ETC + '/' + config_file

    if not os.path.exists(config_file):
        raise Exception('AlwaysOnMonitor: File not found: %s' % config_file)

    # NOTE: Use SafeConfigParser instead of ConfigParser to support
    # escaping of format strings e.g. % as %%
    config = ConfigParser.SafeConfigParser(options)
    config.read(config_file)
    return config

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

class AlwaysOnMonitorUtils(object):
    def __init__(self, clusterid, parent_pid):
        self._cluster_id = clusterid
        self._lb_dbname = LB_SQLITE_FILE % clusterid
        self._cluster_status = STATUS_UP
        self._conn_str = ''
        self._parent_pid = parent_pid
        self._vnn_info = {'vnn_server':'', 'vnn_port':''}

        self._state_refresh_interval = 10 # in seconds
        self._last_state_updated = 0 # time in seconds, float
        self._msg_for_core = ''

        self._old_servers_list = []  # list of dict = {'serverid':n,'ip':'',
                                     #                   'port':n,'type':n}
        self._new_servers_list = [] # list of dict = {'server':'',
                                    # 'primary_role':'', 'secondary_role':''}
        self._old_master = ''
        self._new_primary_server = ''
        self._connection = None
        self._primary_ip = ''
        self._primary_port = ''
        self._health_status = {} # dict that contains {end_url: connected_state} 
        self.always_on_server_type = ''       
        self.threads_list = []

        self._delete_servers_from_config = []
        self._found_new_servers = []
        self._ui_alert_for_del_servers = {}
        self._ui_alert_for_add_servers = {}
        self.events = events.Event()
        self.health_queue = queue.Queue()
        self.get_default_options()

    def get_default_options(self):
        '''Read configuration file and extract default options
        '''
        try:
            self._mssql_login_timeout = int(_config.get('default', 'mssql_login_timeout'))
            _logger.info("MSSQL Login timeout is : %s" % 
                            self._mssql_login_timeout)
        except Exception, ex:
            self._mssql_login_timeout = 5
            _logger.error("Exception fetching login timeout:%s but set 5" % ex)
   
        try:
            self._mssql_query_timeout = int(_config.get('default', 'mssql_query_timeout'))
            _logger.info("MSSQL Query Timeout is : %s" % 
                          self._mssql_query_timeout)
        except Exception, ex:
            self._mssql_query_timeout = 10
            _logger.error("Exception: Set query timeout: 10 and ex is %s" %ex)

        try:
            self._is_split_ag_id = int(_config.get('default', 'split_ag_id'))
            _logger.info("Split ag_id flag is : %s" %
                             self._is_split_ag_id)
        except Exception, ex:
            self._is_split_ag_id = 0
            _logger.error("Exception:fetching in split ag_id set to 0 %s"%ex)


    def _is_parent_alive(self):
        '''
        Returns True/false
        '''
        if not os.path.exists("/var/run/always_on_monitor.pid"):
            return False

        pid_file = "/proc/" + str(self._parent_pid)
        if os.path.exists(pid_file):
            return True
        return False

    def _find_root_user_info(self):
        '''
        Return a dictionary containing  root account information from table
        lb_users for this cluster_id.
        '''
        self._root_accnt_info = {'username':'', 'password':''}
        sqlite_handle = util.get_sqlite_handle(self._lb_dbname)
        if sqlite_handle:
            db_cursor = sqlite_handle.cursor()
            query = "select username, encpassword from lb_users where type=1 " \
                    "and status=1 and clusterid=?"

            _logger.debug("AlwaysOnMonitor(%d): Exec Sqlite Query %s for root user " \
                           " info" % (self._cluster_id, query))
            retry = 0
            while retry < MAX_RETRY:
                try:
                    db_cursor.execute(query, (self._cluster_id,))
                    row = db_cursor.fetchone()
                    if row:
                        self._root_accnt_info['username'] = row['username']
                        self._root_accnt_info['password'] = row ['encpassword']
                    break
                except Exception, ex:
                    retry = retry + 1
                    if retry >= MAX_RETRY:
                        _logger.error("AlwaysOnMonitor(%d): Failed to find root " \
                                      "user info : %s" % (self._cluster_id, ex))
                    else:
                        time.sleep(0.1)

            util.close_sqlite_resources(sqlite_handle, db_cursor)
            if retry < MAX_RETRY :
                #lets decrypt this password
                self._root_accnt_info['password'] = PasswordUtils.decrypt(self._root_accnt_info['password'])
                _logger.debug("AlwaysOnMonitor(%d): Result of  Query %s for root user " \
                           " info" % (self._cluster_id, self._root_accnt_info))

    def _is_root_account_valid(self):
        '''
        Returns True if root account needed for connecting to mysql is available
        for this cluster otherwise return False.
        '''
        return True if self._root_accnt_info['username'] and \
                self._root_accnt_info['password'] else False

    def _load_vnn_info_from_sqlite(self):
        '''
        Read vnn info from sqlite if available.
        '''
        self._vnn_info = {}
        self._cluster_status = STATUS_UP

        db_handle = util.get_sqlite_handle(self._lb_dbname)
        if db_handle:
            cursor = db_handle.cursor()
            query = "select vnnserver,vnnport,status,ag_id from lb_clusters where" \
                        " status=1 and alwayson=1 and clusterid=?"
            
            _logger.debug("AlwaysOnMonitor(%d): Exec Sqlite Query %s for VNN " \
                           " info" % (self._cluster_id, query))
            retry = 0
            while retry < MAX_RETRY:
                try:
                    cursor.execute(query, (self._cluster_id,))
                    row = cursor.fetchone()
                    if row:
                        agid = ''
                        self._vnn_info['vnn_server'] = row['vnnserver']
                        self._vnn_info['vnn_port'] = row['vnnport']
                        if int(self._is_split_ag_id):
                            try:
                                agid = row['ag_id'].split("@@##@@")[0] 
                                self._vnn_info['group_id'] = agid
                                _logger.debug("AlwaysOnMonitor(%d): Split GroupID, new AGID is  %s " \
                                        " info" % (self._cluster_id, agid))
                            except Exception, ex:
                                self._vnn_info['group_id'] = row['ag_id']
                                _logger.error("AlwaysOnMonitor(%d): Exception while split %s " \
                                        " no split" % (self._cluster_id, ex))
                        else:
                            self._vnn_info['group_id'] = row['ag_id']
                            _logger.debug("AlwaysOnMonitor(%d): No Split AGID is  %s " \
                                       " info" % (self._cluster_id, self._vnn_info['group_id']))
                        self._cluster_status = int(row['status'])
                    break
                except (Exception, sqlite3.Error) as ex:
                    retry = retry + 1
                    if retry >= MAX_RETRY:
                        _logger.error("AlwaysOnMonitor(%d): Problem getting vnn " \
                                    "server info : %s" % (self._cluster_id, ex))
                    else:
                        time.sleep(0.1)
            _logger.debug("AlwaysOnMonitor(%d): Query executed and results for VNN " \
                           " info %s" % (self._cluster_id, self._vnn_info))
            util.close_sqlite_resources(db_handle, cursor)

    def _get_health_info_servers(self, connection=None, multigevent=False):
        ''' Fetch helath information for all node from the table
        master.sys.dm_hadr_availablity_replica_states'''

        try:
            if not connection:
                _logger.debug("AlwaysOnMonitor(%d): Get Health status where primary server %s " \
                              % (self._cluster_id, self._primary_ip))
                _conn_str = self._get_connection_string(server_ip=self._primary_ip,
                                            server_port=self._primary_port)
                _logger.debug("Connection String is %s" % _conn_str)
                _connection = self._get_connection(self._primary_ip, self._primary_port, _conn_str)
            else:
                _logger.debug("AlwaysOnMonitor(%d): Get Health status where primary is not present" \
                              % (self._cluster_id))
                _connection = connection

            cursor = _connection.cursor()
        except Exception, ex:
            _logger.error("AlwaysOnMonitor(%d): Error while creating connection with primary server ex is %s" 
                                     % (self._cluster_id, ex))
            if _connection:
                _connection.close()
            #
            # When Primary server is availiable but we could not make a connection with that server
            # then we need to fetch health from each of the server and fill the self._health_status dict
            #
            if connection == None and multigevent:
                health_status = self.get_all_servers_health()
                self._health_status = health_status
                return health_status

            self._health_status = {}
            return self._health_status

        try:
            if self._vnn_info.has_key('group_id'):
                query ="select a.endpoint_url, b.role, b.connected_state, b.operational_state "\
                       "from sys.availability_replicas a, "\
                       "master.sys.dm_hadr_availability_replica_states b "\
                       "where a.group_id = b.group_id and a.replica_id = b.replica_id "\
                       "and a.group_id='%s'" % self._vnn_info['group_id']
                
            else:
                _logger.debug("AlwaysOnMonitor(%d): No Groupid in vnn_info returning empty health info" 
                               % (self._cluster_id))
                self._health_status = {}
                return self._health_status
            
            _logger.debug("AlwaysOnMonitor(%d): Executing a query to find out health %s" 
                                     % (self._cluster_id, query))
            cursor.execute(query)
            rows = cursor.fetchall()
            _logger.debug("AlwaysOnMonitor(%d): Output of a query for health %s" 
                                     % (self._cluster_id, rows))

            self._health_status = {}
            for endpoint_url, role, connected_state, operational_state  in rows:
                _logger.info("AlwaysOnMonitor(%d): Role and state Info %s %s %s %s %s" \
                 %(self._cluster_id, endpoint_url, role, connected_state, operational_state,\
                   OPERATION_STATE_DICT.get(operational_state, None)))
                ip = self._parse_hostname_from_endpoint_url(endpoint_url)
                self._health_status[ip] = [connected_state, role, operational_state]

        except Exception, ex:
            _logger.error("AlwaysOnMonitor(%d): Problem determining health status " \
                            "from hadr_avail: %s" % (self._cluster_id, ex))
            self._health_status = {}
        finally:
            if cursor:
                cursor.close()
            #
            # if we are passing the connection object
            # in that case will not close the connection 
            # it will handle close condtion once we create the same
            #
            if _connection and not connection:
                _connection.close()
            
            _logger.debug("AlwaysOnMonitor(%d): Health status is %s " \
                              % (self._cluster_id, self._health_status))
            return self._health_status
    
    def get_all_servers_health(self):
        '''
        This Function check for health 
        '''
        try:
            _logger.debug("AlwaysOnMonitor(%d): Get all servers health" \
                                    % self._cluster_id)
            gevent.with_timeout(20, self.read_servers_health_using_gevent)
        except Timeout:
            _logger.error("AlwaysOnMonitor(%d): Timeout at gevent to see all servers health" \
                                    % self._cluster_id)
        except Exception, ex:
            _logger.error("AlwaysOnMonitor(%d): Exception at gevent start %s" \
                                    % (self._cluster_id, ex))
        finally:
            _logger.debug("AlwaysOnMonitor(%d): Stopping all the Gevents" \
                                    % self._cluster_id)
            self.stop_threads()

        new_health_info = {}
        for health_dict in self.health_queue.queue:
            _logger.debug("AlwaysOnMonitor(%d): All servers health dict %s " % (self._cluster_id, health_dict))
            if not health_dict:
                continue
            try:
                server_ip = health_dict['ip']
                health_status, role, op_state = health_dict['new_health_info']
                _logger.error("AlwaysOnMonitor(%d): got new health info" \
                              " server_ip %s connected_state %s role %s op_state %s" \
                              %(self._cluster_id, server_ip, health_status, role, op_state))
                new_health_info[server_ip] = [health_status, role, op_state]
            except Exception, ex:
                _logger.error("AlwaysOnMonitor(%d): Exception reading health %s" \
                                 % (self._cluster_id, ex))
        return new_health_info 
               
    def _parse_hostname_from_endpoint_url(self, endpoint_url):
        '''
        Convert end point url to hostname in the format that we undestand and
        return the same.
        endpoint_url = TCP://MSSQLDB1.2012scalearc.local:5022
        convert to : endpoint_url.split('//')[1].split(':')[0]
        '''
        fqdn = ''
        try:
            fqdn = endpoint_url.split('//')[1].split(':')[0]
        except:
            return endpoint_url
        return fqdn

    def _load_servers_info_from_sqlite(self):
        '''
        Read configuration of all servers present in this cluster.
        '''
        self._old_servers_list = []
        db_handle = util.get_sqlite_handle(self._lb_dbname)
        if db_handle:
            db_cursor = db_handle.cursor()
            query = "select serverid,ipaddress,port,type, sql2012_role_setting, health_status from " \
                    "lb_servers where status=1 and clusterid=?"

            _logger.debug("AlwaysOnMonitor(%d): Exec Sqlite Query %s for servers " \
                           " info" % (self._cluster_id, query))
            retry = 0
            while retry < MAX_RETRY:
                try:
                    db_cursor.execute(query, (self._cluster_id,))
                    for row in db_cursor.fetchall():
                        server_info = {}
                        server_info['serverid'] = int(row['serverid'])
                        server_info['ip'] = row['ipaddress']
                        server_info['port'] = row['port']
                        server_info['type'] = int(row['type'])
                        server_info['role'] = int(row['sql2012_role_setting'])
                        server_info['health_status'] = int(row['health_status'])
                        if server_info['type'] == 0:
                            self._primary_ip = server_info['ip']
                            self._primary_port = server_info['port']
                        self._old_servers_list.append(server_info.copy())
                    break
                except (Exception, sqlite3.Error) as ex:
                    retry = retry + 1
                    if retry >= MAX_RETRY:
                        _logger.error('AlwaysOnMonitor(%d): Problem getting list of " \
                                    "servers : %s' % (self._cluster_id, ex))
                    else:
                        time.sleep(0.1)
            
            _logger.debug("AlwaysOnMonitor(%d): Query result %s for old servers " \
                           " info" % (self._cluster_id, self._old_servers_list))
            util.close_sqlite_resources(db_handle, db_cursor)
            _logger.debug("ALwaysOnMonitor(%d): Old servers list: %s" \
                          % (self._cluster_id, self._old_servers_list))

    def _get_proper_server_addr(self, ip):
        '''
        Make sure that ip is a valid IPv4 address. If it's a hostname try to
        resolve and return an ipv4 address. If not, then return an empty
        string.

        First check if it's an ipv4 address , if not then try resolving it.
        '''
        new_ip = ''
        try:
            socket.inet_aton(ip)
            new_ip = ip
        except:
            try:
                new_ip = socket.gethostbyname(ip)
            except:
                new_ip = ''
        return new_ip

    def _get_connection_string(self, server_ip, server_port):
        return "DRIVER={FreeTDS};SERVER=%s;PORT=%s;UID=%s;PWD=%s;TDS_VERSION=8.0;" \
                    % (server_ip, str(server_port),
                        self._root_accnt_info['username'],
                        self._root_accnt_info['password'])

    def _get_connection(self, server_ip, port, conn_str, max_retry=CONN_RETRY):
        retry = 0
        conn = None
        while retry < max_retry:
            try:
                #FIXME check with socket to connect with mssql server
                _logger.info("AlwaysOnMonitor(%d):Check socket connection ip %s"
                              % ( self._cluster_id, server_ip))
                test_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                test_socket.settimeout(SOCKET_TIMEOUT)
                test_socket.connect((server_ip, port))
                _logger.info("AlwaysOnMonitor(%d):Socket connection ip %s successful"
                              % ( self._cluster_id, server_ip))
            except socket.error:
                errno, errstr = sys.exc_info()[:2]
                if errno == socket.timeout:
                    _logger.error("AlwaysOnMonitor(%d): Timeout has occured %s " % (self._cluster_id, errstr))
                else:
                    _logger.error("AlwaysOnMonitor(%d): Error occured while creating socket connections %s " % (self._cluster_id, errstr))
                retry = retry + 1
                if retry >= max_retry:
                    _logger.error("AlwaysOnMonitor(%d): In Socket Failed to make connection with socket " \
                                  "Max retry limit reached:" % (self._cluster_id))
                    return conn
                else:
                    _logger.error("AlwaysOnMonitor(%d): Retrying for socket connection " \
                                  % (self._cluster_id))
                    continue
            except Exception, ex:
                _logger.info("AlwaysOnMonitor(%d): Some Exception While using socket %s" % (self._cluster_id, ex))
                retry = retry + 1
                if retry >= max_retry:
                    _logger.error("AlwaysOnMonitor(%d): In Exception Failed to make connection with socket " \
                                  "Max retry limit reached:" % (self._cluster_id))
                    return conn
                else:
                    _logger.error("AlwaysOnMonitor(%d): Retrying for socket connection " \
                                  % (self._cluster_id))
            finally:
                if test_socket:
                    test_socket.close()
 
            try:
                _logger.info("AlwaysOnMonitor(%d):Check pyodbc connection ip %s and conn_str %s"
                              % ( self._cluster_id, server_ip, conn_str))
                conn = pyodbc.connect(conn_str, timeout=self._mssql_login_timeout)
                _logger.info("AlwaysOnMonitor(%d):Pyodbc connection ip %s sucessful"
                              % ( self._cluster_id, server_ip))
                break
            except Exception, ex:
                retry = retry + 1
                _logger.info("AlwaysOnMonitor(%d): Was Not Able To Connect " \
                                        ": %s" \
                                        % (self._cluster_id, ex))
        if conn:
            _logger.debug("AlwaysOnMonitor(%d): setting query timeout to %s for ip %s"
                              % ( self._cluster_id, self._mssql_query_timeout, server_ip))
            conn.timeout = self._mssql_query_timeout
        return conn

    def _create_connection_string(self):
        '''
        Create the connection string usign vnn information if available, otherwise
        connection string is created using any of the available servers. In this
        case the first available server.
        '''
        #Before getting new connection, close older one
        if self._connection:
            try:
                _logger.debug("AlwaysOnMonitor(%d): before getting new conn " \
                           "close older one" % (self._cluster_id))
                self._connection.close()
            except:
                pass

        self._conn_str = ''
        self._connection = None
        vnn_server_ip = None
        vnn_server_port = None

        if not self._is_root_account_valid():
            return

        if self._vnn_info.get('vnn_server') and self._vnn_info.get('vnn_port'):
            vnn_server_ip = self._get_proper_server_addr(self._vnn_info['vnn_server'])
            vnn_server_port = self._vnn_info.get('vnn_port')
            _logger.debug("AlwaysOnMonitor(%d): Trying to connect with VNN ip " \
                           " %s" % (self._cluster_id, vnn_server_ip))
            if vnn_server_ip:
                self._conn_str = self._get_connection_string(server_ip=vnn_server_ip,
                                                server_port=vnn_server_port)
                self._connection = self._get_connection(vnn_server_ip, vnn_server_port, self._conn_str)

            else:
                _logger.error("AlwaysOnMonitor(%d): Failed to resolve vnn " \
                    "server hostname: %s. Let's try to connect to servers in AG group"\
                    % (self._cluster_id, self._vnn_info['vnn_server']))

        if not self._connection:
 
            _logger.debug("AlwaysOnMonitor(%d): Could not make connection with VNN ip " \
                           " try with other servers" % (self._cluster_id))
            # we will create a connection string with any-of the available servers
            # that we read from sqlite
            if len(self._old_servers_list) == 0:
                    # no vnn info and no servers ? this is bad
                return

            # server_ip is stored as an instance name not as ip address.
            random.shuffle(self._old_servers_list)
            for server_info in self._old_servers_list:
                server_ip = self._get_proper_server_addr(server_info['ip'])
                if server_ip == '':
                    _logger.error("AlwaysOnMonitor(%d): Failed to resolve server_ip : %s" \
                                    % (self._cluster_id, server_info['ip']))
                    continue

                if server_ip == vnn_server_ip and \
                        server_info.get('port') == vnn_server_port:
                    continue

                _logger.info("AlwaysOnMonitor(%d): Will try to use server : %s" \
                              % (self._cluster_id, server_info['ip']))

                self._conn_str = self._get_connection_string(server_ip=server_ip,
                                            server_port=server_info['port'])
                self._connection = self._get_connection(server_ip, server_info['port'], self._conn_str)
                if self._connection:
                    
                    _logger.debug("AlwaysOnMonitor(%d): Got the connection ip " \
                           " %s" % (self._cluster_id, server_ip))
                    break

        if not self._connection:
            _logger.debug("AlwaysOnMonitor(%d): Not able to connect to VNN as well" \
                        "as any serves in VNN group. Let's try again in next cycle." \
                            % (self._cluster_id))


    def _refresh_state_data(self, force_refresh = False):
        '''
        Refresh state information every refresh_interval. Also create connection
        string with populated values.

        To minimize accesses to sqlite, we can load data from it only when there
        has been some change from our side to it, for. e.g master has changed.
        However, if we do so, then how can quickly detect a new server which was
        added to this cluster.

        For now we refresh data every cycle.
        '''
        if ((time.time() - self._last_state_updated) >= self._state_refresh_interval) \
            or force_refresh:
            _logger.info("AlwaysOnMonitor(%d): Refreshing Sqlite information and force_refresh is %s " \
                          % (self._cluster_id, force_refresh))
            _logger.debug("AlwaysOnMonitor(%d): Refreshing VNN Information " \
                          % self._cluster_id)
            self._load_vnn_info_from_sqlite()

            if self._cluster_status == STATUS_DOWN:
                _logger.debug("AlwaysOnMonitor(%d): Cluster has been stopped" \
                              % self._cluster_id)
                return

            _logger.debug("AlwaysOnMonitor(%d): Reading Servers Information" \
                          % self._cluster_id)
            self._load_servers_info_from_sqlite()

            # set the old master
            for server in self._old_servers_list:
                if server['type'] == 0:
                    self._old_master = server['ip']
                    _logger.debug("AlwaysOnMonitor(%d): Determined old primary from" \
                                  " sqlite: %s" % (self._cluster_id, self._old_master))
                    break

            self._find_root_user_info()
            self._create_connection_string()
            if self.always_on_server_type == '' and self._connection:
                _logger.debug("AlwaysOnMonitor(%d): finding cluster type" \
                              " : %s" % (self._cluster_id, self._connection))
                query = "select @@VERSION"
                self.always_on_server_type = self.find_always_on_type(self._connection, query)
                _logger.debug("AlwaysOnMonitor(%d): got cluster type" \
                              " : %s" % (self._cluster_id, self.always_on_server_type))
            self._last_state_updated = time.time()

    def find_always_on_type(self, connection, query):
        ''' Find a always_on_cluster type using version query
        '''
        result = ""
        try:
            if connection:
                cursor = connection.cursor()
                if cursor: 
                    cursor.execute(query)
                    result = cursor.fetchone()[0]
                    if result.startswith(ALWAYS_ON_2014):
                        return ALWAYS_ON_2014
                    elif result.startswith(ALWAYS_ON_2012):
                        return ALWAYS_ON_2012
                    else:
                        _logger.debug("AlwaysOnMonitor(%d): server type is %s" \
                                  % (self._cluster_id, result))
                        return ""
            else:
                _logger.debug("AlwaysOnMonitor(%d): No connection found" \
                                  % (self._cluster_id))
        except Exception, ex:
            _logger.debug("AlwaysOnMonitor(%d): Exception while calculating always" \
                          " type: %s" % (self._cluster_id))
        finally:
            if cursor:
                cursor.close()
        return ""
        
    def find_primary_server(self):
        ''' Executing Query for finding out Primary server
        ''' 
        new_primary_server = ''
        try:
            cursor = self._connection.cursor()
            if self._vnn_info.get('group_id'):
                query = "select endpoint_url from sys.availability_replicas "\
                           "where replica_server_name = (select primary_replica "\
                           "from sys.dm_hadr_availability_group_states where group_id='%s') "\
                           "and group_id='%s'" % (self._vnn_info.get('group_id'),
                                                   self._vnn_info.get('group_id'))
            else:
                query = "select endpoint_url from sys.availability_replicas "\
                        "where replica_server_name = (select primary_replica "\
                        "from sys.dm_hadr_availability_group_states)"""
                 
            _logger.debug("AlwaysOnMonitor(%d): Query for finding Primary server  " \
                           " %s" % (self._cluster_id, query))
            cursor.execute(query)
            row = cursor.fetchone()
            
            _logger.debug("AlwaysOnMonitor(%d): Result of Query Primary server" \
                           " %s info" % (self._cluster_id, row))
            if row:
                new_primary_server = self._parse_hostname_from_endpoint_url(row[0])
                primary_ip = new_primary_server
                primary_port = self._get_server_port(primary_ip)
            _logger.debug("AlwaysOnMonitor(%d): new primary server is " \
                           " %s " % (self._cluster_id, new_primary_server))
        except Exception, ex:
            _logger.error("AlwaysOnMonitor(%d): Problem determining current primary " \
                            "server: %s" % (self._cluster_id, traceback.format_exc()))
        finally:
            cursor.close()
            return new_primary_server

    def find_servers_role_type(self):
        '''Now read all servers information including their roles
        '''
        new_servers_list = []
        try:
            cursor = self._connection.cursor()
            if self._vnn_info.get('group_id'):
                query = "select endpoint_url, primary_role_allow_connections_desc, "\
			"secondary_role_allow_connections_desc from " \
                        "sys.availability_replicas where group_id='%s'" \
			             % (self._vnn_info.get('group_id'))
            else:
                query = "select endpoint_url, primary_role_allow_connections_desc, "\
                        "secondary_role_allow_connections_desc from "\
                        "sys.availability_replicas"
            _logger.debug("AlwaysOnMonitor(%d): Query for servers and their roles" \
                          " %s with agid" % (self._cluster_id, query))
            cursor.execute(query)
            _logger.debug("AlwaysOnMonitor(%d): executed Query for servers and roles" \
                               " info" % (self._cluster_id))
            rows = cursor.fetchall()
            for endpoint_url, primary_role, secondary_role in rows:
                d = {}
                d['ip'] = self._parse_hostname_from_endpoint_url(endpoint_url)

                # determine whether it's primary or secondary
                if d['ip'] == self._new_primary_server:
                    d['type'] = PRIMARY
                else:
                    d['type'] = SECONDARY

                # determine the role of this server
                if d['type'] == PRIMARY:
                    d['role'] = PRIMARY_ROLE_MAP[primary_role] # READ_WRITE/ALL
                else:
                    d['role'] = SECONDARY_ROLE_MAP[secondary_role] # NO/ALL/READ_ONLY

                new_servers_list.append(d)
            
        except Exception, ex:
            _logger.error("AlwaysOnMonitor(%d): Exception while reading role " \
                          "information from server: %s" % (self._cluster_id, traceback.format_exc()))
        finally:
            cursor.close()
            return new_servers_list
    
    def _retrieve_latest_server_stats(self):
        ''' Get latest server stats from sqlserver
        '''
        #self._new_primary_server = ''
        self._new_primary_server = self.find_primary_server()
        if self._new_primary_server == '':
            return
        self._primary_ip = self._new_primary_server
        self._primary_port = self._get_server_port(self._primary_ip)

        self._new_servers_list = []
        self._new_servers_list = self.find_servers_role_type()

        try: 
            _logger.debug("AlwaysOnMonitor(%d): Reading health Information" \
                               " for all servers" % (self._cluster_id))
            self._get_health_info_servers(multigevent=True)
        except Exception, ex:
            _logger.error("AlwaysOnMonitor(%d): Problem while reading health status " \
                          "information from server: %s" % (self._cluster_id, ex))
           
        _logger.debug("AlwaysOnMonitor(%d): New servers list: %s" \
                      % (self._cluster_id, self._new_servers_list))

    def _get_role_of_server(self, server):
        '''
        Return role of old primary server. Note that role of a server whether
        new primary or old primary is always decided by looking up in new_servers_list
        since this list is latest.
        '''
        for item in self._new_servers_list:
            if item['ip'] == server:
                return item['role']
        return -1

    def _process_primary_server_change(self):
        '''
        Perform related changes as there has been a new primary server. We need
        to save this information in sqlite and form the message string to be sent
        to core.

        Probably we dont need to form the msg string here. Even for primary server
        change it will be detected
        '''
        self._msg_for_core = ''
        #
        # we hope that that server name loaded from sqlite will always be as a
        # host name not an ip. This is important since we get host names only
        # from remote server.
        #
        if self._new_primary_server == '':
            _logger.warn("AlwaysOnMonitor(%d): No primary server Found" \
                         % self._cluster_id)
            return False

        # what if we get a primary  server that is not present in our database
        local_servers_list = [ x['ip'] for x in self._old_servers_list ]
        if self._new_primary_server not in local_servers_list:
            _logger.error("AlwaysOnMonitor(%d): Does not recognize server: %s." \
                          " Can't set it as new primary server." \
                          % (self._cluster_id, self._new_primary_server))

        # now we have a valid primary server
        if self._old_master == self._new_primary_server:
            _logger.info("AlwaysOnMonitor(%d): No change in primary server." \
                          % self._cluster_id)
            self._msg_for_core = ''
            return True

        _logger.info("AlwaysOnMonitor(%d): Old master: %s new master : %s" \
                      % (self._cluster_id, self._old_master, \
                         self._new_primary_server))
        #
        # a primary change will trigger two changes- old primary will be a
        # secondary and some secondary will be new primary
        #

        #
        # There might be a initial condition where no server is primary i.e. all
        # are secondary roles. In this case, the next primary will be set in
        # coming cycles.
        #

        # create msg part for primary to secondary transition
        server_id = self._get_serverid(self._old_master)
        if server_id == -1:
            _logger.error("AlwaysOnMonitor(%d): Could not find serverid for " \
                          "server (old_primary): '%s'" % (self._cluster_id, \
                                          self._old_master))
            self._msg_for_core = ''

        role = self._get_role_of_server(self._old_master)
        if role == -1:
            _logger.error("AlwaysOnMonitor(%d): Could not find role for " \
                          "server (old_primary): '%s'" % (self._cluster_id, \
                                          self._old_master))
            self._msg_for_core = ''

        if server_id != -1 and role != -1:
            health_status = self._health_status.get(self._old_master, [0])[0]
            s = '%d:%d:%d:%d|' % (server_id, SECONDARY, role, health_status )
            self._msg_for_core = self._msg_for_core + s

        # create msg part for secondary to primary transition
        server_id = self._get_serverid(self._new_primary_server)
        if server_id == -1:
            _logger.error("AlwaysOnMonitor(%d): Could not find serverid for " \
                          "server (new_primary): %s" % (self._cluster_id, \
                                          self._new_primary_server))

        role = self._get_role_of_server(self._new_primary_server)
        if role == -1:
            _logger.error("AlwaysOnMonitor(%d): Could not find role for " \
                          "server (new_primary): %s" % (self._cluster_id, \
                                          self._old_master))
        if server_id != -1 and role != -1:
            health_status = self._health_status.get(self._new_primary_server, [0])[0]
            s = '%d:%d:%d:%d|' % (server_id, PRIMARY, role, health_status )
            self._msg_for_core = self._msg_for_core + s

        # now make corresponing changes to sqlite
        _logger.debug("AlwaysOnMonitor(%d): Will set server: %s with serverid: " \
                      "%d as new primary" % (self._cluster_id, \
                                             self._new_primary_server, \
                                             server_id))
        return True

    def _get_serverid(self, server):
        '''
        Return serverid by looking up server in self._old_servers_list
        '''
        for item in self._old_servers_list:
            #
            # Fix for IDB-5689
            #
            if item['ip'] == server:
                return item['serverid']
        return -1
    
    def _get_server_port(self, ip):
        '''
        Return serverid by looking up server in self._old_servers_list
        '''
        for item in self._old_servers_list:
            #
            # Fix for IDB-5689
            #
            if item['ip'] == ip:
                return item['port']
        return -1

    def _process_role_and_health_change(self):
        '''
        Process role change for servers by comparing the self._old_servers_list
        against self._new_servers_list.

        For every server in self._old_server_list, first check if the type has
        changed, if yes then in msg string, type will be of the new server.
        If type has not changed then check if role has changed.
        If any server from old list is not in new list, we give a warning
        that 'info for this server is missing' and continue with further
        processing.
        Check Health status change in old servers list that we got from
            sqlite and _health_status dict that we got from db servers
        '''
        # we will assume self._old_servers_list as the base reference for
        # comparison
        role_change_list = []
        old_servers_ip_list = [] 
        new_servers_ip_list = []
        
        for old_server in self._old_servers_list:
            server_found_in_newlist = False
            old_servers_ip_list.append(old_server['ip'])

            for new_server in self._new_servers_list:
                if new_server['ip'] not in new_servers_ip_list:
                    new_servers_ip_list.append(new_server['ip'])
                     
                if old_server['ip'] == new_server['ip']:
                    _logger.info("AlwaysOnMonitor(%d): Check between old " \
                          "server %s and new server %s changes " \
                           % (self._cluster_id, old_server, new_server))
                    server_found_in_newlist = True
                    # determine serverid
                    server_id = self._get_serverid(new_server['ip'])
                    if server_id == -1:
                        _logger.error("AlwaysOnMonitor(%d): Failed to determine" \
                                        " serverid of server: %s" \
                                        % (self._cluster_id, new_server['ip']))
                        break

                    #
                    # We will only detect role change in this routine. Since we
                    # have already dealt with type change, we will skip considering
                    # servers whose type have changed since these will be those
                    # two servers (secondary->primary) and (primary->secondary)
                    #
                    health_status = self._health_status.get(old_server['ip'], [0])[0]
                    _logger.debug("AlwaysOnMonitor(%d): Health status for ip %s is %s where health_dict is %s" \
                          % (self._cluster_id, old_server['ip'], health_status, self._health_status))
               
                    if old_server['type'] != new_server['type']:
                        break

                    if old_server['role'] != new_server['role'] :
                        msg = ''
                        try:
                            msg = '%d:%d:%d:%d|' % (server_id, new_server['type'], \
                                                 new_server['role'], health_status)
                            role_change_list.append(msg)
                        except Exception, ex:
                            _logger.error("AlwaysOnMonitor(%d): Problem generating" \
                                         " role change string. %s" \
                                         % self._cluster_id, ex)
                    elif self._health_status:
                        if (health_status != old_server.get('health_status')):
                            msg = ''
                            try:
                                _logger.info("AlwaysOnMonitor(%d): Health status is changed for ip %s to %s where health_dict is %s \
                                              and old_server health is %s"
                                     %(self._cluster_id, old_server['ip'], health_status, self._health_status, \
                                       old_server.get('health_status')))
                                msg = '%d:%d:%d:%d|' % (server_id, new_server['type'], \
                                                     new_server['role'], health_status)
                                role_change_list.append(msg)
                            except Exception, ex:
                                _logger.error("AlwaysOnMonitor(%d): Problem generating" \
                                             " health status change string. %s" \
                                             % self._cluster_id, ex)
    
                    # we break out of loop since we have found the server in newlist
                    break
 
            if not server_found_in_newlist:
                msg = ''
                try:
                    tmp_del_dict = {'cluster_id':'', 'server_id':'', 'server_ip': ''}
                    # Server Not found case we are marking server down
                    _logger.warn("AlwaysOnMonitor(%d): Server %s not found in " \
                             "latest server list and remove that server from config" % (self._cluster_id, \
                                                      old_server['ip']))
                    server_id = self._get_serverid(old_server['ip'])
                    cluster_server_id_dict = deepcopy(tmp_del_dict)
                    cluster_server_id_dict['cluster_id'] = self._cluster_id
                    cluster_server_id_dict['server_id'] = server_id
                    cluster_server_id_dict['server_ip'] = old_server['ip']
                    self._delete_servers_from_config.append(cluster_server_id_dict)
                except Exception, ex:
                    _logger.error("AlwaysOnMonitor(%d): Problem generating" \
                                             " in deleted server string. %s" \
                                             % self._cluster_id, ex)
        try:
            # Check any server is added in AlwaysOn AG
            if len(self._new_servers_list) != len(new_servers_ip_list): 
                for new_server in self._new_servers_list:
                    if new_server['ip'] not in new_servers_ip_list:
                        new_servers_ip_list.append(new_server['ip'])

            old_servers_ip_set = set(old_servers_ip_list)
            new_servers_ip_set = set(new_servers_ip_list)
            self._found_new_servers = new_servers_ip_set.difference(old_servers_ip_set)
    
            if len(self._found_new_servers) > 0:
                _logger.debug("AlwaysOnMonitor(%d): Found new Server on AlwaysOn AG %s " \
                              "detected in cluster" % (self._cluster_id, self._found_new_servers))

            if len(self._delete_servers_from_config) > 0:
                _logger.debug("AlwaysOnMonitor(%d): Found some Server removed on AlwaysOn AG %s " \
                              "detected in cluster" % (self._cluster_id, self._delete_servers_from_config))
        except Exception, ex:
            _logger.error("AlwaysOnMonitor(%d): Exception in calculated newly added server %s" %(self._cluster_id, ex))

        if len(role_change_list) == 0 and self._msg_for_core == '':
            _logger.debug("AlwaysOnMonitor(%d): No server type or role change " \
                          "detected in cluster" % self._cluster_id)
            return

        _logger.info("AlwaysOnMonitor(%d): Role/connection settings change detected: %s" \
                      % (self._cluster_id, role_change_list))

        # form the msg string to sent to core
        for t in role_change_list:
            self._msg_for_core = self._msg_for_core + t

    def _inform_core_about_role_change(self):
        '''
        There has been role change and command to inform core of the same is
        present in self._msg_for_core. Deliver the same to core.

        prepend header as well
        header = "always_on_monitor|%d|" % self._cluster_id
        self._msg_for_core = header + self._msg_for_core
        '''
        header = "always_on_failover|%d|" % self._cluster_id
        self._msg_for_core = header + self._msg_for_core
        _logger.info("AlwaysOnMonitor(%d): Sending msg to core: %s" \
                      % (self._cluster_id, self._msg_for_core))

        response = util.socket_cmd_runner(unix_sock="/tmp/lb_sock",
                                            command=self._msg_for_core)
        if response != "SUCCESS":
            _logger.error("AlwaysOnMonitor(%d): Failed to inform core about" \
                          " server role/type : %s" \
                          % (self._cluster_id, response))
        self._msg_for_core = ''

    def _writeback_changes_to_sqlite(self):
        '''
        Before informing about change we will first write the changes that we
        have into the sqlite file. Return true/false depending upon whether
        this operation was successful.

        Note self._msg_for_core is a string containing data which denote the
        change in type/role. The format of this string will be
        112:0:2:1|127:1:4:1|156:1:5:0|172:1:27:1|
        Fourth bit contains the health_status
        '''
        if self._msg_for_core == '':
            return False

        _logger.debug("AlwaysOnMonitor(%d): Going to  write : %s" \
                      % (self._cluster_id, self._msg_for_core))

        # lets split the message string and for list of queries
        sub_msg_list = self._msg_for_core.split('|')
        query_list = []
        for item in sub_msg_list:
            if item != '':
                t = item.split(':') # t = ['112', '0', '2', 1], serverid, type, role and health_status
                query = "update lb_servers set type=%s, sql2012_role_setting=%s," \
                        "health_status=%s where clusterid=%d and status=1 and serverid=%s" \
                        % (t[1], t[2], t[3], self._cluster_id, t[0])
                query_list.append(query)

        db_handle = util.get_sqlite_handle(self._lb_dbname, timeout = 0.1)
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
                        _logger.error("AlwaysOnMonitor(%d): Failed to update server role/type " \
                                      "change in sqlite: %s" % (self._cluster_id, e))
                        break

                    retry = retry + 1
                    if retry >= MAX_RETRY:
                        _logger.error("AlwaysOnMonitor(%d): Failed to update " \
                                      "server tole/type change info. Database is locked. " \
                                      "Max retry limit reached:" % (self._cluster_id))
                        return False
                    else:
                        time.sleep(0.1)
            util.close_sqlite_resources(db_handle, db_cursor)
            return True
        else:
            return False

    def monitor_server_role_change(self):
        '''
        Perform the monitoring by going in an infinite loop.
        '''
        while True:
            if gSignalChildToQuit:
                #
                # Since in this case, other threads can safely be killed as there
                # is no risk of data loss, but a simple such mechanism can be built.
                # For e.g. gSignalChildToQuit will signal all threads to begin
                # prepairing to exit and then one special thread(thread_pool_manager
                # in this case), can set another flag gShutdownOK. When this flag
                # set , we will exit this process. For now, quit.
                #

                _logger.info("AlwaysOnMonitor(%d): Got signal. Exiting now " \
                             % (self._cluster_id))
                sys.exit()

            if not self._is_parent_alive():
                _logger.info("AlwaysOnMonitor(%d): Parent is gone away.. " \
                             "Exiting now" % self._cluster_id)
                return

            # 1. refresh state data
            self._refresh_state_data()

            if self._cluster_status == STATUS_DOWN:
                _logger.error("AlwaysOnMonitor(%d): Cluster down, Exiting Now" % self._cluster_id)
                sys.exit()

                #time.sleep(1)
                #continue

            if self._connection and self._conn_str == '':
                _logger.error("AlwaysOnMonitor(%d): Invalid " \
                              "connection string " % self._cluster_id)
                time.sleep(1)
                continue

            # 2. now get latest info about server roles
            _logger.info("AlwaysOnMonitor(%d): *Start* Retrieving latest server stats" \
                          % self._cluster_id)
            self._retrieve_latest_server_stats()
            
            # Check for resolving state of the server 
            try:
                if self._check_resolving_state_inform_core():
                    time.sleep(1)
                    continue
                else:
                    _logger.info("AlwaysOnMonitor(%d): Cluster not Resolving State where Primary Server is %s" \
                          % (self._cluster_id, self._new_primary_server))
            except Exception, ex:
                _logger.error("AlwaysOnMonitor(%d): Error in check resolving stats %s" \
                          % (self._cluster_id, ex))
                

            # reset msg to be sent to core
            self._msg_for_core = ''

            # detect any change in primary server for this cluster.
            _logger.info("AlwaysOnMonitor(%d): Checking primary server role changes if any" \
                          % self._cluster_id)
            
            if not self._process_primary_server_change():
                time.sleep(1)
                continue

            # 3. now find any change in roles.
            _logger.info("AlwaysOnMonitor(%d): Checking role and health changes for all" \
                          "servers if any" % self._cluster_id)
            self._process_role_and_health_change()
            
            if self._writeback_changes_to_sqlite():
                # 4. if writeback to sqlite was successful then lets inform core
                # of the same.
                self._inform_core_about_role_change()
                #Refresh state data forecefully
                self._refresh_state_data(True)

            # Process any server added or deleted   
            self._check_server_add_or_del() 
            # sleep for a while and then begin the cycle
            time.sleep(1)

    def _check_server_add_or_del(self):
        ''' Send UI alert for server addition or deletion
        '''
        try:
            # check any server is deleted from AlwaysOn AG
            while self._delete_servers_from_config:
                del_server_dict = self._delete_servers_from_config.pop()
                if del_server_dict['server_ip'] not in self._ui_alert_for_del_servers:
                    _logger.warn("AlwaysOnMonitor(%d): Delete servers from " \
                              " form ScaleArc Configuration and del dict is %s" % (self._cluster_id, del_server_dict))
                    res = self._do_deletion(del_server_dict['cluster_id'], del_server_dict['server_id'])
                    _logger.debug("AlwaysOnMonitor(%d): API Response for server deletion is %s" %(self._cluster_id, res))
                    if res['success']:
                        self._send_alert_about_server_status("deleted_server", del_server_dict['server_ip'], del_server_dict['server_id'])
                        self._ui_alert_for_del_servers[del_server_dict['server_ip']] = 1
                             
            # Check any server is added on AlwaysOn AG
            while self._found_new_servers:
                newserver_ip = self._found_new_servers.pop()
                if newserver_ip not in self._ui_alert_for_add_servers:
                    _logger.warn("AlwaysOnMonitor(%d): Added servers On " \
                              " Always On AG, Not going to add on scalearc configuration %s" % (self._cluster_id, newserver_ip))
                    servers_count = len(self._ui_alert_for_add_servers)
                    self._send_alert_about_server_status("added_server", newserver_ip, servers_count)
                    self._ui_alert_for_add_servers[newserver_ip] = 1
        except Exception, ex:
            _logger.error("AlwaysOnMonitor(%d): Exception while sending alert %s" %(self._cluster_id, ex))
            
    def _check_resolving_state_inform_core(self):
        '''
        This Function check for resolving state of the any server
        If it finds any server then mark all the server down
        '''
        result = False
        if not self._new_primary_server:
            result = True
            _logger.info("AlwaysOnMonitor(%d): Start Reslove Check Type is %s Resolving No primary server" \
                          % (self._cluster_id, self.always_on_server_type))
            role_change_list = []
            self._msg_for_core = ''
            if self.always_on_server_type == ALWAYS_ON_2014:
                _logger.info("AlwaysOnMonitor(%d):2014: Checking alwayson 2014" \
                          % self._cluster_id)
                try:
                    _logger.debug("AlwaysOnMonitor(%d):2014: Start a process with timeout 10 sec" \
                                 % self._cluster_id)
                    gevent.with_timeout(10, self.read_servers_health_using_gevent)
                    _logger.debug("AlwaysOnMonitor(%d):2014: End a process with timeout 10 sec" \
                                 % self._cluster_id)
                except Timeout:
                    _logger.error("AlwaysOnMonitor(%d):2014: Timeout at gevent to see the health" \
                                 % self._cluster_id)
                except Exception, ex:
                    _logger.error("AlwaysOnMonitor(%d):2014: Exception at gevent start %s" \
                                 % (self._cluster_id, ex))
                finally:
                    _logger.debug("AlwaysOnMonitor(%d):2014: Stopping all the Gevents" \
                                 % self._cluster_id)
                    self.stop_threads()
                _logger.debug("AlwaysOnMonitor(%d):2014: gevent results are %s" \
                                % (self._cluster_id, self.health_queue))
                _logger.debug("AlwaysOnMonitor(%d):2014 old server results are %s" \
                                % (self._cluster_id, self._old_servers_list))
                _logger.debug("AlwaysOnMonitor(%d):2014 Start Processing Queue Results" \
                                % (self._cluster_id))
                for health_dict in self.health_queue.queue:
                    _logger.debug("AlwaysOnMonitor(%d): 2014 health dict %s " 
                                  % (self._cluster_id, health_dict))
                    if not health_dict:
                        continue
                    health_status = 0
                    msg = ''
                    try:
                        server_ip = health_dict['ip']
                        server_id = health_dict['serverid']
                        try:
                            health_status, role, op_state = health_dict['new_health_info']
                            _logger.error("AlwaysOnMonitor(%d):2014: got new health info" \
                                          " server_ip %s connected_state %s role %s op_state %s" \
                                          %(self._cluster_id, server_ip, health_status, role, op_state))
                        except Exception, ex:
                            _logger.error("AlwaysOnMonitor(%d):2014: Exception reading health %s" \
                                 % (self._cluster_id, ex))
                            continue
                          
                        for old_server in self._old_servers_list:
                            new_status = 0
                            if old_server['ip'] == server_ip:
                                if health_status == RESOLVING_ROLE:
                                    if (op_state in HEALTH_DOWN_OP_STATE) or \
                                            (op_state == OFFLINE and old_server['type'] == PRIMARY):
                                        new_status = 0
                                    elif op_state in HEALTH_UP_OP_STATE:
                                        new_status = 1
                                    else:
                                        new_status = 1

                                    _logger.debug("AlwaysOnMonitor(%d):2014: Health of the" \
                                                  " server has changed server id is %s" \
                                                  % (self._cluster_id, server_id))
                                    msg = '%d:%d:%d:%d|' % (server_id, old_server['type'], \
                                                       old_server['role'], new_status)
                                    role_change_list.append(msg)
                                    break
                                else:
                                    _logger.debug("AlwaysOnMonitor(%d): 2014 health status not 0 for server ip %s " \
                                                     % (self._cluster_id, server_ip))
                    except Exception, ex:
                        _logger.error("AlwaysOnMonitor(%d):2014: Problem generating" \
                                                 " health staus change string. %s" \
                                                 % (self._cluster_id, ex))
                _logger.debug("AlwaysOnMonitor(%d):2014 End Processing Queue Results" \
                                % (self._cluster_id))
            else:
                _logger.info("AlwaysOnMonitor(%d): Checking alwayson 2012" \
                          % self._cluster_id)
                role_change_list = self.always_on_2012_resolve_check()
            
            # form the msg string to sent to core
            for t in role_change_list:
                _logger.debug("AlwaysOnMonitor(%d): Resolve Process role change list and build msg %s" \
                              % (self._cluster_id, t))
                self._msg_for_core = self._msg_for_core + t
            
            if self._msg_for_core:
                _logger.info("AlwaysOnMonitor(%d): 2014 Resolve new msg is %s" 
                           % (self._cluster_id, self._msg_for_core))   
                if self._writeback_changes_to_sqlite():
                    
                    _logger.debug("AlwaysOnMonitor(%d): Writeback to sqlite " \
                               " for changes" % (self._cluster_id))
                    # if writeback to sqlite was successful then lets inform core
                    # of the same.
                    self._inform_core_about_role_change()
                    #Refresh state data forecefully
                    self._refresh_state_data(True)
                    _logger.debug("AlwaysOnMonitor(%d): Resolve Inform to core and set resolving state" \
                                   % self._cluster_id)
                    result = True

            _logger.info("AlwaysOnMonitor(%d): Exit form resolve check" % self._cluster_id)   
            self._msg_for_core = ''
        return result
    
    def _do_deletion(self, cluster_id, server_id):
        ip_addr = '127.0.0.1'
        master_base_url_path = '/api/cluster/' + str(cluster_id) + '/server/' + str(server_id) + '?apikey=%s' %APIKEY 
        data_dict = {}
        #data_dict["apikey"] = APIKEY
        res = self._exec_url_generic(ip_addr, master_base_url_path, json.dumps(data_dict), 'DELETE')
        res = self._exec_url_generic(ip_addr, master_base_url_path, json.dumps(data_dict), 'DELETE')
        _logger.debug("AlwaysOnMonitor(%d): Result from API for server delete is %s" \
                                   % (self._cluster_id, res))
        return res

    def _exec_url_generic(self, ip_addr, base_url_path, data_dict, method='PUT'):
        '''
        Makes an http call with the specified method and returns the result.
        '''
        result = 'Failed to make http call.'
        try:
            conn = httplib.HTTPSConnection(ip_addr)
            conn.request(method, base_url_path, data_dict)
            response = conn.getresponse()
            result = json.loads(response.read())
        except Exception, ex:
            _logger.error("Failed to make http call: %s" % ex)
            result = result
        return result
    
    def _send_alert_about_server_status(self, msg_header, server_ip, server_id=0):
        ''' Send alert to alert_engine service
        '''
        msg_dict = {
                   "deleted_server":"ScaleArc detected that server %s is removed from AlwaysOn Group %s. "\
                   "It has been deleted from the ScaleArc cluster configuration.",
                   "added_server": "ScaleArc detected that a new server %s was added on AlwaysOn Group %s. Please add it to the ScaleArc cluster configuration.",
                   }
        message = msg_dict[msg_header]
        message = message % (server_ip, self._vnn_info.get('vnn_server'))
        _logger.info("AlwaysOnMonitor(%d): ALERTMSG: Server Status is change %s" % (self._cluster_id, message))
        
        #Sending alert to UI
        if msg_header == "deleted_server":
            msg_type = str(SystemMonitorStat.SERVER_DELETED_FROM_ALWAYSON)
        else:
            msg_type = str(SystemMonitorStat.SERVER_ADDED_ON_ALWAYSON)
        result = self.events.send_event(message, int(msg_type), clusterid=self._cluster_id, serverid=server_id)
        _logger.info("AlwaysOnMonitor(%d): response from API for sending events %s" % (self._cluster_id, result))

    def read_servers_health_using_gevent(self):
        '''
        This Function check for resolving state and health 
        report the health 
        '''
        i = 0
        for old_server in self._old_servers_list:
            name = 'gevent' + str(i)
            i = i + 1
            _logger.info("AlwaysOnMonitor(%d): Added greenlet for %s name is %s" \
                              % (self._cluster_id, old_server, name))
            self.threads_list.append(gevent.spawn(self.check_secondary_servers_health, old_server, name))
        _logger.debug("AlwaysOnMonitor(%d): emptying the queue" % self._cluster_id)
        self.health_queue.queue.clear()
        while self.health_queue.qsize() < len(self._old_servers_list):
            _logger.debug("AlwaysOnMonitor(%d): Queue size less then " \
                           "number of servers %s and lenth of queue %s" \
                           % (self._cluster_id, len(self._old_servers_list), self.health_queue.qsize()))
	    gevent.sleep(1)
               
    def always_on_2012_resolve_check(self):
        '''
        This Function check for resolving state of the any server
        If it finds any server then mark all the server down
        '''
        role_change_list = []
        self._get_health_info_servers(self._connection)
        _logger.debug("AlwaysOnMonitor(%d): 2012R Got new health status %s" \
                       % (self._cluster_id, self._health_status))
        all_server_in_resolving_state = False
        for ip, values in self._health_status.iteritems():
            role = values[1]
            if role == RESOLVING_ROLE: # For resolving state 
                _logger.debug("AlwaysOnMonitor(%d): 2012R Found server in resolving role %s" \
                          % (self._cluster_id, ip))
                all_server_in_resolving_state = True
                break
             
        if all_server_in_resolving_state:
            for old_server in self._old_servers_list:
                msg = ''
                health_status = 0
                try:
                    _logger.info("AlwaysOnMonitor(%d): 2012R Health status is changed to 0 for server %s " 
					% (self._cluster_id, old_server['ip']))
                    server_id = self._get_serverid(old_server['ip'])
                    msg = '%d:%d:%d:%d|' % (server_id, old_server['type'], \
                                           old_server['role'], health_status)
                    role_change_list.append(msg)
                except Exception, ex:
                    _logger.error("AlwaysOnMonitor(%d): 2012R Problem generating" \
                                             " health staus change string. %s" \
                                             % self._cluster_id, ex)

        return role_change_list

    def check_secondary_servers_health(self, old_server, name):
        ''' Check health of all the servers those are configured
            into sqlite file and put the result into the queue
        '''
        try:
            server_info = deepcopy(old_server)
            ip = server_info['ip']
            port = server_info['port']
            conn_str = self._get_connection_string(server_ip=ip,
                                            server_port=port)
            _logger.debug("AlwaysOnMonitor(%d): %s try to get the connection" \
                                  % (self._cluster_id, name)) 
            connection = self._get_connection(ip, port, conn_str)
            _logger.debug("AlwaysOnMonitor(%d): %s got the connection" \
                                  % (self._cluster_id, name)) 
            if connection:
                check_ip = False
                _logger.debug("AlwaysOnMonitor(%d): %s try to get health info " \
                                  % (self._cluster_id, name)) 
                health_status_info = self._get_health_info_servers(connection)
                _logger.debug("AlwaysOnMonitor(%d): %s got the health info %s" \
                                  % (self._cluster_id, name, health_status_info)) 
                if health_status_info:
                    for server_ip, values in health_status_info.iteritems():
                        if server_ip == ip:
                            _logger.info("AlwaysOnMonitor(%d): %s set the new health values %s"  
                                           % (self._cluster_id, name, values)) 
                            server_info["new_health_info"] = values
                            check_ip = True
                            break
                    if not check_ip:
                       _logger.debug("AlwaysOnMonitor(%d): %s Could not found IP in response %s" \
                                    % (self._cluster_id, name, health_status_info))
                else:
                    _logger.debug("AlwaysOnMonitor(%d): %s Empty response from health query setting server OFFLINE" \
                                  % (self._cluster_id, name))
                    server_info["new_health_info"] = [0, 0, 3]
            else:        
                _logger.error("AlwaysOnMonitor(%d): %s Connection Not found while connecting secondry setting server FAILED" \
                              % (self._cluster_id, name))
                server_info["new_health_info"] = [0, 0, 4]
            _logger.info("AlwaysOnMonitor(%d): %s putting into the queue %s" \
                                   %(self._cluster_id, name, server_info))
            self.health_queue.put_nowait(server_info)
        except Exception, ex:
            _logger.error("AlwaysOnMonitor(%d): %s Exception while Health check %s put empty dict" \
                         % (self._cluster_id, name, ex)) 
            self.health_queue.put_nowait({})

    def stop_threads(self):
        ''' Stop all the greenlets
        '''
        gevent.killall(self.threads_list)   
        _logger.info("AlwaysOnMonitor(%d):2014: stopped all greenlets" \
                      % self._cluster_id)
 
def read_pid(pidfile):
    if pidfile:
        if not os.path.exists(pidfile):
            return False
        try:
            pf = file(pidfile,'r')
            pid = int(pf.read().strip())
            pf.close()
            return pid
        except Exception, ex:
            _logger.error("Failed to read pid from %s" 
                                       % (pidfile,))
    return None


def cleanup_monitor_process(signum, frame):
    '''
    Cleanup marker file if it was found.
    '''
    global gSignalChildToQuit
    gSignalChildToQuit = True
    pid = os.getpid()
    try:
        if read_pid(gMonitorProcessMarkerFile) == pid:
            os.remove(gMonitorProcessMarkerFile)
        else:
            _logger.debug("Markerfile pid not match with the current process pid")
    except Exception, ex:
        _logger.error('Failed to remove marker file: %s' % gMonitorProcessMarkerFile)

def always_on_monitor_routine(cluster_id, parent_pid):
    '''
    The Main Function which does the monitoring of the server role change over
    the VNN
    '''
    # set the marker file
    global gMonitorProcessMarkerFile
    gMonitorProcessMarkerFile = "/var/run/always_on_monitor_%d.file" % cluster_id

    #  try to create marker file
    if os.path.exists(gMonitorProcessMarkerFile) == False:
        try:
            fp = open(gMonitorProcessMarkerFile, "w")
            fp.write(str(os.getpid()))
            fp.close()
        except:
            _logger.error("AlwaysOnMonitor(%d): Failed to create marker file %s" \
                          % (cluster_id, gMonitorProcessMarkerFile))
            sys.exit(1)
    else:
        _logger.warn("AlwaysOnMonitor(%d): Marker file already in use. " \
                     "Exiting now" % cluster_id)
        sys.exit(0)

    # resgister to handle SIGTERM & SIGHUP
    signals = [signal.SIGTERM, signal.SIGHUP ]
    for s in signals:
        signal.signal(s, cleanup_monitor_process)

    aom_object = AlwaysOnMonitorUtils(cluster_id, parent_pid)
    try:
        aom_object.monitor_server_role_change()
    except Exception, ex:
        _logger.error("AlwaysOnMonitor(%d): Instance failed: %s" \
                      % (cluster_id, ex))
        _logger.error("%s" % (traceback.format_exc(),))

    # if we are here then we need to exit, probably because parent is gone away.
    try:
        os.remove(gMonitorProcessMarkerFile)
    except Exception, ex:
        _logger.error("AlwaysOnMonitor(%d): Failed to remove marker " \
                        "file." % cluster_id)
    sys.exit(0)

class AlwaysOnMonitorDaemon(daemon.Daemon):
    """This class runs AlwaysOnMonitor as a daemon
    """
    def get_list_of_cluster_ids(self):
        '''
        Return list of active as well as stopped cluster ids.
        '''
        running_cluster_ids = []
        stopped_cluster_ids = []
        sqlite_handle = util.get_sqlite_handle(GLOBAL_LB_SQLITE_FILE)
        if sqlite_handle:
            db_cursor = sqlite_handle.cursor()
            query = "select cluster_id,status from lb_clusters_summary where status<>9 and type=?"
            retry = 0
            while retry < MAX_RETRY:
                try:
                    db_cursor.execute(query, (PLATFORM_TYPE,))
                    for row in db_cursor.fetchall():
                        if int(row['status']) == STATUS_UP:
                            running_cluster_ids.append(int(row['cluster_id']))
                        else:
                            stopped_cluster_ids.append(int(row['cluster_id']))

                    break
                except Exception, ex:
                    retry = retry + 1
                    if retry >= MAX_RETRY:
                        _logger.error("Failed to find list of all clusters: %s" % ex)
                    else:
                        time.sleep(0.1)

            util.close_sqlite_resources(sqlite_handle, db_cursor)
        return running_cluster_ids, stopped_cluster_ids

    def _read_always_on_status(self, clusterid):
        '''
        Check whether cluster is always on or not from sqlite of each cluster
        '''

        alwayson_status = False
        query = "select alwayson from lb_clusters where clusterid=?"

        sqlite_handle = util.get_sqlite_handle(LB_SQLITE_FILE % clusterid)
        if sqlite_handle:
            db_cursor = sqlite_handle.cursor()
            retry = 0
            while retry < MAX_RETRY:
                try:
                    db_cursor.execute(query, (clusterid,))
                    row = db_cursor.fetchone()
                    if row:
                        alwayson_status = True if int(row['alwayson']) else False
                    break
                except Exception, ex:
                    retry = retry + 1
                    if retry >= MAX_RETRY:
                        _logger.error("Failed to read always_on status of" \
                                      " clusters: %s" % ex)
                    else:
                        time.sleep(0.1)

            util.close_sqlite_resources(sqlite_handle, db_cursor)
        return alwayson_status

    def _cleanup_marker_files(self):
        '''
        Remove all marker files in use by always_on_service or its children
        '''
        fl = glob.glob('/var/run/always_on_monitor*')
        for _file in fl:
            if os.path.exists(_file):
                os.remove(_file)

    def _stop_monitor_process_for_cluster(self, cid):
        '''
        Send a SIGTERM to the monitor process for cluster <cid> .
        '''
        phandle = gMonitoredClusters[cid]
        if phandle.is_alive():
            _logger.info("AlwaysOnParent: Cluster %d is marked down" % cid)
            _logger.info("AlwaysOnParent: Stopping monitor process for " \
                         "cluster: %d" % int(cid))
            phandle.terminate()
            #
            # After issuing SIGTERM we wait for 60 seconds at max for this process
            # to join. If it does not then we send a SIGKILL and remove its
            # marker file.
            # A possiblem race condition can reach here. Consider a case where
            # after SIGTERM child has removed its marker file but has not yet
            # joined in. IN next 60 seconds, most probably, watchdog will start
            # a new user_creds_instance which in turn spawn a new monitor process
            # for this cluster. The current marker file will belong to this new
            # monitor process not the old one, since marker file belonging to
            # older monitor process was already removed by it. This will force
            # parent process to spwan a new monitor process in next cycle as
            # marker file will not be there.
            # To prevent such a case, we will not remove the marker file since
            # on SIGTERM child does it anyway. We just have to make sure that
            # the first thing we do from child is to remove the marker file.
            #
            phandle.join(TIME_TO_WAIT_FOR_CHILD_JOIN)
            # check if process is still alive
            try:
                os.kill(phandle.pid, 0)
                # if still here this process is taking too much time, we kill it
                _logger.warn("AlwaysOnParent: Monitor process for cluster:" \
                             "%d is taking too long (> %d seconds) to quit, " \
                             "killing it now " % (cid, TIME_TO_WAIT_FOR_CHILD_JOIN))
                os.kill(phandle.pid, 9)

                # now join it so as to collect resources
                phandle.join()
            except Exception, ex:
                # process has stopped
                pass
            _logger.info("AlwaysOnParent: Successfully Stopped monitor " \
                         "process for cluster: %d" % int(cid))

    def _signal_handler(self, signum, frame):
        '''
        Process in the event of a signal that we received. Since this part
        belongs to parent, in the event a signal, we will make sure that
        we cleanup our children and then only exit.
        '''
        _logger.info("AlwaysOnParent: Got signal, prepairing to exit gracefully.")
        plist = []
        plist = multiprocessing.active_children() # also cleanup any dead children
        if len(plist) > 0:
            _logger.info("AlwaysOnParent: Found %d monitor children. Sending" \
                         " termination signal. " % (len(plist), ))

            for phandle in plist:
                if phandle.is_alive():
                    #
                    # p.terminate() issues SIGTERM to the child. As a safety measure, it
                    # should never be issued to children who are using shared data, semaphores
                    # locks etc. Howver, if children themselves have signal handlers
                    # registered then it should not be a problem. (i.e. children should
                    # perform cleanup as and when required)
                    #
                    _logger.info("AlwaysOnParent: Terminating the process whose id: %d" % int(phandle.pid))
                    phandle.terminate()
            for phandle in plist:
                if phandle.is_alive():
                    phandle.join(TIME_TO_WAIT_FOR_CHILD_JOIN)

                    try:
                        os.kill(phandle.pid, 0)
                        # if still here this process is taking too much time, we kill it
                        os.kill(phandle.pid, 9)
                        # now join it so as to collect resources
                        phandle.join()
                    except Exception, ex:
                        # process has stopped
                        pass

        self._cleanup_marker_files()
        _logger.info("AlwaysOnMonitor: Finished cleaning up.")

        # now we exit. since pid file is cleanedup by the calling instance's call
        # of stop() method, we donot have anything to cleanup as such.
        sys.exit()

    def _register_signal_handler(self):
        '''
        Registers a set of signals to catch.
        '''
        signals = [ signal.SIGTERM, signal.SIGHUP ]
        for s in signals:
            signal.signal(s, self._signal_handler)

    def spwan_monitor_children(self):
        running_cluster_ids, stopped_cluster_ids = self.get_list_of_cluster_ids()
        _logger.debug("AlwaysOnParent: Active clusters :%s, Stopped Clusters :%s"
                        % (running_cluster_ids, stopped_cluster_ids))

        for cid in stopped_cluster_ids:
            marker_file = "/var/run/always_on_monitor_%d.file" % cid
            if os.path.exists(marker_file):
                self._stop_monitor_process_for_cluster(cid)

        always_on_running_cluster_ids = [cid for cid in \
                running_cluster_ids if self._read_always_on_status(cid)]

        for cid in always_on_running_cluster_ids:
            marker_file = "/var/run/always_on_monitor_%d.file" % cid
            if os.path.exists(marker_file) == False:
                _logger.info("AlwaysOnParent: Spawning a new monitor " \
                              "process for cluster: %d" % cid)
                p = multiprocessing.Process(target = \
                                            always_on_monitor_routine, \
                                            args=(cid, os.getpid()))
                p.start()
                gMonitoredClusters[cid] = p
            else:
                marker_pid = read_pid(marker_file)
                if marker_pid:
                    path = "/proc/%s" % marker_pid
                    check_path = os.path.exists(path)
                    if check_path == False:
                        try:
                            os.remove(marker_file)
                        except:
                            _logger.error("AlwaysOnParent: Error on deleting marker file")
    
    def run(self):
        try:
            self._register_signal_handler()
        except Exception, ex:
            _logger.error("AlwaysOnParent: Failed to install signal handler: %s" % ex)
            _logger.error("%s" % (traceback.format_exc(),))
            sys.exit()

        #
        # Fix  for IDB-5393
        #
        while not os.path.exists('/system/lb.sqlite'):
            _logger.warn("AlwaysOnParent(%d): '/system/lb.sqlite' "\
                            "does not exist " % (os.getpid(),))
            time.sleep(1)

        sleep_interval = 5

        # try to determine the api_key
        while True:
            global APIKEY
            APIKEY = util.get_apikey(GLOBAL_LB_SQLITE_FILE)
            if APIKEY != '':
                break
            _logger.error("AlwaysOnParent(%d): Failed to determine apikey." % (os.getpid(),))
            time.sleep(sleep_interval)

        while True:
            try:
                # cleanup any finished children
                multiprocessing.active_children()
                #
                # see if a new cluster has been added and that we need any
                # monitor process for it.
                #
                self.spwan_monitor_children()
                
                if not os.path.exists("/var/run/always_on_monitor.pid"):
                    _logger.warn("Always On Monitor PID file is not Present Exiting Now")
                    break

            except Exception, ex:
                _logger.error("AlwaysOnMonitorDaemon run failed: %s" % ex)
                _logger.error("%s" % (traceback.format_exc(),))
            finally:
                _logger.debug("AlwaysOnParent: Sleeping for %f seconds" \
                              % (SLEEP_INTERVAL))
                time.sleep(SLEEP_INTERVAL)
def main():
    # Go away if you are not root
    if not os.geteuid()== 0:
        sys.exit("always_on_monitor: You must be root to run this script\n")

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
    global _config
    _config = get_config_parser(ALWAYS_ON_MONITOR_CONF)
    
    always_on_monitor_daemon = AlwaysOnMonitorDaemon('/var/run/always_on_monitor.pid')
    if args:
        if 'stop' == args[0]:
            _logger.info("****************** AlwaysOnMonitor stopping ********************")
            always_on_monitor_daemon.stop()
        elif 'restart' == args[0]:
            _logger.info("***************** AlwaysOnMonitor restarting *******************")
            always_on_monitor_daemon.restart()
        else:
            err_msg = "Invalid command %s" % (repr(args[0]),)
            print >> sys.stderr, err_msg
            _logger.error("%s" % (err_msg,))
            sys.exit(2)
        sys.exit(0)

    if _debug:
        _logger.info("************ AlwaysOnMonitor starting (debug mode)**************")
        always_on_monitor_daemon.foreground()
    else:
        _logger.info("****************** AlwaysOnMonitor starting ********************")
        always_on_monitor_daemon.start()

if __name__ == "__main__":
    main()
