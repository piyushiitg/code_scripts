#!/usr/bin/python
#
# Copyright (C) 2012 ScalArc, Inc., all rights reserved.
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
import getopt
import os
import sys, socket
import traceback
import time
import multiprocessing
#
# import modules from site-packages. iDB pacakge has to be installed before
# the following modules can be imported
#
import idb.log as log
import idb.daemon as daemon
import idb.util as util
from datetime import datetime
import pyodbc
import sqlite3
import base64
import binascii
import hashlib
import atexit
import signal
import socket
import glob
import random
# ###### Global Variables ##########
_debug = False
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
####################################

# Initialize logging
log.set_logging_prefix("always_on_monitor")
_logger = log.get_logger("always_on_monitor")

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

class PasswordUtils(object):
    """
    This class implements routines which encrypt,decrypt idb root account
    passwords.
    """
    @classmethod
    def encrypt(cls, text):
        '''
        Encrypt text and return the encrypted text
        '''
        return base64.b64encode(text.encode('hex').strip()[::-1])

    @classmethod
    def decrypt(cls, text):
        '''
        Decrypt text and return the plain text
        '''
        return base64.b64decode(text)[::-1].decode('hex')

    @classmethod
    def get_binary_of_hex(cls, hex_text):
        '''
        Returns binary stream of hex_text.
        '''
        return binascii.a2b_hex(hex_text)

    @classmethod
    def find_sha1(cls, text):
        '''
        Returns sha1 of text being passd to it.
        '''
        sha1 = hashlib.sha1()
        sha1.update(text)
        return (sha1.hexdigest().upper())

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
        self.connection_time = 0
        self.query1_time = 0
        self.query2_time = 0 
        self.query3_time = 0 
        self.query4_time = 0 
        self._health_status = {} # dict that contains {end_url: connected_state} 

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

            retry = 0
            while retry < MAX_RETRY:
                try:
                    cursor.execute(query, (self._cluster_id,))
                    row = cursor.fetchone()
                    if row:
                        self._vnn_info['vnn_server'] = row['vnnserver']
                        self._vnn_info['vnn_port'] = row['vnnport']
                        self._vnn_info['group_id'] = row['ag_id']
                        self._cluster_status = int(row['status'])
                    break
                except (Exception, sqlite3.Error) as ex:
                    retry = retry + 1
                    if retry >= MAX_RETRY:
                        _logger.error("AlwaysOnMonitor(%d): Problem getting vnn " \
                                    "server info : %s" % (self._cluster_id, ex))
                    else:
                        time.sleep(0.1)
            util.close_sqlite_resources(db_handle, cursor)

    def _get_health_info_servers(self, connection=None):
        ''' Fetch helath information for all node from the table
        master.sys.dm_hadr_availablity_replica_states'''

        try:
            if not connection:
                _logger.debug("AlwaysOnMonitor(%d): get Health status when you donot have connection " \
                              % (self._cluster_id))
                _conn_str = self._get_connection_string(server_ip=self._primary_ip,
                                            server_port=self._primary_port)
                _connection = self._get_connection(self._primary_ip, self._primary_port, _conn_str)
            else:
                _logger.debug("AlwaysOnMonitor(%d): get Health status withconnection " \
                              % (self._cluster_id))
                _connection = connection

            cursor = _connection.cursor()
        except:
            _logger.error("AlwaysOnMonitor(%d): Error while creating connection with primary server" % (self._cluster_id))
            if _connection:
                _connection.close()
            return

        try:
            if self._vnn_info.has_key('group_id'):
                query ="""select a.endpoint_url, b.role, b.connected_state from sys.availability_replicas a, 
                          master.sys.dm_hadr_availability_replica_states b
                          where a.group_id = b.group_id and a.replica_id = b.replica_id
                          and a.group_id='%s'
                       """ % self._vnn_info['group_id']
                
            else:
                self._health_status = {}
                return 

            cursor.execute(query)
            rows = cursor.fetchall()
            self._health_status = {}
            for endpoint_url, role, connected_state in rows:
                ip = self._parse_hostname_from_endpoint_url(endpoint_url)
                self._health_status[ip] = [connected_state, role]

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
            return

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
                # check with socket to connect with mssql server
                test_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                test_socket.settimeout(SOCKET_TIMEOUT)
                test_socket.connect((server_ip, port))
            except socket.error:
                errno, errstr = sys.exc_info()[:2]
                if errno == socket.timeout:
                    _logger.error("AlwaysOnMonitor(%d): Timeout has occured %s " % (self._cluster_id, errstr))
                return conn
            except Exception, ex:
                _logger.info("AlwaysOnMonitor(%d): Some Exception While using socket %s" % (self._cluster_id, ex))
                return conn
            finally:
                if test_socket:
                    test_socket.close()
 
            try:
                conn = pyodbc.connect(conn_str, timeout=MSSQL_LOGIN_TIMEOUT)
                break
            except Exception, ex:
                _logger.info("AlwaysOnMonitor(%d): Was Not Able To Connect " \
                                        ": %s" \
                                        % (self._cluster_id, ex))
        if conn:
            conn.timeout = QUERY_TIMEOUT
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
            if vnn_server_ip:
                self._conn_str = self._get_connection_string(server_ip=vnn_server_ip,
                                                server_port=vnn_server_port)
                self._connection = self._get_connection(vnn_server_ip, vnn_server_port, self._conn_str)

            else:
                _logger.error("AlwaysOnMonitor(%d): Failed to resolve vnn " \
                    "server hostname: %s. Let's try to connect to servers in AG group"\
                    % (self._cluster_id, self._vnn_info['vnn_server']))

        if not self._connection:
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
        current_time = datetime.now()
        if ((time.time() - self._last_state_updated) >= self._state_refresh_interval) \
            or force_refresh:
            _logger.debug("AlwaysOnMonitor(%d): Refreshing state data" \
                          % self._cluster_id)
            self._load_vnn_info_from_sqlite()

            if self._cluster_status == STATUS_DOWN:
                _logger.debug("AlwaysOnMonitor(%d): Cluster has been stopped" \
                              % self._cluster_id)
                return

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
            end_time = datetime.now()
            self.connection_time = end_time - current_time
            self._last_state_updated = time.time()
        else:
            self.connection_time = current_time - current_time

    def _retrieve_latest_server_stats(self):
        '''
        Obtain latest server stats against which we will compare the one we
        obtained from sqlite.
        1. If vnn info is available then obtain the latest server's role info
            from it.
            else
        2. query any server which can provide info of all servers in this
            cluster.
        3. Information is obtained in two steps:
            3.1) determine role : find the primary and secondary servers
                values expected: 0,1

            3.2) For each server obtain the connection type.
                values expected:
                    primary: 1,2
                    secondary: 4,5,6

    <iDB type>                : 0 -> 'R/W (Primary)'
                              : 1 -> 'R-Only (Secondary)'
                              : 2 -> 'W-Only (not used)'
    <sql2012_role_setting>    : 1 -> 'Primary - Allow all connections'
                              : 2 -> 'Primary - Read/Write only'
                              : 4 -> 'Secondary - Yes'
                              : 5 -> 'Secondary - Read-Intent Only' * call tapas code
                              : 6 -> 'Secondary = No'  * just do nothing, return 0
        Find primary
            if availabilty group is is present use that in the queries else 
            query without it.

            With group_id:
                **select endpoint_url from sys.availability_replicas where
                replica_server_name like (select primary_replica from
                sys.dm_hadr_availability_group_states where group_id=group_id)
                and group_id=group_id;
            else:
                **select endpoint_url from sys.availability_replicas where
                replica_server_name like (select primary_replica from
                sys.dm_hadr_availability_group_states);



        find roles:
            select replica_server_name,primary_role_allow_connections_desc,
            secondary_role_allow_connections_desc from sys.availability_replicas;

            With group_id:
                **select endpoint_url,primary_role_allow_connections_desc,
                secondary_role_allow_connections_desc from sys.availability_replicas 
                where group_id=group_id;
            else:
                **select endpoint_url,primary_role_allow_connections_desc,
                secondary_role_allow_connections_desc from sys.availability_replicas;
        '''
        self._new_primary_server = ''
        self._new_servers_list = []
        a = datetime.now()
        self.query1_time = a - a
        self.query2_time = a - a
        self.query3_time = a - a 
        try:
            cursor = self._connection.cursor()
        except Exception, ex:
            _logger.error("AlwaysOnMonitor(%d): Problem determining cursor " \
                            ": %s" % (self._cluster_id, ex))
            return
        try:
            start_time = datetime.now()
            if self._vnn_info.get('group_id'):
                cursor.execute("""select endpoint_url from sys.availability_replicas 
                                where replica_server_name like (select primary_replica 
				from sys.dm_hadr_availability_group_states where group_id=?) 
                                and group_id=?""", self._vnn_info.get('group_id'),
                                                   self._vnn_info.get('group_id'))
            else:
                cursor.execute("""select endpoint_url from sys.availability_replicas 
                                     where replica_server_name like (select primary_replica 
                                     from sys.dm_hadr_availability_group_states)""")

            row = cursor.fetchone()
            if row:
                self._new_primary_server = self._parse_hostname_from_endpoint_url(row[0])
                self._primary_ip = self._new_primary_server
                self._primary_port = self._get_server_port(self._primary_ip)
        except Exception, ex:
            _logger.error("AlwaysOnMonitor(%d): Problem determining current " \
                            "master: %s" % (self._cluster_id, ex))
            self._new_primary_server = ''

        end_time = datetime.now()
        self.query1_time = end_time - start_time
        cursor.close()
        if self._new_primary_server == '':
            return

        _logger.debug("AlwaysOnMonitor(%d): Primary replica from vnn: %s" \
                      % (self._cluster_id, self._new_primary_server))
        # now read all servers information including their roles
        cursor = self._connection.cursor()
        start_time = datetime.now()
        try:
            if self._vnn_info.get('group_id'):
                cursor.execute("""select endpoint_url, primary_role_allow_connections_desc, 
                                    secondary_role_allow_connections_desc from 
                                    sys.availability_replicas where group_id=?""",
                                    self._vnn_info.get('group_id'))
            else:
                cursor.execute("""select endpoint_url, primary_role_allow_connections_desc, 
                                    secondary_role_allow_connections_desc from 
                                    sys.availability_replicas""")

            for row in cursor.fetchall():
                d = {}
                d['ip'] = self._parse_hostname_from_endpoint_url(row[0])

                # determine whether it's primary or secondary
                if d['ip'] == self._new_primary_server:
                    d['type'] = PRIMARY
                else:
                    d['type'] = SECONDARY

                # determine the role of this server
                if d['type'] == PRIMARY:
                    d['role'] = PRIMARY_ROLE_MAP[row[1]] # READ_WRITE/ALL
                else:
                    d['role'] = SECONDARY_ROLE_MAP[row[2]] # NO/ALL/READ_ONLY

                self._new_servers_list.append(d)
        except Exception, ex:
            _logger.error("AlwaysOnMonitor(%d): Problem while reading role " \
                          "information from server: %s" % (self._cluster_id, ex))
            self._new_servers_list = []

        end_time = datetime.now()
        self.query2_time = end_time - start_time
        cursor.close()
        try: 
            start_time = datetime.now()
            self._get_health_info_servers()
        except Exception, ex:
            _logger.error("AlwaysOnMonitor(%d): Problem while reading health status " \
                          "information from server: %s" % (self._cluster_id, ex))
        end_time = datetime.now()
        self.query3_time = end_time - start_time
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
            _logger.warn("AlwaysOnMonitor(%d): Invalid new primary server." \
                         % self._cluster_id)
            return False

        # what if we get a primary  server that is not present in our database
        local_servers_list = [ x['ip'] for x in self._old_servers_list ]
        if self._new_primary_server not in local_servers_list:
            _logger.error("AlwaysOnMonitor(%d): Does not recognize server: %s." \
                          " Can't set it as new primary server." \
                          % (self._cluster_id, self._new_primary_server))
            #
            # TODO:
            # Is it right to quit when we find a strange server? May be we can
            # continue processing role change for servers that we can
            # understand.
            #
            return False

        # now we have a valid primary server
        if self._old_master == self._new_primary_server:
            _logger.debug("AlwaysOnMonitor(%d): No change in primary server." \
                          % self._cluster_id)
            self._msg_for_core = ''
            return True

        _logger.debug("AlwaysOnMonitor(%d): Old master: %s new master : %s" \
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
        
        for old_server in self._old_servers_list:
            server_found_in_newlist = False

            for new_server in self._new_servers_list:
                if old_server['ip'] == new_server['ip']:
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
                    _logger.debug("AlwaysOnMonitor(%d): Health status for ip %s & health_dict %s" \
                          % (self._cluster_id, old_server['ip'], self._health_status))
               
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
                                _logger.debug("AlwaysOnMonitor(%d): Health status is changed for ip %s health_dict %s \
                                              old_server %s"
                                     %(self._cluster_id, old_server['ip'], self._health_status, \
                                       old_server.get('health_status')))
                                msg = '%d:%d:%d:%d|' % (server_id, new_server['type'], \
                                                     new_server['role'], health_status)
                                role_change_list.append(msg)
                            except Exception, ex:
                                _logger.error("AlwaysOnMonitor(%d): Problem generating" \
                                             " health staus change string. %s" \
                                             % self._cluster_id, ex)
    
                    # we break out of loop since we have found the server in newlist
                    break
 
            if not server_found_in_newlist:
                _logger.warn("AlwaysOnMonitor(%d): Server %s not found in " \
                             "latest server list." % (self._cluster_id, \
                                                      old_server['ip']))


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
            _logger.info("**************** Starting ***************")
            start_time1 = datetime.now()
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
            start_time = datetime.now()
            # 1. refresh state data
            self._refresh_state_data()
            end_time = datetime.now()
            sqlite_time = (end_time - start_time)

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
            start_time = datetime.now()
            self._retrieve_latest_server_stats()

            # Check for resolving state of the server 
            _logger.info("AlwaysOnMonitor(%d): Retrieving resolving stats" \
                          % self._cluster_id)
            start_time = datetime.now()

            self._check_resolving_state_inform_core()

            end_time = datetime.now()
            resolving_check_time = (end_time - start_time)

            # reset msg to be sent to core
            self._msg_for_core = ''

            # detect any change in primary server for this cluster.
            _logger.debug("AlwaysOnMonitor(%d): Processing primary server change" \
                          % self._cluster_id)
            
            start_time = datetime.now()
            if not self._process_primary_server_change():
                time.sleep(1)
                end_time1 = datetime.now()
                complete_time = (end_time1 - start_time1)
                _logger.info("*********** Time Taken to before sqlite_time %s, sql_query_time %s, resolv_chk_time %s, process_any_change %s, write_to_sqlite_core %s, complete_time %s " 
                         % (
                            (sqlite_time.seconds*1000) + (sqlite_time.microseconds/1000.0), 
                            (sql_query_time.seconds*1000) + (sql_query_time.microseconds/1000.0), 
                            (resolving_check_time.seconds*1000)+(resolving_check_time.microseconds/1000.0),
                            0,
                            0, 
                            (self.connection_time.seconds*1000)+(self.connection_time.microseconds/1000.0),
                            (self.query1_time.seconds*1000)+(self.query1_time.microseconds/1000.0),
                            (self.query2_time.seconds*1000)+(self.query2_time.microseconds/1000.0),
                            (self.query3_time.seconds*1000)+(self.query3_time.microseconds/1000.0),
                            (self.query4_time.seconds*1000)+(self.query4_time.microseconds/1000.0),
                            (complete_time.seconds*1000)+(complete_time.microseconds/1000.0),
                           ))

                _logger.info("**************** End ***************")
                _logger.info("\n")
                _logger.info("\n")
                continue

            # 3. now find any change in roles.
            _logger.info("AlwaysOnMonitor(%d): Processing role change for " \
                          "servers" % self._cluster_id)
            self._process_role_and_health_change()
            end_time = datetime.now()
            process_any_change =  (end_time - start_time)
            
            start_time = datetime.now()
            if self._writeback_changes_to_sqlite():
                # 4. if writeback to sqlite was successful then lets inform core
                # of the same.
                self._inform_core_about_role_change()

                #Refresh state data forecefully
                self._refresh_state_data(True)

            end_time = datetime.now()
            write_to_sqlite_core = (end_time - start_time)
            # sleep for a while and then begin the cycle
            time.sleep(1)
            end_time1 = datetime.now()
            complete_time = (end_time1 - start_time1)
            _logger.info("*********** Time Taken to sqlite_time %s, sql_query_time %s, resolv_chk_time %s, process_any_change %s, write_to_sqlite_core %s, complete_time %s " 
                         % (
                            (sqlite_time.seconds*1000) + (sqlite_time.microseconds/1000.0), 
                            (sql_query_time.seconds*1000) + (sql_query_time.microseconds/1000.0), 
                            (resolving_check_time.seconds*1000)+(resolving_check_time.microseconds/1000.0), 
                            (process_any_change.seconds*1000)+(process_any_change.microseconds/1000.0), 
                            (write_to_sqlite_core.seconds*1000)+(write_to_sqlite_core.microseconds/1000.0), 
                            (self.connection_time.seconds*1000)+(self.connection_time.microseconds/1000.0),
                            (self.query1_time.seconds*1000)+(self.query1_time.microseconds/1000.0),
                            (self.query2_time.seconds*1000)+(self.query2_time.microseconds/1000.0),
                            (self.query3_time.seconds*1000)+(self.query3_time.microseconds/1000.0),
                            (self.query4_time.seconds*1000)+(self.query4_time.microseconds/1000.0),
                            (complete_time.seconds*1000)+(complete_time.microseconds/1000.0)
                           ))
            _logger.info("**************** End ***************")
            _logger.info("\n")
            _logger.info("\n")

    def _check_resolving_state_inform_core(self):
        '''
        This Function check for resolving state of the any server
        If it finds any server then mark all the server down
        '''
        role_change_list = []
        self._msg_for_core = ''
        if not self._new_primary_server:
            _logger.info("AlwaysOnMonitor(%d): No primary server doing resolve check" \
                          % self._cluster_id)
            start_time = datetime.now()
            self._get_health_info_servers(self._connection)
            end_time = datetime.now()
            self.query4_time = end_time - start_time
            _logger.debug("AlwaysOnMonitor(%d): Got new health status %s" \
                          % (self._cluster_id, self._health_status))
            all_server_in_resolving_state = False
            for ip, values in self._health_status.iteritems():
                health_state = values[0]
                role = values[1]
                if role == 0: # For resolving state 
                    _logger.debug("AlwaysOnMonitor(%d): Found server in resolving role %s" \
                          % (self._cluster_id, ip))
                    all_server_in_resolving_state = True
                    break
             
            if all_server_in_resolving_state:
                for old_server in self._old_servers_list:
                    msg = ''
                    health_status = 0
                    try:
                        _logger.debug("AlwaysOnMonitor(%d): Health status is changed to 0 for server %s " 
                                       % (self._cluster_id, old_server['ip']))
                        server_id = self._get_serverid(old_server['ip'])
                        msg = '%d:%d:%d:%d|' % (server_id, old_server['type'], \
                                                old_server['role'], health_status)
                        role_change_list.append(msg)
                    except Exception, ex:
                        _logger.error("AlwaysOnMonitor(%d): Problem generating" \
                                             " health staus change string. %s" \
                                             % self._cluster_id, ex)

            # form the msg string to sent to core
            for t in role_change_list:
                self._msg_for_core = self._msg_for_core + t
            _logger.debug("AlwaysOnMonitor(%d): message for core %s" \
                          % (self._cluster_id,self._msg_for_core))
            if self._msg_for_core:
                if self._writeback_changes_to_sqlite():
                    # if writeback to sqlite was successful then lets inform core
                    # of the same.
                    self._inform_core_about_role_change()
                    #Refresh state data forecefully
                    self._refresh_state_data(True)
                    _logger.debug("AlwaysOnMonitor(%d): Inform to core and set resolving state" \
                          % self._cluster_id)
        else:
            a = datetime.now()
            self.query4_time = a - a

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

    def run(self):
        try:
            self._register_signal_handler()
        except Exception, ex:
            _logger.error("Failed to install signal handler: %s" % ex)
            _logger.error("%s" % (traceback.format_exc(),))
            sys.exit()

        #
        # Fix  for IDB-5393
        #
        while not os.path.exists('/system/lb.sqlite'):
            _logger.warn("AlwaysOnParent(%d): '/system/lb.sqlite' "\
                            "does not exist " % (os.getpid(),))
            time.sleep(1)

        while True:
            try:
                # cleanup any finished children
                multiprocessing.active_children()

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
                time.sleep(SLEEP_INTERVAL)
            except Exception, ex:
                _logger.error("AlwaysOnMonitorDaemon run failed: %s" % ex)
                _logger.error("%s" % (traceback.format_exc(),))
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
