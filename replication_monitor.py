#!/usr/bin/python
#
# Copyright (C) 2013 ScaleArc, Inc., all rights reserved.
#
"""This file implements the daemon for REPLICATION_MONITOR
"""
import getopt
import os
import sys
import traceback
import time
import sqlite3
import base64
import ConfigParser
import hashlib
import binascii
import socket
import threading
import multiprocessing
import thread
import math
import pyodbc
import select
import random
import signal, errno
import glob

# The configuration file for REPLICATION_MONITOR service
IDB_DIR_ETC = '/opt/idb/conf'
REPLICATION_MONITOR_CONF = 'replication_monitor.conf'
GLOBAL_LB_DB_FILE = "/system/lb.sqlite"
LB_DB_FILE = "/system/lb_%s.sqlite"
NO_SAFETY_NET_FILE = "/opt/idb/.idb_utils_no_safety_net"
MAX_RETRY = 3
PLATFORM_TYPES = ('MSSQL', 'ORACLE')

# list of cluster objects of type ClusterLevelAutoImport
gMonitoredClusters = {} #list of cluster_dict
gMonitorProcessMarkerFile = '' # used by child monitor process
gSignalChildToQuit = False

SQLITE_FILE = "/system/lb.sqlite"
READY = 1
BUSY = 0
MASTER_SERVER = 0
SLAVE_SERVER = (1, 3, 4)
QUERY_TIMEOUT = 5
MSSQL_LOGIN_TIMEOUT = 5
ROLE_READ_INTENT_ONLY = 5
DEFAULT_REPLICATION_LAG = -1

gSimulationInfo = {} # store simulation info
gSimulationInfo['active'] = False
gSimulationInfo['target_ips'] = 'ALL'
gSimulationInfo['replication_lag'] = 10
gSimulationInfo['simulation_type'] = 'FIXED'

TIME_TO_WAIT_FOR_CHILD_JOIN = 60 # in seconds
###################################################
# The global variable for the configuration parser
_config = None

# These can be overriden via command-line options
_debug = False

#
# import modules from site-packages. iDB package has to be installed before
# the following modules can be imported
#
import idb.log as log
import idb.daemon as daemon
import idb.util as util

# Initialize logging
log.set_logging_prefix("replication_monitor")
_logger = log.get_logger("replication_monitor")

# Set the script version
SCRIPT_VERSION = 1.0

def get_error_str(msg):
    return "\n--[Error]--\n%s" % (msg)

def get_traceback_str(msg):
    return "\n--[Traceback]--\n%s" % (msg)


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

def get_config_parser(config_file, options={}):
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

class PasswordUtils(object):
    """This class provides utilities for dealing with idb passwords.
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

class ReplicationMonitorUtils():
    '''
    This class is a collections of generic routines. These routines perform
    a simple but a single task and usually do not hold any state. Therefore,
    all these routines can be accessed by classname.routine_name syntax.
    In other words, this class resembles a singleton class. These routines can
    be moved out of this class as they do not have any state/variables shared
    among them.

    # FIXME: Use a better name for this class.
    '''
    @classmethod
    def find_root_user_info(cls, cluster_id):
        '''
        Return a dictionary containing  root account information from table
        lb_users for this cluster_id.
        '''
        root_accnt_info = {'username':'', 'password':''}

        sqlite_handle = util.get_sqlite_handle(LB_DB_FILE % cluster_id)
        if not sqlite_handle:
            _logger.error("Failed to get sqlite handle")
            return root_accnt_info

        db_cursor = sqlite_handle.cursor()
        query = "select username, encpassword from lb_users where type=1 " \
                "and status=1 and clusterid=?"

        retry = 0
        while retry < MAX_RETRY:
            try:
                db_cursor.execute(query, (cluster_id,))
                row = db_cursor.fetchone()
                if row:
                    root_accnt_info['username'] = row['username']
                    root_accnt_info['password'] = row ['encpassword']
                break
            except Exception, ex:
                retry = retry + 1
                if retry >= MAX_RETRY:
                    _logger.error("Failed to find root user info for cluster" \
                                  " %d: %s" % (cluster_id, ex))
                else:
                    time.sleep(0.1)

        util.close_sqlite_resources(sqlite_handle, db_cursor)
        if retry >= MAX_RETRY :
            return root_accnt_info

        #lets decrypt this password
        root_accnt_info['password'] = PasswordUtils.decrypt(root_accnt_info['password'])
        return root_accnt_info

    @classmethod
    def get_all_servers(cls, cluster_id):
        '''
        Return a list of all dbservers which are in this cluster.
        '''
        all_servers_list = []
        sqlite_handle = util.get_sqlite_handle(LB_DB_FILE % cluster_id)
        if not sqlite_handle:
            return all_servers_list

        db_cursor = sqlite_handle.cursor()

        _logger.info("******************gMonitoredClusters is %s" %gMonitoredClusters)
        cluster_type = gMonitoredClusters[cluster_id]['cluster_type']
        _logger.info("******************cluster id is %s and clustertype is %s" %(cluster_id, cluster_type))
        if cluster_type == 'MSSQL':
            query = "select serverid,ipaddress,port,type,sql2012_role_setting from " \
                            "lb_servers where status=1 and clusterid=?"
        elif cluster_type == 'ORACLE':
            query = "select serverid,ipaddress,port,type,service_name, sid_type, sid_name from " \
                            "lb_servers where status=1 and clusterid=?"
        else:
            return all_servers_list
        retry = 0
        while retry < MAX_RETRY:
            try :
                db_cursor.execute(query, (cluster_id,))
                for row in db_cursor.fetchall():
                    d = {}
                    d['serverid']  = int(row['serverid'])
                    d['ipaddress'] = row['ipaddress']
                    d['port']      = int(row['port'])
                    d['type'] = int(row['type'])
                    if cluster_type == 'MSSQL':
                        d['role'] = int(row['sql2012_role_setting'])
                    elif cluster_type == 'ORACLE':
                        d['service_name'] = row['service_name']
                        d['sid_type'] = row['sid_type']
                        d['sid_name'] = row['sid_name']
                    d['simulation'] = False
                    d['cluster_type'] = cluster_type

                    all_servers_list.append(d.copy())

                break
            except (Exception, sqlite3.Error) as ex:
                retry = retry + 1
                if retry >= MAX_RETRY:
                    _logger.error("ReplicationMonitor(%d): Error reading " \
                                  "servers list : %s" % (cluster_id, traceback.format_exc()))
                else:
                    time.sleep(0.1)

        util.close_sqlite_resources(sqlite_handle, db_cursor)
        return all_servers_list

    @classmethod
    def get_md5_hash(cls, text):
        '''
        Return md5 hash of text.
        '''
        try:
            hash_value = hashlib.md5(str(text)).hexdigest()
            return hash_value
        except Exception, ex:
            _logger.error('Could not calculate hash : %s' % ex )
            return ''

class UpdateThread(object):
    '''
    This class implements functionality of a Update thread. The update thread
    updates the current timestamp in every cycle. The slave servers who are in
    replication, will read that value because of being in replication. We will
    subtract the time diff (time_when_master_wrote - time_when_slaves_read) as
    the replication lag time.
    '''
    def __init__(self, cluster_id, server_id, server_ip, server_port, db_name, \
                 table_name, user_name, password, server_info=None):
        self._cluster_id = cluster_id
        self._server_id = server_id
        self._server_ip = server_ip
        self._server_port = server_port
        self._dbname = db_name
        self._user = user_name
        self._password = password
        self._hash = ''
        self._dbconn = None
        self._dbcursor = None
        self._table_name = table_name
        self._conn_string = ''
        self.server_info = server_info
        _logger.info("************************ server info is %s" %self.server_info)
        # connect to db
        self._create_connection()

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

    def _create_connection(self):
        '''
        Create db connection.
        '''
        # try resolving the server name to make sure we always have proper IP
        # v4 address
        if self.server_info['cluster_type'] == 'MSSQL':
            self.mssql_db_connection()
        elif self.server_info['cluster_type'] == 'ORACLE'
            self.oracle_db_connection()

    def mssql_db_connection(self):
        ''' MSSQL Connection
        '''
        while True:
            server_ip = self._get_proper_server_addr(self._server_ip)
            if server_ip != '':
                self._server_ip = server_ip
                break
            _logger.error("UpdateThread(%d:%d): Failed to resolve server hostname: %s" \
                          % (self._cluster_id, self._server_id, self._server_ip))
            time.sleep(1)

        is_windows_user = False
        domain_name = None
        user_name = None
        try:
            domain_name, user_name = self._user.split('\\')
            is_windows_user = True
        except Exception, ex:
            _logger.debug("UpdateThread(%d:%d): Not a windows user " \
                           % (self._cluster_id, self._server_id))
 
        default_conn_string = "DRIVER={FreeTDS};Server=" + str(self._server_ip) + \
                              ";Port=" + str(self._server_port) + ";UID=" + \
                              str(self._user) + ";PWD=" + str(self._password) + \
                              ";autocommit=True;TDS_VERSION=7.2;"
        if is_windows_user:
            self._conn_string = default_conn_string + \
                                "UseNTLMV2=Yes;Trusted_Domain=" + str(domain_name)+";"
        else:
            self._conn_string = default_conn_string

        try:
            self._dbconn = pyodbc.connect(self._conn_string, timeout=MSSQL_LOGIN_TIMEOUT)
            self._dbconn.timeout = QUERY_TIMEOUT
            self._dbcursor = self._dbconn.cursor()
        except Exception,ex:
            err_msg = 'Could not connect to database.'
            _logger.error("UpdateThread(%d:%d): Failed to connect to db: %s" \
                          % (self._cluster_id, self._server_id, ex))
            raise Exception(err_msg)

    def oracle_db_connection(self):
        ''' Oracle Connection
        '''
        while True:
            server_ip = self._get_proper_server_addr(self._server_ip)
            if server_ip != '':
                self._server_ip = server_ip
                break
            _logger.error("UpdateThread(%d:%d): Failed to resolve server hostname: %s" \
                          % (self._cluster_id, self._server_id, self._server_ip))
            time.sleep(1)

        is_windows_user = False
        domain_name = None
        user_name = None
        try:
            domain_name, user_name = self._user.split('\\')
            is_windows_user = True
        except Exception, ex:
            _logger.debug("UpdateThread(%d:%d): Not a windows user " \
                           % (self._cluster_id, self._server_id))
 
        default_conn_string = "DRIVER={FreeTDS};Server=" + str(self._server_ip) + \
                              ";Port=" + str(self._server_port) + ";UID=" + \
                              str(self._user) + ";PWD=" + str(self._password) + \
                              ";autocommit=True;TDS_VERSION=7.2;"
        if is_windows_user:
            self._conn_string = default_conn_string + \
                                "UseNTLMV2=Yes;Trusted_Domain=" + str(domain_name)+";"
        else:
            self._conn_string = default_conn_string

        try:
            self._dbconn = pyodbc.connect(self._conn_string, timeout=MSSQL_LOGIN_TIMEOUT)
            self._dbconn.timeout = QUERY_TIMEOUT
            self._dbcursor = self._dbconn.cursor()
        except Exception,ex:
            err_msg = 'Could not connect to database.'
            _logger.error("UpdateThread(%d:%d): Failed to connect to db: %s" \
                          % (self._cluster_id, self._server_id, ex))
            raise Exception(err_msg)


    def get_server_hash(self):
        '''
        Returns server hash.
        '''
        hash_string = str(self._cluster_id) + "_" +str(self._server_id)+ '_' + \
                        self._server_ip + "_" + str(self._server_port) + "_" + \
                        self._dbname
        self._hash = ReplicationMonitorUtils.get_md5_hash(hash_string)
        return self._hash

    def init_db_state(self):
        '''#TODO insert query chnage if cluster type is oracle
        Create table/db if not present already. It's a one-time operation only and
        should be called once at begining by a update thread.
        '''
        if self._hash == '':
            self.get_server_hash()

        insert_query = "if not exists (select * from [%s].[dbo].[%s] where " \
                        "server_hash = '%s') INSERT INTO [%s].[dbo].[idb_drlms]" \
                        " ([server_hash],[ts],[exec_ts]) VALUES ('%s','%s','%s')" \
                        % ( self._dbname, self._table_name, self._hash, \
                            self._dbname, self._hash, time.time(), time.time())

        try:
            self._dbcursor.execute(insert_query)
        except Exception,ex:
            _logger.error("UpdateThread(%d:%d): Failed to create db: %s" \
                          % (self._cluster_id, self._server_id, ex))
            self._dbconn.close()
            return False
        return True

    def get_server_ts(self):
        '''
        Returns the timestamp as recorded in server. Here we will update and
        fetch the time stamp. Return a non-zero value on success, else return
        a positive integer.
        '''
        if self._hash == '':
            self.get_server_hash()

#         update_query = "USE [%s] DECLARE @return_value int, @ts bigint EXEC @return_value = " \
#             "[%s].[dbo].[sp_idb_drlms_update] @server_hash = N'%s', @exe_ts = '%s' , @ts = @ts " \
#             "OUTPUT SELECT @ts as N'@ts' SELECT 'Return Value' = @return_value" % (self._dbname ,\
#              self._dbname, self._hash, time.time())

        exec_ts = str(time.time())
        update_query = "exec %s.dbo.sp_idb_drlms_update '%s',%s,%s" \
                        % (self._dbname, self._hash, exec_ts, exec_ts)

        try:
            self._dbcursor.execute(update_query)
            self._dbconn.commit()
        except Exception,ex:
            _logger.error("UpdateThread(%d:%d): Failed to update timestamp in " \
                          "master server. %s" % (self._cluster_id, self._server_id, ex))
            return 0

        # now fetch the timestamp
        select_query = "select server_hash,ts,exec_ts from %s.dbo.%s where " \
                        "server_hash = '%s'" % (self._dbname, self._table_name, \
                                                self._hash)

        try:
            self._dbcursor.execute(select_query)
            row =  self._dbcursor.fetchone()
        except Exception,ex:
            _logger.error("UPdateThread(%d:%d): Failed to readback master server " \
                          "ts: %s" % (self._cluster_id, self._server_id, ex))
            return 0
        return "%.3f" % float(row[1])

    def close_connection(self):
        '''
        Closes the db connection used internally. Although the API is exposed,
        it need not be called in current implementation.
        '''
        try:
            if self._dbconn:
                self._dbconn.close()
        except Exception,ex:
            _logger.error("UpdateThread(%d:%d): Error closing the server connection" \
                          " : %s" % (self._cluster_id, self._server_id, ex))


class FetchThread(object):
    def __init__(self, cluster_id, server_id, server_ip, server_port, db_name, \
                 table_name, user_name, password, role):
        self._cluster_id = cluster_id
        self._server_id = server_id
        self._server_ip = server_ip
        self._server_port = server_port
        self._dbname = db_name
        self._user = user_name
        self._password = password
        self._hash = ''
        self._dbconn = None
        self._dbcursor = None
        self._table_name = table_name
        self._role = role

        # connect to db
        self._create_connection()

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

    def set_server_role(self, new_role):
        '''
        Check if there has been a role change, if yes, then modify the role.
        '''
        if new_role != self._role:
            self._role = new_role

    def get_server_hash(self):
        '''
        Returns server hash.
        '''
        if self._hash != '':
            return self._hash

        hash_string = str(self._cluster_id) + "_" + str(self._server_id) +  \
                        '_' +self._server_ip + "_" + str(self._server_port) + \
                        "_" + self._dbname
        self._hash = ReplicationMonitorUtils.get_md5_hash(hash_string)
        return self._hash

    def _create_connection(self):
        '''
        Create db connection.
        '''
        
        while True:
            server_ip = self._get_proper_server_addr(self._server_ip)
            if server_ip != '':
                _logger.debug("FetcherThread(%d:%d): Resolved server hostname:" \
                              " %s to %s" % (self._cluster_id, self._server_id, \
                                             self._server_ip, server_ip))
                self._server_ip = server_ip
                break
            _logger.error("FetcherThread(%d:%d): Failed to resolve server " \
                          "hostname: %s" % (self._cluster_id, self._server_id, \
                                            self._server_ip))
            time.sleep(1)
       
        is_windows_user = False
        domain_name = None
        user_name = None
        try:
            domain_name, user_name = self._user.split('\\')
            is_windows_user = True
        except Exception, ex:
            _logger.debug("FetcherThread(%d:%d): Not a windows user " \
                           % (self._cluster_id, self._server_id))
 
        default_conn_string = "DRIVER={FreeTDS};Server=" + str(self._server_ip) + \
                              ";Port=" + str(self._server_port) + ";UID=" + \
                              str(self._user) + ";PWD=" + str(self._password) + \
                              ";autocommit=True;TDS_VERSION=7.2;"
        if is_windows_user:
            if self._role != ROLE_READ_INTENT_ONLY:
                self._conn_string = default_conn_string + \
                                    "UseNTLMV2=Yes;Trusted_Domain=" + str(domain_name)+";"

            if self._role  == ROLE_READ_INTENT_ONLY:
                self._conn_string = default_conn_string + \
                                    "UseNTLMV2=Yes;Trusted_Domain=" + str(domain_name) + \
                                    ";ApplicationIntent=ReadOnly;"
        else:
            if self._role != ROLE_READ_INTENT_ONLY:
                self._conn_string = default_conn_string 

            if self._role  == ROLE_READ_INTENT_ONLY:
                self._conn_string = default_conn_string + \
                                    ";ApplicationIntent=ReadOnly;"
        try:
            self._dbconn = pyodbc.connect(self._conn_string, timeout=MSSQL_LOGIN_TIMEOUT)
            self._dbconn.timeout = QUERY_TIMEOUT
            self._dbcursor = self._dbconn.cursor()
        except Exception,ex:
            err_msg = 'Could not connect to database.'
            _logger.error("FetcherThread(%d:%d): Failed to connect to database. " \
                          "Terminated. :%s" % (self._cluster_id, \
                                               self._server_id, ex))
            raise Exception(err_msg)

    def get_repl_lag(self, servers_hash):
        '''
        Calculates the diff between last server ts and the ts read in this cycle.
        server_hash is a dictionary which has key,value as (hash, ts).
        Hash here is the hash of the primary server i.e. server with which this
        slave is in replication with. ts is timestamp as read by corresponding
        update thread.

        Here in this routine we will read all rows, since we dont know with which
        master we are in replication with. It is possible that this slave might be
        in replication with many masters. So we will find
        common rows between servers_hash and the one we will get by querying
        server to find which masters we are replicating. And then we sum up
        rep_lag and finally average it.
        '''

        # now fetch the timestamp
        select_query = "select server_hash,ts,exec_ts from %s.dbo.%s" \
                        % (self._dbname, self._table_name,)
        rows = []
        #
        # we will use a new connection every time because of an issue with pyodbc
        # where library was caching results in some weird way.
        #
        self.reset_connection()
        try:
            self._dbcursor = self._dbconn.cursor()
            self._dbcursor.execute(select_query)
            rows =  self._dbcursor.fetchall()
            self._dbcursor.close()
        except Exception,ex:
            _logger.error("FetcherThread(%d:%d):Failed to determine slave " \
                          "lagtime : %s" % (self._cluster_id, self._server_id, ex))
            # we will not close connection here.
            return DEFAULT_REPLICATION_LAG

        if len(rows) == 0:
            _logger.error("FetcherThread(%d:%d): Got no rows from server. " \
                          "Failed to determine slave lagtime." \
                          % (self._cluster_id, self._server_id, ))
            return DEFAULT_REPLICATION_LAG

        # find servers with which we are in replication.
        total_rep = 0.0
        rep_count = 0

        for k,v in servers_hash.iteritems():
            for row in rows:
                #
                # if this fetcher thread belongs to a master server and is set
                # in replication with another master. then running the fetch query
                # will return the other master's info as well as this masters.
                # therefore, we will ignore if our hash is also present in the rows
                # that we just fetched.
                #
                if len(row) != 3:
                    #
                    # skip cases where row can have malformed result string
                    # or a newline
                    #
                    continue

                if self.get_server_hash() == row[0]:
                    continue

                if k == row[0]:
                    # this key i.e. hash is under replication
                    total_rep = total_rep + (servers_hash[k] - float(row[1]))
                    rep_count = rep_count  + 1
        #
        # servers_hash does not have a master server which this server is in
        # replication with.
        #
        if rep_count == 0:
            return 0

        diff = float ("%.3f" % float(total_rep / rep_count))
        if diff < 0:
            return 0
        else:
            return int(math.ceil(diff))

    def reset_connection(self):
        '''
        Reset the current connection and create a new one.
        '''
        #
        # we will attempt to close a connection when role is set to READ_INTENT_only
        # as we do not have an actual connection to deal with.
        #
        self.close_connection()
        self._create_connection()

    def close_connection(self):
        '''
        Closes the db connection used internally. Although the API is exposed,
        it need not be called in current implementation.
        '''
        try:
            if self._dbconn:
                self._dbconn.close()
        except Exception,ex:
            _logger.error("FetcherThread(%d:%d): Error closing connection : %s" \
                          % (self._cluster_id, self._server_id, ex))

class ClusterMonitor(object):
    '''
    This class implements methods/member variables which are required for
    replication monitor.

    Update: To support master to master replication, we will spawn fetcher threads
    also for master threads, however to make sure that we prevent considering our
    own replication with ourselves, we will ignore the row having our hash.

    For configurations, where master to master replication is not set, we will
    have slave threads but they will not do any work. So in case, we get no
    row (for master server meaning this master is not in replication with anyone)
    we will just return 0 for that thread.

    That is in, fetcher_thread_work_area(),
    '''
    def __init__(self, cluster_id, comm_pipe):
        self._cluster_id = cluster_id
        self._lb_dbname = LB_DB_FILE % cluster_id
        self._comm_pipe = comm_pipe
        self._result = ''
        self._master_servers_list = []
        self._slave_servers_list = []
        self._master_servers_list_lock = threading.Lock()
        self._slave_servers_list_lock = threading.Lock()
        self._manager_interval = 5
        self._root_accnt_info = None
        self._table_name = 'idb_drlms'
        self._dbname = '' # we will read it from sqlite
        self._all_servers = []
        self._repl_lag_dict = {} # entries of {'server_id': ts}, this is what will
                                  # be sent

        self._master_servers_hash = {} # key is server's hash and value is ts.
                                        # will be used for calculating repl_lag

        self._manager_thread = threading.Thread(target = self.thread_pool_manager)
        self._manager_thread.setDaemon(True)
        self._manager_thread.start()

    def _check_and_add_master_server(self, server):
        '''
        Check if server is not in self._master_servers. If not then , add it
        to the list and also spawn an update thread corresponding to it.
        '''
        if server not in self._master_servers_list:
            self._master_servers_list_lock.acquire()
            self._master_servers_list.append(server)
            self._master_servers_list_lock.release()

            # start the update thread for this master server
            th = threading.Thread(target = self.update_thread_work_area, \
                                  args=(server, ))
            th.setDaemon(True)
            th.start()

            # start a fetcher thread for this master server as well to
            # find its replication with another master (if at all configured)
            th = threading.Thread(target = self.slave_thread_work_area, \
                              args=(server, ))
            th.setDaemon(True)
            th.start()

    def _is_slave_under_simulation(self, server):
        '''
        Check if this server's replication lag value will be simulated.
        '''
        if not gSimulationInfo['active']:
            return False

        if gSimulationInfo['target_ips'] == 'ALL':
            return True
        try:
            t = gSimulationInfo['target_ips'].split(',')
            if server['ipaddress'] in t:
                return True
        except:
            pass
        return False

    def _check_and_add_slave_server(self, server):
        '''
        Check and add this server into slave_servers list if not already present.
        Also spawn a new fetcher thread corresponding to it.
        '''
        if server not in self._slave_servers_list:
            self._slave_servers_list_lock.acquire()
            if self._is_slave_under_simulation(server):
                server['simulation'] = True
            self._slave_servers_list.append(server)
            self._slave_servers_list_lock.release()

            th = threading.Thread(target = self.slave_thread_work_area, \
                              args=(server, ))
            th.setDaemon(True)
            th.start()

    def _check_if_server_alive(self, serverid):
        '''
        Return true if serverid is present latest list of servers that we
        fetched in this cycle. All threads must call this routine at begining of
        every cycle to check if server they are representing is alive or not.
        '''
        for item in self._all_servers:
            if item['serverid'] == serverid:
                return True
        return False

    def _get_server_role(self, serverid):
        '''
        Return current role of server. This will help a thread in realizing
        the role change of the server it has been monitoring.
        '''
        try:
            for item in self._all_servers:
                if item['serverid'] == serverid:
                    return item['role']
        except:
            return -1

    def _read_db_name(self, ):
        '''
        Read the dbname used to calculate the replication lag.
        '''
        query = "select repl_dbname from lb_advsettings where clusterid=?"
        retry = 0
        dbname = ''

        sqlite_handle = util.get_sqlite_handle(LB_DB_FILE % self._cluster_id)
        if not sqlite_handle:
            return dbname
        db_cursor = sqlite_handle.cursor()

        while retry < MAX_RETRY:
            try :
                db_cursor.execute(query, (self._cluster_id,))
                row = db_cursor.fetchone()
                if row:
                    dbname = row['repl_dbname']
                break
            except (Exception, sqlite3.Error) as e:
                retry = retry + 1
                if retry >= MAX_RETRY:
                    _logger.error("ReplicationMonitor(%d): Failed to determine " \
                                  "database to be used for finding replication " \
                                  "lag : %s" % (self._cluster_id, e))
                else:
                    time.sleep(0.1)
        util.close_sqlite_resources(sqlite_handle, db_cursor)
        return dbname

    def thread_pool_manager(self):
        '''
        This routine will be run in a separate thread to make sure that we always
        have correct and latest list of servers to deal with.
        '''
        _logger.debug("ReplicationMonitor(%d): Thread pool manager started." \
                      % self._cluster_id)

        while True:
            self._dbname = self._read_db_name()
            if self._dbname == '':
                _logger.warn("ReplicationMonitor(%d): Database needed for " \
                                "replication monitoring is not set." \
                                % self._cluster_id)
                time.sleep(1)
                continue

            _logger.debug("ReplicationMonitor(%d): Using db: %s for replicaiton" \
                          " lag check" % (self._cluster_id, self._dbname, ))
            self._root_accnt_info = ReplicationMonitorUtils.find_root_user_info(self._cluster_id)

            if self._root_accnt_info['username'] == '' or \
                self._root_accnt_info['password'] == '':
                _logger.error("ReplicationMonitor(%d): No valid root account ." \
                              % self._cluster_id)
                time.sleep(self._manager_interval)
                continue

            self._all_servers = []

            # FIXME: get lock before modifying the list
            self._all_servers = ReplicationMonitorUtils.get_all_servers(self._cluster_id)
            _logger.info("All servers: %s" % self._all_servers)
            #
            # here we will separate master servers and slave servers.
            #
            for server in self._all_servers:
                if server['type'] == MASTER_SERVER:
                    _logger.info("Starting master thread")
                    self._check_and_add_master_server(server)
                elif server['type'] in SLAVE_SERVER:
                    _logger.info("Starting slave thread")
                    self._check_and_add_slave_server(server)

            time.sleep(self._manager_interval)

    def _has_server_type_changed(self, serverid, server_type):
        '''
        Return True/False indicating whether server type has changed or not.
        If server type has changed for a server then the representing it will
        have to quit. Thread pool manager any way will will spawn a new thread
        with appropriate type (update/fetcher).
        '''
        for item in self._all_servers:
            if (item['serverid'] == serverid) and (item['type'] != server_type):
                return True
        return False


    def update_thread_work_area(self, server):
        '''
        The work area for an update thread.
        '''
        _logger.debug("UpdateThread(%d): update_thread started with : %s" \
                      % (self._cluster_id, server))
        try:
            uto = UpdateThread(self._cluster_id, server['serverid'], \
                           server['ipaddress'], server['port'], \
                           self._dbname, self._table_name, \
                           self._root_accnt_info['username'], \
                           self._root_accnt_info['password'], server_info = server)
        except:
            # what do we do ?
            _logger.error("UpdateThread(%d:%d): Failed to get UpdateThread object." \
                          " Terminated." % (self._cluster_id, server['serverid']))

            # since this server from master servers list since we are exitng
            # this thread
            self._master_servers_list_lock.acquire()
            for item in self._master_servers_list:
                if item['serverid'] == server['serverid']:
                    self._master_servers_list.remove(item)
                    break
            self._master_servers_list_lock.release()
            thread.exit()

        _logger.debug("UpdateThread(%d:%d): Connect OK " \
                      % (self._cluster_id, server['serverid']))

        # init the db state
        if not uto.init_db_state():
            _logger.error("UpdateThread(%d:%d): Error while initializing db. " \
                          "Terminated." % (self._cluster_id, server['serverid']))
            thread.exit()
        _logger.debug("UpdateThread(%d:%d): Initialize db config: OK " \
                      % (self._cluster_id, server['serverid']))
        # get hash
        server_hash = uto.get_server_hash()
        try:
            while True:
                if not self._check_if_server_alive(server['serverid']) or \
                    self._has_server_type_changed(server['serverid'], \
                                                  server['type']):
                    #
                    # this server is gone, we will remove this from
                    # self._master_servers_list and exit
                    #
                    _logger.info("UpdateThread(%d:%d): Either master server is gone " \
                                 "away or its type has changed. Exiting now."  \
                                 % (self._cluster_id, server['serverid']))
                    uto.close_connection()
                    self._master_servers_list_lock.acquire()
                    self._master_servers_list = [x for x in self._master_servers_list \
                                                 if x['serverid'] != server['serverid']]

                    self._master_servers_list_lock.release()
                    thread.exit()

                ts = float(uto.get_server_ts())
                self._master_servers_hash[server_hash] = ts
                time.sleep(1)
        except Exception, ex:
            _logger.error("UpdateThread(%d:%d): crashed : %s" \
                          % (self._cluster_id, server['serverid'], ex))
            _logger.error("%s" % (traceback.format_exc(),))

    def _get_simulated_replication_lag(self,):
        '''
        Return a positive integer as replication lag, based on the data that
        we have.
        '''
        if gSimulationInfo['simulation_type'] == 'FIXED':
            return int(gSimulationInfo['replication_lag'])

        random.seed()
        return random.randint(1, gSimulationInfo['replication_lag'])

    def slave_thread_work_area(self, server, ):
        '''
        Work area for a slave thread.
        '''
        _logger.debug("FetcherThread(%d): Started with : %s" % (self._cluster_id, \
                                                                server))
        #
        # Depending upon the server role,we will decide whether to connect to
        # secondary or not.
        #
        # if role == 5(Secondary- Read intent only)get the lag from tapas's code
        # elif role == 6 (secondary- No connections) then return replication lag as 0
        #

        try:
            fto = FetchThread(self._cluster_id, server['serverid'], \
                               server['ipaddress'], server['port'], \
                               self._dbname, self._table_name, \
                               self._root_accnt_info['username'], \
                               self._root_accnt_info['password'], server['role'])
        except:
            # what do we do ?
            _logger.error("FetchThread(%d:%d): Failed to get FetchThread " \
                          "object. Terminated." % (self._cluster_id, \
                                                   server['serverid']))
            self._slave_servers_list_lock.acquire()
            for item in self._slave_servers_list:
                if item['serverid'] == server['serverid']:
                    self._slave_servers_list.remove(item)
                    break
            self._slave_servers_list_lock.release()
            thread.exit()

        while True:
            if not self._check_if_server_alive(server['serverid']) or \
                self._has_server_type_changed(server['serverid'], server['type']):
                _logger.info("FetchThread(%d:%d): Either slave server is gone " \
                             "away or its type has changed. Exiting now." \
                             % (self._cluster_id, server['serverid']))
                fto.close_connection()
                self._slave_servers_list_lock.acquire()
                self._slave_servers_list = [x for x in self._slave_servers_list \
                                            if x['serverid'] != server['serverid']]

                self._slave_servers_list_lock.release()
                thread.exit()

            # set the server role
            # since role 5 is processes differently, we will need to act
            # accordingly
            new_role = self._get_server_role(server['serverid'])
            if new_role != -1:
                fto.set_server_role(new_role)

            if server['role'] == 6:
                self._repl_lag_dict[server['serverid']] = 0
                time.sleep(1)
                continue

            try:

                #
                # if this server is under simulation, we will override the
                # calculate value with the simulation data. Just as a note we do
                # not want to bypass fto.get_repl_lag() as it will help in
                # making sure that our code works. It's just that we dont need
                # the actual value as of now.
                #
                if server['simulation']:
                    self._repl_lag_dict[server['serverid']] = self._get_simulated_replication_lag()
                else:
                    self._repl_lag_dict[server['serverid']] = fto.get_repl_lag(self._master_servers_hash)

#                 _logger.debug("ReplicationMonitor(%d:%d): fetcher_thread repl " \
#                               "lag: %d" % (self._cluster_id, server['serverid'], \
#                                            self._repl_lag_dict[server['serverid']]))

                if self._repl_lag_dict[server['serverid']] == DEFAULT_REPLICATION_LAG:
                    #
                    # There was some problem getting replication lag, we cant
                    # say for sure. But we will reset the current connection
                    # to remote server.
                    #
                    fto.reset_connection()

            except Exception, ex:
                _logger.error("FetchThread(%d:%d): crashed: %s" \
                                % (self._cluster_id, server['serverid'], ex))
                _logger.error("%s" % (traceback.format_exc(),))
                self._slave_servers_list_lock.acquire()
                self._slave_servers_list = [ x for x in self._slave_servers_list if \
                                            x['serverid'] != server['serverid'] ]
                self._slave_servers_list_lock.release()
                thread.exit()

            time.sleep(1)

    def send_result_to_core(self):
        '''
        Form the resultant string from self._repl_lag_dict and send the string
        using the shared queue.
        '''
        try:
            res_string = ''
            msg_len = len(res_string)
            for key, val in self._repl_lag_dict.iteritems():
                m = "%s|%s\n" % (key, val)
                msg_len = msg_len + len(m)
                res_string = res_string + m

            # now add header
            header = "%s|%s\n" % (self._cluster_id, msg_len)
            final_string = header + res_string
            self._comm_pipe.send(final_string)
        except Exception, ex:
            _logger.error("ReplicationMonitor(%d): Error sending data to " \
                            "parent: %s" % (self._cluster_id, ex))

    def check_if_cluster_up(self):
        '''
        Returns True if cluster associated with this monitor process is up.
        TODO: Is checking for cluster status every second a good idea whene we
            know that sqlite is a very constrained resource ?
        '''
        query = "select status from lb_clusters_summary where cluster_id=?"

        sqlite_handle = util.get_sqlite_handle(GLOBAL_LB_DB_FILE)
        if not sqlite_handle:
            return False

        db_cursor = sqlite_handle.cursor()

        status = 0
        retry = 0
        while retry < MAX_RETRY:
            try :
                db_cursor.execute(query, (self._cluster_id,))
                row = db_cursor.fetchone()
                if row:
                    status = int(row['status'])
                break
            except (Exception,sqlite3.Error) as e:
                retry = retry + 1
                if retry >= MAX_RETRY:
                    _logger.error("Failed to determine status for " \
                                  "cluster: %d : %s" % \
                                  (self._cluster_id, e))
                else:
                    time.sleep(0.1)
        util.close_sqlite_resources(sqlite_handle, db_cursor)
        if status == 1:
            return True
        return False

    def is_replication_enabled(self, ):
        '''
        Check and return true if replication is enabled for this cluster
        otherwise return False.
        '''
        query = "select replication_enabled from lb_advsettings where clusterid=?"

        sqlite_handle = util.get_sqlite_handle(self._lb_dbname)
        if not sqlite_handle:
            return False
        db_cursor = sqlite_handle.cursor()

        status = 0
        retry = 0
        while retry < MAX_RETRY:
            try :
                db_cursor.execute(query, (self._cluster_id,))
                row = db_cursor.fetchone()
                if row:
                    status = int(row['replication_enabled'])
                break
            except (Exception,sqlite3.Error) as e:
                retry = retry + 1
                if retry >= MAX_RETRY:
                    _logger.error("Failed to determine replication_enabled " \
                                  "status for cluster: %d : %s" % \
                                  (self._cluster_id, e))
                else:
                    time.sleep(0.1)
        util.close_sqlite_resources(sqlite_handle, db_cursor)

        if status == 1:
            return True
        return False

def is_parent_alive(parent_pid):
    '''
    Returns True/false
    '''
    if not os.path.exists("/var/run/replication_monitor.pid"):
        return False

    pid_file = "/proc/" + str(parent_pid)
    if os.path.exists(pid_file):
        return True
    return False

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
    A few things worth noting :
    1. In python (specifically), register the signal handler in parent thread
        only. Even signal when raised will be delivered to parent thread only.
    2. Signal call makes an unconditional JUMP to handler routine, it also
        clears any sleep(), or poll() or any blocking call if parent call was in
        any such call.
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

def inform_core_to_enable_rep_check(cluster_id):
    '''
    When starting up, lets inform core that it can start expecting replication
    lag info from us for this cluster. Return True/False to caller indicating
    whether core was able to recieve our request.
    '''
    msg_for_core = 'set|rep_lag_monitor_state|%d|1|' % cluster_id
    target_sock = '/tmp/lb_sock_%d' % cluster_id
    response = util.socket_cmd_runner(unix_sock=target_sock,
                                        command=msg_for_core )
    if response != "SUCCESS":
        _logger.error("ReplicationMonitor(%d): Failed to inform core to enable" \
                      " replication_check  : %s" \
                      % (cluster_id, response))
        return False
    return True

def inform_core_to_disable_repl_check(cluster_id):
    '''
    When exiting, we inform core to stop quering us from replication lag check.
    '''
    #
    # Sleep for half second then send command to core this is required so that 
    # last output of repl lag command will get processed by core.
    #
    time.sleep(0.5)
    msg_for_core = 'set|rep_lag_monitor_state|%d|0|' % cluster_id
    target_sock = '/tmp/lb_sock_%d' % cluster_id
    response = util.socket_cmd_runner(unix_sock=target_sock,
                                        command=msg_for_core )
    if response != "SUCCESS":
        _logger.error("ReplicationMonitor(%d): Failed to inform core to disable" \
                      " replication_check  : %s" \
                      % (cluster_id, response))

def cluster_monitor_routine(cluster_id, comm_pipe, parent_pid):
    '''
    This is target routine of a process spawned for monitoring a cluster.
    TODO: Do we need to check if marker file for this cluster is present ?
    '''
    _logger.debug("ReplicationMonitor(%d): New pocess started with "\
        "clusterid: %d parent_pid:%d"%(cluster_id, cluster_id, parent_pid))

    # set the marker file
    global gMonitorProcessMarkerFile
    gMonitorProcessMarkerFile = "/var/run/replication_monitor_%d.file" \
                                % cluster_id

    # Create the marker file
    try:
        fp = open(gMonitorProcessMarkerFile, "w")
        fp.write(str(os.getpid()))
        fp.close()
    except:
        _logger.error("ReplicationMonitor(%d): Failed to create marker "
                      "file %s" % ( cluster_id, gMonitorProcessMarkerFile))
        sys.exit()

    # resgister to handle SIGTERM
    signal.signal(signal.SIGTERM, cleanup_monitor_process)

    try:
        cmonitor = ClusterMonitor(cluster_id, comm_pipe)
        # inform the core to expect replication data from us
        if not inform_core_to_enable_rep_check(cluster_id):
            _logger.info("ReplicationMonitor(%d): Exiting now" % cluster_id)
            try:
                os.remove(gMonitorProcessMarkerFile)
            except:
                pass
            sys.exit()

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
                _logger.info("ReplicationMonitor(%d): Got signal. Exiting now " \
                             % cluster_id)
                _logger.info("ReplicationMonitor(%d): Asking core to disable " \
                             "replication check " % cluster_id)
                inform_core_to_disable_repl_check(cluster_id)
                sys.exit()

            # check if cluster is up , exit if cluster is marked down
            if not cmonitor.check_if_cluster_up():
                _logger.info("ReplicationMonitor(%d): Cluster is marked " \
                             "down. Exiting now." % cluster_id)
                _logger.info("ReplicationMonitor(%d): Asking core to disable " \
                             "replication check " % cluster_id)
                inform_core_to_disable_repl_check(cluster_id)

                try:
                    os.remove(gMonitorProcessMarkerFile)
                except:
                    pass
                sys.exit()

            if not cmonitor.is_replication_enabled():
                _logger.info("ReplicationMonitor(%d): Replicaiton monitoring" \
                             " for cluster has been disabled. down. Exiting " \
                             "now." % cluster_id)
                _logger.info("ReplicationMonitor(%d): Asking core to disable " \
                             "replication check " % cluster_id)
                inform_core_to_disable_repl_check(cluster_id)
                try:
                    os.remove(gMonitorProcessMarkerFile)
                except:
                    pass
                sys.exit()

            # check if parent is alive
            if not is_parent_alive(parent_pid):
                _logger.info("ReplicationMonitor(%d): Parent is gone "
                             "away, Exiting now."%(cluster_id))
                _logger.info("ReplicationMonitor(%d): Asking core to disable " \
                             "replication check " % cluster_id)
                inform_core_to_disable_repl_check(cluster_id)
                try:
                    os.remove(gMonitorProcessMarkerFile)
                except:
                    pass
                sys.exit()

            # Check if our marker file is present if not terminate
            if not os.path.exists(gMonitorProcessMarkerFile):
                _logger.info("ReplicationMonitor(%d): Marker file missing. "\
                             " Exiting." % ( cluster_id))
                _logger.info("ReplicationMonitor(%d): Asking core to disable " \
                             "replication check " % cluster_id)
                inform_core_to_disable_repl_check(cluster_id)
                sys.exit()

            # epoll does not work for pipes,queues
            try:
                if comm_pipe.poll(5):
                    data = comm_pipe.recv()
                    arg_list = data.split('|')

                    # Process command based on the _sock that we recieved
                    if arg_list[0] == 'rep_lag_time':
                        # Here perform the work and using comm_pipe send the command
                        # back to parent.
                        cmonitor.send_result_to_core()
                    else:
                        _logger.error("ReplicationMonitor(%d): Does not "
                                      "understand command: %s" % (cluster_id, \
                                                                  arg_list[0]))
                    continue
                _logger.warn("ReplicationMonitor(%d): No activity on pipe " \
                                "in last 5 seconds." % ( cluster_id))
            except Exception, ex:
                if errno.errorcode == errno.EINTR:
                    _logger.warn("ReplicationMonitor(%d): Got signal while" \
                                 " polling msg." % ( cluster_id))
    except Exception, ex:
        _logger.error("ReplicationMonitor instance failed !: %s" % ex)
        _logger.error("%s" % (traceback.format_exc(),))

class TCPRequestHandler(object):
    def __init__(self, clisock, ):
        self._sock = clisock

    def process_request(self, request):
        '''
        Read one command, parse it, route it to the proper cluster monitor
        process, get the result and finally return the result to the request
        source.
        '''
        self.recieved_data = request
        if self.recieved_data:
            # now parse what we have got
            if self._parse_command():
                monitored_clusters = []
                monitored_clusters = [k for k,v in gMonitoredClusters.iteritems()]
                if self._cluster_id not in monitored_clusters:
                    _logger.error("RequestManager: No listener for cluster: %d" \
                                  % self._cluster_id)
                    return ("0|4\n")

                if self._send_command_to_cluster_monitor():
                    return self._process_child_response()
                else:
                    _logger.warn("Msg. routing failure for "\
                                            "cluster: %d" % self._cluster_id)
                    return ("0|2\n")
            else:
                # we could not just parse this request
                return ("0|0\n")

    def _set_parent_pipe_for_cluster(self):
        '''
        Set the parent pipe by looking up in global list of cluster structure.
        '''
        self._parent_pipe = gMonitoredClusters[self._cluster_id]['parent_pipe']

    def _process_child_response(self):
        '''
        In this routine we block while we wait for reponse from the monitor
        children. Monitor children will return the properly formed msg which
        we will simply route back to the _sock source.
        '''
        if self._command == 'rep_lag_time':
            if self._parent_pipe.poll(5):
                msg = self._parent_pipe.recv()
                return msg
        _logger.error("RequestManager(%d): Timeout while waiting " \
                        "for data from child process. " % self._cluster_id)
        return ('0|4\n')

    def _send_command_to_cluster_monitor(self):
        '''
        Sends the currently recieved command to the corresponding cluster
        monitor. We are not using locks for accessing a pipe since, pipes are
        created per cluster. And a cluster will send a single command at any
        instance.
        '''
        self._set_parent_pipe_for_cluster()
        msg_sent = False
        #
        # check if the target listener is present, if not then no
        # point in sending a _sock
        #
        marker_file = "/var/run/replication_monitor_%d.file" % (self._cluster_id, )
        if os.path.exists(marker_file):
            msg = self._command + "|" + self._data
            if not self._parent_pipe:
                _logger.error('No valid parent pipe for cluster : %d' \
                              % self._cluster_id)
            else:
                self._parent_pipe.send(msg)
                msg_sent = True
        else:
            _logger.error("Request Handler: No listener for cluster: "\
                                  "%d "% self._cluster_id)
            msg_sent = False

        if not msg_sent :
            _logger.error("Request Handler: Failed to deliver command to "\
                          "cluster monitor for cluster: %d" % self._cluster_id)
            return False
        return True

    def _parse_command(self):
        '''
        Parse the _sock that we recieved.
        we recieve commands in this synatx:
         1. get repl_lag_time <cluster_id>

         so command is repl_lag_time and data is None here and cluster_id is set.
        '''
        #initial values
        self._command = None
        self._cluster_id = None
        self._data = None
        self._origin = "gui"

        try:
            t = []
            self.recieved_data.strip()
            t = self.recieved_data.split()
            if t[0].upper() == 'GET' and t[1].upper() == 'REP_LAG_TIME':
                self._command = 'rep_lag_time'
                self._cluster_id = int(t[2])
                self._data = 'DUMMY'

        except Exception, e:
            _logger.error("Request Manager: Error parsing _sock data: %s" % e)
            return False

        if ((self._command == None) or (self._cluster_id == None)):
            _logger.error("Request Manager : Error parsing _sock data")
            return False

        _logger.debug("Request Manager: request_type: %s "\
                      "cluster_id: %d"%(self._command, self._cluster_id))
        return True


class ReplicationMonitorDaemon(daemon.Daemon):
    """This class runs REPLICATION_MONITOR as a daemon"""
    def _get_sleep_val_from_config(self):
        sleep_interval = _config.getfloat("general", "sleep")
        if sleep_interval == 0.0:
            sleep_interval = 30 # default
        return sleep_interval

    def _cleanup_marker_files(self):
        '''
        Remove all marker files in use by replication_monitor or its children
        '''
        fl = glob.glob('/var/run/replication_monitor*')
        for _file in fl:
            if os.path.exists(_file):
                os.remove(_file)

    def _signal_handler(self, signum, frame):
        '''
        Process in the event of a signal that we received. Since this part
        belongs to parent, in the event a signal, we will make sure that
        we cleanup our children and then only exit.
        '''
        _logger.info("ReplicationMonitor: Got signal, prepairing to exit gracefully.")
        for k,v in gMonitoredClusters.iteritems():
            phandle = v['child_process_handle']
            if phandle.is_alive():
                _logger.info("ReplicationMonitor: Stopping monitor process for " \
                             "cluster: %d" % int(k))
                #
                # p.terminate() issues SIGTERM to the child. As a safety measure, it
                # should never be issued to children who are using shared data, semaphores
                # locks etc. Howver, if children themselves have signal handlers
                # registered then it should not be a problem. (i.e. children should
                # perform cleanup as and when required)
                #
                phandle.terminate()
                phandle.join(TIME_TO_WAIT_FOR_CHILD_JOIN)
                # check if process is still alive
                try:
                    os.kill(phandle.pid, 0)
                    # if still here this process is taking too much time, we kill it
                    _logger.warn("ReplicationMonitor: Monitor process for cluster:" \
                                 "%d is taking too long (> %d seconds) to quit, " \
                                 "killing it now " % (k, TIME_TO_WAIT_FOR_CHILD_JOIN))
                    os.kill(phandle.pid, 9)
                    # remove its marker file
                    try:
                        marker_file = "/var/run/replication_monitor_%d.file" % (k, )
                        os.unlink(marker_file)
                    except:
                        pass
                    # now join it so as to collect resources
                    phandle.join()

                except Exception, ex:
                    # process has stopped
                    pass
                _logger.info("ReplicationMonitor: Successfully Stopped monitor " \
                             "process for cluster: %d" % int(k))

        self._cleanup_marker_files()
        _logger.info("ReplicationMonitor: Finished cleaning up.")
        # now we exit. since pid file is cleanedup by the calling instance's call
        # of stop() method, we donot have anything to cleanup as such.
        sys.exit()

    def _register_signal_handler(self):
        '''
        Registers a set of signals to catch.
        '''
        signals = [ signal.SIGTERM ]
        for s in signals:
            signal.signal(s, self._signal_handler)

    def _read_all_clusterids(self):
        '''
        #TODO read all clusters and their type also 
        Read a list of all server_ids with the status field.
        '''
        cluster_ids = []
        sqlite_handle = util.get_sqlite_handle(GLOBAL_LB_DB_FILE)
        if not sqlite_handle:
            return  cluster_ids

        db_cursor = sqlite_handle.cursor()
        query = "select cluster_id, status, type from lb_clusters_summary where status<>9 and type in %s" % str(PLATFORM_TYPES)
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

    def _read_repl_status(self, clusterid):
        '''
        Read replication_enabled status from sqlite for all clusters.
        '''
        query = "select replication_enabled from lb_advsettings where clusterid=?"

        sqlite_handle = util.get_sqlite_handle(LB_DB_FILE % clusterid)
        if not sqlite_handle:
            return

        db_cursor = sqlite_handle.cursor()
        retry = 0
        while retry < MAX_RETRY:
            try:
                db_cursor.execute(query, (clusterid,))
                for row in db_cursor.fetchall():
                    self._repl_status[clusterid] = int(row['replication_enabled'])
                    _logger.info("Replication Enable is %s for cluster id %s" %(row['replication_enabled'], clusterid)) 
                break
            except Exception, ex:
                retry = retry + 1
                if retry >= MAX_RETRY:
                    _logger.error("Failed to read replication_enabled status of" \
                                  " clusters: %s" % ex)
                else:
                    time.sleep(0.1)
        util.close_sqlite_resources(sqlite_handle, db_cursor)

    def _is_replication_enabled_for_cluster(self, cid):
        '''
        Look into self._repl_status to find if replcation monitoring is enabled
        for this cluster or not.
        '''
        _logger.info("****************** replication status for cid is %s" %self._repl_status)
        return True if self._repl_status.get(cid) == 1 else False

    def _read_simulation_info(self):
        '''
        Read information related to simulation. This information will be used
        when script is running in simulation mode.
        '''
        try:
            gSimulationInfo['target_ips'] = _config.get('simulation', 'target_ips')
        except:
            pass
        try:
            gSimulationInfo['replication_lag'] = _config.getint('simulation', \
                                                                'replication_lag')
        except:
            pass

        try:
            t = _config.get('simulation', 'simulation_type')
            if t == 'RANDOM':
                gSimulationInfo['simulation_type'] = t
        except:
            pass

        _logger.info("Running replication monitor in simulation mode. ")
        _logger.debug("Target IPs: [%s], Replication lag: %d, simulation type: %s" \
                      % (gSimulationInfo['target_ips'], \
                         gSimulationInfo['replication_lag'], \
                         gSimulationInfo['simulation_type']))

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
            _logger.warn("ReplicationMonitor(%d): '/system/lb.sqlite' "\
                            "does not exist " % (os.getpid(),))
            time.sleep(1)
        try:

            self.listener_thread = None
            self.sleep_interval = self._get_sleep_val_from_config()

            if gSimulationInfo['active'] :
                self._read_simulation_info()
        except Exception, ex:
            _logger.error("ReplicationMonitor : Service Initialization failed: "\
                            "%s" % ex)
            _logger.error("%s" % (traceback.format_exc(),))

        while True:
            try:
                self._all_clusterids = [] # list of dicts {'clusterid':n , 'status':, 'type':}
                self._all_clusterids = self._read_all_clusterids()

                # Create listener thread, if not already present
                self._create_socket_listener_thread()

                #Read replication status of all clusters
                self._repl_status = {}
                for item in self._all_clusterids:
                    self._read_repl_status(item.get('clusterid'))

                #
                # make sure that we have collected any children exited during
                # previous cycle
                #
                multiprocessing.active_children()
                #
                # see if a new cluster has been added and that we need any
                # monitor process for it.
                #
                self._spwan_monitor_children()
                _logger.debug("Parent sleeping for %f seconds" \
                              % (self.sleep_interval))
                time.sleep(self.sleep_interval)
            except Exception, ex:
                _logger.error("ReplicationMonitor Daemon run failed: %s" % ex)
                _logger.error("%s" % (traceback.format_exc(),))
                if os.path.exists(NO_SAFETY_NET_FILE):
                    #
                    # If the debug file is present, we break out the service so
                    # that we can catch this condition in QA/Development,
                    # otherwise we loop forever.
                    #
                    break
                # We are sleeping because ...
                _logger.debug("Sleeping for %f seconds"%self.sleep_interval)
                time.sleep(self.sleep_interval)

    def _find_stopped_cluster_ids(self):
        '''
        Return a list of cluster ids for clusters which have been stopped.
        '''
        return [item['clusterid'] for item in self._all_clusterids if item.get('status') == 0]

    def _find_running_cluster_ids(self):
        '''
        Returns the list of clusters that are running
        '''
        return [item['clusterid'] for item in self._all_clusterids if item.get('status') == 1]

    def _stop_monitor_process_for_cluster(self, cid):
        '''
        Send a SIGTERM to the monitor process for cluster <cid> .
        '''
        phandle = gMonitoredClusters[cid]['child_process_handle']
        if phandle.is_alive():
            _logger.info("UserCredsMonitor: Cluster %d is marked down" % cid)
            _logger.info("UserCredsMonitor: Stopping monitor process for " \
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
                _logger.warn("UserCredsMonitor: Monitor process for cluster:" \
                             "%d is taking too long (> %d seconds) to quit, " \
                             "killing it now " % (cid, TIME_TO_WAIT_FOR_CHILD_JOIN))
                os.kill(phandle.pid, 9)

                # now join it so as to collect resources
                phandle.join()
            except Exception, ex:
                # process has stopped
                pass
            _logger.info("UserCredsMonitor: Successfully Stopped monitor " \
                         "process for cluster: %d" % int(cid))

    def _get_cluster_type(self, cid):
        for cluster_info in self._all_clusterids:
            if cluster_info['clusterid'] == cid:
                return cluster_info['type']
        return None

    def _spwan_monitor_children(self):
        '''
        Spawn monitor processes for clusters for which there is no monitor.
        '''
        
        # stop monitor processes if their corresponding cluster is marked down
        stopped_clusters = []
        stopped_clusters = self._find_stopped_cluster_ids()
        for cid in stopped_clusters:
            marker_file = "/var/run/user_creds_monitor_%d.file" % cid
            if os.path.exists(marker_file):
                self._stop_monitor_process_for_cluster(cid)
        
        cluster_ids = []
        cluster_ids = self._find_running_cluster_ids()
        _logger.info("****************** all cluster ids are %s" %self._all_clusterids)
        # If no cluster id then return
        if len(cluster_ids) == 0:
            _logger.warn("No running clusters. Will not monitor any cluster.")
            return

        for cid in cluster_ids:
            #
            # We will spawn a new monitor process for the cluster for which there
            # is no marker file.
            #
            marker_file = "/var/run/replication_monitor_%d.file" % (cid, )
            if not os.path.exists(marker_file):
                if not self._is_replication_enabled_for_cluster(cid):
                    _logger.info("ReplicationMonitor: Monitoring is disabled " \
                                 "for cluster: %d or problem determining its " \
                                 "status." % cid)
                    continue

                parent_pipe,child_pipe = multiprocessing.Pipe(duplex=True)
                p = multiprocessing.Process(target=cluster_monitor_routine,
                                            args=(cid, child_pipe, os.getpid()))

                d = {}
                d['child_process_handle'] = p
                d['cluster_state'] = READY
                d['parent_pipe'] = parent_pipe
                d['child_pipe'] = child_pipe
                d['cluster_state_lock'] = threading.Lock()
                d['cluster_type'] = self._get_cluster_type(cid)
                gMonitoredClusters[cid] = d.copy()

                # Start the new process
                _logger.info("Spawning a new monitor process for cluster:"\
                             " %d" % (cid))
                p.start()
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


    def _create_socket_listener_thread(self):
        if self.listener_thread == None:
            self.listener_thread = threading.Thread(target = self._socket_listener_thread_function)
            self.listener_thread.setDaemon(True)
            self.listener_thread.start()

    def _socket_listener_thread_function(self):
        #
        # we will not use multi-threaded handling of incoming requests since
        # requests will come from IDb only, we will use plain sockets
        # instead of using SocketServer.ThreadingTCPServer which creates a thread
        # for every requests made.
        #
        HOST = '127.0.0.1'
        PORT = 5510
        # address = 'localhost,%d' % PORT # this format is needed when using AF_UNIX
        address = (HOST, PORT)
        MAX_RECV_SIZE = 1024
        try:
            server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_sock.bind(address)
            server_sock.listen(1000)
            server_sock.setblocking(0)
            _logger.info("RequestManager: Listening for requests on : (%s,%d)" \
                         % (HOST, PORT))

            epoll = select.epoll()
            epoll.register(server_sock.fileno(), select.EPOLLIN | select.EPOLLET \
                           | select.EPOLLERR)

            # we will use a persistent connection with our client. Whenever we
            # detect a new client connection, we will close the existing one
            # and use the new one. Note that, as per our current implementation
            # we expect only one client.

            # for every client being served, with its fd we will store a tuple
            # (connection_object, TCPRequestHandler_object)
            connections = {}
            while True:
                try:
                    events = epoll.poll(10) # wait for events to happen
                    if len(events) == 0:
                        _logger.warn("RequestManager: No requests in last 10 seconds. ")
                        time.sleep(1)
                        continue

                    for fileno, event in events:
                        if fileno == server_sock.fileno():
                            #
                            # since this EPOLLIN event in on serversocket then
                            # it must be for a new conenction
                            #
                            try:
                                clisock, (remhost, remport) = server_sock.accept()
                                clisock.setblocking(0)
                                epoll.register(clisock.fileno(), select.EPOLLIN | \
                                               select.EPOLLERR | select.EPOLLET)
                                req_handler = TCPRequestHandler(clisock)
                                connections[clisock.fileno()] = (clisock, req_handler)
                            except socket.error:
                                pass

                        elif event & select.EPOLLIN:
                            #
                            # Note that when we get a EPOLLIN /EPOLLOUT event and
                            # in between that if something goes wrong then, we
                            # will not a get an epoll() event rather an exception
                            #
                            try:
                                req = ''
                                req = connections[fileno][0].recv(MAX_RECV_SIZE)
                                # this is a read event for a request
                                if len(req) == 0:
                                    # we could not read anything
#                                     _logger.error("Read on fd: %d returned 0 bytes. " \
#                                                   "Closing client socket." % (fileno))
                                    try:
                                        epoll.unregister(fileno)
                                        connections[fileno][0].shutdown(socket.SHUT_RDWR)
                                        del connections[fileno]
                                    except:
                                        pass
                                else:
                                    response = ''
                                    try:
                                        response = connections[fileno][1].process_request(req)
                                    except Exception, ex:
                                        _logger.error("RequestManager: Problem " \
                                                      "while processing request:" \
                                                      " %s" % ex)
                                        _logger.error("%s" % (traceback.format_exc(),))
                                        response = '0|5'

                                    _logger.info("RequestManager: cluster_id|msg_len followed by "
                                                 "dbid|replicationleg Sending " \
                                                  "response is: %s" % (response))
                                    # we can write response by modifying the poll event
                                    # required for this socket but for simplicity we
                                    # will write that here.
                                    # we dont a explicit logic to write n bytes and make
                                    # sure that we could actually write that many bytes
                                    # since python's sendall() does just that.
                                    # this is wrapper over send() with 'write() and check'
                                    # logic.
                                    try:
                                        connections[fileno][0].sendall(response)
                                    except Exception, ex:
                                        _logger.error("RequestManager: Problem " \
                                                      "while writing to socket: " \
                                                      "%d : %s. Closing the " \
                                                      "same." % (fileno, ex))
                                        try:
                                            epoll.unregister(fileno)
                                            connections[fileno][0].shutdown(socket.SHUT_RDWR)
                                            del connections[fileno]
                                        except:
                                            pass

                            except Exception, ex:
                                _logger.error("RequestManager: Probem while " \
                                              "accessing socket: [%s]. Closing " \
                                              "client socket" % ex)
                                _logger.error("%s" % (traceback.format_exc(),))
                                try:
                                    epoll.unregister(fileno)
                                    connections[fileno][0].shutdown(socket.SHUT_RDWR)
                                    del connections[fileno]
                                except:
                                    pass

                        elif event & select.EPOLLOUT:
                            # here we can verify that we were able to write required no. of bytes
                            # Note that just like, reading from a client socket,  while
                            # writing also we may encounter write error, which would
                            # mean a broken socket. IN that case, we will need
                            # to close.
                            pass

                        elif event & select.EPOLLERR:
                            # when is EPOLLERR raised ? Does this happen even when
                            # we read 0 bytes ?
                            if fileno == server_sock.fileno():
                                # we cant accept any error on server socket.
                                _logger.error("RequestManager: Error on server " \
                                              "socket. Closing it.")
                                try:
                                    epoll.unregister(server_sock.fileno())
                                    epoll.close()
                                    server_sock.close()
                                except:
                                    pass
                                time.sleep(1)

                                # TODO: also clean all entries in connections dictionary
                                # we quit
                                self.listener_thread = None
                                return

                            _logger.error("Error on client socket: %d . Closing" \
                                          " it." % fileno)
                            # check for which socket we got this error
#                             epoll.modify(fileno, select.EPOLLET) # whats this for ?
                            try:
                                # close any further communication with this socket
                                epoll.unregister(fileno)
                                connections[fileno][0].shutdown(socket.SHUT_RDWR)
                                del connections[fileno]
                            except:
                                pass

                        elif event & select.EPOLLHUP:
                            # does not this occur as part of EPOLLERR ?
                            try:
                                epoll.unregister(fileno)
                                connections[fileno][0].close()
                                del connections[fileno]
                            except:
                                pass

                except Exception, ex:
                    _logger.error("An unknown problem occurred while waiting " \
                                  "for events. Listener thread exiting. Error : %s" % ex)
                    _logger.error("%s" % (traceback.format_exc(),))
                    try:
                        epoll.unregister(server_sock.fileno())
                        epoll.close()
                        server_sock.close()
                    except:
                        pass
                    time.sleep(1)
                    # we quit
                    self.listener_thread = None
                    return

        except Exception, ex:
            _logger.error("Error while initializing socket: %s" % ex)
            _logger.error("%s" % (traceback.format_exc(),))
            self.listener_thread = None
            return

def main():
    # Go away if you are not root
    if not os.geteuid()==0:
        sys.exit("replication_monitor: You must be root to run this script\n")

    # Parse the command line options
    try:
        opts, args = getopt.getopt(sys.argv[1:],
                            'hdvs',
                            ["help", "debug", "version", "simulate"])
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
        elif opt[0] == '-s' or opt[0] == '--simulate':
            gSimulationInfo['active'] = True

    if len(args) > 2:
        _usage('Invalid args %s' % args)

    # Initialize the logger
    log.config_logging()
    global _config
    _config = get_config_parser(REPLICATION_MONITOR_CONF)

    replication_monitor_daemon = \
        ReplicationMonitorDaemon('/var/run/replication_monitor.pid')
    if args:
        if 'stop' == args[0]:
            _logger.info("******* REPLICATION_MONITOR stopping **********")
            replication_monitor_daemon.stop()
        elif 'restart' == args[0]:
            _logger.info("****** REPLICATION_MONITOR restarting *********")
            replication_monitor_daemon.restart()
        else:
            err_msg = "Invalid command %s" % (repr(args[0]),)
            print >> sys.stderr, err_msg
            _logger.error("%s" % (err_msg,))
            sys.exit(2)
        sys.exit(0)

    if _debug:
        _logger.info("***** REPLICATION_MONITOR starting (debug mode)*******")
        replication_monitor_daemon.foreground()
    else:
        _logger.info("*********** REPLICATION_MONITOR starting ************")
        replication_monitor_daemon.start()

if __name__ == "__main__":
    main()
