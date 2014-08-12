#!/usr/bin/python
#
# Copyright (C) 2013 ScaleArc, Inc., all rights reserved.
#

"""This file implements the daemon for USER_CREDS_MONITOR
"""
import getopt
import os
import sys
import traceback
import time
import sqlite3
import base64
import ConfigParser
import re
import hashlib
import binascii
import socket
import SocketServer
import threading
import multiprocessing
import ipaddr
import signal, errno

#
# import modules from site-packages. iDB package has to be installed before
# the following modules can be imported
#
import idb.log as log
import idb.daemon as daemon
import idb.util as util
import idb.mysql_util as mysql_util

from mssql_user_monitor import FetchFromBDC
# The configuration file for USER_CREDS_MONITOR service
IDB_DIR_ETC = '/opt/idb/conf'
USER_CREDS_MONITOR_CONF = 'user_creds_monitor.conf'

GLOBAL_LB_DB_FILE = "/system/lb.sqlite"
LB_DB_FILE = "/system/lb_%s.sqlite"
PLATFORM_TYPES = ('MYSQL', 'MSSQL')

NO_SAFETY_NET_FILE = "/opt/idb/.idb_utils_no_safety_net"
MAX_RETRY = 10
CURL_BIN = '/usr/bin/curl -s -k'
MAX_USERS_IMPORT_LIMIT = 500
MIN_ALLOWED_AUTO_FETCH_INTERVAL = 60
TIME_TO_WAIT_FOR_CHILD_JOIN = 60 # in seconds

# list of cluster objects of type ClusterLevelAutoImport
gMonitoredClusters = {} #list of cluster_dict
gClusterStatusMarkerFile = ''
gSignalChildToQuit = False
PIPE_READY = 1
PIPE_BUSY = 0

# List of supported commands
SET_AUTO_IMPORT_INTERVAL = 1
AUTO_IMPORT_ENABLE = 2
SET_USER_EXCLUSION_LIST = 3
FETCH_USERLIST_MAXCOUNT = 4
FETCH_USERLIST_BY_PAGE = 5
APIKEY = ''
gUserCredsSupportedCommands = [SET_AUTO_IMPORT_INTERVAL, AUTO_IMPORT_ENABLE, \
                                 SET_USER_EXCLUSION_LIST, FETCH_USERLIST_MAXCOUNT, \
                                 FETCH_USERLIST_BY_PAGE]

# Global related to SSL
CLIENT_CERT_PATH = '/system/certs/cid_%s/client.pem'
CLIENT_KEY_PATH = '/system/certs/cid_%s/client.key'
CA_CERT_PATH = '/system/certs/cid_%s/ca.pem'

###################################################
# The global variable for the configuration parser
_config = None

# These can be overriden via command-line options
_debug = False

# Initialize logging
log.set_logging_prefix("user_creds_monitor")
_logger = log.get_logger("user_creds_monitor")

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

class UserCredsUtils():
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
    def find_master_server_details(cls, cluster_id):
        '''
        Find the master server (read+write) in this cluster and retrieve its
        ip,port and server id in a dictionary..
        '''
        master_server = {'ip':'', 'server_id':-1, 'port':-1}

        sqlite_handle = util.get_sqlite_handle(LB_DB_FILE % cluster_id)
        if sqlite_handle:
            db_cursor = sqlite_handle.cursor()
            query = "select serverid, ipaddress, port from lb_servers where " \
                    "status=1 and type=0 ORDER BY serverid"
            retry = 0
            while retry < MAX_RETRY:
                try:
                    db_cursor.execute(query)
                    row = db_cursor.fetchone()
                    if row:
                        master_server['ip'] = row['ipaddress']
                        master_server['server_id'] = int(row['serverid'])
                        master_server['port'] = int(row['port'])
                    break

                except Exception, ex:
                    retry = retry + 1
                    if retry >= MAX_RETRY:
                        _logger.error("Failed to retrieve master server details" \
                                      " for cluster %d : %s" % (cluster_id, ex))
                    else:
                        time.sleep(0.1)

            util.close_sqlite_resources(sqlite_handle, db_cursor)
        return master_server

    @classmethod
    def find_root_user_info(cls, cluster_id):
        '''
        Return a dictionary containing  root account information from table
        lb_users for this cluster_id.
        '''
        root_accnt_info = {'username':'', 'password':''}

        sqlite_handle = util.get_sqlite_handle(LB_DB_FILE % cluster_id)
        if not sqlite_handle:
            return root_accnt_info

        db_cursor = sqlite_handle.cursor()
        query = "select username, encpassword from lb_users where type = 1 " \
                "and status=1"

        retry = 0
        while retry < MAX_RETRY:
            try:
                db_cursor.execute(query)
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
    def import_users_from_sqlite(cls, cluster_id):
        '''
        Return a list of user accounts from lb.sqlite which are to be monitored.

        **Update**: To prevent older user accounts (having host filed empty) from
        crashing the service, we will simply ignore entries from lb_users where
        host field is empty.
        '''
        user_list = []
        user_list_item = {'userid':'', 'user':'', 'password':'', \
                          'pwd_type':0,'host':'' }

        sqlite_handle = util.get_sqlite_handle(LB_DB_FILE % cluster_id)
        if not sqlite_handle:
            return user_list

        db_cursor = sqlite_handle.cursor()
        query = "select userid, username, password, pwd_type, host from lb_users " \
                "where type = 2 and status = 1"

        retry = 0
        accounts_with_empty_host = 0
        while retry < MAX_RETRY:
            try:
                db_cursor.execute(query)
                for row in db_cursor.fetchall():
                    if row['host'] == None or row['host'] == '':
                        accounts_with_empty_host = accounts_with_empty_host + 1
                        continue
                    user_list_item['user'] = row['username']
                    user_list_item['password'] = row['password'].upper()
                    user_list_item['pwd_type'] = int(row['pwd_type'])
                    user_list_item['userid'] = int(row['userid'])
                    user_list_item['host'] = row['host']
                    user_list.append(user_list_item.copy())

                break
            except Exception, ex:
                retry = retry + 1
                if retry >= MAX_RETRY:
                    _logger.error("Failed to retrieve list of user accounts to" \
                                " monitor for cluster %d : %s" % (cluster_id, ex))
                else:
                    time.sleep(0.1)

        util.close_sqlite_resources(sqlite_handle, db_cursor)
        if accounts_with_empty_host:
            _logger.warn("ClusterMonitor(%d): Found %d user accounts with " \
                         "empty host field. Skipped all of them." % \
                         (cluster_id, accounts_with_empty_host))

        return user_list

    @classmethod
    def update_passwd_in_lbsqlite(cls, clusterid, username, new_pass):
        '''
        Update new passwd for this user. Also set the pwd entry to 1 as we
        will be storing new passwd which is in sha2 form.
        '''
        sqlite_handle = util.get_sqlite_handle(LB_DB_FILE % clusterid)
        if sqlite_handle:
            db_cursor = sqlite_handle.cursor()

            query = "update lb_users set pwd_type=1, password='" + \
                new_pass + "' where username='" + username + "' and status=1"

            retry = 0
            transaction_test_ok = False
            while retry < MAX_RETRY:
                try:
                    if not transaction_test_ok:
                        db_cursor.execute(query)
                        transaction_test_ok = True

                    sqlite_handle.commit()
                    break
                except Exception, ex:
                    retry = retry + 1
                    if retry >= MAX_RETRY:
                        _logger.error("Failed to store new password for user: %s " \
                                      "in cluster: %d into sqlite file. : %s" \
                                      %(username, clusterid, ex))
                    else:
                        time.sleep(0.1)
            util.close_sqlite_resources(sqlite_handle, db_cursor)

    @classmethod
    def fetch_dblist_from_sqlite(cls, cluster_id):
        '''
        Fetch all (dbid,dbname) entries for this cluster from lb_dbs and return
         a list of all such entries.

        '''
        dblist_from_sqlite = []
        sqlite_handle = util.get_sqlite_handle(LB_DB_FILE % cluster_id)
        if sqlite_handle:
            db_cursor = sqlite_handle.cursor()

            query = "select dbid, dbname from lb_dbs where status = 1 and " \
                    "clusterid = "+str(cluster_id)

            retry = 0
            while retry < MAX_RETRY:
                try:
                    db_cursor.execute(query)
                    for row in db_cursor.fetchall():
                        db = {'dbname':'', 'dbid':-1}
                        db['dbname'] = row['dbname']
                        db['dbid'] = int(row['dbid'])

                        dblist_from_sqlite.append(db.copy())
                    break
                except Exception, ex:
                    retry = retry + 1
                    if retry >= MAX_RETRY :
                        _logger.error("Failed to fetch list of dbs from sqlite " \
                                      "for cluster %d : %s"% (cluster_id, ex))
                    else:
                        time.sleep(0.1)

            util.close_sqlite_resources(sqlite_handle, db_cursor)
        return dblist_from_sqlite

    @classmethod
    def find_cluster_info(cls, cluster_id):
        '''
        return outbound ipadress of this cluster
        '''
        ssl_enabled = False
        out_ip = ''
        query = "select backendip,ssl_enabled from lb_clusters where status = 1;"
        sqlite_handle = util.get_sqlite_handle(LB_DB_FILE % cluster_id)
        if sqlite_handle:
            db_cursor = sqlite_handle.cursor()

            retry = 0
            out_ip = ''
            ssl_enabled = False
            while retry < MAX_RETRY:
                try:
                    db_cursor.execute(query)
                    row = db_cursor.fetchone()
                    if row:
                        out_ip = row['backendip']
                        ssl_enabled = True if int(row['ssl_enabled']) else False
                    break
                except (Exception, sqlite3.Error) as e:
                    retry = retry + 1
                    if retry >= MAX_RETRY:
                        _logger.error("Failed to find cluster info"\
                                        ": %d : %s" % (cluster_id, e))
                    else:
                        time.sleep(0.1)

            util.close_sqlite_resources(sqlite_handle, db_cursor)
        return ssl_enabled, out_ip

class ClusterMonitor(object):
    '''
    This class implements methods/member variables which monitor a per cluster
    user accounts change.

    Although we need to import accounts from mysql every interval but do we need
    to do the same for sqlite as well. How about we do it first time, and then
    whenever there is account addition/deletion, then only we do it. Since
    lb.sqlite seems very constrained resource at current time, this will help
    in minimizing access to the sqlite db.
    '''
    def __init__(self, cluster_id):
        self._cluster_id = cluster_id
        self._lb_dbname = LB_DB_FILE % cluster_id
        self._exclusion_list = []
        self._dbname2id_map_list = [] # a list of d={'dbname':'','dbid':-1}
        self._user = None
        self._master_server = None
        self._root_accnt_info = None
        self._dbname2id_map_list = []
        self._user_id = -1
        self._accounts_imported_from_mysql = []
        self._accounts_imported_from_sqlite = []
        self._worker_thread = None
        self._auto_update_enabled = False
        self._processing_cycle = 60
        self._state_refresh_interval = 15 # in seconds
        self._last_state_updated = 0 # time in seconds, float
        self._processed_accounts_list_from_mysql = [] # will be used to send to UI
        self._page_size = 10
        self._safe_to_quit = False
        self._old_dblist = []
        self._ssl_enabled = False
        self._ssl_components = {'cert': CLIENT_CERT_PATH % cluster_id, 
                                 'key': CLIENT_KEY_PATH % cluster_id,
                                 'ca': CA_CERT_PATH % cluster_id}

        # UserCredsUtils.import_users_from_sqlite(self._cluster_id)

    def set_exclusion_string(self,exclusion_list_string):
        self._exclusion_list = exclusion_list_string.split(',')
        _logger.info("ClusterMonitor(%d): Setting exclusion list: %s" \
                     % (self._cluster_id, self._exclusion_list))

    def enable_auto_update(self):
        self._auto_update_enabled = True

    def disable_auto_update(self):
        self._auto_update_enabled = False

    def set_processing_cycle(self, interval):
        self._processing_cycle = interval

    def _is_master_server_valid(self):
        '''
        Returns True if master server for this cluster is present else False.
        '''
        if self._master_server['ip'] == '' or \
                self._master_server['server_id'] == -1:
            return False
        return True

    def _is_root_account_valid(self):
        '''
        Returns True if root account needed for connecting to mysql is available
        for this cluster otherwise return False.
        '''
        if self._root_accnt_info['username'] == '' or \
                self._root_accnt_info['password'] == '':
            return False
        return True

    def _set_user(self,user):
        self._user = user

    def _set_user_id(self,user_id):
        self._user_id = int(user_id)

    def check_if_cluster_up(self):
        '''Returns True if cluster associated with this monitor process is up.
        TODO: Is checking for cluster status every second a good idea whene we
            know that sqlite is a very constrained resource ?
        '''
        query = "select status from lb_clusters_summary where cluster_id=? and type in %s " % str(PLATFORM_TYPES)

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

    # Retaining the below function definition. Uncomment/purge if not neeeded.
    def _set_db_list(self, dblist_string):
        self._new_dblist_for_user = []
        d = {'dbid':-1, 'dbname':''}

        l = dblist_string.split(',')
        for item in l:
            d['dbname'] = item
            self._new_dblist_for_user.append(d.copy())

        _logger.info("ClusterMonitor(%d): Setting db list: %s "
                     "for user: %s" % (self._cluster_id,
                                     self._new_dblist_for_user,
                                     self._user))
    def _get_ssl_info(self):
        return self._ssl_components if self._ssl_enabled else None

    def _populate_state_data(self):
        '''
        Since routines like, fetch_user_list and _process_user_accounts take
        a lot of time, querying both sqlite and mysql sources for data is a
        costly affair. Therefore, instead of fetching these details every time
        a these routines execute, we can probably populate the dataset once
        in a cycle.

        This routine will do just that. It will be called once in a cycle by
        monitor child process. Routines which requires those structures can
        continue using those values. We will attempt to minimize access to
        mysql/sqlite sources.
        '''
        self._master_server = UserCredsUtils.find_master_server_details(self._cluster_id)
        if not self._is_master_server_valid():
            # reset account lists and return back as we do not have a master server
            self._accounts_imported_from_mysql = []
            self._accounts_imported_from_sqlite = []
            _logger.warn("ClusterMonitor(%d): Master server (read+write) missing. " \
                         "Further processing skipped." % self._cluster_id)
            return

        self._root_accnt_info = UserCredsUtils.find_root_user_info(self._cluster_id)
        if not self._is_root_account_valid():
            _logger.warn("ClusterMonitor(%d): No valid root account. Further" \
                         " processing skipped." % self._cluster_id)
            return

        self._ssl_enabled, cluster_oip = UserCredsUtils.find_cluster_info(self._cluster_id)
        _logger.debug("ClusterMonitor(%d): Cluster Outbound IP is %s and"\
                        " Enable SSL flag is %s" % (self._cluster_id, 
                                                    cluster_oip, 
                                                    self._ssl_enabled))
        
        _logger.info("ClusterMonitor(%d): Refreshing list of logical dbs" \
                             % (self._cluster_id))
        self._populate_dblist()

        # import user accounts from mysql server
        self._accounts_imported_from_mysql = mysql_util.import_accounts_from_mysql(
                                                    self._master_server['ip'],
                                                    self._master_server['port'],
                                                    self._root_accnt_info,
                                                    ssl=self._get_ssl_info())
        # process mysql imported accounts and assign order to accounts
        _logger.debug("ClusterMonitor(%d): Ranking mysql imported user accounts." \
                       % (self._cluster_id, ))
        self._assign_order_to_imported_mysql_accounts(cluster_oip)

        #
        # now copy mysql im,ported list to processed_accounts_list.
        # this is the list that we send to UI when queried through a page index
        #
        self._processed_accounts_list_from_mysql = self._accounts_imported_from_mysql

        self._accounts_imported_from_sqlite = UserCredsUtils.import_users_from_sqlite(self._cluster_id)
        _logger.debug("ClusterMonitor(%d): Fetched %d total users from mysql, "\
                    "and a total of %d users are in iDB configuration" % \
                                            (self._cluster_id, \
                                            len(self._accounts_imported_from_mysql),
                                            len(self._accounts_imported_from_sqlite)))

    def monitor_accounts_for_password_change(self):
        '''
        Main routine which will load required info from lb_users in lb.sqlite
        and perform user-account import if necessary.

        Note that for every cluster no matter how many database servers are
        connected, there will be a special root account using which we can
        query the dbserver of address given by ipaddress.
        '''
        if not self._is_master_server_valid():
            return

        if not self._is_root_account_valid():
            return

        # now find list of user accounts to monitor
        if len(self._accounts_imported_from_sqlite) == 0:
            _logger.warn("ClusterMonitor(%d): Could not find any user accounts" \
                         " to monitor " % self._cluster_id)
            return

        # now we will monitor each such user
        for user in self._accounts_imported_from_sqlite:
#             _logger.debug("Checking if update needed for user: %s in cluster: %d "\
#                 "with dbserver: %s" % (user['username'], self._cluster_id,
#                                         self._master_server['ip']))
            new_pass = self._get_new_password_for_user(user)
            if new_pass == "":
                continue

            _logger.info("ClusterMonitor(%d): Changing password for user: %s" % \
                         (self._cluster_id, user['user'] ))
            #send a signal to core that password for this user has changed
            cmd = "set|"+"edit_fetch_user_password|" + str(self._cluster_id) + \
                    "|" + str(user['userid']) + "|" + new_pass + "|"
            response = util.socket_cmd_runner(unix_sock="/tmp/lb_sock", 
                                                command=cmd)

            if response != "SUCCESS":
                _logger.error("ClusterMonitor(%d): Failed to inform core about" \
                              " password change for user %s: %s" \
                              % (self._cluster_id, user['user'], response))
                continue

            UserCredsUtils.update_passwd_in_lbsqlite(self._cluster_id, \
                                                     user['user'], new_pass)

    def _process_dblist_change_for_user(self):
        '''
        Check if dblist_from_mysql association have changed for a user, if yes then
        add/delete new dbs to this user.
        '''
        if not self._is_master_server_valid():
            return

        if not self._is_root_account_valid():
            return

        # now find list of user accounts to monitor
        if len(self._accounts_imported_from_sqlite) == 0:
            _logger.warn("ClusterMonitor(%d): Could not find any user accounts" \
                         " to monitor " % self._cluster_id)
            return

        for acct in self._accounts_imported_from_sqlite:
#             _logger.debug("Monitoring user: %s" % acct['user'])
            dbname2dbid_list = []
            dblist_from_mysql = mysql_util.retrieve_logical_dbs_from_dbserver(self._master_server['ip'],
                                                               self._master_server['port'],
                                                               self._root_accnt_info,
                                                               acct['user'], acct['host'],
                                                               ssl=self._get_ssl_info())

            for db in dblist_from_mysql:
                dbid = self._find_dbid_for_db(db, self._dbname2id_map_list)
                #
                # if in newer list ( i.e. self._dbname2id_map_list) we could
                # not find the dbid for a db then it could be because this dbname
                # was removed in this cycle by routine (populate_dblist).
                # therefore, we will also check in list old_dblist to see if there
                # is a map for this db in the old list.
                #
                if dbid == -1:
                    dbid = self._find_dbid_for_db(db, self._old_dblist)
                if dbid == -1:
                    _logger.warn("ClusterMonitor(%d): Invalid dbid for " \
                                   "dbname: %s user: %s in sqlite" \
                                   % (self._cluster_id, db, acct['user']))
                    continue

                t_dict = {}
                t_dict['dbname'] = db
                t_dict['dbid'] = dbid
                dbname2dbid_list.append(t_dict.copy())
#             _logger.debug("Got %d db entries from mysql" % len(dbname2dbid_list))

            dbusers_from_sqlite = self._find_dbids_assigned_to_user(acct['userid'])
#             _logger.debug("Got %d db entries from sqlite" % len(dbusers_from_sqlite))
            dbs_deleted = []
            dbs_added = []

            # create list of dbids for dbs imported from mysql
            dbids_from_mysql = [item['dbid'] for item in dbname2dbid_list]
            dbids_from_sqlite = [item['dbid'] for item in dbusers_from_sqlite]

            # look for deleted entries
            deleted_entries = []
            for dbid in dbids_from_sqlite:
                if dbid not in dbids_from_mysql:
                    deleted_entries.append(dbid)

            # not form dbs_deleted which is a list of dicts {'dbid':'', 'dbuserid':''}
            # here we will form a list of all items which have been deleted
            for i in deleted_entries:
                for j in dbusers_from_sqlite:
                    if i == j['dbid']:
                        dbs_deleted.append(j.copy())

#             _logger.debug("no. of dbs_deleted: %d" % (len(dbs_deleted), ))
            if len(dbs_deleted) > 0:
                self._remove_entries_from_lbdbusers(acct['user'], acct['userid'], dbs_deleted)
                time.sleep(1)

            added_entries = []
            for dbid in dbids_from_mysql:
                if dbid not in dbids_from_sqlite:
                    added_entries.append(dbid)

            # now form dbs_added which is alist of dicts {'dbid':'', dbname:''}
            # note that for dbs_added we need the dbname as well in informing
            # core rather than just dbuserid
            for i in added_entries:
                for j in dbname2dbid_list:
                    if i == j['dbid']:
                        dbs_added.append(j.copy())

#             _logger.debug("no. of dbs_added: %d" % (len(dbs_added),))
            #
            # Note that dbs_deleted is a list of dicts {<dbid>, <dbuserid>}
            # whereas dbs_added a list of dicts {<dbid>, <dbname>}
            #
            if len(dbs_added) > 0:
                self._add_entries_to_lbdbusers(acct['user'], acct['userid'], dbs_added)
                time.sleep(1)

    def _remove_entries_from_lbdbusers(self, username, userid, dbuserids_to_remove):
        '''
        Remove dbids for username and userid and also inform core of the same.
        dbuserids_to_remove is a list of dicts {'dbid':n, 'dbuserid':n}
        '''
        if len(dbuserids_to_remove) == 0:
            return

        query_list = []
        for row in dbuserids_to_remove:
            # dbid or dbuserid both will have same effect as they are unique for
            # a given user in a cluster.
            query = "delete from lb_dbusers where clusterid=" + str(self._cluster_id) + \
                    " and status=1 and dbid=" + str(row['dbid']) + \
                    " and userid=" + str(userid) + ";"
            query_list.append(query)

        # execute all queries
        sqlite_handle = util.get_sqlite_handle(LB_DB_FILE % self._cluster_id, 
                                               timeout = 0.1)
        db_cursor = sqlite_handle.cursor()

        retry = 0
        trans_active = False
        while retry < MAX_RETRY:
            try:
                if not trans_active:
                    db_cursor.execute("BEGIN TRANSACTION")
                    for query in query_list:
                        db_cursor.execute(query)
                    trans_active = True

                sqlite_handle.commit()
                break
            except (Exception, sqlite3.Error) as e:
                if str(e).find('database is locked') == -1:
                    _logger.error("ClusterMonitor(%d): Failed to execute " \
                                  "script. Removing dbid entries failed for user." \
                                  ":%s : %s" % (self._cluster_id, username, e))
                    break

                retry = retry + 1
                if retry >= MAX_RETRY:
                    _logger.error("ClusterMonitor(%d): Failed to execute " \
                                  "script. Removing dbid entries failed for user." \
                                  ":%s : %s" % (self._cluster_id, username, e))
                else:
                    time.sleep(0.1)

        util.close_sqlite_resources(sqlite_handle, db_cursor)

        # now lets inform core that we have removed some dbid entries
        for item in dbuserids_to_remove:
            cmd = "delete|logical_db|" + str(self._cluster_id) + "|" + \
                    username + "|" + str(item['dbuserid']) + "|"
            response = util.socket_cmd_runner(unix_sock="/tmp/lb_sock", 
                                                command=cmd)
            if response != "SUCCESS":
                _logger.error("ClusterMonitor(%d): Failed to inform" \
                                " core about logical_db deletion: cmd: %s" \
                                " response: %s" % (self._cluster_id,
                                                cmd, response))

    def _get_new_password_for_user(self, user_info):
        '''
        user_info is a dict having elements userid, paswd and pwd_type. We
        will query the remote db server. and retrieve user_id and password pair
        for the userid that we have. If both match then we return an empty string
        else we return the passwd that we recieved from server.
        '''
        sha2_password = user_info['password']
        if user_info['pwd_type'] == 0:
                #
                # we need to get sha1 of what we already have.
                # what if password is of improper length, sha1 has passwords of
                # length 32 chars so we will ignore all password mentioned here
                # which are less than 32 chars in length.
                #
            binary_password = PasswordUtils.get_binary_of_hex(user_info['password'])
            sha2_password = PasswordUtils.find_sha1(binary_password)

        passwd_from_server = mysql_util.retrieve_password_from_dbserver(
                            self._master_server['ip'], self._master_server['port'],\
                            self._root_accnt_info, user_info['user'], user_info['host'],
                            ssl=self._get_ssl_info())

        if passwd_from_server == "" or passwd_from_server == None:
            # thats bad, how could we get an empty password
#             _logger.debug("Server returned an empty response.")
            return ""

        # remove the leading * if present
        if passwd_from_server[0] == '*':
            passwd_from_server = passwd_from_server[1:]

        #
        # Password recieved from server is always in upper case so comparison
        # will be in upper case only.
        #
        if passwd_from_server == (sha2_password).upper():
            return ""

        return passwd_from_server

    def _process_user_accounts(self):
        '''
        Start monitoring the asked cluster.
        1. find the master server in queried clusterid
        select serverid,ipaddress,port from lb_servers where status <> 9 and
        clusterid=1 and type=0;

        2. now find root user for this database server
        select username,encpassword from lb_users where type=1 and status <> 9
        and clusterid=1;

        3. now decode this encpassword and use it to login into server obtained
         in 1. We will import all user/password pair except those usernames
         passed in exclusion list  from this db server.
        select distinct User,Password from user where User <> '' and  Password
        <> '' ;

        //4. import user_list from sqlite
        select username,type,pwd_type,password from lb_users where clusterid=1
        and status <> 9
        '''
        if not self._is_master_server_valid():
            return

        if not self._is_root_account_valid():
            return
        #
        # Since we also read user accounts list to monitor for password change
        # do we need to do it separately here in class member? This list will
        # always be there taking up space. If could use same list in both cases
        # probably, the process could be much faster.
        #
        # We will go this way as of now, since password monitoring can continue
        # even if auto_import is enabled or not.
        #

        # if no accounts were found in remote server then we do nothing
        if len(self._accounts_imported_from_mysql) == 0:
            _logger.error("ClusterMonitor(%d): Failed to fetch any accounts " \
                          "from mysql server." % self._cluster_id)
            return

        # check for deleted user accounts
        _logger.debug("ClusterMonitor(%d): Checking for deleted user"\
                      " accounts"%(self._cluster_id))
        self._process_deleted_accounts()

        # check for newly added user accounts
        _logger.debug("ClusterMonitor(%d): Checking for newly added "\
                      "user accounts"%(self._cluster_id))
        self._process_newly_added_accounts()

    def send_auto_fetched_user_list(self, comm_pipe, seek_page_index):
        '''
        This routine will write back the list of auto_fetched usrs back to
        the comm_pipe.

        While writing we will check if self._accounts_imported_from_mysql has been
        populated, if yes the we return it else we will populate the user list
        now. Note that this routine is on-demand service. It does not require
        auto-fetch to be enabled.

        Note: there might be inconsistencies between two request made by UI to fetch
        records. Assume that UI got the current_page_size count as 250. Now this will
        leave us with 25 pages. However, while UI has been fetching records, lets after
        it has fetched 5 pages, in meantime, worker thread found that now less than 40 records are
        left. In this case, asking for 6th page will cause an error. In cases
        where there are no reords as per asked by UI, we will return the last page
        available to us.

        Solution: To help UI notice this issue, we will first reply a header
        indicating the seek_page_index that we are sending. UI should check if the
        seek_page_index it is getting is indeed what it asked for. If it's not so, then
        it should ask for max_count again.
        '''
        if not self._is_master_server_valid():
            return

        if not self._is_root_account_valid():
            return

        if len(self._processed_accounts_list_from_mysql) == 0 :
            _logger.error("ClusterMonitor(%d): Accounts imported from mysql have" \
                          " not been processed as yet, try again later" \
                          % self._cluster_id)
            msg = "clusterid=%d&cmd=fetch_userlist_bypage&page=%d&page_size=%d&err_code=0\n" \
                % (self._cluster_id, seek_page_index, 0)
            _logger.debug("ClusterMonitor(%d): Sending header: %s" \
                          % (self._cluster_id, msg))

            if not comm_pipe.closed:
                comm_pipe.send(msg)
            else:
                _logger.warn("ClusterMonitor(%d): Pipe has been closed " \
                             "unexpectedly.." % self._cluster_id)
            return

        # find max pages
        max_page_index = 0
        if len(self._processed_accounts_list_from_mysql) % self._page_size:
            max_page_index = (len(self._processed_accounts_list_from_mysql) / self._page_size) + 1
        else:
            max_page_index = len(self._processed_accounts_list_from_mysql) / self._page_size


        # sanitize seek_page_index
        if seek_page_index < 1:
            seek_page_index = 1
        if seek_page_index > max_page_index:
            seek_page_index = max_page_index

        lower_page_index = (seek_page_index - 1) * 10
        if seek_page_index == max_page_index:
            upper_page_index = len(self._processed_accounts_list_from_mysql)
        else:
            upper_page_index = (seek_page_index * 10) # we need only from 0 -9 but since
                                            # python range() does not include
                                            # upper bound, we are good to go.
        #
        # For all pages except, last page, each will have self._page_size len
        # of records in it.
        #

        # find how many records we are sending for this page
        current_page_size = upper_page_index - lower_page_index

        # now we will format this data and write to the pipe
        # cluster_id|user_name|password|host|order|db1,db2,db3
        # cluster_id|user_name|password|host|order|db1,db2,db3
        # cluster_id|user_name|password|host|order|db1,db2,db3
        #
        # First send how many total records we have
        #

        msg = "clusterid=%d&cmd=fetch_userlist_bypage&page=%d&page_size=%d&err_code=0\n" \
                % (self._cluster_id, seek_page_index, current_page_size)
        _logger.debug("ClusterMonitor(%d): Sending header: %s" \
                      % (self._cluster_id, msg))

        if not comm_pipe.closed:
            comm_pipe.send(msg)
        else:
            _logger.warn("ClusterMonitor(%d): Pipe has been closed " \
                         "unexpectedly.." % self._cluster_id)
            return

        for i in range(lower_page_index, upper_page_index):
            dblist = mysql_util.retrieve_logical_dbs_from_dbserver(self._master_server['ip'],
                                                               self._master_server['port'],
                                                               self._root_accnt_info,
                                                               self._processed_accounts_list_from_mysql[i]['user'],
                                                               self._processed_accounts_list_from_mysql[i]['host'],
                                                               ssl=self._get_ssl_info())

            # form a comma separated list of dbs
            dblist_str = ''
            if dblist and len(dblist) != 0:
                dblist_str = ','.join(dblist)
#                 for db in dblist:
#                     tstr = "%s" % db
#                     dblist_str = dblist_str + ',' + tstr
#                 if dblist_str != '':
#                     dblist_str = dblist_str[1:] # remove the preceding comma


            msg = str(self._cluster_id) + "|" + self._processed_accounts_list_from_mysql[i]['user'] + '|' + \
                        self._processed_accounts_list_from_mysql[i]['password'] + \
                        "|" + self._processed_accounts_list_from_mysql[i]['host'] + \
                        "|" + str(self._processed_accounts_list_from_mysql[i]['order']) + \
                        "|" + dblist_str + "\n"
            try:
                if not comm_pipe.closed:
                    comm_pipe.send(msg)
                else:
                    _logger.error("ClusterMonitor(%d): Pipe has been closed. Is " \
                              "parent alive ? Will not send any more data." \
                              % (self._cluster_id))
                    return
            except Exception, ex:
                _logger.error("ClusterMonitor(%d): Error sending data to " \
                              "parent: %s" % (self._cluster_id, ex))

    def _assign_order_to_imported_mysql_accounts(self, cluster_oip):
        '''
        Assign order to mysql imported user accounts. The idea of order is to
        find the user account which is closest

        The order 1 is what we will insert,delete/ monitor for password change.
        Order values are basically to help UI and the user_creds_service to find
        the closest user account that is accessible to us.

        The order is decided for a user account based on how closely this
        cluster's outbound IP lies in subnet/host address of that user account.
        We can have multiple user accounts with same username but not in the
        same host address.

        Algorithm :
                # for better searching, sort the list based on user name
                1. cluster_outbound_ip = _find_outbound_ip_of_cluster(self._cluster_id)
                2. for each acct in self.mysql_imported_accounts:
                    2.1 if acct['order'] is not -1:
                            # we have already assigned order to this account
                           continue

                    2.2 same_username_list = _find_same_username_accnts(acct)
                        # if list is sorted then the moment we find a different
                        # username than acct['user'] we can return
                        # same_username_list is a list of dicts in
                        # self.mysql_imported_accounts

                    2.3 same_user_name_list.append(acct)
                    2.4 # Now filter same_user_name_list based on whether
                        # cluster_outbound_ip lies in host subnet
                        for item in same_user_name_list:
                            if _check_if_host_lies_in_cluster_oip(cluster_oip, item['host']) == False:
                                same_user_name_list.remove(item)
                    2.5 # Now sort same_user_name_list based on closely our
                        # cluster_oip lies in this subnet
                        same_user_name_list = _sort_list_based_on_closest_oip_match(same_user_name_list)

                    2.6 # Now assign order with increasing value to each item
                        # in same_user_name_list starting from 1
                        order = 1
                        for item in same_user_name_list:
                            item['order'] = order
                            order = order + 1
                    2.7 # Now once again we iterate over the same_user_name_list and
                        # for each item , find the corresponding item in
                        # self._mysql_imported_list assign the order
                        # How do we optimize it ?
                        for i in same_user_name_list:
                            for j in self._mysql_imported_user_accounts:
                                if i['user_name'] == j['user_name'] and i['password'] == j['password']
                                    and i['host'] == j['host']:
                                        j['order'] = i['order']
                                        break
                3. return

        verify if we have valid hostnames. if not an ipaddress then try to resolve
        its hostname and get the ipaddress if failed, ignore this entry.
        '''
        if cluster_oip.upper() == 'ALL' or cluster_oip == '':
            cluster_oip = util.get_ipaddress_of_interface('eth0')

        _logger.debug("ClusterMonitor(%d): Determined outbound ipaddress: %s" \
                      % (self._cluster_id, cluster_oip))

        max_imported_accounts = len(self._accounts_imported_from_mysql)
        current_index = 0
        old_index = 0
        while current_index < max_imported_accounts:
            if self._accounts_imported_from_mysql[current_index]['order'] != -1:
                # it has already been processed
                continue

            same_username_list = []
            same_username_list, current_index = self._find_accounts_with_same_username(current_index, max_imported_accounts)
#             if len(same_username_list) > 1:
#             l = [x['user'] for x in same_username_list]
#             _logger.debug("same username list(%d): index: %d : %s" % (len(same_username_list), (current_index-len(l)), l))

            new_username_list = []
            # first stage filtering, direct in-domain check
            for item in same_username_list:
                host = ''
                host = self._get_proper_host_address(item['host'])
                if host == '':
                    _logger.error("ClusterMonitor(%d): Problem in resolving " \
                                  "host address for user %s with host %s" \
                                  % (self._cluster_id, item['user'], \
                                    item['host']))
                    continue

                if self._check_if_cluster_oip_in_host_subnet(cluster_oip, host):
                    item['proper_host'] = host
                    new_username_list.append(item)
                    continue
#                 else:
#                    _logger.debug("User creds for '%s' from host %s does not "
#                                  "match Cluster IP %s" % (item['user'],
#                                             item['host'], cluster_oip))

            if len(new_username_list) == 1 and len(same_username_list) == 1:
                # if we have only one account which has passed previous two tests
                # then we can assign it order 1
                self._accounts_imported_from_mysql[current_index - 1]['order'] = 1
            else:
                # even if there is only entry in new_username_list still we need
                # to find the exact account in mysql imported_accounts list.
                # Now cluster_oip is in each subnet of same_username_list['host']
                new_username_list = self._sort_list_based_on_closest_oip_match(new_username_list)
                new_username_list.reverse()

                # now assign orders to elements in this list
                order = 1
                for item in new_username_list:
                    item['order'] = order
                    order = order + 1

                # now find these elements in our main list and assign orders
                for record in new_username_list:
                    for i in range(old_index, current_index):
                        if self._accounts_imported_from_mysql[i]['user'] == record['user'] and \
                            self._accounts_imported_from_mysql[i]['password'] == record['password'] and \
                                self._accounts_imported_from_mysql[i]['host'] == record['host']:
                            self._accounts_imported_from_mysql[i]['order'] = record['order']
                            break

            old_index = current_index

    def _sort_list_based_on_closest_oip_match(self, same_username_list):
        '''
        Sort the entries in this list based on the mask value.
        Using just a simple bubble sort. Since at max , there will be 4 entries.
        in same_username_list
        '''
        return sorted(same_username_list, \
                      key=lambda x: int(x['proper_host'].split('/')[1]))

    def _get_proper_host_address(self, host):
        '''
        Ensure that host address is in proper form as understood by ipaddr
        library. Return host address in proper form or empty string if operation
        failed.
        '''
        # check if it's a 4 octet integers
        if self._check_if_proper_ipv4_address(host):
            # make sure that if we have a proper ipv4 address then it's
            # mask is set as : '10.0.0.23/32'
            host = host + "/32"

        host_ip = ''
        try:
            addr = ipaddr.IPv4Network(host)
            host_ip = host
        except:
            # hostname could be a DNS name or in mysql host format as 10.%,
            # %, 10.5.% . Decide what it is
            if host.find('%') > -1:
                # it's in form 10.%
                host_ip = self._convert_host_addr_from_mysql_format(host)
            else:
                # it could be a fully qualified domain name
                host_ip = self._resolve_hostname(host)
                if host_ip != '':
                    host_ip = host_ip + '/32'
        return host_ip

    def _check_if_cluster_oip_in_host_subnet(self, cluster_oip, host):
        '''
        Check if cluster_oip lies in host subnet. Before doing this , make sure
        we have proper ipaddress as host. Return true/false depending what we
        find.
        '''
        if cluster_oip == '0.0.0.0':
            return True

        try:
            subnet = ipaddr.IPv4Network(host)
        except Exception, ex:
            _logger.error("ClusterMonitor(%d): Failed to create subnet object:" \
                          " %s " % (self._cluster_id, ex,))
            return False

        try:
            addr = ipaddr.IPv4Address(cluster_oip)
        except Exception, ex:
            _logger.error("ClusterMonitor(%d): Failed to create cluster IP " \
                          "object: %s" % (self._cluster_id, ex))
            return False

        if addr in subnet:
            return True
        return False

    def _check_if_proper_ipv4_address(self, ip_string):
        '''
        Check if the passed ip_string is valid IPv4 address.
        '''
        try:
            socket.inet_aton(ip_string)
            return True
        except:
            return False

    def _convert_host_addr_from_mysql_format(self, host):
        '''
        Host address is in format %,10.%,10.5.%,10.5.12.% format. Convert this
        into a format understood by ipaddr library like '10.5.0.0/16'
        '''
        try:

            #
            # we have seen host names like 10.0% and 10.0.5% as well. make sure
            # that we convert them to 10.0.% and 10.0.5.%
            #
            '''
            nstr = ''
            for i in range(len(host)):
                if host[i] != '.' and (i+1) < len(host):
                    if host[i+1] == '%':
                        nstr = nstr + host[i] + '.'
                        continue
                nstr = nstr + host[i]
            host = nstr

            # Same thing using list comprehension
            nstr = None
            for item in [re.sub('%','',x) if x != '%' else x for x in str1.split('.')]:
                if not nstr:
                    nstr = item
                else:
                    nstr = nstr + '.' + item

            # Another method a simpler one
            nhost = ''
            for x in host.split('.'):
                if x != '%':
                    x = re.sub('%','',x)
                if nhost == '':
                    nhost = nhost + x
                else:
                    nhost = nhost + "." + x
            '''
            # host = nstr
            # a far nifitier method
            host = ".".join([re.sub('%', '', x) if x != '%' else x for x in host.split('.')])

            for x in range(4 - len(host.split('.'))):
                host = host + '.%'

            if host == '%.%.%.%':
                return '0.0.0.0/0'

            mask_factor = 0
            for item in host.split('.'):
                if item == '%':
                    mask_factor = mask_factor + 1

            if mask_factor == 0:
                return (host + '/' + str(4 * 8))

            host = re.sub('%', '0', host)
            return (host + '/' + str(mask_factor * 8))
        except:
            return ''

    def _resolve_hostname(self, host):
        '''
        Resolve hostname and return its ipaddress else an empty string
        '''
        try:
            return socket.gethostbyname(host)
        except Exception, ex:
            _logger.error("ClusterMonitor(%d): Error resolving host %s: " \
                          "%s" % (self._cluster_id, host, ex))
            return ''

    def _find_accounts_with_same_username(self, record_index, max_records):
        '''
        Return a list of entries from self._mysql_imported_accounts
        which have same username as the one being asked.

        TRICK: Since we know that list is sorted based on username, we can
        return from this routine as soon as we find an entry having different
        username.
        '''
        same_username_list = []
        while record_index < max_records:
            if len(same_username_list) == 0:
                same_username_list.append(self._accounts_imported_from_mysql[record_index])
                record_index = record_index + 1
                continue
            if same_username_list[-1]['user'] == self._accounts_imported_from_mysql[record_index]['user']:
                same_username_list.append(self._accounts_imported_from_mysql[record_index])
                record_index = record_index + 1
            else:
                return (same_username_list, record_index)

        return (same_username_list, record_index)

    def _find_dbids_assigned_to_user(self, user_id):
        '''
        Returns a list of tuples (dbid,dbuserid) that are assigned to
        user_id in this cluster select dbid from lb_dbusers where userid=1
        and status =1 and clusterid=1
        '''
        dbid_list = []
        sqlite_handle = util.get_sqlite_handle(self._lb_dbname)
        if sqlite_handle:
            db_cursor = sqlite_handle.cursor()
            query = "select dbuserid, dbid from lb_dbusers where userid = " + \
                        str(user_id) + " and status = 1"

            retry = 0
            dbid_list = []
            while retry < MAX_RETRY:
                try:
                    db_cursor.execute(query)
                    for row in db_cursor.fetchall():
                        if row:
                            d = {}
                            d['dbid'] = int(row['dbid'])
                            d['dbuserid'] = int(row['dbuserid'])
                            dbid_list.append(d.copy())
                    break
                except (Exception, sqlite3.Error) as e:
                    retry = retry + 1
                    if retry >= MAX_RETRY:
                        _logger.error("ClusterMonitor(%d): Failed to find dbids " \
                                      "assigned to user: %d : %s" \
                                      % (self._cluster_id, user_id, e))
                    else:
                        time.sleep(0.1)

            util.close_sqlite_resources(sqlite_handle, db_cursor)
        return dbid_list

    def _populate_dblist(self):
        '''
        Form the complete (dbid,dbname) mapping by querying mysql and sqlite
        sources. This routine will ensure that we always have correct no. of db
        entries that we have in mysql.

        The complete list of dbname to dbid mapping is stored in
        self._dbname2id_map_list.
        '''
        # import list of databases
        dblist_from_mysql = mysql_util.import_dblist_from_mysql(self._master_server['ip'],
                                                      self._master_server['port'],
                                                      self._root_accnt_info,
                                                      ssl=self._get_ssl_info())

        if len(dblist_from_mysql) ==0:
            # It's not possible that remote server has no db
            _logger.info("ClusterMonitor(%d): Got an empty dblist_from_mysql from "
                          " remote server: %s" % (self._cluster_id,
                                                  self._master_server['ip']))
            return

        #
        # Now create dbname to dbid mapping by either looking the sqlite file
        # or creating a new entry for non-existent dbname and then obtaining its
        # dbid
        #
        self._old_dblist = UserCredsUtils.fetch_dblist_from_sqlite(self._cluster_id)

        if len(self._dbname2id_map_list) == 0:
            self._dbname2id_map_list = self._old_dblist

        dbs_to_remove = []
        dbs_to_add = []

        # first check if any db has been dropped from the server side
        for item in self._old_dblist:
            if item['dbname'] not in dblist_from_mysql:
                dbs_to_remove.append(item)
        self._remove_entries_from_lbdbs(dbs_to_remove)

        # check if we have added any new global dbs
        dbname_list_from_sqlite = [ x['dbname'] for x in self._old_dblist ]
        for item in dblist_from_mysql:
            if item not in dbname_list_from_sqlite:
                dbs_to_add.append(item)
        self._add_entries_to_lbdbs(dbs_to_add)

    def _remove_entries_from_lbdbs(self, dblist):
        '''
        Remove entries from lb_dbs. dblist is a list of dict = {'dbname':db1,'dbid':1}
        We will perform entire operation in transaction and also inform the core
        about it.

        '''
        if len(dblist) == 0:
            return

        query_list = []
        for item in dblist:
            query = "delete from lb_dbs where dbid=%d;" \
                    % (item['dbid'], )
            query_list.append(query)

        # execute all queries
        sqlite_handle = util.get_sqlite_handle(self._lb_dbname)
        db_cursor = sqlite_handle.cursor()

        retry = 0
        trans_active = False
        while retry < MAX_RETRY:
            try:
                if not trans_active:
                    db_cursor.execute("BEGIN TRANSACTION")
                    for query in query_list:
                        db_cursor.execute(query)
                    trans_active = True

                sqlite_handle.commit()
                break
            except (Exception, sqlite3.Error) as e:
                if str(e).find('database is locked') == -1:
                    _logger.error("ClusterMonitor(%d): Failed to execute " \
                                  "script. Removing logical dbs failed." \
                                  ": %s" % (self._cluster_id, e))
                    break

                retry = retry + 1
                if retry >= MAX_RETRY:
                    _logger.error("ClusterMonitor(%d): Failed to execute " \
                                  "script. Removing logical dbs failed and max." \
                                  " retry limit reached." \
                                  ": %s" % (self._cluster_id, e))
                else:
                    time.sleep(0.1)

        util.close_sqlite_resources(sqlite_handle, db_cursor)

        #
        # now we will inform core that we have imported entries in
        # newly_added list
        #
        for entry in dblist:
            cmd = "delete|global_ldb|%d|%d|" % (self._cluster_id, entry['dbid'])

            response = util.socket_cmd_runner(unix_sock="/tmp/lb_sock", 
                                                command=cmd)
            _logger.info("ClusterMonitor(%d): Sent command to core to remove " \
                         "global logical db: %s" % (self._cluster_id, cmd))
            if response != "SUCCESS":
                _logger.error("ClusterMonitor(%d): Failed to " \
                              "inform core about removal of global logical_db :" \
                              " cmd: %s response: %s" % (self._cluster_id,
                                                cmd, response))

    def _add_entries_to_lbdbs(self, dblist):
        '''
        Add new db enties to lb_dbs. dblist is a list of logical dbnames (strings)
        Also inform core once we are done inserting all entries in one transaction.
        cmd = "add|global_ldb|" + str(self._cluster_id) + "|" + str(dbid) + "|" + dbname + "|"

        Also update the self._dbname2id_map_list
        '''
        if len(dblist) == 0:
            return

        query_list = []
        t = time.strftime("%Y-%m-%d %H:%M:%S")
        for db in dblist:
            query = "insert into lb_dbs(dbname, clusterid,status,updatetime) " \
                    "values('%s', %d, 1, '%s');" % (db, self._cluster_id, t)
            query_list.append(query)

        # execute all queries
        sqlite_handle = util.get_sqlite_handle(self._lb_dbname)
        db_cursor = sqlite_handle.cursor()

        retry = 0
        trans_active = False
        while retry < MAX_RETRY:
            try:
                if not trans_active:
                    db_cursor.execute("BEGIN TRANSACTION")
                    for query in query_list:
                        db_cursor.execute(query)
                    trans_active = True

                sqlite_handle.commit()
                break
            except (Exception, sqlite3.Error) as e:
                if str(e).find('database is locked') == -1:
                    _logger.error("ClusterMonitor(%d): Failed to execute " \
                                  "script. Adding global logical dbs failed." \
                                  ": %s" % (self._cluster_id, e))
                    break

                retry = retry + 1
                if retry >= MAX_RETRY:
                    _logger.error("ClusterMonitor(%d): Failed to execute " \
                                  "script. Adding global logical dbs failed and" \
                                  " max. retry limit reached." \
                                  ": %s" % (self._cluster_id, e))
                else:
                    time.sleep(0.1)

        util.close_sqlite_resources(sqlite_handle, db_cursor)

        dblist_from_sqlite = []
        dblist_from_sqlite = UserCredsUtils.fetch_dblist_from_sqlite(self._cluster_id)

        newly_added = []
        for i in dblist:
            for j in dblist_from_sqlite:
                if i == j['dbname']:
                    d = {}
                    d['dbid'] = j['dbid']
                    d['dbname'] = j['dbname']
                    newly_added.append(d.copy())
        #
        # now we will inform core that we have imported entries in
        # newly_added list
        #
        for entry in newly_added:
            cmd = "add|global_ldb|%d|%d|%s|" % (self._cluster_id, entry['dbid'],\
                                                entry['dbname'])
            response = util.socket_cmd_runner(unix_sock="/tmp/lb_sock", 
                                                command=cmd)
            _logger.info("ClusterMonitor(%d): Sent command to core to add " \
                         "global logical db: %s" % (self._cluster_id, cmd))
            if response != "SUCCESS":
                _logger.error("ClusterMonitor(%d): Failed to " \
                              "inform core about global logical_db addition: cmd: %s " \
                              "response: %s" % (self._cluster_id,
                                                cmd, response))
        #
        # now since, dblist_from_Sqlite that we just fetched has latest information
        # about all maps, we will update self._dbname2id_map_list with it.
        #
        self._dbname2id_map_list = dblist_from_sqlite

    def _ROLLBACK_remove_db_from_lbdbs(self, dbid):
        '''
        Remove the logical db as given by dbid as we failed to inform core,
        '''

    def _find_dbid_for_db(self, dbname, name2id_map_list):
        '''
        Check if dbname is present in dbname2id_map_list that we have created.
        IF yes then return its corresponding dbid else -1.
        '''
        for db in name2id_map_list:
            if db['dbname'] == dbname:
                return db['dbid']
        return -1

    def _process_deleted_accounts(self):
        '''
        Check if any user account that we have is not present in remote
        mysql server. Once such an entry is found then delete the local entry.
        '''
        # mysql_user_list = [ imported_user['user'] for imported_user in self._accounts_imported_from_mysql ]
        if len(self._accounts_imported_from_sqlite) == 0:
            _logger.error("ClusterMonitor(%d): Failed to fetch any accounts " \
                          "from sqlite." % self._cluster_id)
            return

        mysql_user_list = []
        for imported_user in self._accounts_imported_from_mysql:
            if imported_user['order'] == 1:
                mysql_user_list.append((imported_user['user'],imported_user['host']))

        # search accounts imported from sqlite in the list of mysql imported list
        for sqlite_imported_account in self._accounts_imported_from_sqlite:
            if (sqlite_imported_account['user'], sqlite_imported_account['host'])\
                                                not in mysql_user_list:
                #
                # When an account is being removed, we will remove all databaes
                # attached with it
                #
                _logger.info("ClusterMonitor(%d): Detaching databases "
                              "from user '%s'@'%s' " % \
                              (self._cluster_id,
                               sqlite_imported_account['user'],
                               sqlite_imported_account['host'],))

                self._dettach_databases_from_user_being_deleted(sqlite_imported_account['user'], \
                                                                  sqlite_imported_account['host'])

                 # remove this user from sqlite file
                _logger.info("ClusterMonitor(%d): Removing user: %s with "
                              "host: %s" % (self._cluster_id,
                                            repr(sqlite_imported_account['user']),
                                            repr(sqlite_imported_account['host']), ))

                self._remove_entry_from_lbusers(sqlite_imported_account['user'],
                                                sqlite_imported_account['host'])

                # reload account list from sqlite
                self._accounts_imported_from_sqlite = UserCredsUtils.import_users_from_sqlite(self._cluster_id)

                # now signal core that we have removed this user account from mysql
                cmd = "delete|user|" + str(self._cluster_id) + "|" + sqlite_imported_account['user'] + "|"
                response = util.socket_cmd_runner(unix_sock="/tmp/lb_sock", 
                                                    command=cmd)
                if response != "SUCCESS":
                    _logger.error("ClusterMonitor(%d): Failed to " \
                                  "inform core about user account deletion:" \
                                  " cmd: %s response: %s" % (self._cluster_id,
                                                        cmd, response))
                    continue

                #
                # FIXME: continous error from core saying 306: Data not found for deletion
                # Does this mean core itself removes the entry or should we do that ?
                #

    def _process_newly_added_accounts(self):
        '''
        Check if the mysql imported list has an entry which is not present in
        the sqlite file. if such an entry is found then add the same.

        We will also apply a hardcoded limit on max. no. of accounts that can
        be imported. Although we will not be able to limit user from adding
        new accounts manually as of now.
        '''
        # check if we have already reached our max. no. users that can be imported
        if len(self._accounts_imported_from_sqlite) >= MAX_USERS_IMPORT_LIMIT:
            _logger.warn("ClusterMonitor(%d): Max. user accounts import " \
                         "limit(%d) is already reached. No new accounts will " \
                         "be imported." % (self._cluster_id,
                                           MAX_USERS_IMPORT_LIMIT))
            return

        # search accounts imported from sqlite in the list of mysql imported list
        for mysql_imported_account in self._accounts_imported_from_mysql:

            # skip accounts with order not =1 altogether from comparison
            if mysql_imported_account['order'] != 1:
                continue

            # skip users who are in exclusion_list
            if mysql_imported_account['user'] in self._exclusion_list:
                continue

            sqlite_user_list = [ imported_user['user'] for imported_user \
                                    in self._accounts_imported_from_sqlite ]

            if mysql_imported_account['user'] not in sqlite_user_list:
                if len(self._accounts_imported_from_sqlite) >= MAX_USERS_IMPORT_LIMIT:
                    _logger.warn("ClusterMonitor(%d): Max. user accounts import " \
                                 "limit(%d) is already reached. No new accounts will " \
                                 "be imported." % (self._cluster_id,
                                                   MAX_USERS_IMPORT_LIMIT))
                    return

                _logger.info("ClusterMonitor(%d): Adding new user '%s'@'%s'" \
                             % (self._cluster_id, mysql_imported_account['user'], \
                                mysql_imported_account['host']))

                self._add_entry_to_lbusers(mysql_imported_account['user'],
                                            mysql_imported_account['password'],
                                            mysql_imported_account['host'])
                #
                # Since, we have updated sqlite file with a new entry, we will
                # reload the accounts list from sqlite.
                #
                self._accounts_imported_from_sqlite = UserCredsUtils.import_users_from_sqlite(self._cluster_id)

                uid = self._find_user_id(mysql_imported_account['user'],
                                         mysql_imported_account['host'])

                if uid == -1:
                    #TODO: do a roll back.
                    _logger.error("ClusterMonitor(%d): Failed to fech " \
                                  "userid for user %s host: %s " % (self._cluster_id,
                                                        mysql_imported_account['user'],
                                                        mysql_imported_account['host'], ))
                    continue

                cmd = "add|user|" + str(self._cluster_id) + "|" + str(uid) + \
                         "|" + mysql_imported_account['user'] + "|" + \
                         mysql_imported_account['password'] + "|0|NULL|2|1|0|"

                response = util.socket_cmd_runner(unix_sock="/tmp/lb_sock", 
                                                    command=cmd)
                _logger.debug("ClusterMonitor(%d): Sent cmd to core: %s , " \
                              "reponse: %s" % (self._cluster_id, cmd,response))
                if response != 'SUCCESS':
                    _logger.debug('ClusterMonitor(%d): Problem in adding user: %s' %\
                                  (self._cluster_id, mysql_imported_account['user']) )
                    continue

                #
                # Now that this account has been added successfully, we will assign
                # it a list of default databases
                #
                _logger.info("ClusterMonitor(%d): Finding logical "
                             "databases for user '%s' host: %s" % \
                             (self._cluster_id,
                              mysql_imported_account['user'],
                              mysql_imported_account['host'], ))

                self._assign_default_databases_to_new_user(uid, \
                                                           mysql_imported_account['user'],
                                                           mysql_imported_account['host'])

    def _dettach_databases_from_user_being_deleted(self, username, host):
        '''
        By using the username and password we will find the user_id, which will
        be used to further remove entries from lb_dbusers.
        '''
        uid = self._find_user_id(username, host)
        if uid == -1:
            _logger.error("ClusterMonitor(%d): No userid for user: '%s'@'%s' . " \
                          "Can't dettach dbs."%(self._cluster_id, username, \
                                                host,))
            return

        sqlite_handle = util.get_sqlite_handle(self._lb_dbname)
        db_cursor = sqlite_handle.cursor()

        query = "delete from lb_dbusers where status = 1 and userid = " + \
                 str(uid)

        retry = 0
        transaction_test_ok = False
        while retry < MAX_RETRY:
            try:
                if not transaction_test_ok:
                    db_cursor.execute(query)
                    transaction_test_ok = True

                sqlite_handle.commit()
                break
            except (Exception, sqlite3.Error) as e:
                retry = retry + 1
                if retry >= MAX_RETRY:
                    _logger.error("ClusterMonitor(%d): Failed to remove " \
                                    "dbuserid entries for user: %s " \
                                    % (self._cluster_id, username, ))
                else:
                    time.sleep(0.1)
        util.close_sqlite_resources(sqlite_handle, db_cursor)
        #
        # when we delete a user account then core anyway removes all dbs associated
        # with that user, so do not need to inform core of the same.
        #

    def _assign_default_databases_to_new_user(self, user_id, user_name, host):
        '''
        For this cluster and this user_id, make entry for all databases in
        lb_dbusers. Instead of writing new routines to do the same we will
        use exisiting routines just making sure that the proper environment is
        set.
        '''
        #
        # get a list of logical dbs for this user
        #
        dblist = mysql_util.retrieve_logical_dbs_from_dbserver(self._master_server['ip'],
                                                               self._master_server['port'],
                                                               self._root_accnt_info,
                                                               user_name, host,
                                                               ssl=self._get_ssl_info())
        if dblist == None or len(dblist) == 0:
            _logger.info("ClusterMonitor(%d): No databases for user: %s with " \
                         "host: %s" % (self._cluster_id, user_name, host))
            return True

        dblist_info = []
        for dbname in dblist:
            d = {}
            d['dbname']  = dbname
            dbid = self._find_dbid_for_db(dbname,
                                                self._dbname2id_map_list)
            if dbid == -1:
                dbid = self._find_dbid_for_db(dbname, self._old_dblist)
            if dbid != -1:
                d['dbid'] = dbid
                dblist_info.append(d.copy())

        self._add_entries_to_lbdbusers(user_name, user_id, dblist_info)
        time.sleep(1)

    def _add_entries_to_lbdbusers(self, username, userid , dblist_info):
        '''
        Insert entries for all dbs in one go. Also inform core the same.
        dblist is a list of dictionaries of type:
            {<dbname>, <dbid>}

        Informing the core requires dbuserid which we will get only after we have
        inserted dblist into lb_dbusers.
        '''
        if len(dblist_info) == 0:
            return

        query_list = []
        t = time.strftime("%Y-%m-%d %H:%M:%S")
        for row in dblist_info:
            query = "insert into lb_dbusers(userid,dbid,status,updatetime," \
                "clusterid) values(" + str(userid) + "," + \
                str(row['dbid']) + ",1,'" + t + "'," + str(self._cluster_id) + \
                ");"
            query_list.append(query)

        # execute all queries
        sqlite_handle = util.get_sqlite_handle(self._lb_dbname)
        db_cursor = sqlite_handle.cursor()

        retry = 0
        trans_active = False
        while retry < MAX_RETRY:
            try:
                if not trans_active:
                    db_cursor.execute("BEGIN TRANSACTION")
                    for query in query_list:
                        db_cursor.execute(query)
                    trans_active = True

                sqlite_handle.commit()
                break
            except (Exception, sqlite3.Error) as e:
                if str(e).find('database is locked') == -1:
                    _logger.error("ClusterMonitor(%d): Failed to execute " \
                                  "script. Adding dbid entries failed." \
                                  ": %s" % (self._cluster_id, e))
                    break

                retry = retry + 1
                if retry >= MAX_RETRY:
                    _logger.error("ClusterMonitor(%d): Failed to execute " \
                                  "script. Adding dbid entries failed." \
                                  ": %s" % (self._cluster_id, e))
                else:
                    time.sleep(0.1)

        util.close_sqlite_resources(sqlite_handle, db_cursor)

        #
        # Now find what all dbuserids we added this time. Once we have a complete
        # list of all maps {dbid<->dbuserid} we will try to find which userid we
        # inserted in this cycle.
        #
        dblist_from_sqlite = self._find_dbids_assigned_to_user(userid)
        newly_added = []
        for i in dblist_info:
            for j in dblist_from_sqlite:
                if i['dbid'] == j['dbid']:
                    d = {}
                    d['dbid'] = i['dbid']
                    d['dbname'] = i['dbname']
                    d['dbuserid'] = j['dbuserid']
                    newly_added.append(d.copy())
        #
        # now we will inform core that we have imported entries in
        # newly_added list
        #
        for entry in newly_added:
            cmd = "add|logical_db|" + str(self._cluster_id) + "|" + \
                 username + "|" + str(entry['dbuserid']) + "|" + entry['dbname'] + "|" \
                 + str(entry['dbid']) + "|"

            response = util.socket_cmd_runner(unix_sock="/tmp/lb_sock", 
                                                command=cmd)
            _logger.info("ClusterMonitor(%d): Sent command to core to add " \
                         "logical db: %s" % (self._cluster_id, cmd))
            if response != "SUCCESS":
                _logger.error("ClusterMonitor(%d): Failed to " \
                              "inform core about logical_db addition: cmd: %s " \
                              "response: %s" % (self._cluster_id,
                                                cmd, response))

    def _remove_entry_from_lbusers(self, username, host):
        '''
        Remove the (username,password) pair from the sqlite file.

        Due to limitation in our implementations of user accounts, we only
        support single account with any username. Therefore, username
        should be sufficiently unique to give us the required userid.
        '''
        sqlite_handle = util.get_sqlite_handle(self._lb_dbname)
        if sqlite_handle:
            db_cursor = sqlite_handle.cursor()
            query = "delete from lb_users where status = 1 and type = 2" + \
                    " and username = '" + username + "' and host = '" + host + "'"

            retry = 0
            transaction_test_ok = False
            while retry < MAX_RETRY:
                try:
                    if not transaction_test_ok:
                        db_cursor.execute(query)
                        transaction_test_ok = True

                    sqlite_handle.commit()
                    break
                except (Exception, sqlite3.Error) as e:
                    retry = retry + 1
                    if retry >= MAX_RETRY:
                        _logger.error("ClusterMonitor(%d): Failed to remove entry " \
                                      "from lbusers for user: %s host: %s : %s" % \
                                      (self._cluster_id, username, host, e))
                    else:
                        time.sleep(0.1)

            util.close_sqlite_resources(sqlite_handle, db_cursor)

    def _add_entry_to_lbusers(self, username, password, host):
        '''
        Add an account in the sqlite file.
        '''
        sqlite_handle = util.get_sqlite_handle(self._lb_dbname)
        db_cursor = sqlite_handle.cursor()
        query = "insert into lb_users(clusterid, username, password, type, " \
                "status, updatetime, encpassword, pwd_type, host) values(" \
                + str(self._cluster_id) + ", '" + username + "', '" + \
                password + "' ," + "2,1, '" + time.strftime("%Y-%m-%d %H:%M:%S") + \
                "' , 'NA',1,'" + host + "')"

        retry = 0
        transaction_test_ok = False
        while retry < MAX_RETRY:
            try:
                if not transaction_test_ok:
                    db_cursor.execute(query)
                    transaction_test_ok = True

                sqlite_handle.commit()
                break
            except (Exception, sqlite3.Error) as e:
                retry = retry + 1
                if retry >= MAX_RETRY :
                    _logger.error("ClusterMonitor(%d): Failed to make an entry " \
                                  "in lbusers for user: %s host: %s : %s" % \
                                  (self._cluster_id, username, host, e))
                else:
                    time.sleep(0.1)

        util.close_sqlite_resources(sqlite_handle, db_cursor)

    def _find_user_id(self, username, host):
        '''
        Returns the corresponding userid of the queries username,password
        pair.

        Due to limitation in our implementations of user accounts, we only
        support single account with any username. Therefore, username
        should be sufficiently unique to give us the required userid.

        **Update** : Since we already have entire account list in
            self._accounts_imported_from_sqlite, instead of querying sqlite for
            userid, we will do a lookup in the list and return the corresponding
            dbid.
        '''
        for item in self._accounts_imported_from_sqlite:
            if item['user'] == username and item['host'] == host:
                return item['userid']
        return -1
     
    def _processor_thread_work_area(self):
        '''
        Entire logic of processing goes in this thread.
        '''
        while True:
            if gSignalChildToQuit:
                self._safe_to_quit = True
                return
            t1 = time.time()
            _logger.debug("ClusterMonitor: Processing "
                "cluster: %d" % (self._cluster_id))

            # we have a new cycle, update internal structures
            _logger.info("ClusterMonitor(%d): Refreshing state information " \
                     % self._cluster_id)
            self._populate_state_data()

            if self._auto_update_enabled:

                if gSignalChildToQuit:
                    self._safe_to_quit = True
                    return

                _logger.info("ClusterMonitor(%d): Performing "
                    "add, delete users and logical db list sync from "
                    "database" % (self._cluster_id))
                self._process_user_accounts()

                if gSignalChildToQuit:
                    self._safe_to_quit = True
                    return

                _logger.info("ClusterMonitor(%d): Monitoring user accounts for" \
                                " dblist change." % (self._cluster_id))
                self._process_dblist_change_for_user()

            if gSignalChildToQuit:
                self._safe_to_quit = True
                return
            #
            # Whether auto_import is enabled or not we will
            # go for password monitoring
            #
            _logger.info("ClusterMonitor(%d): Monitoring  user accounts for " \
                         "password change" % (self._cluster_id, ))
            self.monitor_accounts_for_password_change()

            if gSignalChildToQuit:
                self._safe_to_quit = True
                return

            _logger.debug("ClusterMonitor(%d): Finished this cycle of processing in %f seconds" \
                          % (self._cluster_id, (time.time() - t1)))

            already_slept = 0
            while already_slept < self._processing_cycle:
                time.sleep(1)
                already_slept = already_slept + 1
                if gSignalChildToQuit:
                    self._safe_to_quit = True
                    return

    def process_in_separate_thread(self):
        '''
        Start all the processing work in a separate thread. This routine must
        be called only once.
        '''
        if not self._worker_thread:
            self._worker_thread = threading.Thread \
                                        (target = self._processor_thread_work_area)
            self._worker_thread.setDaemon(True)
            self._worker_thread.start()

    def get_user_accounts_max_count(self):
        '''
        Return the no. of user accounts that we have imported from mysql.
        '''
        return len(self._processed_accounts_list_from_mysql)

    def proceed_if_safe_to_quit(self):
        '''
        Check and block untill self._safe_to_quit is set to True.
        '''
        while True:
            if self._safe_to_quit:
                return
            time.sleep(0.5)

def is_parent_alive(parent_pid):
    '''
    Returns True/false
    '''
    if os.path.exists("/var/run/user_creds_monitor.pid") == False :
        return False

    pid_file = "/proc/" + str(parent_pid)
    if os.path.exists(pid_file):
        return True
    return False

def get_per_cluster_auto_import_state(cluster_id):
    '''
    Load fields auto_update_enabled,interval and excludeuser from lb_auto_import
    and return a dictionary else None.
    '''
    query = "select autoupdate, interval, excludeuser from lb_auto_importuser" \
            " where status = 1"

    d = {'autoupdate':0, 'interval':600, 'excludeuser':''}
    sqlite_handle = util.get_sqlite_handle(LB_DB_FILE % cluster_id)
    if sqlite_handle:
        db_cursor = sqlite_handle.cursor()

        retry = 0
        while retry < MAX_RETRY:
            try:
                db_cursor.execute(query)
                row = db_cursor.fetchone()
                if row:
                    d['autoupdate'] = int(row['autoupdate'])
                    d['interval'] = int(row['interval'])
                    d['excludeuser'] = row['excludeuser']
                    break
            except (Exception, sqlite3.Error) as ex:
                retry = retry + 1
                if retry >= MAX_RETRY:
                    _logger.error("ClusterMonitor(%d):Failed to read state init " \
                                  "data:  %s" % (cluster_id, ex))
                else:
                    time.sleep(0.1)

        util.close_sqlite_resources(sqlite_handle, db_cursor)
    return d

def save_auto_import_state(cluster_id, auto_import_state):
    '''
    Save the current state in lb_auto_importuser.
    We dont need to update the 'includedbs' field since it will be done by UI.
    '''
    query = "update lb_auto_importuser set autoupdate=" + \
            str(auto_import_state['autoupdate']) + \
                ", interval=" + str(auto_import_state['interval']) + \
                ",updatetime='" + time.strftime("%Y-%m-%d %H:%M:%S") + \
                "', excludeuser='" + auto_import_state['excludeuser'] + \
                "' where status=1"

    sqlite_handle = util.get_sqlite_handle(LB_DB_FILE % cluster_id)
    if sqlite_handle:
        db_cursor = sqlite_handle.cursor()
        transaction_test_ok = False
        retry = 0
        while retry < MAX_RETRY:
            try:
                if not transaction_test_ok:
                    db_cursor.execute(query)
                    transaction_test_ok = True
                sqlite_handle.commit()
                break
            except (Exception, sqlite3.Error) as e:
                retry = retry + 1
                if retry >= MAX_RETRY:
                    _logger.error("ClusterMonitor(%d): Failed to save state " \
                                  "information. :%s" % (cluster_id, e))
                else:
                    time.sleep(0.1)
        util.close_sqlite_resources(sqlite_handle, db_cursor)

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


def cluster_monitor_cleanup(signum, sigframe):
    '''
    Remove the marker file when exiting.
    '''
    global gSignalChildToQuit
    gSignalChildToQuit = True
    pid = os.getpid()
    try:
        if read_pid(gClusterStatusMarkerFile) == pid:
            os.remove(gClusterStatusMarkerFile)
        else:
            _logger.debug("Markerfile pid not match with the current process pid")
    except Exception, ex:
        _logger.error('Failed to remove marker file: %s' % gClusterStatusMarkerFile)

def cluster_monitor_routine(cluster_id, comm_pipe,):
    '''
    This is target routine of a process spawned for monitoring a cluster.
    TODO: Do we need to check if marker file for this cluster is present ?
    '''
    parent_pid = os.getppid()
    _logger.debug("ClusterMonitor(%d): New pocess started with "\
                  "clusterid: %d parent_pid: %d" % (os.getpid(), cluster_id, \
                                                    parent_pid, ))

    # count of how many seconds we have already slept so far
    auto_import_state = {'autoupdate':0 ,'interval':60 ,'excludeuser':''}
    
    _logger.debug("ClusterMonitor(%d): DECLARE GLOBAL" % (cluster_id, ))
    
    global gClusterStatusMarkerFile
    global gSignalChildToQuit
    gClusterStatusMarkerFile = "/var/run/user_creds_monitor_%d.file" % cluster_id
    
    #  try to create marker file
    if os.path.exists(gClusterStatusMarkerFile) == False:
        try:
            fp = open(gClusterStatusMarkerFile, "w")
            fp.write(str(os.getpid()))
            fp.close()
        except Exception, ex:
            _logger.error("ClusterMonitor(%d): Failed to create marker file %s: %s" \
                          % (cluster_id, gClusterStatusMarkerFile, ex))
            sys.exit(1)
    else:
        _logger.warn("ClusterMonitor(%d): Marker file already in use. " \
                     "Exiting now" % cluster_id)
        sys.exit(0)

    # resgister to handle SIGTERM & SIGHUP
    signals = [signal.SIGTERM, signal.SIGHUP ]
    for s in signals:
        signal.signal(s, cluster_monitor_cleanup)

    try:
        #
        # Init stage: We check what was our last state per cluster e.g. we look up
        # lb_auto_importuser and for this cluster we initialise cmonitor instance
        # with those loaded values.
        #
        _logger.debug("ClusterMonitor(%d): Reading state "\
                      "initialization data from sqlite." % (cluster_id))
        auto_import_state = get_per_cluster_auto_import_state(cluster_id)

        if not auto_import_state:
        #
        # We cant exit rather we go down and probably wait for new command
        # to come
        #
            _logger.error("ClusterMonitor(%d): Failed to read "\
                          "state_init data from sqlite. Using defaults."\
                           % (cluster_id))
            cmonitor = ClusterMonitor(cluster_id)
            cmonitor.disable_auto_update()
            cmonitor.set_processing_cycle(60)
        else:
            # Initiliaze clustermonitor object with the parameters loaded from sqlite.
            cmonitor = ClusterMonitor(cluster_id)
            if auto_import_state['excludeuser'] != '':
                cmonitor.set_exclusion_string(auto_import_state['excludeuser'])

            if auto_import_state['autoupdate'] == 1:
                _logger.debug("ClusterMonitor(%d): Enabling auto_update "\
                              " from config." % (cluster_id))
                cmonitor.enable_auto_update()
            else:
                _logger.debug("ClusterMonitor(%d): Auto update is disabled"\
                              " from config." % (cluster_id))
                cmonitor.disable_auto_update()

            _logger.debug("ClusterMonitor(%d): Setting update interval "\
                            "to %d seconds." % (cluster_id, auto_import_state['interval']))
            cmonitor.set_processing_cycle(auto_import_state['interval'])

        _logger.debug("ClusterMonitor(%d): Creating a new processing thread." % (cluster_id))
        # call routine process in a diff_thread()
        cmonitor.process_in_separate_thread()

        while True:
            '''
            1. Check if parent is gone this means, probably shutdown has occurred or
                parent has crashed. Either way, we give up.
            2. Check if we have any message from parent. Act accordingly.
            3. if command = auto_update_disable then sleep() for a second and
                check again for new command.

            Note that although we will monitor cluster every 'update_interval'
            however, we should not sleep for that interval altogether. We need to
            listen for any msgs that we might get before we have completed one
            cycle of processing and sleeping.
            '''
            if gSignalChildToQuit:
                #
                # Since processing continues in a separate thread, we need to make
                # sure that thread has stopped processing in order to prevent
                # system from going into an inconsistent state.
                #
                _logger.info("UserCredsMonitor(%d): Got signal. Waiting for " \
                             "processing thread to finish." % cluster_id)
                # block if needed, but return only if it's safe to exit
                cmonitor.proceed_if_safe_to_quit()
                _logger.info("ClusterMonitor(%d): Saving current state. " \
                              % (cluster_id))
                save_auto_import_state(cluster_id, auto_import_state)

                _logger.info("UserCredsMonitor(%d): Exiting now " \
                             % cluster_id)
                sys.exit()

            if comm_pipe.closed:
                _logger.info("ClusterMonitor(%d): Child pipe has been closed. " \
                            "Waiting for processing thread to finish." % (cluster_id))
                gSignalChildToQuit = True
                cmonitor.proceed_if_safe_to_quit()

                _logger.info("ClusterMonitor(%d): Saving current state. " \
                              % (cluster_id))
                save_auto_import_state(cluster_id, auto_import_state)
                try:
                    os.remove(gClusterStatusMarkerFile)
                except:
                    pass
                _logger.info("UserCredsMonitor(%d): Exiting now " \
                             % cluster_id)
                sys.exit()

            # check if cluster is up , exit if cluster is marked down
            if not cmonitor.check_if_cluster_up():
                _logger.info("ClusterMonitor(%d): Cluster is stopped. " \
                            "Waiting for processing thread to finish." % (cluster_id))
                gSignalChildToQuit = True
                cmonitor.proceed_if_safe_to_quit()

                _logger.info("ClusterMonitor(%d): Saving current state. " \
                              % (cluster_id))
                save_auto_import_state(cluster_id, auto_import_state)
                try:
                    os.remove(gClusterStatusMarkerFile)
                except:
                    pass
                _logger.info("UserCredsMonitor(%d): Exiting now " \
                             % cluster_id)
                sys.exit()

            # check if parent is alive
            if not is_parent_alive(parent_pid):
                _logger.info("ClusterMonitor(%d): Parent is dead. " \
                            "Waiting for processing thread to finish." % (cluster_id))
                gSignalChildToQuit = True
                cmonitor.proceed_if_safe_to_quit()

                _logger.info("ClusterMonitor(%d): Saving current state. " \
                              % (cluster_id))
                save_auto_import_state(cluster_id, auto_import_state)
                try:
                    os.remove(gClusterStatusMarkerFile)
                except:
                    pass
                _logger.info("UserCredsMonitor(%d): Exiting now " \
                             % cluster_id)
                sys.exit()


            try:
                if comm_pipe.poll(1):
                    # Got some msg from parent. Read and modify state
                    data = comm_pipe.recv()
                    _logger.debug("ClusterMonitor(%d): Got message %s" % \
                                  (cluster_id, data))

                    arg_list = data.split('|')

                    # Process command based on the request that we recieved
                    if int(arg_list[0]) == SET_AUTO_IMPORT_INTERVAL:
                        #
                        # IDB-5410
                        # Set the minimum fetch_interval that can be allowed.
                        #
                        _logger.info("ClusterMonitor(%d): Setting " \
                                     "auto_update_interval to %d seconds" \
                                     % (cluster_id, int(arg_list[1])))
                        sleep_interval = int(arg_list[1])
                        auto_import_state['interval'] = sleep_interval
                        cmonitor.set_processing_cycle(sleep_interval)
                        if not comm_pipe.closed:
                            comm_pipe.send("clusterid=%d&cmd=set_auto_import_interval&err_code=0" % (cluster_id))

                    elif int(arg_list[0]) == FETCH_USERLIST_MAXCOUNT:
                        max_records = cmonitor.get_user_accounts_max_count()
                        try:
                            if not comm_pipe.closed:
                                _logger.debug("ClusterMonitor(%d): Sending max_records=%d" \
                                              % (cluster_id, max_records, ))
                                comm_pipe.send("clusterid=%d&cmd=fetch_userlist_maxcount&max_records=%d&err_code=0" \
                                               % (cluster_id, max_records, ))
                        except:
                            _logger.error("ClusterMonitor(%d): Error sending " \
                                          "max_records value to parent." \
                                          % cluster_id)
                            pass

                    elif int(arg_list[0]) == FETCH_USERLIST_BY_PAGE:
                        _logger.debug("ClusterMonitor(%d): Fetching user list for page: %d" \
                                      % (cluster_id, int(arg_list[1])))
                        cmonitor.send_auto_fetched_user_list(comm_pipe, int(arg_list[1]))

                    elif int(arg_list[0]) == AUTO_IMPORT_ENABLE:
                        if int(arg_list[1]) == 1:
                            _logger.info("ClusterMonitor(%d): Enabling auto account" \
                                         " import." % (cluster_id))
                            cmonitor.enable_auto_update()
                            auto_import_state['autoupdate'] = 1

                        elif int(arg_list[1]) == 0:
                            _logger.info("ClusterMonitor(%d): Disabling "\
                                            "auto account import." % (cluster_id))
                            cmonitor.disable_auto_update()
                            auto_import_state['autoupdate'] = 0

                        if not comm_pipe.closed:
                            comm_pipe.send("clusterid=%d&cmd=auto_import_enable&err_code=0" % (cluster_id))

                    elif int(arg_list[0]) == SET_USER_EXCLUSION_LIST:
                        cmonitor.set_exclusion_string(arg_list[1])
                        auto_import_state['excludeuser'] = arg_list[1]

                        if not comm_pipe.closed:
                            comm_pipe.send("clusterid=%d&cmd=set_user_exclusion_list&err_code=0" % (cluster_id))
                    else:
                        _logger.error("ClusterMonitor(%d): Does not "
                                      "understand command: %s" % (cluster_id, \
                                                                  arg_list[0]))
            except Exception, ex:
                if errno.errorcode == errno.EINTR:
                    _logger.warn("UserCredsMonitor(%d): Got signal while" \
                                 " polling for request." % ( cluster_id))
            time.sleep(1)
    except Exception, ex:
        _logger.error("UserCredsMonitor(%d): Instance failed !: %s" \
                      % (cluster_id, ex))
        _logger.error("%s" % (traceback.format_exc(),))

def auto_import_data_processing(cmonitor, cluster_id):
    # count of how many seconds we have already slept so far
    auto_import_state = {'autoupdate':0, 'interval':60, 'excludeuser':''}
    try:
        #
        # Init stage: We check what was our last state per cluster e.g. we look up
        # lb_auto_importuser and for this cluster we initialise cmonitor instance
        # with those loaded values.
        #
        _logger.debug("ClusterMonitor(%d): Reading state "\
                      "initialization data from sqlite." % (cluster_id))
        
        auto_import_state = get_per_cluster_auto_import_state(cluster_id)
        if not auto_import_state:
            _logger.error("ClusterMonitor(%d): Failed to read "\
                          "state_init data from sqlite. Using defaults."\
                           % (cluster_id))
            cmonitor.disable_auto_update()
            cmonitor.set_processing_cycle(60)
        else:
            # Initiliaze clustermonitor object with the parameters loaded from sqlite.
            if auto_import_state['excludeuser'] != '':
                cmonitor.set_exclusion_string(auto_import_state['excludeuser'])

            if auto_import_state['autoupdate'] == 1:
                _logger.debug("ClusterMonitor(%d): Enabling auto_update "\
                              " from config." % (cluster_id))
                cmonitor.enable_auto_update()
            else:
                _logger.debug("ClusterMonitor(%d): Auto update is disabled"\
                              " from config." % (cluster_id))
                cmonitor.disable_auto_update()

            _logger.debug("ClusterMonitor(%d): Setting update interval "\
                            "to %d seconds." % (cluster_id, auto_import_state['interval']))
            cmonitor.set_processing_cycle(auto_import_state['interval'])
    except Exception, ex:
        _logger.error("ClusterMonitor(%d): Exception in getting auto import data "\
                            " %s ." % (cluster_id, ex))

def mssql_cluster_monitor_routine(cluster_id):
    '''
    This is target routine of a process spawned for monitoring a cluster.
    TODO: Do we need to check if marker file for this cluster is present ?
    '''
    parent_pid = os.getppid()
    _logger.debug("ClusterMonitor(%d): New pocess started with "\
                  "clusterid: %d parent_pid: %d" % (os.getpid(), cluster_id, \
                                                    parent_pid, ))

    # count of how many seconds we have already slept so far
    auto_import_state = {'autoupdate':0 ,'interval':60 ,'excludeuser':''}
    
    _logger.debug("ClusterMonitor(%d): DECLARE GLOBAL" % (cluster_id, ))
    
    global gClusterStatusMarkerFile
    global gSignalChildToQuit
    gClusterStatusMarkerFile = "/var/run/user_creds_monitor_%d.file" % cluster_id
    
    #  try to create marker file
    if os.path.exists(gClusterStatusMarkerFile) == False:
        try:
            fp = open(gClusterStatusMarkerFile, "w")
            fp.write(str(os.getpid()))
            fp.close()
        except Exception, ex:
            _logger.error("ClusterMonitor(%d): Failed to create marker file %s: %s" \
                          % (cluster_id, gClusterStatusMarkerFile, ex))
            sys.exit(1)
    else:
        _logger.warn("ClusterMonitor(%d): Marker file already in use. " \
                     "Exiting now" % cluster_id)
        sys.exit(0)

    # resgister to handle SIGTERM & SIGHUP
    signals = [signal.SIGTERM, signal.SIGHUP ]
    for s in signals:
        signal.signal(s, cluster_monitor_cleanup)

    try:
        #
        # Init stage: We check what was our last state per cluster e.g. we look up
        # lb_auto_importuser and for this cluster we initialise cmonitor instance
        # with those loaded values.
        #
        _logger.debug("ClusterMonitor(%d): Reading state "\
                      "initialization data from sqlite." % (cluster_id))
        
        cmonitor = ClusterMonitor(cluster_id)
        bdc_client = FetchFromBDC(cluster_id)
        auto_import_data_processing(cmonitor, cluster_id)

        while True:
            '''
            1. Check if parent is gone this means, probably shutdown has occurred or
                parent has crashed. Either way, we give up.
            2. Check if we have any message from parent. Act accordingly.
            3. if command = auto_update_disable then sleep() for a second and
                check again for new command.

            Note that although we will monitor cluster every 'update_interval'
            however, we should not sleep for that interval altogether. We need to
            listen for any msgs that we might get before we have completed one
            cycle of processing and sleeping.
            '''
            if gSignalChildToQuit:
                _logger.info("UserCredsMonitor(%d): Got signal. Waiting for " \
                             "processing thread to finish." % cluster_id)
                _logger.info("ClusterMonitor(%d): Saving current state. " \
                              % (cluster_id))

                _logger.info("UserCredsMonitor(%d): Exiting now " \
                             % cluster_id)
                sys.exit()

            # check if cluster is up , exit if cluster is marked down
            if not cmonitor.check_if_cluster_up():
                _logger.info("ClusterMonitor(%d): Cluster is stopped. " \
                            "Waiting for processing thread to finish." % (cluster_id))
                gSignalChildToQuit = True

                _logger.info("ClusterMonitor(%d): Saving current state. " \
                              % (cluster_id))
                try:
                    os.remove(gClusterStatusMarkerFile)
                except:
                    pass
                _logger.info("UserCredsMonitor(%d): Exiting now " \
                             % cluster_id)
                sys.exit()

            # check if parent is alive
            if not is_parent_alive(parent_pid):
                _logger.info("ClusterMonitor(%d): Parent is dead. " \
                            "Waiting for processing thread to finish." % (cluster_id))
                gSignalChildToQuit = True

                _logger.info("ClusterMonitor(%d): Saving current state. " \
                              % (cluster_id))
                try:
                    os.remove(gClusterStatusMarkerFile)
                except:
                    pass
                _logger.info("UserCredsMonitor(%d): Exiting now " \
                             % cluster_id)
                sys.exit()

            if cmonitor._auto_update_enabled:
                try:
                    _logger.info("UserCredsMonitor(%d): fetch users from BDC " \
                             % (cluster_id))
                    bdc_client.fetch_update_users()
                    _logger.info("UserCredsMonitor(%d): Wait for interval time %s " \
                             % (cluster_id, cmonitor._processing_cycle))
                    already_slept = 0
                    while already_slept < cmonitor._processing_cycle:
                        time.sleep(1)
                        already_slept = already_slept + 1
                        if gSignalChildToQuit:
                            break
                    _logger.info("UserCredsMonitor(%d): Wait over " \
                             % (cluster_id))
                except Exception, ex:
                    _logger.info("UserCredsMonitor(%d): Exception while fetching data from bdc " \
                             % (cluster_id))
            
            if ((time.time() - cmonitor._last_state_updated) >= cmonitor._state_refresh_interval):
                if gSignalChildToQuit:
                    return
                _logger.info("UserCredsMonitor(%d): Reading Auto Import data after 15 secs " \
                             % (cluster_id))
                auto_import_data_processing(cmonitor, cluster_id)
                
                _logger.info("UserCredsMonitor(%d): Newly auto import data is enable %s " \
                             " interval is %s"% (cluster_id, cmonitor._auto_update_enabled, cmonitor._processing_cycle))
                cmonitor._last_state_updated = time.time()
            time.sleep(1)
    except Exception, ex:
        _logger.error("UserCredsMonitor(%d): Instance failed !: %s" \
                      % (cluster_id, ex))
        _logger.error("%s" % (traceback.format_exc(),))

class ThreadedTCPRequestHandler(SocketServer.BaseRequestHandler):
    def handle(self):
        '''
        This entire class starting from this routine are per thread.

        Reads the request made through socket.
        1. Try and acquire lock for the parent end of the pipe.
        2. If someone else has the lock, exiting giving error 'A previous request
            for this cluster is in progress.'
        3. If got the lock, process and finally release lock.

        '''
        self._recieved_data = self.request.recv(8192).strip()
        if self._recieved_data:
            _logger.debug("Got request: %s" % self._recieved_data)
            # now parse what we have got
            if not self.parse_command():
                _logger.warn("RequestManager: Problem while parsing request: %s" % self._recieved_data)
                try:
                    self.request.sendall('err_code=1')
                except:
                    pass
                return

            # now verify the command we recieved
            if not self._verify_request():
                _logger.warn("RequestManager: Problem while verfy request. " \
                             "Either command is unsupported or format is " \
                             "incorrect.")
                try:
                    self.request.sendall('err_code=5')
                except:
                    pass
                return

                # acqurie lock for this cluster
            if self._get_cluster_state() == PIPE_BUSY:
                _logger.warn("RequestManager(%d): Cluster pipe is busy. " \
                                "Will ignore command: %s" % (self._cluster_id, \
                                                            self._recieved_data))
                try:
                    self.request.sendall("clusterid=%d&cmd=%d&err_code=2" \
                                         % (self._cluster_id, self._cmd, ))
                except:
                    pass
                return

            # try to get lock for this cluster
            self._get_cluster_state_lock()
            self._set_cluster_state_to_BUSY()

            if self.send_command_to_cluster_monitor():
                self._process_child_response()
            else:
                try:
                    self.request.sendall("clusterid=%d&cmd=%d&err_code=3" \
                                         % (self._cluster_id, self._cmd, ))
                except:
                    pass

            # now release the lock but before that set the cluster state
            # to READY
            self._set_cluster_state_to_READY()
            self._release_cluster_state_lock()

    def _get_cluster_state_lock(self):
        '''
        Get the cluster lock so that we can have access over pipe.
        '''
        gMonitoredClusters[self._cluster_id]['cluster_state_lock'].acquire()

    def _release_cluster_state_lock(self):
        '''
        Release cluster state lock.
        '''
        gMonitoredClusters[self._cluster_id]['cluster_state_lock'].release()

    def _get_cluster_state(self):
        '''
        Returns 1 or 0 indicating whether the cluster state is PIPE_READY or PIPE_BUSY.
        '''
        return gMonitoredClusters[self._cluster_id]['cluster_state']

    def _set_cluster_state_to_BUSY(self):
        '''
        Set the cluster state busy so that any thread attempting to take a lock
        can decide whether to attempt for the lock or fall back.
        '''
        gMonitoredClusters[self._cluster_id]['cluster_state'] = PIPE_BUSY

    def _set_cluster_state_to_READY(self):
        '''
        Mark this cluster state as ready meaning that our work with this cluster's
        pipe is done and therefore another thread can now have the lock.
        '''
        gMonitoredClusters[self._cluster_id]['cluster_state'] = PIPE_READY

    def _set_parent_pipe_for_cluster(self):
        '''
        Set the parent pipe by looking up in global list of cluster structure.
        '''
        self._parent_pipe = gMonitoredClusters[self._cluster_id]['parent_pipe']

    def _process_fetch_userlist_bypage_request(self):
        '''
        Wait on pipe and read child response and transfer the same to the request
        source. Expect header first and then data rows.
        '''
        header_recieved = False
        max_records = 0
        max_duration_to_wait = 10 # seconds
        recieved_records = 0
        sent_records = 0
        while True:
            if max_duration_to_wait <= 0:
                _logger.debug("Request_manager: timeout while waiting for service")
                self.request.sendall("clusterid=%d&cmd=%d&err_code=4" \
                                     % (self._cluster_id, self._cmd))
                break

            if self._parent_pipe.poll(2):
                if not header_recieved :
                    header_recieved = True
                    msg = self._parent_pipe.recv()
#                         _logger.debug("RequestManager(%d): Header receive: %s" \
#                                       % (self._cluster_id, msg))
                    try:
                        if msg.split('&')[1].split('=')[1] == 'fetch_userlist_bypage':
                            page_id = int(msg.split('&')[2].split('=')[1])
                            max_records = int(msg.split('&')[3].split('=')[1])
                            # send the header as well
                            try:
                                self.request.sendall(msg)
                            except Exception, ex:
                                _logger.error("RequestManager(%d): Error " \
                                              "sending fetch_userlist_response " \
                                              "header: %s" \
                                              % (self._cluster_id, ex))
                            if max_records == 0:
                                _logger.info("RequestManager(%d): Child returned" \
                                             " page size: 0, skipping further " \
                                             "reading" % (self._cluster_id, ))
                                return
                    except:
                            # probably we recieved data before we got the
                            # header msg.
                        _logger.warning('RequestManager(%d): fetch_userlist:" \
                                        " Got data rows before header msg. " \
                                        "Will send whatever I got. %s' \
                                        % (self._cluster_id, msg))
                            # Set header_recieved to True to prevent further warning msgs.
                        header_recieved = True
                        self.request.sendall(msg)
                else:
                    _logger.debug("RequestManager(%d): fetch_userlist_response: " \
                                          "Prepairing to read %d rows for page: %d" \
                                          % (self._cluster_id, max_records, page_id))

                    for x in range(max_records):
                        try:
                            if not self._parent_pipe.closed:
                                msg = self._parent_pipe.recv()
                                recieved_records = recieved_records + 1
                            else:
                                _logger.error("RequestManager(%d): Error " \
                                            "receiving data. Pipe has been " \
                                            "closed unexpectedly. Is monitor " \
                                            "process alive ?" % (self._cluster_id))
                                return
                        except Exception, ex:
                            _logger.error("RequestManager(%d): Error " \
                                            "receiving data: %s" \
                                            % (self._cluster_id, ex))

                        try:
                            self.request.sendall(msg)
                            sent_records = sent_records + 1
                        except Exception, ex:
                            _logger.error("RequestManager(%d): Error " \
                                            "sending data: %s" \
                                            % (self._cluster_id, ex))

                    _logger.info("RequestManager(%d): Received %d and sent" \
                                " %d records out of %d" \
                                 % (self._cluster_id, recieved_records, \
                                    sent_records, max_records))

                        # we are out of loop so we will return anyway
                    return
            else:
                if self._parent_pipe.closed:
                    _logger.error("RequestManager(%d): Parent pipe is " \
                                  "closed while recieving data." % self._cluster_id)
                    return

                time.sleep(1)
                max_duration_to_wait = max_duration_to_wait - 1

    def _process_generic_request(self):
        '''
        Process generic requests i.e. request which do not require any special
        way of retriveving and sending data to UI can be processed here.
        Commands like set_auto_import_interval, auto_import_enable, set_user_exclusion_list,
        fetch_userlist_maxcount and fetch_userlist_bypage etc.

        This simply transfers to UI what it received from child monitor process.
        '''
        if self._parent_pipe.closed:
            _logger.error("RequestManager(%d): Parent pipe is " \
                          "closed while recieving data." % self._cluster_id)
            return
        if self._parent_pipe.poll(5):
            try:
                self.request.sendall(self._parent_pipe.recv())
            except Exception, ex:
                _logger.error("RequestManager(%d): Problem processing request: " \
                              "%s" % (self._cluster_id, ex))
        else:
            self.request.sendall("clusterid=%d&cmd=%d&err_code=4" \
                                     % (self._cluster_id, self._cmd))

    def _process_child_response(self):
        '''
        Process the child response and also send it back to the request source.
        '''
        if self._cmd == FETCH_USERLIST_BY_PAGE:
            self._process_fetch_userlist_bypage_request()
        else:
            self._process_generic_request()

    def send_command_to_cluster_monitor(self):
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
        # point in sending a request
        #
        _logger.debug("Request Manager(%d): request_type: %s data: %s origin: %s "\
                      ""%(self._cluster_id, self._cmd,self._data, self._origin,))
        marker_file = "/var/run/user_creds_monitor_%d.file" % (self._cluster_id, )

        if os.path.exists(marker_file):
            msg = "%s|%s" % (self._cmd, self._data)

            if self._parent_pipe.closed:
                _logger.error('RequestManager(%d): Parent pipe has been closed. Is " \
                "parent or monitor child alive ?'  % self._cluster_id)
                msg_sent = False
            else:
                self._parent_pipe.send(msg)
                msg_sent = True
        else:
            _logger.error("RequestManager(%d): No listener for cluster." \
                          % self._cluster_id)
            msg_sent = False

        if not msg_sent :
            _logger.error("RequestManager(%d): Failed to deliver command to "\
                          "cluster monitor." % self._cluster_id)
            return False
        return True

    def _set_command(self, cmd):
        '''
        Set the command recieved from UI if we support that.
        '''
        if cmd == 'set_auto_import_interval':
            self._cmd = SET_AUTO_IMPORT_INTERVAL
        elif cmd == 'auto_import_enable':
            self._cmd = AUTO_IMPORT_ENABLE
        elif cmd == 'set_user_exclusion_list':
            self._cmd = SET_USER_EXCLUSION_LIST
        elif cmd == 'fetch_userlist_maxcount':
            self._cmd = FETCH_USERLIST_MAXCOUNT
        elif cmd == 'fetch_userlist_bypage':
            self._cmd = FETCH_USERLIST_BY_PAGE

    def parse_command(self):
        '''
        Parse the request that we recieved.
        The new command that we meed to parse
        cmd4 =  "command=update_dblist&clusterid=1&user=qa102&dblist=db1,
                    cms,pms&origin=gui"

        cmd5 = "command=set_dbinclusion_list&clusterid=1&include_list=7,11"
        "command=fetch_userlist&clusterid=$cid&origin=gui"
        '''
        #initial values
        self._cmd = None
        self._cluster_id = None
        self._data = None
        self._origin = "gui"
        self._user = None

        try:
            t = []
            t = self._recieved_data.split('&')
            for item in t:
                sub_items = []
                sub_items = item.split('=')
                if sub_items[0] == 'cmd':
                    self._set_command(sub_items[1])

                elif sub_items[0] == 'clusterid':
                    self._cluster_id = int(sub_items[1])
                elif sub_items[0] == 'origin':
                    self._origin = sub_items[1]
                elif sub_items[0] == 'user':
                    self._user = str(sub_items[1])
                elif (sub_items[0] == 'value'):
                    self._data = sub_items[1]
        except Exception, e:
            _logger.error("Request Manager: Error parsing request data: %s" % e)
            return False
        return True

    def _verify_request(self):
        '''
        Return true/false indicating whether this command is valid or not.
        '''
        if not self._cmd:
            return False

        if not self._cluster_id:
            return False

        if self._cmd not in gUserCredsSupportedCommands:
            return False

        # now for each command, depending upon their requirement check if  we have
        # proper data to carry on

        if self._cmd == SET_AUTO_IMPORT_INTERVAL:
            try:
                self._data = int(self._data)
                if self._data <= 0:
                    return False
            except:
                return False
        elif self._cmd == AUTO_IMPORT_ENABLE:
            try:
                self._data = int(self._data)
                if self._data < 0 or self._data > 1:
                    return False
            except:
                return False
        elif self._cmd == SET_USER_EXCLUSION_LIST:
            # no check possible, though we expect a comma separated
            # list of strings
            return True
        elif self._cmd == FETCH_USERLIST_MAXCOUNT:
            # no check, we dont expect 'value' field
            return True
        elif self._cmd == FETCH_USERLIST_BY_PAGE:
            try:
                self._data = int(self._data)
                if self._data < 1:
                    return False
            except:
                return False
        return True

class UserCredsMonitorDaemon(daemon.Daemon):
    """This class runs USER_CREDS_MONITOR as a daemon"""

    def get_sleep_val_from_config(self):
        sleep_interval = _config.getfloat("general", "sleep")
        if sleep_interval == 0.0:
            sleep_interval = 30 # default

        return sleep_interval

    def read_all_clusterids(self):
        '''
        Read a list of all server_ids with the status field.
        '''
        cluster_ids = []
        sqlite_handle = util.get_sqlite_handle(GLOBAL_LB_DB_FILE)
        if sqlite_handle:
            db_cursor = sqlite_handle.cursor()
            query = "select cluster_id, status, type from lb_clusters_summary where status <> 9 and type in %s " % str(PLATFORM_TYPES)
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

    def _signal_handler(self, signum, frame):
        '''
        Process in the event of a signal that we received. Since this part
        belongs to parent, in the event a signal, we will make sure that
        we cleanup our children and then only exit.
        '''
        _logger.info("UserCredsMonitor: Got signal, prepairing to exit gracefully.")
        for k, v in gMonitoredClusters.iteritems():
            phandle = v['child_process_handle']
            if phandle.is_alive():
                #
                # p.terminate() issues SIGTERM to the child. As a safety measure, it
                # should never be issued to children who are using shared data, semaphores
                # locks etc. Howver, if children themselves have signal handlers
                # registered then it should not be a problem. (i.e. children should
                # perform cleanup as and when required)
                #
                _logger.info("UserCredsMonitor: terminating the process id: %d" % int(phandle.pid))
                phandle.terminate()

        for k, v in gMonitoredClusters.iteritems():
            phandle = v['child_process_handle']
            if phandle.is_alive():
                _logger.info("UserCredsMonitor: Stopping monitor process for cluster: %d" % int(k))
                phandle.join(TIME_TO_WAIT_FOR_CHILD_JOIN)
                # check if process is still alive
                try:
                    os.kill(phandle.pid, 0)
                    # if still here this process is taking too much time, we kill it
                    _logger.warn("UserCredsMonitor: Monitor process for cluster:" \
                                 "%d is taking too long (> %d seconds) to quit, " \
                                 "killing it now " % (k, TIME_TO_WAIT_FOR_CHILD_JOIN))
                    os.kill(phandle.pid, 9)
                    # now join it so as to collect resources
                    phandle.join()

                except Exception, ex:
                    # process has stopped
                    pass
                _logger.info("UserCredsMonitor: Successfully Stopped monitor " \
                             "process for cluster: %d" % int(k))

        _logger.info("ClusterMonitor: Parent exiting now")
        sys.exit()

    def _register_signal_handler(self):
        '''
        Registers a set of signals to catch.
        '''
        signals = [ signal.SIGTERM ]
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
            _logger.warn("UserCredsMonitor(%d): '/system/lb.sqlite' "\
                         "does not exist " % (os.getpid(),))
            time.sleep(1)
        # try to determine the api_key
        while True:
            global APIKEY
            APIKEY = util.get_apikey()
            if APIKEY != '':
                break
            _logger.error("Failover: Failed to determine apikey.")
            time.sleep(2)
        _logger.info("UserCredsMonitor: Using apikey: %s" % APIKEY)

        try:
            '''
            According to new design , logic of accounts addition/deletion as well
            password change will be integrated. This routine will basically do:
            1. Create a socket-listener thread which will listen to any commands
                taht we will recieve from UI.
            2. Spawn montior children per cluster. Monitor children will take
                care of monitoring new accounts/deleted ones as well password
                changes.
            3. If a cluster has been stopped , kill the corresponding monitor
                child.
                (Killing a child simply means, remove marker file for that
                 cluster, then children should notice the missing marker file,
                 and exit.)
            '''
            self._listener_thread = None
            self._sleep_interval = self.get_sleep_val_from_config()
        except Exception, ex:
            _logger.error("UserCredsMonitor: Service Initialization failed: "\
                            "%s" % ex)
            _logger.error("%s" % (traceback.format_exc(),))

        while True:
            try:
                self._all_serverids = [] # list of dicts {'clusterid':n , 'status':}
                self._all_serverids = self.read_all_clusterids()

                    
                # Create listener thread, if not already present
                self.create_socket_listener_thread()

                # cleanup any finished children
                multiprocessing.active_children()
                #
                # see if a new cluster has been added and that we need any
                # monitor process for it.
                #
                self._spwan_monitor_children()
                _logger.debug("UserCredsMonitor: Sleeping for %f seconds" \
                              % (self._sleep_interval))
                time.sleep(self._sleep_interval)
            except Exception, ex:
                _logger.error("UserCredsMonitor Daemon run failed: %s" % ex)
                _logger.error("%s" % (traceback.format_exc(),))
                if os.path.exists(NO_SAFETY_NET_FILE):
                    #
                    # If the debug file is present, we break out the service so
                    # that we can catch this condition in QA/Development,
                    # otherwise we loop forever.
                    #
                    break
                # We are sleeping because ...
                _logger.debug("UserCredsMonitor: Sleeping for %f seconds" \
                              % self._sleep_interval)
                time.sleep(self._sleep_interval)

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


    def _spwan_monitor_children(self):
        '''
        Create one process for monitoring each cluster. Find the list of
        clusters  and their ids.

        1. populate list of clusterids
        2. check if a new cluster has been added. If yes then for this cluster
            spawn a monitor child process.

        Note: Consider this situation. The parent dies and before children monitor
            processes notice it, new instance of parent is invoked. In this case,
            the pid file will exist. Due to this, children will not detect that
            their parent has died. And new children for monitoring the clusters
            will be spawned again. To prevent this from happening, child processes
            should check if pid file has pid of their original parent.

            Also to prevent a new instance of this routine from spawning new
            children, each child will create a file in
            '/var/run/idb_cluster_monitor_<cluster_id>.file'
            If this file exists for any cluster then, return from this routine, as
            leftover children from previous instance are still running.
        '''
        # stop monitor processes if their corresponding cluster is marked down
        stopped_clusters = []
        stopped_clusters = self.find_stopped_cluster_ids()
        for cid in stopped_clusters:
            marker_file = "/var/run/user_creds_monitor_%d.file" % cid
            if os.path.exists(marker_file):
                self._stop_monitor_process_for_cluster(cid)

        cluster_type_ids = {}
        
        cluster_type_ids = self.find_running_cluster_ids()

        # If no cluster id then return
        if len(cluster_type_ids) == 0:
            _logger.warn("UserCredsMonitor: No running clusters. Will not " \
                         "monitor any cluster.")
            return

        for cid, ctype in cluster_type_ids.iteritems():
            #
            # We will spawn a new monitor process for the cluster for which there
            # is no marker file.
            #
            marker_file = "/var/run/user_creds_monitor_%d.file" % cid
            if not os.path.exists(marker_file):
                parent_pipe, child_pipe = multiprocessing.Pipe(duplex=True)
                if ctype == 'MSSQL':
                    p = multiprocessing.Process(target = mssql_cluster_monitor_routine,
                                            args=(cid,))
                else:
                    p = multiprocessing.Process(target=cluster_monitor_routine,
                                            args=(cid, child_pipe, ))
                #
                # Since gMonitoredClusters now stores an entry for each cluster,
                # it will overwrite state information for a monitor of past
                # for this very cluster. This means, from now on, we are assumming
                # that this new process will be sole representative of this cluster
                # and thus any past monitor for this cluster (if any) will cut off
                # from communicating with parent. There will be timing issues but
                # this should be acceptable as new monitor will handle any requests
                # coming for this cluster.
                #

                d = {}
                d['child_process_handle'] = p
                d['cluster_state'] = PIPE_READY
                d['parent_pipe'] = parent_pipe
                d['child_pipe'] = child_pipe
                d['cluster_state_lock'] = threading.Lock()

                global gMonitoredClusters
                gMonitoredClusters[cid] = d.copy()
                # Start the new process
                _logger.info("UserCredsMonitor: Creating a new monitor process" \
                             " for cluster: %d" % (cid))
                p.start()
            else:
                marker_pid = read_pid(marker_file)
                if marker_pid:
                    path = "/proc/%s" % marker_pid
                    check_path = os.path.exists(path)
                    if check_path == False:
                        try:
                            _logger.info("UserCredsMonitor: Removing marker file %s" % marker_file)
                            os.remove(marker_file)
                        except:
                            _logger.error("UserCredsMonitor: Error on deleting marker file")

    def create_socket_listener_thread(self):
        '''
        Create the socket listener thread. This thread will listen to external
        requests and accordingly service them as well. Parent thread will only
        handle the task of per cluster process management.
        '''
        if self._listener_thread == None:
            self._listener_thread = threading.Thread \
                                    (target = self.socket_listener_thread_function)
            self._listener_thread.setDaemon(True)
            self._listener_thread.start()

    def socket_listener_thread_function(self):
        '''
        The target routine of self._listener_thread .
        '''
        HOST, PORT = "127.0.0.1", 5002
        _logger.info("UserCredsMonitor: Creating socket listener: HOST %s " \
                     "PORT %d" % (HOST, PORT))
        SocketServer.ThreadingTCPServer.allow_reuse_address = True
        server = SocketServer.ThreadingTCPServer((HOST, PORT), ThreadedTCPRequestHandler)
        server.serve_forever()

def main():
    # Go away if you are not root
    if not os.geteuid()==0:
        sys.exit("user_creds_monitor: You must be root to run this script\n")

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
    global _config
    _config = get_config_parser(USER_CREDS_MONITOR_CONF)

    user_creds_monitor_daemon = \
        UserCredsMonitorDaemon('/var/run/user_creds_monitor.pid')
    if args:
        if 'stop' == args[0]:
            _logger.info("******* USER_CREDS_MONITOR stopping **********")
            user_creds_monitor_daemon.stop()
        elif 'restart' == args[0]:
            _logger.info("****** USER_CREDS_MONITOR restarting *********")
            user_creds_monitor_daemon.restart()
        else:
            err_msg = "Invalid command %s" % (repr(args[0]),)
            print >> sys.stderr, err_msg
            _logger.error("%s" % (err_msg,))
            sys.exit(2)
        sys.exit(0)

    if _debug:
        _logger.info("***** USER_CREDS_MONITOR starting (debug mode)*******")
        user_creds_monitor_daemon.foreground()
    else:
        _logger.info("*********** USER_CREDS_MONITOR starting ************")
        user_creds_monitor_daemon.start()

if __name__ == "__main__":
    main()
