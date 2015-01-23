#!/usr/bin/python
#
# Copyright (C) 2013 ScaleArc, Inc., all rights reserved.
#
import os
import sys
import glob
import json
import time
import getopt
import socket
import sqlite3
import urllib
import httplib
import commands
import traceback
import SocketServer, ConfigParser
import threading, random
from commands import *
from SocketServer import BaseServer
from idb.cluster_util import PasswordUtils 
from idb import log, daemon, util, cluster_util, events
from idb.cmd.alert_engine.publisher import publisher
from idb.cmd.failover.subscriber import subscriber
import idb.mysql_util as mysql_util
from idb.cmd.system_monitor.constants import SystemMonitorStat

_debug = False
_config = None
NO_SAFETY_NET_FILE = "/opt/idb/.idb_utils_no_safety_net"
APIKEY = ""
MAX_RETRY = 3
SCRIPT_VERSION = "1.0"
GLOBAL_LB_DB_FILE = "/system/lb.sqlite"
LB_DB_FILE = "/system/lb_%s.sqlite"
IDB_DIR_ETC = '/opt/idb/conf'
FAILOVER_CONF = 'failover.conf'

# failover types
IDB_FAILOVER = 1
EXTERNAL_API_FAILOVER = 2

# Ignore attempts value for commands from idbcore_force, default 0
IGNORE_ATTEMPTS_IDBCORE_FORCE = 0

# server health definitions
SERVER_DOWN = 0
SERVER_LAGGING = 1
SERVER_HEALTHY = 2

# role definitions
READ_WRITE = 0
READ_ONLY = 1
WRITE_ONLY = 2 # not in use, reserved for future use.
STANDBY_TRAFFIC = 3
STANDBY_NO_TRAFFIC = 4

# role mappings
SERVER_ROLE_MAP = {}
SERVER_ROLE_MAP['Read + Write'] = READ_WRITE
SERVER_ROLE_MAP['Read'] = READ_ONLY
SERVER_ROLE_MAP['Write'] = WRITE_ONLY
SERVER_ROLE_MAP['Standby + Read'] = STANDBY_TRAFFIC
SERVER_ROLE_MAP['Standby, No Traffic'] = STANDBY_NO_TRAFFIC

# reverse role mappings
REVERSE_SERVER_ROLE_MAP = {}
REVERSE_SERVER_ROLE_MAP[READ_WRITE] = 'Read + Write'
REVERSE_SERVER_ROLE_MAP[READ_ONLY] = 'Read'
REVERSE_SERVER_ROLE_MAP[WRITE_ONLY] = 'Write'
REVERSE_SERVER_ROLE_MAP[STANDBY_TRAFFIC] = 'Standby + Read'
REVERSE_SERVER_ROLE_MAP[STANDBY_NO_TRAFFIC] = 'Standby, No Traffic'
# #############################

PLATFORM_TYPE_ORACLE = 'ORACLE'
PLATFORM_TYPE_MYSQL = 'MYSQL'
PLATFORM_TYPE_MSSQL = 'MSSQL'

# ##########################
# READ_ONLY Flag values
UNSET_READ_ONLY = 0 
SET_READ_ONLY = 1
# Negative Value Conditions for REPLICATION_LAG
IO_CONNECTION_ERROR = -3
SECONDS_BEHIND_MASTER = -1
RESPONSE_ERROR = -2
IO_ERROR = -4
SQL_ERROR = -5
CONNECTION_ERROR = -6
GALERA_REPLICATION_ERROR = -7

# Do not wait for sync for following conditions
ZERO_LAGTIME_CONDITIONS = [IO_CONNECTION_ERROR,]

# If all servers are having below conditions then abort failover
ABORT_FAILOVER_CONDITIONS = [CONNECTION_ERROR,]

# Prority list for REPLICATION_LAG consideration in multiple standby
NEGATIVE_REPLCIATION_LAG_PRIORITY = [IO_CONNECTION_ERROR, RESPONSE_ERROR, 
                                    SECONDS_BEHIND_MASTER, SQL_ERROR, IO_ERROR,
                                    GALERA_REPLICATION_ERROR]


# Default SIMULATION LAG VALUES
ZERO_LAG = 0 
POSITIVE_LAG = 100
SIMULATION_VALUES = [ZERO_LAG, IO_CONNECTION_ERROR, SECONDS_BEHIND_MASTER,
                        RESPONSE_ERROR, IO_ERROR, SQL_ERROR,
                        CONNECTION_ERROR, POSITIVE_LAG]
gSimulationInfo = {} # store simulation info
gSimulationInfo['active'] = False
gSimulationInfo['simulation_values'] = SIMULATION_VALUES
# #############################
# Global related to SSL
CLIENT_CERT_PATH = '/system/certs/cid_%s/client.pem'
CLIENT_KEY_PATH = '/system/certs/cid_%s/client.key'
CA_CERT_PATH = '/system/certs/cid_%s/server-ca.pem'

# Initialize logging
log.set_logging_prefix("failover")
_logger = log.get_logger("failover")

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
            -s, --simulate        : Run in simulate mode
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

class ProcessFailover(object):
    '''
    This class implements routines/member variables which will process one single
    request for failover. Ofcourse this means that, for every cluster at any
    given time, one instance of this class should be active.
    '''
    def __init__(self, cluster_id, origin, last_master_down, core_failover_timeout, 
                    logger, dc_failover=False):
        self._cluster_id = cluster_id
        self._origin = origin
        self._last_master_down = last_master_down # origin= UI then it will be 0
        self._error_msg = ''
        self._api_max_retry = 3
        self._base_url = 'https://127.0.0.1/api/'
        self._api_sub_url = '?apikey=' + APIKEY
        self._cluster_started = False
        self._cluster_stats = '' # complete list of cluster stats in string form
                                # after jsonifying it.
        self._servers_list = [] # list of dicts  = {}
        self._flip_flop_interval = 0
        self._failure_timeout = 0.3
        self._status_lock_file = '/tmp/failover.lock.%d' % self._cluster_id
        self._external_api_path = ''
        self._external_retry_attempts = 3
        self._external_api_timeout = 60
        self.mssql_replication = None
        self._server_to_be_promoted = {} # {'server_id':n, 'server_role':''}
        self._server_to_be_demoted = {}
        self._root_accnt_info = {}
        self._replication_type = 'async' # async/sync
        self._switch_delay_time = -1
        self._wait_for_sync = False
        self._force_failover = False
        self._max_wait_sync_retry = 3
        self._wait_sync_retry_interval = 1
        self._failover_type = IDB_FAILOVER # default
        self._standby_ids = []
        self._core_failover_timeout = core_failover_timeout
        self._logger = logger
        self._dc_failover = dc_failover
        self.is_read_only_present_on_slave = False
        self.read_only_logic_enable = self._get_read_only_flag()
        self.read_only_flag_unset = False
        self.events = events.Event() 

    def get_root_user_info(self):
        ''' Reading User Information regarding ssl and username and password
        '''
        self._logger.info("Failover: Reading root User info and ssl info if enabled") 
        self._root_accnt_info = self.find_root_user_info()
        self._ssl_enabled, self._ssl_enable_client,\
        self._ssl_verify_server, self.outbound_ip = self.find_cluster_info()
        self._ssl_components = {'cert': CLIENT_CERT_PATH % self._cluster_id, 
                                 'key': CLIENT_KEY_PATH % self._cluster_id,
                                 'ca': CA_CERT_PATH % self._cluster_id,
                                 'cipher': 'ALL'}
        self.ssl = self._get_ssl_info()

    def _get_read_only_flag(self):
        '''
        Get Read_only flag from failover conf. Reading this setting will tell
        do we need to apply read_only logic for failover request
        '''
        try:
            read_only_logic_enable = int(_config.get('default', 'read_only'))
            _logger.debug("Read Only Flag logic is %s" % read_only_logic_enable)
        except:
            read_only_logic_enable = 1

        return read_only_logic_enable

    def _show_read_only_flag(self, server_ip, server_port):
        ''' Find permission on all standby servers 
        '''
        retry = 0
        is_read_only_present = False
        dbconn = None
        cursor = None
        while retry < MAX_RETRY:
            try:
                query = "show variables like 'read_only';"
                dbconn, cursor = mysql_util.get_connection(host=server_ip,
                                        port=server_port,
                                        user=self._root_accnt_info['username'],
                                        passwd=self._root_accnt_info['password'],
                                        ssl=self.ssl)
                result = mysql_util.execute_query(dbconn, cursor, query)
                variable_name = result['Variable_name']
                variable_value = result['Value']
                if variable_name == 'read_only' and variable_value == 'ON':
                    is_read_only_present = True
                self._logger.info("Show Variables Query is %s and response is %s and" \
                                  " is_read_only_present is %s" % (query, result, is_read_only_present))
                break
            except Exception, ex:
                retry = retry + 1
                self._logger.error("Exception in reading read_only variable exception is %s" % (ex))
            finally:
                if cursor:
                    cursor.close()
                if dbconn:
                    dbconn.close()
        return is_read_only_present

    def _set_read_only_flag_on_server(self, server_ip, server_port, value):
        ''' Change the read_only flag with value provided by in the
            funcation.
        '''
        retry = 0
        response = False
        result = ''
        dbconn = None
        cursor = None
        is_read_only_present = False
        while retry < MAX_RETRY:
            try:
                query = "SET GLOBAL READ_ONLY=%s" % value
                dbconn, cursor = mysql_util.get_connection(host=server_ip,
                                            port=server_port,
                                            user=self._root_accnt_info['username'],
                                            passwd=self._root_accnt_info['password'],
                                            ssl=self.ssl)
                result = mysql_util.execute_query(dbconn, cursor, query)
                self._logger.info("SET Query is %s and response is %s" % (query, result))
                #
                # Check flag set ot not
                #
                query = "show variables like 'read_only';"
                result = mysql_util.execute_query(dbconn, cursor, query)
                variable_name = result['Variable_name']
                variable_value = result['Value']
                if variable_name == 'read_only' and variable_value == 'ON':
                    is_read_only_present = True
                self._logger.info("SHOW_VARIABLES Query is %s and response is %s and" \
                                  " is_read_only_present is %s" % (query, 
                                                                    result,
                                                                    is_read_only_present))
                #
                # Check incoming value and is_read_only_present if both are same then SET is successful
                if is_read_only_present == bool(value):
                    response = True
                else:
                    response = False
                self._logger.info("Successfully Change ReadOnly Flag value is %s" % (response))
                break
            except Exception, ex:
                self._logger.error("Exception in setting read_only is %s now retrying" % (ex))
                retry = retry + 1 
            finally:
                if cursor:
                    cursor.close()
                if dbconn:
                    dbconn.close()
        return response

    def send_alert(self, msg_header, server_ip=None, 
                        server_id=0, error_message=None):
        ''' Send alert to alert_engine service
        '''
        msg = {'ident': self._cluster_id, 'cid': self._cluster_id, 'subject': 'Failover', 'message': ''}
        msg_dict = {
                   "demoted_server":"ScaleArc database failed to modify MySQL variable READ_ONLY on demoted server %s "\
                   "required for Auto Failover operation.",
                   "promoted_server": "ScaleArc database failed to modify MySQL variable READ_ONLY on newly promoted server %s, "\
                   "that is required for Auto Failover operation. So Aborting the Failover Operation.",
                   "replication_error": error_message,
                   "failover_error": 'Failover for Cluster %s failed, %s' % (self._cluster_stats['data']['cluster_name'], error_message)
                   }
        message = msg_dict[msg_header]
        if server_ip:
            message = message % server_ip

        self._logger.info("ALERTMSG %s" % (message))
        msg['message'] = message
        # Publishing alert to redis which will consumed by alert engine to send email alert
        publisher().publish('failover', msg)

        # Sending alert to UI
        if msg_header == "promoted_server":
            msg_type = str(SystemMonitorStat.FAILOVER_PROMOTION_READ_ONLY_FLAG_FAILURE)
        elif msg_header == "demoted_server":
            msg_type = str(SystemMonitorStat.FAILOVER_DEMOTION_READ_ONLY_FLAG_FAILURE)
        elif msg_header == "replication_error":
            msg_type = str(SystemMonitorStat.FAILOVER_REPLICATION_FAILURE)
        elif msg_header == "failover_error":
            msg_type = str(SystemMonitorStat.FAILOVER_OPERATION_FAILURE)
        result = self.events.send_event(message, int(msg_type), clusterid=self._cluster_id, serverid=server_id)

        self._logger.info("Response from API for sending events %s" % (result))

    def find_cluster_info(self):
        '''
        return outbound ipadress of this cluster
        '''
        ssl_enabled = False
        ssl_enable_client = False
        ssl_verify_server = False
        out_ip = ''
        retry = 0
        query = "select backendip,ssl_enabled,ssl_enable_client,ssl_verify_server from lb_clusters where status = 1;"
        sqlite_handle = util.get_sqlite_handle(LB_DB_FILE % self._cluster_id)
        if sqlite_handle:
            db_cursor = sqlite_handle.cursor()
            while retry < MAX_RETRY:
                try:
                    db_cursor.execute(query)
                    row = db_cursor.fetchone()
                    if row:
                        out_ip = row['backendip']
                        ssl_enabled = True if int(row['ssl_enabled']) else False
                        ssl_enable_client = True if int(row['ssl_enable_client']) else False
                        ssl_verify_server = True if int(row['ssl_verify_server']) else False
                    break
                except (Exception, sqlite3.Error) as e:
                    retry = retry + 1
                    if retry >= MAX_RETRY:
                        _logger.error("Failed to find cluster info: %s" % (e))
                    else:
                        time.sleep(0.1)

            util.close_sqlite_resources(sqlite_handle, db_cursor)
        return ssl_enabled, ssl_enable_client, ssl_verify_server, out_ip

    def _get_ssl_info(self):
        if self._ssl_enabled:
            if not self._ssl_verify_server:
                self._ssl_components['ca'] = None

            if not self._ssl_enable_client:
                self._ssl_components['key'] = None
                self._ssl_components['cert'] = None

            return self._ssl_components
        else:
            return None

    def find_root_user_info(self):
        '''
        Return a dictionary containing  root account information from table
        lb_users for this cluster_id.
        '''
        root_accnt_info = {'username':'', 'password':''}

        sqlite_handle = util.get_sqlite_handle(LB_DB_FILE % self._cluster_id)
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
                    root_accnt_info['password'] = row['encpassword']
                break
            except Exception, ex:
                retry = retry + 1
                if retry >= MAX_RETRY:
                    _logger.error("Failed to find root user info for cluster %s" % (ex))
                else:
                    time.sleep(0.1)

        util.close_sqlite_resources(sqlite_handle, db_cursor)
        if retry >= MAX_RETRY:
            return root_accnt_info

        #lets decrypt this password
        root_accnt_info['password'] = PasswordUtils.decrypt(root_accnt_info['password'])
        return root_accnt_info

    def _get_json_formatted_reply_from_url(self, url):
        '''
        Makes the api call and returns the data in json formatted python objects.
        Return valid data in json form on success or return None on failure.

        Note that retries made by routine only deal with low level library
        errors. Caller still needs to check if api call failed for e.g.
        clusterid not found, db locked issues etc.
        '''
        retry = 0
        while retry <= self._api_max_retry:
            try:
                f = urllib.urlopen(url,)
                json_data = f.read()
                f.close()
                return json.loads(json_data)
            except Exception, ex:
                retry = retry + 1

                if retry >= self._api_max_retry:
                    self._logger.error("Failed to make api call: %s, exception: %s" \
                              % (url, ex))
                    return None

    def _read_cluster_flip_flop_interval(self):
        '''
        Get the cluster flip_flop_interval.
        '''
        api_url = self._base_url + 'cluster/' + str(self._cluster_id) + \
                    "/auto_failover_flipflop_timeout" + self._api_sub_url
        response = self._get_json_formatted_reply_from_url(api_url)

        if response == None:
            self._error_msg = 'API call failed.'
            return False

        if not response['success']:
            # in what cases do we retry for e.g when db is locked.
            # for now we return.
            self._error_msg = 'API called returned failure. %s' % response['message']
            return False

        self._flip_flop_interval = int(response['data']['auto_failover_flipflop_timeout'])
        self._logger.debug("Setting flip-flop interval to %d seconds" \
                            % (self._flip_flop_interval))

        return True

    def _read_cluster_failure_timeout(self):
        '''
        Get the cluster failure_timeout.
        '''
        api_url = '%scluster/%s/auto_failover_failure_timeout%s' %(self._base_url,
                                                    self._cluster_id,
                                                    self._api_sub_url)
        response = self._get_json_formatted_reply_from_url(api_url)

        if response == None:
            self._error_msg = 'API call failed.'
            return False

        if not response['success']:
            # in what cases do we retry for e.g when db is locked.
            # for now we return.
            self._error_msg = 'API called returned failure. %s' % response['message']
            return False
        
        self._failure_timeout = response['data']['auto_failover_failure_timeout']
        self._logger.debug("Setting failure_timeout to %s seconds" \
                            % (self._failure_timeout))
        return True

    def _read_external_api_path(self):
        '''
        Read the external api configured for this cluster.
        '''
        api_url = self._base_url + 'cluster/' + str(self._cluster_id) +\
                    "/auto_failover_external_api" + self._api_sub_url
        response = self._get_json_formatted_reply_from_url(api_url)
        if response == None:
            self._error_msg = 'API call failed.'
            return False

        if not response['success']:
            # in what cases do we retry for e.g when db is locked.
            # for now we return.
            self._error_msg = 'API called returned failure.'
            return False
        self._external_api_path = response['data']['auto_failover_external_api']

        if self._failover_type == EXTERNAL_API_FAILOVER:
            if self._external_api_path == '':
                self._logger.error("Failover type set to use external api but no external api path available.")
                return False

        return True

    def _read_external_api_timeout(self):
        '''
        Read the external api timeout configured for this cluster.
        '''
        api_url = self._base_url + 'cluster/' + str(self._cluster_id) +\
                    "/auto_failover_get_retry_interval_time" + self._api_sub_url
        response = self._get_json_formatted_reply_from_url(api_url)
        if response == None:
            self._error_msg = 'API call failed.'
            return False

        if not response['success']:
            # in what cases do we retry for e.g when db is locked.
            # for now we return.
            self._error_msg = 'API called returned failure.'
            return False
        self._external_api_timeout = response['data']['auto_failover_get_retry_interval_time']
        return True
    
    def _read_external_retry_attempts(self):
        '''
        Read the external api retry attempts configured for this cluster.
        '''
        api_url = self._base_url + 'cluster/' + str(self._cluster_id) +\
                    "/auto_failover_get_max_retries" + self._api_sub_url
        response = self._get_json_formatted_reply_from_url(api_url)
        if response == None:
            self._error_msg = 'API call failed.'
            return False

        if not response['success']:
            # in what cases do we retry for e.g when db is locked.
            # for now we return.
            self._error_msg = 'API called returned failure.'
            return False
        self._external_retry_attempts = response['data']['auto_failover_get_max_retries']
        return True

    def _read_replication_type(self):
        '''
        Determine the type of replication set for auto_failover.
        '''
        api_url = self._base_url + 'cluster/' + str(self._cluster_id) + "/auto_failover_replication_type" + self._api_sub_url
        response = self._get_json_formatted_reply_from_url(api_url)
        if response == None:
            self._error_msg = 'API call failed.'
            return False

        if not response['success']:
            # in what cases do we retry for e.g when db is locked.
            # for now we return.
            self._error_msg = 'API called returned failure.'
            return False
        if  response['data']['auto_failover_replication_type'] == 'syncronous':
            self._replication_type = 'sync'
        else:
            self._replication_type = 'async'

        return True

    def _read_switch_delay_time(self):
        '''
        Determine the switch delay time set for auto-failover.
        '''
        api_url = self._base_url + 'cluster/' + str(self._cluster_id) + "/auto_failover_switch_delay_time" + self._api_sub_url
        response = self._get_json_formatted_reply_from_url(api_url)
        if response == None:
            self._error_msg = 'API call failed.'
            return False

        if not response['success']:
            # in what cases do we retry for e.g when db is locked.
            # for now we return.
            self._error_msg = 'API called returned failure.'
            return False
        self._switch_delay_time = int(response['data']['auto_failover_switch_delay_time'])
        return True

    def _read_wait_for_sync_value(self):
        '''
        Determine whether wait_for_sync is set to on or off
        '''
        api_url = self._base_url + 'cluster/' + str(self._cluster_id) + "/auto_failover_wait_for_sync" + self._api_sub_url
        response = self._get_json_formatted_reply_from_url(api_url)
        if response == None:
            self._error_msg = 'API call failed.'
            return False

        if not response['success']:
            # in what cases do we retry for e.g when db is locked.
            # for now we return.
            self._error_msg = 'API called returned failure.'
            return False
        if response['data']['auto_failover_wait_for_sync'] == 'on':
            self._wait_for_sync = True
        else:
            self._wait_for_sync = False

        return True
    
    def _read_force_failover_value(self):
        '''
        Determine whether force failover is set to True or False
        '''
        api_url = self._base_url + 'cluster/' + str(self._cluster_id) + "/auto_failover_force_failover" + self._api_sub_url
        response = self._get_json_formatted_reply_from_url(api_url)
        if response == None:
            self._error_msg = 'API call failed.'
            return False

        if not response['success']:
            # in what cases do we retry for e.g when db is locked.
            # for now we return.
            self._error_msg = 'API called returned failure.'
            return False
        if response['data']['auto_failover_force_failover'] == 'on':
            self._force_failover = True
        else:
            self._force_failover = False

        self._logger.debug("Setting force failover flag to %s" \
                            % (self._force_failover))
        return True

    def _read_wait_sync_retry(self):
        '''
        Read retry attempts to make while waiting for new master to be in sync.
        '''
        api_url = self._base_url + 'cluster/' + str(self._cluster_id) + "/auto_failover_get_max_retries_waitsync" + self._api_sub_url
        response = self._get_json_formatted_reply_from_url(api_url)
        if response == None:
            self._error_msg = 'API call failed.'
            return False

        if not response['success']:
            # in what cases do we retry for e.g when db is locked.
            # for now we return.
            self._error_msg = 'API called returned failure.'
            return False
        self._max_wait_sync_retry = int(response['data']['auto_failover_get_max_retries_waitsync'])
        self._logger.debug("Setting wait for sync retry to %d" % (
                                                            self._max_wait_sync_retry))
        return True

    def _read_wait_sync_retry_interval(self):
        '''
        Read retry attempts to make while waiting for new master to be in sync.
        '''
        api_url = self._base_url + 'cluster/' + str(self._cluster_id) + "/auto_failover_get_retry_interval_time_waitsync" + self._api_sub_url
        response = self._get_json_formatted_reply_from_url(api_url)
        if response == None:
            self._error_msg = 'API call failed.'
            return False

        if not response['success']:
            # in what cases do we retry for e.g when db is locked.
            # for now we return.
            self._error_msg = 'API called returned failure.'
            return False
        self._wait_sync_retry_interval = int(response['data']['auto_failover_get_retry_interval_time_waitsync'])
        self._logger.debug("Setting wait for sync retry interval to %d" \
                            % (self._wait_sync_retry_interval))
        return True

    def _read_failover_type(self):
        '''
        Determine the failover type
        '''
        api_url = self._base_url + 'cluster/' + str(self._cluster_id) + "/auto_failover_type" + self._api_sub_url
        response = self._get_json_formatted_reply_from_url(api_url)
        if response == None:
            self._error_msg = 'API call failed.'
            return False

        if not response['success']:
            # in what cases do we retry for e.g when db is locked.
            # for now we return.
            self._error_msg = 'API called returned failure.'
            return False

        if response['data']['auto_failover_type'] == 'idb':
            self._failover_type = IDB_FAILOVER
        else:
            self._failover_type = EXTERNAL_API_FAILOVER

        return True

    def _read_cluster_config(self):
        '''
        Read entire info for this cluster. This should probably be the first
        routine to be called. Returns true/false depending upon whether operation
        failed or succeded.
        '''
        try:
            self._logger.debug("Getting cluster information")
            self._read_cluster_info()
        except Exception, ex:
            self._error_msg = 'Failed to determine cluster information'
            self._logger.error('Problem determining cluster information')
            self._logger.error("%s" % (traceback.format_exc(),))
            return False

        if not self._read_cluster_flip_flop_interval():
            self._error_msg = 'Failed to determine cluster flip_flop_timeout'
            self._logger.error('Problem determining cluster flip-flop interval')
            return False

        if not self._read_cluster_failure_timeout():
            self._error_msg = 'Failed to determine cluster failure_timeout'
            self._logger.error('Problem determining cluster failure_timeout')
            return False

        if not self._read_failover_type():
            self._error_msg = 'Failed to determine failover type.'
            self._logger.error("Failed to determine failover type.")
            return False

        if not self._read_external_api_path():
            self._error_msg = 'Failed to determine external api path.'
            self._logger.error("Failed to determine external api path")
            return False

        if not self._read_external_retry_attempts():
            self._error_msg = 'Failed to determine external api retry attempts.'
            self._logger.error("Failed to determine external api retry attempts ")
            return False

        if not self._read_external_api_timeout():
            self._error_msg = 'Failed to determine external api timeout.'
            self._logger.error("Failed to determine external api timeout")
            return False

        if not self._read_replication_type():
            self._error_msg = 'Failed to determine replication type'
            self._logger.error("Failed to determine replication type")
            return False

        if self._failover_type != EXTERNAL_API_FAILOVER:

            if not self._read_switch_delay_time():
                self._error_msg = 'Failed to determine switch delay time.'
                self._logger.error('Failed to determine switch delay time.')
                return False

            if self._platform_type in (PLATFORM_TYPE_MYSQL, PLATFORM_TYPE_MSSQL):

                if not self._read_force_failover_value():
                    self._error_msg = 'Failed to determine force failover value.'
                    self._logger.error('Failed to determine force failover value.')
                    return False

                if not self._read_wait_for_sync_value():
                    self._error_msg = 'Failed to determine wait for sync value.'
                    self._logger.error('Failed to determine wait for sync value.')
                    return False

                if not self._read_wait_sync_retry():
                    self._error_msg = 'Failed to determien wait_for_sync max. retries.'
                    self._logger.error('Failed to determine wait_for_sync max. retries.')
                    return False

                if not self._read_wait_sync_retry_interval():
                    self._error_msg = 'Failed to determine wait_for_sync_retry interval.'
                    self._logger.error('Failed to determine wait_for_sync_retry interval.')
                    return False

        return True


    def _read_cluster_info(self):
        '''Function to read only cluster information from /cluster api
        '''
        api_url = self._base_url + 'cluster/' + str(self._cluster_id) + self._api_sub_url
        self._cluster_stats = self._get_json_formatted_reply_from_url(api_url)
        if self._cluster_stats == None:
            self._error_msg = 'API call failed.'
            return False

        if not self._cluster_stats['success']:
            # in what cases do we retry for e.g when db is locked.
            # for now we return.
            self._error_msg = 'API called returned failure. (%s)' % self._cluster_stats['message']
            return False
        
        # Set Platform type from cluster stats
        self._platform_type = self._cluster_stats['data']['iDB_type']

        # now read all information that we got and save it.
        if self._cluster_stats['data']['cluster_started'] == 'yes':
            self._cluster_started = True
        else:
            self._cluster_started = False

        self._servers_list = []

        # Read root user info related to ssl and username and password
        if self._platform_type in (PLATFORM_TYPE_MYSQL, PLATFORM_TYPE_MSSQL):
            self.get_root_user_info()

        for item in self._cluster_stats['data']['cluster_servers']:
            d = {}
            d['server_id'] = int(item['server_id'])
            d['server_status'] = int(item['server_status']) # 0-down,
                                                            # 1-lagging,
                                                            # 2-healthy
            # if server is down then we ignore it altogether
#             if d['server_status'] == SERVER_DOWN:
#                 continue

            d['server_role'] = SERVER_ROLE_MAP[item['server_role']]
            d['mark_server_status'] = item['mark_server_status']
            d['server_ip'] = item['server_ip']
            d['server_port'] = item['server_port']
            d['username'] = self._root_accnt_info.get('username', '')
            d['password'] = self._root_accnt_info.get('password', '')
            self._servers_list.append(d.copy())

        return True

    def _is_cluster_up(self):
        '''
        Return true if cluster is marked up else false.

        When idblb starts, then it performs some checks and then marks status
        for that cluster as UP. It takes time, but before that it can invoke
        failover script even though cluster is not fully up. So here we will check
        if cluster is up then only, we will proceed else we will ignore this
        request.
        '''
        if self._cluster_started:
            return True
        return False

    def _is_wait_for_failure_timeout(self):
        '''
        if request came from idbcore wait for failure_timeout
        before changing the rule.
        '''
        try:
            self._logger.info("Going to wait for failure timeout %s." \
                          % (self._failure_timeout))
            time.sleep(self._failure_timeout)
            self._logger.debug("Again gathering cluster information,"\
                            " as it might have changed.")
            self._read_cluster_info()
        except Exception, ex:
            self._logger.error("Problem while gathering cluster " \
                            "information: %s" % (ex, ))
            self._logger.error("%s" % (traceback.format_exc(),))
            self._error_msg = 'Error while getting cluster information: ' + self._error_msg
            return False
        return True

    def _is_flip_flop_rule_verified(self):
        '''
        Verify that the time difference between last failover operation that
        happened for this cluster (if happened at all) and this request is more
        than flip_flop time set for this cluster.
        '''
        # if failover request source is UI and force idbcore then we skip flip-flop rule check.
        if self._origin in ['gui', 'idbcore_force']:
            return True

        #
        # If failvoer request is for database failover which happened when external api is 
        # configured and source is idbcore. In such scenario we will skip flip flop verification.
        #
        last_master_info = self._get_server_by_id(self._last_master_down)
        if self._failover_type == EXTERNAL_API_FAILOVER and \
                last_master_info.get('server_role') != READ_WRITE and \
                self._origin == 'idbcore':
            return True

        self._logger.info("Verifying flip flop interval.")

        flip_flop_file_pattern = '/tmp/failover.last.%d.*' % self._cluster_id
        fl = glob.glob(flip_flop_file_pattern)
        if len(fl) == 0:
            # no flip-flop ever occurred
            return True

        # we believe that since failover for a cluster is an atomic operation,
        # there will always be only one file of pattern failover.last.<cid>.*
        try:
            last_failover_time = int(fl[0].split('.')[3])
        except Exception, ex:
            self._logger.error('Failed to determine last failover time. :%s' % (ex))
            return False
        if (int(time.time()) - last_failover_time) >= self._flip_flop_interval:
            return True
        return False


    def get_status_lock(self):
        '''
        Get status lock to prevent failover operation to be  triggered for this
        cluster while current request is underway.

        Failover status lock files are of form: '/tmp/failover.lock.<cid>'
        and last failover marker: '/tmp/failover.last.<cid>.<time>'
        '''
        if os.path.exists(self._status_lock_file):
            return False
        # get lock
        try:
            self._logger.debug("Getting status lock %s" % self._status_lock_file)
            fptr = open(self._status_lock_file, 'w+')
            fptr.close()
        except Exception, ex:
            self._logger.error("Error while creating lock file: %s" % ex)
            return False
        return True

    def release_status_lock(self):
        '''
        Release status lock file
        '''
        if os.path.exists(self._status_lock_file):
            self._logger.debug("Releasing the status lock %s" % self._status_lock_file)
            try:
                os.unlink(self._status_lock_file)
            except Exception, ex:
                self._logger.error("Error while removing lock file.")
                return False
        return True

    def _update_last_failover_time_file(self):
        '''
        Update the last-flip flop time file. Remove any files of pattern
        '/tmp/failover.last.<cid>.*' and create a new one
        '''
        flip_flop_file_pattern = '/tmp/failover.last.%d.*' % self._cluster_id
        last_flip_flop_time_file = '/tmp/failover.last.%d.%d' \
                                    % (self._cluster_id, int(time.time()))
        fl = glob.glob(flip_flop_file_pattern)
        if len(fl) > 0:
            for f in fl:
                try:
                    os.unlink(f)
                except Exception, ex:
                    self._logger.error("Failed to remove last failover time marker file.")
        #
        # FIX for IDB-5635
        # if this failover was triggered manually from gui and idbcore_force, we will create
        # the timestamp file.
        #
        if self._origin in ['gui', 'idbcore_force']:
            return

        #
        # If failvoer request is for database failover which happened when external api is 
        # configured and source is idbcore. In such scenario we will skip flip flop update.
        #
        last_master_info = self._get_server_by_id(self._last_master_down)
        if self._failover_type == EXTERNAL_API_FAILOVER and \
                last_master_info.get('server_role') != READ_WRITE and \
                self._origin == 'idbcore':
            return

        # now  create the newer marker file
        try:
            file = open(last_flip_flop_time_file, 'w+')
            file.close()
        except Exception, ex:
            self._logger.error("Error while creating failover last-time marker file: %s" % ex)

    def _is_single_master_up(self):
        '''
        Return true/false indicating whether we have single master up for this
        cluster or not (many masters up). We want only one and atleast one
        master.

        Note: Do we even need to have this check ?
        '''
        #ignoring master check for forec idbcore
        if self._origin == 'idbcore_force':
            return True
        master_count = 0
        for item in self._servers_list:
            if item['server_status'] == SERVER_HEALTHY and item['server_role'] == READ_WRITE and item['mark_server_status'] == 'online':
                master_count = master_count + 1
        if self._origin == 'idbcore':
            if master_count >= 1:
                return False
        else:
            if master_count > 1:
                return False
        return True

    def _is_standby_server_present(self):
        '''
        Return true if there is atleast one standby server present in this cluster
        else false.

        ** Note that, when we talk of standby servers we consider only
        those who are online. (IDB-5473)
        '''
        for item in self._servers_list:
            if item['mark_server_status'] == 'online':
                if item['server_role'] == STANDBY_TRAFFIC or item['server_role'] == STANDBY_NO_TRAFFIC:
                    return True
        return False

    def _is_failover_enabled(self):
        '''
        Returns true if failover is enabled for this cluster else false.
        '''
        api_url = self._base_url + 'cluster/' + str(self._cluster_id) + "/auto_failover" + self._api_sub_url
        response = self._get_json_formatted_reply_from_url(api_url)
        if response == None:
            self._error_msg = 'API call failed.'
            return False

        if not response['success']:
            # in what cases do we retry for e.g when db is locked.
            # for now we return.
            self._error_msg = 'API called returned failure.'
            return False
        if response['data']['auto_failover'] == 'off':
            return False
        return True

    def _is_external_api_configured(self):
        '''
        Return true/false indicating whether external api for this cluster is
        configured or not. If true, then we will still verify the failover
        request but will not use our logic to decide which master to promote as
        new master rather we will get this info from external api.

        Also if external api is enabled set the same in class variable.
        '''
        if self._external_api_path == '':
            return False
        return True

    def _verify_failover_request(self):
        '''
        Verify if this request for failover can be met. We have following
        constraints to check for :
        1. Make sure this cluster is marked active.
        2. is wait for failure timeout is needed, if yes do sleep for failure_timeout
            interval and then reload cluster information as it might have changed.
            else go ahead.
        3. At least one master server should not be up if request is from idbcore
            and more than one master should not be up when request is from gui
        4. Atleast one standby server should be present (Role other than
            Read+Write).
        5. make sure that time diff between last failover operation and this
            request is greater than flip-flop time set for this cluster.
        '''
        if not self._is_failover_enabled():
            self._error_msg = 'Failover is disabled for this cluster.'
            self._logger.error("Failover is disabled for this cluster")
            return False

        if self._origin == 'idbcore':
            if not self._is_wait_for_failure_timeout():
                self._error_msg = 'Error while doing failure timeout.'
                self._logger.error("Error while doing failure timeout")
                return False
        else:
            self._logger.info("Request is from %s, So no Waiting for"\
                              " failure timeout" % (self._origin))

        if not self._is_cluster_up():
            self._error_msg = 'Cluster is marked down.'
            self._logger.error("Cluster is marked down.")
            return False

        if not self._is_single_master_up():
            self._error_msg = 'Master server(s) is/are present.'
            self._logger.error("Master server(s) is/are present.")
            return False

        if not self._is_standby_server_present():
            self._error_msg = 'No valid standby server present'
            self._logger.error("No valid standby server present.")
            return False

        return True
    
    def _failover_via_external_api(self):
        '''
        Return the server id which will be promoted as new server in the cluster.
        '''
        if self._origin in ['idbcore', 'idbcore_force']:
            failover_type = 1
        else:
            if self._dc_failover:
                # manual accross dc failover
                failover_type = 3
            else:
                # Manual failover 
                failover_type = 2

        sid = -1
        index = 0

        self._cluster_stats['failover_timeout'] = self._core_failover_timeout
        self._cluster_stats['failover_type'] = failover_type
        self._cluster_stats['failure_timeout'] = self._failure_timeout
        self._cluster_stats['replication_type'] = self._replication_type

        while index < self._external_retry_attempts:
            try:
                index = index + 1
                cluster_stats_string_in_json = json.dumps(self._cluster_stats)
                cmd = "curl -ss --max-time %s -k -X POST '%s' --data 'data=%s'" % (self._external_api_timeout,
                                                                            self._external_api_path, cluster_stats_string_in_json)
                self._logger.info("Curl command for external API %s" % (cmd))
                status, output = commands.getstatusoutput(cmd)
                self._logger.debug("Curl command output: %s" % (output))
                output = json.loads(output)
                self._logger.info("Message from response %s" \
                                % (urllib.unquote(output['message'])))
                success = output['success']
                if success:
                    return True
            except Exception, ex:
                self._logger.error("Failed to do failover using " \
                              "external api: %s with response %s" % (ex, output))
        return False

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
            self._logger.error("Failed to make http call: %s" % ex)
            result = result
        return result

    def _get_lagtime_of_servers(self):
        '''
        Return a list of dicts {'server_id','lag_time'}.
        '''
        lagtime_list = []
        cmd = 'show_stat_status|%d|' % self._cluster_id
        server_response = util.socket_cmd_runner(unix_sock="/tmp/lb_sock_%s" % self._cluster_id,
                                                    command=cmd)
        if (server_response[:5] == "ERROR"):
            self._logger.error("Invalid server response: %s" % server_response)
            return lagtime_list

        if server_response == "":
            self._logger.error("Server returned empty response.")
            return lagtime_list
        if (server_response[:6]) == "STATUS":
            self._logger.warn("Unexpected response: %s." % server_response)
            return lagtime_list

        # now parse server_response
        lines = server_response.split()
        for line in lines:
            cols = line.split('|')
            if cols[0] != 'SR':
                continue
            d = {}
            d['server_id'] = int(cols[2])
            d['lagtime'] = int(cols[6])
            if gSimulationInfo['active'] and \
                    self._platform_type == PLATFORM_TYPE_MYSQL:
                d['lagtime'] = random.choice(gSimulationInfo['simulation_values'])
            lagtime_list.append(d.copy())

        return lagtime_list

    def _get_lagtime_of_server(self, server_id, lagtime_list):
        '''
        Return lag time of serverid. If not found return 0.
        '''
        for item in lagtime_list:
            if item['server_id'] == server_id:
                return item['lagtime']
        return 0

    def _find_standby_to_be_promoted(self):
        '''
        Find the serverid of standby server that will be promoted. We will
        choose the standby server with least replication lag.
        '''
        #TODO get leg time if mssql
        standby_ids = []
        if self._platform_type == PLATFORM_TYPE_MYSQL:
            lagtime_list = self._get_lagtime_of_servers()
            self._logger.info("Servers lagtime list is %s" \
                                    % (lagtime_list))
        for item in self._servers_list:
            if item['mark_server_status'] == 'online':
                if item['server_role'] == STANDBY_TRAFFIC or item['server_role'] == STANDBY_NO_TRAFFIC:
                    d = {}
                    d['server_id'] = item['server_id']
                    if self._platform_type == PLATFORM_TYPE_MYSQL:
                        d['lagtime'] = self._get_lagtime_of_server(item['server_id'], lagtime_list)
                    else:
                        d['lagtime'] = 0 
                    standby_ids.append(d.copy())

        self._standby_ids = standby_ids

        #
        # If replication type is Asynchronus and wait for sync is ON then 
        # do not check for abort failover case else we have to do that.
        #

        if self._platform_type == PLATFORM_TYPE_MYSQL:
            if self._replication_type == 'async' and self._wait_for_sync:
                server_id, abort_failover = self._find_lowest_lagged_server(check_abort_failover=False)
            else:
                server_id, abort_failover = self._find_lowest_lagged_server()
        else:
            if len(self._standby_ids) > 0:
                server_id = self._standby_ids[0]['server_id']
                abort_failover = False
            else:
                abort_failover = True
                server_id = -1
        return server_id, abort_failover
    
    def _get_current_role_of_server(self, server_id):
        '''
        Get role of server idenitified by server_id by looking up in
        self._servers_list
        '''
        for item in self._servers_list:
            if item['server_id'] == server_id:
                return item['server_role']
        return -1
    
    def _get_ip_port_of_server(self, server_id):
        '''
        Get role of server idenitified by server_id by looking up in
        self._servers_list
        '''
        for item in self._servers_list:
            if item['server_id'] == server_id:
                return item['server_ip'], item['server_port'] 
        return None, None

    def _find_server_to_be_promoted(self):
        '''
        Find the new primry server.
        1. check if external_api_configured and if so find the serverid of server
            to be promoted.
        2. else
            find a standby slave to be promoted
        3. find the role of this slave
        4. save the role and serverid in self._server_to_be_promoted dictionary.

        Return true/false indicating success/failure.
        '''
        server_id = -1
        abort_failover = False

        server_id, abort_failover = self._find_standby_to_be_promoted()

        if abort_failover:
            self._logger.info("Aborting Failover as all servers are  "\
                            "having CONNECTION_ERROR and wait "\
                            "for sync is OFF.")
            return False

        if server_id == -1:
            self._logger.error("Failed to determine server to " \
                          "be promoted.")
            return False

        current_role = self._get_current_role_of_server(server_id)
        if current_role == -1:
            self._logger.error("Failed to determine current role of "\
                          "server to be promoted.")
            return False

        # save this in server to be promoted.
        self._server_to_be_promoted['server_id'] = server_id
        self._server_to_be_promoted['server_role'] = current_role
        return True

    def _find_master_to_be_demoted(self):
        '''
        Find the current master.
        1. find master which is healthy, and online
        2. else
            choose any master at random since we dont know which master to accurately
            demote. In ideal condition, this should not happen, as there will only
            be one master.
        '''
        master_server_id = -1
        for item in self._servers_list:
            if item['server_status'] == SERVER_HEALTHY and \
                item['mark_server_status'] == 'online' and \
                    item['server_role'] == READ_WRITE:
                return item['server_id']
                break

        if master_server_id == -1:
            # we could not find a master server
            for item in self._servers_list:
                if item['server_role'] == READ_WRITE:
                    return item['server_id']

        return -1

    def _find_server_to_be_demoted(self):
        '''
        Find the server to be demoted.
        '''
        server_id = -1
        if self._origin == 'idbcore':
            server_id = self._last_master_down
        else:
            server_id = self._find_master_to_be_demoted()

        if server_id == -1:
            self._logger.error("Failed to determine server to be demoted.")
            return False

        current_role = self._get_current_role_of_server(server_id)
        if current_role == -1:
            self._logger.error("Failed to determine current role of " \
                                "server to be demoted.")
            return False

        # save this in server to be promoted.
        self._server_to_be_demoted['server_id'] = server_id
        self._server_to_be_demoted['server_role'] = current_role
        return True

    def get_err_msg(self):
        '''
        Return the error string. Needed to make sure no public access to
        member variables is given.
        '''
        return self._error_msg

    def set_err_msg(self, msg):
        '''
        Set error message 
        '''
        self._error_msg = msg

    def _process_async_replication(self):
        '''
        In case of replication set to Asynchronus we have more things to do
        before we promote master. We do those here.
        '''
        self._logger.info("Waiting for Switch delay time that is %s" %self._switch_delay_time)
        time.sleep(self._switch_delay_time)

        if self._platform_type == PLATFORM_TYPE_MYSQL:
            if self._wait_for_sync:
                self._logger.info("Wait for sync check is started")
                # we ensure that the server demoted and the one to be promoted
                # are in sync
                retry = 0
                self._zero_lagtime_server = False
                self._all_negative_three = False

                while retry < self._max_wait_sync_retry:
                    self._logger.info("Retrying for wait for sync where current retry is %s"\
                                      " and max_retry is %s" % (retry, self._max_wait_sync_retry))
                    lagtime_list = self._get_lagtime_of_servers()
                    self._logger.debug("Servers lagtime list is %s" \
                                    % (lagtime_list))
                    if not self._is_wait_retry_required(lagtime_list):
                        self._logger.info("Wait for sync no more required." \
                                        " Breaking from loop.")
                        break

                    retry = retry + 1
                    self._logger.info("Sleeping for wait_sync_retry_interval %s" %self._wait_sync_retry_interval)
                    time.sleep(self._wait_sync_retry_interval)

                if self._zero_lagtime_server or self._all_negative_three or self._force_failover:
                    server_id, abort_failover = self._find_lowest_lagged_server()
                else:
                    abort_failover = True

                if abort_failover:
                    msg = "Aborting Failover as force failvoer is OFF"\
                                       " or all standby servers are having CONECTION_ERROR."
                    self._logger.error(msg)
                    self._error_msg += msg
                    return False

                if server_id == -1:
                    msg = "This case should not occur, if it occurs "\
                                   "becasue of some error. Abort Failover and revert last demotion"
                    self._logger.error(msg)
                    self._error_msg += msg
                    return False

                current_role = self._get_current_role_of_server(server_id)
                if current_role == -1:
                    msg = "Failed to determine current role of "\
                                  "server after wait for sync. Aborting Failover and reverting"\
                                  " last demotion"
                    self._logger.error(msg)
                    self._error_msg += msg
                    return False
                #
                # Find whether server to be promoted that we found earlier has different role
                # than what we find now. If it has changed then change again role of demoted server.
                #
                change_role_again = False
                if current_role != self._server_to_be_promoted['server_role']:
                    change_role_again = True

                # save this in server to be promoted.
                self._server_to_be_promoted['server_id'] = server_id
                self._server_to_be_promoted['server_role'] = current_role

                if change_role_again:
                    self._logger.info("Server to be promoted has been changed and its role "\
                                  "is %s . We need to change role of demoted server too." 
                                   % (REVERSE_SERVER_ROLE_MAP[self._server_to_be_promoted['server_role']]))
                    # Change roler of server to be demoted.
                    res = self._do_demotion()

                    #
                    # Wait for sync we might have to change role of demoted server as
                    # a change in promoted server, we need to sleep for one second before executing
                    # promotion API.
                    #
                    time.sleep(1)

                    if res['message'].find('ERROR:') >= 0 or (not res['success']):
                        self._logger.error("Something went wrong while demoting " \
                                      "server: %s" % (res['message']))
                        self._error_msg = res['message']
                        return False

            #from idb.cmd.failover.failover_repl import ReplicationOperations
            from .failover_repl import ReplicationOperations

            old_server_ip, old_server_port = self._get_ip_port_of_server(self._server_to_be_demoted['server_id'])
            new_server_ip, new_server_port = self._get_ip_port_of_server(self._server_to_be_promoted['server_id'])

            replication = ReplicationOperations(old_master='%s:%s' % (old_server_ip, old_server_port),
                                                new_master='%s:%s' % (new_server_ip, new_server_port),
                                                servers_info=self._servers_list,
                                                log=self._logger, origin=self._origin, ssl=self.ssl)
            success, abort_failover, self._mark_offline, error_msg = replication.change_replication()

            # If there is any error_msg that will raised as an event as well mail alert will be sent
            if error_msg:
                error_msg = 'Cluster %s, %s' % (self._cluster_stats['data']['cluster_name'], error_msg)
                self.send_alert("replication_error", error_message=error_msg,)

            # If abort failover is triggered we need to revert back to older older state.
            if abort_failover:
                self._logger.error("Error occured while changing replication %s" % error_msg)
                return False

            # Marking servers offline
            for server_ip, msg in self._mark_offline.items():
                self._logger.info("Marking server %s offline as %s" % (server_ip, msg))
                self._change_mark_server_status(server_ip)
        else:
            # elif
            if self._platform_type == PLATFORM_TYPE_MSSQL:
                self._logger.info("MSSQL replication checks started...")
                #from idb.cmd.failover.failover_repl import ReplicationOperations
                from .mssql.sqlmirroring import MssqlAutoFailover
                
                old_server_ip, old_server_port = self._get_ip_port_of_server(self._server_to_be_demoted['server_id'])
                new_server_ip, new_server_port = self._get_ip_port_of_server(self._server_to_be_promoted['server_id'])
                self.mssql_replication = MssqlAutoFailover() 
                success, abort_failover, error_msg = self.mssql_replication.process_failover(self._cluster_id, 
                                                '%s:%s' % (old_server_ip, old_server_port),
                                                '%s:%s' % (new_server_ip, new_server_port),
                                                self._servers_list, self._root_accnt_info,
                                                self._wait_for_sync, self._max_wait_sync_retry,
                                                self._wait_sync_retry_interval, self._force_failover,
                                                log=self._logger)

                # If there is any error_msg that will raised as an event as well mail alert will be sent
                if error_msg:
                    error_msg = 'Cluster %s, %s' % (self._cluster_stats['data']['cluster_name'], error_msg)
                    self.send_alert("replication_error", error_message=error_msg,)

                # If abort failover is triggered we need to revert back to older older state.
                if abort_failover:
                    self._logger.error("Error occured while changing replication %s" % error_msg)
                    return False

        return True
    
    def _change_mark_server_status(self, server_ip, online=False):
        retry = 0
        while retry < MAX_RETRY:
            try:
                serverinfo = self._get_server_info(server_ip)
                if not serverinfo:
                    self._logger.warning("Server %s does not have server information" % server_ip)
                    return

                ip_addr = '127.0.0.1'
                master_base_url_path = '/api/cluster/%s/server/%s/mark_server_status' % (str(self._cluster_id),
                                                    str(self._server_to_be_demoted['server_id']))

                data_dict = {}
                data_dict["apikey"] = APIKEY
                data_dict["mark_server_status"] = 'offline' if not online else 'online'
                data_dict["timetowait"] = 0

                res = self._exec_url_generic(ip_addr, master_base_url_path, json.dumps(data_dict), 'PUT')
                self._logger.info("Response of marking server offline %s: %s" % (server_ip, res))
                if res['message'].find('ERROR:') >= 0 or (not res['success']):
                    self._logger.error("Something went wrong while marking server "\
                                    " offline: %s" % (res['message']))
                    retry += 1
                    time.sleep(0.5)
                else:
                    self._logger.info("Sucessfully changes server %s mark server status" % server_ip)
                    break
            except Exception, ex:
                self._logger.error("Got an error %s while marking server %s offline. Retrying ..." % (ex, server_ip))
                retry += 1
                time.sleep(0.5)

        if retry >= MAX_RETRY:
            self._logger.error("Failed to marke Server %s offline after all retry attempts." % (server_ip))


    def _get_server_info(self, server_ip):
        for item in self._servers_list:
            host = '%s:%s' % (item['server_ip'], item['server_port'])
            if host == server_ip:
                return item
        return None
    
    def _get_server_by_id(self, server_id):
        for item in self._servers_list:
            if item['server_id'] == server_id:
                return item
        return None

    def _is_server_healthy(self, server_id):
        for item in self._servers_list:
            if item['server_id'] == server_id \
                and item['server_status'] in [SERVER_HEALTHY]:
                return True
        return False

    def _is_wait_retry_required(self, lagtime_list):
        '''
            Check whether retry for wait for sync is required or not
            This will return False in following conditions:
            1. When any standby server has zero replication lag
            2. When all standby servers are having I/O error i.e -3 replication lag
        '''
        zero_lagtime = False
        all_negative_three = True

        for server in self._standby_ids:
            server['lagtime'] = self._get_lagtime_of_server(server['server_id'], 
                                                            lagtime_list)
            if server['lagtime'] == 0:
                zero_lagtime = True
            elif not server['lagtime'] in ZERO_LAGTIME_CONDITIONS:
                all_negative_three = False

        #
        # If any server lagtimg is zero then we will break 
        # from wait for sync loop.
        #
        if zero_lagtime:
            self._zero_lagtime_server = True
            self._logger.info("Found a server with zero replication lag")
            return False
        #
        # If all servers have -3 as replication lag, then we will
        # break from sync loop
        #
        if all_negative_three:
            self._all_negative_three = True
            self._logger.info("All standby servers are having" \
                            " I/O connection error.")
            return False

        return True

    def _find_lowest_lagged_server(self, check_abort_failover=True):
        '''
            Find lowest lagged server to promote.
            This function is executing following cases:
            1. Find servers with postive replication lag (>=0) and if found return server
                with least relplication lag.
            2. If no positive replication lag found then find servers with negative replication
                lag. 
            3. Find does all negative replication lag servers are having CONNECTION_ERROR. If it 
                is then abort the Failover
                else find servers with valid replication lag i.e ignore connection errors servers.
            4. After third step find servers with replicaiton lag priority and return first server
                from it.
        '''
        self._logger.debug("Finding lowest lagged standby server with check abort"\
                        " failover flag as %s" % (check_abort_failover))
        #
        # Sort this servers by lagtime and choose first one which 
        # will have lowest lagtime
        #
        sorted_positive_server_ids = sorted(filter(lambda x: True if x['lagtime'] >= 0 else False, 
                                                    self._standby_ids),
                                            key=lambda x: x['lagtime'])
        if len(sorted_positive_server_ids) >= 1:
            self._logger.info("Valid positive replication lag servers %s" \
                                % (sorted_positive_server_ids))

            server_id = sorted_positive_server_ids[0]['server_id']
            return server_id, False

        sorted_negative_server_ids = sorted(filter(lambda x: True if x['lagtime'] < 0 else False, 
                                                    self._standby_ids),
                                            key=lambda x: x['lagtime'])

        self._logger.debug("All servers %s are having negative replication lags" \
                            % (sorted_negative_server_ids))

        if check_abort_failover:

            abort_failover = True
            for server in sorted_negative_server_ids:
                if not server['lagtime'] in ABORT_FAILOVER_CONDITIONS:
                    abort_failover = False

            #
            # Remove servers whose replication lag is equal to values 
            # in ABORT_FAILOVER_CONDITIONS
            #
            sorted_valid_negative_server_ids = sorted(filter(lambda x: False if x['lagtime'] \
                                                                in ABORT_FAILOVER_CONDITIONS else True,
                                                            self._standby_ids),
                                                        key=lambda x: x['lagtime'])
        else:
            # If check abort failover is disabled then assign sorted_negative_server_ids are valid server ids
            abort_failover = False
            sorted_valid_negative_server_ids = sorted_negative_server_ids

        self._logger.debug("Valid servers %s with negative replication lag" \
                            % (sorted_negative_server_ids))

        # Sort server ids as per priority list of replication lags
        min_index = None
        final_index = 0
        for server_index, server in enumerate(sorted_valid_negative_server_ids):
            if server['lagtime'] in NEGATIVE_REPLCIATION_LAG_PRIORITY:
                index = NEGATIVE_REPLCIATION_LAG_PRIORITY.index(server['lagtime'])
                if min_index == None or index < min_index:
                    min_index = index
                    final_index = server_index

        self._logger.info("Valid prority sorted negative replication lag servers %s" \
                            % (sorted_valid_negative_server_ids))

        # Find Final index server
        if len(sorted_valid_negative_server_ids) > 0:
            server_id = sorted_valid_negative_server_ids[final_index]['server_id']
        else:
            server_id = ''
        return server_id, abort_failover

    def _revert_server_roles(self):
        ''' Revert server roles as well as replication changes if required
            This revvert will revert previous promotion as well as demotion including switchover
            demotion command.
        '''
        self._revert_previous_promotion()
        self._revert_replication_changes()
        self._revert_previous_demotion(switchover=True)

        if self.read_only_flag_unset:
            self._logger.info("Reverting ReadOnly ie Doing SET that was unset Previously")
            server_ip, server_port = self._get_ip_port_of_server(self._server_to_be_promoted['server_id'])
            self._set_read_only_flag_on_server(server_ip, server_port, SET_READ_ONLY) 

    def _revert_replication_changes(self):
        """
            This method is ised to revert replication changes. CUrrently it
            is doing it for MYSQL platform only.
        """

        #
        # Revert only if server to be demoted is healthy. i.e in case of 
        # manual failover with healthy server
        #
        if self._replication_type == 'async' \
                and self._is_server_healthy(self._server_to_be_demoted['server_id']):
            if self._platform_type == PLATFORM_TYPE_MYSQL:
                self._logger.info("Reverting replication changes that has been done earlier.")

                #
                # Changing servers status to online whose status is 
                # marked as offline after replication changes
                #
                for server_ip, msg in self._mark_offline.items():
                    self._logger.info("Marking server %s online." % (server_ip))
                    self._change_mark_server_status(server_ip, online=True)

                from .failover_repl import ReplicationOperations
                old_server_ip, old_server_port = self._get_ip_port_of_server(self._server_to_be_promoted['server_id'])
                new_server_ip, new_server_port = self._get_ip_port_of_server(self._server_to_be_demoted['server_id'])
                replication = ReplicationOperations(old_master='%s:%s' % (old_server_ip, old_server_port),
                                                    new_master='%s:%s' % (new_server_ip, new_server_port),
                                                    servers_info=self._servers_list,
                                                    log=self._logger, 
                                                    origin=self._origin,
                                                    ssl=self.ssl)
                success, abort_failover, mark_offline, error_msg = replication.change_replication()
	    elif self._platform_type == PLATFORM_TYPE_MSSQL:
                mssql_failover_obj = self.mssql_replication.failover_obj
                mssql_failover_obj.revert_replication_if_any()

    def _revert_previous_demotion(self, switchover=False):
        '''
        Revert the demotion in stage1 since our attempt to promote in stage2
        failed. This is needed to keep the system in a consistent state.
        '''
        if self._server_to_be_demoted.get('server_id'): 

            if switchover and self._platform_type != PLATFORM_TYPE_MSSQL:
                server_id = self._server_to_be_demoted['server_id']

                data_dict = {}
                data_dict["apikey"] = APIKEY
                data_dict['server_id'] = server_id
                data_dict['server_role'] = REVERSE_SERVER_ROLE_MAP\
                                                    [self._server_to_be_demoted['server_role']]
                data_dict['failover_timeout'] = self._core_failover_timeout
                data_dict['type'] = 'promotion'
                self._logger.info("Reverting Switchover Demotion Command")
                success_demotion = self._switch_server_role(data_dict)
                if not success_demotion:
                    self._logger.error("Failed to revert switchover demotion.")

            #
            # we need to sleep for one second before executing
            # other API.
            #
            time.sleep(1)

            ip_addr = '127.0.0.1'
            self._logger.warn("Reverting demotion of last stage.")
            self._logger.debug("Attempting to restore server state: %d with role: %s" \
                          % (self._server_to_be_demoted['server_id'], \
                             REVERSE_SERVER_ROLE_MAP[self._server_to_be_demoted['server_role']]))
            master_base_url_path = '/api/cluster/' + str(self._cluster_id) + '/server_role/' + str(self._server_to_be_demoted['server_id'])

            data_dict = {}
            data_dict["apikey"] = APIKEY
            data_dict["server_role"] = REVERSE_SERVER_ROLE_MAP[self._server_to_be_demoted['server_role']]
            res = self._exec_url_generic(ip_addr, master_base_url_path, json.dumps(data_dict), 'PUT')

            if res['message'].find('ERROR:') >= 0 or (not res['success']):
                self._logger.error(" Something went wrong while restoring " \
                              "old primary server state: %s" % (res['message']))

            self._logger.debug("Reverting Demotion logs: %s" % (res))

    def _revert_previous_promotion(self):
        '''
        Revert the demotion in stage1 since our attempt to promote in stage2
        failed. This is needed to keep the system in a consistent state.
        '''
        #
        # we need to sleep for one second before executing
        # other API.
        #
        time.sleep(1)
        ip_addr = '127.0.0.1'
        self._logger.warn("Reverting promotion of last stage.")
        self._logger.debug("Attempting to restore server state: %d with role: %s" \
                      % (self._server_to_be_promoted['server_id'], \
                         REVERSE_SERVER_ROLE_MAP[self._server_to_be_promoted['server_role']]))
        master_base_url_path = '/api/cluster/' + str(self._cluster_id) + '/server_role/' + str(self._server_to_be_promoted['server_id'])
        data_dict = {}
        data_dict["apikey"] = APIKEY
        data_dict["server_role"] = REVERSE_SERVER_ROLE_MAP[self._server_to_be_promoted['server_role']]
        res = self._exec_url_generic(ip_addr, master_base_url_path, json.dumps(data_dict), 'PUT')
        if res['message'].find('ERROR:') >= 0 or (not res['success']):
            self._logger.error("Something went wrong while restoring " \
                                "server state: %s" % (res['message']))
        self._logger.debug("Reverting Promotion Logs: %s" % (res))

    def _switch_server_role(self, data_dict):
        '''
            Switch server role function will execute switch_server_role
            API to inform core about failover i.e promotion or demotion
        '''
        #
        # we need to sleep for one second before executing
        # other API.
        #
        time.sleep(1)
        if self._platform_type == PLATFORM_TYPE_MSSQL: 
            master_base_url_path = '/api/cluster/' + str(self._cluster_id) + '/server_role/' + str(data_dict['server_id'])
            self._logger.info("Master base url %s" %master_base_url_path)
        else:
            master_base_url_path = '/api/cluster/' + str(self._cluster_id) + '/switch_server_role'
        ip_addr = '127.0.0.1'

        retry = 0
        while retry < MAX_RETRY:
            try:
                res = self._exec_url_generic(ip_addr, master_base_url_path, json.dumps(data_dict), 'PUT')
                if res['message'].find('ERROR:') >= 0 or (not res['success']):
                    self._logger.error("Something went wrong while switching"\
                                    " of servers: %s" % (res['message']))
                    retry += 1
                else:
                    self._logger.debug("Switch server role change response %s" % (res))
                    break
            except:
                self._logger.error("Something went wrong while switching"\
                                    " of servers: %s" % (res))
                retry += 1

        if retry >= MAX_RETRY:
            return False
        return True


    def _inform_core_about_demotion(self):
        '''
        Inform core about the role change that we are going to make.

        switch_standby_demotion|cid|dbid|role|timeout|
        '''
        if self._server_to_be_demoted.get('server_id'): 
            server_id = self._server_to_be_demoted['server_id']

            data_dict = {}
            data_dict["apikey"] = APIKEY
            data_dict['server_id'] = server_id
            data_dict['server_role'] = REVERSE_SERVER_ROLE_MAP\
                                                [self._server_to_be_promoted['server_role']]
            data_dict['failover_timeout'] = self._core_failover_timeout
            data_dict['type'] = 'demotion'
            self._logger.info("Informing core about demotion using switch server role API.")
            success_demotion = self._switch_server_role(data_dict)
            if not success_demotion:
                self._logger.error("Failed to inform core regarding demotion."\
                                    "Reverting older server role changes.")
                success = False
                return success

        return True

    def _send_failover_alert(self):
        """ Publish messsage on redis so that alert for failover will be sent.
        """

        msg = {'ident': self._cluster_id, 'cid': self._cluster_id, 'subject': 'Failover', 'message': ''}
        db_list = {}
        try:
            for i in cluster_util.ClusterUtils.get_all_server_details(self._cluster_id):
                db_list[i['server_id']] = i
        except Exception as e:
            self._logger.error("Could not get database details for clusterid %d")

        # If demotion server is avialble then demotion is also done and create its message
        if self._server_to_be_demoted.get('server_id'): 
            server_id = self._server_to_be_demoted['server_id']
            if server_id in db_list:
                db_info = '%s:%d' % (db_list[server_id]['ip'], db_list[server_id]['port'])
            else:
                db_info = '%d' % (server_id)

            msg["message"] += "Database (%s) role \"%s\" has been demoted via %s.\r\n" % \
                                (db_info, \
                                REVERSE_SERVER_ROLE_MAP[self._server_to_be_demoted['server_role']], \
                                self._origin)

        if self._server_to_be_demoted.get('server_id'): 
            server_role = self._server_to_be_demoted['server_role'] 
        else:
            #
            # This case will occure when origin is idbcore_force and there are only Standby
            # servers no reas write server
            #
            server_role = READ_WRITE

        server_id = self._server_to_be_promoted['server_id']
        if server_id in db_list:
            db_info = '%s:%d' % (db_list[server_id]['ip'], db_list[server_id]['port'])
        else:
            db_info = '%d' % (server_id)

        curr_role = self._server_to_be_promoted['server_role']
        msg["message"] += "Database (%s) role \"%s\" has been promoted " \
                            % (db_info, REVERSE_SERVER_ROLE_MAP[curr_role])

        if server_role != self._server_to_be_promoted['server_role']:
            msg["message"] += "to new role \"%s\" " % REVERSE_SERVER_ROLE_MAP[server_role]

        msg["message"] += "via %s." % (self._origin)

        self._logger.info("Sending Failover alert %s" % msg)
        publisher().publish('failover', msg)


    def _inform_core_about_promotion(self):
        '''
        Inform core about the role change that we are going to make.

        switch_standby_promotion|cid|dbid|role|timeout|
        '''

        if self._server_to_be_demoted.get('server_id'): 
            server_role = self._server_to_be_demoted['server_role'] 
        else:
            #
            # This case will occure when origin is idbcore_force and there are only Standby
            # servers no reas write server
            #
            server_role = READ_WRITE

        data_dict = {}
        data_dict["apikey"] = APIKEY
        data_dict['server_id'] = self._server_to_be_promoted['server_id']
        data_dict['server_role'] = REVERSE_SERVER_ROLE_MAP[server_role]
        data_dict['failover_timeout'] = self._core_failover_timeout
        data_dict['type'] = 'promotion'
        self._logger.info("Informing core about promotion using switch server role API.")
        success_promotion = self._switch_server_role(data_dict)
        if not success_promotion:
            self._logger.error("Failed to inform core regarding promotion."\
                                " Not able to revert it.")
            success = False
            return success

        return True, False

    def _make_demoted_server_readonly(self):
        """ This method will mark demoted server to read only.
            i.e It sets flag of read only oon mysql server.
        """

        # SETTING Read_Only Flag on demoted server if it fails then send alert
        if self.is_read_only_present_on_slave and self.read_only_logic_enable \
            and self._server_to_be_demoted.get('server_id') \
            and self._platform_type == PLATFORM_TYPE_MYSQL:
            server_ip, server_port = self._get_ip_port_of_server(self._server_to_be_demoted['server_id'])
            if server_ip and server_port:
                self._logger.info("Setting Read_Only Flag for new demoted server %s"\
                                         % (server_ip))
                res = self._set_read_only_flag_on_server(server_ip, server_port, SET_READ_ONLY)
                if not res:
                    self.send_alert("demoted_server",
                                      server_ip=server_ip,
                                      server_id=self._server_to_be_demoted['server_id'])
                    self._logger.error("Failed to set read only flag on server_to_be_demoted %s" % (server_ip))


    def _do_demotion(self):

        ip_addr = '127.0.0.1'
        master_base_url_path = '/api/cluster/' + str(self._cluster_id) + '/server_role/' + str(self._server_to_be_demoted['server_id'])

        data_dict = {}
        data_dict["apikey"] = APIKEY
        data_dict["server_role"] = REVERSE_SERVER_ROLE_MAP[self._server_to_be_promoted['server_role']]
        data_dict["failover_timeout"] = self._core_failover_timeout

        res = self._exec_url_generic(ip_addr, master_base_url_path, json.dumps(data_dict), 'PUT')
        return res

    def _perform_role_change(self):
        '''
        By now we have found server to be promoted and server to be demoted.
        Make api calls to finalize the changes.
        '''
        ip_addr = '127.0.0.1'

        self._logger.debug("Server to be demoted: %s" % (self._server_to_be_demoted))
        self._logger.debug("Server to be promoted: %s" % (self._server_to_be_promoted))

        # first demotion
        if self._server_to_be_demoted.get('server_id'):
            demoted_server_ip, demoted_server_port = self._get_ip_port_of_server(self._server_to_be_demoted['server_id'])
            self._logger.info("Attempting to demote server: %d having IP %s with new role: %s" \
                          % (self._server_to_be_demoted['server_id'], demoted_server_ip, \
                             REVERSE_SERVER_ROLE_MAP[self._server_to_be_promoted['server_role']]))

            # Do demotion using server_role API
            res = self._do_demotion()
            if res['message'].find('ERROR:') >= 0 or (not res['success']):
                self._logger.error("Something went wrong while demoting " \
                              "server: %s" % (res['message']))
                self._error_msg = res['message']
                return False
            self._logger.debug("Demotion logs: %s" % (res))

            self._logger.debug("Informing core about demotion.")
            if not self._inform_core_about_demotion():
                self._error_msg = "Problem while informing core about demotion " \
                                  "operation."
                self._revert_previous_demotion()
                return False

            #
            # sleep for core failover timeout. After this time interval process 
            # further operations.
            #
            self._logger.info("Sleeping for core failover timeout value %s"\
                                             % (self._core_failover_timeout))
            time.sleep(self._core_failover_timeout)

            if self._replication_type == 'async':
                try:
                    if not self._process_async_replication():
                        self._error_msg += " Aborting Failover."
                        if self._platform_type != PLATFORM_TYPE_MSSQL:
                            self._revert_replication_changes()
                        self._revert_previous_demotion(switchover=True)
                        return False
                except Exception, ex:
                    self._logger.error("Problem while processing " \
                                  "async_replication operations: %s" % (ex))
                    self._error_msg += "Problem while processing async_replication " \
                                      "operations: %s" % ex
                    if self._platform_type != PLATFORM_TYPE_MSSQL:
                        self._revert_replication_changes()
                    self._revert_previous_demotion(switchover=True)
                    return False
        else:
            if self._replication_type == 'async':
                self._logger.info("No demotion server available, so skipping "\
                            "demotion and async replication process")
            else:
                self._logger.info("No demotion server available, so skipping demotion")

        if self._server_to_be_demoted.get('server_id'): 
            server_role = REVERSE_SERVER_ROLE_MAP[self._server_to_be_demoted['server_role']]
        else:
            #
            # This case will occure when origin is idbcore_force and there are only Standby
            # servers no read write server
            #
            server_role = REVERSE_SERVER_ROLE_MAP[READ_WRITE]

        #
        #
        #Logic: UNSET the Read_Only flag on newly promoted server so that it can server r/w traffic.
        #If it fails to UNSET then abort the operation and send the alert
        #
        promoted_server_ip, promoted_server_port = self._get_ip_port_of_server(\
                                                    self._server_to_be_promoted['server_id'])
        if self.read_only_logic_enable and \
            self._platform_type == PLATFORM_TYPE_MYSQL:
            if promoted_server_ip and promoted_server_port: 
                self.is_read_only_present_on_slave = self._show_read_only_flag(promoted_server_ip, 
                                                                                promoted_server_port)
                self._logger.info("read_only present %s for server_ip %s"\
                                         % (self.is_read_only_present_on_slave, 
                                                promoted_server_ip))
                if self.is_read_only_present_on_slave:
                    self._logger.info("UnSetting Read_Only Flag for new promoted server %s"\
                                             % (promoted_server_ip))
                    res = self._set_read_only_flag_on_server(promoted_server_ip, 
                                                                promoted_server_port, 
                                                                UNSET_READ_ONLY)
                    if not res:
                        # Revert Demotion and send alert
                        self._logger.error("Failed to unset read only flag on server_to_be_promoted %s"\
                                           " Reverting Demotion and if needed replication changes" \
                                           % (promoted_server_ip))
                        self._error_msg += "Aborting Failover."
                        self._revert_replication_changes()
                        self._revert_previous_demotion(switchover=True)
                        self.send_alert("promoted_server", server_ip=promoted_server_ip,
                                            server_id=self._server_to_be_promoted['server_id'])
                        return False
                    self.read_only_flag_unset = True
            else:
                self._logger.info("Could not Found server ip and server port for server id %s"\
                                         % (self._server_to_be_promoted['server_id']))
                return False

        # now promote
        self._logger.info("Attempting to promote server: %d having IP %s " \
                            "with new role: %s" % (self._server_to_be_promoted['server_id'],
                                                    promoted_server_ip,
                                                    server_role))
        master_base_url_path = '/api/cluster/' + str(self._cluster_id) + '/server_role/' + str(self._server_to_be_promoted['server_id'])
        data_dict = {}
        data_dict["apikey"] = APIKEY
        data_dict["server_role"] = server_role
        res = self._exec_url_generic(ip_addr, master_base_url_path, json.dumps(data_dict), 'PUT')
        if res['message'].find('ERROR:') >= 0 or (not res['success']):
            self._logger.error("Something went wrong while promoting " \
                                "server: %s" % (res['message']))
            self._error_msg = res['message']
            #
            # If promotion failed for whatsover reason, we will reverse replication 
            # changes if required and demotion in first stage.
            #
            self._error_msg += "Aborting Failover."
            self._revert_replication_changes()
            self._revert_previous_demotion(switchover=True)
            return False
        self._logger.debug("Promotion logs: %s" % (res))

        if self._platform_type in [PLATFORM_TYPE_MYSQL, 
                                    PLATFORM_TYPE_ORACLE]:
            # Do Final step about informing core about promotion
            if not self._inform_core_about_promotion():
                self._error_msg += 'Failed to inform core.'
                self._revert_server_roles()
                return False
        self._send_failover_alert()
        self._make_demoted_server_readonly()

        return True

    def process_failover_request(self):
        '''
        Main routine which will process the failover request.
        1. gather basic data set that we need
        2. verify if we can meet this request
        3. Check if external api configured. if yes get the new master to
            promoted.
            Depending upon the source, we will determine the server to be demoted
        4. if not, then determine the server to be promoted and demoted.
            4.1) if origin=GUI:
                    server_to_be_demoted = current_master
                    server_to_be_promoted = any standby server (in case of many
                                                       standby servers  choose
                                                       the one with least
                                                       replication lag)
            4.2) if origin=idbcore:
                    server_to_be_demoted = self._last_master_down
                    server_to_be_promoted = any standby server (in case of many
                                                       standby servers  choose
                                                       the one with least
                                                       replication lag)
        '''
        self._logger.info("Gathering required information.")
        try:
            if not self._read_cluster_config():
                self._logger.error("Problem while gathering required information.")
                self._error_msg = 'Error while initialization: ' + self._error_msg
                return False
        except Exception, ex:
            self._logger.error("Problem while gathering required "\
                                "information: %s" % (ex, ))
            self._logger.error("%s" % (traceback.format_exc(),))
            self._error_msg = 'Error while initialization: ' + self._error_msg
            return

        #
        # Do flip flop verification before doing other veriication
        # becasue external api need to be called only when filp flop rule is verified
        #
        if not self._is_flip_flop_rule_verified():
            self._error_msg = "Last failover took place quite recently." \
                            "(flip-flop rule check failed)"
            self._logger.error("Last failover took place quite " \
                          "recently.(flip-flop rule check failed).")
            return

        # External API is configured then do failover via external API
        if self._failover_type == EXTERNAL_API_FAILOVER:
            if not self._is_failover_enabled():
                self._error_msg = 'Failover is disabled for this cluster.'
                self._logger.error("Failover is disabled for this cluster")
                return False

            self._logger.info("External API is configured. Calling API to do failover.")
            if not self._failover_via_external_api():
                self._error_msg = 'Failed to do failover via external API.'
            else:
                self._cleanup_after_success()
            return

        # now verify this failover request
        self._logger.debug("Verifying failover request.")
        if not self._verify_failover_request():
            self._logger.error("Could not verify this failover " \
                                "request. Operation aborted.")
            self._error_msg = 'Error verifying failover request: ' + self._error_msg
            return

        self._logger.debug("Going to perform failover")


        if not self._find_server_to_be_promoted():
            self._error_msg = 'Failed to find server to be promoted'
            return

        #In case of request from idbcore_force then we will not check demotion_flag
        demotion_flag = self._find_server_to_be_demoted()
        if not self._origin == 'idbcore_force':
            if not demotion_flag:
                self._error_msg = 'Failed to find server to be demoted'
                return

        if not self._perform_role_change():
            self._error_msg += " Failed to perform role change."
            return


        # if everything was successful then clear the error buffer
        self._error_msg = ''
        self._cleanup_after_success()

    def _cleanup_after_success(self):
        # perform cleanup
        self._update_last_failover_time_file()
        #
        # To avoid race condition of failover command from idbcore_force 
        # we are setting ignore attempts to two, it means we will ignore next
        # 2 failover commands from idbcore_force
        #
        global IGNORE_ATTEMPTS_IDBCORE_FORCE
        IGNORE_ATTEMPTS_IDBCORE_FORCE = 2
        return True

class ThreadedTCPRequestHandler(SocketServer.BaseRequestHandler):
    '''
    Incoming request handler - when the "do failover" request comes to this module,
    this class creates a new thread to handle the operation and continues
    to lisen on the same port for other failover requests for other clusters
    '''
    def _parse_request(self, request):
        '''
        Parse the failover request that we arrived making sure that we have
        required values in proper form and also set appropriate variables
        as class members. Return true/false depending on whether everything went
        OK or not.

        # command=do_failover&clusterid=2&origin=idbcore&last_master_down=3&timetowait=30
        '''
        cmd_split_list = request.split('&')

        # set default values
        self._command = ''
        self._cluster = 0
        self._origin = ''
        self._last_master_down = 0
        self._core_failover_timeout = 0
        self._dc_failover = False
        for item in cmd_split_list:
            t = item.split('=')
            if len(t) != 2:
                return False
            if t[0] == 'command':
                self._command = t[1]
            elif t[0] == 'clusterid':
                self._cluster = int(t[1])
            elif t[0] == 'origin':
                self._origin = t[1]
            elif t[0] == 'last_master_down':
                self._last_master_down = int(t[1])
            elif t[0] == 'timetowait':
                self._core_failover_timeout = int(t[1])
            elif t[0] == 'dc':
                self._dc_failover = True if int(t[1]) else False

        # now verify if we have proper request
        if self._cluster <= 0 or self._command != 'do_failover':
            return False

        if self._origin == 'idbcore' and self._last_master_down == 0:
            # if request is from core, last master id is compulsory
            return False
        return True

    def handle(self):
        '''
        This routine is the entry point for this thread. Everythign specific to
        this thread should go in here. We will assume this class to be isolated
        from other request and thus avoid using global variables.
        After receiving the valid request we will send back success response
        instead of waiting for complete request procesing. This change has 
        been done to support failure_timeout feature.
        '''
        global IGNORE_ATTEMPTS_IDBCORE_FORCE
        request = self.request.recv(1024).strip()
        
        _logger.info("Failover: Got request: %s" % request)
        if not self._parse_request(request):
            try:
                _logger.error("Failover: Problem processing request. Please check " \
                                     "the command.")
                self.request.sendall("ERROR: Invalid command")
                return
            except Exception, ex:
                _logger.error("Failed to send response.")
                return

        logger = log.get_logger("failover.cluster_%s" % self._cluster)
        log.add_child_handler(logger, self._cluster, _logger.level)

        logger.info("Got failover request from: %s " % (self._origin))
        pfr_object = ProcessFailover(self._cluster, self._origin,\
                                     self._last_master_down, \
                                     self._core_failover_timeout, \
                                     logger,
                                     dc_failover=self._dc_failover)
        try:

            if pfr_object.get_status_lock():
                self.request.sendall("1")
                try:
                    if self._origin == 'idbcore_force' and IGNORE_ATTEMPTS_IDBCORE_FORCE > 0:
                        IGNORE_ATTEMPTS_IDBCORE_FORCE -= 1
                        error_msg = "Ignoring request as ignore attempts of idbcore force "\
                                    "are in process."
                        pfr_object.set_err_msg(error_msg)
                    else:
                        pfr_object.process_failover_request()
                        error_msg = pfr_object.get_err_msg()
                        if error_msg:
                            pfr_object.send_alert("failover_error", error_message=error_msg,)

                except Exception as ex:
                    error_msg = "Error occured while processing failover request %s" % ex
                    pfr_object.set_err_msg(error_msg)
                finally:
                    pfr_object.release_status_lock()
            else:
                error_msg = "Failed to get status lock. Probably a failover request is " \
                            "already under progress."
                self.request.sendall("0")
                pfr_object.set_err_msg(error_msg)

            err_msg = pfr_object.get_err_msg()
            if err_msg != '':
                logger.error("Request did not complete " \
                              "successfully : %s" % (err_msg))
            else:
                logger.info("Request completed successfully.")

        except Exception, ex:
            logger.error("Request could not be completed" \
                            " successfully. %s" % (ex))
            logger.error("%s" % (traceback.format_exc(),))

class ThreadedTCPServer(SocketServer.ThreadingMixIn, SocketServer.TCPServer):
    BaseServer.allow_reuse_address = True

class FAILOVERDaemon(daemon.Daemon):
    """This class runs FAILOVER as a daemon
    """
    def __init__(self, pid_file):
        self.receiver = None
        super(FAILOVERDaemon, self).__init__(pid_file)

    def _clear_previous_lock_files(self):
        '''
        When service restarts make sure that we delete all lock files this will
        ensure that, service works even if there has been a crash.
        '''
        lock_file_pattern = '/tmp/failover.lock.*'
        fl = glob.glob(lock_file_pattern)
        if len(fl) > 0:
            for f in fl:
                try:
                    os.unlink(f)
                except Exception, ex:
                    _logger.error("Failed to remove previous failover lock file(s).")

    def monitor_subscriber_thread(self):
        '''
        Monitor subscriber thread and if it is stop then start it.
        '''
        is_running = True
        while True:
            try:
                time.sleep(5)
                is_running = self.receiver.isAlive()
                _logger.debug("MonitorThread: Subscriber thread is Running %s" % is_running)
                if not is_running:
                    self.receiver = subscriber()
                    self.receiver.start()
            except Exception, ex:
                _logger.error("MonitorThread: Exception in monitor thread %s" % ex)

    def start_monitor_thread(self):
        '''
        Start a monitor thread that will monitor subscriber thread
        '''
        monitorThread = threading.Thread(target=self.monitor_subscriber_thread,
                                            name="MonitorThread", args=())
        monitorThread.setDaemon(True)
        monitorThread.start()

    def _read_simulation_info(self):
        '''
        Read information related to simulation. This information will be used
        when script is running in simulation mode.
        '''
        try:
            gSimulationInfo['simulation_values'] = map(int, _config.get('simulation', \
                                                                'replication_lag').split(','))
            _logger.debug("Failover: Simulation values are %s" % gSimulationInfo['simulation_values'])
        except:
            pass

    def run(self):
        #
        # Fix  for IDB-5393
        #
        while not os.path.exists('/system/lb.sqlite'):
            _logger.warn("'/system/lb.sqlite' does not exist ")
            time.sleep(1)

        sleep_interval = 5

        # try to determine the api_key
        while True:
            global APIKEY
            APIKEY = util.get_apikey(GLOBAL_LB_DB_FILE)
            if APIKEY != '':
                break
            _logger.error("Failed to determine apikey.")
            time.sleep(sleep_interval)
        _logger.debug("Using apikey: %s" % APIKEY)
        # make sure that all lock files from previous instance are cleared.
        self._clear_previous_lock_files()

        # Start a Subscriber Thread
        try:
            self.receiver = subscriber()
            self.receiver.start()
        except Exception, ex:
            _logger.error("Error in starting subscriber thread %s" % ex)

        # Monitor thread for subscriber thread
        try:
            self.start_monitor_thread()
            # Read simulation lag values if service is started in simulation mode.
            if gSimulationInfo['active']:
                self._read_simulation_info()
        except Exception, ex:
            _logger.error("Error in starting Monitor thread %s" % ex)


        # try to binf the port untill we get hold of it.
        while True:
            try:
                HOST, PORT = "127.0.0.1", 5000
                SocketServer.ThreadingTCPServer.allow_reuse_address = True
                server = SocketServer.ThreadingTCPServer((HOST, PORT), ThreadedTCPRequestHandler)
                _logger.debug("Listening for requests on port 5000")
                server.serve_forever()
                break
            except Exception, ex:
                _logger.error("Service Initialization failed: %s" % ex)
                _logger.error("%s" % (traceback.format_exc(),))
                time.sleep(1)

def main():
    # Go away if you are not root
    if not os.geteuid()==0:
        sys.exit("You must be root to run this script\n")

    # Parse the command line options
    try:
        opts, args = getopt.getopt(sys.argv[1:],
                            'hdvs',
                            ["help", "debug", "version", "simulate"])
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
        elif opt[0] == '-s' or opt[0] == '--simulate':
            gSimulationInfo['active'] = True

    if len(args) > 2:
        _usage('Invalid args %s' % args)

    # Initialize the logger
    log.config_logging()
    global _config
    _config = get_config_parser(FAILOVER_CONF)

    failover_daemon = FAILOVERDaemon('/var/run/failover.pid')

    if args:
        if 'stop' == args[0]:
            _logger.info("****************** FAILOVER stopping ********************")
            failover_daemon.stop()
        elif 'restart' == args[0]:
            _logger.info("***************** FAILOVER restarting *******************")
            failover_daemon.restart()
        else:
            err_msg = "Invalid command %s" % (repr(args[0]),)
            print >> sys.stderr, err_msg
            _logger.error("%s" % (err_msg,))
            sys.exit(2)
        sys.exit(0)

    if _debug:
        _logger.info("************ FAILOVER starting (debug mode)**************")
        failover_daemon.foreground()
    else:
        _logger.info("****************** FAILOVER starting ********************")
        failover_daemon.start()

if __name__ == "__main__":
    main()

