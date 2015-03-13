import getopt
import sys
import json
import os
import socket
from idb import log  
import traceback
from idb.cluster_util import PasswordUtils
import urllib, urllib2
import httplib
import time
import pyodbc
from datetime import datetime

########### Script Constants ##################
SCALEARC_IP_ADDRESS = "127.0.0.1"

MAX_RETRY = 3
CONN_RETRY = 3
SOCKET_TIMEOUT = 1
MSSQL_LOGIN_TIMEOUT = 10
MSSQL_QUERY_TIMEOUT = 5
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

#initialize logging
log.set_logging_prefix("failover")
_logger = log.get_logger("failover")

# UI event message and their code
events_error_code = { "replication_error":74,
             "failover_error":75,
             "mark_offline":80,
           }

# GLobal Variable
APIKEY = ""
###############################################

class LoggerClass(object):
    ''' Customized class for logging
    '''
    def __init__(self):
        self.message = []

    def info(self, msg_str):
        d = (datetime.now()).strftime("%Y-%m-%d %H:%M:%S,%f") 
        self.message.append(d + " " + "INFO: " + msg_str)

    def debug(self, msg_str):
        d = (datetime.now()).strftime("%Y-%m-%d %H:%M:%S,%f") 
        self.message.append(d + " " + "DEBUG: " + msg_str)
    
    def error(self, msg_str):
        d = (datetime.now()).strftime("%Y-%m-%d %H:%M:%S,%f") 
        self.message.append(d + " " + "ERROR: " + msg_str)

    def warn(self, msg_str):
        d = (datetime.now()).strftime("%Y-%m-%d %H:%M:%S,%f") 
        self.message.append(d + " " + "WARN: " + msg_str)


class ProcessFailover(object):
    '''   
    This class supports promotion, demotion of a server
    and verifying the failover request
    '''
    
    def __init__(self, cluster_stats):
        self._root_accnt_info = {}
        self._cluster_stats = json.loads(cluster_stats)
        self._logger = LoggerClass()
        self._parse_cluster_stats()
        self._ip_address = SCALEARC_IP_ADDRESS
        self._base_url = 'https://%s/api/' % self._ip_address
        self._api_max_retry = 3        
        self._api_sub_url = '?apikey=' + APIKEY
        self._server_to_be_promoted = {} # {'server_id':n, 'server_role':''}
        self._server_to_be_demoted = {}
        self._wait_for_sync = True
        self._max_wait_sync_retry = 3
        self._wait_sync_retry_interval = 1 
        self._force_failover = True 
        self._error_msg = ""
        self._alert_msg = ""
        self._abort_failover = False
        self.mark_offline = {}
        self.events = None

    def is_replication_enabled(self, cluster_id, _logger):
        '''
        Check and return true if replication is enabled for this cluster
        otherwise return False.
        '''
        is_rep_enable = False
        try:
            data_dict = {}
            master_base_url_path = '/api/cluster/%s/replication_enabled?apikey=%s' %(cluster_id, APIKEY)
            res = self._exec_url_generic(self._ip_address, master_base_url_path, json.dumps(data_dict), 'GET')
            if res['message'].find('ERROR:') >= 0 or (not res['success']):
                self._logger.error("Something went wrong while fetching replication enable flag " \
                                    "from server: %s" % (res['message']))
                return 
            is_rep_enable = res["data"]["replication_enabled"]
            if is_rep_enable == "on":
                return True
        except Exception, ex:
            _logger.error("Error Occured while getting replication enable check %s" %ex)
        return True 

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

    def _parse_cluster_stats(self):
        '''Function to read only cluster information from /cluster api
        '''
        self._logger.info("Parsing cluster stats where cluster stats is %s" %self._cluster_stats)
        if self._cluster_stats == None:
            self._logger.error("Cluster information is provided")
            return False

        if not self._cluster_stats['success']:
            self._logger.info("Cluster stats contains success is false")
            return False
        
        # Set Platform type from cluster stats
        self._platform_type = self._cluster_stats['data']['iDB_type']

        # now read all information that we got and save it.
        if self._cluster_stats['data']['cluster_started'] == 'yes':
            self._cluster_started = True
        else:
            self._cluster_started = False
      
        # Timeout values 
        self.failover_type = self._cluster_stats["failover_type"]

        # failover type -> 1 = ['idbcore', 'idbcore_force'] and 2 -> "gui"
        self._origin = "idbcore" if self.failover_type == 1 else "gui"

        self._failure_timeout = self._cluster_stats["failure_timeout"]
        self._failover_timeout = self._cluster_stats["failover_timeout"]
        self._replication_type = self._cluster_stats["replication_type"]

        # Cluster Specific values
        self.cluster_id = int(self._cluster_stats["data"]['cluster_id'])
        self.cluster_name = self._cluster_stats["data"]['cluster_name']
        self.cluster_started = True if self._cluster_stats["data"]['cluster_started'] == "yes" else False

        self._servers_list = []
        
        # Read root user info username and password
        self._root_accnt_info['username'] = self._cluster_stats["username"]
        self._root_accnt_info['password'] = self._cluster_stats["password"]

        for item in self._cluster_stats['data']['cluster_servers']:
            d = {}
            d['server_id'] = int(item['server_id'])
            d['server_status'] = int(item['server_status']) # 0-down, # 1-lagging, # 2-healthy
            d['server_role'] = SERVER_ROLE_MAP[item['server_role']]
            d['mark_server_status'] = item['mark_server_status']
            d['server_ip'] = item['server_ip']
            d['server_port'] = item['server_port']
            d['username'] = self._root_accnt_info.get('username', '')
            d['password'] = self._root_accnt_info.get('password', '')
            self._servers_list.append(d.copy())
        return True

    def _find_server_to_be_promoted(self):
        '''
        Find the new primry server.
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

    def _find_standby_to_be_promoted(self):
        '''
        Find the serverid of standby server that will be promoted. We will
        choose the standby server with least replication lag.
        '''
        standby_ids = []
        lagtime_list = self._get_lagtime_of_servers()
        self._logger.info("Servers lagtime list is %s" % (lagtime_list))
        for item in self._servers_list:
            if item['mark_server_status'] == 'online':
                if item['server_role'] == STANDBY_TRAFFIC or item['server_role'] == STANDBY_NO_TRAFFIC:
                    d = {}
                    d['server_id'] = item['server_id']
                    d['lagtime'] = self._get_lagtime_of_server(item['server_id'], lagtime_list)
                    standby_ids.append(d.copy())

        self._standby_ids = standby_ids
        self._logger.info("Standby ids is %s " %self._standby_ids)
        #
        # If replication type is Asynchronus and wait for sync is ON then 
        # do not check for abort failover case else we have to do that.
        #

        server_id, abort_failover = self._find_lowest_lagged_server()
        self._logger.info("Lowest lagged server is %s and abort_failover is %s" %(server_id, abort_failover))
        return server_id, abort_failover
 
    def _get_lagtime_of_server(self, server_id, lagtime_list):
        '''
        Return lag time of serverid. If not found return 0.
        '''
        for item in lagtime_list:
            if item['server_id'] == server_id:
                return item['lagtime']
        return 0

    def _find_lowest_lagged_server(self):
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
        self._logger.debug("Finding lowest lagged standby server")
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
            abort_failover = False
        else:
            server_id = -1
            abort_failover = True

        return server_id, abort_failover
 
    @staticmethod
    def socket_cmd_runner(host = "127.0.0.1", port = 4000,
                          unix_sock = "/tmp/lb_sock",
                          command = "show_stat_status"):
        '''
        Creates a socket and runs the specified command. If unix_sock is
        provided then a unix type socket is opened. However if unix_sock is empty
        then a tcp socket is opened to specified host.
        Finally result of execution is returned to the caller
        '''
        # seconds to wait for server response. can it be in config file
        timeout = 5
        idb_reply_chunk_size = 4096
        sock = None
        error_list_file = "/opt/idb/conf/error_strings.txt"
	server_reply = ""
	error_string = "**Unexpected server reply.**"

        if unix_sock:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            server_addr = unix_sock
        else:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            server_addr = (host, port)

        if sock:
            # try to connect
            try:
                sock.connect(server_addr)
                # strip the command to ensure it's void of spaces
                command.strip()
                sock.sendall(command)

                while True:
                    # server will reply status per cluster so data may be large
                    try:
                        data = sock.recv(idb_reply_chunk_size)
                        if data:
                            server_reply = server_reply + data
                        else:
                            # we could not read anything probably a connection close
                            break
                    except socket.timeout:
                        # a timeout occurred, we wont read any further
                        break
                #
                # load all error strings with their respective codes
                # some commands retrieve multi-line results or non-integer results
                # therefore, it may not be possible to find their meaning in
                # error list file. So avoid looking up error strings in such cases
                #
                try:
                    server_reply = int(server_reply)
                    if server_reply == 0:
                        #
                        # it simply means communication with server was successful no
                        # need to do a lookup
                        #
                        return "SUCCESS"
                    #
                    # server replied a status code (integer) do a lookup in error_list_file
                    # return the equivalent msg
                    #
                    try:
                        fp = open(error_list_file, 'r')
                        for line in fp:
                            l = line.split("|")
                            if server_reply == int(l[0]):
                                error_string = l[1]
                                break
                        error_string = "STATUS: %s|%s" % (server_reply, error_string)
                    except IOError, ex:
                        error_string =  "ERROR: %s"  % (ex, )
                    finally:
                        fp.close()
                except ValueError:
                    if server_reply == "":
                        error_string = "ERROR: Got an empty response"
                    else:
                        # response is not a code we will return it as it is
                        return server_reply
            except socket.error:
                error_string = "ERROR: Failed to connect to remote server"
            finally:
                sock.close()
        else:
            error_string = "ERROR: Could not get a socket"
        return error_string


    def _get_lagtime_of_servers(self):
        '''
        Return a list of dicts {'server_id','lag_time'}.
        '''
        lagtime_list = []
        cmd = 'show_stat_status|%d|' % self.cluster_id
        server_response = ProcessFailover.socket_cmd_runner(unix_sock="/tmp/lb_sock_%s" % self.cluster_id,
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
            lagtime_list.append(d.copy())

        return lagtime_list
 
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
        REVIEW
        '''
        server_id = -1
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

    def _get_current_role_of_server(self, server_id):
        '''
        Get role of server idenitified by server_id by looking up in
        self._servers_list
        '''
        for item in self._servers_list:
            if item['server_id'] == server_id:
                return item['server_role']
        return -1

    def get_apikey(self, _logger=None):
        """This function will be used to get apikey
        """
        apikey = None
        try:
            master_base_url_path = '/api/system/show_api_key'
            data_dict = {}
            data_dict["apikey"] = "show_api_key"
            data_dict["username"] = "root"
            data_dict["password"] = "admin"
            res = self._exec_url_generic(self._ip_address, master_base_url_path, json.dumps(data_dict), 'POST')
            if res['message'].find('ERROR:') >= 0 or (not res['success']):
                self._logger.error("Something went wrong while fetching apikey " \
                                    "from server: %s" % (res['message']))
                return 
            apikey = res["data"]["apikey"]
        except Exception, ex:
            self._error_msg = "Error Occured while getting apikey"
            _logger.error("Error Occured while getting apikey %s" % ex)
        finally:
            return apikey

    def _refresh_servers_info(self):
        '''Function to read only cluster information from /cluster api
        '''
        self._logger.info("Refresing servers information")
        api_url = self._base_url + 'cluster/' + str(self.cluster_id) + self._api_sub_url
        self._cluster_stats = self._get_json_formatted_reply_from_url(api_url)
        if self._cluster_stats == None:
            self._logger.error('API call failed.')
            return False

        if not self._cluster_stats['success']:
            self._logger.error('API called returned failure. (%s)' % self._cluster_stats['message'])
            return False

        # now read all information that we got and save it.
        if self._cluster_stats['data']['cluster_started'] == 'yes':
            self._cluster_started = True
        else:
            self._cluster_started = False

        self._servers_list = []
        for item in self._cluster_stats['data']['cluster_servers']:
            d = {}
            d['server_id'] = int(item['server_id'])
            d['server_status'] = int(item['server_status']) # 0-down, # 1-lagging, # 2-healthy
            d['server_role'] = SERVER_ROLE_MAP[item['server_role']]
            d['mark_server_status'] = item['mark_server_status']
            d['server_ip'] = item['server_ip']
            d['server_port'] = item['server_port']
            d['username'] = self._root_accnt_info.get('username', '')
            d['password'] = self._root_accnt_info.get('password', '')
            self._servers_list.append(d.copy())

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

        if self._origin == "gui" and not self.is_replication_enabled(self.cluster_id, self._logger): 
            self._error_msg = "Replication Monitoring should be ON in Manual Failover."
            self._logger.error("Replicaiton monitoring for cluster has been disabled.")
            return False

        return True

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
            self._refresh_servers_info()
        except Exception, ex:
            self._logger.error("Problem while gathering cluster " \
                            "information: %s" % (ex, ))
            self._logger.error("Error while getting cluster information %s" % (traceback.format_exc(),))
            return False
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
   
    def _get_ip_port_of_server(self, server_id):
        '''
        Get role of server idenitified by server_id by looking up in
        self._servers_list
        '''
        for item in self._servers_list:
            if item['server_id'] == server_id:
                return item['server_ip'], item['server_port']
        return None, None

    def _do_demotion(self):
        master_base_url_path = '/api/cluster/' + str(self.cluster_id) + '/server_role/' + str(self._server_to_be_demoted['server_id'])
        data_dict = {}
        data_dict["apikey"] = APIKEY
        data_dict["server_role"] = REVERSE_SERVER_ROLE_MAP[self._server_to_be_promoted['server_role']]
        data_dict["failover_timeout"] = self._failover_timeout
        res = self._exec_url_generic(self._ip_address, master_base_url_path, json.dumps(data_dict), 'PUT')
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
            self._logger.error("Failed to make http call: %s" % ex)
            result = result
        return result

 
    def _perform_role_change(self):
        '''
        By now we have found server to be promoted and server to be demoted.
        Make api calls to finalize the changes.
        '''
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
                self._logger.error("Demotion is failed and message is %s " %res['message'])
                self._error_msg = res['message']
                return False

            self._logger.info("Demotion logs: %s" % (res))

            #
            # sleep for core failover timeout. After this time interval process 
            # further operations.
            #
            self._logger.info("Sleeping for core failover timeout value %s"\
                                             % (self._failover_timeout))
            time.sleep(self._failover_timeout)

            if self._replication_type == 'async':
                try:
                    if not self._process_async_replication():
                        self._logger.error("Aborting Failover. as process async replication is failed")
                        self._revert_previous_demotion()
                        return False
                except Exception, ex:
                    self._logger.error("Problem while processing " \
                                  "async_replication operations: %s" % (ex))
                    self._revert_previous_demotion()
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

        promoted_server_ip, promoted_server_port = self._get_ip_port_of_server(\
                                                    self._server_to_be_promoted['server_id'])
        # now promote
        self._logger.info("Attempting to promote server: %d having IP %s " \
                            "with new role: %s" % (self._server_to_be_promoted['server_id'],
                                                    promoted_server_ip,
                                                    server_role))
        master_base_url_path = '/api/cluster/' + str(self.cluster_id) + '/server_role/' + str(self._server_to_be_promoted['server_id'])
        data_dict = {}
        data_dict["apikey"] = APIKEY
        data_dict["server_role"] = server_role

        retry = 0
        while retry < MAX_RETRY:
            try:
                res = self._exec_url_generic(self._ip_address, master_base_url_path, json.dumps(data_dict), 'PUT')
                if res['message'].find('ERROR:') >= 0 or (not res['success']):
                    self._logger.error("Something went wrong while promoting"\
                                    " of servers: %s" % (res['message']))
                    retry += 1
                else:
                    self._logger.debug("Promotion logs %s" % (res))
                    break
            except Exception, ex:
                self._logger.error("Something went wrong while promoting"\
                                    " of servers: %s" % (res))
                retry += 1

        if retry >= MAX_RETRY:
            #
            # If promotion failed for whatsover reason, we will reverse replication 
            # changes if required and demotion in first stage.
            #
            self._logger.error("Aborting Failover.")
            self._revert_previous_demotion()
            return False

        return True
    
    def _revert_previous_demotion(self):
        '''
        Revert the demotion in stage1 since our attempt to promote in stage2
        failed. This is needed to keep the system in a consistent state.
        '''
        if self._server_to_be_demoted.get('server_id'):
            #
            # we need to sleep for one second before executing
            # other API.
            #
            time.sleep(1)
            self._logger.warn("Reverting demotion of last stage.")
            self._logger.debug("Attempting to restore server state: %d with role: %s" \
                          % (self._server_to_be_demoted['server_id'], \
                             REVERSE_SERVER_ROLE_MAP[self._server_to_be_demoted['server_role']]))
            master_base_url_path = '/api/cluster/' + str(self.cluster_id) + '/server_role/' + str(self._server_to_be_demoted['server_id'])

            data_dict = {}
            data_dict["apikey"] = APIKEY
            data_dict["server_role"] = REVERSE_SERVER_ROLE_MAP[self._server_to_be_demoted['server_role']]
            res = self._exec_url_generic(self._ip_address, master_base_url_path, json.dumps(data_dict), 'PUT')

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
        self._logger.warn("Reverting promotion of last stage.")
        self._logger.debug("Attempting to restore server state: %d with role: %s" \
                      % (self._server_to_be_promoted['server_id'], \
                         REVERSE_SERVER_ROLE_MAP[self._server_to_be_promoted['server_role']]))
        master_base_url_path = '/api/cluster/' + str(self.cluster_id) + '/server_role/' + str(self._server_to_be_promoted['server_id'])
        data_dict = {}
        data_dict["apikey"] = APIKEY
        data_dict["server_role"] = REVERSE_SERVER_ROLE_MAP[self._server_to_be_promoted['server_role']]
        res = self._exec_url_generic(self._ip_address, master_base_url_path, json.dumps(data_dict), 'PUT')
        if res['message'].find('ERROR:') >= 0 or (not res['success']):
            self._logger.error("Something went wrong while restoring " \
                                "server state: %s" % (res['message']))
        self._logger.debug("Reverting Promotion Logs: %s" % (res))
    
    def _is_wait_retry_required(self, lagtime_list, new_promoted_servers):
        '''
            Check whether retry for wait for sync is required or not
        '''
        zero_lagtime = False
        new_server_id = -1
        for server in self._standby_ids:
            server['lagtime'] = self._get_lagtime_of_server(server['server_id'],
                                                            lagtime_list)
            server_ip, server_port = self._get_ip_port_of_server(server['server_id'])
            if server['lagtime'] == 0 and server_ip in new_promoted_servers:
                zero_lagtime = True
                new_server_id = server['server_id']
        #
        # If any server lagtimg is zero then we will break 
        # from wait for sync loop.
        #
        if zero_lagtime:
            self._zero_lagtime_server = True
            self._logger.info("Found a server with zero replication lag")
            return False, new_server_id

        return True, new_server_id

    def do_wait_for_sync(self, new_promoted_servers):
        ''' Wait for sync 
        '''
        if self._wait_for_sync:
            self._logger.info("Wait for sync check is started")
            # we ensure that the server demoted and the one to be promoted
            # are in sync
            retry = 0
            self._zero_lagtime_server = False
            new_server_id = -1
            while retry < self._max_wait_sync_retry:
                self._logger.info("Retrying for wait for sync where current retry is %s"\
                                  " and max_retry is %s" % (retry, self._max_wait_sync_retry))
                lagtime_list = self._get_lagtime_of_servers()
                self._logger.debug("Servers lagtime list is %s" \
                                   % (lagtime_list))
                do_wait, new_server_id = self._is_wait_retry_required(lagtime_list, new_promoted_servers)
                self._logger.info("Wait retry required output is: new_server_id %s and do_wait %s"\
                                  %(new_server_id, do_wait))
                if do_wait:
                    self._logger.info("Wait for sync no more required." \
                                        " Breaking from loop.")
                    break

                retry = retry + 1
                self._logger.info("Sleeping for wait_sync_retry_interval %s" %self._wait_sync_retry_interval)
                time.sleep(self._wait_sync_retry_interval)

            if self._zero_lagtime_server and new_server_id > 0:
                self._logger.info("Zero lag time server found whose id is %s" %new_server_id)
                server_id, abort_failover = new_server_id, False
            elif self._force_failover:
                self._logger.info("Could not find zero lag time server now trying force failover")
                server_id, abort_failover = self._find_lowest_lagged_server()
                server_ip, server_port = self._get_ip_port_of_server(server_id)
                if server_ip not in new_promoted_servers:
                    abort_failover = True
            else:
                abort_failover = True

            if abort_failover:
                msg = "Aborting Failover as force failover is OFF or Could not found out the server"
                self._logger.error(msg)
                return False

            if server_id == -1:
                msg = "This case should not occur, if it occurs "\
                               "becasue of some error. Abort Failover and revert last demotion"
                self._logger.error(msg)
                return False

            current_role = self._get_current_role_of_server(server_id)
            if current_role == -1:
                msg = "Failed to determine current role of "\
                                  "server after wait for sync. Aborting Failover and reverting"\
                                  " last demotion"
                self._logger.error(msg)
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
                    return False
        return True

    def _change_mark_server_status(self, server_ip, online=False):
        retry = 0
        while retry < MAX_RETRY:
            try:
                master_base_url_path = '/api/cluster/%s/server/%s/mark_server_status' % (str(self.cluster_id),
                                                    str(self._server_to_be_demoted['server_id']))

                data_dict = {}
                data_dict["apikey"] = APIKEY
                data_dict["mark_server_status"] = 'offline' if not online else 'online'
                data_dict["timetowait"] = 0

                res = self._exec_url_generic(self._ip_address, master_base_url_path, json.dumps(data_dict), 'PUT')
                self._logger.info("Response of marking server offline %s: %s" % (server_ip, res))
                if res['message'].find('ERROR:') >= 0 or (not res['success']):
                    self._logger.error("Something went wrong while marking server "\
                                    " offline: %s" % (res['message']))
                    retry += 1
                    time.sleep(0.5)
                else:
                    self._logger.info("Sucessfully changes server %s mark server status" % server_ip)
                    self.send_alert("mark_offline", server_ip=server_ip)
                    break
            except Exception, ex:
                self._logger.error("Got an error %s while marking server %s offline. Retrying ..." % (ex, server_ip))
                retry += 1
                time.sleep(0.5)

        if retry >= MAX_RETRY:
            self._logger.error("Failed to marke Server %s offline after all retry attempts." % (server_ip))
 
    def _process_async_replication(self):
        '''
        In case of replication set to Asynchronus we have more things to do
        before we promote master. We do those here.
        '''
        self._logger.info("MSSQL replication checks started...")
        old_server_ip, old_server_port = self._get_ip_port_of_server(self._server_to_be_demoted['server_id'])
        new_server_ip, new_server_port = self._get_ip_port_of_server(self._server_to_be_promoted['server_id'])
        self.trans_p2p_failover = transaction_peer2peer_autofailover(self.cluster_id, 
                                             '%s:%s' % (old_server_ip, old_server_port),
                                             '%s:%s' % (new_server_ip, new_server_port),
                                             self._servers_list, self._root_accnt_info,
                                             self._wait_for_sync, self._max_wait_sync_retry,
                                             self._wait_sync_retry_interval, self._force_failover, self._origin,
                                             log=self._logger)
        success, abort_failover, error_msg, new_promoted_list = self.trans_p2p_failover.detect_topology() 
        
        # If there is any error_msg that will raised as an event as well mail alert will be sent
        if error_msg:
            self._error_msg = 'Cluster %s, %s' % (self._cluster_stats['data']['cluster_name'], error_msg)
            self._logger.error(self._error_msg)
            self.send_alert("replication_error", error_message=error_msg,)

        # If abort failover is triggered we need to revert back to older older state.
        if abort_failover:
            msg = "Aborting Failover as error occured while changing Detecting Active-Active Replication: %s" %error_msg
            self._logger.error(msg)
            return False

        if not self.do_wait_for_sync(new_promoted_list):
            return False

        return True

    def find_server_for_marking_offline(self):
        ''' Find the server for marking offline
            This is for Autofailover case only
        '''
        mark_offline = {} 
        if self._origin == 'idbcore' and self._server_to_be_demoted.get('server_id'):
            for server in self._servers_list:
                if server['server_id'] == self._server_to_be_demoted.get('server_id') and \
                                          server['server_status'] == SERVER_HEALTHY and \
                                          server['server_role'] == READ_WRITE and \
                                          server['mark_server_status'] == 'online':
                    mark_offline[server['server_ip']] = "Mark the Server Offline"     
        
        return mark_offline

    def send_alert(self, msg_header, server_ip=None, server_id=0, error_message=None):
        ''' Send alert to alert_engine service
        '''
        msg = {'ident': self.cluster_id, 'cid': self.cluster_id, 'subject': 'Failover', 'message': ''}
        msg_dict = {
                   "mark_offline": "Sucessfully mark server %s status offline for cluster id %s " % (server_ip, self.cluster_id), 
                   "replication_error": error_message,
                   "failover_error": 'Failover for Cluster %s failed, %s' % (self._cluster_stats['data']['cluster_name'], error_message)
                   }
        
        message = msg_dict[msg_header]
        result = self.send_event(message, int(msg_header), clusterid=self.cluster_id, serverid=server_id)
        self._logger.info("Response from API for sending events %s" % (result))

    def send_event(self, message, event_header, priority = '1', clusterid='', serverid=0):
        """This method will be used to send the events
            :param message: message to be send in the event_type.
            :param event_type: Event type eg 11.
            :param priority: Priority of the event to be send.

        """
        event_type = events_error_code[event_header]
        args_dict = dict(apikey = APIKEY,
                            message = message,
                            type = event_type,
                            clusterid=clusterid,
                            serverid=serverid,
                            priority = priority)
        master_base_url_path = '/api/events'
        res = self._exec_url_generic(self._ip_address, master_base_url_path, json.dumps(args_dict), 'POST')
        return res

class transaction_peer2peer_autofailover(object):
    '''
    This class supports Transaction and Peer to Peer based
    MSSQL Failover
    '''
    
    def __init__(self, cluster_id, old_master, new_master, servers_list, root_accnt_info,\
                 wait_for_sync, max_wait_sync_retry, wait_sync_retry_interval, force_failover, origin, log=None):
        ''' Initialize the vaiables
        '''
        self.old_master_ip, self.old_master_port = old_master.split(":")
        self.new_master_ip, self.new_master_port = new_master.split(":")
        self.servers_list = servers_list
        self.root_account_info = root_accnt_info
        self.wait_for_sync = wait_for_sync
        self.max_wait_sync_retry = max_wait_sync_retry
        self.wait_sync_retry_interval = wait_sync_retry_interval
        self.force_failover = force_failover
        self.server_ip_name_mapping = {}
        self.server_name_ip_mapping = {}
        self.server_name_publication_info = {}
        self._origin = origin
        self._logger = log

    def get_servers_publishers_info(self):
        '''
        Executing query
        '''
        servers_info = {'server_name': '', 'publisher': '',
                        'publication': '', 'publisher_db': '',
                        'subscriber': [],
                       }
        for server in self.servers_list:
            try:
                conn = cursor = None
                conn = self._create_connection(server)
                if not conn:
                    self.server_name_publication_info[server['server_ip']] = servers_info 
                    continue

                cursor = conn.cursor()
                # select database
                query = "use distribution;"
                cursor.execute(query)
            
                #select servername
                server_name = self.find_server_name(cursor)
                self._logger.info("Result of the query for servername is %s" %server_name)
                if not server_name:
                    self.server_name_publication_info[server['server_ip']] = servers_info 
                    continue
                self.server_name_ip_mapping[server_name] = server['server_ip']
            
                # select publisher name
                publisher = self.find_publisher_name(cursor)
                self._logger.info("Result of the query for publishername is %s" %publisher)
                if not publisher:
                    self.server_name_publication_info[server['server_ip']] = servers_info 
                    continue
            
                #select publisher_db name and publication name
                publisher_db, publication = self.find_publisher_db_name(cursor, publisher)
                self._logger.info("Result of the query for publisherdb and publication is %s, %s" %(publisher_db, publication))
                if not publisher_db or  not publication:
                    self.server_name_publication_info[server['server_ip']] = servers_info 
                    continue
            
                # select subscribers names
                subscriber_list = self.get_subscriber_list(cursor, publisher, publisher_db, publication)
                self._logger.info("Result of the query for subscriber_list is %s" %subscriber_list)
                if not subscriber_list:
                    self.server_name_publication_info[server['server_ip']] = servers_info 
                    continue
            
                self.server_name_publication_info[server['server_ip']] = {'server_name': server_name,
                                                                  'publisher':publisher,
                                                                  'publication': publication,
                                                                  'publisher_db': publisher_db,
                                                                  'subscriber':subscriber_list,
                                                                 }
            except Exception, ex:
                self._logger.error("Exception while fetching publishers and subscribers info for serverip %s and exception is %s"\
                                   %(server['server_ip'], ex)) 
            finally: 
                self.close_connection(cursor, conn)
   

    def get_subscriber_list(self, cursor, publisher, publisher_db, publication):
        # Get subscriber list
        try: 
            subscriber_list = []
            query = "exec sp_replmonitorhelpsubscription @publisher= '%s', \
                 @publisher_db = '%s', @publication = '%s',\
                 @publication_type = 0;" %(publisher, publisher_db, publication)
            self._logger.info("Query executed for subscriber list %s" %query)
            cursor.execute(query)
            for subscriber_info in cursor.fetchall():
                subscriber_list.append(subscriber_info[2])
        except Exception, ex:
            self._logger.error("Exception while calculating subscriber list %s" %ex)
        return subscriber_list

    def find_server_name(self, cursor):
        #select servername
        try:
            server_name = ''
            query = "select @@SERVERNAME as servername;"
            self._logger.info("Query executed for servername %s" %query)
            cursor.execute(query)
            for name in cursor.fetchone():
                server_name = name
        except Exception, ex:
            self._logger.error("Exception while calculating server name %s" %ex)
        return server_name

    def find_publisher_name(self, cursor):
        # Find Publisher name
        try:
            publisher = ''
            query = "exec sp_replmonitorhelppublisher;"
            self._logger.info("Query executed for publisher name %s" %query)
            cursor.execute(query)
            for pubs_info in cursor.fetchall():
                publisher = pubs_info[0]
        except Exception, ex:
            self._logger.error("Exception while calculating publisher name %s" %ex)
        return publisher

    def find_publisher_db_name(self, cursor, publisher):
        # Find out publisher db and publication name
        try:
            publisher_db = ''
            publication = ''    
            query = "exec sp_replmonitorhelppublication @publisher='%s'" %publisher 
            self._logger.info("Query executed for publisher db and publication %s" %query)
            cursor.execute(query)
            for publication_info in cursor.fetchall():
                publisher_db = publication_info[0]
                publication = publication_info[1]
        except Exception, ex: 
            self._logger.error("Exception while calculating publisher db and publication name %s" %ex)
        return publisher_db, publication

    def close_connection(self, cursor, connection):
        try:
            if cursor:
                cursor.close()
            if connection:
                connection.close()
        except Exception, ex:
            self._logger.error("Exception while closing cursor and connection %s"%ex)

    def find_new_promoted_server(self, old_server_name, old_sublist):
        self._logger.info("Finding Server Name %s in Subscribe list of sublist %s" \
                          %(old_server_name, old_sublist)) 
        new_list = []
        for server_name in old_sublist:
            if server_name not in self.server_name_ip_mapping.keys():
                self._logger.info("Servername %s not in configured servers %s, so not considering for promotion" \
                                  %(server_name, self.server_name_ip_mapping.keys()))
                continue
            # Find out subscriber list of server_name
            server_ip = self.server_name_ip_mapping[server_name]
            sublist_of_element = self.server_name_publication_info[server_ip]['subscriber']
            self._logger.info("Subscriber list %s of server_name is %s" %(sublist_of_element, server_name))

            # check old server name present in subscriber sublist
            if sublist_of_element:
                if old_server_name in sublist_of_element:
                    # Select that server for promotion
                    self._logger.info("Old Server Name %s is present in the sublist of server_name %s"\
                                      %(old_server_name, server_name))
                    new_list.append(server_ip)
                    continue
                else:
                    # Ignoring that server for promotion
                    self._logger.info("Old Server Name %s is not present in the sublist of server_name %s,"\
                                      " so ignoring the server for promotion"\
                                      %(old_server_name, server_name))
            else:
                self._logger.info("Subscriber list is empty for the server %s" %server_name)
        return new_list

    def find_new_server_from_publisher_info(self, old_master_server_name):
        ''' Find out all the servers whom replication towards old_master server
        '''
        new_list = []
        for server_name, publisher_info in self.server_name_publication_info.iteritems():
            # Find out subscriber list of server_name
            subs_list = publisher_info['subscriber']
            self._logger.info("Subscriber list %s of server_name is %s" %(subs_list, server_name))

            # check old server name present in subscriber sublist
            if subs_list:
                if old_master_server_name in subs_list:
                    # Select that server for promotion
                    server_ip = self.server_name_ip_mapping[server_name]
                    self._logger.info("Old Server Name %s is present in the sublist of server_name %s and IP is %s"\
                                      %(old_master_server_name, server_name, server_ip))
                    new_list.append(server_ip)
                    continue
                else:
                    # Ignoring that server for promotion
                    self._logger.info("Old Server Name %s is not present in the sublist of server_name %s,"\
                                      " so ignoring the server for promotion"\
                                      %(old_master_server_name, server_name))
            else:
                self._logger.info("Subscriber list is empty for the server %s" %server_name)
        return new_list


    def detect_topology(self):
        ''' This Function detect what topology changes we need to do 
        '''
        success = True
        error_msg = ""
        abort_failover = False
        new_promoted_list = []

        self._logger.info("Starting Failover Using Transaction/P2P based failover")
        
        # Get All servers publishers info  
        self.get_servers_publishers_info()
        self._logger.info("Got servers publishers info %s" %self.server_name_publication_info)
       
        # Get Old Master subscriber list
        old_master_sub_list = self.server_name_publication_info[self.old_master_ip]['subscriber']
        old_master_server_name = self.server_name_publication_info[self.old_master_ip]['server_name']
        
        #TODO if primary server is down
        if len(old_master_sub_list) == 0:
            if self._origin == "gui":
                self._logger.info("Old Master Subscriber list is empty in Manual Failover Request")
                new_promoted_list = []
            elif self._origin == "idbcore":
                self._logger.info("Finding new servers subscriber list when primary server is down")
                # Find out all the new server from publishers info
                new_promoted_list = self.find_new_server_from_publisher_info(old_master_server_name)
        else:
            self._logger.info("Old Master Subscriber list is %s and Server name is %s" \
                              %(old_master_sub_list, old_master_server_name))
            # Find out all the server in old_master_sub_list which are in MM replication
            new_promoted_list = self.find_new_promoted_server(old_master_server_name, old_master_sub_list)

        if len(new_promoted_list) == 0:
            success = False
            abort_failover = True
            error_msg = "Could not find out server with Master-Master Replication"
            self._logger.info("New Servers list is empty could not find out server for promotion. So Aborting...")
            return success, abort_failover, error_msg, new_promoted_list
            
        self._logger.info("Servers list %s those can be promoted as new master server" %new_promoted_list)
        return success, abort_failover, error_msg, new_promoted_list

    def _create_connection(self, server_details):
        root_account_info = {'username': server_details['username'], 'password': server_details['password']}
        conn_str = self.get_connection_string(server_details['server_ip'], \
                                  server_details['server_port'], root_account_info)
        conn = self.get_sqlserver_connection(server_details['server_ip'], \
                             int(server_details['server_port']), conn_str, self._logger)
        return conn
    
    def get_connection_string(self, server_ip, server_port, root_account):
        return "DRIVER={FreeTDS};SERVER=%s;PORT=%s;UID=%s;PWD=%s;TDS_VERSION=8.0;" \
                    % (server_ip, str(server_port), root_account['username'], root_account['password'])

    def get_sqlserver_connection(self, server_ip, port, conn_str, _logger, max_retry=CONN_RETRY):
        retry = 0
        conn = None
        while retry < max_retry:
            try:
                test_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                test_socket.settimeout(SOCKET_TIMEOUT)
                test_socket.connect((server_ip, port))
            except socket.error:
                errno, errstr = sys.exc_info()[:2]
                if errno == socket.timeout:
                    self._logger.error("Timeout has occured %s " % (errstr))
                else:
                    self._logger.error("Error occured while creating socket connections %s " % (errstr))
                retry = retry + 1
                if retry >= max_retry:
                    self._logger.error("In Socket Failed to make connection with socket " \
                                  "Max retry limit reached:" )
                    return conn
                else:
                    self._logger.error("Retrying for socket connection ")
                    continue
            except Exception, ex:
                self._logger.info("Some Exception While using socket %s" % (ex))
                retry = retry + 1
                if retry >= max_retry:
                    self._logger.error("In Exception Failed to make connection with socket " \
                                  "Max retry limit reached:")
                    return conn
                else:
                    self._logger.error("Retrying for socket connection ")
            finally:
                if test_socket:
                    test_socket.close()
 
            try:
                conn = pyodbc.connect(conn_str, autocommit=True, timeout=MSSQL_LOGIN_TIMEOUT)
                break
            except Exception, ex:
                retry = retry + 1
                self._logger.info("Was Not Able To Connect : %s" %ex)
        if conn:
            self._logger.debug("setting query timeout to %s for ip %s"
                              % (MSSQL_QUERY_TIMEOUT, server_ip))
            conn.timeout = MSSQL_QUERY_TIMEOUT
        return conn

def main():

    ''' This is the main function, Script starts from here
    '''
    #Read option from command 
    cluster_stats = None
    try:
        opts, args = getopt.getopt(sys.argv[1:],'hc:', ["help", "data="])
    except Exception, ex:
        return json.dumps({"success": False, "message": "Error in Command arguments and Exception is %s" %ex})

    for opt in opts:
        if opt[0] == '-c' or opt[0] == '--data':
            cluster_stats = opt[1]

    # Failover object is initiated
    global APIKEY
    process_failover = ProcessFailover(cluster_stats)
    
    APIKEY = process_failover.get_apikey(process_failover._logger)
    process_failover._logger.info("APIKey is %s" %APIKEY)

    if not APIKEY:
        process_failover._logger.error("Could not find out API Key from ScaleArc API")
        if process_failover._error_msg:
            process_failover.send_alert("failover_error", error_message=process_failover._error_msg,)
        return json.dumps({"success": False, "message": "Error in finding API key from Scalearc API"})
    
    # Verify Failover Request    
    if not process_failover._verify_failover_request():
        process_failover._logger.error("Could not verify this failover " \
                                       "request. Operation aborted.")
        if process_failover._error_msg:
            process_failover.send_alert("failover_error", error_message=\
                            'Error verifying failover request: ' + process_failover._error_msg)
        return json.dumps({"success": False, "message": process_failover._logger.message})

    # Going to perform failover
    process_failover._logger.info("Going to perform failover")

    # Finding server to be promoted
    if not process_failover._find_server_to_be_promoted():
        process_failover._logger.error( 'Failed to find server to be promoted')
        process_failover._error_msg = 'Failed to find server to be promoted'
        process_failover.send_alert("failover_error", error_message = process_failover._error_msg)
        return json.dumps({"success": False, "message": process_failover._logger.message})

    # Finding server to be demoted
    if not process_failover._find_server_to_be_demoted():
        process_failover._logger.error('Failed to find server to be demoted')
        process_failover._error_msg = 'Failed to find server to be demoted'
        process_failover.send_alert("failover_error", error_message = process_failover._error_msg)
        return json.dumps({"success": False, "message": process_failover._logger.message})

    # Find out servers for marking offline
    process_failover.mark_offline = process_failover.find_server_for_marking_offline()
    if process_failover.mark_offline:
        process_failover._logger.info("Servers to be marked offline is %s" %process_failover.mark_offline)

    # Performing Role Change
    if not process_failover._perform_role_change():
        process_failover._logger.error(" Failed to perform role change.")
        if process_failover._error_msg:
            process_failover.send_alert("failover_error", error_message=process_failover._error_msg)
        return json.dumps({"success": False, "message": process_failover._logger.message})

    #Marking servers offline
    for server_ip, msg in process_failover.mark_offline.iteritems():
        process_failover._logger.info("Marking server %s offline as %s" % (server_ip, msg))
        process_failover._change_mark_server_status(server_ip)

    return json.dumps({"success": True, "message": process_failover._logger.message})

if __name__ == '__main__':
    res = main()
    res = json.loads(res)   
    for msg in res["message"]:
        print msg
