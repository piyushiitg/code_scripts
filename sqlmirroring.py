import datetime
from idb import log, util, cluster_util, events
import time, sqlite3
import socket
import pyodbc
import sys
import traceback
from copy import deepcopy 
CONN_RETRY = 3
SOCKET_TIMEOUT = 1
mssql_login_timeout = 10
mssql_query_timeout = 10
APIKEY = ''
GLOBAL_LB_DB_FILE = "/system/lb.sqlite"
LB_FILE_PATH = "/system/lb_%s.sqlite"
# server health definitions
SERVER_DOWN = 0
SERVER_LAGGING = 1
SERVER_HEALTHY = 2
# Mirroring ROle Information
MIRRORING_ROLE = {1 : 'PRINCIPAL', 2: 'MIRROR'}
MIRRORING_SAFETY_LEVEL = {0: 'UNKNOWN', 1: 'ASYNC', 2:'SYNC', 'NULL': 'Not Connected'}
MIRRORING_WITNESS_STATE = {0: 'UNKNOWN', 1: 'CONNECTED', 2: 'DISCONNECTED', 'NULL': 'NO WITNESS'}

class MssqlAutoFailover(object):
    ''' Factory class that will call appropriate kind of Failover
    '''
    def __init__(self):
        self.failover_obj = None
        self.topology = None
 
    def detect_topology(self):
        return 'SQLMirror'
     
    def process_failover(self, cid, old_master, new_master, servers_info, root_account_info, wait_for_sync, \
                         max_wait_sync_retry, wait_sync_retry_interval, force_failover, log):
        self.topology = self.detect_topology()
        if self.topology == 'SQLMirror':
            self.failover_obj = SqlMirrorFailover(cid, old_master, new_master, servers_info,\
                                          root_account_info, log, self.topology, wait_for_sync,\
                                          max_wait_sync_retry, wait_sync_retry_interval, force_failover)
            return self.failover_obj.do_failover()

class ConnectionData(object):
    ''' Helper Class to make connection either from sqlite or sql server
    '''
    @staticmethod
    def get_connection_string(server_ip, server_port, root_account):
        return "DRIVER={FreeTDS};SERVER=%s;PORT=%s;UID=%s;PWD=%s;TDS_VERSION=8.0;" \
                    % (server_ip, str(server_port), root_account['username'], root_account['password'])

    @staticmethod
    def get_sqlserver_connection(server_ip, port, conn_str, _logger, max_retry=CONN_RETRY):
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
                    _logger.error("Timeout has occured %s " % (errstr))
                else:
                    _logger.error("Error occured while creating socket connections %s " % (errstr))
                retry = retry + 1
                if retry >= max_retry:
                    _logger.error("In Socket Failed to make connection with socket " \
                                  "Max retry limit reached:" )
                    return conn
                else:
                    _logger.error("Retrying for socket connection ")
                    continue
            except Exception, ex:
                _logger.info("Some Exception While using socket %s" % (ex))
                retry = retry + 1
                if retry >= max_retry:
                    _logger.error("In Exception Failed to make connection with socket " \
                                  "Max retry limit reached:")
                    return conn
                else:
                    _logger.error("Retrying for socket connection ")
            finally:
                if test_socket:
                    test_socket.close()
 
            try:
                conn = pyodbc.connect(conn_str, autocommit=True, timeout=mssql_login_timeout)
                break
            except Exception, ex:
                retry = retry + 1
                _logger.info("Was Not Able To Connect : %s" %ex)
        if conn:
            _logger.debug("setting query timeout to %s for ip %s"
                              % (mssql_query_timeout, server_ip))
            conn.timeout = mssql_query_timeout
        return conn

class SqlMirrorFailover(object):
    ''' Server class
    '''
    def __init__(self, cid, old_master, new_master, servers, root_account_info, log, topology,\
                       wait_for_sync, max_wait_sync_retry, wait_sync_retry_interval, force_failover):
       self.cluster_id = cid
       self.old_master_ip, self.old_master_port = old_master.split(":")
       self.new_master_ip, self.new_master_port = new_master.split(":")
       self.log = log
       self.topology = topology
       self.servers_info = servers
       self.root_account_info = root_account_info
       self.principal_server_health = None
       self.mirror_server_health = None
       self.db_list = []
       self.selected_dbids = []
       self.successful_dbids = []
       self.sync_witness_dbids = []
       self.recovery_rate_dict = {}
       self.database_info = {}
       self.dbid_name_dict= {}
       self.connection_old_master = None
       self.connection_new_master = None
       self.error_msg = ''
       self._wait_for_sync = wait_for_sync
       self._max_wait_sync_retry = max_wait_sync_retry
       self._wait_sync_retry_interval = wait_sync_retry_interval
       self._force_failover = force_failover

    def find_database_ids(self):
        ''' Find database ids and their namse
        '''
        query = "select name, database_id from sys.databases"
        self.log.info("Query for finding databases ids and their names from sys.databases is %s" %query) 
        id_name_dict = {}
        try:
            if self.principal_server_health:
                connection = self.get_primary_server_connection()
            else:
                connection = self.get_secondary_server_connection()
            if not connection:
                return
            cursor = connection.cursor()
            cursor.execute(query)
            for name, database_id in cursor.fetchall():
                id_name_dict[database_id] = name 
            cursor.close()
            return id_name_dict
        except Exception, ex:
            self.log.error("Exception while fetching database ids from sqlserver %s" %ex)
            return id_name_dict

    def get_database_mirroring_info(self, id_name_dict, check_mirror=False):
        try:
            query1 = "use msdb;"
            # This is for checking mirror_role on secondary server
            if check_mirror:
                query2 = "select database_id, mirroring_role, mirroring_safety_level,"\
                         " mirroring_witness_state from sys.database_mirroring"\
                         " where database_id in (%s)" %(', '.join(str(x) for x in id_name_dict.keys()))
                connection = self.get_secondary_server_connection()
                self.log.info("Query for finding database info %s executed on secondary server "\
                              "where check_mirror is %s" %(query2, check_mirror))
            else:
                if self.principal_server_health:
                    #Selecting Principal server only
                    query2 = "select database_id, mirroring_role, mirroring_safety_level,"\
                             " mirroring_witness_state from sys.database_mirroring"\
                             " where mirroring_role = 1" 
                    connection = self.get_primary_server_connection() 
                    self.log.info("Query for finding database info %s executed on primary server" %(query2))
                else:
                    # Selecting Mirror Server Only
                    query2 = "select database_id, mirroring_role, mirroring_safety_level,"\
                             " mirroring_witness_state from sys.database_mirroring"\
                             " where mirroring_role = 2" 
                    connection = self.get_secondary_server_connection()
                    self.log.info("Query for finding database info %s executed on secondary server" %(query2))
 
            tmp_dict = {"name": "", "mirroring_role": "", "mirroring_safety_level":"",
                    "mirroring_witness_state":"",}

            db_mirroring_info = {}
            if not connection:
                self.log.info("Could not found the connection")
                return db_mirroring_info

            cursor = connection.cursor()
            cursor.execute(query1)
            cursor.execute(query2)
            for database_id, mirroring_role, mirroring_safety_level, mirroring_witness_state in cursor.fetchall():
                db_dict = deepcopy(tmp_dict)
                db_dict["name"] = id_name_dict[database_id]
                db_dict["mirroring_role"] = mirroring_role
                db_dict["mirroring_safety_level"] = mirroring_safety_level
                db_dict["mirroring_witness_state"] = mirroring_witness_state
                db_mirroring_info[database_id] = db_dict
            cursor.close()
        except Exception, ex:
            self.log.error("Exception while fetching database ids from sqlserver %s" %ex)
        return db_mirroring_info

    def get_primary_server_connection(self):
        if not self.connection_old_master:
            conn_str = ConnectionData.get_connection_string(self.old_master_ip, self.old_master_port, self.root_account_info)
            conn = ConnectionData.get_sqlserver_connection(self.old_master_ip, int(self.old_master_port), conn_str, self.log)
            if conn:
                self.connection_old_master = conn
                return self.connection_old_master
        else:
            return self.connection_old_master
    
    def get_secondary_server_connection(self):
        if not self.connection_new_master:
            conn_str = ConnectionData.get_connection_string(self.new_master_ip, self.new_master_port, self.root_account_info)
            conn = ConnectionData.get_sqlserver_connection(self.new_master_ip, int(self.new_master_port), conn_str, self.log)
            if conn:
                self.connection_new_master = conn
                return self.connection_new_master
        else:
            return self.connection_new_master

    def check_principal_server_health(self):
        '''
        check old master server is UP or Down
        '''
        for server in self.servers_info:
            if server['server_ip'] == self.old_master_ip and str(server['server_port']) == self.old_master_port:
                if server['server_status'] == SERVER_HEALTHY:
                    self.log.debug("Server %s health is UP" %server)
                    return True
                else:
                    self.log.debug("Server %s health is Down" %server)
                    return False
            
        self.log.info("Not found the Server %s so health is Down" % self.old_master_ip)
        return False    

    def check_mirror_server_health(self):
        '''
        check old master server is UP or Down
        '''
        for server in self.servers_info:
            if server['server_ip'] == self.new_master_ip and str(server['server_port']) == self.new_master_port:
                if server['server_status'] == SERVER_HEALTHY:
                    self.log.debug("Server %s health is UP" %server)
                    return True
                else:
                    self.log.debug("Server %s health is Down" %server)
                    return False
        self.log.info("Not found the Server %s so health is Down" % self.old_master_ip)
        return False    

    def get_dbids_for_replication_change(self):
        '''# If principal server up than select sync + principal/ async+ principal server
        # If principal server down than select all the servers
        # mirroring_role-->(Principal->1, Mirror->2)
        # mirroring_safety_level-->sync->2/async->1/unkown->0/NULL->Not connected
        # mirroring_witness_state --> connected->1/disconnected->2/0->unknown/NULL->no witness
        '''
        dbids = []
        for database_id, mirror_info in self.database_info.iteritems():
            if self.principal_server_health:
                if mirror_info["mirroring_role"] == 1: # 1 means PRINCIPAL for Async/Sync on that server
                    if mirror_info['mirroring_safety_level'] == 2: # For Sync
                        dbids.append(database_id)
                    else:
                        # For Async server no operation
                        self.log.info("Not Selecting database id %s, ITS Async server with Principal" %(database_id))
                        continue
                else:
                    self.log.info("Not Selecting database id %s, ITS Mirror server on Current server" %(database_id))
            else:
                if mirror_info['mirroring_role'] == 2: # Picking UP Mirror Server on Secondary server
                    if mirror_info['mirroring_safety_level'] == 2:
                        if mirror_info['mirroring_witness_state'] == 1:
                            self.log.info("Not Selecting database id %s, ITS Sync server with WItness Server Present" %(database_id))
                            self.sync_witness_dbids.append(database_id)
                            continue
                        else:
                            dbids.append(database_id)
                    else: 
                        dbids.append(database_id)
                else:
                    self.log.info("Not Selecting database id %s, ITS Principal Server so ignoring it." %(database_id))
        return dbids        
       
    def revert_replication_changes_for_primary(self):
        #Process sucessful dbids and revert alter command           
        self.log.info("Reverting Alter command for successful_dbids %s" %self.successful_dbids)
        for dbid in self.successful_dbids:
            db_info = self.database_info[dbid]
            if self.mirror_server_health:
                connection = self.get_secondary_server_connection()
                cursor = connection.cursor()
                query1 = "use master;"
                cursor.execute(query1)
                query2 = "ALTER DATABASE %s SET PARTNER FAILOVER" %db_info['name']
                self.log.info("Executing Alter command for Revert where query is %s" %query2)
                if self.execute_query_with_retry(cursor, query2):
                    continue
                else:
                    self.log.info("Failed to revert Alter command on mirror server for database id %s" %dbid)
                if cursor:
                    cursor.close()

    def revert_replication_if_any(self):
        if len(self.successful_dbids) == 0:
            self.log.info("There were no replication changes happen in this failover request")
            return
        if self.principal_server_health:
            self.log.info("Principal Server health is UP and needs to revert replication changes on Mirror server")
            self.revert_replication_changes_for_primary()
        else:
            self.log.info("Primary Server is Down, could not do any revert changes")

    def do_replication_changes_for_selected_dbids(self, max_retry=2):
        self.log.info("Performing replication changes on master DB for selected database ids")
        query1 = "use master;"
        error_msg = ""
        if self.principal_server_health:
            self.log.info("Connected with Primary Server to perform role change")
            connection = self.get_primary_server_connection() 
        else:
            self.log.info("Connected with Secondary Server to perform role change")
            connection = self.get_secondary_server_connection()

        if not connection:
            self.log.info("No Connection is available to perform the action")
            return False, "No Connection is available to perform replication changes"
        cursor = connection.cursor()
        cursor.execute(query1)
        self.log.info("Executed query '%s' for replication changes" %query1)

        if self.principal_server_health:
            #Primary
            self.log.info("Principal Server is Healthy and doing Replication changes")
            is_revert = False
            for dbid in self.selected_dbids:
                db_info = self.database_info[dbid]
                query2 = "ALTER DATABASE %s SET PARTNER FAILOVER;" %db_info['name']
                self.log.info("Executing query %s for dbid %s" %(query2, dbid))
                if self.execute_query_with_retry(cursor, query2):
                    self.successful_dbids.append(dbid)
                else:
                    is_revert = True
                    self.log.info("Failed to Execute Alter command for database_id %s so reverting other alter commands also" %dbid)
                    error_msg = "Failed to change replication on database id %s" %dbid
                    break
            if cursor:
                cursor.close()
            if is_revert == True:
                self.log.info("Reverting the replication changes when primary server is UP because Alter command is Fail")
                self.revert_replication_changes_for_primary() 
                return False, error_msg
            else:
                return True, error_msg
        else:
            #mirror
            self.log.info("Mirror Server is Healthy and doing Replication changes")
            for dbid in self.selected_dbids:
                db_info = self.database_info[dbid]
                query2 = "ALTER DATABASE %s SET PARTNER FORCE_SERVICE_ALLOW_DATA_LOSS" %db_info['name']
                self.log.info("Executing query %s for dbid %s" %(query2, dbid))
                if self.execute_query_with_retry(cursor, query2):
                    self.successful_dbids.append(dbid)
                else:
                    self.log.info("Failed to Execute Alter command for database_id %s"\
                                  " could not revert Alter commands as Primary is Down" %dbid)

            #TODO explain this    
            if len(self.successful_dbids) > 0 or len(self.sync_witness_dbids) > 0:
                self.log.info("Successful replication dbids are %s and sync_dbids are %s" %(self.successful_dbids, self.sync_witness_dbids))
                return True, "Done Replication changes" 
            return False, "Could Not execute alter command"
                    
    def execute_query_with_retry(self, dbcursor, query, max_retry=2):
        retry = 0
        is_successful = False
        while retry < max_retry: 
            try:
                dbcursor.execute(query)
                is_successful = True
                break
            except Exception, ex:
                self.log.error("Exception %s While Executing Alter command on Primary for dbid " % (ex))
                retry = retry + 1

        self.log.debug("Executed the query %s and execution was successful is %s" %(query, is_successful)) 
        return is_successful

    def _is_all_dbs_proper_recovery_rate(self, lagtime_list):
        '''
            Check whether retry for wait for sync is required or not
            This will return False in following conditions:
            1. When all the servers have recovery rate is 0 then Return True
            2. else return False
        '''
        self.log.info("Checking all the dbs recovery_rate to break wait for sync in lagtime_list %s" %lagtime_list)
        server_in_sync = True
        if lagtime_list:
            for lagtime in lagtime_list:
                if lagtime in [None, 0]:
                    continue
                else:
                    server_in_sync = False
                    break
        else:
            self.log.info("Lag time list is empty returning False")
            server_in_sync = False
        return server_in_sync
    
    def find_recovery_rate(self, db_name):
        query1 = "use msdb;"
        query2 = "EXEC sp_dbmmonitorresults %s, 0, 1" %db_name
        self.log.info("Query on msdb for finding recovery_rate for database name is %s" %query2)
        recovery_rate = None
        try:
            connection = self.get_secondary_server_connection()
            if not connection:
                return recovery_rate
            else:
                cursor = connection.cursor()
                cursor.execute(query1)
                cursor.execute(query2)
            for row in cursor.fetchall():
                recovery_rate = row[8]
                break
            cursor.close()
        except Exception, ex:
            self.log.error("Exception while fetching database ids from sqlserver %s" %ex)
        return recovery_rate

    def _get_recovery_rate_of_servers(self):
        self.log.debug("Find Out recovery_rate of all database ids")
        for dbid in self.selected_dbids:
            if self.recovery_rate_dict.has_key(dbid) and self.recovery_rate_dict[dbid] == 0:
                continue
            else: 
                recovery_rate = None
                db_name = self.database_info[dbid]["name"]
                recovery_rate = self.find_recovery_rate(db_name)
                self.log.info("Response from sp_dbmmonitorresults %s on database name %s" %(recovery_rate, db_name))
                self.recovery_rate_dict[dbid] = recovery_rate

    def do_wait_for_sync_for_selected_dbids(self):
        ''' Wait for sync and find out the recovery_rate
        '''
        retry = 0
        do_repl_change = False
        error_msg = ""
        if self._wait_for_sync:
            while retry < self._max_wait_sync_retry:
                self._get_recovery_rate_of_servers()
                self.log.info("Recovery Rate of servers is (dbid:recovery_rate) %s" \
                              % (self.recovery_rate_dict))
                if self.recovery_rate_dict:
                    if self._is_all_dbs_proper_recovery_rate(self.recovery_rate_dict.values()):
                        self.log.info("Wait for sync no more required." \
                                          " Breaking from loop.")
                        break
                else:
                    self.log.error("No Information got from Recovery dict")
                self.log.info("Sleeping for wait_sync_retry_interval for retrying for max_wait_sync_retry")
                time.sleep(self._wait_sync_retry_interval)
                retry = retry + 1
            # Force Failover option consider while primary server is down
            all_dbs_recovery_rate_health = self._is_all_dbs_proper_recovery_rate(self.recovery_rate_dict.values())
            self.log.info("Out for wait for sync loop and all dbs recovery rate health is %s" %all_dbs_recovery_rate_health) 
        else:
            all_dbs_recovery_rate_health = True
            self.log.info("Wait For sync is disable for this cluster") 
       
        # Force Failover option consider while primary server is down
        all_dbs_recovery_rate_health = self._is_all_dbs_proper_recovery_rate(self.recovery_rate_dict.values())
        self.log.info("Out for wait for sync loop and all dbs recovery rate health is %s" %all_dbs_recovery_rate_health) 

        if all_dbs_recovery_rate_health:
            do_repl_change = True
        else:
            error_msg = "All the servers recovery rate was not 0 or None"

        if do_repl_change == False:
            self.log.info("Do replication change flag is False checking for force_failover")
            if self._force_failover:
                self.log.info("Force Failover is On now change Do replication change flag to True")
                do_repl_change = True
                error_msg = ""
            else:
                self.log.info("Force Failover also off so aborting the failover")

        return do_repl_change, error_msg

    def check_for_mirror_role_after_replication(self):
        id_name_dict = {}
        for dbid in self.successful_dbids:
            id_name_dict[dbid] = self.dbid_name_dict[dbid]

        # In case of Primary server down and sync + witness server is configured
        for dbid in self.sync_witness_dbids:
            id_name_dict[dbid] = self.dbid_name_dict[dbid]

        self.log.info("Checking Mirror Role for these database ids %s" %id_name_dict)
        endTime = datetime.datetime.now() + datetime.timedelta(minutes=1)
        all_server_become_principal = True
        while datetime.datetime.now() >= endTime:
            all_server_become_principal = True
            db_info = self.get_database_mirroring_info(id_name_dict, check_mirror=True)
            self.log.info("Got database mirroring info from Mirror Server %s" %db_info)
            for database_id, mirror_info in db_info.iteritems():
                if mirror_info["mirroring_role"] != 1:
                    all_server_become_principal = False
                    break
            if all_server_become_principal:
                break
        if all_server_become_principal:
            self.log.info("All server become principal server")
            return True, "Successful Replication changes"
        else:
            if self.principal_server_health:
                self.revert_replication_changes_for_primary()
                return False, "All Server not become Principal Server"
            else:
                # DO Nothing because can not revert
                return True, ""
 
    def do_failover(self):
       try:
           success = True
           abort_failover = False 
           error_msg = ""
           # Get the Server health Information From API
           self.principal_server_health = self.check_principal_server_health()
           self.log.info("Principal Server health is %s" %self.principal_server_health)
           self.mirror_server_health = self.check_mirror_server_health()
           self.log.info("Secondary Server health is %s" %self.mirror_server_health)
           
           # Check Principal Server is Up and make the connection
           if self.principal_server_health:
               self.log.info("Connecting with Primary server %s" %self.old_master_ip)
               self.connection_old_master = self.get_primary_server_connection()
           
           # Make a connection with secondary for wait for sync
           self.log.info("Connecting with secondary Server %s" %self.new_master_ip)
           self.connection_new_master = self.get_secondary_server_connection()
           
           if self.principal_server_health:
               if not self.connection_old_master:
                   success = False
                   abort_failover = True
                   error_msg = "Could not connect to the current primary server %s" %self.old_master_ip
                   return success, abort_failover, error_msg

           if not self.connection_new_master:
               success = False
               abort_failover = True
               error_msg = "Could not connect to the secondary server" %self.new_master_ip
               return success, abort_failover, error_msg

           # Database ids information and their Mirroring Information Fetch
           self.dbid_name_dict = self.find_database_ids()
           self.log.info("DatabaseId's and their name on SQL Server are %s from sys.databases" %self.dbid_name_dict)
           self.database_info = self.get_database_mirroring_info(self.dbid_name_dict)
           self.log.info("DatabaseId's and their mirroring information %s from SQL Server from sys.database_mirroring" %self.database_info)
           if len(self.database_info) == 0:
               self.log.error("Could not find out database mirroring information for clusterid %s,"\
                              "so aborting the failover" %self.cluster_id)
               success = False
               abort_failover = True
               error_msg = "Could not find out database mirroring information for clusterid %s,"\
                           " so aborting the failover" %self.cluster_id
               return success, abort_failover, error_msg
           
           # Printing database info
           self.log.debug("Mirroring Role %s Mirroring safty level %s Mirroring Witness %s"\
                      %(MIRRORING_ROLE, MIRRORING_SAFETY_LEVEL, MIRRORING_WITNESS_STATE))
           
           # Do the Failover for selected database ids
           self.selected_dbids = self.get_dbids_for_replication_change()
           self.log.info("Got the database ids %s for Replication Changes" %self.selected_dbids)
      
           #Aborting Condition if all the servers not selected 
           if len(self.selected_dbids) == 0:
               if self.principal_server_health:
                   self.log.info("Principal server is UP and could not find database ids replication changes, so aborting the failover") 
                   abort_failover = True
               else:
                   if len(self.sync_witness_dbids) == 0:
                       self.log.info("Principal server is Down and could not find database ids replication changes, so aborting the failover") 
                       abort_failover = True
           elif len(self.selected_dbids) != len(self.database_info):
               if self.principal_server_health:
                   self.log.info("Principal server is UP but all the Database server are not in the same state either sync/async")
                   abort_failover = True
                
           if abort_failover:    
               self.log.info("Aborting the failover because we did not get databaseid for replication change")
               success = False
               error_msg = "Aborting the failover because we did not get databaseid's for replication change"
               return success, abort_failover, error_msg
             
           self.log.info("Replication changes has to be done on dbids %s and sync_witness_dbids %s"\
                         %(self.selected_dbids, self.sync_witness_dbids))

           # Wait for Sync and Replication changes
           self.log.info("Starting Wait for Sync for selected database ids %s" %self.selected_dbids)
           do_repl_changes, error_msg = self.do_wait_for_sync_for_selected_dbids()
           if do_repl_changes:
               success, error_msg = self.do_replication_changes_for_selected_dbids()
               if not success:
                   abort_failover = True
                   return success, abort_failover, error_msg
           else:
               abort_failover = True
               success = False
               return success, abort_failover, error_msg

           # TODO check for 60 seconds
           self.log.info("Successful Replication changes for dbids %s" %self.successful_dbids)
           success, error_msg = self.check_for_mirror_role_after_replication()
           if not success:
               abort_failover = True
               return success, abort_failover, error_msg
           return success, abort_failover, error_msg
       except Exception, ex:
           self.log.error("Exception in do_failover %s" %traceback.format_exc())
           return False, True, "Error in Doing Replication changes"
       finally:
           if self.connection_old_master:
               self.connection_old_master.close()
               self.connection_old_master = None
           if self.connection_new_master:
               self.connection_new_master.close()
               self.connection_new_master = None
           

if __name__ == '__main__':
    pass
    # Initialize logging
    #log.set_logging_prefix("failover")
    #_logger = log.get_logger("failover")
    #log.config_logging()
    #'''servers_info = [
    #               {'server_ip': '10.0.101.91',
    #                    'server_status': 1,
    #                    'username': 'CSS\sqlmirror',
    #                    'password': 'r00t.!@#',
    #                    'server_port': 1433},
    #               {'server_ip': '10.0.101.92',
    #                   'server_status': 2,
    #                   'username': 'CSS\sqlmirror',
    #                   'password': 'r00t.!@#',
    #                   'server_port': 1433},
    #               ]
    #'''
    #old_master = '10.0.101.91:1433'
    #new_master = '10.0.101.92:1433'
    #origin = 'origin'
    #root_account_info = {'username':'CSS\sqlmirror', 
    #                     'password':'r00t.!@#',
    #                    } 
    #mssql_failover = MssqlAutoFailover()
    #try:
    #    print mssql_failover.process_failover(58, old_master, new_master, 
    #                      servers_info, root_account_info,True, 2, 3, True, _logger)
    #except Exception, ex:
    #    print traceback.format_exc()
 
