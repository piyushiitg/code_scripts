import commands
import pyodbc
import socket
import Queue
from datetime import datetime
import time
import idb.util as util
import idb.log as log
import sqlite3
import sys
from idb.cluster_util import PasswordUtils
LB_FILE_PATH = '/system/lb_%s.sqlite'
GLOBAL_LB_FILE_PATH = '/system/lb.sqlite'
AUTO_FETCH_FILE = "/system/lb_auto_fetch_users_%s.sqlite"
MAX_RETRY = 3
SOCKET_TIMEOUT = 1
MSSQL_LOGIN_TIMEOUT = 5
QUERY_TIMEOUT = 10
log.set_logging_prefix("user_creds_monitor")
_logger = log.get_logger("user_creds_monitor")

class FetchFromBDC(object):
    ''' Fetch data from BDC '''
    def __init__(self, cluster_id):
        self.cluster_id = cluster_id
        self.root_user = ''
        self.root_pass = ''
        self.server_info = []
        self.netbios_domain_name = ''
        self.connection = None
        
        self.sqluser_list = []
        self.sqlgroup_list = []
       
        self.autofetch_user_dict = {}
        self.configure_dict = {} 

        self.user_group_mapping = {}
        self.final_user_dict = {}
        self.pdbuser_dict = {}
        self.exclude_usertype_list = ['D', 'W', 'S', 'T']
        self.queue = Queue.Queue()
        self.primary_ip = ''
        self.primary_port = ''

    def get_server_connection(self):
        '''
        Get any connection from any of the servers list
        ''' 
        connection = None
        if self.primary_ip:
            _logger.debug("FetchFromBDC(%d): For making connection with primary ip %s " \
                             " and port is %s" % (self.cluster_id, self.primary_ip, self.primary_port))
            connection = self.get_connection(self.primary_ip, self.primary_port)
            if connection:
                _logger.debug("Connected with primary server")
                return connection
            
        for ip, port, server_type in self.server_info:
            if ip == self.primary_ip:
                continue
            _logger.debug("FetchFromBDC(%d): For making connection with ip %s " \
                             " and port is %s and server_type is %s" % (self.cluster_id, ip, port, server_type))
            connection = self.get_connection(ip, port)
            if connection:
                return connection
        return connection

    def execute_command(self, command):
        ''' Execute pdbedit command to read user list with 
            account flag on U and UX and return user dict 
            contains username as key and hash as value
        '''
        status, output = commands.getstatusoutput(command)
        _logger.debug("FetchFromBDC(%d): Executing command %s " \
                        % (self.cluster_id, command))
        return status, output 

    def _read_servers_info(self, max_retry=3):
        '''
        Read servers info
        '''
        query = "select ipaddress, port, type from lb_servers where status=1"
        _logger.debug("FetchFromBDC(%d): Reading servers info " \
                       " and query is %s." % (self.cluster_id, query))
        db_servers_list = []
        sqlite_handle = util.get_sqlite_handle(LB_FILE_PATH % self.cluster_id)
        if sqlite_handle:
            db_cursor = sqlite_handle.cursor()
            retry = 0
            while retry < max_retry:
                try:
                    db_cursor.execute(query)
                    row = db_cursor.fetchall()
                    for ipaddress, port, server_type in row:
                        if server_type == 0:
                            self.primary_ip = ipaddress
                            self.primary_port = port
                        db_servers_list.append((ipaddress, port, server_type))
                    break
                except (Exception, sqlite3.Error) as ex:
                    retry = retry + 1
                    if retry >= max_retry:
                        _logger.error("Failed to get users")
                    else:
                        time.sleep(0.1)

            util.close_sqlite_resources(sqlite_handle, db_cursor)
        _logger.debug("FetchFromBDC(%d): Response servers info " \
                       " from query is %s." % (self.cluster_id, db_servers_list))
        return db_servers_list
    
    def _read_netbios_and_fqdn_domain_name(self, max_retry=3):
        '''
        Read servers info
        '''
        query = "select domain_name, netbios_domain_name from lb_ad_setup_info where status=1"
        _logger.debug("FetchFromBDC(%d): Reading net bios domain name " \
                       " and query is %s." % (self.cluster_id, query))
        sqlite_handle = util.get_sqlite_handle(GLOBAL_LB_FILE_PATH)
        netbios_domain_name = ''
        fqdn_domain_name = ''
        if sqlite_handle:
            db_cursor = sqlite_handle.cursor()
            retry = 0
            while retry < max_retry:
                try:
                    db_cursor.execute(query)
                    row = db_cursor.fetchone()
                    netbios_domain_name = row['netbios_domain_name']
                    fqdn_domain_name = row['domain_name']
                    break
                except (Exception, sqlite3.Error) as ex:
                    retry = retry + 1
                    if retry >= max_retry:
                        _logger.error("Failed to get users")
                    else:
                        time.sleep(0.1)

            util.close_sqlite_resources(sqlite_handle, db_cursor)
        _logger.debug("FetchFromBDC(%d): Response netbios domain name  " \
                       " from query is %s" % (self.cluster_id, netbios_domain_name))
        if netbios_domain_name:
            self.netbios_domain_name = netbios_domain_name
        if fqdn_domain_name:
            self.fqdn_domain_name = fqdn_domain_name
        return self.netbios_domain_name, self.fqdn_domain_name

    def _get_connection_string(self, server_ip, server_port):
        ''' Get connection string '''
        return "DRIVER={FreeTDS};SERVER=%s;PORT=%s;UID=%s;PWD=%s;TDS_VERSION=8.0;" \
                    % (server_ip, str(server_port), self.root_user, self.root_pass) 
    
    def get_connection(self, server_ip, server_port, max_retry=3):
        '''
        Get Connection from sql server
        '''
        retry = 0
        conn = None
        conn_str = self._get_connection_string(server_ip, server_port)
        while retry < max_retry:
            try:
                # check with socket to connect with mssql server
                _logger.info("FetchFromBDC(%d): Checking with socket and ip %s" \
                               % (self.cluster_id, server_ip))
                test_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                test_socket.settimeout(SOCKET_TIMEOUT)
                test_socket.connect((server_ip, server_port))
                _logger.info("FetchFromBDC(%d): Socket Connection sucessful ip %s" 
                                 % (self.cluster_id, server_ip))
            except socket.error:
                errno, errstr = sys.exc_info()[:2]
                if errno == socket.timeout:
                    _logger.error("FetchFromBDC(%d): Timeout has occured %s ip is %s" 
                                       % (self.cluster_id, errstr, server_ip))
                return conn
            except Exception, ex:
                _logger.info("FetchFromBDC(%d): Some Exception While using socket %s ip is %s" 
                                       % (self.cluster_id, ex, server_ip))
                return conn
            finally:
                if test_socket:
                    test_socket.close()
 
            try:
                _logger.info("FetchFromBDC(%d): Checking with pyodbc and ip is %s" 
                                        % (self.cluster_id, server_ip))
                conn = pyodbc.connect(conn_str, timeout=MSSQL_LOGIN_TIMEOUT)
                _logger.info("FetchFromBDC(%d): pyodbc connection sucessful ip is %s" 
                                        % (self.cluster_id, server_ip))
                break
            except Exception, ex:
                retry = retry + 1
                _logger.info("FetchFromBDC(%d): Was Not Able To Connect %s ip is %s" \
                                        % (self.cluster_id, ex, server_ip))
        if conn:
            conn.timeout = QUERY_TIMEOUT
        return conn

    def insert_into_autofetch_user(self, query, items):
        ''' Insert Multiple entries in auto fetch table
        '''
        _logger.debug("FetchFromBDC(%d): Insert into auto fetchusers & query is" \
                       " %s.and items %s" % (self.cluster_id, query, items))
        db_file_path = AUTO_FETCH_FILE % self.cluster_id
        sqlite_handle = util.get_sqlite_handle(db_file_path)
        is_inserted = False
        if sqlite_handle:
            db_cursor = sqlite_handle.cursor()
            retry = 0
            while retry < MAX_RETRY:
                try:
                    db_cursor.executemany(query, items)
                    sqlite_handle.commit()
                    is_inserted = True
                    break
                except Exception, ex:
                    retry = retry + 1
                    _logger.error("UserCredMonitor:Problem in inserting %s" %ex)
                    if retry >= MAX_RETRY:
                        _logger.error("UserCredMonitor: Error")
                    else:
                        time.sleep(0.1)

            util.close_sqlite_resources(sqlite_handle, db_cursor)
        else:
            _logger.debug("FetchFromBDC(%d): Problem in getting sqlite handle" \
                           % (self.cluster_id))
        return is_inserted
    
    def execute_query(self, query, db_file_path):
        ''' Execute query '''
        _logger.debug("FetchFromBDC(%d): Executing sqlite query and query is" \
                       " %s.and db_file_path %s" % (self.cluster_id, query, db_file_path))
        changes_in_sqlite = False
        sqlite_handle = util.get_sqlite_handle(db_file_path)
        if sqlite_handle:
            db_cursor = sqlite_handle.cursor()
            retry = 0
            while retry < MAX_RETRY:
                try:
                    db_cursor.execute(query)
                    sqlite_handle.commit()
                    changes_in_sqlite = True
                    break
                except Exception, ex:
                    retry = retry + 1
                    if retry >= MAX_RETRY:
                        _logger.info("FetchFromBDC(%d): Problem in executing %s"\
                                 % (self.cluster_id,ex))
                    else:
                        time.sleep(0.1)

            util.close_sqlite_resources(sqlite_handle, db_cursor)
        else:
            _logger.debug("FetchFromBDC(%d): Problem in getting sqlite handle" \
                           % (self.cluster_id))
        return changes_in_sqlite
    
    def get_sql_users_groups(self):
        ''' Execute query for users '''
        query = "SELECT name, type FROM sys.server_principals where (type = 'U' or type = 'G') and is_disabled=0"
        _logger.info("FetchFromBDC(%d): get sqlserver users and groups from" \
                       " query %s " % (self.cluster_id, query))
        user_list = []
        group_list = []
        try:
            cursor = self.connection.cursor()
        except Exception, ex:
            _logger.debug("FetchFromBDC(%d): Problem in getting cursor %s" \
                               % (self.cluster_id, ex))
            return user_list, group_list

        try:
            cursor.execute(query)
            _logger.debug("FetchFromBDC(%d): NetBIOS domain is %s" \
                               % (self.cluster_id, self.netbios_domain_name))
            for username, user_type in cursor.fetchall():
                if user_type == 'U':
                    try:
                        d_name, u_name = username.split("\\")
                        if (self.netbios_domain_name == '') or (d_name.lower() == self.netbios_domain_name.lower() or \
                               d_name.lower() == self.fqdn_domain_name.lower()):
                            user_list.append(username.lower())
                        else:
                            _logger.info("FetchFromBDC(%d): Username %s seems does not belong to the configure domain name %s" \
                                   % (self.cluster_id, username, self.netbios_domain_name))
                    except Exception, ex:
                        _logger.error("FetchFromBDC(%d): Error in adding the user %s because %s" \
                               % (self.cluster_id, username, ex))
                elif user_type == 'G':
                    group_list.append(username.lower())
            return user_list, group_list
        except Exception, ex:
            _logger.error("FetchFromBDC(%d): Query Execution failed %s" \
                               % (self.cluster_id, ex))
            return user_list, group_list
        finally:
            if cursor:
                cursor.close()

    def read_user_using_pdbedit(self):
        ''' 
        read users form pdbedit commands
        '''
        _logger.debug("FetchFromBDC(%d): reading user from pdbedit " \
                        % (self.cluster_id))
        status, output = self.execute_command("sudo pdbedit -Lw")
        user_hash_dict = {}
        try:
            if status == 0:
                rows = output.split("\n")
                for row in rows:
                    val = row.split(":")
                    if len(val) >= 6:
                        account_flag = val[4]
                        if not any(substring in account_flag for substring in self.exclude_usertype_list):
                            user_hash_dict[(val[0]).lower()] = (val[3]).lower()
        except Exception, ex:
            _logger.error("FetchFromBDC(%d): Exception while pdbedit %s" %(self.cluster_id, ex))     
        return user_hash_dict

    def read_user_using_samba_tool(self, group_name): 
        users = []
        _logger.debug("FetchFromBDC(%d): reading user from samba-tool for group %s" \
                        % (self.cluster_id, group_name))
        status, output = self.execute_command("sudo samba-tool" \
                         " group listmembers %s" % group_name)
        if status == 0:
            users = output.split("\n")
        return users
    
    def _find_root_user_info(self):
        '''
        Return a dictionary containing  root account information from table
        lb_users for this cluster_id.
        '''
        db_file_path = LB_FILE_PATH % str(self.cluster_id)
        query = "select username, encpassword from lb_users where type=1 " \
                    "and status=1"
        _logger.debug("FetchFromBDC(%d): Executing sqlite query for root user query is" \
                       " %s.and db_file_path %s" % (self.cluster_id, query, db_file_path))
        root_accnt_info = {'username':'', 'password':''}
        sqlite_handle = util.get_sqlite_handle(db_file_path)
        if sqlite_handle:
            db_cursor = sqlite_handle.cursor()

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
                    _logger.error("UserCredMonitor: Exception is %s" %ex)
                    retry = retry + 1
                    if retry >= MAX_RETRY:
                        _logger.error("UserCredMonitor: Error")
                    else:
                        time.sleep(0.1)

            util.close_sqlite_resources(sqlite_handle, db_cursor)
            if retry < MAX_RETRY :
                #lets decrypt this password
                root_accnt_info['password'] = PasswordUtils.decrypt(root_accnt_info['password'])
        return root_accnt_info

    def get_users_bw_sql_pdb(self):
        '''
        Get all the common user from sqlserver and pdbedit
        add to final dict
        '''
        _logger.debug("FetchFromBDC(%d): get all common users from sqlserver " \
                       "and pdbedit " % (self.cluster_id))
        user_dict = {}
        for username in self.sqluser_list:
            user = username.split("\\")[1]
            if user in self.pdbuser_dict:
                user_dict[username] = self.pdbuser_dict[user]
            else:
                _logger.debug("FetchFromBDC(%d): User is not present in pdbedit %s" \
                             % (self.cluster_id, user))
        return user_dict

    def fetch_users_recursively(self):
        ''' Fetch users in the group using samba-tool
            and store it into final_user_dict and mapping with
            group is store in user_group_mapping
        '''
        # BFS Implementation
        _logger.debug("FetchFromBDC(%d): Fetch users recursively using " \
                       "samba-tool " % (self.cluster_id))
        while not self.queue.empty():
            group = self.queue.get()
            group_list = group.split('\\')
            domain_name = ''
            if len(group_list) > 1:
                domain_name = group_list[0]
                group_name = group_list[1]
                _logger.debug("FetchFromBDC(%d): Group name is %s and domain name is %s" \
                                        % (self.cluster_id, group_name, domain_name))
            else:
                group_name = group_list[0]

            _logger.debug("FetchFromBDC(%d): Fetch users for the group %s" \
                                        % (self.cluster_id, group_name))
            #4. Read Users from Samba-tool for group name
            sambauser_list = self.read_user_using_samba_tool(group_name)
            _logger.debug("FetchFromBDC(%d): Fetch users form the group %s is %s" \
                                        % (self.cluster_id, group_name, sambauser_list))
            for ug in sambauser_list:
                if ug in self.pdbuser_dict:
                    # This is a User now check in final dict  
                    if ug not in self.final_user_dict:
                        _logger.debug("FetchFromBDC(%d): Fetch users form the group %s is %s" \
                                        % (self.cluster_id, group_name, sambauser_list))
                        if domain_name:
                            self.final_user_dict[domain_name + '\\'+ ug] = self.pdbuser_dict[ug]
                        else:
                            self.final_user_dict[ug] = self.pdbuser_dict[ug]
                            _logger.debug("FetchFromBDC(%d): domain name not found in recursive resolution of groups %s"\
                                           %(self.cluster_id, group_name))
                    else:
                        _logger.debug("FetchFromBDC(%d): Query executions are failed " \
                                                % (self.cluster_id))
                    if ug in self.user_group_mapping:
                        self.user_group_mapping[ug].append(group_name)
                    else:
                        self.user_group_mapping[ug] = [group_name]
                else:
                    # This is group fetch all the users from group 
                    if domain_name:
                        _logger.debug("FetchFromBDC(%d): found a new group %s domain name %s will resolve " \
                                                % (self.cluster_id, ug, domain_name))
                        self.queue.put(domain_name + '\\' + ug)
                    else:
                        _logger.debug("FetchFromBDC(%d): found a new group %s did not find domain name will resolve group only" \
                                                % (self.cluster_id, ug))
                        self.queue.put(ug)
            time.sleep(1)
        

    def get_users_from_domain_controller(self):
        ''' Get all users from bdc using pdbedit, samba-tool 
            and from sqlserver
        '''
        _logger.debug("FetchFromBDC(%d):Step1.1 Finding servers info and root user info " \
                                   % (self.cluster_id))
        self.server_info = self._read_servers_info()
        self.netbios_domain_name, self.fqdn_domain_name = self._read_netbios_and_fqdn_domain_name() 
        root_account_info = self._find_root_user_info()
        if root_account_info:
            self.root_user = root_account_info['username']
            self.root_pass = root_account_info['password']
        else:
            _logger.info("FetchFromBDC(%d): error in root username and password" %(self.cluster_id))
        _logger.debug("FetchFromBDC(%d):Step1.2 Making connection with root info %s " \
                                   % (self.cluster_id, root_account_info))
        self.connection = self.get_server_connection()
        if not self.connection:
            _logger.error("FetchFromBDC(%d): Got Empty connection object with all sqlserver" %(self.cluster_id))
            return False
        #NOTE SqlServer
        self.sqluser_list, self.sqlgroup_list = self.get_sql_users_groups()
        _logger.info("FetchFromBDC(%d):Step1.3 sqlserver list %s group list %s" \
                      % (self.cluster_id, self.sqluser_list, self.sqlgroup_list))
        #NOTE PdbEdit
        self.pdbuser_dict = self.read_user_using_pdbedit()
        _logger.info("FetchFromBDC(%d):Step1.4 pdbuser hash info  %s " % (self.cluster_id, self.pdbuser_dict))
        #NOTE Common user in final dict
        self.final_user_dict = self.get_users_bw_sql_pdb() 
        _logger.info("FetchFromBDC(%d):Step1.5 final user hash info %s " %(self.cluster_id, self.final_user_dict))

        #NOTE groups in queue
        map(self.queue.put, self.sqlgroup_list)
        
        # NOTE fetch all the users recursively
        _logger.info("FetchFromBDC(%d):Step1.5 fetch users recursively from group list %s "\
                       %(self.cluster_id, self.sqlgroup_list))
        self.fetch_users_recursively()
        return True

    def get_users_from_auto_fetch(self, max_retry=3):
        '''
        fetch data from auto fetch table
        '''
        query_for_users = "select user_name, nt_hash, added_by from lb_auto_fetch_users \
                               where status=1"
        _logger.debug("FetchFromBDC(%d): get users from auto fetch table " \
                      " query is %s"  % (self.cluster_id, query_for_users))
        auto_fetch_file = AUTO_FETCH_FILE % self.cluster_id
        sqlite_user_dict = {}
        configure_dict = {}
        auto_sqlite_handle = util.get_sqlite_handle(auto_fetch_file)
        if auto_sqlite_handle:
            db_cursor = auto_sqlite_handle.cursor()
            retry = 0
            while retry < max_retry:
                try:
                    db_cursor.execute(query_for_users)
                    row = db_cursor.fetchall()
                    for user, hashcode, configured in row:
                        sqlite_user_dict[user] = hashcode
                        configure_dict[user] = configured
                    break
                except (Exception, sqlite3.Error) as ex:
                    retry = retry + 1
                    if retry >= max_retry:
                        _logger.error("FetchFromBDC(%d): Exception is %s" %(self.cluster_id, ex))
                    else:
                        time.sleep(0.1)

            util.close_sqlite_resources(auto_sqlite_handle, db_cursor)
        return sqlite_user_dict, configure_dict

    def get_users_from_sqlite(self):
        ''' Get all the users from lb_auto_fetch users sqlite
            file and that file requires cluster wise
            if status of that entry is 1 that means that user is 
            also saved in lb_users table
        '''
        self.autofetch_user_dict, self.configure_dict = self.get_users_from_auto_fetch()
        _logger.debug("FetchFromBDC(%d): autofetch users are %s and configured users are  " \
                      " %s"  % (self.cluster_id, self.autofetch_user_dict, self.configure_dict))
        
    def get_diff_bw_dc_autofetch_users(self):
        ''''
        Compare sqlite users and users from
        autofetch_user_dict and final_user_dict
        '''
        _logger.debug("FetchFromBDC(%d): get diff bw autofetch users and  " \
                      " domaincontroller users"  % (self.cluster_id))
        autofetch_user_item_set = set(self.autofetch_user_dict.items())
        final_user_item_set = set(self.final_user_dict.items()) 
        _logger.debug("FetchFromBDC(%d): autofetch users %s and  " \
                      " domaincontroller users %s"  % (self.cluster_id, autofetch_user_item_set, final_user_item_set))
        new_updated = final_user_item_set.difference(autofetch_user_item_set)
        new_users = set([])
        update_users = set([])
        del_users = set([])
        for username, hashcode in new_updated:
            if username in self.autofetch_user_dict:
                update_users.add((username, hashcode))
            else:
                new_users.add((username, hashcode))
        
        del_updated = autofetch_user_item_set.difference(final_user_item_set)
        for username, hashcode in del_updated:
            if username in self.final_user_dict:
                # this is the updated user handled in previous loop
                pass
            else:
                if self.check_if_user_to_be_deleted(username, self.final_user_dict):
                    del_users.add((username, hashcode))
        return new_users, update_users, del_users

    def check_if_user_to_be_deleted(self, username, final_user_dict):
        '''
        Check if user is root user then should not delete it
        if username have netbios_domain_name or fqdn_domain_name and root user not to delete
        if user came from sqlsever with fqdn_domain_name and in sqlite we have stored in netbios_domain_name
        then also not to delete
        '''
        
        del_user_domain_name, del_user_name = username.split("\\")
        root_domain_name, root_user_name = self.root_user.split("\\")
        new_user_fqdn = self.fqdn_domain_name.lower() + "\\" + del_user_name
        new_user_netbios = self.netbios_domain_name.lower() + "\\" + del_user_name
        
        if del_user_domain_name in [self.netbios_domain_name.lower(), self.fqdn_domain_name.lower()]:
            if del_user_name == root_user_name:
                _logger.debug("FetchFromBDC(%d): Username %s matches with root user %s so could not delete it " \
                       % (self.cluster_id, username, self.root_user))
                return False
            if new_user_fqdn in final_user_dict:
                _logger.debug("FetchFromBDC(%d): Username %s matches with fqdn " \
                       % (self.cluster_id, username))
                return False
            if new_user_netbios in final_user_dict:
                _logger.debug("FetchFromBDC(%d): Username %s matches with netbios name " \
                       % (self.cluster_id, username))
                return False

        return True           

    def writeback_changes_into_sqlite(self, new_users, update_users, del_users, updatetime):
        '''
        Three type of list we have new, update, del we need to update the 
        changes in both sqlite file lb_users and auto_fetch_users
        '''
        # Insert into auto fetch users 
        _logger.debug("FetchFromBDC(%d): write some changes to sqlite " \
                       % (self.cluster_id))
        params = []
        insertion_in_sqlite = False
        update_in_sqlite = False
        deletion_in_sqlite = False
        update_in_lbusers = 0
        del_in_lbusers = 0
        query = """insert or replace into lb_auto_fetch_users(user_name, nt_hash, 
                 status, added_by, update_time) values (?,?,?,?,?)"""
        if new_users:
            for username, hashcode in new_users:
                params.append((username, hashcode, 1, 0, updatetime))
        
            _logger.debug("FetchFromBDC(%d): Query for insertion" \
                                        % (self.cluster_id))
            insertion_in_sqlite = self.insert_into_autofetch_user(query, params)
        else:
            _logger.debug("FetchFromBDC(%d): Number of Insertion is 0" \
                           % (self.cluster_id))

        # Update Process
        #FIXME how to do update and delete in transaction
        if update_users:
            result = False
            update_in_autousers = False
            query1 = """update lb_auto_fetch_users set nt_hash = '%s', 
                        update_time = '%s' where user_name = '%s' """
            query2 = """update lb_users set nt_hash = '%s', updatetime = '%s' 
                          where username = '%s'"""
            _logger.debug("FetchFromBDC(%d): Query for update " \
                                        % (self.cluster_id))
            #FIXME need to ask update time in lb_users
            for username, hashcode in update_users:
                if self.configure_dict[username] == 1:
                    tmp_query = query2 % (hashcode, updatetime, username) 
                    db_file_path = LB_FILE_PATH % self.cluster_id 
                    result = self.execute_query(tmp_query, db_file_path) 
                    if result and not update_in_lbusers:
                        update_in_lbusers = 1

                tmp_query = query1 % (hashcode, updatetime, username) 
                db_file_path = AUTO_FETCH_FILE % self.cluster_id
                result = self.execute_query(tmp_query, db_file_path) 
                if result and not update_in_autousers:
                    update_in_autousers = True
            if update_in_lbusers or update_in_autousers:
                update_in_sqlite = True
        else:
            _logger.debug("FetchFromBDC(%d): Number of update is 0" \
                           % (self.cluster_id))
        # Process delete
        if del_users:
            result = False
            del_in_autousers = False
            query1 = "update lb_auto_fetch_users set status = 9 where user_name = '%s'"
            query2 = "update lb_users set status = 9 where username = '%s'"
            _logger.debug("FetchFromBDC(%d): Query for delete " \
                                        % (self.cluster_id))
            for username, hashcode in del_users:
                if self.configure_dict[username] == 1:
                    db_file_path = LB_FILE_PATH % self.cluster_id 
                    tmp_query = query2 % (username) 
                    result = self.execute_query(tmp_query, db_file_path) 
                    if result and not del_in_lbusers:
                        del_in_lbusers = 1
            
                tmp_query = query1 % (username) 
                db_file_path = AUTO_FETCH_FILE % self.cluster_id
                result = self.execute_query(tmp_query, db_file_path)
                if result and not del_in_autousers:
                    del_in_autousers = True
            if del_in_lbusers or del_in_autousers:
                deletion_in_sqlite = True
        else:
            _logger.debug("FetchFromBDC(%d): Number of delete is 0" \
                           % (self.cluster_id))

        if (insertion_in_sqlite or update_in_sqlite or deletion_in_sqlite):
            _logger.info("FetchFromBDC(%d): Changes in backened Insert %s, update %s, delete %s happened "\
                         % (self.cluster_id, insertion_in_sqlite, update_in_sqlite, deletion_in_sqlite)) 
            return True, (update_in_lbusers or del_in_lbusers) 
        return False, False

    
    def _inform_core_about_users(self, update_time, update_in_lbusers):
        '''
        There has been role change and command to inform core of the same is
        present in self._msg_for_core. Deliver the same to core.

        prepend header as well
        header = "refresh|auto_fetch_users_list|%d|%s|%d" % (self._cluster_id, update_time, updateLBusers)
        '''
        msg_for_core = "refresh|auto_fetch_users_list|%s|'%s'|%s|" % (self.cluster_id, update_time, update_in_lbusers) 
        
        _logger.info("FetchFromBDC(%d): Msg for core is %s " % (self.cluster_id, msg_for_core))
        response = util.socket_cmd_runner(unix_sock="/tmp/lb_sock",
                                            command=msg_for_core)
        if response != "SUCCESS":
            _logger.error("FetchFromBDC(%d) :Failed to inform core about %s" % (self.cluster_id, response))


    def fetch_update_users(self):
        ''' This method fetch all the users from Domain controller
            find the difference from sqlite users and update them
            insert or delete them from sqlite
        '''
 
        _logger.debug("FetchFromBDC(%d): Start Fetching the data" \
                           % (self.cluster_id))
        #NOTE This function update final_user_dict
        _logger.debug("FetchFromBDC(%d):Step1: Starting Fetching user form domain controller" \
                           % (self.cluster_id))
        res = self.get_users_from_domain_controller()   
       
        if res == False:
            _logger.error("FetchFromBDC(%d): Unable to make Connection with sqlserver returning it" \
                                  % (self.cluster_id))
            return
             
        _logger.debug("FetchFromBDC(%d):Step2: Starting Fetching user form sqlite" \
                           % (self.cluster_id))
        #NOTE Get all the users form auto fetch sqlite file
        # This call we can avoid and can use timly basis
        self.get_users_from_sqlite()         
             
        #NOTE Difference b/w autofetch users and domain controller user
        _logger.debug("FetchFromBDC(%d):Step3: Calculating diff bw domain user and sqlite user" \
                           % (self.cluster_id))
        new_users, update_users, del_users = self.get_diff_bw_dc_autofetch_users()
        _logger.info("FetchFromBDC(%d): New_users is %s update is %s del is %s"
                               %(self.cluster_id, new_users, update_users, del_users))
        #NOTE Insert, update, delete from sqlite files
        t = datetime.now()
        updatetime = t.strftime("%Y-%m-%d %H:%M:%S")
        _logger.debug("FetchFromBDC(%d):Step4: Write back change to sqlite and informing core" \
                           % (self.cluster_id))
        update_in_sqlite, update_in_lbusers = self.writeback_changes_into_sqlite(new_users, 
                                             update_users, del_users, updatetime)
        if update_in_sqlite:
            _logger.info("FetchFromBDC(%d): changes in sqlite informing to core" % (self.cluster_id))
            self._inform_core_about_users(updatetime, update_in_lbusers)
