import commands
import pyodbc
import Queue
from datetime import datetime
import time
import idb.util as util
import idb.log as log
import sqlite3
import base64
import logging
from time import mktime
LB_FILE_PATH = '/system/lb_%s.sqlite'
AUTO_FETCH_FILE = "/system/lb_auto_fetch_users_%s.sqlite"
MAX_RETRY = 3

log.set_logging_prefix("user_creds_monitor")
_logger = log.get_logger("user_creds_monitor")

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

class FetchFromBDC(object):
    ''' Fetch data from BDC '''
    def __init__(self, cluster_id):
        self.cluster_id = cluster_id
        self.root_user = ''
        self.root_pass = ''
        self.server_info = []
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
	# Initialize the logger

    def get_server_connection(self):
        '''
        Get any connection from any of the servers list
        ''' 
        connection = None
        for ip, port in self.server_info:
            _logger.info("UserCredMonitor:for connection ip %s and port is %s " %(ip, port))
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
        return status, output 

    def _read_servers_info(self, max_retry=3):
        '''
        Read servers info
        '''
        db_servers_list = []
        sqlite_handle = util.get_sqlite_handle(LB_FILE_PATH % self.cluster_id)
        if sqlite_handle:
            db_cursor = sqlite_handle.cursor()
            query = "select ipaddress, port from lb_servers where status=1"
            retry = 0
            while retry < max_retry:
                try:
                    db_cursor.execute(query)
                    row = db_cursor.fetchall()
                    for ipaddress, port in row:
                        db_servers_list.append((ipaddress, port))
                    break
                except (Exception, sqlite3.Error) as ex:
                    retry = retry + 1
                    if retry >= max_retry:
                        _logger.error("Failed to get users")
                    else:
                        time.sleep(0.1)

            util.close_sqlite_resources(sqlite_handle, db_cursor)
        return db_servers_list


    def _get_connection_string(self, server_ip, server_port):
        ''' Get connection string '''
        return "DRIVER={FreeTDS};SERVER=%s;PORT=%s;UID=%s;PWD=%s;TDS_VERSION=8.0;" \
                    % (server_ip, str(server_port), self.root_user, self.root_pass) 
    
    def get_connection(self, server_ip, server_port):
        '''
        Get Connection from sql server
        '''
        conn_str = self._get_connection_string(server_ip, server_port)
        _logger.info("UserCredMonitor: connection string is %s" % conn_str)
        conn = None
        try:
            conn = pyodbc.connect(conn_str, timeout=5)
        except Exception, ex:
            _logger.error("UserCredMonitor: Was not able to connect %s" %ex)
        if conn:
            conn.timeout = 5
        return conn

    def insert_into_autofetch_user(self, query, items):
        ''' Insert Multiple entries in auto fetch table
        '''
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
            _logger.info("UserCredMonitor:Problem in getting sqlite handle")

        return is_inserted
    
    def execute_query(self, query, db_file_path):
        ''' Execute query '''
        changes_in_sqlite = False
        sqlite_handle = util.get_sqlite_handle(db_file_path)
        if sqlite_handle:
            db_cursor = sqlite_handle.cursor()
            retry = 0
            while retry < MAX_RETRY:
                try:
                    _logger.info("UserCredMonitor: query to execute %s " % query)
                    db_cursor.execute(query)
                    sqlite_handle.commit()
                    changes_in_sqlite = True
                    break
                except Exception, ex:
                    retry = retry + 1
                    _logger.info("UserCredMonitor: Problem in executing %s" % ex)
                    if retry >= MAX_RETRY:
                        _logger.error("UserCredMonitor: Error")
                    else:
                        time.sleep(0.1)

            util.close_sqlite_resources(sqlite_handle, db_cursor)
        else:
            _logger.info("UserCredMonitor: Problem in getting sqlite handle")
        return changes_in_sqlite
    
    def get_sql_users_groups(self):
        ''' Execute query for users '''
        user_list = []
        group_list = []
        try:
            cursor = self.connection.cursor()
        except Exception, ex:
            _logger.info("UserCredMonitor: Problem in getting cursor")
            return user_list, group_list

        try:
            cursor.execute("SELECT name, type FROM sys.server_principals where (type = 'U' or type = 'G') and is_disabled=0")
            for username, user_type in cursor.fetchall():
                if user_type == 'U':
                    user_list.append(username.lower())
                elif user_type == 'G':
                    group_list.append(username.lower())
            return user_list, group_list
        except Exception, ex:
            _logger.info("UserCredMonitor: Query executions are failed %s" % ex)
            return user_list, group_list
        finally:
            if cursor:
                cursor.close()

    def read_user_using_pdbedit(self):
        ''' 
        read users form pdbedit commands
        '''
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
            _logger.error("UserCredMonitor: Exception while pdbedit")     
        return user_hash_dict

    def read_user_using_samba_tool(self, group_name): 
        users = []
        status, output = self.execute_command("sudo /home/idb/samba-master/INSTALL/bin/samba-tool" \
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
        root_accnt_info = {'username':'', 'password':''}
        sqlite_handle = util.get_sqlite_handle(db_file_path)
        if sqlite_handle:
            db_cursor = sqlite_handle.cursor()
            query = "select username, encpassword from lb_users where type=1 " \
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
        user_dict = {}
        for username in self.sqluser_list:
            user = username.split("\\")[1]
            if user in self.pdbuser_dict:
                user_dict[username] = self.pdbuser_dict[user]
            else:
                _logger.info("UserCredMonitor: User is missing %s" %user)
        return user_dict

    def fetch_users_recursively(self):
        ''' Fetch users in the group using samba-tool
            and store it into final_user_dict and mapping with
            group is store in user_group_mapping
        '''
        # BFS Implementation
        while not self.queue.empty():
            group = self.queue.get() 
            #4. Read Users from Samba-tool for group name
            sambauser_list = self.read_user_using_samba_tool(group)
            for ug in sambauser_list:
                if ug in self.pdbuser_dict:
                    # This is a User now check in final dict  
                    if ug not in self.final_user_dict:
                        self.final_user_dict[ug] = self.pdbuser_dict[ug]
                    else:
                        _logger.info("UserCredMonitor: Query executions are failed")
                    if ug in self.user_group_mapping:
                        self.user_group_mapping[ug].append(group)
                    else:
                        self.user_group_mapping[ug] = [group]
                else:
                    # This is group fetch all the users from group 
                    self.queue.put(ug)
            time.sleep(1)
        

    def get_users_from_domain_controller(self):
        ''' Get all users from bdc using pdbedit, samba-tool 
            and from sqlserver
        '''
        self.server_info = self._read_servers_info()
        root_account_info = self._find_root_user_info()
        if root_account_info:
            self.root_user = root_account_info['username']
            self.root_pass = root_account_info['password']
        else:
            _logger.info("UserCredMonitor: error in root username and password")
        self.connection = self.get_server_connection()
        #NOTE SqlServer
        self.sqluser_list, self.sqlgroup_list = self.get_sql_users_groups()
        _logger.info("UserCredMonitor: sqlserver list %s " % self.sqluser_list)
        #NOTE PdbEdit
        self.pdbuser_dict = self.read_user_using_pdbedit()
        _logger.info("UserCredMonitor: pdbuser dict  %s " % self.pdbuser_dict)
        #NOTE Common user in final dict
        self.final_user_dict = self.get_users_bw_sql_pdb() 
        _logger.info("UserCredMonitor: final user dict %s " % self.final_user_dict)

        #NOTE groups in queue
        map(self.queue.put, self.sqlgroup_list)
        
        # NOTE fetch all the users recursively
        self.fetch_users_recursively()

    def get_users_from_auto_fetch(self, max_retry=3):
        '''
        fetch data from auto fetch table
        '''
        auto_fetch_file = AUTO_FETCH_FILE % self.cluster_id
        sqlite_user_dict = {}
        configure_dict = {}
        auto_sqlite_handle = util.get_sqlite_handle(auto_fetch_file)
        if auto_sqlite_handle:
            db_cursor = auto_sqlite_handle.cursor()
            query_for_users = "select user_name, nt_hash, added_by from lb_auto_fetch_users \
                               where status=1"
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
                    _logger.error("UserCredMonitor: Exception is %s" %ex)
                    retry = retry + 1
                    if retry >= max_retry:
                        _logger.error("UserCredMonitor: Failed to get users")  
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
        
    def get_diff_bw_dc_autofetch_users(self):
        ''''
        Compare sqlite users and users from
        autofetch_user_dict and final_user_dict
        '''
        autofetch_user_item_set = set(self.autofetch_user_dict.items())
        final_user_item_set = set(self.final_user_dict.items()) 
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
                del_users.add((username, hashcode))
        return new_users, update_users, del_users

    def writeback_changes_into_sqlite(self, new_users, update_users, del_users, updatetime):
        '''
        Three type of list we have new, update, del we need to update the 
        changes in both sqlite file lb_users and auto_fetch_users
        '''
        # Insert into auto fetch users 
        params = []
        insertion_in_sqlite = False
        update_in_sqlite = False
        deletion_in_sqlite = False
        update_in_lbusers = False
        del_in_lbusers = False
        query = """insert or replace into lb_auto_fetch_users(user_name, nt_hash, 
                 status, added_by, update_time) values (?,?,?,?,?)"""
        if new_users:
            for username, hashcode in new_users:
                params.append((username, hashcode, 1, 0, updatetime))
        
            insertion_in_sqlite = self.insert_into_autofetch_user(query, params)
        else:
            _logger.info("UserCredMonitor: Nothing to Insert")

        # Update Process
        #FIXME how to do update and delete in transaction
        if update_users:
            result = False
            update_in_autousers = False
            query1 = """update lb_auto_fetch_users set nt_hash = '%s' 
                        update_time = '%s' where user_name = '%s' """
            query2 = "update lb_users set nt_hash = '%s' where username = '%s'"
            #FIXME need to ask update time in lb_users
            for username, hashcode in update_users:
                if self.configure_dict[username] == 1:
                    tmp_query = query2 % (hashcode, username) 
                    db_file_path = LB_FILE_PATH % self.cluster_id 
                    result = self.execute_query(tmp_query, db_file_path) 
                    if result and not update_in_lbusers:
                        update_in_lbusers = True

                tmp_query = query1 % (hashcode, updatetime, username) 
                db_file_path = AUTO_FETCH_FILE % self.cluster_id
                result = self.execute_query(tmp_query, db_file_path) 
                if result and not update_in_autousers:
                    update_in_autousers = True
            if update_in_lbusers or update_in_autousers:
                update_in_sqlite = True
        else:
            _logger.info("UserCredMonitor: Nothing to Update")
        # Process delete
        if del_users:
            result = False
            del_in_autousers = False
            query1 = "update lb_auto_fetch_users set status = 9 where user_name = '%s'"
            query2 = "update lb_users set status = 9 where username = '%s'"
            for username, hashcode in del_users:
                if self.configure_dict[username] == 1:
                    db_file_path = LB_FILE_PATH % self.cluster_id 
                    tmp_query = query2 % (username) 
                    result = self.execute_query(tmp_query, db_file_path) 
                    if result and not del_in_lbusers:
                        del_in_lbusers = True
            
                tmp_query = query1 % (username) 
                db_file_path = AUTO_FETCH_FILE % self.cluster_id
                result = self.execute_query(tmp_query, db_file_path)
                if result and not del_in_autousers:
                    del_in_autousers = True
            if del_in_lbusers or del_in_autousers:
                deletion_in_sqlite = True
        else:
            _logger.info("UserCredMonitor: Nothing to delete")

        if (insertion_in_sqlite or update_in_sqlite or deletion_in_sqlite):
            _logger.info("UserCredMonitor: Some Insert %s, update %s, delete %s happened " 
                         % (insertion_in_sqlite, update_in_sqlite, deletion_in_sqlite)) 
            return True, (update_in_lbusers or del_in_lbusers) 
        return False, False

    
    def _inform_core_about_users(self, update_time, update_in_lbusers):
        '''
        There has been role change and command to inform core of the same is
        present in self._msg_for_core. Deliver the same to core.

        prepend header as well
        header = "refresh|auto_fetch_users|%d|%s|%d" % (self._cluster_id, update_time, updateLBusers)
        '''
        msg_for_core = "refresh|%s|%s" % (self.cluster_id, update_time, update_in_lbusers) 
        
        _logger.info("UserCredMonitor: Msg for core is %s " % msg_for_core)
        response = util.socket_cmd_runner(unix_sock="/tmp/lb_sock",
                                            command=msg_for_core)
        if response != "SUCCESS":
            _logger.error("UserCredMonitor: %s Failed to inform core about %s" % (self.cluster_id, response))


    def fetch_update_users(self):
        ''' This method fetch all the users from Domain controller
            find the difference from sqlite users and update them
            insert or delete them from sqlite
        '''
        #NOTE This function update final_user_dict
        self.get_users_from_domain_controller()   
        
        #NOTE Get all the users form auto fetch sqlite file
        # This call we can avoid and can use timly basis
        self.get_users_from_sqlite()         
             
        #NOTE Difference b/w autofetch users and domain controller user
        new_users, update_users, del_users = self.get_diff_bw_dc_autofetch_users()
        _logger.info("UserCredMonitor: New_users is %s update is %s del is %s"%(new_users, update_users, del_users ))
        #NOTE Insert, update, delete from sqlite files
        t = datetime.now()
        updatetime = mktime(t.timetuple())+1e-6*t.microsecond
        update_in_sqlite, update_in_lbusers = self.writeback_changes_into_sqlite(new_users, 
                                             update_users, del_users, updatetime)
        if update_in_sqlite:
            _logger.info("Some changes in sqlite informing to core")
            self._inform_core_about_users(updatetime, update_in_lbusers)
 
#if __name__ == '__main__':
#    ''' Main function '''
#    cluster_id = str(1)
#    bdc_client = FetchFromBDC(cluster_id)
#    bdc_client.fetch_update_users()
