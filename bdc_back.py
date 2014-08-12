import commands
import pyodbc
import Queue
from datetime import datetime
import time
import util
import sqlite3
from util import PasswordUtils
LB_FILE_PATH = '/system/lb.sqlite'
AUTO_FETCH_FILE = "/system/lb_auto_fetch_users_%s.sqlite"
MAX_RETRY = 3

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
        self.sqluser_dict = {}
        self.sqlite_user_list = []
        self.exclude_usertype_list = ['D','W','S','T']
        self.queue = Queue.Queue()

    def get_server_connection(self):
        '''
        Get any connection from any of the servers list
        ''' 
        connection = None
        for ip, port in self.server_info:
            connection = self.get_connection(ip, port)
            if connection:
                return connection

    def execute_command(self, command):
        ''' Execute pdbedit command to read user list with 
            account flag on U and UX and return user dict 
            contains username as key and hash as value
        '''
        status, output = commands.getstatusoutput(command)
        return status, output 

    def get_sqlite_handle(self, db_name, timeout=None):
        '''
        Returns a sqlite handle to the recieved db_name
        '''
        try:
            if timeout:
                conn = sqlite3.connect(db_name, timeout=timeout)
            else:
                conn = sqlite3.connect(db_name)
            # obtain all results as python dictionaries
            conn.row_factory = sqlite3.Row
            return conn
        except :
            return None

    def read_user_from_auto_fetch(self, cluster_id, timeout=None, max_retry=3):
        '''
        fetch data from auto fetch table
        '''
        auto_fetch_file = AUTO_FETCH_FILE % cluster_id
        auto_sqlite_handle = self.get_sqlite_handle(auto_fetch_file)
        sqlite_user_dict = {}
        configure_dict = {}
        if auto_sqlite_handle:
            db_cursor = auto_sqlite_handle.cursor()
            query_for_users = "select user, hashcode, configured from auto_fetch_user \
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
                    retry = retry + 1
                    if retry >= max_retry:
                        print "Failed to get users"
                    else:
                        time.sleep(0.1)

            auto_sqlite_handle.close()
            if db_cursor:
                db_cursor.close()
        return sqlite_user_dict, configure_dict
        
    def read_user_from_sqlite(self, timeout=None, max_retry=3):
        '''
        Read data from sqlite file
        '''
        sqlite_user_dict = {}
        sqlite_handle = self.get_sqlite_handle("/system/lb.sqlite")
        if sqlite_handle:
            db_cursor = sqlite_handle.cursor()
            #Query to get apikey from lb_network table
            #TODO filter on type windows users in query
            query_for_users = "select user, hashcode from lb_users"
            
            retry = 0
            while retry < max_retry:
                try:
                    db_cursor.execute(query_for_users)
                    row = db_cursor.fetchall()
                    for user, hashcode in row:
                        sqlite_user_dict[user] = hashcode
                    break
                except (Exception, sqlite3.Error) as ex:
                    retry = retry + 1
                    if retry >= max_retry:
                        print "Failed to get users"
                    else:
                        time.sleep(0.1)

            sqlite_handle.close()
        return sqlite_user_dict

    def _read_servers_info(self, max_retry=3):
        '''
        Read servers info
        '''
        db_servers_list = []
        sqlite_handle = self.get_sqlite_handle("/system/lb_%s.sqlite" % self.cluster_id)
        if sqlite_handle:
            db_cursor = sqlite_handle.cursor()
            query = "select ipaddress, port from lb_servers"
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
                        print "Failed to get users"
                    else:
                        time.sleep(0.1)

            sqlite_handle.close()
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
        conn = None
        try:
            conn = pyodbc.connect(conn_str, timeout=5)
        except Exception, ex:
            print "Was Not Able To Connect" 
        if conn:
            conn.timeout = 5
        return conn

    def insert_into_autofetch_user(self, query, items):
        ''' Insert Multiple entries in auto fetch table
        '''
        db_file_path = AUTO_FETCH_FILE % self.cluster_id
        sqlite_handle = util.get_sqlite_handle(db_file_path)
        if sqlite_handle:
            db_cursor = sqlite_handle.cursor()
            retry = 0
            while retry < MAX_RETRY:
                try:
                    db_cursor.executemany(query, items)
                    break
                except Exception, ex:
                    retry = retry + 1
                    print "Problem in inserting"
                    if retry >= MAX_RETRY:
                        print "Error"
                    else:
                        time.sleep(0.1)

            util.close_sqlite_resources(sqlite_handle, db_cursor)
        else:
            print "Problem in getting sqlite handle"
    
    def execute_query(self, query, db_file_path):
        ''' Execute query '''
        sqlite_handle = util.get_sqlite_handle(db_file_path)
        if sqlite_handle:
            db_cursor = sqlite_handle.cursor()
            retry = 0
            while retry < MAX_RETRY:
                try:
                    db_cursor.execute(query)
                    break
                except Exception, ex:
                    retry = retry + 1
                    print "Problem in executing"
                    if retry >= MAX_RETRY:
                        print "Error"
                    else:
                        time.sleep(0.1)

            util.close_sqlite_resources(sqlite_handle, db_cursor)
        else:
            print "Problem in getting sqlite handle"
    

        try:
            cursor = conn.cursor()
        except Exception, ex:
            print "Problem determining cursor " 
            return None
        try:
            cursor.execute(query)
        except Exception, ex:
            print "Query executions are failed"
            return False
        return True
    

    def get_sql_users_groups(self):
        ''' Execute query for users '''
        user_list = []
        group_list = []
        try:
            cursor = self.connection.cursor()
        except Exception, ex:
            print "Problem determining cursor " 
            return user_list, group_list

        try:
            cursor.execute("SELECT username, type FROM sys.database_principals where type = 'U' or type = 'G'")
            for username, user_type in cursor.fetchall():
                if user_type == 'U':
                    user_list.append(username.split("\\")[1])
                elif user_type == 'G':
                    group_list.append(username)
            return user_list, group_list
        except Exception, ex:
            print "Query executions are failed"
            return user_list, group_list
        finally:
            if cursor:
                cursor.close()

    def read_user_using_pdbedit(self):
        ''' 
        read users form pdbedit commands
        '''
        status, output = self.execute_command("sudo /usr/local/samba/bin/pdbedit -Lw")
        user_hash_dict = {}
        try:
            if status == 0:
                rows = output.split("\n")
                for row in rows:
                    val = row.split(":")
                    if len(val) >= 6:
                        account_flag = val[4]
                        if not any(substring in account_flag for substring in self.exclude_usertype_list):
                            user_hash_dict[val[0]] = val[3]
        except Exception, ex:
            print "Exception while pdbedit"
        return user_hash_dict

    def read_user_using_samba_tool(self, group_name): 
        users = []
        status, output = self.execute_command("sudo /home/idb/samba-master/INSTALL/bin/samba-tool" \
                         " group listmembers %s" % group_name)
        if status == 0:
            users = output.split("\n")
        return users
    
    def _find_root_user_info(self, cluster_id):
        '''
        Return a dictionary containing  root account information from table
        lb_users for this cluster_id.
        '''
        db_file_path = LB_FILE_PATH % cluster_id
        root_accnt_info = {}
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
                    retry = retry + 1
                    if retry >= MAX_RETRY:
                        print "Error"
                    else:
                        time.sleep(0.1)

            util.close_sqlite_resources(sqlite_handle, db_cursor)
            if retry < MAX_RETRY :
                #lets decrypt this password
                root_accnt_info['password'] = PasswordUtils.decrypt(root_accnt_info['password'])
        return root_accnt_info

    def get_users_bw_sql_pdb():
        '''
        Get all the common user from sqlserver and pdbedit
        add to final dict
        '''
        user_dict = {}
        for user in self.sqluser_list:
            if user in self.pdbuser_dict:
                user_dict[user] = self.pdbuser_dict[user]
            else:
                print "User is missing in pdbEdit list", user
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
                        print "user is already in final user dict"
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
        self.connection = self.get_server_connection()
        self.server_info = self._read_servers_info()
        self.root_user, self.root_pass = self._find_root_user_info()
        
        #NOTE SqlServer
        self.sqluser_list, self.sqlgroup_list = self.get_sql_users_groups()
        
        #NOTE PdbEdit
        self.pdbuser_dict = self.read_user_using_pdbedit()

        #NOTE Common user in final dict
        self.final_user_dict = self.get_users_bw_sql_pdb() 

        #NOTE groups in queue
        map(self.queue.put, self.sqlgroup_list)

        # NOTE fetch all the users recursively
        self.fetch_users_recursively()

    def get_users_from_auto_fetch(self):
        '''
        fetch data from auto fetch table
        '''
        auto_fetch_file = AUTO_FETCH_FILE % cluster_id
        sqlite_user_dict = {}
        configure_dict = {}
        auto_sqlite_handle = util.get_sqlite_handle(auto_fetch_file)
        if auto_sqlite_handle:
            db_cursor = auto_sqlite_handle.cursor()
            query_for_users = "select user, hashcode, configured from auto_fetch_user \
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
                    retry = retry + 1
                    if retry >= max_retry:
                        print "Failed to get users"
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
            if username in final_user_dict:
                # this is the updated user handled in previous loop
                pass
            else:
                del_users.add((username, hashcode))
        return new_users, update_users, del_users

    def writeback_changes_into_sqlite(self, new_users, update_users, del_users):
        '''
        Three type of list we have new, update, del we need to update the 
        changes in both sqlite file lb_users and auto_fetch_users
        '''
        # Insert into auto fetch users 
        updatetime = datetime.now()
        params = []
        query = """insert into auto_fetch_user(user_name, nt_hash, 
                 status, added_by, updatetime) values (?,?,1,0,?)"""
        for username, hashcode in new_users:
            params.append((username, hashcode, 1, 0, updatetime))
        
        self.insert_into_autofetch_user(query, params)
        
        # Update Process
        #FIXME how to do update and delete in transaction
        query1 = """update auto_fetch_users set nt_hash = '%s' 
                    updatetime = '%s' where user_name = '%s' """
        #FIXME need to ask update time in lb_users
        query2 = "update lb_users set nt_hash = '%s' where user_name = '%s'"
        for username, hashcode in update_users:
            if configured_dict[username] == 1:
                tmp_query = query2 % (hashcode, username) 
                self.execute_query(tmp_query, LB_FILE_PATH) 
            else:
                tmp_query = query1 % (hashcode, updatetime, username) 
                db_file_path = AUTO_FETCH_FILE % cluster_id
                self.execute_query(tmp_query, db_file_path) 
        
        # Process delete 
        query1 = "update auto_fetch_users set status = 9 where user_name = '%s'"
        query2 = "update lb_users set status = 9 where user_name = '%s'"
        for username, hashcode in del_users:
            if configured_dict[username] == 1:
                tmp_query = query1 % (username) 
                db_file_path = AUTO_FETCH_FILE % cluster_id
                bdc_client.execute_query(tmp_query, db_file_path)
            else: 
                tmp_query = query2 % (username) 
                bdc_client.execute_query(tmp_query, LB_FILE_PATH) 

    def fetch_update_users(self):
        ''' This method fetch all the users from Domain controller
            find the difference from sqlite users and update them
            insert or delete them from sqlite
        '''
        while True:
            #NOTE This function update final_user_dict
            self.get_users_from_domain_controller()   
            
            #NOTE Get all the users form auto fetch sqlite file
            # This call we can avoid and can use timly basis
            self.get_users_from_sqlite()         
             
            #NOTE Difference b/w autofetch users and domain controller user
            new_users, update_users, del_users = self.get_diff_bw_dc_autofetch_users()
 
            #NOTE Insert, update, delete from sqlite files
            self.writeback_changes_into_sqlite(new_users, update_users, del_users)
 
            time.sleep(15)   
 
def main(cluster_id):
    ''' Main function '''
    bdc_client = FetchFromBDC(cluster_id)
    bdc_client.fetch_update_users()

    server_info = bdc_client.read_servers_info(cluster_id)
    username, password = bdc_client._find_root_user_info(cluster_id)
    for ip, port in server_info:
        conn = bdc_client.get_connection(ip, port, username, password)
        if conn:
            break
        time.sleep(1)
    sqluser_list = []
    sqlgroup_list = []
    user_group_mapping = {}
    final_user_dict = {}

    sqluser_list, sqlgroup_list = bdc_client.execute_query_for_users(conn)

    #STEP. PDBEdit -Lw for finding user and NT hash
    pdbuser_dict = bdc_client.read_user_using_pdbedit()

    for user in sqluser_list:
        if user in pdbuser_dict:
            final_user_dict[user] = pdbuser_dict[user]
        else:
            print "User is missing in pdbEdit list", user

    # TODO BFS Implementation
    map(bdc_client.queue.put, sqlgroup_list)
    while not bdc_client.queue.empty():
        group = bdc_client.queue.get() 
        #4. Read Users from Samba-tool for group name
        sambauser_list = bdc_client.read_user_using_samba_tool(group)
        for ug in sambauser_list:
            if ug in pdbuser_dict:
                # This is a User now check in final dict  
                if ug not in final_user_dict:
                    final_user_dict[ug] = pdbuser_dict[ug]
                else:
                    print "user is already in final user dict"
                if ug in user_group_mapping:
                    user_group_mapping[ug].append(group)
                else:
                    user_group_mapping[ug] = [group]
            else:
                # This is group fetch all the users from group 
                bdc_client.queue.put(ug)
  
    #START HERE 5. Read Users from sqlite file from lb_users table
    autofetch_user_dict, configured_dict = bdc_client.read_user_from_auto_fetch(cluster_id)

    #6. Compare sqlite users and users from
    # autofetch_user_dict and final_user_dict
    autofetch_user_item_set = set(autofetch_user_dict.items())
    final_user_item_set = set(final_user_dict.items()) 
    new_updated = final_user_item_set.difference(autofetch_user_item_set)
    new_users = set([])
    update_users = set([])
    del_users = set([])
    for username, hashcode in new_updated:
        if username in autofetch_user_dict:
            update_users.add((username, hashcode))
        else:
            new_users.add((username, hashcode))
        
    del_updated = autofetch_user_item_set.difference(final_user_item_set)
    for username, hashcode in del_updated:
        if username in final_user_dict:
            # this is the updated user handled in previous loop
            pass
        else:
            del_users.add((username, hashcode))
    
    # Insert into auto fetch users 
    updatetime = datetime.now()
    params = []
    query = "insert into auto_fetch_user(user_name, nt_hash, status, added_by, updatetime) values (?,?,1,0,?)"
    for username, hashcode in new_users:
        params.append((username, hashcode, 1, 0, updatetime))
 
    bdc_client.execute_insert_multiple(conn, query, params)
    
    # Update Process
    query1 = "update auto_fetch_users set nt_hash = '%s' updatetime = '%s' where user_name = '%s'"
    #FIXME need to ask update time in lb_users
    query2 = "update lb_users set nt_hash = '%s' where user_name = '%s'"
    for username, hashcode in update_users:
        if configured_dict[username] == 1:
            tmp_query = query2 % (hashcode, username) 
            bdc_client.execute_query(conn, tmp_query) 
        else:
            tmp_query = query1 % (hashcode, updatetime, username) 
            bdc_client.execute_query(conn, tmp_query) 
        
    # Process delete 
    query1 = "update auto_fetch_users set status = 9 where user_name = '%s'"
    query2 = "update lb_users set status = 9 where user_name = '%s'"
    for username, hashcode in del_users:
        if configured_dict[username] == 1:
            tmp_query = query1 % (username) 
            bdc_client.execute_query(conn, tmp_query)
        else: 
            tmp_query = query2 % (username) 
            bdc_client.execute_query(conn, tmp_query) 
    
if __name__ == '__main__':
    cluster_id = 3
    main(cluster_id)
