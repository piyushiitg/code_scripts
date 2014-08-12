import commands
import pyodbc
import Queue
from datetime import datetime
import time
import util
import sqlite3
import base64
from time import mktime
LB_FILE_PATH = '/system/lb_%s.sqlite'
AUTO_FETCH_FILE = "/system/lb_auto_fetch_users_%s.sqlite"
MAX_RETRY = 3

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

    def get_server_connection(self):
        '''
        Get any connection from any of the servers list
        ''' 
        connection = None
        for ip, port in self.server_info:
            print ip, port
            connection = self.get_connection(ip, port)
            if connection:
                return connection
        print self.server_info
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
                        print "Failed to get users"
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
        print conn_str
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
                    sqlite_handle.commit()
                    break
                except Exception, ex:
                    retry = retry + 1
                    print "Problem in inserting", ex
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
                    print query
                    db_cursor.execute(query)
                    sqlite_handle.commit()
                    print "after query"
                    break
                except Exception, ex:
                    retry = retry + 1
                    print "Problem in executing", ex
                    if retry >= MAX_RETRY:
                        print "Error"
                    else:
                        time.sleep(0.1)

            util.close_sqlite_resources(sqlite_handle, db_cursor)
        else:
            print "Problem in getting sqlite handle"
    
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
            cursor.execute("SELECT name, type FROM sys.database_principals where type = 'U' or type = 'G'")
            for username, user_type in cursor.fetchall():
                if user_type == 'U':
                    user_list.append(username)
                elif user_type == 'G':
                    group_list.append(username)
            return user_list, group_list
        except Exception, ex:
            print "Query executions are failed", ex
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
                    print ex
                    retry = retry + 1
                    if retry >= MAX_RETRY:
                        print "Error"
                    else:
                        time.sleep(0.1)

            util.close_sqlite_resources(sqlite_handle, db_cursor)
            if retry < MAX_RETRY :
                #lets decrypt this password
                root_accnt_info['password'] = PasswordUtils.decrypt(root_accnt_info['password'])
        print root_accnt_info
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
        self.server_info = self._read_servers_info()
        root_account_info = self._find_root_user_info()
        if root_account_info:
            self.root_user = root_account_info['username']
            self.root_pass = root_account_info['password']
        else:
            print "error in root username and password"
        self.connection = self.get_server_connection()
        #NOTE SqlServer
        self.sqluser_list, self.sqlgroup_list = self.get_sql_users_groups()
        print "sqlserver list", self.sqluser_list 
        #NOTE PdbEdit
        self.pdbuser_dict = self.read_user_using_pdbedit()
        print "pdbuser_dict", self.pdbuser_dict
        #NOTE Common user in final dict
        self.final_user_dict = self.get_users_bw_sql_pdb() 
        print "final user dict", self.final_user_dict, 

        #NOTE groups in queue
        map(self.queue.put, self.sqlgroup_list)
        print self.queue.queue
        # NOTE fetch all the users recursively
        self.fetch_users_recursively()

    def get_users_from_auto_fetch(self, max_retry=3):
        '''
        fetch data from auto fetch table
        '''
        auto_fetch_file = AUTO_FETCH_FILE % cluster_id
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
                    print ex
                    retry = retry + 1
                    if retry >= max_retry:
                        print "Failed to get users"
                    else:
                        time.sleep(0.1)

            util.close_sqlite_resources(auto_sqlite_handle, db_cursor)
            print sqlite_user_dict,configure_dict
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
        print "Doing insertion"
        params = []
        query = """insert or replace into lb_auto_fetch_users(user_name, nt_hash, 
                 status, added_by, update_time) values (?,?,?,?,?)"""
        for username, hashcode in new_users:
            params.append((username, hashcode, 1, 0, updatetime))
        
        self.insert_into_autofetch_user(query, params)
        
        # Update Process
        #FIXME how to do update and delete in transaction
        query1 = """update lb_auto_fetch_users set nt_hash = '%s' 
                    update_time = '%s' where user_name = '%s' """
        #FIXME need to ask update time in lb_users
        query2 = "update lb_users set nt_hash = '%s' where username = '%s'"
        for username, hashcode in update_users:
            if self.configure_dict[username] == 1:
                tmp_query = query2 % (hashcode, username) 
                db_file_path = LB_FILE_PATH % self.cluster_id 
                self.execute_query(tmp_query, db_file_path) 
                 
            tmp_query = query1 % (hashcode, updatetime, username) 
            db_file_path = AUTO_FETCH_FILE % self.cluster_id
            self.execute_query(tmp_query, db_file_path) 
        
        # Process delete 
        query1 = "update lb_auto_fetch_users set status = 9 where user_name = '%s'"
        query2 = "update lb_users set status = 9 where username = '%s'"
        for username, hashcode in del_users:
            if self.configure_dict[username] == 1:
                db_file_path = LB_FILE_PATH % self.cluster_id 
                tmp_query = query2 % (username) 
                self.execute_query(tmp_query, db_file_path) 
            
            tmp_query = query1 % (username) 
            db_file_path = AUTO_FETCH_FILE % self.cluster_id
            self.execute_query(tmp_query, db_file_path)
    
    def _inform_core_about_users(self, update_time):
        '''
        There has been role change and command to inform core of the same is
        present in self._msg_for_core. Deliver the same to core.

        prepend header as well
        header = "refresh|auto_fetch_users|%d|%s|%d" % (self._cluster_id, update_time, updateLBusers)
        '''
        msg_for_core = "refresh|%d|%s" % (self.cluster_id, update_time) 
        
        response = util.socket_cmd_runner(unix_sock="/tmp/lb_sock",
                                            command=msg_for_core)
        if response != "SUCCESS":
            print "%s Failed to inform core about %s" % (self.cluster_id, response)


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
            print "New_users-------", new_users, update_users, del_users 
            #NOTE Insert, update, delete from sqlite files
            t = datetime.now()
            updatetime = mktime(t.timetuple())+1e-6*t.microsecond
            if self.writeback_changes_into_sqlite(new_users, update_users, del_users, updatetime):
                self._inform_core_about_users(updatetime)
 
            time.sleep(15)   
 
if __name__ == '__main__':
    ''' Main function '''
    cluster_id = str(1)
    bdc_client = FetchFromBDC(cluster_id)
    bdc_client.fetch_update_users()
