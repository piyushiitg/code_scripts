from abc import ABCMeta, abstractmethod
import idb.util as util
import socket
import sys

MAX_RETRY = 3

class Database(object):
    ''' Superclass of all the database class'''
    __metaclass__ = ABCMeta
    #FIXME read constant from config
    def __init__(self, kwargs):
        self.db_type = kwargs.get('db_type', 'Test')
        self.socket_retry = kwargs.get('socket_retry', 3)
        self.query_retry = kwargs.get('query_retry', 3)
        self.socket_timeout = kwargs.get('socket_timeout', 1)
        self.query_timeout = kwargs.get('query_timeout',5)
        self.no_of_probe = kwargs.get('no_of_probe', 3)
        self.query = kwargs.get('query', 'select 1')
        self.database = kwargs.get('database','')
        self.function = kwargs.get('function','')


    def get_servers_from_sqlite(self, db_file_name, cluster_id):
        '''
        Read a list of all server_ids with the status field.
        '''
        servers_list = []
        sqlite_handle = util.get_sqlite_handle(db_file_name)
        if sqlite_handle:
            db_cursor = sqlite_handle.cursor()
            query = "select ipaddress, port, serverid from lb_servers where clusterid = %s" % (cluster_id)
            retry = 0
            while retry < MAX_RETRY:
                try:
                    db_cursor.execute(query)
                    for ip, port, serverid in db_cursor.fetchall():
                        if self.db_type == 'MSSQL':
                            new_ip = self.get_proper_server_addr(ip)
                        else:
                            new_ip = ip 
                    servers_list.append((new_ip, port, serverid))
                    break
                except Exception, ex:
                    retry = retry + 1
                    time.sleep(0.1)
            util.close_sqlite_resources(sqlite_handle, db_cursor)
        return servers_list

    def get_proper_server_addr(self, ip):
        new_ip = ''
        try:
            new_ip = socket.gethostbyname(ip)
        except Exception, ex:
            print ex
        return new_ip

    def socket_monitor(self, inputdata):
        ''' Socket level health check '''
        server_ip = inputdata.get("server_ip")
        server_port = inputdata.get("server_port")
        retry = 0
        result = False
        while retry < self.socket_retry:
            try:
                #FIXME check with socket to connect with mssql server
                test_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                test_socket.settimeout(self.socket_timeout)
                test_socket.connect((server_ip, server_port))
                result = True
                break
            except socket.error:
                retry = retry + 1
                errno, errstr = sys.exc_info()[:2]
                if errno == socket.timeout:
                    #print "Timeout has occured ", server_ip 
                    #result ="Timeout has occured %s" %server_ip
                    result = False
                else:
                    result = "Error occured while creating socket connections %s" %server_ip
                    result = False
            except Exception, ex:
                retry = retry + 1
                result = "Some Exception While using socket %s" %ex
                result = False
            finally:
                if test_socket:
                    test_socket.close()
        return result
    
    def query_monitor(self, inputdata):
        pass
