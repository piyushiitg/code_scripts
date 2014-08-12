import pyodbc
import socket
import sys
from datetime import datetime
def get_connection_string(server_ip, server_port):
    return "DRIVER={FreeTDS};SERVER=%s;PORT=%s;UID=%s;PWD=%s;TDS_VERSION=8.0;" \
               % (server_ip, str(server_port),"sa","info@123")

def get_connection(server_ip, port, max_retry=3):
    conn_str = get_connection_string(server_ip, port)
    retry = 0
    conn = None
    while retry < max_retry:
        try:
            print "checking with the socket"
            # check with socket to connect with mssql server
            test_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            test_socket.settimeout(1)
            test_socket.connect((server_ip, port))
            print "socket connection sucessful"
        except socket.error:
            errno, errstr = sys.exc_info()[:2]
            if errno == socket.timeout:
                print "Timeout has occured  " , errstr
            return conn
        except Exception, ex:
            print ex
            return conn
        finally:
            if test_socket:
                test_socket.close()
        print "checking with pyodbc"
        try:
            conn = pyodbc.connect(conn_str, timeout=5)
            break
        except Exception, ex:
            retry = retry + 1
            print "Was Not Able To Connect  ", ex
    print "connection is done"
    if conn:
        conn.timeout = 5
    return conn

def execute_query(conn, query):
    try:
        cursor = conn.cursor()
        cursor.execute(query)
        results = cursor.fetchall()
        return results
    except Exception, ex:
        return ex

def always_on_queries(conn, group_id):
    query1 = """select endpoint_url from sys.availability_replicas where replica_server_name like (select primary_replica from sys.dm_hadr_availability_group_states where group_id='%s') and group_id='%s'""" %( group_id,  group_id)
    print query1

    #query2 = """ select endpoint_url, primary_role_allow_connections_desc, secondary_role_allow_connections_desc from sys.availability_replicas where group_id='%s'""" % (group_id)
    query2 = """ select * from sys.availability_replicas where group_id='%s'""" % (group_id)
    print query2
    query3 = """select a.endpoint_url, b.role, b.connected_state from sys.availability_replicas a, master.sys.dm_hadr_availability_replica_states b where a.group_id = b.group_id and a.replica_id = b.replica_id and a.group_id='%s'""" %group_id
    print query3
    print "query1 finding Primary Result--->", execute_query(conn, query1) 
    print "query2 finding Information about others--->", execute_query(conn, query1) 
    print "query3 finding ip, role, health--->", execute_query(conn, query3) 

def main():
    from datetime import datetime
  
    ip = sys.argv[1]
    port = int(sys.argv[2])
    query = sys.argv[3]
    all_query = int(sys.argv[4])
    group_id = str(sys.argv[5])
    conn = get_connection(ip, port)
    start_time = datetime.now()
    if all_query:
        always_on_queries(conn, group_id) 
    else: 
        print execute_query(conn, query)
    end_time = datetime.now()
    print start_time, end_time
    conn.close()

if __name__ == '__main__':
    main()
