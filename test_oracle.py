import cx_Oracle
import sys
def create_connection(server_info):
    ''' Create a connection with oracle server
    '''
    db_conn = None
    server_ip = server_info["server_ip"]
    server_port = server_info["server_port"]
    username = server_info['username']
    passwd = server_info['password']
    service_name = server_info['service_name']
    sid_name = server_info['sid_name']
    sid_type = server_info['sid_type']
    if sid_type == 1:
        db_name = service_name
    else:
        db_name = sid_name
    try:
        if sid_type == 2:
            dsn = cx_Oracle.makedsn(server_ip, server_port, db_name)
            dbconn = cx_Oracle.connect(username, passwd, dsn)
        else:
            dbconn = cx_Oracle.connect(username, passwd, '%s:%s/%s'%(server_ip, server_port, db_name))
    except Exception, ex:
        print "Exception while creating connection with Oracle %s" %ex

    return dbconn

def execute_query(query, connection):
    """ Execute the Query and return the response
    """
    result = None
    try:
        cursor = connection.cursor()
        cursor.execute(query)
        result = cursor.fetchall()
        return result
    except Exception, ex:
        print "Exception while executing the query %s and ex is %s" %(query, ex)
    finally:
        if cursor:
            cursor.close()

    return result

def main():
    server_ip = sys.argv[1]
    server_port = int(sys.argv[2])
    username = sys.argv[3]
    password = sys.argv[4]
    sid_type = int(sys.argv[5]) #2 for SID and 1 for service name
    service_name = sys.argv[6]
    sid_name = sys.argv[7]
    query = sys.argv[8]
    serverinfo = {"server_ip": server_ip,
            "server_port": server_port,
            "username": username,
            "password": password,
            "sid_type" : sid_type,
            "service_name": service_name,
            "sid_name": sid_name,
                 }

    conn = create_connection(serverinfo)
    print execute_query(conn, query)
    conn.close()
