import getopt
import sys
import json
import os
import cx_Oracle
import socket
    
def socket_monitor(server_ip, server_port):
    ''' Socket level health check '''
    retry = 0
    result = False
    test_socket = None
    while retry < 3:
        try:
            #FIXME check with socket to connect with mssql server
            test_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            test_socket.settimeout(1)
            test_socket.connect((server_ip, server_port))
            result = True
            break
        except Exception, ex:
            retry = retry + 1
            result = False
        finally:
            if test_socket:
                test_socket.close()
    return result

def oracle_handling(ip, port, username, passwd, db_name, query, sid_type, db_type):
    try:    
        cursor = None 
        result = None
        dbconn = None
        is_socket_up = False
        is_socket_up = socket_monitor(ip, port)
        if is_socket_up:
            if sid_type == 2:
                dsn = cx_Oracle.makedsn(ip, port, db_name)
                dbconn = cx_Oracle.connect(username, passwd, dsn)
            else:
                dbconn = cx_Oracle.connect(username, passwd, '%s:%s/%s'%(ip, port, db_name))
        
            if dbconn:
                cursor = dbconn.cursor()
                cursor.execute(query)
                result = cursor.fetchall()
                return True, "Success"
            else:
                return False, "Could not Get connection object"
        else:
            return False, "Socket Connection Fail"
    except Exception, ex:
        return False, "Exception while making connection"
    finally:
        if cursor:
            cursor.close()
        if dbconn:
            dbconn.close()

  
def main():
    ip = None
    port = None 
    username =  None
    password = None
    db = None 
    query = None 
    db_type = 'ORACLE'
    sid_type = 1 # 1 for service name  2 for SID
    try:
        opts, args = getopt.getopt(sys.argv[1:],
                            'hi:p:u:w:d:q:t:o:',
                            ["help", "ip=", "port=", "username=","password=", "db=","query=","type=", "sid="])
    except Exception, ex:
        print (False,  "Error in opt parser")

    for opt in opts:
        if opt[0] == '-i' or opt[0] == '--ip':
            ip = opt[1]
        elif opt[0] == '-p' or opt[0] == '--port':
            port = int(opt[1])
        elif opt[0] == '-u' or opt[0] == '--username':
            username = opt[1]
        elif opt[0] == '-w' or opt[0] == '--password':
            password = opt[1]
        elif opt[0] == '-d' or opt[0] == '--db':
            db = opt[1]
        elif opt[0] == '-q' or opt[0] == '--query':
            query = opt[1]
        elif opt[0] == '-o' or opt[0] == '--sid':
            sid_type = int(opt[1])
        elif opt[0] == '-t' or opt[0] == '--type':
            db_type = opt[1]
        elif opt[0] == '-h' or opt[0] == '--help':
            _usage()

    if ip and port and username and password and db and query:
        print oracle_handling(ip, port, username, password, db, query, sid_type, db_type)
    else:
        print (False, "Error in Arguments")


if __name__ == '__main__':
    main()   
