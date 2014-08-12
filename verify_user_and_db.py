import MySQLdb
import sys
import json
import os
def connect_and_execute_command(ip, port, username, passwd, db_name=None, query=None, 
                                is_ssl_enable=0, client_cert=None, client_key=None):
    '''
    Connect to Mysql Server and execute the query if present.
    '''
    try:
        if is_ssl_enable:
            if os.path.exists(client_cert) and os.path.exists(client_key):
                ssl = {"cert": client_cert, "key": client_key} 

                if db_name:
                    dbconn = MySQLdb.Connect(host=ip,connect_timeout = 5,port=port,\
                             user=username,passwd=passwd, db=db_name, ssl=ssl)
                elif query:
                    dbconn = MySQLdb.Connect(host=ip,connect_timeout = 5,port=port,\
                             user=username,passwd=passwd, ssl=ssl)
                else:
                    dbconn = MySQLdb.Connect(host=ip,connect_timeout = 5,port=port,\
                             user=username,passwd=passwd, ssl=ssl)
                    return  "Authenticated"
            else:
                return "No certificate file present"
        else:
            if db_name:
                dbconn = MySQLdb.Connect(host=ip,connect_timeout = 5,port=port,\
                         user=username,passwd=passwd, db=db_name)
            elif query:
                dbconn = MySQLdb.Connect(host=ip,connect_timeout = 5,port=port,\
                         user=username,passwd=passwd)
            else:
                dbconn = MySQLdb.Connect(host=ip,connect_timeout = 5,port=port,\
                         user=username,passwd=passwd)
                return  "Authenticated"
             
        cursor = dbconn.cursor(MySQLdb.cursors.DictCursor)
    except Exception,ex:
        #_logger.error("Failed to connect to db %s@%s:%d: %s" %\
        #(username, ip, port, ex))
        return str(ex)

    result = None
    try:
        cursor.execute(query)
        result = cursor.fetchall()
    except Exception, ex:
        result = str(ex)
        #_logger.error("Failed to execute query %s: %s" % (query, ex))
    finally:
        cursor.close()
        dbconn.close()
    new_result = None
    try:
        new_result = json.dumps(list(result))
        return new_result
    except:
        return result

if __name__ == '__main__':
    args = sys.argv
    if len(args) < 9:
        print "Insufficent argument: Command should like ip port username passwd db query is_ssl_enble cert key"
    try:
        if len(args) >= 9:
            ip = args[1]
            port = int(args[2])
            username =  args[3]
            passwd = args[4]
            db = None if args[5] == 'None' else args[5]
            query =None if args[6] == 'None' else args[6]
            is_ssl = 0 if args[7] == 'None' else int(args[7])
            cert = None if args[8] == 'None' else args[8]
            key = None if args[9] == 'None' else args[9]
            print connect_and_execute_command(ip, port, username, passwd, db, query, is_ssl, cert, key)
        else:
            print "Wrong number of parameter"
    except Exception, ex:
        print "Arguement Parsing Error:", ex

    
