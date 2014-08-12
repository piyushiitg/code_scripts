
from database import Database
import MySQLdb

class Mysql(Database):
    def __init__(self, kwargs):
        super(Mysql, self).__init__(kwargs)

    def query_monitor(self, inputdata):
        pass

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

