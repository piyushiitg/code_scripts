from database import Database
import cx_Oracle
import idb.log as log

log.set_logging_prefix("health_monitor")
_logger = log.get_logger("health_monitor")

class Oracle(Database):
    def __init__(self, kwargs):
        super(Oracle, self).__init__(kwargs)
   
    def popen_timeout(self, command, timeout=7):
        """call shell command and either return its output or kill it
           If it doesn't normally exit within timeout seconds and return None
           On using this method keep in mind that the output returned has a \n appended in the end
        """
        import subprocess, signal, os, time
        from datetime import datetime
        start = datetime.now()
        process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        while process.poll() is None:
            time.sleep(0.5)
            now = datetime.now()
            if (now - start).seconds > timeout:
                os.kill(process.pid, signal.SIGKILL)
                os.waitpid(-1, os.WNOHANG)
                return str((None, "Timeout at Popen"))
        return process.communicate()[0] 

    def query_monitor(self, inputdata):
        '''
        python oracle_test.py -i 10.0.0.105 -p 1521 -u "system" -w "Info_123" -o 1 -d "orcl" -q "select 1 from dual"
        '''
        is_success = True
        dbconn = None
        cursor = None
        try:
            server_ip = inputdata['server_ip']
            server_port = inputdata['server_port']
            username = inputdata['username']
            passwd = inputdata['password']
            service_name = inputdata['service_name']
            sid_name = inputdata['sid_name']
            sid_type = inputdata['sid_type']
            db_obj = inputdata['db_obj']
            query = db_obj.query
            if sid_type == 2:
                command = "/usr/bin/python /opt/idb/utils/scripts/oracle_test.py -i '%s' -p %s -u '%s' -w '%s' -o '%s' -d '%s' -q '%s'"\
                          %(server_ip, server_port, username, passwd, sid_type, sid_name, query)
            else:
                command = "/usr/bin/python /opt/idb/utils/scripts/oracle_test.py -i '%s' -p %s -u '%s' -w '%s' -o '%s' -d '%s' -q '%s'"\
                          %(server_ip, server_port, username, passwd, sid_type, service_name, query)
            result = self.popen_timeout(command, timeout=7)
            _logger.debug("Health Monitor: Command Execute for calculating health is %s and result is %s" % (command, result))
            try:
                result = eval(result)
            except Exception, ex:
                _logger.error("Error While doing eval of result: %s" % (ex))
            if len(result) > 1 and result[0] in [True, False]:
                return result[0]
            else:
                return False
        except Exception, ex:
            _logger.error("Failed to connect or In Script Execution failed with Oracle database: %s" % (ex))
            return False 

    def query_monitor_old(self, inputdata):
        ''' Oracle Sql Level Health Monitoring
        '''
        is_success = True
        dbconn = None
        cursor = None
        try:
            server_ip = inputdata['server_ip']
            server_port = inputdata['server_port']
            username = inputdata['username']
            passwd = inputdata['password']
            service_name = inputdata['service_name']
            sid_name = inputdata['sid_name']
            sid_type = inputdata['sid_type']
            db_obj = inputdata['db_obj']
            query = db_obj.query
            _logger.debug("Health Monitor: Check with Socket Level %s %s" %(server_ip, server_port))
            result = self.socket_monitor(inputdata)
            if not result:
                _logger.error("Health Monitor: Failed with socket connection %s" % server_ip)
                return False
            _logger.debug("Health Monitor: Trying to Connect with Oracle ip %s and port %s and service_name %s"\
                         % (server_ip, server_port, service_name))

            if sid_type == 2:
                dsn = cx_Oracle.makedsn(server_ip, server_port, sid_name)
                dbconn = cx_Oracle.connect(username, passwd, dsn)
            else:
                dbconn = cx_Oracle.connect(username, passwd, '%s:%s/%s'%(server_ip, server_port, service_name))
            _logger.debug("Health Monitor: Connection with IP %s suceesful" % server_ip)
            if query:
                res = ''
                _logger.debug("Health Monitor: Executing Oracle Query %s" % query)
                cursor = dbconn.cursor()
                cursor.execute(query)
                res = cursor.fetchall()
                _logger.debug("Health Monitor: Query Executed Successfully for ip %s" % server_ip)
        except Exception, ex:
            is_success = False
            _logger.error("Failed to connect or In Query Execution failed with Oracle database: %s" % (ex))
        finally:
            if cursor:
                cursor.close()
            if dbconn:
                dbconn.close()
        return is_success
