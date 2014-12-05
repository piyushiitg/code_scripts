import copy
import gevent
import socket

import pyodbc
import MySQLdb
import cx_Oracle

from .common import HealthStatus
from .core import core
from idb.cmd.alert_engine.publisher import publisher
from idb import log

log.set_logging_prefix("db_monitor.db")
_logger = log.get_logger("db_monitor.db")

CONNECT_TIMEOUT=3
database_queries_list = { 
                          "mysql": {
                                    "read_only": "show variables like 'read_only';", 
                                    "max_connections": "show variables like 'max_connections';",
                                    "max_connect_errors": "show variables like 'max_connect_errors';",
                                    "skip_name_resolve": "show variables like 'skip_name_resolve';",
                                   }
                        }
class db_interface():
    @classmethod
    def mysql(cls, ip, port, username, password, database=None, query=None, multiple_query=False):
        error = cur = con = None
        data = None
        try:
            if database:
                con = MySQLdb.connect(host=ip, connect_timeout=CONNECT_TIMEOUT,
                                        user=username, passwd=password,
                                        port=port, db=database,
                                        tryautocommit=False)
            else:
                con = MySQLdb.connect(host=ip, connect_timeout=CONNECT_TIMEOUT,
                                        user=username, passwd=password,
                                        port=port, tryautocommit=False)
            _logger.debug("Successfully logged into (%s:%s)" % (ip, port))
            if query:
                cur = con.cursor()
                _logger.debug("Executing query: %s on %s:%s" %
                                (query, ip, port))
                if multiple_query == False:
                    cur.execute(query)
                    data = cur.fetchone()
                elif type(query) == dict:
                    data = {}
                    for variable_name, query_item in query.iteritems():
                        cur.execute(query_item)
                        result = cur.fetchone()
                        if len(result) > 1:
                            data[variable_name] = result[1]
                        else:
                            data[variable_name] = None
                _logger.debug("Query successful, Result: %s " % data)
        except MySQLdb.Error as e:
            _logger.info("Failed to connect to %s:%s, using username:%s "
                            "password:%s %s" % (ip, port,
                            username, "<hidden>", e))
            error = e
        except Exception as ex:
            _logger.info("Failed to connect to host %s:%s and exception is %s" % (ip, port, ex))
            error = ex
        finally:
            if cur:
                cur.close()
            if con:
                con.close()

        if error: 
            return False, error, data
        return True, None, data

    @classmethod
    def mssql(cls, ip, port, username, password, database=None, query=None, multiple_query=False):
        error = sock = None
        cur = con = None
        data = None
        _logger.info("mssql")
        try:
            _logger.info("before Socket COnnection done")
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(CONNECT_TIMEOUT)
            sock.connect((ip, port))
            sock.close()
            _logger.info("Socket COnnection done")
        except Exception as e:
            _logger.info("Failed to connect to host %s:%s and exception is %s" % (ip, port, e))
            if sock:
                sock.close()
            return False, e, data

        con_str = "DRIVER={FreeTDS};SERVER=%s;PORT=%s;UID=%s;PWD=%s;TDS_VERSION=8.0;" \
                            % (ip, port, username, password)

        try:
            con = pyodbc.connect(con_str, timeout=CONNECT_TIMEOUT)
            _logger.info("Successfully logged into (%s:%s)" % (ip, port))
            if query:
                cur = con.cursor()
                if multiple_query == False:
                    _logger.info("Executing query: %s on %s:%s" %
                                (query, ip, port))
                    cur.execute(query)
                    data = cur.fetchone()
                elif type(query) == dict:
                    data = {}
                    for variable_name, query_item in query.iteritems():
                        cur.execute(query_item)
                        data[variable_name] = cur.fetchone()
                _logger.info("Query successful, Result: %s " % data)
        except Exception as e:
            _logger.info("Failed to connect to %s:%s, using username:%s "
                            "password:%s %s" % (ip, port,
                            username, "<hidden>", e))
            error = e
        finally:
            if cur:
                cur.close()
            if con:
                con.close()

        if error:
            return False, error, data
        return True, None, data

    @classmethod
    def oracle(cls, ip, port, username, password, database=None, query=None):
        pass

class database(object):
    """This class represents the database to be monitored"
    """
    def __init__(self, cid, db_type, db_id):
        self.error = (0, '')
        self._cid = cid
        self._db_id = db_id
        self._db_type = db_type

        self._health = None
        self.health_data = {'cid': self._cid, 'db_id': self._db_id}
        self.health_data['ident'] = '%s_%s' % (self._cid, self._db_id)
        self._last_failure = 0

    def set_attr(self, ipaddr, port, username, password,
                    dbname=None, query=None, max_failure=5, max_replication_lag=30):
        self._ip_addr = ipaddr 
        self._port = int(port)
        self._username = username 
        self._password = password
        self._database = dbname
        self._query = query
        self._max_failure = int(max_failure)
        self._max_replication_lag = max_replication_lag

    def set_health(self, status):
        if status not in [HealthStatus.UP, HealthStatus.DOWN]:
            _logger.error("Invalid health status %s" % status)

        if status is HealthStatus.DOWN or self._health is HealthStatus.DOWN:
            self.health_data['ipaddr'] = self._ip_addr
            self.health_data['port'] = self._port
   
            if not self._db_id:
                db_type = 'Cluster'
            else:
                db_type = 'Database'

            message = 'Alert: %s ' % (db_type)
            message += '(%s:%s) health is marked %s\r\n' % \
                        (self._ip_addr, self._port, status)
            health_data = copy.copy(self.health_data)

            if status is HealthStatus.DOWN:
                health_data['code'] = self.error[0]
                health_data['error'] = self.error[1]
                message += 'Reason: %s' % (self.error[1])

            health_data['status'] = status
            health_data['message'] = message
            health_data['subject'] = '%s is %s' % (db_type, status)

            publisher().publish('db_health', health_data)

        self._health = status

    def get_id(self):
        """This method returns the database name
        """
        return self._db_id
     
    def get_health(self):
        """This method returns the current health of the cluster
        """
        return self._health
 
    def execute(self, **kwargs):
        query_list = kwargs.get("query_list", None)
        db_type = self._db_type.lower()
        db_methods = [k for k,v in db_interface.__dict__.iteritems()
                        if isinstance(v, classmethod)]
        if db_type in db_methods:
            if not query_list:
                return getattr(db_interface, db_type)(self._ip_addr, self._port,
                               self._username, self._password,
                               self._database, self._query)
            else:
                if (query_list) and (db_type in query_list):
                    _logger.info("2 inside else query_list is %s and db_type is %s" %(query_list, db_type))
                    variable_monitor = True
                    queries_list = query_list.get("mysql")
                    return getattr(db_interface, db_type)(self._ip_addr, self._port,
                           self._username, self._password,
                           self._database, queries_list, variable_monitor)
            
                else:
                    return False, (0, 'Can Not Execute query for dbtype: %s' % (self._db_type)), None
        else:
            _logger.info('Unknown Database type received: %s' % (self._db_type))
            return False, (0, 'Unknown Database type received: %s' % (self._db_type)), None

    def monitor_health(self, core_status=None, db_lag=-1, variable_monitor=False):
        """This method starts monitoring the database
        """
        _logger.debug("Trying to connect to %s(%s), using username:%s, "
                "password:%s, port=%s, database:%s, query:%s" % (self._db_id,
                 self._ip_addr, self._username, self._password, self._port,
                 self._database, self._query))

        if core_status == HealthStatus.UP:
            self._last_failure = 0
            self.set_health(HealthStatus.UP)
            _logger.info("Database %s, IP: %s is healthy (From Core)" % (self._db_id,
                                                     self._ip_addr))
            if variable_monitor:
                try:
                    success, e, data = gevent.with_timeout(CONNECT_TIMEOUT, getattr(self, 'execute'), query_list=database_queries_list)
                    return data
                except Exception, ex:
                    import traceback
                    _logger.error("Exception is %s" %(traceback.format_exc()))
            return False 
        
        if self.check_replication_lag(db_lag):
            return

        try:
            success, e, data = gevent.with_timeout(CONNECT_TIMEOUT, getattr(self, 'execute'), query_list=None)
            if not success:
                self.error = e
                self.check_health_status(core_status)
        except Exception, ex:
            _logger.info("Error while trying to connect to %s(%s), using username:%s "
                            "password:%s %s" % (self._db_id, self._ip_addr,
                            self._username, "<hidden>", ex))
            self.error = (0, str(ex))
            self.check_health_status(core_status)
        else:
            # Reset last failure and health
            if core_status:
                self.error = (0, 'Database (%s) health is down for some unknown reason.'\
                                'Please contact support at support@scalearc.com' % (self._ip_addr))
                self.set_health(HealthStatus.DOWN)
            else:
                self._last_failure = 0
                self.set_health(HealthStatus.UP)
                _logger.info("Database %s, IP: %s is healthy (From network)" % (self._db_id,
                                                     self._ip_addr))

    def check_replication_lag(self, db_lag=-1):
        if not self._db_id:
            return False

        if 0 < db_lag and db_lag < self._max_replication_lag:
            return False

        if db_lag > 0:
            self.error = (0, 'Replication lag (%d) has crossed ' \
                    'the configured Max Replication Lag (%d)' \
                    % (db_lag, self._max_replication_lag))
            _logger.error("Database %s(%s) replication lag %d is above %d" \
                    % (self._db_id, self._ip_addr, db_lag, self._max_replication_lag))

        elif db_lag in [0, -6]: # Investigate Network Connection Error further
            return False

        elif db_lag in core.replication_lag_errors.keys():
            self.error = (0, core.replication_lag_errors[db_lag])
            _logger.error("Database %s(%s) replication lag error: %s" \
                    % (self._db_id, self._ip_addr, core.replication_lag_errors[db_lag]))

        else:
            self.error = (0, 'Database (%s) health is down for some replication reason.'\
                            'Please contact support at support@scalearc.com' % (self._ip_addr))
            _logger.error("Database %s(%s) Unknown replication lag error: %d" \
                    % (self._db_id, self._ip_addr, db_lag))

        self.set_health(HealthStatus.DOWN)

        return True

    def check_health_status(self, core_status):
        """Send health alert if configured
        """
        self._last_failure += 1
        if self._last_failure >= self._max_failure or core_status:
            self.set_health(HealthStatus.DOWN)
            _logger.error("Database %s(%s) health is marked down" % \
                (self._db_id, self._ip_addr))


