from factory import DatabaseFactory
from config import capability, database_configuration
import sqlite3
from sqlite import SqliteHandler
import socket

GLOBAL_SQLITE_FILE = "/system/lb.sqlite"
LOCAL_SQLITE_FILE = "/system/lb_%s.sqlite"

class HealthMonitor(object):

    @classmethod
    def get_clusters_info(cls, db_file_name):
        sqlhandler = SqliteHandler()
        query = "select cluster_id, type from lb_clusters_summary where status = 1"
        result = sqlhandler.get_sqlite_data(GLOBAL_SQLITE_FILE, query)
        return result

    @classmethod
    def execute_capability(cls, db_obj, servers_list):
        func_cap = db_obj.function
        for server_ip, server_port in servers_list: 
            inputdata = {
                          'server_ip':server_ip, 'server_port': int(server_port), 
                          'query': db_obj.query, 'database': db_obj.database, 	
                        }
            for func in func_cap:
                print "%s_monitor output ->"%func, getattr(db_obj, "%s_monitor"%func)(inputdata)

    @classmethod
    def start(cls):
        cluster_info = cls.get_clusters_info(GLOBAL_SQLITE_FILE)
        for cluster_id, cluster_type in cluster_info:
            db_config = database_configuration[cluster_type] 
            #db_cap = capability[cluster_type]
            db_obj = DatabaseFactory(db_config)
            db_file_name = LOCAL_SQLITE_FILE % cluster_id
            servers_list = db_obj.get_servers_from_sqlite(db_file_name, cluster_id)
            print servers_list
            cls.execute_capability(db_obj, servers_list)    

if __name__ == '__main__':
    health_monitor = HealthMonitor.start()


