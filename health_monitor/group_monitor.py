from factory import DatabaseFactory
from config import capability, database_configuration
import sqlite3
from sqlite import SqliteHandler
import socket
import gevent
from gevent.pool import Group
from datetime import datetime
import gevent.monkey
gevent.monkey.patch_all()
import time
 
GLOBAL_SQLITE_FILE = "/system/lb.sqlite"
LOCAL_SQLITE_FILE = "/system/lb_%s.sqlite"

class GroupOfGreenlet(Group):
    def __init__(self, *args):
        super(GroupOfGreenlet, self).__init__(*args)
        self.greenlet_and_checkin_time = []
        self.health_status = 'Healthy' # TimeOut, Not Healthy, Partial Healthy, Error, Retry

    def spawn(self, func, *args, **kwargs):
        parent = super(GroupOfGreenlet, self)
        p = parent.spawn(func, *args, **kwargs)
        t = datetime.now()
        self.greenlet_and_checkin_time.append((p, t))
        return p

    def monitor(self, server_ip, server_port):
        self.health_status = 'Healthy'
        return self.health_status


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
        all_groups = []
        for cluster_id, cluster_type in cluster_info:
            db_config = database_configuration[cluster_type] 
            #db_cap = capability[cluster_type]
            db_obj = DatabaseFactory(db_config)
            db_file_name = LOCAL_SQLITE_FILE % cluster_id
            servers_list = db_obj.get_servers_from_sqlite(db_file_name, cluster_id)
            print servers_list
            gg = GroupOfGreenlet()
            for server_ip, server_port in servers_list:
                inputdata = {
                             'server_ip':server_ip, 'server_port': int(server_port), 
                             'query': db_obj.query, 'database': db_obj.database, 	
                            }
                g1 = gg.spawn(cls.execute_capability, db_obj)

            gg.join(timeout=10)
            all_groups.append(gg)
            
        for gp in all_groups:
            for g, checkin_time in self.greenlet_and_checkin_time:
                print g.value, checkin_time
    

if __name__ == '__main__':
    health_monitor = HealthMonitor.start()

