from factory import DatabaseFactory
from config import database_configuration
import sqlite3
from sqlite import SqliteHandler
import socket
import gevent
from gevent.pool import Group
from datetime import datetime
import time
import gevent.monkey
gevent.monkey.patch_all()
GLOBAL_SQLITE_FILE = "/system/lb.sqlite"
LOCAL_SQLITE_FILE = "/system/lb_%s.sqlite"

class GroupOfGreenlet(Group):
    def __init__(self, *args):
        super(GroupOfGreenlet, self).__init__(*args)
        self.greenlet_and_checkin_time = []
        self.all_groups = []
        self.health_status = 'Healthy' # TimeOut, Not Healthy, Partial Healthy, Error, Retry

    def spawn(self, func, *args, **kwargs):
        parent = super(GroupOfGreenlet, self)
        p = parent.spawn(func, *args, **kwargs)
        t = datetime.now()
        self.greenlet_and_checkin_time.append((p, t))
        return p

class HealthMonitor(object):

    def __init__(self):
        self.clusterwise_greenlet_health = {}
        self.clusterwise_info = {}

    def get_clusters_info(self, db_file_name):
        sqlhandler = SqliteHandler()
        query = "select cluster_id, type from lb_clusters_summary where status = 1"
        result = sqlhandler.get_sqlite_data(GLOBAL_SQLITE_FILE, query)
        return result

    def execute_capability(self, inputdata, name):
        db_obj = inputdata['db_obj']
        func_cap = db_obj.function
        result = []
        for func in func_cap:
            response = getattr(db_obj, "%s_monitor"%func)(inputdata)
            result.append((func, response))
            time.sleep(.1)
        return result

    def check_servers_health(self, cluster_id):
        gg = GroupOfGreenlet()
        while True:
            servers_list = self.clusterwise_info[cluster_id]['servers_list']
            db_obj = self.clusterwise_info[cluster_id]['db_obj']
            greenlets_dict = {}
            temp_dict = {}
            i = 0
            #print cluster_id, "start_time-->", datetime.now()
            for server_ip, server_port in servers_list:
                i = i + 1
                inputdata = {
                             'server_ip':server_ip, 
                             'server_port': int(server_port), 
                             'db_obj': db_obj,
                            }
                g1 = gg.spawn(self.execute_capability, inputdata, "g%s"%str(i)) 
                greenlets_dict[server_ip] = g1
 
            gg.join(timeout=10)
           
            for ip, g in greenlets_dict.iteritems():
                temp_dict[ip] = g.value 
            self.clusterwise_info[cluster_id]['servers_health'] = temp_dict
            #print cluster_id, "end_time-->", datetime.now()

    def start_monitor(self):
        cluster_info = self.get_clusters_info(GLOBAL_SQLITE_FILE)
        for cluster_id, cluster_type in cluster_info:
            db_config = database_configuration[cluster_type] 
            db_obj = DatabaseFactory(db_config)
            db_file_name = LOCAL_SQLITE_FILE % cluster_id
            servers_list = db_obj.get_servers_from_sqlite(db_file_name, cluster_id)
            self.clusterwise_info[cluster_id] = { 
                                                  'servers_list' : servers_list,
                                                  'cluster_type': cluster_type,
                                                  'db_obj' : db_obj,
                                                  'servers_health' : {}
                                                } 
                                                  
            a = gevent.spawn(self.check_servers_health, cluster_id)
            a.start()
        while True:
            time.sleep(2)
            print ""
            for key, value in self.clusterwise_info.iteritems():
                print key, value['servers_health']
                    

if __name__ == '__main__':
    health_monitor = HealthMonitor()
    health_monitor.start_monitor()

