import os
import json 
import urlparse
import sqlite3
import subprocess
import datetime
from datetime import timedelta
LB_SQLITE_FILE = '/system/lb_%s.sqlite'

def get_sqlite_data(db_name, query):
    db_handle = get_sqlite_handle(db_name)
    cursor = db_handle.cursor()
    try:
        cursor.execute(query)
        result = cursor.fetchall()
    except Exception, ex:
        raise ex
    cursor.close()
    db_handle.close()
    return result

        
def get_sqlite_handle(db_name, timeout=None):
    '''
    Returns a sqlite handle to the recieved db_name
    '''
    try:
        if timeout:
            conn = sqlite3.connect(db_name, timeout=timeout)
        else:
            conn = sqlite3.connect(db_name)
        # obtain all results as python dictionaries
        conn.row_factory = sqlite3.Row
        return conn
    except :
        return None
 
def main():
    import sys
    cluster_id = int(sys.argv[1])
    sqlite_file = LB_SQLITE_FILE % str(cluster_id)
    
    query1 = "select vnnserver,vnnport,status,ag_id from lb_clusters where status=1 and alwayson=1 and clusterid=%s" % (cluster_id)
    print "vnnserver, port, status, ag_id------------->", get_sqlite_data(sqlite_file, query1)    

    query2 = "select serverid,ipaddress,port,type, sql2012_role_setting, health_status from lb_servers where status=1 and clusterid=%s" % (cluster_id)
    print "serverid, ip, port, type, sql2012, health_status---->", get_sqlite_data(sqlite_file, query2)

if __name__=='__main__':
    main()

