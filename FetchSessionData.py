import os
from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler
import json 
import urlparse
import sqlite3
import subprocess
import datetime
from datetime import timedelta
SQLITE_FILE = "/logs/%s/cid_%s/idb.log.%s.%s.sqlite"

urls = {
        "/get_ssid":"get_ssid",
        "/get_all_records":"get_all_records", 
       }

ErrorCode = {
             '100': (0, "Wrong Arguments"), 
             '101': (0, "Internal SQLITE Exception"),
             '102': (0, "Wrong DB Type"),
            }

query_type = { "query_rec_30": ["cid","clientip_tq","username_tq","db","cache ,serverip_tq","pattern","Rule" ,"Error" ,"TimeTake" 
     ,"QueryTime" ,"Query" ,"message" ,"ssid" ,"response_size" ,"compressed_response_size" ,"intransaction",
     "query_trim_flag","Querysize","Intrans_Id","Server_SSID","timetakencom_qry","timetakenqueue","timetakenWriteFirst",
     "timetakenWrite","timetakenResponseFirst","timetakenResponse","timetakencom_wr_setmul_qry","timetakenfrst_wr_set_qry",
     "timetakencom_wr_set_qry","timetakencom_set_resp_read","timetakencom_setmul_resp_read","rows ,cmd_number","ok_pkt_msg",
     "timetaken_resp_write_first","timetaken_resp_write_last","timetaken_resp_write_last1","timetaken_resp_write_last2",
     "timetaken_resp_write_last11","timetaken_resp_write_last3","timetakenconn","querytype","sp","shardid","route_queueid"],

     "query_rec_31": ["cid", "lientip_tq","username_tq","db","Rule","Error","Query","message",
      "ssid","Querysize", "Intrans_Id","Server_SSID","rows","cmd_number","ok_pkt_msg"],

     "query_rec_40": ["cid","clientip_tq" ,"Error","severity", "message","ssid"],
     }
 
def get_sqlite_file(cluster_id):
    today_date = datetime.date.today().strftime("%Y%m%d")
    current_hour = str(datetime.datetime.now().hour)
    prev_hour = str((datetime.datetime.now() - timedelta(hours=1)).hour)
    current_hour = current_hour if len(current_hour) == 2 else '0%s'%current_hour
    prev_hour = prev_hour if len(prev_hour) == 2 else '0%s'%prev_hour
    current_date_with_hour = today_date + current_hour
    prev_date_with_hour = today_date + prev_hour
    current_sqlite_file = SQLITE_FILE % (today_date, cluster_id, cluster_id, current_date_with_hour) 
    prev_sqlite_file = SQLITE_FILE % (today_date, cluster_id, cluster_id, prev_date_with_hour) 
    return prev_sqlite_file, current_sqlite_file
    
def get_ssid(url_args):
    ''' Find out the session id with the help of ip and port
    '''
    print "Inside getssid"
    ip = url_args.get('ip', None)
    port = url_args.get('port', None)
    cluster_id = url_args.get('cluster_id', None)
    if ip and port and cluster_id:
        result = execute_command(cluster_id, ip, port)
        return result
    else:
        return ErrorCode['100']

def get_all_records(url_args):
    ''' This method fetch all the records for session id
    '''
    print "Inside get_all_records"
    ssid = url_args.get('ssid', None)
    cluster_id = url_args.get('cluster_id', None)
    dbtype = url_args.get('dbtype', None)
    if ssid and cluster_id:
        ssid = ssid[0]
        cluster_id = cluster_id[0]
        dbtype = dbtype[0]
        prev_sqlite_file, current_sqlite_file = get_sqlite_file(cluster_id)
        if not os.path.exists(prev_sqlite_file) or not os.path.exists(current_sqlite_file):
            prev_sqlite_file = "/opt/idb/idb.log.6.2014022419.sqlite"
            current_sqlite_file = "/opt/idb/idb.log.6.2014022419.sqlite"
        
        #TODO apply where condition for ssid               
        base_query = "select * from %s"
        #base_query = "select * from %s where ssid=%s"%ssid
        table_name = "query_rec_%s"%dbtype
        if not query_type.has_key(table_name):
            return ErrorCode['102']
        try:
            result_dict = {}
            query = base_query %(table_name)#, ssid)
            args = query_type[table_name]
            results = get_sqlite_data(prev_sqlite_file, query)
            if len(results) > 0:
                result_dict = convert_res_to_dict(results, args)
                return result_dict
            result = get_sqlite_data(current_sqlite_file, query)
            if len(results) > 0:
                result_dict = convert_res_to_dict(results, args)
                return result_dict
            return result_dict
        except:
            import traceback
            print traceback.format_exc()
            return ErrorCode['101']
    else:
        return ErrorCode['100']

def convert_res_to_dict(results, args):
    result_list = []
    for res in results:
        tmp_dict = {}
        index = 0
        for arg in args:
            tmp_dict[arg] = res[index]
            index = index + 1
        result_list.append(tmp_dict)
    return result_list
        

class customHTTPServer(BaseHTTPRequestHandler):
    ''' This clas will handle all the http get request
    '''
    def do_GET(self):
        '''This is the Get method 
        '''
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
         
        result = self._url_engine()
        json_foo = json.dumps(result)
        self.wfile.write(json_foo)
        return

    def _url_engine(self):
        ''' Decsion on the basis of url for executing function
        '''
        url_des = urlparse.urlparse(self.path)
        sec_url = url_des.path
        url_args = urlparse.parse_qs(url_des.query)
        if urls.has_key(sec_url):
            res = eval(urls[sec_url])(url_args)
            return res
        

def execute_command(cluster_id, ip, port):
    cmd = "/opt/idb/bin/CliProto -s /tmp/lb_sock_%s get_ssid %s %s"%(cluster_id, ip, port)
    #TODO Remove this hard coded thing
    res = """Command Buffer:get_ssid|172.16.1.5|42779|
    Error No: SSID|101418|"""
    ssid = res.split("\n")[1].split(":")[1].split("|")[1]
    return {'SSID':ssid}
    return popen_timeout(cmd)

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
 
def popen_timeout(command, timeout=120):
    """call shell command and either return its output or kill it
    If it doesn't normally exit within timeout seconds and return None
    On using this method keep in mind that the output returned has a \n appended in the end"""
    import subprocess, signal, os, time
    from datetime import datetime
    start = datetime.now()
    process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    while process.poll() is None:
        time.sleep(0.2)
        now = datetime.now()
        if (now - start).seconds> timeout:
            os.kill(process.pid, signal.SIGKILL)
            os.waitpid(-1, os.WNOHANG)
            return None
    return process.communicate()[0]


              
def main():
    try:
        server = HTTPServer(('',8080),customHTTPServer)
        print 'server started at port 8080'
        server.serve_forever()
    except KeyboardInterrupt:
        server.socket.close() 
 
if __name__=='__main__':
    main()

