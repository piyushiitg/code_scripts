import gevent
import socket
import time
from datetime import datetime
import sys
from gevent import Timeout
from gevent import monkey
monkey.patch_all()
from gevent.queue import Queue
result_dict = {}
servers_list = [
               ('10.0.5.11', 1433), 
               ('10.0.5.115', 1433),
               ('10.0.36.4', 1433),
               ('10.0.40.24', 1433),
               ('10.0.40.25', 1433)
              ]
class TaskComplete(Exception):
    pass

class Monitor():
    def __init__(self):
        self.threads_list = []
        self.queue = Queue()
    def health_check(self, ip, port, i):
        print ip, port
        conn = None
        try:
            # check with socket to connect with mssql server
            test_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            test_socket.settimeout(1)
            test_socket.connect((ip, port))
            result_dict[ip] = (True, i)
            return ip, True
        except socket.error:
            errno, errstr = sys.exc_info()[:2]
            if errno == socket.timeout:
                print  "Timeout has occured"
            result_dict[ip] = (False, i)
            return ip, False
            #self.queue.put_nowait(ip)
        except Exception, ex:
            print "Some Exception While using socket", ex
            result_dict[ip] = (False, i)
            return ip, False
            #self.queue.put_nowait(ip)
        finally:
            if test_socket:
                test_socket.close()
    
    def start(self, i):
        for ip, port in servers_list:
            self.threads_list.append(gevent.spawn(self.health_check,  ip, port, i))
        gevent.sleep(1)
        #while self.queue.empty():
        #    pass
        #    gevent.sleep(0)
        #    raise TaskComplete
        
    def stop(self):
        print "Killing all greenlets"
        gevent.killall(self.threads_list)

def maingreenlet():
    monit = Monitor()
    i = 0
    while True:
        current_time = datetime.now()
        try:
            gevent.with_timeout(5, monit.start, i)
            print "about to close"
        except Timeout:
            print 'Exception of timeout'
            monit.stop()
            print 'Exiting all greenlets'
        except Exception, ex:
            print "Hahahahah", ex
            monit.stop()
        end_time = datetime.now()
        #output = []
        #for thread in monit.threads_list:
        #    output.append(thread.value)
        print result_dict, (end_time - current_time).seconds
        time.sleep(1)
        i = i + 1


if __name__ == '__main__':
    maingreenlet() 
