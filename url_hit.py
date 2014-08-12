import gevent
import socket
import time
from datetime import datetime
import sys
from gevent import Timeout
from gevent import monkey
import urllib2
monkey.patch_all()
from gevent.queue import Queue

urls = ['http://127.0.0.1:8000/api/v1/clusters/']*1000


class Monitor():
    def __init__(self):
        self.threads_list = []
        self.queue = Queue()
    
    def url_hit(self, url):
        try: 
            response = urllib2.urlopen(url)
            html = response.read()
            #print html
            # do something
            response.close()  # best practice to close the file
            return html
        except:
            print "-------------------"
            return None

    def start(self):
        jobs = [gevent.spawn(self.url_hit, url) for url in urls]
        gevent.joinall(jobs, timeout=100)
        l = [job.value for job in jobs]
        print l

if __name__ == '__main__':
    m = Monitor() 
    m.start()
