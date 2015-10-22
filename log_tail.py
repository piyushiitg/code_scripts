#!/usr/bin/python
import threading, Queue, subprocess
from dateutil import parser

#tailq = Queue.Queue(maxsize=10) # buffer at most 100 lines

def tail_forever(fn):
    p = subprocess.Popen(["tail", "-f", fn], stdout=subprocess.PIPE)
    while 1:
        line = p.stdout.readline()
        if line.rfind("Putting data in queue") > 0:
            line = line.strip()
            x = line.split(" ")
            time1 = ' '.join(x[:2])
            time1 = parser.parse('.'.join(time1.split(',')))
            time2 = parser.parse(' '.join(x[-2:]))
            t = time1 - time2
            print t.seconds,"----time1---", time1, "----time2------", time2
        if not line:
            break

def read_file(fn):
    fn = open(fn)
    lines = fn.readlines()
    for line in lines:
        line = line.strip()
        x = line.split(" ")
        time1 = ' '.join(x[:2])
        time1 = parser.parse('.'.join(time1.split(',')))
        time2 = parser.parse(' '.join(x[-2:]))
        t = time1 - time2
        print t.seconds,"----time1---", time1, "----time2------", time2
        

read_file("/tmp/socket_client.log")
#threading.Thread(target=tail_forever, args=("/logs/services/socket_client.log",)).start()

#while True:
#    import time
#    time.sleep(1)



