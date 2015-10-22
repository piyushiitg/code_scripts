import socket
import sys
import time
# Create a TCP/IP socket

def read_lagtime():
    lagtime_dict = {}
    if True:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_address = ('127.0.0.1', 5003)
        print 'connecting to %s port %s' % server_address
        sock.settimeout(5)
        sock.connect(server_address)
        try:
            # Receive the data in small chunks and retransmit it
            while True:
                #print "Fire get rep_leg command on cluster id 1"
                sock.sendall("get rep_lag_time 9")
                data = sock.recv(100)
                print 'received data is "%s"' % data
                break
            lag_list = data.split("\n")[1:-1]
            for value in lag_list:
                val = value.split('|')
                lagtime_dict[val[0]] = int(val[1])  
            print lagtime_dict
        except Exception, ex:
            print ex
        finally:
            # Clean up the connection
            sock.close()

def do_failover():
    if True:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_address = ('127.0.0.1', 5000)
        print 'connecting to %s port %s' % server_address
        sock.settimeout(5)
        sock.connect(server_address)
        try:
            # Receive the data in small chunks and retransmit it
            while True:
                #print "Fire get rep_leg command on cluster id 1"
                sock.sendall("command=do_recovery&clusterid=4&origin=idbcore&recovery_server_id=3")
                data = sock.recv(100)
                print 'received data is "%s"' % data
                break
        except Exception, ex:
            print ex
        finally:
            # Clean up the connection
            sock.close()

do_failover()
#read_lagtime()
