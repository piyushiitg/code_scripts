#!/usr/bin/python
#
# Copyright (C) 2012 ScalArc, Inc., all rights reserved.
#

"""This file implements the daemon for SystemMonitor
"""
import getopt
import os
import sys
import socket
import traceback
import time

import ConfigParser
#
# import modules from site-packages. iDB pacakge has to be installed before
# the following modules can be imported
#
import idb.log as log
import idb.daemon as daemon
import idb.util as util
import idb.events as events
import idb.alerts as alerts
import psutil
import crontab
from constants import SystemMonitorStat, ThresholdValue
from datetime import datetime, timedelta
# The configuration file for DB_MONITOR service
IDB_DIR_ETC = '/opt/idb/conf'
SYSTEM_MONITOR_CONF = 'system_monitor.conf'
LB_DB_FILE = "/system/lb.sqlite"
LB_SESSION_FILE = "/system/lb_session.sqlite"
CERT_FILES = [
              "/system/certs/cid_%s/client.pem", 
              "/system/certs/cid_%s/server.pem",
              "/system/certs/cid_%s/ca.pem",
             ]
# The global variable for the configuration parser
_config = None

# ###### Global Variables ##########
_debug = False
MAX_RETRY = 5
DAYS_DIFF = 0
SCRIPT_VERSION = 1.0
####################################

# Initialize logging
log.set_logging_prefix("system_monitor")
_logger = log.get_logger("system_monitor")

def _usage(msg=None):
    """Display the program's usage on stderr and exit
    """
    if msg:
        print >> sys.stderr, msg
    print >> sys.stderr, """
Usage: %s [options] [stop|restart]

Options:
    -v, --version         : Report version and exit
    -d, --debug           : Run the program in debug mode
    -h, --help            : Display help
""" % (os.path.basename(sys.argv[0]))
    sys.exit(1)


def get_config_parser(config_file, options={ }):
    """Get a config parser for the given configuration file
    """
    if not os.path.isabs(config_file):
        config_file = IDB_DIR_ETC + '/' + config_file

    if not os.path.exists(config_file):
        raise Exception('File not found: %s' % config_file)

    # NOTE: Use SafeConfigParser instead of ConfigParser to support
    # escaping of format strings e.g. % as %%
    config = ConfigParser.SafeConfigParser(options)
    config.read(config_file)
    return config

class SystemMonitorDaemon(daemon.Daemon):
    """This class runs SystemMonitor as a daemon
    """
    def __init__(self, pid_file):
        self._sleep_interval = 10
        self._mem_threshold = 75.0
        self._swap_threshold = 75.0
        self._disk_threshold = 75.0
        self._cron_job_list = []
        self._tcp_local_port_range = [32768, 61000]
        self._tcp_reserved_port_range = [4000, 5010]
        self._monitor_process_list = {}
        self._attempts_to_detect_failure = 3
        self._event_msg_dict = {}
        self._send_mail_date = datetime.now()
        super(SystemMonitorDaemon, self).__init__(pid_file)

    def run(self):
        '''Method to run the daemon
        '''
        self.get_default_options()
        try:
            # Add the logic of the daemon
            while True:
                self.validate_system_info()
                self.validate_tcp_ports_info()
                self.validate_cron_info()
                self.validate_processes()
                self.delete_unused_session_data()
                self.check_ssl_cert_exp()
                time.sleep(self._sleep_interval)
        except Exception, ex:
            _logger.error("SystemMonitorDaemon run failed: %s" % ex)
            _logger.error("%s" % (traceback.format_exc(),))

    def get_default_options(self):
        '''Read configuration file and extract default options
        '''
        try:
            self._sleep_interval = int(_config.get('default', 'sleep_interval'))
            _logger.info("Sleep interval specified: %s" % self._sleep_interval)
        except Exception, ex:
            _logger.info("No sleep interval specified: %s" % ex)

        try:
            self._mem_threshold = float(_config.get('default', 'mem_threshold'))
            _logger.info("Memory threshold specified: %s" %
                             self._mem_threshold)
        except Exception, ex:
            _logger.info("No default memory threshold specified: %s" % ex)

        try:
            self._swap_threshold = float(_config.get('default', 'swap_threshold'))
            _logger.info("Swap threshold specified: %s" %
                             self._swap_threshold)
        except Exception, ex:
            _logger.info("No default swap threshold specified: %s" % ex)

        try:
            self._disk_threshold = float(_config.get('default', 'disk_threshold'))
            _logger.info("Disk threshold specified: %s" %
                             self._disk_threshold)
        except Exception, ex:
            _logger.info("No default disk threshold specified: %s" % ex)

        try:
            self._tcp_local_port_range = \
                _config.get('default', 'tcp_local_port_range').split(',')
            _logger.info("TCP local port range specified: %s" %
                             self._tcp_local_port_range)
        except Exception, ex:
            _logger.info("No TCP local port range specified: %s" % ex)

        try:
            self._tcp_reserved_port_range = \
                _config.get('default', 'tcp_reserved_port_range').split(',')
            _logger.info("TCP reserved port range specified: %s" %
                             self._tcp_reserved_port_range)
        except Exception, ex:
            _logger.info("No TCP reserved port range specified: %s" % ex)

        try:
            self._cron_job_list = \
                _config.get('default', 'cron_job_list').split(',')
            _logger.info("Cron job list specified: %s" %
                             self._cron_job_list)
        except Exception, ex:
            _logger.info("No default cron jobs specified: %s" % ex)

        try:
            process_list = \
                _config.get('default', 'process_list').split(',')
            self._monitor_process_list = dict((x, 0) for x in process_list)
            _logger.info("Monitor process list specified: %s" %
                             process_list)
        except Exception, ex:
            _logger.info("No default monotor process specified: %s" % ex)

        try:
            self._attempts_to_detect_failure = \
                int(_config.get('default', 'attempts_to_detect_failure'))
            _logger.info("Attempts to detect failure is: %s" %
                             self._attempts_to_detect_failure)
        except Exception, ex:
            _logger.info("No default attempts to detect failure specified: %s" % ex)

        try:
            self._last_time = datetime.now()
            _logger.info("setting last time variable to now(): %s" %
                             self._last_time)
        except Exception, ex:
            _logger.info("Error in setting time to _last_time: %s" % ex)

        try:
            self._wait_time_for_session_data = \
                int(_config.get('default', 'wait_time_for_session_data'))
            _logger.info("wait time for session data: %s" %
                             self._wait_time_for_session_data)
        except Exception, ex:
            _logger.info("Error reading wait time for session data: %s" % ex)

        try:
            self._expiry_days = \
                int(_config.get('default', 'expiry_days'))
            _logger.info("expiry_days is: %s" %
                             self._expiry_days)
        except Exception, ex:
            _logger.info("Error reading wait time for session data: %s" % ex)


        try:
            self._time_interval = _config.get('default', 'time_interval')
            if len(self._time_interval) > 0 and self._time_interval.find(",") >= 0:
                self._time_interval = self._time_interval.split(",")
            _logger.info("time_interval for sending email: %s" %
                             self._time_interval)
        except Exception, ex:
            _logger.info("Error reading time interval: %s" % ex)


        #Creating instance of event which will be used by System Monitor
        self.event = events.Event()


    def validate_system_info(self):
        """This module will be used to validate system information.
        """
        hostname = socket.gethostname()
        memory = psutil.virtual_memory()
        swap = psutil.swap_memory()
        disk_partitions = psutil.disk_partitions()

        _logger.info("Hostname: %s" % repr(hostname))

        self._check_memory_consumption(memory)
        self._check_swap_consumption(swap)
        self._check_disk_consumption(disk_partitions)


    def validate_cron_info(self):
        """This module will be used to validate cron job entries presnt on the
        iDB machine.
        Function will raise an event if any of the required cron entry did not
        found.
        """
        root_cron = crontab.CronTab('root', tabfile='/etc/cron.d/idb')
        missing_list = [job for job in self._cron_job_list if not\
                            root_cron.find_command(job)]

        if missing_list:
            msg = "System cron is missing job(s): %s" % \
                    (', '.join([str(item) for item in missing_list]))
            _logger.warn(msg)
            self._send_notification(msg, SystemMonitorStat.VALIDATE_CRON_INFO)
        else:
            self._del_notification(SystemMonitorStat.VALIDATE_CRON_INFO)
        _logger.info("Cron job check complete")


    def validate_tcp_ports_info(self):
        """This module will be used to validate tcp local port as well as
        tcp reserved port range.
        Function will raise an event if any of the ports ranges are out of the
        default port ranges.
        """
        fd = open('/proc/sys/net/ipv4/ip_local_port_range')
        port_range = fd.readline()
        port_range = port_range.strip().split()

        if not (len(port_range) == 2 and \
                (port_range[0] == self._tcp_local_port_range[0] and \
                port_range[1] == self._tcp_local_port_range[1])):
            msg = "Incompatible TCP local port range: %s" % (port_range)
            _logger.warn(msg)
            self._send_notification(msg, SystemMonitorStat.INCOMPATIBLE_TCP_LOCAL_PORT_RANGE)
        else:
            self._del_notification(SystemMonitorStat.INCOMPATIBLE_TCP_LOCAL_PORT_RANGE)

        fd = open('/proc/sys/net/ipv4/ip_local_reserved_ports')
        port_range = fd.readline()
        port_range = port_range.strip().split('-')

        if not (len(port_range) == 2 and \
                (port_range[0] == self._tcp_reserved_port_range[0] and \
                port_range[1] == self._tcp_reserved_port_range[1])):
            msg = "Incompatible TCP reserved port range: %s" % (port_range)
            _logger.warn(msg)
            self._send_notification(msg, SystemMonitorStat.INCOMPATIBLE_TCP_RESERVED_PORT_RANGE)
        else:
            self._del_notification(SystemMonitorStat.INCOMPATIBLE_TCP_RESERVED_PORT_RANGE)

        _logger.info("TCP port range check complete")


    def _check_memory_consumption(self, memory):
        """This module will calculcate memory consumption and will check the
        same with threshold value. Function will raise an event if memory usage
        is grater than threshold value.
        """
        total = memory[0]
        available = memory[1]
        percentage_used = memory[2]
        used = memory[3]
        free = memory[4]
        active = memory[5]
        inactive = memory[6]
        buffers = memory[7]
        cached = memory[8]
        _logger.info("System memory usage: Total: %s, Available: %s, Used: %s"\
                    ", Free: %s, Active: %s, Inactive: %s, Buffers: %s, "
                    "Cached: %s, Used Percent: %s%%" % (total, available, used,\
                     free, active, inactive, buffers, cached, percentage_used))
        if percentage_used >= self._mem_threshold:
            #
            # If the size if greater than 1GB (1000MB), print in GB otherwise
            # print in MB
            #
            if used > ThresholdValue.USED_MEMORY:
                msg = "System is consuming %s GB (%s%%) of memory. This is " \
                        "above the system default threshold of %s%%" % \
                        (util.convert_bytes(used, 'B', 'GB'), percentage_used,
                            self._mem_threshold)
            else:
                msg = "System is consuming %s MB (%s%%) of memory. This is" \
                        "above the system default threshold of %s%%" % \
                        (util.convert_bytes(used, 'B', 'MB'), percentage_used,
                            self._mem_threshold)
            _logger.warn(msg)
            self._send_notification(msg, SystemMonitorStat.SYSTEM_MEMORY_CONSUMPTION)
        else:
            self._del_notification(SystemMonitorStat.SYSTEM_MEMORY_CONSUMPTION)

    def _check_swap_consumption(self, swap):
        """This module will calculcate swap consumption and will check the
        same with threshold value. Function will raise an event if swap usage
        is grater than threshold value.
        """
        total = swap[0]
        used = swap[1]
        free = swap[2]
        percentage_used = swap[3]
        _logger.info("Swap usage: Total: %s, Used: %s, Free: %s, "
                        "Used Percent: %s%%" % (total, used, free,
                                                    percentage_used))
        if float(percentage_used) >= self._swap_threshold:
            #
            # If the size if greater than 1GB (1000MB), print in GB
            # otherwise print in MB
            #
            if used > ThresholdValue.USED_MEMORY:
                msg = "System is consuming %s GB (%s%%) of swap. This is"\
                        "above the system default threshold %s%%" % \
                        (util.convert_bytes(used, 'B', 'GB'),
                            percentage_used,
                            self._swap_threshold)
            else:
                msg = "System is consuming %s MB (%s%%) of swap. This is"\
                        "above the system default threshold %s%%" % \
                        (util.convert_bytes(used, 'B', 'MB'),
                            percentage_used,
                            self._swap_threshold)
            _logger.warn(msg)
            self._send_notification(msg, SystemMonitorStat.SYSTEM_SWAP_CONSUMPTION)
        else:
            self._del_notification(SystemMonitorStat.SYSTEM_SWAP_CONSUMPTION)

    def _check_disk_consumption(self, disk_partitions):
        """This module will calculcate disk consumption and will check the
        same with threshold value. Function will raise an event if disk usage
        is grater than threshold value.
        """
        for partition in disk_partitions:
            path = partition[0]
            mount_point = partition[1]
            disk_usage = psutil.disk_usage(mount_point)
            total = disk_usage[0]
            used = disk_usage[1]
            free = disk_usage[2]
            percentage_used = disk_usage[3]
            _logger.info("Disk usage for %s (%s): Total: %s, Used: %s, "\
                            "Free: %s, Used Percent: %s%%" % (path,
                                mount_point,
                                total,
                                used,
                                free,
                                percentage_used))

            if percentage_used >= self._disk_threshold:
                #
                # If the size if greater than 1GB (1000MB), print in GB
                # otherwise print in MB
                #
                if used > ThresholdValue.USED_MEMORY:
                    msg = "System is consuming %s GB (%s%%) disk for %s, "\
                            "mounted at %s. This is above the system default "\
                            "threshold %s%%" % (util.convert_bytes(used, 'B', 'GB'),
                                                percentage_used, path,
                                                repr(mount_point),
                                                self._disk_threshold)
                else:
                    msg = "System is consuming %s MB (%s%%) disk for %s, "\
                            "mounted at %s. This is above the system default "\
                            "threshold %s%%" % (util.convert_bytes(used, 'B', 'MB'),
                                                percentage_used, path,
                                                repr(mount_point),
                                                self._disk_threshold)
                _logger.warn(msg)
                self._send_notification(msg, SystemMonitorStat.SYSTEM_DISK_CONSUMPTION)
            else:
                self._del_notification(SystemMonitorStat.SYSTEM_DISK_CONSUMPTION)

    def validate_processes(self):
        """This module will monitor different processes specified in config
        file and if it founds any process is not present then it will trigger
        an event"""
        try:
            stopped_list = []
            for x in self._monitor_process_list:
                cmd = 'pgrep -f "%s"' % x
                cmd_output = []
                util.cmd_runner(cmd, cmd_output)
                self._monitor_process_list[x] = 0 if cmd_output \
                                                  else self._monitor_process_list[x] + 1
                if self._monitor_process_list[x] > \
                    self._attempts_to_detect_failure:
                    self._monitor_process_list[x] = self._attempts_to_detect_failure + 1
                    _logger.warn('Crossed max attempts of detecting failure %s' \
                                    % x)
                    stopped_list.append(x)
            #
            # Special handling for idbweb_autorestart process, if we detect it has been stopped
            # we will start it and we will remove its entry from stopped_list list.
            # This removal is necessary to avoid event generation for this process.
            #
            if 'idbweb_autorestart' in stopped_list:
                _logger.debug("Starting idbweb_autorestart process")
                stopped_list.remove('idbweb_autorestart')
                idbweb_autorestart_output = []
                idbweb_autorestart_cmd = "/usr/bin/sudo /bin/sh "\
                        "/opt/idb/utils/scripts/idbweb_autorestart.sh > /dev/null 2>&1"
                util.cmd_runner(idbweb_autorestart_cmd, idbweb_autorestart_output)

            if stopped_list:
                msg = "Processes [%s] are stopped. Please contact support at "\
                        "support@scalearc.com" % \
                        (', '.join([str(item) for item in stopped_list]))
                _logger.warn(msg)
                self._send_notification(msg, SystemMonitorStat.VALIDATE_SYSTEM_PROCESS)
            else:
                self._del_notification(SystemMonitorStat.VALIDATE_SYSTEM_PROCESS)
            
            _logger.info("Check for stopped processes has been completed")

        except Exception, ex:
            _logger.error("SystemMonitorDaemon: Error occured while doing validation "\
                            " of processes %s" % ex)

    def _del_notification(self, msg_type):
        """Method to send del notifications.
            1. deleting msg_type from event message dict
            2. call reset event 
        """
        if self._event_msg_dict.has_key(msg_type):
            _logger.info("eventid searching %s"%(str(self._event_msg_dict.items())))
            status, message = self.event.del_event(msg_type, 
                                                   self._event_msg_dict[msg_type])
            if status:
                self._event_msg_dict.pop(msg_type)
                _logger.info("event deleted sucessfully")
            else:
                _logger.info("error in deleting event %s" % message)
        
    def delete_unused_session_data(self):
        ''' Delete old session data from session table
            It delete 10 min before data from self._last_time
        '''
        db_cursor = None
        sqlite_handle = None
        try:
            current_time = datetime.now()
            seconds = ((current_time - self._last_time).seconds)
            if seconds > (self._wait_time_for_session_data * 60):
                _logger.info("Deleting lb_session and lb_login_attempt data")
                sqlite_handle = util.get_sqlite_handle(LB_SESSION_FILE)
                db_cursor = sqlite_handle.cursor()
                last_time = self._last_time.strftime("%Y-%m-%d %H:%M:%S")
                query1 = "delete from lb_login_attempt where updatetime <= ?"
                query2 = "delete from lb_session where updatetime < ?"
                query_list = [query1, query2]
                retry = 0
                trans_active = False
                while retry < MAX_RETRY:
                    try:
                        if not trans_active:
                            db_cursor.execute("BEGIN TRANSACTION")
                            for query in query_list:
                                db_cursor.execute(query, (last_time,))
                            trans_active = True
                        sqlite_handle.commit()
                        self._last_time = current_time
                        break
                    except Exception, ex:
                        retry = retry + 1
                        if retry >= MAX_RETRY:
                            _logger.error("Failed to delete session and login attempt data"\
                                            ": %s" % ex)
                        else:
                            time.sleep(0.1)

            else:
                _logger.debug("Skipping session deletion operation because difference between"\
                                " current time and last time when session "\
                                "data is deleted is less than " \
                                "%s min" % (self._wait_time_for_session_data))
        except Exception, ex:
            _logger.error("Error occured while doing deletion "\
                            " of unused data from session %s" % ex)
        finally:
            if db_cursor:
                db_cursor.close()
            if sqlite_handle:
                sqlite_handle.close()
                
    def _send_notification(self, msg, msg_type, cluster_id=None, send_mail_flag=False):
        """Method to send notifications by different ways.
            1. Event based messaging
            2. Mail based messaging (Has to be implemented)
        """
        result = self.event.send_event(msg, msg_type)
        data = result['data']
        _logger.debug("SystemMonitor: event sent and result data is %s and result is %s"%(data, result ))
        if not self._event_msg_dict.has_key(msg_type):
            self._event_msg_dict[msg_type] = data['eventid']
        _logger.debug("SystemMonitor: event msg dict is %s"%(self._event_msg_dict))
        if send_mail_flag and cluster_id:
            _logger.debug("SystemMonitor: before sending email")
            self._send_email_alert(msg, cluster_id)

    def _send_email_alert(self, msg, clusterid=None):
        """Send health alert if configured
        """
        #If this is first time, we detect failure send alert
        (smtp_server, smtp_port, sender, receivers, subject, message, password) = \
              util.get_smtp_config_from_sqlite(LB_DB_FILE, clusterid)
        #(smtp_server, smtp_port, sender, receivers, subject, message, password) = \
        #    alerts.get_smtp_config()
        #subject = "ScaleArc system monitoring alert"
        if smtp_server and smtp_port and receivers:
            out = alerts.send_email(smtp_server, smtp_port, \
                  sender, receivers, subject, message, password)
        else:
            _logger.info("Email alert: mail configuration is missing")
        _logger.info("Email alert: %s, %s %s %s" % (out, smtp_server, sender, receivers))
   
    def _read_all_clusterids(self):
        '''
        Read a list of all server_ids with the status field.
        '''
        cluster_ids = []
        sqlite_handle = util.get_sqlite_handle(LB_DB_FILE)
        if not sqlite_handle:
            return cluster_ids

        db_cursor = sqlite_handle.cursor()
        query = "select clusterid from lb_clusters where status<>9 and ssl_enabled=1"
        retry = 0
        while retry < MAX_RETRY:
            try:
                db_cursor.execute(query)
                for row in db_cursor.fetchall():
                    cluster_ids.append(int(row['clusterid']))
                break
            except Exception, ex:
                retry = retry + 1
                if retry >= MAX_RETRY:
                    _logger.error("Failed to find list of all clusters: %s" % ex)
                else:
                    time.sleep(0.1)
        if db_cursor:
            db_cursor.close()
        if sqlite_handle:
            sqlite_handle.close()
        return cluster_ids
 
    def check_ssl_cert_exp(self):
        '''
        Execute a command on client cert file and get the expiry date
        Command is: "openssl x509 -noout -in /tmp/client-cert.pem -enddate"
        Output is: 
                 notAfter=Jan 11 05:50:13 2024 GMT
        '''
        try:
            cluster_ids = self._read_all_clusterids()
            cluster_msg_dict = {}
            for cluster_id in cluster_ids:
                for cert_file in CERT_FILES:
                    cert_file_path = cert_file % (cluster_id)
                    expired, send_mail = self._check_expiry_status(cert_file_path)
                    if expired:
                        if cluster_id in cluster_msg_dict:
                            cluster_msg_dict[cluster_id].append(cert_file_path)
                        else:
                            cluster_msg_dict[cluster_id] = [cert_file_path]
            if cluster_msg_dict:
                msg = "Certifcates are about to Expire for cluster_ids %s. "
                      "Please contact support at support@scalearc.com" \
                       % (cluster_msg_dict.keys().join(',') ))
                _logger.warn(msg)
                self._send_notification(msg, SystemMonitorStat.CERTIFICATE_EXPIRE, 
                                        cluster_id, send_mail)
            else:
                self._del_notification(SystemMonitorStat.CERTIFICATE_EXPIRE)
        except Exception, ex:
            _logger.info("Exception while calculating expiry time %s " % ex)

    def _check_expiry_status(self, cert_file_path):
        send_mail_flag = False
        try:
            cmd = "openssl x509 -noout -in %s -enddate" % (cert_file_path) 
            result_list = []
            util.cmd_runner(cmd, result_list)
            _logger.debug("SystemMonitor: Output of certificate command is %s" 
                            % (result_list))
            #current time in UTC
            if result_list:
                today_date = datetime.now()
                current_time = datetime.utcnow() + timedelta(minutes=5)
                
                temp_date = (result_list[0].strip()).split("=")[1]
                expiry_time = datetime.strptime(temp_date, '%b %d %H:%M:%S %Y %Z')
                
                time_diff = (expiry_time - current_time).days
                date_diff = (today_date - self._send_mail_date).days
                
                _logger.debug("SystemMonitor: Time diff from expiry time is %s and date" \
                               " difference is %s" %(time_diff, date_diff))
                if time_diff <= self._expiry_days:
                    if date_diff > DAYS_DIFF and time_diff in self._time_interval:
                        _logger.debug("SystemMonitor: Certificate is expired."\
                                        " Configuring to send email alert.")
                        send_mail_flag = True
                        self._send_mail_date = datetime.now()
                    return True, send_mail_flag
        except Exception, ex:
            _logger.info("Exception while calculating expiry time %s " % ex)
        return False, send_mail_flag

        

def main():
    # Go away if you are not root
    if not os.geteuid()==0:
        sys.exit("system_monitor: You must be root to run this script\n")

    # Parse the command line options
    try:
        opts, args = getopt.getopt(sys.argv[1:],
                            'hdv',
                            ["help", "debug", "version"])
    except:
        _usage("error parsing options")

    for opt in opts:
        if opt[0] == '-v' or opt[0] == '--version':
            print "%s: version %s" % (os.path.basename(sys.argv[0]), SCRIPT_VERSION)
            sys.exit(0)
        elif opt[0] == '-h' or opt[0] == '--help':
            _usage()
        elif opt[0] == '-d' or opt[0] == '--debug':
            global _debug
            _debug = True

    if len(args) > 2:
        _usage('Invalid args %s' % args)

    # Read the configuration file
    global _config
    _config = get_config_parser(SYSTEM_MONITOR_CONF)

    # Initialize the logger
    log.config_logging()
    system_monitor_daemon = SystemMonitorDaemon('/var/run/system_monitor.pid')
    
    if args:
        if 'stop' == args[0]:
            _logger.info("****************** SystemMonitor stopping ********************")
            system_monitor_daemon.stop()
        elif 'restart' == args[0]:
            _logger.info("***************** SystemMonitor restarting *******************")
            system_monitor_daemon.restart()
        else:
            err_msg = "Invalid command %s" % (repr(args[0]),)
            print >> sys.stderr, err_msg
            _logger.error("%s" % (err_msg,))
            sys.exit(2)
        sys.exit(0)

    if _debug:
        _logger.info("************ SystemMonitor starting (debug mode)**************")
        system_monitor_daemon.foreground()
    else:
        _logger.info("****************** SystemMonitor starting ********************")
        system_monitor_daemon.start()

if __name__ == "__main__":
    main()
