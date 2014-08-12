#!/usr/bin/python
#
# Copyright (C) 2013 ScaleArc, Inc., all rights reserved.
#
"""
This file implements the daemon for LOGS_BACKUP service.
Description:
            This service monitors system's log and cache directories. It backs
            up log filews as and when required. It also cleans up coredumps and
            old log files.
Note: As per change in logic, now logs backup to ftp will not be an exclusive
        process rather, the simple logic we will use is that whichever file
        is being deleted then if ftp is configured then we will do a backup.
        Thats it.
"""
import getopt
import os
import sys
import traceback
import time
import urllib2
import ftplib
import ConfigParser
import shutil
import sqlite3
import re
import math
import glob
from datetime import datetime, timedelta
import psutil
try:
    import psutil
except:
    pass
# These can be overriden via command-line options
_debug = False
BASE_DIR = "/logs/"
ANALYTICS_LOG = 1
NORMAL_LOG = 2
DISK_CRITICAL = 80
MIN_USAGE = 60
MAX_USAGE = 80
EXCLUDE_DIR = ['/logs/currentlogs', '/logs/services']
#
# import modules from site-packages. iDB pacakge has to be installed before
# the following modules can be imported
#
import idb.log as log
import idb.daemon as daemon
import idb.util as util

# Initialize logging
log.set_logging_prefix("logs_backup")
_logger = log.get_logger("logs_backup")

########### Global Values ##################
STD_LOG_DIR = "/logs"
STD_CACHE_DIR = "/cache"
LB_INFO_DB = "/system/lb.sqlite"
FTP_TARGET_DB = "/logs/ftplog.sqlite"
NICE_CMD = "/bin/nice -n 10 "
HA_CF_PATH = "/etc/ha.d/ha.cf"
ROOT_DIR_DEFAULT_THRESHOLD = 70
SCRIPT_VERSION = "1.0"
NO_SAFETY_NET_FILE = "/opt/idb/.idb_utils_no_safety_net"
MAX_RETRY = 3
DISK_SPACE_CHECK_INTERVAL = 10
DISK_SPACE_CRITICAL_MIN = 60
DISK_SPACE_CRITICAL = 80
DAYS_LIST = [180, 30, 7, 2]

# A few global variables related to archiving files, with default values
gArchiveFilesWithPattern = ['idb.log.*', ]
gArchiveExcludeFilesWithExtension = ['sqlite', 'gz', 'tar', ]
gArchiveFilesEnabled = True
gArchiveFilesOlderThan = 3 # in days
######### End of Global Variables ##############

# The configuration file for LOGS_BACKUP service
IDB_DIR_ETC = '/opt/idb/conf'
LOGS_BACKUP_CONF = 'logs_backup.conf'

#
# FIXME: Move these patterns in the configuration file, so its easy to update it if
# a new log is created
#  
ANALYTICS_PATTERN = { 
                      'file_pattern': ["lbstats_historical_[0-9]+.sqlite",
                                       "plog_[0-9]+_prep_sbtest_[0-9]+.sqlite",
                                       "log.sqlite",
                                       "idb.log.[0-9]+.[0-9]+.sqlite",
                                       "counter.[0-9]+.sqlite",
                                      ],   
                      'directory_pattern': ['[0-9]+_sbtest_no_prep', ], 
                    }
#
# FIXME: Move these patterns in the configuration file, so its easy to update it if
# a new log is created
#  
NORMAL_LOG_PATTERN = {
              'file_pattern': 
                  ['vmstat.log', 'mpstat.log', 'pidstat.log', 'log_parser.txt', 
                  'idb.substate_err_array.log', 'count.', 'api.error',  
                  'idb.uilog.', 'idbapi.', 'idb.log.', 'idb.error.', 
                  'idb.slowtime.', 'idb.mail.', 'idb.genlog.', 'idb.alert.', 
                  'debuglogs.core.', 'corelogtxtfile_'], 
               'directory_pattern': [], 
                     }


# The global variable for the configuration parser
_config = None

def get_config_parser(config_file, options = {}):
    """Get a config parser for the given configuration file
    """
    if not os.path.isabs(config_file):
        config_file = IDB_DIR_ETC + '/' + config_file

    if not os.path.exists(config_file):
        raise Exception('LogsBackup: File not found: %s' % config_file)

    # NOTE: Use SafeConfigParser instead of ConfigParser to support
    # escaping of format strings e.g. % as %%
    config = ConfigParser.SafeConfigParser(options)
    config.read(config_file)
    return config

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

class GetSystemData(object):
    @classmethod
    def get_date_with_specified_time(cls, no_of_days=180):
        ''' Get the date before the specified time
        '''
        previous_date = (datetime.now() - timedelta(no_of_days)).date().strftime("%Y%m%d")
        return previous_date

    @classmethod
    def calculate_disk_usage(cls, partition='/'):
        ''' Calculate the disk usage
        '''
        return psutil.disk_usage(partition).percent

    @classmethod
    def get_files_in_asc_order(cls, path='/logs/'):
        ''' This is the same as ls -lrt, using glob we list files
        on the basis of modified time 
    	Return: List of files 
    	'''
    	files_list = sorted(glob.glob(path + "/*" ), key=os.path.getmtime)    
    	# delete EXCLUDE_DIR from desired_files
    	for ex_dir in EXCLUDE_DIR:
            try:
                files_list.remove(ex_dir)
            except ValueError:
                print "ValueError: for removing files from list"
        return files_list

    @classmethod
    def check_log_category(cls, file_path):
        '''
        1.  <cid>_sbtest_no_prep (which includes hour wise txt files)
        2.   All the Sqlite files ( plog_1_*.sqlite,  idb.log.1.2014032000.sqlite,  
             lbstats_historical_00.sqlite, counter.1.sqlite, log.sqlite)
        Return: Type either ANALYTICS_LOG (1) or NORMAL_LOG (2)
        '''
        #
        # FIXME: Extract the last component of the path, so that you can apply the
        # comparison only on the filename or directory name, not on the path.
        #
        #First Check with Directory Pattern
        isdir = os.path.isdir(file_path)
        if isdir:
            dirname = os.path.basename(file_path)
            dir_patterns = ANALYTICS_PATTERN['directory_pattern']
            if dir_patterns:
                for pattern in dir_patterns:
                    p = re.compile(pattern)
                    if p.match(dirname):
                        return ANALYTICS_LOG
            dir_patterns = NORMAL_LOG_PATTERN['directory_pattern']
            if dir_pattern:
                for pattern in dir_patterns:
                    p = re.compile(pattern)
                    if p.match(dirname):
                        return NORMAL_LOG
            # Check with File Pattern
            filename = os.path.basename(filepath)
            file_patterns = ANALYTICS_PATTERN['file_pattern']
            if file_patterns:
                for pattern in file_patterns:
                    if filename.startswith(pattern):
                        return ANALYTICS_LOG
            file_patterns = NORMAL_LOG_PATTERN['file_pattern']
            if file_patterns:
                for pattern in file_patterns:
                    if filename.startswith(pattern):
                        return NORMAL_LOG
            #
            #TODO If we are not identifying any pattern then mark as analytics
            # So will will avoid deletion for some time
            #
            return ANALYTICS_LOG



class LogsBackupUtils(object):
    '''
    This class implements functionality of service logs_backup
    '''
    def __init__(self):
        self._filetype_threshold = []
        self._log2ftp_info_list = [] # log info for all clusters
        self._archive_config = {}
        self._partition_to_clean = None

    def get_sleep_val_from_config(self):
        '''
        Return the sleep interval value read from the config file.
        '''
        try:
            return _config.getint("general", "sleep")
        except Exception, ex:
            _logger.error("LogsBackup: Error reading sleep interval value" \
                          " : %s" % ex)
            return 30 # default

    def _read_archival_config(self):
        '''
        Read and store per cluster archiving related config in
        self._archive_config.
        self._archive_config[<cid>] = {'archive_enabled': True/False,
                                        'archive_older_than': <n_days>}
        '''
        query = "select clusterid, archive_enabled, archive_older_than from" \
                " lb_log where status = 1"
        lb_dbhandle = util.get_sqlite_handle(LB_INFO_DB)
        db_cursor = lb_dbhandle.cursor()

        archive_info = None
        retry = 0
        while retry < MAX_RETRY:
            try:
                db_cursor.execute(query)
                for row in db_cursor.fetchall():
                    if row['archive_enabled'] == 1:
                        archive_enabled = True
                    else:
                        archive_enabled = False 
                    archive_info[row['clusterid']] = {'archive_enabled' : archive_enabled,\
                                                      'archive_older_than':int(row['archive_older_than'])}
                break
            except (Exception, sqlite3.Error) as e:
                retry = retry  + 1
                if retry >= MAX_RETRY:
                    _logger.error("LogsBackup: Failed to find archive info :" \
                                  " %s" % (e, ))
                    archive_info = None
                else:
                    time.sleep(0.1)

        lb_dbhandle.close()
        if not archive_info:
            _logger.warn("LogsBackup: Problem reading archive related info")
            return
        self._archive_config = archive_info

    def _get_archival_config(self, clusterid):
        '''
        Return a Tuple(archive_enable, archive_older_than) by looking into
        self._archive_config if there is an entry for clusterid. If not return
        the default values
        '''
        for k,v in self._archive_config.iteritems():
            if k == clusterid:
                return (self._archive_config[clusterid]['archive_enabled'], \
                        self._archive_config[clusterid]['archive_older_than'])
        return (gArchiveFilesEnabled, gArchiveFilesOlderThan)

    def get_hacf_ip(self):
        '''
        Return HA secondary pair ip address (secondary )
        '''
        if not os.path.isfile(HA_CF_PATH):
            _logger.error("LogsBackup: %s does not exist. Could not find HA" \
                          " pair IP!" % HA_CF_PATH)
            return

        cmd = "cat " + HA_CF_PATH + " | grep ucast"
        output = []
        util.cmd_runner(cmd, output)
        line = output[0].split()
        ha_ip = line[2]
        return ha_ip

    def determine_http_mode(self, ha_ip):
        '''
        Determine if we are dealing with http or https
        '''
        mode = "https://"
        location = mode + ha_ip
        try:
            urllib2.urlopen(location)
        except urllib2.URLError, ex:
            _logger.warning("LogsBackup: Could not find ha_ip with http. Will" \
                            " use https :%s" % ex)
            mode = "https://"
        return mode

    def ha_secondary_logdir_check(self, log_dirs, location):
        '''
        Check if every directory in dirs is present at the remote HA pair
        '''
        for _dir in log_dirs:
            post_data =  "createfolder=1&value=" + _dir['path']
            try:
                urllib2.urlopen(location, post_data)
            except urllib2.URLError, e:
                _logger.warning("LogsBackup: Tried to access: %s?%s : %s"\
                                 %(location, post_data, e))

    def _find_log2ftp_info(self, cid):
        '''
        Returns necessary information required to backup logs on the
        ftp server.
        '''
        lb_dbhandle = util.get_sqlite_handle(LB_INFO_DB)
        db_cursor = lb_dbhandle.cursor()
        query = "select * from lb_log where clusterid="+str(cid) + \
                " and status=1"

        log2ftp_info = None
        retry = 0
        while retry < MAX_RETRY:
            try:
                db_cursor.execute(query)
                row = db_cursor.fetchone()
                if row:
                    if row['dumpfreq'] == '' or row['ftpip'] == '' or \
                      row['ftpport'] == '' or row['username'] == '' or \
                      row['password'] == '':
                        _logger.error("Failed to find ftp info for cluster: %d"\
                                      % (cid, ))
                        return log2ftp_info

                    log2ftp_info = {}
                    log2ftp_info['cluster_id'] = cid
                    log2ftp_info['freq'] = int(row['dumpfreq'])
                    log2ftp_info['ftp_ip'] = row['ftpip']
                    log2ftp_info['ftp_port'] = int(row['ftpport'])
                    log2ftp_info['user'] = row['username']
                    log2ftp_info['pass'] = row['password']
                break
            except (Exception, sqlite3.Error) as e:
                retry = retry  + 1
                if retry >= MAX_RETRY:
                    _logger.error("LogsBackup: Failed to find ftp info for" \
                                  " cluster: %d : %s" % (cid, e))
                    log2ftp_info = None
                else:
                    time.sleep(0.1)

        lb_dbhandle.close()
        return log2ftp_info

    def _get_partition_threshold_from_config(self):
        '''
        Finds partition threshold values loaded from the configuration file.
        Make sure that partition field does not end with '/'.
        '''
        partition_threshold = []

        # TODO: Ensure that valid values for threshold are present
        for item in _config.items('partition_threshold'):
            cfg = {}
            #  ensure that partition name does not end with '/'
            if item[0][-1] == '/' and item[0] != '/':
                cfg['partition'] = item[0][:-1]
            else:
                cfg['partition'] = item[0]

            try:
                cfg['threshold'] = (int(item[1]) % 100)
            except Exception, ex:
                _logger.warn("LogsBackup: Problem while accessing " \
                             "configuration. : %s" % ex)
                continue

            # verify if this partition indeed exists
            if os.path.exists(cfg['partition']):
                partition_threshold.append(cfg.copy())

        return partition_threshold

    def _get_filetype_threshold_from_config(self):
        '''
        Returns filetype threshold values loaded from the configuration file.
        '''
        filetype_threshold = []
        for item in _config.items('filetype_threshold'):
            cfg = {}
            cfg['pattern'] = item[0]
            cfg['threshold'] = int(item[1])
            filetype_threshold.append(cfg.copy())

        return filetype_threshold

    def _get_partitions(self):
        '''
        Return a list of dictionaries containing information abouyt paritions
        with the used space.
        '''
        p = []
        try:
            p = [ i[1] for i in psutil.disk_partitions() ]
        except Exception, ex:
            _logger.error("psutil_lib_error: %s" % ex)
            return p

        disk_usage = []
        for item in p:
            used_perc = int((psutil.disk_usage(item)[3]) + 0.5)
            d = {}
            d['partition'] = item
            d['used_perc'] = used_perc
            d['threshold'] = 0
            disk_usage.append(d.copy())

        return disk_usage

    def _get_disk_cleanup_info(self):
        '''
        Check for directories where logs may be present. Create a list of such
        directories. When such a directory is found , load its corresponding
        cleanup threshold from the config file. cleanup threshold represents
        the max used space beyond which the partitions will be checked for
        cleanup.

        If no partition is provided this routine will assume / as default
        and check if it needs to be cleaned. If not, an empty list will be
        returned.
        '''
        partition_to_scan = {'partition':'', 'threshold':0, 'used_perc':0}
        output_lines = []

        partition_threshold = self._get_partition_threshold_from_config()

        if len(partition_threshold) == 0:
            _logger.error("LogsBackup: No information to cleanup partitions." \
                          " Disk cleanup skipped.")
            return None

        _logger.debug("LogsBackup: Loaded partitions threshold info: %s" \
                      % partition_threshold)

#         t1 = time.time()
#         disk_usage = self._get_partitions()
#         final_list = []
#         for i in partition_threshold:
#             for j in disk_usage:
#                 if (i['partition'] == j['partition']) and (i['threshold'] > j['used_perc']):
#                     j['threshold'] = i['threshold']
#                     final_list.append(j.copy())
#                     break
#                 else:
#                     _logger.debug("LogsBackup: Partition '%s' skipped as threshold" \
#                               " value is not reached yet." % (i['partition']))
#
#         _logger.debug("disk_usage: %s: \n took: %f" % (disk_usage, (time.time() - t1)))

#         t1 = time.time()

        # determine the partition where /logs is mounted
        command = "df -hP /logs | tail -1"
        retval = util.cmd_runner(command, output_lines)

        if (retval != 0) or (len(output_lines) == 0):
            _logger.error("LogsBackup: Problem while determining partition for /logs")
            return None

        # there will be only one line
        for line in output_lines:
            line = line.strip() # remove any spaces from both sides
            cols = line.split() # slpit the line around spaces
            _logger.debug("LogsBackup: /logs is present under partition: %s" \
                            % (cols[5], ))

            used_perc = int(cols[4][:-1]) # remove the trailing % sign
            #
            # The threshold value for this partition will be same as that for
            # /logs since it contains /logs physically.
            #
            th = 0
            for item in partition_threshold:
                if item['partition'] == '/logs':
                    th = item['threshold']
                    break

            if th == 0:
                _logger.debug("LogsBackup: No threshold value specified for :" \
                              " %s . Partition skipped." % cols[5])
                return None

            if used_perc < th:
                _logger.debug("LogsBackup: Partition '%s' skipped as threshold" \
                              " value is not reached yet." % cols[5])
                return None

            partition_to_scan['partition'] = cols[5]
            partition_to_scan['used_perc'] = used_perc
            partition_to_scan['threshold'] = th

        return partition_to_scan

    def _is_date_older_than_thirty_days(self, srcdir):
        '''
        srcdir is of form :/logs/20130619/. Return true if it was created 30
        days ago else return false.
        '''
        try:
            # ensure that last component of sub_dir is indeed in the form that
            # we can accept.
            if srcdir[-1] == '/':
                dir_creation_date = int(srcdir.split('/')[-2])
            else:
                dir_creation_date = int(srcdir.split('/')[-1])
        except:
            return False

        thirty_days = 2592000 # 30*24*60*60
        # convert it back to string form
        dir_creation_date = "%s" % dir_creation_date
        try:
            # convert dir_creation_date in seconds
            y = int(dir_creation_date[0:4])
            m = int(dir_creation_date[4:6])
            d = int(dir_creation_date[6:8])

            secs = time.mktime(y, m, d, 0, 0, 0, 0, 0, 0)
            if time.time() - secs >= thirty_days:
                return True
        except:
            pass
        return False

    def _get_filelist(self, base_dir, fl):
        '''
        Recursively scan base dir and return a list of files in base_dir
        '''
        tmp = []
        if os.path.isdir(base_dir):
            tmp = os.listdir(base_dir)

        for item in tmp:
            # deal with trailing '/' as os.listdir does not add trailing '/'
            if base_dir[-1] == '/':
                _path = base_dir + item
            else:
                _path = base_dir + '/' + item

            if os.path.isdir(_path):
                self._get_filelist(_path, fl)
            elif os.path.isfile(_path):
                fl.append(_path)

    def _archive_log_files(self, base_dir):
        '''
        Main routine which archives log files. This will be called before cleanup
        routine and runs for base_dir which can be somethig like /logs/20130619/

        However we will archive only a select patterns as specified in
        gArchiveFilesWithPattern. Similarly, we will also skip files with patterns
        as specified in gArchiveExcludeFilesWithPattern. Apart from that we will
        skip also files with '.tar' extension.
        1. load archive configuration per cluster
        2. Exclude files which need not be archived
        3. Now archive files

        Archival config is a dictionary with key being clusterid and values being
        another dict(archive=on/off, archive_older_than=n days)

        '''
        _logger.info("LogsBackup: Prepairing to archive files in %s" % (base_dir, ))
        fl = []
        self._get_filelist(base_dir, fl)

        if len(fl) == 0:
            _logger.info("LogsBackup: Directory %s is empty, nothing to archive" \
                         % (base_dir))
            return

        for item in fl:
            # exclude files with specified extensions
            bname = os.path.basename(item)
            extension = bname.split('.')[-1]
            if extension in gArchiveExcludeFilesWithExtension:
                continue

            # now check if this file matches our required extensions
            pattern_match = False
            for p in gArchiveFilesWithPattern:
                if re.match(p, bname):
                    pattern_match = True
                    break
            if not pattern_match:
                continue

            # now we will compress this file, determine its archival config
            #
            # our archival logic depends upon the fact that we can extract
            # clusterid to which a log file belongs simply from its name,
            # otherwise it would be difficult to determine as to which cluster
            # a log file belongs to.
            #
            try:
                cid = int(bname.split('.')[2])
            except:
                _logger.error("LogsBackup: Problem determining clusterid from" \
                              " file: %s while archiving it" % (item))
                continue

            archive_on, days_older_than = self._get_archival_config(cid)
            if not archive_on:
                continue
            
            _logger.debug("Archive: On for cluster: %d for files older than: %d days" % (cid, days_older_than))

            # determine timestamp of this file
            try:
                ts = bname.split('.')[3]
            except:
                _logger.error("LogsBackup: Problem determining timestamp from" \
                              " file: %s while archiving it" % (item))
                continue

            # convert days_older_than into seconds
            seconds_to_check = days_older_than * 24 * 60 * 60
            try:
                # convert dir_creation_date in seconds
                y = int(ts[0:4])
                m = int(ts[4:6])
                d = int(ts[6:8])
                h = int(ts[8:10])
                secs = time.mktime((y, m, d, h, 0, 0, 0, 0, 0))
            except Exception, ex:
                _logger.error("LogsBackup: Problem converting timestamp from" \
                              " file: %s to seconds while archiving it. Ex: %s" \
                              % (item, ex, ))
                continue

            if time.time() - secs >= seconds_to_check:
                _logger.info("LogsBackup: Creating archive: %s" % (item + '.gz'))
                try:
                    cmd = NICE_CMD + " tar -czf " + item + ".gz" + " " + item
                    output = []
                    ret = util.cmd_runner(cmd, output)
                    zipped_file = item + ".gz"
                except Exception, ex:
                    _logger.error("LogsBackup: Failed to create gzip archive of" \
                                  " file: %s, Shell Error: %s , Exception: %s" \
                                  % (item, output, ex))
                    # cleanup temporary file if it exists
                    if os.path.exists(zipped_file):
                        os.unlink(zipped_file)
                    _logger.error("LogsBackup: Problem removing file: %s :" \
                                      " %s" % (item, ex))
                    continue

                if os.path.exists(zipped_file):
                    _logger.info("LogsBackup: Archive %s : OK, removing " \
                                "source file: %s" % (zipped_file, item, ))
                    os.unlink(item)
        _logger.info("LogsBackup: Archive operation finished.")

    def _get_partition_used_space_perc(self, partition):
        '''
        Return percentage of disk space used for this partition.
        '''
        cmd = "df " + partition + " -P"
        output_lines = []
        retval  = util.cmd_runner(cmd, output_lines)
        if retval != 0:
            _logger.error("LogsBackup: Problem while getting disk space info")
            return

        # check if directories to be cleaned are present as partitions
        header_skipped = False
        for line in output_lines:
            if not header_skipped:
                header_skipped = True
                continue

            line = line.strip() # remove any spaces from both sides
            cols = line.split() # slpit the line around spaces
            try:
                return int(cols[4][:-1]) # remove the trailing % sign
            except Exception, ex:
                _logger.error("LogsBackup: Error parsing df output: %s" % ex)
                return -1

    def _is_file_skippable(self, pattern, filename):
        '''
        Return True/False whether a file of particular pattern needs to be
        skipped for cleanup based on when it was created. For e.g. as a general
        rule all files created in current hour should be skipped. In this
        routine, (if required) we may have rules indicating whether a particular
        file needs to be skipped or not.
        '''
        patterns_having_timestamp = ['idb.log.*', 'idb.alert.*', 'idb.error.*',
                                     'vmstat.log.*', 'mpstat.log.*',
                                     'pidstat.log.*','idb.uilog.*',
                                     'api.error.*']

        # skip files created in current hour
        current_hour_ts = time.strftime('%Y%m%d%H')
        #
        # should we use the timestamp as present in filename or the one we
        # can obtain via looking at it creation_time or modification_time ?
        # Right now, we will consider the ts obtained from filename.
        #
        if pattern in patterns_having_timestamp:
            if filename.find(current_hour_ts) > -1:
                return True

        return False

    def _process_file_to_be_removed(self, filename, pattern):
        '''
        Process files to be removed.
        1. There are only certain types to files that we will backup, rest will
            be removed immediately.
        2. Files to be backed up (after zipping):
                idb.log.* (have been processed)
                idb.alert.*
                idb.error.*
                idb.slowtime.*
        3. Remove files not matching any of the above patterns and return
        4. Now gzip this file and remove corresponding file.
        5. backup the gzip file.
        '''
        backable_patterns = ['idb.log.*', 'idb.alert.*', 'idb.error.*', \
                             'idb.slowtime.*', ]
        if pattern in backable_patterns:
            #
            # what to do for clusters for whom log backup is not configured.
            # we will remove them even though _backup_file_to_ftp() returned
            # false, first compress the file
            #
            cid =  int(filename.split('.')[2])
            #
            # check if log2ftp info is available for this cluster, if not remove
            # this file directly.
            #
            ftp_info = None
            for i in self._log2ftp_info_list:
                if i['cluster_id'] == cid:
                    ftp_info = i
                    break

            if not ftp_info:
                _logger.info("LogsBackup: Log2ftp information is missing. " \
                             "Removing file: %s" % filename)
                try:
                    os.unlink(filename)
                except Exception, ex:
                    _logger.error("LogsBackup: Problem removing file: %s : %s" \
                                  % (filename, ex))
                return

            # we will create a tar of filename only if its not already a tarfile
            # (ofcourse)
            zipped_file = ''
            if filename[-3:] == 'tar':
                zipped_file = filename
            else:
                try:
                    _logger.debug("LogsBackup: Creating archive: %s" % (filename + '.gz'))
                    cmd = NICE_CMD + " tar -czf " + filename + ".gz" + " " + filename
                    output = []
                    ret = util.cmd_runner(cmd, output)
                    zipped_file = filename + ".gz"
                except Exception, ex:
                    _logger.error("LogsBackup: Failed to create gzip archive of" \
                                  " file: %s, Shell Error: %s , Exception: %s" \
                                  % (filename, output, ex))
                    if os.path.exists(filename):
                        os.unlink(filename)
                        # cleanup temporary file if it exists
                    if os.path.exists(zipped_file):
                        os.unlink(zipped_file)
                    return

            # lets try to backup the tar file.
            try:
                if os.path.exists(zipped_file):
                    self._backup_file_to_ftp(zipped_file, cid, ftp_info)
            except Exception, ex:
                _logger.warn("LogsBackup: Failed to backup gzip archive: %s, ex:%s" \
                             % (zipped_file, ex, ))

            # remove both tarred as well as untarred version of file if they exist
            if os.path.exists(filename):
                os.unlink(filename)
            if os.path.exists(zipped_file):
                os.unlink(zipped_file)
        else:
            # for other patterns, we remove them
            _logger.info("LogsBackup: Removing file: %s (File not supported" \
                         " for backup to FTP)" % filename)
            if os.path.exists(filename):
                os.unlink(filename)

    def _backup_file_to_ftp(self, filename, cid, ftp_info):
        '''
        Back up file to ftp.
        '''
        try:
            session = ftplib.FTP(ftp_info['ftp_ip'])
            session.connect("",  ftp_info['ftp_port'])
            session.login(ftp_info['user'], ftp_info['pass'])
            _logger.info("LogsBackup: FTP: connected to %s@%s:%s" \
                         % (ftp_info['user'], ftp_info['ftp_ip'], \
                            session.pwd()))

        except Exception, e:
            _logger.error("LogsBackup: Could not get a valid FTP handle")
            _logger.warning("LogsBackup: Action backup to ftp will be skipped !!")
            _logger.info(e)
            return
        #
        # we will backup logs in <YYYYMMDD>/Cluster_<cid>/
        # read the timestamp for filename, all supported files are in format
        # idb.log.1.2013051401
        #
        try:
            ts = filename.split('.')[3][:8]
            cluster_dir_name = 'Cluster_' + str(cid)

            if util.check_if_ftpdir_exists(session, ts) == False:
                _logger.info("LogsBackup: Creating remote directory: %s" % ts)
                ret=session.mkd(ts)

            # anyway now we will have YYYYMMDD at the remote server, cd to it
            session.cwd(ts)

            if util.check_if_ftpdir_exists(session, cluster_dir_name) == False:
                _logger.info("LogsBackup: Creating remote directory: %s" \
                             % cluster_dir_name)
                ret=session.mkd(cluster_dir_name)
            session.cwd(cluster_dir_name)

            #extract file name from f
            dest_file = filename[filename.rfind('/') + 1:]
            _logger.info("LogsBackup: Will upload file : %s " % (dest_file))

            util.upload_file2ftp(session, filename, dest_file)

        except Exception, e:
            _logger.error("LogsBackup: FTP: backup of file: %s failed : %s" \
                          % (filename, e))
        finally:
            session.close()

    def _check_if_logfile_marked_complete(self, filename):
        '''
        Check if this sqlite file has been marked complete.
        '''
        sqlite_handle = util.get_sqlite_handle(filename)
        db_cursor = sqlite_handle.cursor()
        query = "select is_completed from analysed_records"

        file_marked_complete = False
        retry = 0
        while retry < MAX_RETRY:
            try:
                db_cursor.execute(query)
                row = db_cursor.fetchone()
                if int(row['is_completed']) == 1:
                    file_marked_complete = True
                break
            except (Exception, sqlite3.Error) as e:
                retry = retry + 1
                if retry >= MAX_RETRY:
                    _logger.info("LogsBackup: Failed to determine marked " \
                                 "status of file: %s : %s" % (filename, e))
                else:
                    time.sleep(0.1)
        sqlite_handle.close()
        return file_marked_complete

    def _get_dir_size(self, start_path = '.'):
        '''
        Returns directory size in bytes
        '''
        total_size = 0
        for dirpath, dirnames, filenames in os.walk(start_path):
            for f in filenames:
                fp = os.path.join(dirpath, f)
                total_size += os.path.getsize(fp)
        return total_size

    def _find_list_of_clusterids(self):
        '''
        Return a list of active cluster ids.
        '''
        cluster_ids = []
        if os.path.exists(LB_INFO_DB):
            sqlite_handle = util.get_sqlite_handle(LB_INFO_DB)
            db_cursor = sqlite_handle.cursor()
            query = "select clusterid from lb_clusters where status = 1"

            retry = 0
            while retry < MAX_RETRY:
                try:
                    db_cursor.execute(query)
                    for row in db_cursor.fetchall():
                        cluster_ids.append(int(row['clusterid']))
                    break
                except (Exception, sqlite3.Error) as e:
                    retry = retry + 1
                    if retry >= MAX_RETRY:
                        _logger.error("LogsBackup: Failed to find list of " \
                                      "clusterids. : %s" % e)
                    else:
                        time.sleep(0.1)
            sqlite_handle.close()
        return cluster_ids

    def _populate_log2ftp_info(self):
        '''
        Gather per clusterid log2ftp info which we will use to save logs to the
        ftp server.
        '''
        cluster_ids = self._find_list_of_clusterids()
        if len(cluster_ids) == 0:
            _logger.error("LogsBackup: Failed to obtain list of clusteids.")
            return

        # first reset self._log2ftp_info_list, we will do it in every cycle
        self._log2ftp_info_list = []

        # now for every clusterid , find log2ftp info
        for clusterid in cluster_ids:
            log2ftp_info = self._find_log2ftp_info(clusterid)
            if log2ftp_info != None:
                self._log2ftp_info_list.append(log2ftp_info.copy())

    def _check_if_dir_is_partition(self, _dir):
        '''
        Check if _dir is mounted as a separate partition
        '''
        cmd = "df -P"
        output_lines = []
        retval  = util.cmd_runner(cmd, output_lines)
        if retval != 0:
            _logger.error("LogsBackup: Problem while determining partitions to" \
                          " scan.")
            return

        # check if directories to be cleaned are present as partitions
        header_skipped = False
        for line in output_lines:
            if not header_skipped:
                header_skipped = True
                continue

            line = line.strip() # remove any spaces from both sides
            cols = line.split() # slpit the line around spaces
            if cols[5] == _dir:
                return True
        return False

    def disk_cleaner(self, days):
        '''
        Main routine which cleans up logs,cache etc. partitions/dirs when
        applicable.

        '''
        self._partition_to_clean = self._get_disk_cleanup_info()
        if not self._partition_to_clean:
            _logger.info("LogsBackup: Could not determine partitions to clean." \
                         " Skipping disk cleanup.")
            return

        _logger.debug("LogsBackup: Partitions to clean: %s" \
                      % self._partition_to_clean)

        if len(self._filetype_threshold) == 0:
            self._filetype_threshold = self._get_filetype_threshold_from_config()

        #
        # we will read log2 ftp info for all clusters everytime this routine is
        # invoked. This will help us in using modified credentials without
        # restarting service
        #
        self._populate_log2ftp_info()

        # read archiving related configuration
        self._read_archival_config()

        #
        # Specify how a particular partition/directory is to be cleaned
        #
        # there will only be a single partition where /logs is present.
        #
        if self._partition_to_clean['partition'][-1] == '/':
            base_dir = self._partition_to_clean['partition'] + 'logs'
        else:
            base_dir = self._partition_to_clean['partition'] + '/logs'

        disk_usage = GetSystemData.calculate_disk_usage(base_dir)
        for days in DAYS_LIST:
            _logger.warning("LogsBackup: Deleting logs for %s days..." \
                            % (base_dir))
            if disk_usage > DISK_SPACE_CRITICAL_MIN:
                #FIXME: If index not find for that day we need to increase or decrese the day
                # so we need to return some value on the basis of this we can decide
                self.log_cleans_up(base_dir, days, DISK_SPACE_CRITICAL_MIN, DISK_SPACE_CRITICAL)
                disk_usage = GetSystemData.calculate_disk_usage(base_dir)
                if disk_usage < DISK_SPACE_CRITICAL_MIN:
                    _logger.warning("LogsBackup: Disk status is Normal...")
                    break
	        else:
                    break
            _logger.warning("LogsBackup: Could not clean %s ...Now" \
                        " modify the Days !!" \
                        % (base_dir))
        _logger.info("LogsBackup: Disk cleaning finished")

    def log_cleans_up(self, base_dir, days, min_value, max_value, delete_analytics=False):
        ''' Log deletion from range wise
        '''
        disk_usage = GetSystemData.calculate_disk_usage(base_dir)
        if disk_usage > min_value:
            list_of_files = GetSystemData.get_files_in_asc_order(base_dir)
            date_with_specified_time = GetSystemData.get_date_with_specified_time(days)
            try:
                file_name = base_dir + str(date_with_specified_time) + "/"
                index = list_of_files.index(file_name)
            except ValueError:
                _logger.info("LogsBackup: ValueError: file is not present for finding index")
                return 
            #
            # Ignore files that are less than 180 days old, in list_of_files.
            # Find the Index of the six_months_before_date.
            #
            desired_files = list_of_files[:index]
            if len(desired_files) > 0:
                _logger.info("LogsBackup: Deleting Normal log files")
                for item in desired_files:
                    self.clean_logs_per_day(item, delete_analytics)
                    disk_usage = GetSystemData.calculate_disk_usage(base_dir)
                    if disk_usage < min_value:
                        break
                disk_usage = GetSystemData.calculate_disk_usage(base_dir)
                _logger.info("LogsBackup: Deleting Analytics log files")
                if disk_usage > min_value:
                    for item in desired_files:
                        self.clean_logs_per_day(item, True)
                        disk_usage = GetSystemData.calculate_disk_usage(base_dir)
                        if disk_usage < min_value:
                            break
     
    def clean_logs_per_day(self, item, delete_analytics):     
         ''' Delete files and dirs of given dir (item) and
             delete_analytics will tell that do we need to 
             delete analytics files or not. If it is true then
             and file is directory we delete the dir directly
         ''' 
         if os.path.exists(item):
             if os.path.isdir(item):
                 if not delete_analytics:
                     for root, dirs, files in os.walk(dir_name):
                         print "root is ", root, "dirs is ", dirs, "files is ", files
                         log_category = GetSystemData.check_log_category(root)
                         if log_category == NORMAL_LOG:
                             for f in files:
                                 log_category = GetSystemData.check_log_category(f)
                                 if log_category == NORMAL_LOG:
                                     os.remove(f)
                 else:
                     shutil.rmtree(item)
             else:
                 log_category = GetSystemData.check_log_category(item)
                 if (log_category == ANALYTICS_LOG and delete_analytics) \
                     or (log_category == NORMAL_LOG):
                     os.remove(item)

class LOGS_BACKUPDaemon(daemon.Daemon):
    """
    This class runs LOGS_BACKUP as a daemon
    """
    def run(self):

        while not os.path.exists('/system/lb.sqlite'):
            _logger.warn("LogsBackup(%d): '/system/lb.sqlite' "\
                            "does not exist " % (os.getpid(),))
            time.sleep(1)

        try:
            log_utils = LogsBackupUtils()
            sleep_interval = log_utils.get_sleep_val_from_config()
        except Exception, ex:
            _logger.error("LogsBackup : Service Initialization failed: %s"\
                               % ex)
            _logger.error("%s" % (traceback.format_exc(), ))

        while True:
            try:
                _logger.info("LogsBackup: Starting disk cleanup...")
                log_utils.disk_cleaner()

                _logger.debug("LogsBackup: Sleeping for %f seconds" \
                              % sleep_interval)
                time.sleep(sleep_interval)
            except Exception, ex:
                _logger.error("LogsBackup: Daemon run failed: %s" % ex)
                _logger.error("%s" % (traceback.format_exc(), ))
                if os.path.exists(NO_SAFETY_NET_FILE):
                    #
                    # If the debug file is present, we break out the service so
                    # that we can catch this condition in QA/Development,
                    # otherwise we loop forever.
                    #
                    break
                # We are sleeping because ...
                time.sleep(sleep_interval)

def main():
    # Go away if you are not root
    if not os.geteuid()==0:
        sys.exit("logs_backup: You must be root to run this script\n")

    # Parse the command line options
    try:
        opts, args = getopt.getopt(sys.argv[1:],
                            'hdv',
                            ["help", "debug", "version"])
    except:
        _usage("error parsing options")
    for opt in opts:
        if opt[0] == '-v' or opt[0] == '--version':
            print "%s: version %s" % (os.path.basename(sys.argv[0]), \
                                      SCRIPT_VERSION)
            sys.exit(0)
        elif opt[0] == '-h' or opt[0] == '--help':
            _usage()
        elif opt[0] == '-d' or opt[0] == '--debug':
            global _debug
            _debug = True
    if len(args) > 2:
        _usage('Invalid args %s' % args)

    # Initialize the logger
    log.config_logging()

    # Read the configuration file
    global _config
    _config = get_config_parser(LOGS_BACKUP_CONF)
    logs_backup_daemon = LOGS_BACKUPDaemon('/var/run/logs_backup.pid')

    if args:
        if 'stop' == args[0]:
            _logger.info("*********** LOGS_BACKUP stopping *****************")
            logs_backup_daemon.stop()
        elif 'restart' == args[0]:
            _logger.info("************ LOGS_BACKUP restarting **************")
            logs_backup_daemon.restart()
        else:
            err_msg = "Invalid command %s" % (repr(args[0]),)
            print >> sys.stderr, err_msg
            _logger.error("%s" % (err_msg,))
            sys.exit(2)
        sys.exit(0)

    if _debug:
        _logger.info("************ LOGS_BACKUP starting (debug mode)***********"
                      "***")
        logs_backup_daemon.foreground()
    else:
        _logger.info("****************** LOGS_BACKUP starting ****************"
                      "**")
        logs_backup_daemon.start()
