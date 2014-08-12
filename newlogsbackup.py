from datetime import datetime, timedelta
import psutil
import re
import os
import shutil
import glob
import time
BASE_DIR = "/logs/"
ANALYTICS_LOG = 1
NORMAL_LOG = 2
DISK_CRITICAL = 80
MIN_USAGE = 60
MAX_USAGE = 80
EXCLUDE_DIR = ['/logs/currentlogs', '/logs/services']
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

def log_cleans_up(days, min_value, max_value, delete_analytics=False):
    ''' Log deletion from range wise
    '''
    disk_usage = GetSystemData.calculate_disk_usage()
    if (disk_usage > min_value and disk_usage < max_value) \
        or (disk_usage > max_value):

        list_of_files = GetSystemData.get_files_in_asc_order(BASE_DIR)
        date_with_specified_time = GetSystemData.get_date_with_specified_time(days)
        try:
            file_name = BASE_DIR + str(date_with_specified_time) + "/"
            index = list_of_files.index(file_name)
        except ValueError:
            print "ValueError: file is not present for finding index"
        #
        # Ignore files that are less than 180 days old, in list_of_files.
        # Find the Index of the six_months_before_date.
        #
        desired_files = list_of_files[:index]
        if len(desired_files) > 0:
            for item in desired_files:
                clean_logs_per_day(item, delete_analytics)
                disk_usage = GetSystemData.calculate_disk_usage()
                if disk_usage < min_value:
                    break
            disk_usage = GetSystemData.calculate_disk_usage()
            if disk_usage > min_value:
                for item in desired_files:
                    clean_logs_per_day(item, True)
                    disk_usage = GetSystemData.calculate_disk_usage()
                    if disk_usage < min_value:
                        break
     
def clean_logs_per_day(item, delete_analytics):     
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
def get_days():
    days_list = [180, 30, 7, 2]
    for days in days_list:
        yield days
             
def main(min_value, max_value):
    '''
    Algo: 1. Calculate disk usage
          2. If disk usage between 60 and 80 
             then 
             Delete 6 months old files in the sequence of logs and analytics
          3. If the disk usage is greater then 80 
             then 
             Delete Files from last day of the machine
    '''
    gen = get_days()
    disk_usage = GetSystemData.calculate_disk_usage()
    while True:
        if disk_usage > min_value:
            days = gen.next()
            log_cleans_up(days, min_value, max_value)
            disk_usage = GetSystemData.calculate_disk_usage()
            if disk_usage < min_value:
                gen = get_days()
	else:
            break
        time.sleep(1)


if __name__ == '__main__':
    range_tuple = (60, 80)
    min_value = range_tuple[0]
    max_value = range_tuple[1]
    while True:
        disk_usage = GetSystemData.calculate_disk_usage()
        if disk_usage > min_value:
            main(min_value)
        time.sleep(1)

