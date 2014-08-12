from datetime import datetime, timedelta
import psutil
import re
import os
import shutil
import glob
BASE_DIR = "/logs/"
ANALYTICS_LOG = 1
NORMAL_LOG = 2
DISK_CRITICAL = 80
MIN_USAGE = 60
MAX_USAGE = 80
EXCLUDE_DIR = ['/logs/currentlogs', '/logs/services']
SIX_MONTH_RULE = [180, ]
MONTHLY_RULES = range(150, 0, -30)
DAYS_RULES = range(30, 2, -1)
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
    def get_files_in_asc_order(cls, path='/logs/*'):
        ''' This is the same as ls -lrt, using glob we list files
        on the basis of modified time 
    	Return: List of files 
    	'''
    	files_list = sorted(glob.glob(path), key=os.path.getmtime)    
    	# delete EXCLUDE_DIR from desired_files
    	for ex_dir in EXCLUDE_DIR:
            try:
                files_list.remove(ex_dir)
            except ValueError:
                print "ValueError: for removing files from list"
        return files_list

class LogOperations(object):

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

		# First Check with Directory Pattern
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

    @classmethod
    def delete_files_from_dir(cls, dir_name):
		''' Iterate the dir using the os.walk
		'''
		# Step0: Create a list of directories
		# Step1: Look throgh the list in chronological order
		# Step2: Check logs file first (delete the logs for the date). If no more date left, goto Step5
		# Step3: Check disk usage. If less than 60% quit
		# Step4: Goto Step2
		# Step5: Delete analytics file (in chrono order)
		# Step6: Check disk usage. If less than 60% quit
		# Step7: Goto Step5
		# Step8: This mean that after deleting 6 months data, the disk usage is still > 80
		# Goto Step1 (with a new list of directories of last 5 months)
		gen = os.walk(dir_name)
		while True:
		   try:
			   root, dirs, files = gen.next()
			   print "root is ", root, "dirs is ", dirs, "files is ", files
			   if cls.check_log_category(root) == NORMAL_LOG:
				   for f in files:
					   path, ext = os.path.splitext(f)
					   if ext != ".sqlite":
						   os.remove(f)
		   except StopIteration:
			   print "StopIteration comes"
			   break
		   except Exception, ex:
			   print "Unexpected Exception", ex 

    @classmethod
    def delete_normal_log_files(cls, desired_files):
        ''' This function delete only normal log files and skip
            analytics files
        '''
        for item in desired_files:
            if os.path.isdir(item):
                cls.delete_files_from_dir(item)
            else:
                file_type = cls.check_log_category(item)
                if file_type == NORMAL_LOG:         
                    os.remove(item)
                else:
                    # Skip ANALYTICS_LOG file right now
                    pass
    @classmethod
    def delete_all_files(cls, desired_files):
        ''' Delete all the files and dirs those are present in the 
            system  and list
        '''
        for item in desired_files:
            if os.path.exists(item):
                if os.path.isdir(item):
                    shutil.rmtree(item)
                else:
                    os.remove(item) 

    @classmethod				
    def apply_bw_60_80_rules(cls, files_names):
        ''' This function reads days from SIX_MONTH_RULE and delete the
            files before that date in the sequence of normal log and
            analytics log files
        ''' 
        for days in SIX_MONTH_RULE:
            cls.delete_on_time_basis(days, 60, 80)

    @classmethod
    def apply_gt_80_rules(cls, file_names):
        for days in MONTHLY_RULES:
            cls.delete_on_time_basis(days, 60, 80)
            disk_usage = GetSystemData.calculate_disk_usage()
            if disk_usage < 80:
                break

        disk_usage = GetSystemData.calculate_disk_usage()
        if disk_usage > 80:
            for days in DAYS_RULES:
                cls.delete_on_time_basis(days, 80, 80)
                if disk_usage < 80:
                    break

    @classmethod
    def delete_on_time_basis(days, min_threshold, max_threshold):
        #
        # Get the calendar date of 6 months earlier e.g. 20130328 represents
	    # 28th March 2013.
        #
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
			cls.delete_normal_log_files(desired_files)
			disk_usage = GetSystemData.calculate_disk_usage()
			if ((disk_usage > min_threshold and disk_usage < max_threshold) or \
				   (disk_usage > min_threshold and min_threshold == max_threshold)):
				cls.delete_all_files(desired_files)

if __name__ == '__main__':
    '''
    Algo: 1. Calculate disk usage
          2. If disk usage between 60 and 80 
             then 
             Delete 6 months old files in the sequence of logs and analytics
          3. If the disk usage is greater then 80 
             then 
             Delete Files from last day of the machine
    '''
    disk_usage = GetSystemData.calculate_disk_usage()
    print disk_usage
    # This function will return both files an directories
    list_of_files = GetSystemData.get_files_in_asc_order(BASE_DIR + "*")
    if disk_usage > MIN_USAGE and disk_usage < MAX_USAGE:
        result = LogOperations.apply_bw_60_80_rules(list_of_files)    
    elif disk_usage > 80:
        result = apply_gt_80_rules(list_of_files)
    else:
        pass

