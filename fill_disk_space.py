import os,  glob
import subprocess
from datetime import *
import psutil
EXCLUDE_DIR = ['/mylogs/currentlogs', '/mylogs/services']
BASE_DIR = "/mylogs/"
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
        return psutil.disk_usage(partition)

    @classmethod
    def get_files_in_asc_order(cls, path):
        ''' This is the same as ls -lrt, using glob we list files
        on the basis of modified time 
    	Return: List of files 
    	'''
    	files_list = sorted(glob.glob(path +"/*"), key=os.path.getmtime)    
    	# delete EXCLUDE_DIR from desired_files
    	for ex_dir in EXCLUDE_DIR:
            try:
                files_list.remove(ex_dir)
            except ValueError:
                print "ValueError: for removing files from list"
        return files_list

    @classmethod
    def fill_disk_space(cls, days, memory_size):
        cls.genrate_dirs(days)
        dir_list = cls.get_files_in_asc_order(BASE_DIR)
        sdiskusage = cls.calculate_disk_usage(partition='/')
        convert_to_gb = (1024*1024)
        total = (sdiskusage.total)/convert_to_gb
        used = sdiskusage.used/convert_to_gb
        free = sdiskusage.free/convert_to_gb
        percent = sdiskusage.percent
        required_space = ((total*60)/100) - used
        number_of_files = required_space/10
        print number_of_files
        #for d in dir_list:
        #    cls.create_file_with_size("%s/x1.txt"%d, "100M")
            
    @classmethod
    def create_file_with_size(cls, file_name, size):
        command = "sudo fallocate -l %s %s"%(size, file_name)
        print command
        process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        while process.poll() is None:
            pass

    @classmethod
    def genrate_dirs(cls, days_from):
        try:
            if not os.path.exists(BASE_DIR):
                os.mkdir(BASE_DIR)
                os.chmod(BASE_DIR, 0777)

            for i in range(days_from, 0, -1):
                dir_name = BASE_DIR + str(cls.get_date_with_specified_time(i))
                if not os.path.exists(dir_name):
                    os.mkdir(dir_name)
            if not os.path.exists(BASE_DIR + "services"):
                os.mkdir(BASE_DIR + "services")
            if not os.path.exists(BASE_DIR + "currentlogs"):
                os.mkdir(BASE_DIR + "currentlogs")
        except Exception, ex:
            print "Exception is ", ex
	

if __name__ == '__main__':
    GetSystemData.fill_disk_space(365, 100)
