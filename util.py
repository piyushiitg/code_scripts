#!/usr/bin/python
#
# Copyright (C) 2013 ScaleArc, Inc., all rights reserved.
#
from __future__ import division

import os, time, operator, re, subprocess
import sqlite3, hashlib, sys, socket, errno
import datetime, json
import math
import socket, fcntl, struct

import idb.exception as idb_exception
import idb.log as log

# Initialize logging
_logger = log.get_logger("lib.util", relative_name=True)


def convert_bytes(value, from_format=None, to_format=None):
    """Converts between different data size formats.
    Can raise idb.exception.InternalException
    :returns: the value in the new format. Rounds off to 2 decimal points.
    """
    #
    # Check that the value to be converted is valid.
    #
    try:
        value = int(math.ceil(float(value)))
    except ValueError:
        raise idb_exception.InternalException("Invalid value %s. " +\
                "Must be an integer" %value)

    if value == 0:
        return 0

    # Capitalize the first letter of the size format e.g. kB-->KB
    to_format =  to_format[0].upper() + to_format[1:]
    from_format =  from_format[0].upper() + from_format[1:]

    # Check that the format is valid.
    if from_format not in ['B', 'KB', 'MB', 'GB', 'KiB', 'MiB', 'GiB']:
        raise idb_exception.InternalException(("Invalid format %s: " + \
                "Must be B, KB, MB GB, KiB, MiB or GiB") % (repr(from_format),))

    if to_format not in ['B', 'KB', 'MB', 'GB', 'KiB', 'MiB', 'GiB']:
        raise idb_exception.InternalException(("Invalid format %s: " + \
                "Must be B, KB, MB GB, KiB, MiB or GiB") % (repr(to_format),))

    # Convert Bytes to the given format.
    if from_format == 'B':
        if to_format in ['KB', 'KiB']:
            value = value/1024
        elif to_format in ['MB', 'MiB']:
            value = value/1048576
        elif to_format in ['GB', 'GiB']:
            value = value/1073741824
    elif from_format in ['KB', 'KiB']:
        if to_format == 'B':
            value = value*1024
        elif to_format in ['MB', 'MiB']:
            value = value/1024
        elif to_format in ['GB', 'GiB']:
            value = value/1048576
    elif from_format in ['MB', 'MiB']:
        if to_format == 'B':
            value = value*1048576
        elif to_format in ['KB', 'KiB']:
            value = value*1024
        elif to_format in ['GB', 'GiB']:
            value = value/1024
    elif from_format in ['GB', 'GiB']:
        if to_format == 'B':
            value = value*1073741824
        elif to_format in ['KB', 'KiB']:
            value = value*1048576
        elif to_format in ['MB', 'MiB']:
            value = value*1024
    # Round up the value.
    #return int(math.ceil(value))
    return round(value, 1)


def ioctl(fd, code, fmt, *input):
    """Run an ioctl command
    fmt is defined in http://docs.python.org/library/struct.html
    """
    data = struct.pack(fmt, *input)
    data = fcntl.ioctl(fd.fileno(), code, data)
    return struct.unpack(fmt, data)


def round_bytes(value):
    """This function rounds off a the value to the nearest power of 2
    """
    if type(value) != int:
        raise TypeError("value should be an integer")
    value = value - 1
    value |= value >> 1
    value |= value >> 2
    value |= value >> 4
    value |= value >> 8
    value |= value >> 16
    value = value + 1
    return value


def uniqify_list_fast(seq):
    """Uniqify a list without preserving order
    """
    return list(set(seq))


def list_subdirectories(root_dir):
    '''
    Returns the list of unique sub-directories under root_dir sorted
    according to their date of modification
    '''
    sub_dirs = []
    if os.path.exists(root_dir) == False:
        return None
    for name in os.listdir(root_dir):
        if os.path.isdir(os.path.join(root_dir, name)):
            full_path = root_dir + name
            mtime = os.path.getmtime(full_path)
            tmp = {'path':full_path, 'mtime':mtime}
            sub_dirs.append(tmp)

    # sort the directories according to their date of modification
    sorted(sub_dirs, key=operator.itemgetter('mtime'), reverse=False)
    return sub_dirs

def set_time_zone(timezone="Asia/Calcutta"):
    '''
    Sets the time zone for the system. Default is 'ASIA/CALCUTTA'
    '''
    os.environ['TZ'] = timezone
    time.tzset()

def get_current_time():
    '''
    Return current localtime as string. Time inlcudes year+month+date+hour+
    minute+seconds
    '''
    return str(time.strftime("%Y%m%d%H%M%S"))

def get_time_formats():
        '''
        Return today's,yesterday's and current hour time in format
        "20120323"
        '''
        t1 = datetime.datetime.now()
        tdate = t1.strftime("%Y%m%d")
        pdate = (t1 - datetime.timedelta(days=1)).strftime("%Y%m%d")
        chour = t1.strftime("%Y%m%d%H")

        return tdate, pdate, chour

def get_previous_hour():
    '''
    Returns previous hour in for "year-month-date-hour"
    '''
    t1 = datetime.datetime.now()
    phour = t1 - datetime.timedelta(hours=1)
    return str(phour.strftime("%Y%m%d%H"))

def get_current_hour():
    '''
    Returns current hour
    '''
    return (str(time.strftime("%Y%m%d%H")))

def get_today():
    '''
    Returns todays date in year-month-date format
    '''
    return (str(time.strftime("%Y%m%d")))

def get_yesterday():
    '''
    Returns yesterday in year-month-date format
    '''
    t1 = datetime.datetime.now()
    return ((t1 - datetime.timedelta(days=1)).strftime("%Y%m%d"))

def get_day_before_yesterday():
    '''
    Returns day_before_yesterday in year-month-date format
    '''
    t1 = datetime.datetime.now()
    return ((t1 - datetime.timedelta(days=2)).strftime("%Y%m%d"))

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

def substr (s, start, length=None):
    """Returns the portion of string specified by the start and length
    parameters.
    """
    if len(s) >= start:
        return False
    if not length:
        return s[start:]
    elif length > 0:
        return s[start:start + length]
    else:
        return s[start:length]

def multiple_replace(subject, replacement_dict):
    '''
    Usage:
        subject = "Hello how are you ?"

        replacement_dict = {
                    "Hello" : "Hi",
                    "how" : "where",
                    "are" : "do",
                    "you" : "you live"
                    }
        This routine will replace every occurrence of keys from replacement_dict in subject
        with the corresponding values of replacement_dict.

        Returns the modified subject
    '''
    pattern = "|".join(map(re.escape, replacement_dict.keys()))
    return re.sub(pattern, lambda m: replacement_dict[m.group()], subject)

def md5_for_file(file, block_size=2 ** 20):
    '''
    Returns md5 hash of a file
    '''
    f = open(file, "rb")
    if not f:
        return None

    md5 = hashlib.md5()
    while True:
        data = f.read(block_size)
        if not data:
            break
        md5.update(data)
    return md5.hexdigest()

def get_dirsize(start_path='.'):
    '''
    Returns directory size in bytes
    '''
    total_size = 0
    try:
        for dirpath, dirnames, filenames in os.walk(start_path):
            for f in filenames:
                fp = os.path.join(dirpath, f)
                total_size += os.path.getsize(fp)
    except:
        pass
    finally:
        return total_size

def is_exe(path):
    """This function check if the path is an executable
    :returns: True if the path is an executable, False otherwise
    """
    return os.path.exists(path) and os.access(path, os.X_OK)

def which(program):
    """This function checks if a program exists and retuns the absolute path
    of the program
    :returns: A string containing the path of the executable. Returns None or
    error.
    """
    fpath, fname = os.path.split(program)
    if fpath:
        if is_exe(program):
            return program
    else:
        paths = os.environ["PATH"].split(os.pathsep)
        # Add some common paths to the list
        paths.extend(['/bin', '/sbin', '/usr/bin', '/usr/sbin',
            '/usr/local/bin', '/opt/idb/bin'])
        paths = uniqify_list_fast(paths)
        for path in paths:
            exe_file = os.path.join(path, program)
            if is_exe(exe_file):
                return exe_file
    return None


def execute_command(cmd_list, assert_on_retcode=True):
    """Executes a command specified in the 'cmd_list'
       :param cmd_list: a list containing the command and arguments
       :raises Exception: CommandException when the command returns an error or
                          OSError
       :rtype: a tuple of stdout, stderr, returncode
    """
    try:
        # Find the absolute path of the program
        program_path = which(cmd_list[0])
        if program_path:
            cmd_list[0] = program_path
    except IndexError:
        pass

    _logger.debug("Executing command: %s" % cmd_list)
    #
    # If close_fds is True,  all file descriptors except 0, 1 and 2 will be
    # closed before the child process is executed.
    #
    cmd = subprocess.Popen(cmd_list, close_fds=True,
                           stderr=subprocess.PIPE,
                           stdout=subprocess.PIPE)
    try:
        (stdout_data, stderr_data) = cmd.communicate()
    finally:
        # Close all the file descriptors
        if cmd.stdin:
            cmd.stdin.close()
        if cmd.stdout:
            cmd.stdout.close()
        if cmd.stderr:
            cmd.stderr.close()

    if (cmd.returncode != 0 and assert_on_retcode):
        cmd_line = " ".join(cmd_list)
        raise idb_exception.CommandException(cmd_line,
                                                     cmd.returncode,
                                                     stdout_data,
                                                     stderr_data)
    return stdout_data, stderr_data, cmd.returncode



def cmd_runner(cmd, out):
    '''
    Runs the command specified by cmd in a suprocess and stores output captured
    to output. also saves return value to retval

    TODO: find a way to capture stderr of subprocess. And print it here. A
            options I tried but of no use.
    '''
    lines = []
    try:
        p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
#        out,errors = p.communicate()
#        _logger.info(out,errors)
#        lines = p.stdout.realines()
        # print errors if any right here where as let the caller deal with output
#        for line in :
#            _logger.info(line)

        for line in p.stdout.readlines():
            out.append(line.strip())
        retval = p.wait()
    # usually all utilities return 0 on success.
    # any attempt to log in this routine sets the script into an infinite loop
        return retval
    except:
        return (-9999)

def execute_api(method, url, data):
    """This method is wrapper over cmd_runner which will be used to
        execute api call and return json response
    """
    output = []
    response = None
    try:
        if method in ['GET', 'DELETE']:
            data_str = ''
            for key in data:
                data_str += '%s%s=%s' % ('\&' if data_str else '',
                                            key,
                                            data.get(key))
            api_call = 'curl -k -X %s https://127.0.0.1/api%s?%s' % (method,
                                                                    url,
                                                                    data_str)
        else:
            api_call = 'curl -k -X %s https://127.0.0.1/api%s -d \'%s\'' % (method,
                                                                     url,
                      	                                             json.dumps(data))
        _logger.info("API CALL is %s" % api_call)
        cmd_runner(api_call, output)
        try:
            response = json.loads(output[0])
        except:
            response = output[0]
    except Exception, e:
        _logger.exception("Error Occured while executing api_call %s: %s"\
                            %(api_call, e))
    finally:
        return response

def get_apikey(db_name = '/system/lb.sqlite', max_retry = 10):
    """This function will be used to get apikey from sqlite table
    """
    apikey = None
    sqlite_handle = get_sqlite_handle(db_name)

    if sqlite_handle:
        db_cursor = sqlite_handle.cursor()
        #Query to get apikey from lb_network table
        query_for_apikey = "select apikey from lb_network"

        retry = 0
        while retry < max_retry:
            try:
                db_cursor.execute(query_for_apikey)
                row = db_cursor.fetchone()
                if row:
                    apikey = row['apikey']
                break
            except (Exception, sqlite3.Error) as ex:
                retry = retry + 1
                if retry >= max_retry:
                    _logger.error("Failed to get apikey %s" % ex)
                else:
                    time.sleep(0.1)

        sqlite_handle.close()
    return apikey

def check_if_ftpdir_exists(ftp_session, dir_to_check):
    '''
    Check if a directory on remote server exists.
    '''
    filelist = []  # to store all files
    ftp_session.retrlines('NLST', filelist.append)  # append to list
    dir_exists = False
    for f in filelist:
        if f.split()[-1] == dir_to_check:
            # do something
            dir_exists = True
            break

    return dir_exists

def upload_file2ftp(ftp_session, src_file, dest_file):
    '''
    Upload a file to remote ftp server
    '''
    f = open(src_file, "rb")
    target = "STOR " + dest_file
    ftp_session.storbinary(target, f)
    f.close()

def get_ipaddress_of_interface(ifname = 'eth0'):
    '''
    Returns ipv4 address of a network interface. If not specified then return
    ipaddress of eth0.
    '''
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return socket.inet_ntoa(fcntl.ioctl(
        s.fileno(),
        0x8915,  # SIOCGIFADDR
        struct.pack('256s', ifname[:15])
        )[20:24])


def socket_cmd_runner(host = "127.0.0.1", port = 4000,
                          unix_sock = "/tmp/lb_sock",
                          command = "show_stat_status"):
    '''
    Creates a socket and runs the specified command. If unix_sock is
    provided then a unix type socket is opened. However if unix_sock is empty
    then a tcp socket is opened to specified host.
    Finally result of execution is returned to the caller
    '''
    # seconds to wait for server response. can it be in config file
    timeout = 5
    idb_reply_chunk_size = 4096
    sock = None
    error_list_file = "/opt/idb/conf/error_strings.txt"
    server_reply = ""
    error_string = "**Unexpected server reply.**"

    if unix_sock:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        server_addr = unix_sock
    else:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        server_addr = (host, port)

    if sock:
        # try to connect
        try:
            sock.connect(server_addr)
            # strip the command to ensure it's void of spaces
            command.strip()
            sock.sendall(command)

            while True:
                # server will reply status per cluster so data may be large
                try:
                    data = sock.recv(idb_reply_chunk_size)
                    if data:
                        server_reply = server_reply + data
                        #
                        # if command was to delete a cluster then once we
                        # have read something then we stop
                        #
                        if command[0:6] == "delete":
                            break
                    else:
                        # we could not read anything probably a connection close
                        break
                except socket.timeout:
                    # a timeout occurred, we wont read any further
                    break
            #
            # load all error strings with their respective codes
            # some commands retrieve multi-line results or non-integer results
            # therefore, it may not be possible to find their meaning in
            # error list file. So avoid looking up error strings in such cases
            #
            try:
                server_reply = int(server_reply)
            except ValueError:
                if server_reply == "":
                    return "ERROR"

            if server_reply == 0:
                #
                # it simply means communication with server was successful no
                # need to do a lookup
                #
                return "SUCCESS"
            #
            # server replied a status code (integer) do a lookup in error_list_file
            # return the equivalent msg
            #
            try:
                fp = open(error_list_file,'r')
                for line in fp:
                    l = line.split("|")
                    if server_reply == int(l[0]):
                        error_string = l[1]
                        break

                return ("STATUS:" + str(server_reply) + "|" + error_string)
            except IOError, ex:
                return "ERROR:" + str(ex)
            finally:
                fp.close()

        except socket.error:
            error_string = "ERROR: Failed to connect to remote server"
            return error_string
        finally:
            sock.close()

    else:
        error_string = "ERROR: " + " Could not get a socket"
        return error_string


def read_file(filepath):
    """Open the file in read-only model & read the contents into a string.
    Can raise IOError
    :param filepath: Path of the file to read
    :returns: A string containing the data of the file
    :rtype: String
    """
    _logger.debug("Reading file: %s" % filepath)
    fp = open(filepath, 'r')
    file_info = fp.readlines()
    fp.close()
    return file_info

def get_smtp_config_from_sqlite(self, db_file, clusterid=None):
    '''
    Read smtp configuration from sqlite file using clusterid
    '''
    smtp_ip = None
    smtp_port = None
    smtp_user = None
    smtp_pass = None
    emailids = None
    message = 'This is a test e-mail message\
               Please ignore it'
    subject = 'ScaleArc Alert'
    try:
        db_handle = get_sqlite_handle(db_file)
        
        cursor = db_handle.cursor()
        if clusterid:
            query = "select * from lb_sendalert where clusterid=%s;"%clusterid
        else:
            query = "select * from lb_sendalert;"
    
        cursor.execute(query)
        result = cursor.fetchone()
        smtp_ip = result['smtp_ip']
        smtp_user = result['smtp_user']
        smtp_port = result['smtp_port']
        smtp_pass = result['smtp_pass']
        status = result['status']
        clusterid = result['clusterid']
        emailids = result['emailids']
    except Exception, ex:
        _logger.error("SystemMonitor: Failed to get smtpconfig from sqlite. : %s" \
                      % (ex))
    finally:
        if cursor:
            cursor.close()
        if db_handle:
            db_handle.close()
        return smtp_ip, smtp_port, smtp_user, emailids, subject, message, smtp_pass



