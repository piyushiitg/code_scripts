#!/usr/bin/python
#
# Copyright (C) 2013 ScaleArc, Inc., all rights reserved.
#

import sys, os, time, atexit
from signal import SIGTERM

import idb.log as log

_logger = log.get_logger("lib.daemon", relative_name=True)

DEV_NULL = '/dev/null'

class Daemon(object):
    """
    A generic daemon class. To create a daemon, you will need to subclass the
    Daemon class and override the run() method.
    """
    def __init__(self, pidfile, stdin=DEV_NULL, stdout=DEV_NULL, \
        stderr=DEV_NULL):
        self.stdin = stdin
        self.stdout = stdout
        self.stderr = stderr
        self.pidfile = pidfile

    def daemonize(self):
        """
        Make the process into a daemon by double fork. The second fork is
        recommended to ensure that the daemon is re-parented onto init, and it
        never acquires a controlling terminal.
        """
        #
        # Do first fork
        #
        try:
            #
            # The fork() command returns 0 in the child and returns the child's
            # pid in the parent.
            #
            pid = os.fork()
            if pid > 0:
                #
                # Exit first parent
                #
                sys.exit(0)
        except OSError, ex:
            sys.stderr.write("fork #1 failed: %d (%s)\n" % (ex.errno, \
                    ex.strerror))
            sys.exit(1)

        #
        # Decouple from parent environment
        #
        os.chdir("/")
        os.setsid()
        os.umask(0)

        #
        # Do second fork
        #
        try:
            #
            # The fork() command returns 0 in the child and returns the child's
            # pid in the parent.
            pid = os.fork()
            if pid > 0:
                #
                # Exit from second parent. This will cause the second child
                # process to be orphaned, making the init process responsible
                # for its cleanup.
                #
                sys.exit(0)
        except OSError, ex:
            sys.stderr.write("fork #2 failed: %d (%s)\n" % (ex.errno, \
                    ex.strerror))
            sys.exit(1)

        #
        # Redirect standard file descriptors. A true daemon has no environment.
        # No parent process, no working directory and no stdin, stdout and
        # stderr. That's why I redirect everything to /dev/null.
        #
        sys.stdout.flush()
        sys.stderr.flush()
        si = file(self.stdin, 'r')
        so = file(self.stdout, 'a+')
        se = file(self.stderr, 'a+', 0)
        os.dup2(si.fileno(), sys.stdin.fileno())
        os.dup2(so.fileno(), sys.stdout.fileno())
        os.dup2(se.fileno(), sys.stderr.fileno())

        #
        # Write pidfile
        #
        atexit.register(self.delpid)
        pid = str(os.getpid())
        try:
            file(self.pidfile,'w+').write("%s\n" % pid)
        except Exception,ex:
            sys.stderr.write("Failed to record pid in pidfile: %s" % self.pidfile)
            if os.path.exists(self.pidfile):
                os.remove(self.pidfile)
            sys.exit(1)
        
    def delpid(self):
        """
        Remove the pid file
        """
        if os.path.exists(self.pidfile):
            os.remove(self.pidfile)

    def start(self):
        """
        Start the daemon
        """
        #
        # Check for a pidfile to see if the daemon already runs
        #
        try:
            pf = file(self.pidfile,'r')
            pid = int(pf.read().strip())
            pf.close()
        except IOError:
            pid = None
        except ValueError:
            # if pidfile exists but no pid in it then we should remove the pidfile
            if os.path.exists(self.pidfile):
                os.remove(self.pidfile)
            pid = None
        #
        # TODO: ensure that this pid indeed belongs to us, if not remove the pidfile
        #         start fresh
        #
        if pid:
            message = "pidfile %s already exist. Daemon already running?\n"
            sys.stderr.write(message % self.pidfile)
            sys.exit(1)
        
        #
        # Crate a daemon
        #
        self.daemonize()
        self.run()

    def stop(self):
        """
        Stop the daemon
        """
        #
        # Get the pid from the pidfile
        #
        try:
            pf = file(self.pidfile,'r')
            pid = int(pf.read().strip())
            pf.close()
        except IOError:
            if os.path.exists(self.pidfile):
                os.remove(self.pidfile)
            pid = None
        except ValueError:
            # if pidfile exists but no pid in it then we should remove the pidfile
            if os.path.exists(self.pidfile):
                os.remove(self.pidfile)
            pid = None

        if not pid:
            message = "pidfile %s does not exist. Daemon is not running?\n"
            sys.stderr.write(message % self.pidfile)
            return

        #
        # Try killing the daemon process
        #
        try:
            os.kill(pid, SIGTERM)
            if os.path.exists(self.pidfile):
                os.remove(self.pidfile)
        except OSError, err:
            if os.path.exists(self.pidfile):
                os.remove(self.pidfile)
            err = str(err)
            if err.find("No such process") == -1:
                print str(err)
            
            # we are gonna exit anyway
            sys.exit(1)

    def restart(self):
        """
        Restart the daemon
        """
        self.stop()
        self.start()

    def foreground(self):
        """
        Run the process in the foreground without daemonizing it.
        For Debugging only.
        """
        self.run()

    def run(self):
        """
        Override this method after you subclass Daemon. It is called from
        start() after the process has need daemonized.
        """

#
# This is another implementation of daemonizing processes
#

def _fix_file(file_obj, fd):
    if fd != file_obj.fileno():
        os.dup2(fd, file_obj.fileno())
        os.close(fd)


class _DaemonInfo(object):
    """This class maintains all the daemon state, used by watchdog service
    """
    daemon_pid = 0
    stdin_path = DEV_NULL
    stdout_path = DEV_NULL
    stderr_path = DEV_NULL
    curdir = "/"
    pidfile_path = None

    @classmethod
    def __cleanup(cls):
        if cls.pidfile_path:
            try:
                os.unlink(cls.pidfile_path)
            except OSError, ose:
                _logger.error("failed to unlink %s: %s" %
                            (cls.pidfile_path, ose))

    @classmethod
    def __daemon_setup(cls):
        try:
            os.chdir(cls.curdir)
        except OSError, ex:
            _logger.error("chdir(%s) failed: %s" % (cls.curdir, ex))
            sys.exit(1)
        os.umask(0)
        cls.__io_redirection()
        cls.daemon_pid = os.getpid()

    @classmethod
    def __io_redirection(cls):
        try:
            fd = os.open(cls.stdin_path, os.O_RDONLY)
        except OSError, ex:
            _logger.error("failed to open %s for stdin: %s" %
                    (cls.stdin_path, ex))
            sys.exit(1)
        _fix_file(sys.stdin, fd)
        sys.stdout.flush()
        try:
            fd = os.open(cls.stdout_path,
                    os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0755)
        except OSError, ex:
            _logger.error("failed to open %s for stdout: %s" %
                    (cls.stdout_path, ex))
            sys.exit(1)
        _fix_file(sys.stdout, fd)
        sys.stderr.flush()
        try:
            fd = os.open(cls.stderr_path,
                    os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0755)
        except OSError, ex:
            _logger.error("failed to open %s for stderr: %s" %
                    (cls.stderr_path, ex))
            sys.exit(1)
        _fix_file(sys.stderr, fd)

    @classmethod
    def record_pid(cls, pidfile_path):
        if not cls.daemon_pid:
            return
        pidfile = None
        try:
            pidfile = file(pidfile_path, "w")
            pidfile.write("%d" % (cls.daemon_pid,))
        except IOError, ioe:
            _logger.error("unable to record pid in file %s: %s" %
                    (pidfile_path, ioe))
            if os.path.exists(pidfile_path):
                os.remove(pidfile_path)
            sys.exit(1)
        finally:
            if pidfile:
                pidfile.close()
        cls.pidfile_path = pidfile_path
        atexit.register(cls.__cleanup, cls)

    @classmethod
    def become_daemon(cls):
        """This function will turn the current process into a daemon.
        Since this is a one-time operation, the function remembers the
        pid to make sure that it is only applied once per process.
        Returns True if successful, False otherwise.
        """
        if cls.daemon_pid == os.getpid():
            _logger.error("attempt to become daemon again!")
            return False
        #
        # Our previous caller must have forked; we are in a different
        # process now
        #
        cls.daemon_pid = 0
        try:
            pid = os.fork()
        except OSError, ex:
            _logger.error("failed to fork: %s" % (ex,))
            return False
        #
        # The parent exits here; the child is inherited by init.
        #
        if pid != 0:
            os._exit(0)
        #
        # The child process is running here.
        # Errors beyond this point result in process termination
        #
        try:
            os.setsid()
        except:
            # already a process group leader?
            _logger.error("setsid() failed: %s" % (ex,))
        cls.__daemon_setup()
        return True


def become_daemon():
    return _DaemonInfo.become_daemon()


def record_pid(pidfile):
    _DaemonInfo.record_pid(pidfile)
