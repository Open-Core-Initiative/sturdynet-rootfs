# Netify Firewall Agent
# Copyright 2007 Jerry Seutter yello (*a*t*) thegeeks.net
# Copyright (C) 2019-2020 eGloo Incorporated <http://www.egloo.ca>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import os
import sys
import fcntl

from syslog import \
    openlog, syslog, LOG_PID, LOG_PERROR, LOG_DAEMON, \
    LOG_DEBUG, LOG_ERR, LOG_WARNING

def create(pid_file=None, debug=False):
    if pid_file is not None:
        try:
            fd_lock = open(pid_file, 'w+')
            fcntl.flock(fd_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except FileNotFoundError as e:
            syslog(LOG_ERR, "Unable to create PID file: %s" %(pid_file))
            sys.exit(1)

    # Fork, creating a new process for the child.
    pid = os.fork()
    if pid < 0:
        # Fork error.  Exit badly.
        sys.exit(1)
    elif pid != 0:
        # This is the parent process.  Exit.
        sys.exit(0)

    # This is the child process.  Continue.
    if pid_file is not None:
        fd_lock.write('%d' %(os.getpid()))
        fd_lock.flush()

    pid = os.setsid()
    if pid == -1:
        sys.exit(1)

    if not debug:
        path_null = '/dev/null'
        if hasattr(os, 'devnull'):
            path_null = os.devnull

        fd_null = open(path_null, 'w+')
        for fd in (sys.stdin, sys.stdout, sys.stderr):
            fd.close()
            fd = fd_null

    os.umask(0o027)

    os.chdir('/')
