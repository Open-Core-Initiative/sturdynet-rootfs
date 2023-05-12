# Netify Firewall Agent
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

import subprocess

from syslog import \
    openlog, syslog, LOG_PID, LOG_PERROR, LOG_DAEMON, \
    LOG_DEBUG, LOG_ERR, LOG_WARNING

def exec_log_output(name, output, level=LOG_ERR):
    if len(output):
        lines = output.rstrip().split("\n")
        for line in lines:
            syslog(level, "%s: %s" %(name, line))

def exec(name, command_args):
    rv = { 'rc': 255, 'stdout': '', 'stderr': '' }

    result = subprocess.run(
        command_args,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        universal_newlines=True
    )

    rv['rc'] = result.returncode
    if len(result.stdout):
        rv['stdout'] = result.stdout
    if len(result.stderr):
        rv['stderr'] = result.stderr

    if result.returncode != 0:
        if len(result.stderr):
            exec_log_output(name, result.stderr)
        else:
            syslog(LOG_ERR, "%s: Unknown error." %(name))
            syslog(LOG_DEBUG, "%s: %s" %(result))

    return rv
