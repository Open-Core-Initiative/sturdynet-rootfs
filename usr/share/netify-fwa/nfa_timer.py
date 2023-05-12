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

import os
import threading
import time

from signal import SIGALRM

from syslog import \
    openlog, syslog, LOG_PID, LOG_PERROR, LOG_DAEMON, \
    LOG_DEBUG, LOG_ERR, LOG_WARNING

import nfa_global

class timer(threading.Thread):
    interval = 0
    one_shot = True
    signo_ALRM = 0

    def __init__(self, interval, one_shot=True):

        self.interval = int(interval)
        self.one_shot = one_shot

        if isinstance(SIGALRM, int):
            self.signo_ALRM = SIGALRM
        else:
            self.signo_ALRM = SIGALRM.value

        super().__init__()

    def run(self):

        while nfa_global.should_terminate is False:
            ticks = self.interval
            while ticks > 0 and nfa_global.should_terminate is False:
                time.sleep(1)
                ticks -= 1
            os.kill(os.getpid(), self.signo_ALRM)
            if self.one_shot:
                return
