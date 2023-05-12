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

from syslog import LOG_PID, LOG_PERROR

debug = False
foreground = False

fw = None
fw_sync = []
fw_interfaces = { "internal": [], "external": [] }

config_reload = True
should_terminate = False
expire_matches = False

config = None
config_dynamic = None
config_cat_index = None
config_app_proto = None

log_options = LOG_PID | LOG_PERROR

timestamp_epoch = 0

stats = {
    'uptime': 0,
    'flows': 0,
    'blocked': 0, 'prioritized': 0,
    'blocked_total': 0, 'prioritized_total': 0
}

matches = []

rx_app_id = None
