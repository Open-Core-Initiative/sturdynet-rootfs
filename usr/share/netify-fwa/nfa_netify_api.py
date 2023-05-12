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

import json
import urllib.request

from syslog import \
    openlog, syslog, LOG_PID, LOG_PERROR, LOG_DAEMON, \
    LOG_DEBUG, LOG_ERR, LOG_WARNING

import nfa_global

def get(url):
    try:
        if nfa_global.should_terminate:
            return None

        syslog(LOG_DEBUG, "url: " + url)

        with urllib.request.urlopen(url) as ul:
            data = json.loads(ul.read().decode())
            #syslog(LOG_DEBUG str(data))
        return data

    except urllib.error.URLError as e:
        syslog(LOG_ERR, "API request failed: %s" %(e.reason))
        return None

    except:
        syslog(LOG_ERR, 'API request failed: Unknown exception.');
        return None

def get_data(url):
    options = []
    pages = []

    url += '?settings_limit=100'

    data = get(url)

    if data is None:
        return None

    if 'status_code' not in data:
        return None

    if data['status_code'] != 0:
        return None

    if 'data' not in data:
        return None

    # Unpaginated small datasets vs paginated large datasets
    if 'data_info' not in data:
        total_pages = 1
        options = []
    else:
        data_info = data['data_info']

        if 'total_pages' not in data_info:
            return None

        total_pages = data_info['total_pages']

        if 'data_options' in data:
            options = data['data_options']

    pages.append(data['data'])

    if total_pages > 1:
        for page in range(2, total_pages + 1):
            syslog(LOG_DEBUG, "Get page: %d / %d..." %(page, total_pages))
            data = get(url + '&page=' + str(page))

            if data is None:
                return None

            if 'status_code' not in data:
                return None

            if data['status_code'] != 0:
                return None

            if 'data' not in data:
                return None

            pages.append(data['data'])

    return [ options, pages ]
