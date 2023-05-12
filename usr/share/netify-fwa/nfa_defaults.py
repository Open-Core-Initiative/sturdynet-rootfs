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

NFA_PATH_PID='/var/run/netify-fwa/netify-fwa.pid'
NFA_CONF='/etc/netify-fwa/netify-fwa.ini'
NFA_CONF_DYNAMIC='/etc/netify-fwa/netify-fwa.json'
NFA_PATH_STATUS='/var/run/netify-fwa/status.json'
NFA_PATH_STATUS_MATCHES='/var/run/netify-fwa/matches.json'
NFA_PATH_APP_PROTO_DATA='/etc/netify-fwa/app-proto-data.json'
NFA_PATH_CATEGORIES='/etc/netify-fwa/category-index.json'
NFA_URI_SOCKET='unix://var/run/netifyd/netifyd.sock'
NFA_URI_API='https://api.netify.ai/api/v1'
NFA_TTL_MATCH=600
NFA_TTL_CATEGORY_INDEX=86400
NFA_MAX_MATCH_HISTORY=100
