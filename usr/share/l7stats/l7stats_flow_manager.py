# openwrt Engine
# Copyright (C) 2022 IPSquared, Inc. <https://www.ipsquared.com>
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

###############
# Written by:
#
# mfoxworthy
# gchadda
#
################


from threading import RLock
from l7stats_collectd_uds import Collectd
import socket
from syslog import \
    openlog, syslog, LOG_PID, LOG_PERROR, LOG_DAEMON, \
    LOG_DEBUG, LOG_ERR, LOG_WARNING, LOG_INFO, LOG_CRIT

class CollectdFlowMan:

    def __init__(self):
        self._flow = {}
        self._app = {}
        self._cat = {}
        self._csocket = Collectd()
        self._lock = RLock()

    def addflow(self, dig, app, cat, iface):
        app_int_name = app + "_" + iface
        cat_int_name = cat + "_" + iface
        if app_int_name not in self._app.keys():
            with self._lock:
                self._app.update({app_int_name: {"bytes_tx": 0, "bytes_rx": 0, "tot_bytes": 0,
                                                 "old_tx": 0, "old_rx": 0, "old_tot": 0}})
        if cat_int_name not in self._cat.keys():
            with self._lock:
                self._cat.update({cat_int_name: {"bytes_tx": 0, "bytes_rx": 0, "tot_bytes": 0,
                                                 "old_tx": 0, "old_rx": 0, "old_tot": 0}})
        with self._lock:
            self._flow.update(
                {dig: {"app_name": app, "app_cat": cat, "iface_name": iface, "bytes_tx": 0,
                       "bytes_rx": 0, "tot_bytes": 0, "purge": 0, "status": 0}})

    def _delflow(self, dig):
        if dig not in self._flow.keys():
            syslog(LOG_WARNING, "Digest not found...\n", dig)
        else:
            _ = self._flow.pop(dig, None)

    def updateflow(self, dig, tx_bytes, rx_bytes, t_bytes):
        has_dig = dig in self._flow.keys()
        if has_dig:
            c_app = self._flow[dig]["app_name"] + "_" + self._flow[dig]["iface_name"]
            c_cat = self._flow[dig]["app_cat"] + "_" + self._flow[dig]["iface_name"]

            with self._lock:
                self._app[c_app]['bytes_tx'] += tx_bytes
                self._app[c_app]['bytes_rx'] += rx_bytes
                self._app[c_app]['tot_bytes'] += t_bytes
                self._cat[c_cat]["bytes_tx"] += tx_bytes
                self._cat[c_cat]["bytes_rx"] += rx_bytes
                self._cat[c_cat]["tot_bytes"] += t_bytes
                self._delflow(dig)

    def sendappdata(self, interval):
        interval = {"interval": interval}

        try:
            hostname = socket.gethostname()
        except Exception as e:
            hostname = "default_sturdynet"
            syslog(LOG_CRIT, "Please set the hostname")
        with self._lock:
            for i in list(self._app):
                x = i.split("_")
                app_name = x[0].replace("-", "_")
                i_name = x[1].replace("-", "_")
                app_id_rxtx = hostname + "/application-" + app_name + "/if_octets-" + i_name
                app_id_tot = hostname + "/application-" + app_name + "/total_bytes-" + i_name
                app_txbytes = self._app[i]['bytes_tx']
                app_rxbytes = self._app[i]['bytes_rx']
                app_tbytes = self._app[i]['tot_bytes']
                app_cd_if = ["N", app_txbytes, app_rxbytes]
                app_cd_tot = ["N", app_tbytes]

                # TODO evaluate ways to compress data

                # if app_txbytes != self._app[i]['old_tx'] or app_rxbytes != self._app[i]['old_rx']:
                #    self._app[i]['old_tx'] = app_txbytes
                #    self._app[i]['old_rx'] = app_rxbytes

                self._csocket.putval(app_id_rxtx, app_cd_if, interval)

                # if app_tbytes != self._app[i]['old_tot']:
                #    self._app[i]['old_tot'] = app_tbytes

                self._csocket.putval(app_id_tot, app_cd_tot, interval)

            for i in list(self._cat):
                x = i.split("_")
                cat_name = x[0].replace("-", "_")
                i_name = x[1].replace("-", "_")
                cat_id_rxtx = hostname + "/category-" + cat_name + "/if_octets-" + i_name
                cat_id_tot = hostname + "/category-" + cat_name + "/total_bytes-" + i_name
                cat_txbytes = self._cat[i]['bytes_tx']
                cat_rxbytes = self._cat[i]['bytes_rx']
                cat_tbytes = self._cat[i]['tot_bytes']
                cat_cd_if = ["N", cat_txbytes, cat_rxbytes]
                cat_cd_tot = ["N", cat_tbytes]
                self._csocket.putval(cat_id_rxtx, cat_cd_if, interval)
                self._csocket.putval(cat_id_tot, cat_cd_tot, interval)
# TODO add code to add types to types.db
#total_bytes-eth1        value:DERIVE:0:U
#total_bytes-br_lan      value:DERIVE:0:U
#total_bytes-3g_wwan     value:DERIVE:0:U
#if_octets-eth1          rx:DERIVE:0:U, tx:DERIVE:0:U
#if_octets-br_lan        rx:DERIVE:0:U, tx:DERIVE:0:U
#if_octets-3g_wwan       rx:DERIVE:0:U, tx:DERIVE:0:U