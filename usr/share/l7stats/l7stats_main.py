# openwrt Engine
# Copyright (C) 2022 IPSquared, Inc. <https://www.ipsquared.com)>
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
#
# Written by:
#
# gchadda
# mfoxworthy
#
###############


import os
import threading
import signal
import ast
import time

from l7stats_netifyd_uds import netifyd
from random import randint
from l7stats_flow_manager import CollectdFlowMan
from syslog import \
    openlog, syslog, LOG_PID, LOG_PERROR, LOG_DAEMON, \
    LOG_DEBUG, LOG_ERR, LOG_WARNING, LOG_INFO

def round_float_by_precision(inval, p = -1):
    if -1 == p:
        p = TIMING_PRECISION
    return round(float(inval), p)

def update_data(e, t, fl):
    b = -1
    while not e.isSet():
        timing_bias = 0
        if b >= 0:
            timing_bias -= round_float_by_precision(time.time())
            fl.sendappdata(t)
            timing_bias += round_float_by_precision(time.time())
        else:
            b += 1

        if timing_bias < t and timing_bias > 0:
            t_delta = round_float_by_precision(t - timing_bias)
            syslog(LOG_INFO, f"normalized sleep to {t_delta}")
            time.sleep(t_delta)
        else:
            syslog(LOG_INFO, f"using default sleep timer, timing_bias is: {timing_bias}")
            time.sleep(t)

def cleanup():
    global nd
    global eh
    nd.close()
    eh.set()

def sig_handler(s, f):
    syslog(LOG_ERR, f"Received stack {repr(s)} on frame {repr(f)}")
    cleanup()
    os._exit(0)

def gen_socket(e):
    fp = e.split("unix://")[-1]
    err = True

    try:
        retsock = nd.connect(uri=e)
    except:
        try:
            syslog(LOG_INFO, f"unlinking {fp}")
            os.unlink(fp)
        except OSError:
            if not os.path.exists(fp):
                syslog(LOG_INFO, f"{fp} doesn't exist")
            else:
                syslog(LOG_ERR, f"{fp} exists after attempting to unlink")
    else:
        err = False

    if err:
        try:
            retsock = nd.connect(uri=e)
        except:
            retsock = None

    return retsock

SOCKET_ENDPOINT   = "unix:///var/run/netifyd/netifyd.sock"
SLEEP_PERIOD      = randint(1, 5)
APP_UPDATE_ITVL   = 30
app_to_cat        = dict()
APP_PROTO_FILE    = "/etc/netify-fwa/app-proto-data.json"
APP_CAT_FILE      = "/etc/netify-fwa/netify-categories.json"
nd                = netifyd()
fh                = gen_socket(SOCKET_ENDPOINT)
fl                = CollectdFlowMan()
eh                = threading.Event()
TIMING_PRECISION  = 1

signal.signal(signal.SIGHUP,  sig_handler)
signal.signal(signal.SIGTERM, sig_handler)
signal.signal(signal.SIGINT,  sig_handler)


for fp in (APP_PROTO_FILE, APP_CAT_FILE):
    with open(fp,mode="r") as f:
         s = f.read()

    if isinstance(s, str):
        app_to_cat[fp] = ast.literal_eval(s)
        assert isinstance(app_to_cat[fp], dict) == True
    else:
        raise RuntimeError("app mapping failure..")

# start off a thread to report data every APP_UPDATE_ITVL secs
threading.Thread(target=update_data, args=(eh, APP_UPDATE_ITVL, fl)).start()

while True:
    try:
        jd = nd.read()

        if jd is None:
            nd.close()
            fh = None
            syslog(LOG_INFO, f"backing off for {SLEEP_PERIOD}..")
            time.sleep(SLEEP_PERIOD)
            nd = netifyd()
            fh = gen_socket(SOCKET_ENDPOINT)
            continue

        if jd['type'] == 'noop':
            syslog(LOG_DEBUG, "detected noop, continuing...")
            continue

        if all(['flow_count' in jd.keys(),'flow_count_prev' in jd.keys()]):
            syslog(LOG_INFO, f"flow count == {jd['flow_count']}{os.linesep}previous flow count == {jd['flow_count_prev']}"\
                  + f"{os.linesep}delta == {-nd.flows_delta}")
            continue

        digest = jd['flow']['digest']

        if jd['type'] == 'flow':
            if jd['flow']['other_type'] != 'remote': continue

            if jd['flow']['ip_protocol'] != 6 and \
                    jd['flow']['ip_protocol'] != 17 and \
                    jd['flow']['ip_protocol'] != 132 and \
                    jd['flow']['ip_protocol'] != 136: continue

            if jd['flow']['detected_protocol'] == 5 or \
                    jd['flow']['detected_protocol'] == 8: continue

            app_name_str = jd['flow']['detected_application_name']
            app_int, *app_trail = app_name_str.split("netify")
            if 1 == len(app_trail):
                app_int = app_int.rstrip(".")
                app_name = app_trail[0].lstrip(".")
                syslog(LOG_INFO, f"app_int == {app_int}, app_name = {app_name}")
                app_cat = app_to_cat[APP_CAT_FILE ]['applications'][str(app_int)]
                app_cat_name = app_to_cat[APP_PROTO_FILE]['application_category'][str(app_cat)]['tag']
            else:
                syslog(LOG_INFO, f"failure.... read in {app_name_str}, unable to parse further")
                app_name     = "unknown"
                app_cat      = 0
                app_cat_name = "unknown"

            syslog(LOG_INFO, f"app_cat = {app_cat}, app_cat_name = {app_cat_name}")

            iface_name = jd['interface']

            detected_protocol         = jd['flow']['detected_protocol']
            detected_protocol_mapping = app_to_cat[APP_CAT_FILE]['protocols'][str(detected_protocol)]
            protocol_mapping_name     = app_to_cat[APP_PROTO_FILE]['protocol_category'][str(detected_protocol_mapping)]['tag']

            syslog(LOG_INFO, f"detected_protocol_mapping={detected_protocol_mapping}, protocol_mapping_name  = {protocol_mapping_name}")

            if digest:
                fl.addflow(digest, app_name, app_cat_name, iface_name)

        if jd['type'] == 'flow_purge':
            bytes_tx = int(jd['flow']['local_bytes'])
            bytes_rx = int(jd['flow']['other_bytes'])
            tot_bytes = int(jd['flow']['total_bytes'])
            if digest:
                fl.updateflow(digest, bytes_tx, bytes_rx, tot_bytes)

        if jd['type'] == 'flow_status':
            #bytes_tx = int(jd['flow']['local_bytes'])
            #bytes_rx = int(jd['flow']['other_bytes'])
            #tot_bytes = int(jd['flow']['total_bytes'])
            #if digest:
            #    fl.updateflow(digest, bytes_tx, bytes_rx, tot_bytes)
            syslog(LOG_ERR, "flow status received...unexpected")
            syslog(LOG_ERR, str(jd))

        if jd['type'] == 'agent_status':
            """ we explicitly ignore agent_status ; not implemented """
            pass

    except KeyError as ke:
        syslog(LOG_ERR, f"hit key error for : {ke}")
        syslog(LOG_ERR, str(jd))
        continue
    except Exception as e:
        syslog(LOG_ERR, f"hit general exception: {e}")
        continue
