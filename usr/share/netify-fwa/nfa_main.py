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

import sys
import json
import socket
import errno
import time
import os.path
import re
import select
import math

from getopt import getopt, GetoptError

from signal import \
    signal, Signals, SIGALRM, SIGHUP, SIGINT, SIGTERM, SIGUSR1, SIGUSR2

from syslog import \
    openlog, syslog, LOG_PID, LOG_PERROR, LOG_DAEMON, \
    LOG_DEBUG, LOG_ERR, LOG_WARNING

import nfa_global
import nfa_defaults
import nfa_config
import nfa_daemonize
import nfa_netifyd
import nfa_task
import nfa_rule
import nfa_timer

from nfa_defaults import NFA_CONF, NFA_MAX_MATCH_HISTORY
from nfa_version import NFA_VERSION

def nfa_signal_handler(signum, frame):

    if isinstance(SIGHUP, int):
        signo_ALRM = SIGALRM
        signo_HUP = SIGHUP
        signo_INT = SIGINT
        signo_TERM = SIGTERM
        signo_USR1 = SIGUSR1
        signo_USR2 = SIGUSR2
    else:
        signo_ALRM = SIGALRM.value
        signo_HUP = SIGHUP.value
        signo_INT = SIGINT.value
        signo_TERM = SIGTERM.value
        signo_USR1 = SIGUSR1.value
        signo_USR2 = SIGUSR2.value

    if signum == signo_ALRM:
        nfa_global.expire_matches = True
    elif signum == signo_HUP:
        nfa_global.config_reload = True
    elif signum == signo_USR1:
        nfa_global.fw_sync.append(4)
    elif signum == signo_USR2:
        nfa_global.fw_sync.append(6)
    elif signum == signo_INT or signum == signo_TERM:
        syslog(LOG_WARNING, "Exiting...")
        nfa_global.should_terminate = True
    else:
        syslog(LOG_WARNING,
            "Caught unhandled signal: %s" %(Signals(signum).name))

def nfa_config_load():

    nfa_global.config = nfa_config.load_main(NFA_CONF)

def nfa_config_reload():

    config_dynamic = nfa_global.config.get('netify-fwa', 'path-config-dynamic')

    if os.path.isfile(config_dynamic):

        config = nfa_config.load_dynamic(config_dynamic)
        if config is not None:
            nfa_global.config_dynamic = config
            syslog("Loaded dynamic configuration.")

    nfa_global.config_reload = False

def nfa_cat_index_refresh(config_cat_index, ttl_cat_index):

    if not os.path.isfile(config_cat_index) or \
        int(os.path.getmtime(config_cat_index)) + int(ttl_cat_index) < int(time.time()):

        syslog(LOG_DEBUG, "Updating category index...")

        task_cat_update = nfa_task.cat_update(nfa_global.config)
        task_cat_update.start()

        return task_cat_update

    return None

def nfa_cat_index_reload(config_cat_index, config_app_proto, task_cat_update):

    if not task_cat_update.is_alive():

        task_cat_update.join()

        if not task_cat_update.exit_success:
            syslog(LOG_DEBUG, "Failed to update category index.")
        else:
            cat_index = nfa_config.load_cat_index(config_cat_index)
            app_proto = nfa_config.load_app_proto(config_app_proto)

            if cat_index is not None:
                syslog("Reloaded category index.")
                nfa_global.config_cat_index = cat_index
                nfa_global.config_app_proto = app_proto
                nfa_global.config_reload = True

        return None

    return task_cat_update

def nfa_fw_init():

    try:
        fw_engine = nfa_global.config.get('netify-fwa', 'firewall-engine')
    except NoOptionError as e:
        printf("Mandatory configuration option not set: firewall-engine")
        return False

    if fw_engine == 'iptables':
        from nfa_fw_iptables import nfa_fw_iptables
        nfa_global.fw = nfa_fw_iptables(nfa_global.config)
    elif fw_engine == 'firewalld':
        from nfa_fw_firewalld import nfa_fw_firewalld
        nfa_global.fw = nfa_fw_firewalld(nfa_global.config)
    elif fw_engine == 'clearos':
        from nfa_fw_clearos import nfa_fw_clearos
        nfa_global.fw = nfa_fw_clearos(nfa_global.config)
    elif fw_engine == 'openwrt':
        from nfa_fw_openwrt import nfa_fw_openwrt
        nfa_global.fw = nfa_fw_openwrt(nfa_global.config)
    elif fw_engine == 'pf':
        from nfa_fw_pf import nfa_fw_pf
        nfa_global.fw = nfa_fw_pf(nfa_global.config)
    elif fw_engine == 'pfsense':
        from nfa_fw_pfsense import nfa_fw_pfsense
        nfa_global.fw = nfa_fw_pfsense(nfa_global.config)
    else:
        print("Unsupported firewall engine: %s" %(fw_engine))
        return False

    if fw_engine == 'firewalld':
        # XXX: Have to open syslog again because the firewalld client code
        # is rude and does some of it's own syslog initialization.
        openlog('netify-fwa', nfa_global.log_options, LOG_DAEMON)

    syslog("Firewall engine: %s" %(nfa_global.fw.get_version()))

    if not nfa_global.fw.is_running():
        syslog(LOG_ERR, "Firewall engine is not running.")
        return False

    #nfa_global.fw.test()

    nfa_global.fw.remove_hooks()

    return nfa_global.fw.install_hooks()

def nfa_process_agent_status(status):

    if 'flows' in status and 'flows_prev' in status:
        nfa_global.stats['flows'] = status['flows']

    status = nfa_global.config.get('netify-fwa', 'path-status')

    nfa_global.stats['uptime'] = math.floor(time.time()) - nfa_global.timestamp_epoch
    nfa_global.stats['blocked_total'] += nfa_global.stats['blocked']
    nfa_global.stats['prioritized_total'] += nfa_global.stats['prioritized']

    try:
        with open(status, 'w') as fh:
            json.dump(nfa_global.stats, fh)
    except:
        syslog(LOG_ERR, "Unable to update status file: %s" %(status))

    nfa_global.stats['blocked'] = 0
    nfa_global.stats['prioritized'] = 0

    while len(nfa_global.matches) > NFA_MAX_MATCH_HISTORY:
        nfa_global.matches.pop()

    matches = nfa_global.config.get('netify-fwa', 'path-status-matches')

    try:
        with open(matches, 'w') as fh:
            json.dump(nfa_global.matches, fh)
    except:
        syslog(LOG_ERR, "Unable to update matches status file: %s" %(matches))

def nfa_create_daemon():
    try:
        nfa_daemonize.create(
            pid_file=nfa_defaults.NFA_PATH_PID,
            debug=nfa_global.debug
        )
    except BlockingIOError as e:
        if e.errno == errno.EAGAIN or e.errno == errno.EACCESS:
            syslog(LOG_ERR, "An instance is already running.")
        else:
            syslog(LOG_ERR, "Error starting daemon: %d" %(e.errno))
        return False

    return True

def nfa_main():

    nfa_global.timestamp_epoch = math.floor(time.time())

    nfa_fw_init()

    fh = None
    nd = nfa_netifyd.netifyd()

    task_cat_index_update = None

    config_app_proto = nfa_global.config.get('netify-api', 'path-app-proto-data')
    config_cat_index = nfa_global.config.get('netify-api', 'path-category-index')
    ttl_cat_index = nfa_global.config.get('netify-api', 'ttl-category-index')

    if os.path.isfile(config_cat_index):
        nfa_global.config_cat_index = nfa_config.load_cat_index(config_cat_index)

    if os.path.isfile(config_app_proto):
        nfa_global.config_app_proto = nfa_config.load_app_proto(config_app_proto)

    wd = None
    if nfa_global.fw.flavor == 'iptables':
        from inotify_simple import INotify, flags

        inotify = INotify()
        config_dynamic = nfa_global.config.get('netify-fwa', 'path-config-dynamic')
        wd = inotify.add_watch(config_dynamic, flags.CLOSE_WRITE | flags.MOVE_SELF | flags.MODIFY)

    matches = nfa_config.load_matches(
        nfa_global.config.get('netify-fwa', 'path-status-matches')
    )

    if matches is not None: nfa_global.matches = matches

    match_expire_timer = nfa_timer.timer(60, False)
    match_expire_timer.start()

    while not nfa_global.should_terminate:

        if wd is not None:
            fd_read = [ inotify.fd ]
            fd_write = []

            rd, wr, ex = select.select(fd_read, fd_write, fd_read, 0)

            if len(rd):
                for event in inotify.read():
                    nfa_global.config_reload = True

        if nfa_global.config_reload:
            nfa_config_reload()
            nfa_global.fw.sync(nfa_global.config_dynamic)

            if fh is not None:
                nd.close()
                fh = None

        if len(nfa_global.fw_sync):
            ipvs = []
            while len(nfa_global.fw_sync):
                ipvs.append(nfa_global.fw_sync.pop())

            nfa_global.fw.install_hooks(ipvs)
            nfa_global.fw.sync(nfa_global.config_dynamic, ipvs)

        if task_cat_index_update is None:
            task_cat_index_update = nfa_cat_index_refresh(config_cat_index, ttl_cat_index)

        if task_cat_index_update is not None:
            task_cat_index_update = nfa_cat_index_reload(config_cat_index, config_app_proto, task_cat_index_update)

        if nfa_global.expire_matches:
            nfa_global.fw.expire_matches()
            nfa_global.expire_matches = False

        if fh is None:
            fh = nd.connect(
                nfa_global.config.get('netify-agent', 'socket-uri')
            )
            time.sleep(1)
        else:
            jd = nd.read()

            if jd is None:
                nd.close()
                fh = None
                time.sleep(5)
                continue

            if jd['type'] == 'flow':
                # Only interested in flows that have a remote partner
                if jd['flow']['other_type'] != 'remote': continue
                # Only interested in flows that originate from internal interfaces
                if not jd['internal']: continue

                # We can only mark the following: TCP, UDP, SCTP, and UDPLite
                if jd['flow']['ip_protocol'] != 6 and \
                    jd['flow']['ip_protocol'] != 17 and \
                    jd['flow']['ip_protocol'] != 132 and \
                    jd['flow']['ip_protocol'] != 136: continue

                # Ignore DNS and MDNS
                if jd['flow']['detected_protocol'] == 5 or \
                    jd['flow']['detected_protocol'] == 8: continue

                #syslog(LOG_DEBUG, str(jd))

                nfa_global.fw.process_flow(jd)

            if jd['type'] == 'agent_status':
                nfa_process_agent_status(jd)

    nd.close()
    nfa_global.fw.remove_hooks()

    return 0

if __name__ == "__main__":

    nfa_config_load()

    try:
        params, args = getopt(sys.argv[1:],
            'dR', (
                'debug',
                'save-default-config',
                'version',
                'help')
        )
    except GetoptError as e:
        print("Parameter error: %s" %(e.msg))
        print("Try option --help for usage information.")
        sys.exit(1)

    for option in params:
        if option[0] == '-d' or option[0] == '--debug':
            nfa_global.debug = True
        elif option[0] == '-R':
            nfa_global.foreground = True
        elif option[0] == '--save-default-config':
            print("Generating default configuration file: %s" %(NFA_CONF))
            nfa_config.save_main(NFA_CONF, nfa_global.config)
            sys.exit(0)
        elif option[0] == '--version':
            print("Netify FWA v%s" %(NFA_VERSION))
            sys.exit(0)
        elif option[0] == '--help':
            print("Netify FWA v%s" %(NFA_VERSION))
            sys.exit(0)

    if not nfa_global.debug and not nfa_global.foreground:
        nfa_global.log_options = LOG_PID
        openlog('netify-fwa', nfa_global.log_options, LOG_DAEMON)
        if not nfa_create_daemon():
            sys.exit(1)

    openlog('netify-fwa', nfa_global.log_options, LOG_DAEMON)
    syslog("Netify FWA v%s started." %(NFA_VERSION))

    signal(SIGALRM, nfa_signal_handler)
    signal(SIGHUP, nfa_signal_handler)
    signal(SIGINT, nfa_signal_handler)
    signal(SIGTERM, nfa_signal_handler)
    signal(SIGUSR1, nfa_signal_handler)
    signal(SIGUSR2, nfa_signal_handler)

    sys.exit(nfa_main())
