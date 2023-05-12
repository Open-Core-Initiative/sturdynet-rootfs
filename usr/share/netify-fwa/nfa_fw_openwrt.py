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
#
#----------------------------------------------------------------------------
#
# OpenWrt well know mark masks:
# - qos-scripts: 0x000000ff
# -       mwan3: 0x00003f00
# -   fwa-block: 0x00ff0000
# -    fwa-mark: 0xff000000
#----------------------------------------------------------------------------

from syslog import \
    openlog, syslog, LOG_PID, LOG_PERROR, LOG_DAEMON, \
    LOG_DEBUG, LOG_ERR, LOG_WARNING

import nfa_ipset
import nfa_rule
import nfa_util

from nfa_fw_iptables import nfa_fw_iptables

class nfa_fw_openwrt(nfa_fw_iptables):
    """OpenWrt PoC for Netify FWA"""

    def __init__(self, nfa_config):
        super(nfa_fw_openwrt, self).__init__(nfa_config)
        syslog(LOG_DEBUG, "OpenWrt driver initialized.")

    # Status

    def get_version(self):

        result = nfa_util.exec(
            'nfa_fw_openwrt::get_version', ["iptables", "--version"]
        )

        if result['rc'] == 0:
            version = result['stdout']
            parts = version.split()
            return "OpenWrt iptables %s" %(parts[1])
        else:
            return "OpenWrt"

    # Interfaces

    def get_external_interfaces(self):

        result = nfa_util.exec(
            'nfa_fw_openwrt::get_external_interfaces', ["uci", "get", "network.wan.ifname"]
        )

        if result['rc'] == 0:
            return result['stdout'].split(' ')
        else:
            return self.nfa_config.get('iptables', 'interfaces-external').split(',')

    def get_internal_interfaces(self):
        result = nfa_util.exec(
            'nfa_fw_openwrt::get_external_interfaces', ["uci", "get", "network.lan.ifname"]
        )

        if result['rc'] == 0:
            return result['stdout'].split(' ')
        else:
            return self.nfa_config.get('iptables', 'interfaces-internal').split(',')

    # Synchronize state

    def sync(self, config_dynamic, ipvs=[4, 6]):

        if (config_dynamic is None):
            return

        for ipv in ipvs:
            self.flush_chain('mangle', 'NFA_whitelist', ipv)
            self.flush_chain('mangle', 'NFA_ingress', ipv)
            self.flush_chain('mangle', 'NFA_egress', ipv)

            ipsets_new = []
            ipsets_created = []
            ipsets_existing = nfa_ipset.nfa_ipset_list(ipv)

            for rule in config_dynamic['rules']:
                if rule['type'] == 'block' or rule['type'] == 'ipset' or rule['type'] == 'mark':
                    if rule['type'] == 'mark':
                        # TODO: hard-coded for PoC. Review.
                        bitshift = 24
                        mark_mask = 0xff000000
                    else:
                        bitshift = self.mark_bitshift
                        mark_mask = self.mark_mask

                    if 'mark' not in rule:
                        mark = 1 << bitshift
                    else:
                        mark = int(rule['mark']) << bitshift

                    name = nfa_rule.criteria(rule)

                    if rule['type'] == 'ipset':
                        ipset_type= "hash:ip"
                    else:
                        ipset_type= "hash:ip,port,ip"

                    ipset = nfa_ipset.nfa_ipset(name, ipv, self.ttl_match, ipset_type)
                    ipsets_new.append(ipset.name)

                    if ipset.name not in ipsets_existing and ipset.name not in ipsets_created:
                        if ipset.create():
                            ipsets_created.append(ipset.name)
                        else:
                            syslog(LOG_WARNING, "Error creating ipset: %s" %(ipset.name))
                            continue

                    if rule['type'] == 'ipset':
                        continue;

                    directions = {}

                    if 'direction' not in rule or rule['direction'] == 'ingress':
                        directions.update({'ingress': 'src,src,dst'})
                    if 'direction' not in rule or rule['direction'] == 'egress':
                        directions.update({'egress': 'dst,dst,src'})

                    for direction, ipset_param in directions.items():

                        params = '-m set --match-set %s %s' %(ipset.name, ipset_param)

                        if 'weekdays' in rule or 'time-start' in rule:
                            params = '%s -m time' %(params)
                            if 'weekdays' in rule:
                                params = '%s --weekdays %s' %(params, rule['weekdays'])
                            if 'time-start' in rule:
                                params = '%s --timestart %s' %(params, rule['time-start'])
                            if 'time-stop' in rule:
                                params = '%s --timestop %s' %(params, rule['time-stop'])

                        self.add_rule('mangle', 'NFA_%s' %(direction),
                            '%s -j MARK --set-xmark 0x%x/0x%x' %(params, mark, mark_mask), ipv)

            for name in ipsets_existing:
                if name in ipsets_new: continue
                syslog(LOG_DEBUG, "ipset destroy: %s" %(name))
                nfa_ipset.nfa_ipset_destroy(name)

            for rule in config_dynamic['whitelist']:
                if rule['type'] == 'mac':
                    # TODO: iptables mac module only supports --mac-source
                    continue

                if ipv == 4 and rule['type'] != 'ipv4':
                    continue
                if ipv == 6 and rule['type'] != 'ipv6':
                    continue

                directions = ['-s', '-d']

                for direction in directions:
                    self.add_rule('mangle', 'NFA_whitelist',
                        '%s %s -j ACCEPT' %(direction, rule['address']), ipv)
