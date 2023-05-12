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

from syslog import \
    openlog, syslog, LOG_PID, LOG_PERROR, LOG_DAEMON, \
    LOG_DEBUG, LOG_ERR, LOG_WARNING

import nfa_global
import nfa_ipset
import nfa_rule
import nfa_util

class nfa_fw_iptables():
    """Generic iptables support for Netify FWA"""

    def __init__(self, nfa_config):

        self.flavor = 'iptables'
        self.nfa_config = nfa_config
        self.ttl_match = int(self.nfa_config.get('netify-fwa', 'ttl-match'))
        self.mark_bitshift = int(nfa_config.get('iptables', 'mark-bitshift'))
        self.mark_mask = int(nfa_config.get('iptables', 'mark-mask'), 16)

        syslog(LOG_DEBUG, "IPTables Firewall driver initialized.")

    def ip_version(self, ipv):
        if ipv == 6:
            return 'ipv6'
        return 'ipv4'

    # Status

    def get_version(self):

        result = nfa_util.exec(
            'nfa_fw_iptables::get_version', ["iptables", "--version"]
        )

        if result['rc'] == 0:
            return result['stdout']

        return 'iptables'

    def is_running(self):
        return True

    # Interfaces

    def get_external_interfaces(self):
        return self.nfa_config.get('iptables', 'interfaces-external').split(',')

    def get_internal_interfaces(self):
        return self.nfa_config.get('iptables', 'interfaces-internal').split(',')

    # Chains

    def get_chains(self):

        table = 'mangle'
        nfa_chains = []

        for ipv in [ 4, 6 ]:
            iptables = 'ip%stables' %('' if ipv == 4 else '6')

            result = nfa_util.exec(
                'nfa_fw_iptables::get_chains', [ iptables, '-w', '-t', table, '-S' ]
            )

            if result['rc'] != 0:
                return nfa_chains

            lines = result['stdout'].rstrip().split("\n")

            for line in lines:
                if line.startswith('-N NFA_'):
                    chain = line.split()
                    nfa_chains.append([ 'ipv' + str(ipv), table, chain[1] ])

        return nfa_chains

    def chain_exists(self, table, name, ipv=4):
        chains = self.get_chains()
        for chain in chains:
            if self.ip_version(ipv) == chain[0] and \
                table == chain[1] and name[0:28] == chain[2]:
                return True
        return False

    def add_chain(self, table, name, ipv=4):
        if not self.chain_exists(table, name, ipv):
            iptables = 'ip%stables' %('' if ipv == 4 else '6')

            result = nfa_util.exec(
                'nfa_fw_iptables::add_chain', [ iptables, '-w', '-t', table, '-N', name ]
            )

            if result['rc'] == 0:
                return True

        return False

    def flush_chain(self, table, name, ipv=4):
        if self.chain_exists(table, name, ipv):
            iptables = 'ip%stables' %('' if ipv == 4 else '6')

            result = nfa_util.exec(
                'nfa_fw_iptables::flush_chain', [ iptables, '-w', '-t', table, '-F', name ]
            )

            if result['rc'] == 0:
                return True

        return False

    def delete_chain(self, table, name, ipv=4):
        if self.chain_exists(table, name, ipv):
            iptables = 'ip%stables' %('' if ipv == 4 else '6')

            result = nfa_util.exec(
                'nfa_fw_iptables::delete_chain', [ iptables, '-w', '-t', table, '-X', name ]
            )

            if result['rc'] == 0:
                return True

        return False

    # Rules

    def rule_exists(self, table, chain, args, ipv=4, priority=0):

        if not chain.startswith('NFA_') or self.chain_exists(table, chain, ipv):
            iptables = 'ip%stables' %('' if ipv == 4 else '6')
            params = [ iptables, '-w', '-t', table, '-C', chain ] + args.split()

            result = nfa_util.exec('nfa_fw_iptables::rule_exists', params)

            if result['rc'] == 0:
                return True

        return False

    def add_rule(self, table, chain, args, ipv=4, priority=0):

        iptables = 'ip%stables' %('' if ipv == 4 else '6')
        params = [ iptables, '-w', '-t', table, '-A', chain ] + args.split()

        result = nfa_util.exec('nfa_fw_iptables::add_rule', params)

        if result['rc'] != 0:
            return False

        return True

    def delete_rule(self, table, chain, args, ipv=4, priority=0):

        if self.rule_exists(table, chain, args, ipv, priority):
            iptables = 'ip%stables' %('' if ipv == 4 else '6')
            params = [ iptables, '-w', '-t', table, '-D', chain ] + args.split()

            result = nfa_util.exec('nfa_fw_iptables::delete_rule', params)

            if result['rc'] == 0:
                return True

        return False


    # Install hooks

    def install_hooks(self, ipvs=[4,6]):
        ifn_int = self.get_internal_interfaces()
        ifn_ext = self.get_external_interfaces()

        if len(ifn_int) == 0 and len(ifn_ext) == 0:
            syslog(LOG_ERR, "No interfaces with roles defined.")
            return False

        for iface in ifn_int:
            syslog(LOG_DEBUG, "Prepping internal interface hooks: %s" %(iface))

        for iface in ifn_ext:
            syslog(LOG_DEBUG, "Prepping external interface hooks: %s" %(iface))

        # Create whitelist chain
        for ipv in ipvs:
            self.add_chain('mangle', 'NFA_whitelist', ipv)

            # Add jumps to whitelist chain
            self.add_rule('mangle', 'FORWARD', '-j NFA_whitelist', ipv)

            # Create ingress/egress chains
            self.add_chain('mangle', 'NFA_ingress', ipv)
            self.add_chain('mangle', 'NFA_egress', ipv)

            # Add jumps to ingress/egress chains
            for iface in ifn_ext:
                self.add_rule('mangle', 'FORWARD',
                    '-i %s -j NFA_ingress' %(iface), ipv)
            for iface in ifn_int:
                self.add_rule('mangle', 'FORWARD',
                    '-i %s -j NFA_egress' %(iface), ipv)

            # Create block chain
            self.add_chain('mangle', 'NFA_block', ipv)
            self.add_rule('mangle', 'NFA_block', '-j DROP', ipv)

            # Add jumps to block chain
            self.add_rule('mangle', 'FORWARD',
                '-m mark ! --mark 0x0/0x%x -j NFA_block' %(self.mark_mask),
                ipv)

        return True

    # Remove hooks

    def remove_hooks(self):
        ifn_int = self.get_internal_interfaces()
        ifn_ext = self.get_external_interfaces()

        for ipv in [4, 6]:
            if self.chain_exists('mangle', 'NFA_whitelist', ipv):
                self.delete_rule('mangle', 'FORWARD', '-j NFA_whitelist', ipv)

            for iface in ifn_ext:
                if self.chain_exists('mangle', 'NFA_ingress', ipv):
                    self.delete_rule('mangle', 'FORWARD',
                        '-i %s -j NFA_ingress' %(iface), ipv)
            for iface in ifn_int:
                if self.chain_exists('mangle', 'NFA_egress', ipv):
                    self.delete_rule('mangle', 'FORWARD',
                        '-i %s -j NFA_egress' %(iface), ipv)

            self.flush_chain('mangle', 'NFA_whitelist', ipv)
            self.delete_chain('mangle', 'NFA_whitelist', ipv)

            self.flush_chain('mangle', 'NFA_ingress', ipv)
            self.delete_chain('mangle', 'NFA_ingress', ipv)

            self.flush_chain('mangle', 'NFA_egress', ipv)
            self.delete_chain('mangle', 'NFA_egress', ipv)

            if self.chain_exists('mangle', 'NFA_block', ipv):
                self.delete_rule('mangle', 'FORWARD',
                    '-m mark ! --mark 0x0/0x%x -j NFA_block' %(
                        self.mark_mask
                    ), ipv)

            self.flush_chain('mangle', 'NFA_block', ipv)
            self.delete_chain('mangle', 'NFA_block', ipv)

            for name in nfa_ipset.nfa_ipset_list(ipv):
                nfa_ipset.nfa_ipset_destroy(name)

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
                if rule['type'] != 'block': continue

                if 'mark' not in rule:
                    mark = 1 << self.mark_bitshift
                else:
                    mark = int(rule['mark']) << self.mark_bitshift

                name = nfa_rule.criteria(rule)

                ipset = nfa_ipset.nfa_ipset(name, ipv, self.ttl_match)
                ipsets_new.append(ipset.name)

                if ipset.name not in ipsets_existing and ipset.name not in ipsets_created:
                    if ipset.create():
                        ipsets_created.append(ipset.name)
                    else:
                        syslog(LOG_WARNING, "Error creating ipset: %s" %(ipset.name))
                        continue

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
                        '%s -j MARK --set-xmark 0x%x/0x%x' %(params, mark, self.mark_mask), ipv)

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

    # Process flow

    def process_flow(self, flow):

        if nfa_global.config_dynamic is None:
            return

        for rule in nfa_global.config_dynamic['rules']:
            if rule['type'] == 'block' or rule['type'] == 'ipset' or rule['type'] == 'mark':
                if not nfa_rule.flow_matches(flow['flow'], rule): continue

                name = nfa_rule.criteria(rule)

                if rule['type'] == 'ipset':
                    ipset_type= "hash:ip"
                else:
                    ipset_type= "hash:ip,port,ip"

                ipset = nfa_ipset.nfa_ipset(name, flow['flow']['ip_version'], 0, ipset_type)

                if not ipset.upsert( \
                    flow['flow']['other_ip'], flow['flow']['other_port'], \
                    flow['flow']['local_ip']):
                    syslog(LOG_WARNING, "Error upserting ipset with flow match.")
                else:
                    nfa_global.stats['blocked'] += 1

                break

    # Expire matches

    def expire_matches(self):
        pass

    # Test

    def test(self):
        syslog(LOG_DEBUG, "chains: %s" %(self.get_chains()))
