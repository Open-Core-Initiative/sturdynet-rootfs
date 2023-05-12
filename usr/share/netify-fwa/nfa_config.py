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
import configparser
import nfa_global

from syslog import \
    openlog, syslog, LOG_PID, LOG_PERROR, LOG_DAEMON, \
    LOG_DEBUG, LOG_ERR, LOG_WARNING

from nfa_defaults import \
        NFA_CONF_DYNAMIC, NFA_PATH_STATUS, NFA_PATH_STATUS_MATCHES, \
        NFA_PATH_APP_PROTO_DATA, NFA_PATH_CATEGORIES, NFA_URI_SOCKET, \
        NFA_URI_API, NFA_TTL_MATCH, NFA_TTL_CATEGORY_INDEX

from nfa_version import NFA_JSON_CONFIG_VERSION

def create_main():
    config = {}

    config = configparser.ConfigParser()

    config.add_section('netify-fwa')
    config.set('netify-fwa', 'firewall-engine', 'firewalld')
    config.set('netify-fwa', 'path-config-dynamic', NFA_CONF_DYNAMIC)
    config.set('netify-fwa', 'path-status', NFA_PATH_STATUS)
    config.set('netify-fwa', 'path-status-matches', NFA_PATH_STATUS_MATCHES)
    config.set('netify-fwa', 'ttl-match', '%d' %(NFA_TTL_MATCH))

    config.add_section('firewalld')
    config.set('firewalld', 'zones-external', 'public')
    config.set('firewalld', 'zones-internal', 'internal')

    config.add_section('iptables')
    config.set('iptables', 'mark-bitshift', '11')
    config.set('iptables', 'mark-mask', '0x800')
    config.set('iptables', 'interfaces-external', 'eth0')
    config.set('iptables', 'interfaces-internal', 'eth1,eth2')

    # TODO: Add ClearOS options
    #config.add_section('clearos')

    config.add_section('netify-agent')
    config.set('netify-agent', 'socket-uri', NFA_URI_SOCKET)

    config.add_section('netify-api')
    config.set('netify-api', 'path-app-proto-data', NFA_PATH_APP_PROTO_DATA)
    config.set('netify-api', 'path-category-index', NFA_PATH_CATEGORIES)
    config.set('netify-api', 'ttl-category-index', '%d' %(NFA_TTL_CATEGORY_INDEX))
    config.set('netify-api', 'url', NFA_URI_API)

    return config

def load_main(path):
    config = create_main()

    not_found = False

    try:
        with open(path, 'r') as fd:
            config.read_file(fd)
    except FileNotFoundError as e:
        not_found = True
        syslog(LOG_WARNING, "Configuration file not found: %s" %(path))

    if not_found:
        save_main(path, config)

    return config

def save_main(path, config):
    with open(path, 'w') as fd:
        config.write(fd)

def key_exists(data, name, key, required=True):
    if key not in data:
        if required:
            syslog(LOG_ERR, "Malformed %s, required key \"%s\" not found." %(name, key))
        return False

    return True

def one_key_exists(data, name, keys):
    key_found = False
    for key in keys:
        if key in data:
            key_found = True
            break

    if not key_found:
        syslog(LOG_ERR, "Malformed %s, at least one key required: \"%s\"." %(name, ', '.join(keys)))
        return False

    return True

def all_keys_exists(data, name, keys):
    keys_found = True
    for key in keys:
        if key not in data:
            keys_found = False
            break

    if not keys_found:
        syslog(LOG_ERR, "Malformed %s, all keys required: \"%s\"." %(name, ', '.join(keys)))
        return False

    return True

def load_json(path):
    data = None
    try:
        with open(path, 'r') as fd:
            data = json.load(fd)
    except json.decoder.JSONDecodeError as e:
        syslog(LOG_WARNING,
            "JSON file is invalid: %s on line: %d, column: %d: %s"
            %(e.msg, e.lineno, e.colno, path))
    except FileNotFoundError as e:
        syslog(LOG_WARNING, "JSON file not found: %s" %(path))

    return data

def load_dynamic(path):
    config = load_json(path)

    if config is None:
        return None

    name = 'dynamic JSON configuration'

    if not key_exists(config, name, 'version'):
        return None

    if float(config['version']) > NFA_JSON_CONFIG_VERSION:
        syslog(LOG_ERR, "Unsupported %s version: %.02f" %(name, config['version']))
        return None

    if not key_exists(config, name, 'rules', False):
        config['rules'] = []
    if not key_exists(config, name, 'whitelist', False):
        config['whitelist'] = []

    valid_rule_types = [ 'ipset', 'mark', 'block', 'prioritize' ]

    parsed_rules = []

    for rule in config['rules']:

        if not key_exists(rule, name, 'type'):
            return None

        if rule['type'] not in valid_rule_types:
            syslog(LOG_ERR,
                "Malformed %s, invalid rule type: \"%s\"." %(name, rule['type']))
            return None

        if rule['type'] == 'prioritize' and not key_exists(rule, name, 'priority'):
            return None

        if not one_key_exists(rule, name, [
            'protocol', 'application', 'protocol_category', 'application_category'
            ]):
            return None

        if 'time-start' in rule and 'time-stop' not in rule:
            syslog(LOG_ERR,
                "Malformed %s, required key not found: \"%s\"." %(name, 'time-stop'))
            return None

        # Support tags, but bend a bit to keep everything backwards compatible with IDs
        # The example internal structure is:
        # - rule['application'] = ID
        # - rule['application_tag'] = 'netyify.app'

        if nfa_global.config_app_proto is not None:
            if 'application' in rule and isinstance(rule['application'], str):
                # Add netify prefix if no prefix exists
                if "." not in rule['application']:
                    rule['application'] = 'netify.' + rule['application']

                if 'application_tags' in nfa_global.config_app_proto and rule['application'] in nfa_global.config_app_proto['application_tags']:
                    rule['application_tag'] = rule['application']
                    rule['application'] = nfa_global.config_app_proto['application_tags'][rule['application']]
                    parsed_rules.append(rule)

            elif 'protocol' in rule and isinstance(rule['protocol'], str):
                if 'protocol_tags' in nfa_global.config_app_proto and rule['protocol'] in nfa_global.config_app_proto['protocol_tags']:
                    rule['protocol_tag'] = rule['protocol']
                    rule['protocol'] = nfa_global.config_app_proto['protocol_tags'][rule['protocol']]
                    parsed_rules.append(rule)

            elif 'application_category' in rule and isinstance(rule['application_category'], str):
                if 'application_category_tags' in nfa_global.config_app_proto and rule['application_category'] in nfa_global.config_app_proto['application_category_tags']:
                    rule['application_category_tag'] = rule['application_category']
                    rule['application_category'] = nfa_global.config_app_proto['application_category_tags'][rule['application_category']]
                    parsed_rules.append(rule)

            elif 'protocol_category' in rule and isinstance(rule['protocol_category'], str):
                if 'protocol_category_tags' in nfa_global.config_app_proto and rule['protocol_category'] in nfa_global.config_app_proto['protocol_category_tags']:
                    rule['protocol_category_tag'] = rule['protocol_category']
                    rule['protocol_category'] = nfa_global.config_app_proto['protocol_category_tags'][rule['protocol_category']]
                    parsed_rules.append(rule)

        else:
            parsed_rules.append(rule)

    config['rules'] = parsed_rules

    valid_whitelist_types = [ 'mac', 'ipv4', 'ipv6' ]

    for addr in config['whitelist']:

        if not key_exists(addr, name, 'type'):
            return None

        if addr['type'] not in valid_whitelist_types:
            syslog(LOG_ERR,
                "Malformed %s, invalid address type: \"%s\"." %(name, addr['type']))
            return None

        if not key_exists(addr, name, 'address'):
            return None

    return config

def load_app_proto(path):
    return load_json(path)

def load_cat_index(path):
    return load_json(path)

def load_matches(path):
    return load_json(path)
