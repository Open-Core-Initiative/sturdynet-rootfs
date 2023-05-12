import re
import time
import math

from syslog import \
    openlog, syslog, LOG_PID, LOG_PERROR, LOG_DAEMON, \
    LOG_DEBUG, LOG_ERR, LOG_WARNING

import nfa_defaults
import nfa_global

def criteria(rule):
    criteria = '';

    if 'protocol_tag' in rule:
        criteria = 'PROTO_' + rule['protocol_tag'].replace('-', '_')
    elif 'protocol' in rule:
        criteria = 'PROTO_' + str(rule['protocol'])

    elif 'protocol_category_tag' in rule:
        criteria = 'PROTOCAT_' + rule['protocol_category_tag'].replace('-', '_')
    elif 'protocol_category' in rule:
        criteria = 'PROTOCAT_' + str(rule['protocol_category'])

    elif 'application_tag' in rule:
        criteria = 'APP_' + re.sub(r'^netify.', r'', rule['application_tag']).replace('-', '_')
    elif 'application' in rule:
        criteria = 'APP_' + str(rule['application'])

    elif 'application_category_tag' in rule:
        criteria = 'APPCAT_' + rule['application_category_tag'].replace('-', '_')
    elif 'application_category' in rule:
        criteria = 'APPCAT_' + str(rule['application_category'])

    else:
        criteria = 'RAW_'

    return criteria

def flow_matches(flow, rule):
    if nfa_global.rx_app_id is None:
        nfa_global.rx_app_id = re.compile('\d+')
        syslog(LOG_DEBUG, 'Compiled app_id regex.')

    if 'enable' in rule and rule['enable'] == False:
        return False

    match = {
        'timestamp': math.floor(time.time()),
        'type': rule['type'],
        'protocol': 0, 'application': 0,
        'protocol_category': 0, 'application_category': 0,
        'flows': 1
    }

    app_id = 0
    app_match = nfa_global.rx_app_id.match(flow['detected_application_name'])
    if app_match is not None:
        app_id = int(app_match.group())

    if 'protocol' in rule:
        if flow['detected_protocol'] != int(rule['protocol']):
            return False
        else:
            match['protocol'] = int(rule['protocol'])
    if 'application' in rule:
        if app_id != int(rule['application']):
            return False
        else:
            match['application'] = int(rule['application'])

    try:
        if 'protocol_category' in rule:
            key = str(flow['detected_protocol'])
            if key not in nfa_global.config_cat_index['protocols']:
                return False
            if nfa_global.config_cat_index['protocols'][key] != int(rule['protocol_category']):
                return False
            match['protocol_category'] = int(rule['protocol_category'])
        if 'application_category' in rule:
            key = str(app_id)
            if key not in nfa_global.config_cat_index['applications']:
                return False
            if nfa_global.config_cat_index['applications'][key] != int(rule['application_category']):
                return False
            match['application_category'] = int(rule['application_category'])
    except TypeError:
        return False

    updated = False
    for i, match_compare in enumerate(nfa_global.matches):

        if match_compare['protocol'] == match['protocol'] \
            and match_compare['application'] == match['application'] \
            and match_compare['protocol_category'] == match['protocol_category'] \
            and match_compare['application_category'] == match['application_category']:

            nfa_global.matches[i]['flows'] += 1
            nfa_global.matches[i]['timestamp'] = math.floor(time.time())

            updated = True
            break

    if updated is False:
        nfa_global.matches.append(match)

    return True
