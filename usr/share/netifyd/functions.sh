# Netify Agent Utility Functions
# Copyright (C) 2016-2021 eGloo, Incorporated
#
# This is free software, licensed under the GNU General Public License v3.

NETIFYD_CONF="/etc/netifyd.conf"

[ -f /etc/conf.d/netifyd ] && . /etc/conf.d/netifyd
[ -f /etc/default/netifyd ] && . /etc/default/netifyd
[ -f /etc/sysconfig/netifyd ] && . /etc/sysconfig/netifyd

# Load defaults for RedHat/CentOS/Ubuntu/Debian
load_defaults()
{
    local options=""

    options=$NETIFYD_EXTRA_OPTS

    for entry in $NETIFYD_INTNET; do
        if [ "$entry" == "${entry/,/}" ]; then
            options="$options -I $entry"
            continue
        fi
        for net in ${entry//,/ }; do
            if [ "$net" == "${entry/,*/}" ]; then
                options="$options -I $net"
            else
                options="$options -A $net"
            fi
        done
    done

    for entry in $NETIFYD_EXTNET; do
        if [ "$entry" == "${entry/,/}" ]; then
            options="$options -E $entry"
            continue
        fi
        for ifn in ${entry//,/ }; do
            if [ "$ifn" == "${entry/,*/}" ]; then
                options="$options -E $ifn"
            else
                options="$options -N $ifn"
            fi
        done
    done

    options=$(echo "$options" |\
        sed -e 's/^[[:space:]]*//g' -e 's/[[:space:]]*$$//g')

    echo "$options"
}

# ClearOS: Dynamically add all configured LAN/WAN interfaces.
load_clearos()
{
    local options=""

    [ -f /etc/clearos/network.conf ] && . /etc/clearos/network.conf

    for ifn in $LANIF; do
        [ -z "$ifn" ] && break
        options="$options -I $ifn"
    done

    for ifn in $HOTIF; do
        [ -z "$ifn" ] && break
        options="$options -I $ifn"
    done

    for ifn in $EXTIF; do
        [ -z "$ifn" ] && break
        [ -f "/etc/sysconfig/network-scripts/ifcfg-${ifn}" ] &&
            . "/etc/sysconfig/network-scripts/ifcfg-${ifn}"
        if [ ! -z "$ETH" ]; then
            options="$options -E $ETH -N $ifn"
            unset ETH
        else
            options="$options -E $ifn"
        fi
    done

    options=$(echo "$options" |\
        sed -e 's/^[[:space:]]*//g' -e 's/[[:space:]]*$$//g')

    echo "$options"
}

# NethServer: Dynamically add all configured LAN/WAN interfaces.
load_nethserver()
{
    local options=""
    local ifcfg_sw="/etc/shorewall/interfaces"

    if [ -f "$ifcfg_sw" ]; then
        for ifn in $(grep '^loc[[:space:]]' $ifcfg_sw | awk '{ print $2 }'); do
            [ -z "$ifn" ] && break
            options="$options -I $ifn"
        done

        for ifn in $(grep "^blue[[:space:]]" $ifcfg_sw | awk '{ print $2 }'); do
            [ -z "$ifn" ] && break
            options="$options -I $ifn"
        done

        for ifn in $(grep "^orang[[:space:]]" $ifcfg_sw | awk '{ print $2 }'); do
            [ -z "$ifn" ] && break
            options="$options -I $ifn"
        done

        for ifn in $(grep '^net[[:space:]]' $ifcfg_sw | awk '{ print $2 }'); do
            [ -z "$ifn" ] && break
            [ -f "/etc/sysconfig/network-scripts/ifcfg-${ifn}" ] &&
                . "/etc/sysconfig/network-scripts/ifcfg-${ifn}"
            if [ ! -z "$ETH" ]; then
                options="$options -E $ETH -N $ifn"
                unset ETH
            else
                options="$options -E $ifn"
            fi
        done
    fi

    options=$(echo "$options" |\
        sed -e 's/^[[:space:]]*//g' -e 's/[[:space:]]*$$//g')

    echo "$options"
}

# OpenWrt: Dynamically add all configured LAN/WAN interfaces.
load_openwrt()
{
    local options="-I br-lan"

    ifn=$(uci get network.wan.ifname)
    [ ! -z "$ifn" ] && options="$options -E $ifn"

    options=$(echo "$options" |\
        sed -e 's/^[[:space:]]*//g' -e 's/[[:space:]]*$$//g')

    echo "$options"
}

# EdgeOS: Dynamically add all configured LAN/WAN interfaces.
load_edgeos()
{
    echo "$(/usr/share/netifyd/netify_edgeos/options.py)"
}

# pfSense: Dynamically add all configured LAN/WAN interfaces.
load_pfsense()
{
    local conf="$1"
    local xpath_ifaces="$2"
    local xmllint="/usr/local/bin/xmllint"

    for role in lan wan; do
        i=1; while true; do
            xpath="$xpath_ifaces/$role[$i]"
            $xmllint --xpath "$xpath/enable" $conf >/dev/null 2>&1 || break
            enabled=$($xmllint --xpath "boolean($xpath/enable)" $conf)

            if [ "$enabled" == "true" ]; then
                ifn=$($xmllint --xpath "$xpath/if/text()" $conf)
                case "$role" in
                    lan)
                        options="$options -I $ifn"
                        ;;
                    wan)
                        options="$options -E $ifn"
                        ;;
                    esac
            fi

            i=$(expr $i + 1)
        done
    done

    options=$(echo "$options" |\
        sed -e 's/^[[:space:]]*//g' -e 's/[[:space:]]*$$//g')

    echo "$options"
}

load_modules()
{
    modprobe nfnetlink >/dev/null 2>&1
    modprobe nf_conntrack_netlink >/dev/null 2>&1
}

detect_os()
{
    if [ -f /etc/version ]; then
        if egrep -q '^UniFiSecurityGateway' /etc/version; then
            echo "edgeos"
            return
        fi
    fi

    if [ -f /etc/os-release ]; then
        if egrep -q '^NAME=UbiOS' /etc/os-release; then
            echo "ubios"
            return
        fi
    fi

    if [ -f /etc/issue ]; then
        if egrep -q '^Ubuntu' /etc/issue; then
            echo "ubuntu"
            return
        fi
    fi

    if [ -f /etc/clearos-release ]; then
        echo "clearos"
    elif [ -f /etc/nethserver-release ]; then
        echo "nethserver"
    elif [ -f /etc/gentoo-release ]; then
        echo "gentoo"
    elif [ -f /etc/openwrt_release ]; then
        echo "openwrt"
    elif [ -f /usr/local/sbin/opnsense-version ]; then
            echo "opnsense"
    elif [ -x /bin/freebsd-version ]; then
        if [ -f /etc/version ]; then
            echo "pfsense"
        else
            echo "freebsd"
        fi
    elif [ -f /etc/debian_version ]; then
        echo "debian"
    elif [ -f /etc/centos-release ]; then
        echo "centos"
    elif [ -f /etc/redhat-release ]; then
        echo "redhat"
    else
        echo "unknown"
    fi
}

auto_detect_options()
{
    local options=""

    options=$(load_defaults)

    if [ "$NETIFYD_AUTODETECT" == "yes" ]; then
        case "$(detect_os)" in
            clearos)
                options=$(load_clearos)
            ;;
            nethserver)
                options=$(load_nethserver)
            ;;
            openwrt)
                options=$(load_openwrt)
            ;;
            opnsense)
                options=$(load_pfsense "/conf/config.xml" "/opnsense/interfaces")
            ;;
            pfsense)
                options=$(load_pfsense "/cf/conf/config.xml" "/pfsense/interfaces")
            ;;
            edgeos)
                options=$(load_edgeos)
            ;;
        esac
    fi

    echo "$options"
}

restart_netifyd()
{
    case "$(detect_os)" in
        clearos)
            systemctl restart netifyd
        ;;
        nethserver)
            systemctl restart netifyd
        ;;
        freebsd)
            /etc/rc.d/netifyd restart
        ;;
        opnsense)
            /etc/rc.d/netifyd restart
        ;;
        pfsense)
            /etc/rc.d/netifyd.sh restart
        ;;
        *)
            /etc/init.d/netifyd restart
        ;;
    esac
}

config_enable_sink()
{
    if egrep -i -q '^enable_sink = (no|0|false)' $NETIFYD_CONF; then
        sed -i -e 's/^enable_sink.*/enable_sink = yes/' $NETIFYD_CONF
        restart_netifyd
    fi
}

config_disable_sink()
{
    if egrep -i -q '^enable_sink = (yes|1|true)' $NETIFYD_CONF; then
        sed -i -e 's/^enable_sink.*/enable_sink = no/' $NETIFYD_CONF
        restart_netifyd
    fi
}

# vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4 syntax=sh
