#!/bin/sh

# (Re)assign the router's static ULA addresses: main LAN (br0) and every custom VLAN bridge.
# Idempotent. Called on dnsmasq start (service-event), after bridge rebuilds (service-event-end)
# and on DHCPv6 events (dhcpc-event). restart_wireless drops these addresses from all three bridges;
# dnsmasq picks them up again through netlink and resumes RAs / DHCPv6 without a restart.

. /jffs/scripts/lan_ula_config.env
. /jffs/scripts/vlan_config.env
LOGGER_TAG=$(basename $0)

add_ula() {
    ip -6 addr show dev "$1" 2>/dev/null | grep -q " ${2%/*}/" && return 0
    ip -6 addr add dev "$1" "$2" && logger -t "$LOGGER_TAG" "added $2 to $1"
}

add_ula br0 "$LAN_ULA_PREFIX"1/"$LAN_ULA_PREFIX_LEN"
for VID in $RM_VLAN_ID $IOT_VLAN_ID; do
    . /jffs/scripts/vlan_info.sh $VID
    [ -n "$VLAN_BR" ] && add_ula $VLAN_BR $VLAN_ULA_ADDR_CIDR
done
