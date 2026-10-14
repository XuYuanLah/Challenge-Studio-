#!/bin/sh

# Route, address and firewall rules for the ONT (PON module) management subnet on the WAN side.
# Run once from firewall-start, before its own rules: everything here is inserted at the top of
# FORWARD, so firewall-start's later inserts land above it. Only the IoT WAN LOG rule (no verdict)
# matches ONT traffic before these rules, so IoT attempts are still logged as IOT_TO_WAN_NEW.

# PON module and router IP settings (ONT_NET_CIDR, ONT_IP, ROUTER_ONT_IP[_CIDR])
. /jffs/scripts/ont_config.env

# Try to detect physical WAN interface
WANPHY="$(nvram get wan0_gw_ifname)"
[ -z "$WANPHY" ] && WANPHY="$(nvram get wan0_ifname)"

# Add secondary IP to WAN-facing interface
ip addr show dev "$WANPHY" | grep -q "$ROUTER_ONT_IP" || \
    ip addr add "$ROUTER_ONT_IP_CIDR" dev "$WANPHY"

# Ensure route exists
ip route replace "$ONT_NET_CIDR" dev "$WANPHY" src "$ROUTER_ONT_IP"

# Allow main LAN -> ONT management traffic
iptables -C FORWARD -i br0 -d "$ONT_NET_CIDR" -j ACCEPT 2>/dev/null || \
    iptables -I FORWARD 1 -i br0 -d "$ONT_NET_CIDR" -j ACCEPT

# Block ONT management from every VLAN (the generic VLAN -> WAN accepts would let it through).
# IPv4 only: the ONT has no IPv6 management address.
for VID in $(/jffs/scripts/vlan_ids.sh); do
    . /jffs/scripts/vlan_info.sh $VID
    iptables -C FORWARD -i "$VLAN_BR" -d "$ONT_NET_CIDR" -j DROP 2>/dev/null || \
        iptables -I FORWARD -i "$VLAN_BR" -d "$ONT_NET_CIDR" -j DROP
done

# SNAT so the ONT replies to the router instead of your LAN subnet
iptables -t nat -C POSTROUTING -d "$ONT_NET_CIDR" -j SNAT --to-source "$ROUTER_ONT_IP" 2>/dev/null || \
    iptables -t nat -I POSTROUTING 1 -d "$ONT_NET_CIDR" -j SNAT --to-source "$ROUTER_ONT_IP"
