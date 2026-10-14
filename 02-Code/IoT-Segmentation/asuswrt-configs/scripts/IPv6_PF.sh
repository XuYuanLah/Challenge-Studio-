#!/bin/sh

# Remember to set static ULA in dnsmasq config
# Open firewall
#ip6tables -I FORWARD -i [IF] -m state --state NEW -p [PROT] --dport [DEV_PORT] -d [DEV_IP] -j ACCEPT
# NAT forward
#ip6tables -t nat -A PREROUTING -i [IF] -p [PROT] --dport [EXT_PORT] -j DNAT --to-destination [DEV_IP]:[DEV_PORT]

# Gets LAN_ULA_*
#. /jffs/scripts/lan_ula_config.env

if [ "$#" -lt 4 ] || [ "$#" -gt 5 ] ; then
    echo "Error: incorrect number of arguments" >&2
    echo "Usage: $0 EXT_PORT DEV_PORT DEV_IP PROT [SRC_IP]" >&2
    exit 1
fi

WAN_IF=$(nvram get wan0_gw_ifname)
#LAN_BR_IF=$(nvram get lan_ifname)
EXT_PORT="$1"
DEV_PORT="$2"
DEV_IP="$3"
PROT="$4"
SRC_IP="$5"
# Same as the one in ddns-start
#BR_GUA=$([ -n "$LAN_BR_IF" ] && ip -6 addr list scope global $LAN_BR_IF | grep -v " fd" | sed -n 's/.*inet6 \([0-9a-f:]\+\).*/\1/p' | head -n 1)

# Open firewall
# WAN interface
ip6tables -I FORWARD \
          -i "$WAN_IF" -m state --state NEW \
          -p "$PROT" --dport "$DEV_PORT" -d "$DEV_IP" -j ACCEPT

# Create NAT rules
# No source IP
if [ "$#" -eq 4 ]; then
    # WAN interface - accessing from internet
    ip6tables -t nat -A PREROUTING \
              -i "$WAN_IF" -p "$PROT" --dport "$EXT_PORT" \
              -j DNAT --to-destination ["$DEV_IP"]:"$DEV_PORT"

    # Main LAN bridge - accessing from inside
    # Gave up - IPv6 hairpinning won't work with ip6tables v1.4.15
    # DNAT rule works
    #ip6tables -t nat -A PREROUTING \
    #          -i "$LAN_BR_IF" -p "$PROT" --dport "$EXT_PORT" \
    #          -j DNAT --to-destination ["$DEV_IP"]:"$DEV_PORT"
    # SNAT or MASQUERADE rule does not, cannot do hairpin, results in invalid connection pairs (address mismatch)
    #ip6tables -t nat -A POSTROUTING \
    #          -s "$LAN_ULA_CIDR" -d "$LAN_ULA_CIDR" \
    #          -o "$LAN_BR_IF" -p "$PROT" --sport "$DEV_PORT" -j MASQUERADE
    # A more general version exactly like the IPv4 hairpin rule, still doesn't work
    #ip6tables -t nat -A POSTROUTING \
    #          -s "$LAN_ULA_CIDR" -d "$LAN_ULA_CIDR" \
    #          -j MASQUERADE
    # SNAT version, negligible performance increase but needs to be rerun with dhcp-event, also incompatible with ip6tables v1.4.15 in asuswrt
    #ip6tables -t nat -A POSTROUTING \
    #          -s "$LAN_ULA_CIDR" -d "$LAN_ULA_CIDR" \
    #          -o "$LAN_BR_IF" -p "$PROT" --sport "$DEV_PORT" -j SNAT --to-source ["$BR_GUA"]
# With source IP
elif [ "$#" -eq 5 ]; then
    ip6tables -t nat -A PREROUTING \
              -i "$WAN_IF" -p "$PROT" -s "$SRC_IP" --dport "$EXT_PORT" \
              -j DNAT --to-destination ["$DEV_IP"]:"$DEV_PORT"
fi
