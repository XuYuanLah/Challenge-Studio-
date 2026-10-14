#!/bin/sh

# STP for the bridges that need it, following the web UI switch (nvram lan_stp).
# Applied from firewall-start, and re-applied from service-event-end after network/wireless/lan
# restarts, because restart_wireless resets STP on the VLAN bridges.
# Only ever turns STP on: bridges default to off, so with the switch off, or for bridges not listed
# here (the IoT VLAN: Wi-Fi and single-device access ports, no loop possible), STP stays off.

[ "$(nvram get lan_stp)" = 1 ] || exit 0

. /jffs/scripts/vlan_config.env

# Main LAN: the web UI switch alone doesn't take effect on br0 (firmware bug)
brctl stp br0 on
brctl setbridgeprio br0 10

# Roommate VLAN: trunk to his AP-mode router
. /jffs/scripts/vlan_info.sh $RM_VLAN_ID >/dev/null
brctl stp $VLAN_BR on
brctl setbridgeprio $VLAN_BR 10
