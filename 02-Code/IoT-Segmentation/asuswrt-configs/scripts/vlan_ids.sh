#!/bin/sh

# Print the ID of every VLAN defined in vlan_config.env, one per line.
# A VLAN is any variable named *_VLAN_ID; the main LAN is not a VLAN here.

VLAN_CONFIG=/jffs/scripts/vlan_config.env
. $VLAN_CONFIG

for VAR in $(sed -n -e 's/^export //' -e 's/^\([A-Za-z0-9_]*_VLAN_ID\)=.*/\1/p' $VLAN_CONFIG); do
    eval "echo \"\$$VAR\""
done
