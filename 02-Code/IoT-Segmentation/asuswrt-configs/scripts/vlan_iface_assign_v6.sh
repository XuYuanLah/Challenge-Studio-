#!/bin/sh

# Print usage
usage() {
  echo "Usage:"
  echo "  $0 <VLAN_ID> <INTERFACE>         # Assign IP address to interface"
  echo "  $0 -s <VLAN_ID> | --show-address # Show IPv6 address, no action"
  exit 1
}

# Check for --show-address mode
SHOW_ONLY=0
if [ "$1" = "-s" ] || [ "$1" = "--show-address" ]; then
  SHOW_ONLY=1
  VLAN_ID="$2"
  if [ -z "$VLAN_ID" ]; then
    usage
  fi
else
  # Regular mode: must have VLAN_ID and INTERFACE
  if [ "$#" -ne 2 ]; then
    usage
  fi
  VLAN_ID="$1"
  IFACE="$2"
fi

# Validate VLAN ID is numeric
if ! echo "$VLAN_ID" | grep -Eq '^[0-9]+$'; then
  echo "Error: VLAN_ID must be numeric"
  exit 1
fi

# Convert VLAN ID to hexadecimal
VLAN_HEX=$(printf "%x" "$VLAN_ID")

# Extract GLOBAL (non-ULA & non-link-local) IPv6 address from br0
GLOBAL_IP=$(ip -6 addr show dev br0 \
  | awk '/inet6 [^f][^d|e]/ && /scope global/ { print $2; exit }')

if [ -z "$GLOBAL_IP" ]; then
  echo "No global IPv6 address found on br0. Exiting."
  exit 1
fi

# Extract first 3 hextets from IPv6 address (for /48 prefix)
PREFIX_48=$(echo "$GLOBAL_IP" | cut -d/ -f1 \
  | awk -F: '{ printf "%x:%x:%x", "0x"$1, "0x"$2, "0x"$3 }')

# Construct /64 prefix using VLAN ID as 4th hextet
PREFIX_64="${PREFIX_48}:${VLAN_HEX}"

# Full IPv6 address to assign (always ::1)
IPV6_ADDR="${PREFIX_64}::1/64"

if [ "$SHOW_ONLY" -eq 1 ]; then
  echo "$IPV6_ADDR"
  exit 0
fi

# Perform the actual action
ip -6 addr add "${IPV6_ADDR}" dev "${IFACE}" 2>/dev/null

# Enable IPv6 forwarding
sysctl -w net.ipv6.conf.all.forwarding=1 > /dev/null

# Output result
echo "Assigned IPv6 address ${IPV6_ADDR} to interface ${IFACE} for VLAN ${VLAN_ID}"
logger -t $(basename $0) "Assigned IPv6 address ${IPV6_ADDR} to interface ${IFACE} for VLAN ${VLAN_ID}"
