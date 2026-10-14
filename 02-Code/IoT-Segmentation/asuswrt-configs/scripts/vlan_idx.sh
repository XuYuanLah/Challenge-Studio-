#!/bin/sh

# Check if VLAN ID (1st arg) is given
if [ "$#" -lt 1 ]; then
    echo "Usage: $0 <vlan_id> [br|sdn]" >&2
    exit 1
fi

VID="$1"

# Validate VLAN ID is numeric
case "$VID" in
    (*[!0-9]*|'')
        echo "Error: VLAN ID must be numeric" >&2
        exit 1
    ;;
esac

# Check for valid optional second arg
MODE=""
if [ "$#" -eq 2 ]; then
    case "$2" in
        br|sdn)
            MODE="$2"
            ;;
        *)
            echo "Error: Second argument must be 'br' or 'sdn'" >&2
            exit 1
            ;;
    esac
fi

# Call get_mtlan_by_vid and parse
get_mtlan_by_vid "$VID" | awk -v vid="$VID" -v mode="$MODE" '
{
    line = $0
    sub(/^[ \t\r\n]+/, "", line)
    sub(/[ \t\r\n]+$/, "", line)

    # Detect section
    if (index(line, "|-*") == 1) {
        section = line
        gsub(/\|\-\*/, "", section)
        gsub(/:.*/, "", section)
    }
    # Detect subsection
    else if (index(line, "|--") == 1) {
        subsection = line
        gsub(/\|\-\-/, "", subsection)
        gsub(/:.*/, "", subsection)
    }

    # br_ifname from Network/IPv4
    else if (index(line, "|-br_ifname:[") == 1 && section == "Network" && subsection == "IPv4") {
        match(line, /\[.*\]/)
        val = substr(line, RSTART+1, RLENGTH-2)
        if (mode == "br") {
            print val
            exit
        } else if (mode == "") {
            print "vlan" vid "_br_ifname=" val
        }
    }

    # sdn_idx from SDN Feature Index/Switch
    else if (index(line, "|-sdn_idx:[") == 1 && section == "SDN Feature Index/Switch") {
        match(line, /\[.*\]/)
        val = substr(line, RSTART+1, RLENGTH-2)
        if (mode == "sdn") {
            print val
            exit
        } else if (mode == "") {
            print "vlan" vid "_sdn_idx=" val
        }
    }
}
'
