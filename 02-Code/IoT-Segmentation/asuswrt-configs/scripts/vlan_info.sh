#!/bin/sh

VALID_VLAN_ID=1
usage() {
    echo "Usage: $0 <VLAN_ID>" 
    echo "VLAN_ID must be 0-4095, following 802.1Q specs"
    VALID_VLAN_ID=0
}

if [ "$1" = -h ] || [ "$1" = --help ] || [ -z "$1" ]; then
    usage
fi

if [ "$VALID_VLAN_ID" = 1 ]; then
    case "$1" in
        ''|*[!0-9]*)
            usage
            ;;
    esac
fi

if [ "$VALID_VLAN_ID" = 1 ] && [ "$1" -gt 4095 ]; then
    usage
fi

if [ "$VALID_VLAN_ID" = 1 ]; then
    #case ${0##*/} in sh|-sh|dash|-dash|bash|-bash) SOURCED=1;; esac
    case ${0##*/} in vlan_info.sh) true;; *) SOURCED=1;; esac
    VLAN_ID=$1
    VLAN_HEX=$(printf "%x" "$1")
    VLAN_ULA_PREFIX=fd00:d:e:$VLAN_HEX::
    VLAN_ULA_PREFIX_CIDR="$VLAN_ULA_PREFIX"/64
    VLAN_ULA_ADDR="$VLAN_ULA_PREFIX"1
    VLAN_ULA_ADDR_CIDR="$VLAN_ULA_ADDR"/64
    VLAN_BR=$(/jffs/scripts/vlan_idx.sh "$1" br)
    VLAN_SDN=$(/jffs/scripts/vlan_idx.sh "$1" sdn)
    if [ -z $VLAN_BR ]; then
        echo "Warning: VLAN $1 does not have a bridge device"
    fi
    if [ -z $VLAN_SDN ]; then
        echo "Warning: VLAN $1 does not have an SDN index"
    fi
    [ -z $SOURCED ] && echo "VLAN_ID=$VLAN_ID"
    [ -z $SOURCED ] && echo "VLAN_HEX=$VLAN_HEX"
    [ -z $SOURCED ] && echo "VLAN_ULA_PREFIX=$VLAN_ULA_PREFIX"
    [ -z $SOURCED ] && echo "VLAN_ULA_PREFIX_CIDR=$VLAN_ULA_PREFIX_CIDR"
    [ -z $SOURCED ] && echo "VLAN_ULA_ADDR=$VLAN_ULA_ADDR"
    [ -z $SOURCED ] && echo "VLAN_ULA_ADDR_CIDR=$VLAN_ULA_ADDR_CIDR"
    [ -z $SOURCED ] && echo "VLAN_BR=$VLAN_BR"
    [ -z $SOURCED ] && echo "VLAN_SDN=$VLAN_SDN"
fi
