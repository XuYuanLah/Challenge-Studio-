#!/bin/sh
#
# https://www.dynu.com/en-US/DynamicDNS/IP-Update-Protocol

is_ipv4() {
    echo "$1" | grep -E '^[0-9]{1,3}(\.[0-9]{1,3}){3}$' >/dev/null || return 1

    # Split the IPv4 address into parts and check each number
    OLDIFS="$IFS"
    IFS=.
    set -- $1
    IFS="$OLDIFS"

    # Ensure each part is within the valid range 0-255
    [ "$1" -ge 0 ] 2>/dev/null && [ "$1" -le 255 ] 2>/dev/null || return 1
    [ "$2" -ge 0 ] 2>/dev/null && [ "$2" -le 255 ] 2>/dev/null || return 1
    [ "$3" -ge 0 ] 2>/dev/null && [ "$3" -le 255 ] 2>/dev/null || return 1
    [ "$4" -ge 0 ] 2>/dev/null && [ "$4" -le 255 ] 2>/dev/null || return 1
    return 0
}

is_ipv6() {
    echo "$1" | grep -E '^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$' >/dev/null && return 0
    return 1
}

HOSTNAME="$1"
PASSWORD="$2"
ADDR="$3"

if [ -z $1 ]; then
    echo "IP address required" >&2
    exit 1
fi

if is_ipv4 "$ADDR"; then
    VER=4
    IP_PARAM="myip=$ADDR&myipv6=no"
elif is_ipv6 "$ADDR"; then
    VER=6
    IP_PARAM="myip=no&myipv6=$ADDR"
else
    logger -t $(basename $0) "'$ADDR' is not a valid IP address"
    exit 1
fi

URL="https://api.dynu.com/nic/update?$IP_PARAM&hostname=$HOSTNAME&password=$PASSWORD"

echo -n "Updating IPv$VER for $HOSTNAME with addr '$ADDR': "
logger -t $(basename $0) "Updating IPv$VER for $HOSTNAME with addr '$ADDR':"
ANSWER=$(curl -$VER -s -w " %{http_code}\n" "$URL")
echo $ANSWER
logger -t $(basename $0) $ANSWER 

if [ "$ANSWER" == "good $ADDR 200" ] || [ "$ANSWER" == "nochg 200" ]; then
    exit 0
else
    exit 1
fi
