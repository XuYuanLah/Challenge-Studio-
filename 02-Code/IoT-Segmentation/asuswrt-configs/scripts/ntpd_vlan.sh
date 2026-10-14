#!/bin/sh

# Companion NTP servers for VLAN bridges.
# The firmware starts its ntpd as "ntp ... -l -I <lan_ifname>". BusyBox ntpd binds the server socket
# to that interface (SO_BINDTODEVICE), so NTP requests arriving on a VLAN bridge go unanswered,
# whichever router address they target. This runs one extra "ntp -n -l -I <bridge>" for every VLAN
# in vlan_config.env (vlan_ids.sh), i.e. every bridge except the main LAN.
# With no peers, BusyBox ntpd is a "stratum 1 server": it serves the system clock (disciplined by the
# main ntpd) and never sets it. Replies leave from the address the request was sent to.
#
# Lifecycle follows the main ntpd:
#   - runs only while "Enable local NTP server" is on (ntpd_enable=1), the main ntpd runs and the
#     clock has been set (ntp_ready=1), so an unsynced clock is never served; turning the server
#     off in the web UI stops these at the next check
#   - stop_ntpd ("killall ntp") stops these too: same binary, same process name
#   - "check" (cron every minute, service-event-end, wan-event, services-start) starts/stops to
#     match the main ntpd, and restarts an instance whose bridge was rebuilt (the bound ifindex changed)
#   - the firmware also restarts ntpd without any service event (refresh_ntpc() on WAN up), which
#     kills these; the cron job restarts them within a minute
#   - every run (re)adds that cron job if it's missing: cru entries live in tmpfs and one added
#     from services-start alone didn't survive boot, so any hook calling this script restores it
#
# Usage: ntpd_vlan.sh start|stop|restart|check

LOGGER_TAG=$(basename $0)
CRON_ID=ntpd_vlan
NTP_BIN=/usr/sbin/ntp
STATE_DIR=/var/run

# PID of the ntp process serving on interface $1
ntp_pid() {
    for p in $(pidof ntp); do
        case " $(tr '\0' ' ' < /proc/$p/cmdline 2>/dev/null)" in
            *" -I $1 "*) echo $p; return 0 ;;
        esac
    done
    return 1
}

ensure_cron() {
    cru l 2>/dev/null | grep -q "#$CRON_ID#\$" && return 0
    cru a $CRON_ID "* * * * * /jffs/scripts/ntpd_vlan.sh check"
    if cru l 2>/dev/null | grep -q "#$CRON_ID#\$"; then
        logger -t "$LOGGER_TAG" "cron job $CRON_ID added"
    else
        logger -t "$LOGGER_TAG" "failed to add cron job $CRON_ID"
    fi
}

# "Enable local NTP server" (web UI) is on, the firmware ntpd serves the main LAN, and the clock is set
main_running() {
    [ "$(nvram get ntpd_enable)" = 1 ] || return 1
    [ "$(nvram get ntp_ready)" = 1 ] || return 1
    ntp_pid "$LAN_IF" >/dev/null
}

start_one() {
    ntp_pid "$1" >/dev/null && return 0
    [ -e /sys/class/net/$1/ifindex ] || return 1
    $NTP_BIN -n -l -I "$1" </dev/null >/dev/null 2>&1 &
    cat /sys/class/net/$1/ifindex > $STATE_DIR/ntpd_vlan_$1.ifindex
    sleep 1
    if pid=$(ntp_pid "$1"); then
        logger -t "$LOGGER_TAG" "NTP server started on $1 (pid $pid)"
    else
        logger -t "$LOGGER_TAG" "NTP server on $1 failed to start"
        return 1
    fi
}

stop_one() {
    rm -f $STATE_DIR/ntpd_vlan_$1.ifindex
    pid=$(ntp_pid "$1") || return 0
    kill $pid
    # Wait for it to exit so a following start can bind again; SIGKILL after 5 s
    for i in 1 2 3 4 5; do kill -0 $pid 2>/dev/null || break; sleep 1; done
    kill -0 $pid 2>/dev/null && kill -9 $pid
    logger -t "$LOGGER_TAG" "NTP server on $1 stopped (pid $pid)"
}

case "$1" in
    start|stop|restart|check) ensure_cron ;;
esac

LAN_IF=$(nvram get lan_ifname)
for VID in $(/jffs/scripts/vlan_ids.sh); do
    . /jffs/scripts/vlan_info.sh $VID >/dev/null
    [ -n "$VLAN_BR" ] && [ "$VLAN_BR" != "$LAN_IF" ] || continue
    case "$1" in
        start)
            main_running && start_one $VLAN_BR
            ;;
        stop)
            stop_one $VLAN_BR
            ;;
        restart)
            stop_one $VLAN_BR
            main_running && start_one $VLAN_BR
            ;;
        check)
            if main_running; then
                if ntp_pid $VLAN_BR >/dev/null && \
                   [ "$(cat /sys/class/net/$VLAN_BR/ifindex 2>/dev/null)" != "$(cat $STATE_DIR/ntpd_vlan_$VLAN_BR.ifindex 2>/dev/null)" ]; then
                    logger -t "$LOGGER_TAG" "$VLAN_BR was rebuilt, restarting its NTP server"
                    stop_one $VLAN_BR
                fi
                start_one $VLAN_BR
            elif ntp_pid $VLAN_BR >/dev/null; then
                stop_one $VLAN_BR
            fi
            ;;
        *)
            echo "Usage: $0 start|stop|restart|check" >&2
            exit 1
            ;;
    esac
done
