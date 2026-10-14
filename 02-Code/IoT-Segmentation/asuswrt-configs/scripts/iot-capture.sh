#!/bin/sh
# =============================================================================
# iot-capture.sh - timed packet capture for the IoT segment (Asuswrt-Merlin, HND)
#
# Captures each interface with its own tcpdump process (keeps the Ethernet/MAC
# headers; avoids the Linux "cooked" header that -i any produces), optionally
# rotates output files, and stops after a configurable duration. Broadcom flow
# cache (fc) and Runner offload are disabled for the capture window so offloaded
# flows stay visible, then re-enabled on exit, including on early stop.
#
# Usage:
#   iot-capture.sh [-b] [-d DURATION] [-r ROTATE] [-i "IF1 IF2"] [-o BASEDIR] [-f BPF] [-n]
#
#   -b           run in background: detach into a new session (setsid), no
#                controlling terminal, survives SSH logout. Replaces nohup.
#   -d DURATION  total capture time; accepts s/m/h/d suffix (default: 24h)
#                e.g. 90m, 6h, 2d, 3600 (bare number = seconds)
#   -r ROTATE    file rotation interval, same format (default: no rotation,
#                one file per interface for the whole run)
#   -i IFACES    space-separated interface list (default: "wl0.2 eth7")
#   -o BASEDIR   capture storage root (default: /tmp/mnt/opt/captures)
#   -f BPF       optional BPF filter applied to all interfaces
#   -n           do NOT toggle fc/runner offload (capture may miss offloaded flows)
#
# Start detached (survives SSH logout):
#   /jffs/scripts/iot-capture.sh -b -d 24h
#
# Stop early (offload is restored automatically):
#   kill "$(cat /tmp/mnt/opt/captures/current.pid)"
# =============================================================================

# Ignore SIGHUP explicitly. Some trimmed BusyBox shells reset the "ignored"
# disposition that nohup sets, so the hangup on SSH logout killed the script
# outright: no EXIT trap, stale PID file, offload left disabled. Background
# children (tcpdump, sleep) inherit the ignore.
trap '' HUP

DURATION="24h"
ROTATE=""                 # empty = no rotation
IFACES="wl0.2 eth7"
BASE="/tmp/mnt/opt/captures"
BPF=""
TOGGLE_OFFLOAD=1
BACKGROUND=0
MIN_FREE_MB=5120          # refuse to start with less than 5 GiB free
SNAPLEN=0                 # 0 = full packets (keeps TLS ClientHello / DNS intact)
BUFFER_KB=8192            # kernel capture buffer per process

# absolute path to this script, needed to re-launch it detached
case "$0" in
    /*) SELF="$0" ;;
    *)  SELF="$(pwd)/$0" ;;
esac

die() { echo "ERROR: $*" >&2; exit 1; }

# Portable PATH lookup: replaces `command -v` / `which`, which are not
# available in every BusyBox build. Prints the full path, returns 1 if not found.
# Resolving to an absolute path also avoids shell builtins that shadow
# binaries; e.g. `fc` is the history builtin in bash/ksh, not Broadcom's tool.
find_bin() {
    case "$1" in
        */*) [ -x "$1" ] && [ ! -d "$1" ] && { echo "$1"; return 0; }; return 1 ;;
    esac
    _ifs=$IFS; IFS=:
    for _d in $PATH; do
        [ -n "$_d" ] || _d=.
        if [ -x "$_d/$1" ] && [ ! -d "$_d/$1" ]; then
            IFS=$_ifs; echo "$_d/$1"; return 0
        fi
    done
    IFS=$_ifs
    return 1
}

TCPDUMP="${TCPDUMP:-$(find_bin tcpdump)}"

# Convert "90m" / "6h" / "2d" / "3600" / "45s" to seconds
to_seconds() {
    v="$1"
    case "$v" in
        *d) n="${v%d}"; mult=86400 ;;
        *h) n="${v%h}"; mult=3600  ;;
        *m) n="${v%m}"; mult=60    ;;
        *s) n="${v%s}"; mult=1     ;;
        *)  n="$v";     mult=1     ;;
    esac
    case "$n" in
        ''|*[!0-9]*) return 1 ;;
    esac
    echo $(( n * mult ))
}

usage() { sed -n '2,31p' "$SELF"; }

# ---- options -----------------------------------------------------------------
if [ "${IOTCAP_CHILD:-0}" = "1" ]; then
    # detached child: settings were validated by the parent and passed via env
    DURATION="$IOTCAP_DURATION"
    ROTATE="$IOTCAP_ROTATE"
    IFACES="$IOTCAP_IFACES"
    BASE="$IOTCAP_BASE"
    BPF="$IOTCAP_BPF"
    TOGGLE_OFFLOAD="$IOTCAP_TOGGLE_OFFLOAD"
    TCPDUMP="$IOTCAP_TCPDUMP"
else
    # Manual option parsing (no getopts: unavailable in some trimmed BusyBox shells).
    # Accepts both "-d 24h" and "-d24h"; "--" ends option parsing.
    need_arg() {
        case "$2" in
            ''|-*) die "option $1 requires an argument (see -h)" ;;
        esac
    }

    while [ $# -gt 0 ]; do
        opt="$1"
        case "$opt" in
            -d|-r|-i|-o|-f)
                need_arg "$opt" "$2"; val="$2"; shift 2 ;;
            -d?*|-r?*|-i?*|-o?*|-f?*)
                val="${opt#-?}"; opt="${opt%"$val"}"; shift ;;
            -n)     TOGGLE_OFFLOAD=0; shift; continue ;;
            -b)     BACKGROUND=1;     shift; continue ;;
            -h|--help) usage; exit 0 ;;
            --)     shift; break ;;
            -*)     echo "ERROR: unknown option: $opt" >&2; usage >&2; exit 2 ;;
            *)      echo "ERROR: unexpected argument: $opt" >&2; usage >&2; exit 2 ;;
        esac
        case "$opt" in
            -d) DURATION="$val" ;;
            -r) ROTATE="$val" ;;
            -i) IFACES="$val" ;;
            -o) BASE="$val" ;;
            -f) BPF="$val" ;;
        esac
    done
fi

DUR_S=$(to_seconds "$DURATION") || die "invalid duration: $DURATION"
[ "$DUR_S" -gt 0 ] || die "duration must be > 0"

ROT_S=""
if [ -n "$ROTATE" ]; then
    ROT_S=$(to_seconds "$ROTATE") || die "invalid rotation interval: $ROTATE"
    [ "$ROT_S" -gt 0 ] || die "rotation interval must be > 0"
    # a rotation interval >= the duration would only ever produce one file
    [ "$ROT_S" -ge "$DUR_S" ] && ROT_S=""
fi

# ---- pre-flight checks -------------------------------------------------------
[ -n "$TCPDUMP" ] && [ -x "$TCPDUMP" ] || die "tcpdump not found"
[ "$(nvram get ntp_ready 2>/dev/null)" = "1" ] || die "NTP not synced; timestamps would be unreliable"

for IF in $IFACES; do
    [ -e "/sys/class/net/$IF" ] || die "interface not found: $IF"
done

mkdir -p "$BASE" || die "cannot create $BASE"
FREE_MB=$(df -m "$BASE" | awk 'NR==2 {print $4}')
[ -n "$FREE_MB" ] && [ "$FREE_MB" -ge "$MIN_FREE_MB" ] \
    || die "insufficient free space on $BASE (${FREE_MB:-?} MiB < ${MIN_FREE_MB} MiB)"

PIDFILE="$BASE/current.pid"
OFFLOAD_MARK="$BASE/.offload-disabled"     # exists while fc/runner are turned off by us

if [ -f "$PIDFILE" ]; then
    OLDPID=$(cat "$PIDFILE")
    if kill -0 "$OLDPID" 2>/dev/null; then
        die "a capture is already running (PID $OLDPID)"
    fi
    # Only the detached child cleans up; the parent must not remove anything yet.
    if [ "$BACKGROUND" -ne 1 ]; then
        echo "WARNING: stale PID file (PID $OLDPID): previous run ended without cleanup" >&2
        rm -f "$PIDFILE"
    fi
fi

# ---- detach (-b) -------------------------------------------------------------
# Re-launch this script in a new session with no controlling terminal, so the
# SSH/pty hangup never reaches it. Settings are passed via the environment.
if [ "$BACKGROUND" -eq 1 ]; then
    IOTCAP_CHILD=1
    IOTCAP_DURATION="$DURATION"; IOTCAP_ROTATE="$ROTATE"; IOTCAP_IFACES="$IFACES"
    IOTCAP_BASE="$BASE"; IOTCAP_BPF="$BPF"; IOTCAP_TOGGLE_OFFLOAD="$TOGGLE_OFFLOAD"
    IOTCAP_TCPDUMP="$TCPDUMP"
    export IOTCAP_CHILD IOTCAP_DURATION IOTCAP_ROTATE IOTCAP_IFACES IOTCAP_BASE \
           IOTCAP_BPF IOTCAP_TOGGLE_OFFLOAD IOTCAP_TCPDUMP

    DAEMON_OUT="$BASE/daemon.out"            # stderr of the detached run (errors before run.log exists)
    if SETSID=$(find_bin setsid); then
        "$SETSID" /bin/sh "$SELF" </dev/null >>"$DAEMON_OUT" 2>&1 &
    else
        echo "WARNING: setsid not found; falling back to HUP-ignoring background job" >&2
        ( /bin/sh "$SELF" </dev/null >>"$DAEMON_OUT" 2>&1 & )
    fi

    # wait for the child to come up and report where it is writing
    i=0
    while [ $i -lt 10 ]; do
        sleep 1; i=$((i + 1))
        if [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
            NEWPID=$(cat "$PIDFILE")
            RUNDIR=$(ls -1d "$BASE"/2*/ 2>/dev/null | tail -n 1)
            echo "capture running in background: PID $NEWPID"
            echo "run dir: ${RUNDIR%/}"
            echo "stop:    kill $NEWPID"
            exit 0
        fi
    done
    echo "ERROR: background capture did not start; see $DAEMON_OUT" >&2
    tail -n 5 "$DAEMON_OUT" >&2 2>/dev/null
    exit 1
fi

# ---- run setup ---------------------------------------------------------------
RUN=$(date +%Y%m%d-%H%M%S)
OUT="$BASE/$RUN"
mkdir -p "$OUT" || die "cannot create $OUT"
LOG="$OUT/run.log"
echo $$ > "$PIDFILE"

# Write to the log file directly; only echo to stdout when attached to a
# terminal session (the detached child has no one to talk to).
log() {
    _msg="$(date '+%Y-%m-%d %H:%M:%S %z') $*"
    echo "$_msg" >>"$LOG"
    [ "${IOTCAP_CHILD:-0}" = "1" ] || echo "$_msg" 2>/dev/null
}

# ---- offload control ---------------------------------------------------------
FC_BIN=$(find_bin fc)         && HAVE_FC=1     || HAVE_FC=0
RUNNER_BIN=$(find_bin runner) && HAVE_RUNNER=1 || HAVE_RUNNER=0

offload_enable_cmds() {
    if [ "$HAVE_FC" -eq 1 ]; then
        "$FC_BIN" enable >>"$LOG" 2>&1 && log "flow cache re-enabled"
    fi
    if [ "$HAVE_RUNNER" -eq 1 ]; then
        "$RUNNER_BIN" enable >>"$LOG" 2>&1 && log "runner re-enabled"
    fi
    rm -f "$OFFLOAD_MARK"
}

offload_disable() {
    [ "$TOGGLE_OFFLOAD" -eq 1 ] || { log "offload toggle skipped (-n)"; return; }
    : > "$OFFLOAD_MARK"
    if [ "$HAVE_RUNNER" -eq 1 ]; then
        log "runner status (before): $("$RUNNER_BIN" status 2>&1 | tr '\n' ' ')"
        "$RUNNER_BIN" disable >>"$LOG" 2>&1 && log "runner disabled ($RUNNER_BIN)"
    fi
    if [ "$HAVE_FC" -eq 1 ]; then
        log "fc status (before): $("$FC_BIN" status 2>&1 | tr '\n' ' ')"
        "$FC_BIN" disable >>"$LOG" 2>&1 && "$FC_BIN" flush >>"$LOG" 2>&1 \
            && log "flow cache disabled + flushed ($FC_BIN)"
    fi
}

offload_restore() {
    [ "$TOGGLE_OFFLOAD" -eq 1 ] || return
    offload_enable_cmds
}

# A previous run that died uncleanly may have left offload disabled.
if [ -f "$OFFLOAD_MARK" ]; then
    log "previous run left offload disabled; restoring before starting"
    offload_enable_cmds
fi

# ---- cleanup (normal end, kill, or Ctrl-C) -----------------------------------
PIDS=""
SLEEP_PID=""
CLEANED=0

cleanup() {
    [ "$CLEANED" -eq 1 ] && return
    CLEANED=1
    [ -n "$SLEEP_PID" ] && kill "$SLEEP_PID" 2>/dev/null
    # SIGTERM, not SIGINT: background jobs of a non-interactive shell inherit SIGINT
    # as ignored. tcpdump handles TERM the same way: flush, print stats, exit.
    for p in $PIDS; do kill -TERM "$p" 2>/dev/null; done
    for p in $PIDS; do wait "$p" 2>/dev/null; done
    offload_restore
    log "capture stopped"
    for IF in $IFACES; do
        log "[$IF] $(grep -E 'packets (captured|received|dropped)' "$OUT/${IF}.log" 2>/dev/null | tr '\n' ' ')"
    done
    log "files: $(ls "$OUT"/*.pcap 2>/dev/null | wc -l) pcap(s), total $(du -sh "$OUT" | awk '{print $1}')"
    rm -f "$PIDFILE"
}

trap 'cleanup; exit 0' INT TERM
trap 'cleanup' EXIT

# ---- start -------------------------------------------------------------------
log "run id:     $RUN (PID $$, $([ "${IOTCAP_CHILD:-0}" = "1" ] && echo detached || echo foreground))"
log "duration:   $DURATION (${DUR_S}s)"
if [ -n "$ROT_S" ]; then
    log "rotation:   every ${ROT_S}s"
else
    log "rotation:   none (one file per interface)"
fi
log "interfaces: $IFACES"
log "filter:     ${BPF:-<none>}"
log "tcpdump:    $TCPDUMP ($("$TCPDUMP" --version 2>&1 | head -n 1))"
log "storage:    $OUT (${FREE_MB} MiB free at start)"

offload_disable

for IF in $IFACES; do
    if [ -n "$ROT_S" ]; then
        ROT_OPT="-G $ROT_S"
        OUTFILE="$OUT/${IF}_%Y%m%d-%H%M%S.pcap"   # strftime pattern, expanded by tcpdump -G
    else
        ROT_OPT=""
        OUTFILE="$OUT/${IF}_${RUN}.pcap"          # literal name; tcpdump ignores % without -G
    fi
    # shellcheck disable=SC2086
    "$TCPDUMP" -i "$IF" -n -s "$SNAPLEN" -U -B "$BUFFER_KB" \
               $ROT_OPT \
               -w "$OUTFILE" \
               $BPF \
               </dev/null >"$OUT/${IF}.log" 2>&1 &
    PIDS="$PIDS $!"
    log "[$IF] tcpdump started (PID $!)"
done

# sanity check: did every tcpdump survive startup?
sleep 2
for p in $PIDS; do
    kill -0 "$p" 2>/dev/null || { log "a tcpdump process exited early, see $OUT/*.log"; exit 1; }
done

END_TS=$(( $(date +%s) + DUR_S ))
log "capturing until $(date -d "@$END_TS" '+%Y-%m-%d %H:%M:%S' 2>/dev/null || echo "+${DUR_S}s")"

# interruptible wait: a backgrounded sleep lets the trap fire immediately on kill
sleep "$DUR_S" &
SLEEP_PID=$!
wait "$SLEEP_PID"
SLEEP_PID=""

log "duration reached"
exit 0
