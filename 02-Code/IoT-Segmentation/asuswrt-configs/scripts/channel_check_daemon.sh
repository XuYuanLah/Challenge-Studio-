#!/bin/sh

LOCKFILE="/tmp/$(basename "$0").lock"
LOGGER_TAG=channel_check_daemon

if [ -e "$LOCKFILE" ]; then
    PID=$(cat "$LOCKFILE")
    if kill -0 "$PID" 2>/dev/null; then
        logger -t "$LOGGER_TAG" -s "Another instance is already running (PID $PID). Exiting." 2>&1
        exit 1
    else
        logger -t "$LOGGER_TAG" -s "Stale lock file found. Removing it." 2>&1
        rm -f "$LOCKFILE"
    fi
fi

echo $$ > "$LOCKFILE"

clean_up() {
    rm -f "$LOCKFILE"
}
trap "clean_up && exit" 0 1 2 3 15 # 0=EXIT, 1=SIGHUP, 2=SIGINT, 3=SIGQUIT, 15=SIGTERM

while true; do
    /jffs/scripts/channel_check.sh
    sleep 60
done
