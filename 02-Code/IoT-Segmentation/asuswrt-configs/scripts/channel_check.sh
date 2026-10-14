#!/bin/sh


TARGET_IF=wl1
NVRAM_CHANSPEC_VAR=wl1_chanspec

CURRENT_CHANSPEC=$(wl -i "$TARGET_IF" chanspec | cut -d' ' -f1)
#CURRENT_CH=$(wl -i "$TARGET_IF" channel | grep current | cut -f2)
CURRENT_CH=$(echo "$CURRENT_CHANSPEC" | cut -d'/' -f1)
TARGET_CHANSPEC=$(nvram get "$NVRAM_CHANSPEC_VAR")
TARGET_CH=$(echo "$TARGET_CHANSPEC" | cut -d'/' -f1)
LOGGER_TAG=channel_check

logger -t "$LOGGER_TAG" -s "Current channel spec is $CURRENT_CHANSPEC, target channel spec is $TARGET_CHANSPEC" 2>&1
#echo "Current channel spec is $CURRENT_CHANSPEC, target channel spec is $TARGET_CHANSPEC"
if [ -z "$CURRENT_CH" ] || [ -z "$TARGET_CH" ]; then
    logger -t "$LOGGER_TAG" -s "Could not get one of current or target chanspec, or both"
    #echo "Could not get one of current or target channel spec, or both" >&2
    exit 2
fi
if [ "$CURRENT_CH" = "$TARGET_CH" ]; then
    logger -t "$LOGGER_TAG" -s "Radio is using the target channel, nothing to do" 2>&1
    #echo "Radio is using the target channel, nothing to do"
    exit 0
else
    logger -t "$LOGGER_TAG" -s "Radio is NOT using the target channel, adjusting..." 2>&1
    #echo "Radio is NOT using the target channel, adjusting..."
    wl -i "$TARGET_IF" clear_radar_status
    wl -i "$TARGET_IF" radar_sc_status clear
    wl -i "$TARGET_IF" radar_subband_status clear
    wl -i "$TARGET_IF" dfs_ap_move $TARGET_CHANSPEC
    #wl -i "$TARGET_IF" chanspec $TARGET_CHANSPEC
    #wl -i "$TARGET_IF" dfs_channel_forced $TARGET_CHANSPEC
    #wl -i "$TARGET_IF" down
    #wl -i "$TARGET_IF" up
    if [ $? != 0 ]; then
        logger -t "$LOGGER_TAG" -s "Failed to adjust channel"
        #echo "Failed to adjust channel" >&2
        exit 1
    else
        logger -t "$LOGGER_TAG" -s "Successfully adjusted channel" 2>&1
        #echo "Successfully adjusted channel"
        exit 0
    fi
fi
