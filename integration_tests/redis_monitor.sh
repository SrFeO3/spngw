#!/bin/bash
# v0.1: Redis Session Monitor.
# Setup: apt install redis-tools jq
# Run:   ./redis_monitor.sh

INTERVAL=2

while true; do
    clear
    echo "=== Redis Session Monitor ($(date +'%H:%M:%S')) ==="
    echo "Interval: ${INTERVAL}s | Keys: $(redis-cli KEYS "*" | wc -l)"
    echo "----------------------------------------------------------------"

    # Iterate through keys using SCAN for safety
    keys=$(redis-cli --raw SCAN 0 | tail -n +2)
    if [ -z "$keys" ]; then
        echo "(No keys found)"
    else
        for k in $keys; do
            val=$(redis-cli GET "$k")
            # Summary via jq if available, otherwise raw
            echo -n "[$k] "
            echo "$val" | jq -c '{user: .user_id, auth: .is_authenticated, exp: .expires_at}' 2>/dev/null || echo "$val"
        done
    fi
    sleep $INTERVAL
done
