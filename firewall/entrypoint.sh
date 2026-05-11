#!/bin/bash
# Entrypoint: apply firewall rules, then run monitor + blocker with signal propagation

set -e

# Apply static firewall rules
bash /app/firewall_rules.sh

# Trap SIGTERM/SIGINT and forward to children
cleanup() {
    echo "[ENTRYPOINT] Shutting down gracefully..."
    kill -TERM "$MONITOR_PID" "$BLOCKER_PID" "$PCAP_PID" 2>/dev/null
    wait "$MONITOR_PID" "$BLOCKER_PID" "$PCAP_PID" 2>/dev/null
    exit 0
}
trap cleanup SIGTERM SIGINT

# Optional pcap capture for Zeek offline analysis. This avoids live-capture
# issues in Docker Desktop while keeping the firewall inline datapath intact.
if [ "${PACKET_CAPTURE_ENABLED:-false}" = "true" ]; then
    CAPTURE_INTERFACE="${CAPTURE_INTERFACE:-any}"
    PCAP_ROTATION_SECONDS="${PCAP_ROTATION_SECONDS:-15}"
    mkdir -p /pcap
    rm -f /pcap/*.pcap
    echo "[ENTRYPOINT] Starting tcpdump on ${CAPTURE_INTERFACE} -> /pcap (rotation: ${PCAP_ROTATION_SECONDS}s)"
    tcpdump -i "${CAPTURE_INTERFACE}" -s 0 -n -G "${PCAP_ROTATION_SECONDS}" -w "/pcap/scada-%Y%m%d%H%M%S.pcap" "tcp" &
    PCAP_PID=$!
else
    PCAP_PID=""
fi

# Start both daemons in background
python /app/active_blocker.py &
BLOCKER_PID=$!

python /app/firewall_monitor.py &
MONITOR_PID=$!

# Wait for any daemon to exit. If tcpdump dies, Zeek will stop receiving
# pcap batches, so treat that as a container failure too.
if [ -n "$PCAP_PID" ]; then
    wait -n "$MONITOR_PID" "$BLOCKER_PID" "$PCAP_PID"
else
    wait -n "$MONITOR_PID" "$BLOCKER_PID"
fi

# If one exits, kill the others
cleanup
