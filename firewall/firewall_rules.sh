#!/bin/bash
# Industrial Firewall Rules - SCADA Multi-Protocol Security
# Implements whitelist-based ACL for Modbus, IEC104, DNP3, OPC-UA

echo "=========================================="
echo "  Industrial Firewall - Starting Setup   "
echo "=========================================="

TOPOLOGY="${FIREWALL_TOPOLOGY:-flat}"
echo "[FIREWALL] Topology mode: ${TOPOLOGY}"

# Enable routing in inline mode
if [ "$TOPOLOGY" = "inline" ]; then
  if ! sysctl -w net.ipv4.ip_forward=1 >/dev/null; then
    echo "[FIREWALL] ERROR: failed to enable net.ipv4.ip_forward"
    exit 1
  fi

  if [ "$(cat /proc/sys/net/ipv4/ip_forward)" != "1" ]; then
    echo "[FIREWALL] ERROR: net.ipv4.ip_forward is not enabled"
    exit 1
  fi

  echo "[FIREWALL] IPv4 forwarding enabled"
fi

# Flush existing rules
iptables -F
iptables -X
iptables -t nat -F
iptables -t nat -X

# Default policy: DROP all
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

# Allow loopback
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

# Allow established connections
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT

# Allow ICMP (ping) for diagnostics
iptables -A INPUT -p icmp -j ACCEPT
iptables -A FORWARD -p icmp -j ACCEPT

# Allow DNS queries and replies for Docker embedded DNS.
iptables -A INPUT -p udp --dport 53 -j ACCEPT
iptables -A INPUT -p tcp --dport 53 -j ACCEPT
iptables -A INPUT -p udp --sport 53 -j ACCEPT
iptables -A INPUT -p tcp --sport 53 -j ACCEPT

# Allow InfluxDB from all (for metrics)
iptables -A INPUT -p tcp --dport 8086 -j ACCEPT

echo "[FIREWALL] Default policies set: DROP INPUT/FORWARD, ACCEPT OUTPUT"

if [ "$TOPOLOGY" = "inline" ]; then
  # ============================================
  # Inline routed mode: client-side subnet -> server-side subnet
  # ============================================
  echo "[FIREWALL] Configuring inline routed ACL rules..."

  # Modbus: 172.20.10.0/24 -> 172.20.110.0/24
  iptables -A FORWARD -s 172.20.10.0/24 -d 172.20.110.0/24 -p tcp --dport 502 -j LOG --log-prefix "[FW-MODBUS-ALLOW] "
  iptables -A FORWARD -s 172.20.10.0/24 -d 172.20.110.0/24 -p tcp --dport 502 -j ACCEPT

  # DNP3: 172.20.20.0/24 -> 172.20.120.0/24
  iptables -A FORWARD -s 172.20.20.0/24 -d 172.20.120.0/24 -p tcp --dport 20000 -j LOG --log-prefix "[FW-DNP3-ALLOW] "
  iptables -A FORWARD -s 172.20.20.0/24 -d 172.20.120.0/24 -p tcp --dport 20000 -j ACCEPT

  # IEC104: 172.20.30.0/24 -> 172.20.130.0/24
  iptables -A FORWARD -s 172.20.30.0/24 -d 172.20.130.0/24 -p tcp --dport 2404 -j LOG --log-prefix "[FW-IEC104-ALLOW] "
  iptables -A FORWARD -s 172.20.30.0/24 -d 172.20.130.0/24 -p tcp --dport 2404 -j ACCEPT

  # OPC-UA: 172.20.40.0/24 -> 172.20.140.0/24
  iptables -A FORWARD -s 172.20.40.0/24 -d 172.20.140.0/24 -p tcp --dport 4840 -j LOG --log-prefix "[FW-OPCUA-ALLOW] "
  iptables -A FORWARD -s 172.20.40.0/24 -d 172.20.140.0/24 -p tcp --dport 4840 -j ACCEPT
else
  # ============================================
  # Flat VLAN mode (legacy)
  # ============================================
  echo "[FIREWALL] Configuring flat VLAN ACL rules..."

  # VLAN 10 - Modbus Rules (Port 502)
  iptables -A FORWARD -s 172.20.10.0/24 -d 172.20.10.0/24 -p tcp --dport 502 -j LOG --log-prefix "[FW-MODBUS-ALLOW] "
  iptables -A FORWARD -s 172.20.10.0/24 -d 172.20.10.0/24 -p tcp --dport 502 -j ACCEPT

  # VLAN 20 - DNP3 Rules (Port 20000)
  iptables -A FORWARD -s 172.20.20.0/24 -d 172.20.20.0/24 -p tcp --dport 20000 -j LOG --log-prefix "[FW-DNP3-ALLOW] "
  iptables -A FORWARD -s 172.20.20.0/24 -d 172.20.20.0/24 -p tcp --dport 20000 -j ACCEPT

  # VLAN 30 - IEC104 Rules (Port 2404)
  iptables -A FORWARD -s 172.20.30.0/24 -d 172.20.30.0/24 -p tcp --dport 2404 -j LOG --log-prefix "[FW-IEC104-ALLOW] "
  iptables -A FORWARD -s 172.20.30.0/24 -d 172.20.30.0/24 -p tcp --dport 2404 -j ACCEPT

  # VLAN 40 - OPC-UA Rules (Port 4840)
  iptables -A FORWARD -s 172.20.40.0/24 -d 172.20.40.0/24 -p tcp --dport 4840 -j LOG --log-prefix "[FW-OPCUA-ALLOW] "
  iptables -A FORWARD -s 172.20.40.0/24 -d 172.20.40.0/24 -p tcp --dport 4840 -j ACCEPT
fi

# ============================================
# Log and drop all other traffic
# ============================================
iptables -A FORWARD -j LOG --log-prefix "[FW-BLOCKED] "
iptables -A FORWARD -j DROP

echo "[FIREWALL] Rules applied successfully!"
echo "=========================================="
iptables -L -v -n
echo "=========================================="
