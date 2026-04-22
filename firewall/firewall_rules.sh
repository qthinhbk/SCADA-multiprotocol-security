#!/bin/bash
# Industrial Firewall Rules - SCADA Multi-Protocol Security
# Implements whitelist-based ACL for Modbus, IEC104, DNP3, OPC-UA

echo "=========================================="
echo "  Industrial Firewall - Starting Setup   "
echo "=========================================="

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

# Allow DNS
iptables -A INPUT -p udp --dport 53 -j ACCEPT
iptables -A INPUT -p tcp --dport 53 -j ACCEPT

# Allow InfluxDB from all (for metrics)
iptables -A INPUT -p tcp --dport 8086 -j ACCEPT

echo "[FIREWALL] Default policies set: DROP INPUT/FORWARD, ACCEPT OUTPUT"

# ============================================
# VLAN 10 - Modbus Rules (Port 502)
# ============================================
echo "[FIREWALL] Configuring VLAN 10 - Modbus rules..."

# Allow modbus-client -> modbus-server
iptables -A FORWARD -s 172.20.10.0/24 -d 172.20.10.0/24 -p tcp --dport 502 -j LOG --log-prefix "[FW-MODBUS-ALLOW] "
iptables -A FORWARD -s 172.20.10.0/24 -d 172.20.10.0/24 -p tcp --dport 502 -j ACCEPT

# ============================================
# VLAN 20 - DNP3 Rules (Port 20000)
# ============================================
echo "[FIREWALL] Configuring VLAN 20 - DNP3 rules..."

iptables -A FORWARD -s 172.20.20.0/24 -d 172.20.20.0/24 -p tcp --dport 20000 -j LOG --log-prefix "[FW-DNP3-ALLOW] "
iptables -A FORWARD -s 172.20.20.0/24 -d 172.20.20.0/24 -p tcp --dport 20000 -j ACCEPT

# ============================================
# VLAN 30 - IEC104 Rules (Port 2404)
# ============================================
echo "[FIREWALL] Configuring VLAN 30 - IEC104 rules..."

iptables -A FORWARD -s 172.20.30.0/24 -d 172.20.30.0/24 -p tcp --dport 2404 -j LOG --log-prefix "[FW-IEC104-ALLOW] "
iptables -A FORWARD -s 172.20.30.0/24 -d 172.20.30.0/24 -p tcp --dport 2404 -j ACCEPT

# ============================================
# VLAN 40 - OPC-UA Rules (Port 4840)
# ============================================
echo "[FIREWALL] Configuring VLAN 40 - OPC-UA rules..."

iptables -A FORWARD -s 172.20.40.0/24 -d 172.20.40.0/24 -p tcp --dport 4840 -j LOG --log-prefix "[FW-OPCUA-ALLOW] "
iptables -A FORWARD -s 172.20.40.0/24 -d 172.20.40.0/24 -p tcp --dport 4840 -j ACCEPT

# ============================================
# Log and drop all other traffic
# ============================================
iptables -A FORWARD -j LOG --log-prefix "[FW-BLOCKED] "
iptables -A FORWARD -j DROP

echo "[FIREWALL] Rules applied successfully!"
echo "=========================================="
iptables -L -v -n
echo "=========================================="
