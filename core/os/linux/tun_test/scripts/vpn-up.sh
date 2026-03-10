#!/bin/bash
# vpn-up.sh — Intercept inbound via NFQUEUE, outbound via tun0

TUN_OUT="tun0"
TABLE_OUT="vpn_out"
PRIORITY_OUT=100
NFQUEUE_NUM=0

# --- Create tun0 if it doesn't exist ---
if ! ip link show "$TUN_OUT" &>/dev/null; then
    ip tuntap add dev "$TUN_OUT" mode tun
    echo "Created device: $TUN_OUT"
fi

# --- Register vpn_out routing table if not already present ---
if ! grep -qw "$TABLE_OUT" /etc/iproute2/rt_tables; then
    echo "101 $TABLE_OUT" | tee -a /etc/iproute2/rt_tables
    echo "Registered routing table: $TABLE_OUT"
fi

# --- Bring up tun0 before adding routes ---
ip link set "$TUN_OUT" up && echo "Brought up: $TUN_OUT (outbound)"

# --- Add default route for vpn_out table if not already present ---
if ! ip route show table "$TABLE_OUT" 2>/dev/null | grep -q "^default"; then
    ip route add default dev "$TUN_OUT" table "$TABLE_OUT"
    echo "Added default route: $TABLE_OUT → $TUN_OUT"
fi

# --- Global rule for locally-generated (outbound) traffic → tun0 ---
ip   rule add priority "$PRIORITY_OUT" table "$TABLE_OUT"
ip -6 rule add priority "$PRIORITY_OUT" table "$TABLE_OUT"
echo "Outbound rule added: (local) → $TUN_OUT"

# --- Fwmark rule: processed packets bypass vpn_out and go via main table ---
ip   rule add fwmark 1 priority 50 table main
ip -6 rule add fwmark 1 priority 50 table main
echo "Fwmark bypass rule added (mark=1 → main table)"

# --- NFQUEUE rules to intercept inbound before local delivery ---
iptables  -I INPUT -j NFQUEUE --queue-num "$NFQUEUE_NUM"
ip6tables -I INPUT -j NFQUEUE --queue-num "$NFQUEUE_NUM"
echo "Inbound NFQUEUE rule added (queue $NFQUEUE_NUM)"

echo "VPN is UP. Outbound → $TUN_OUT | Inbound → NFQUEUE $NFQUEUE_NUM"
