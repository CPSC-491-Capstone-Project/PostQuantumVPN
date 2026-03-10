#!/bin/bash
# vpn-down.sh — Remove NFQUEUE inbound rules and tear down tun0

TUN_OUT="tun0"
TABLE_OUT="vpn_out"
NFQUEUE_NUM=0

# --- Remove NFQUEUE inbound rules ---
iptables  -D INPUT -j NFQUEUE --queue-num "$NFQUEUE_NUM" 2>/dev/null
ip6tables -D INPUT -j NFQUEUE --queue-num "$NFQUEUE_NUM" 2>/dev/null
echo "Removed NFQUEUE inbound rules"

# --- Remove all outbound routing rules ---
while ip   rule del table "$TABLE_OUT" 2>/dev/null; do :; done
while ip -6 rule del table "$TABLE_OUT" 2>/dev/null; do :; done
echo "Removed all rules for: $TABLE_OUT"

# --- Remove fwmark bypass rule ---
ip   rule del fwmark 1 priority 50 table main 2>/dev/null
ip -6 rule del fwmark 1 priority 50 table main 2>/dev/null
echo "Removed fwmark bypass rule"

# --- Bring down and delete tun0 ---
ip link set "$TUN_OUT" down 2>/dev/null
ip tuntap del dev "$TUN_OUT" mode tun && echo "Deleted: $TUN_OUT"

echo "VPN is DOWN. All interfaces routing normally."
