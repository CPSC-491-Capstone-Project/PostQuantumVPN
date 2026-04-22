#!/bin/bash
# vpn-up.sh — Client VPN routing setup
#
# Captures all IPv4 traffic through tun0 except the VPN process's own UDP
# socket, which uses SO_MARK=51820 and is explicitly routed via the main table.
# IPv6 is blocked entirely to prevent leaks (this VPN tunnels IPv4 only).
#
# Run as root BEFORE starting bin/PQ_VPN_Client.

set -euo pipefail

TUN_DEV="tun0"
TUN_CIDR="10.8.0.2/24"
VPN_TABLE=100
VPN_TABLE_NAME="vpn"
FWMARK=51820

if [[ $EUID -ne 0 ]]; then
    echo "Error: must run as root" >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# TUN device
# ---------------------------------------------------------------------------

if ! ip link show "$TUN_DEV" &>/dev/null; then
    ip tuntap add dev "$TUN_DEV" mode tun
    echo "[+] Created: $TUN_DEV"
fi

if ! ip addr show dev "$TUN_DEV" | grep -qw "${TUN_CIDR%%/*}"; then
    ip addr add "$TUN_CIDR" dev "$TUN_DEV"
    echo "[+] Assigned: $TUN_CIDR to $TUN_DEV"
fi

ip link set "$TUN_DEV" up
echo "[+] Interface up: $TUN_DEV"

# ---------------------------------------------------------------------------
# Routing table
# ---------------------------------------------------------------------------

if ! grep -qw "$VPN_TABLE_NAME" /etc/iproute2/rt_tables; then
    echo "$VPN_TABLE $VPN_TABLE_NAME" >> /etc/iproute2/rt_tables
    echo "[+] Registered routing table $VPN_TABLE ($VPN_TABLE_NAME)"
fi

if ! ip route show table "$VPN_TABLE" 2>/dev/null | grep -q "^default"; then
    ip route add default dev "$TUN_DEV" table "$VPN_TABLE"
    echo "[+] Default route in table $VPN_TABLE via $TUN_DEV"
fi

# ---------------------------------------------------------------------------
# Policy rules (clean slate, then re-add)
#
# Rule A (priority 50):  fwmark 51820 → main table
#   The VPN process marks its UDP socket with SO_MARK=51820, so its packets
#   skip the VPN table and reach the server via the normal routing table.
#
# Rule B (priority 100): everything else → VPN table → default via tun0
#   All other outbound traffic is captured by tun0 and forwarded by the
#   VPN client.
# ---------------------------------------------------------------------------

# Rule A — VPN socket bypass
ip rule del fwmark "$FWMARK" table main 2>/dev/null || true
ip rule add priority 50 fwmark "$FWMARK" table main
echo "[+] Rule A (priority  50): fwmark $FWMARK → main table (VPN bypass)"

# Rule B — catch-all into VPN table
ip rule del table "$VPN_TABLE" 2>/dev/null || true
ip rule add priority 100 table "$VPN_TABLE"
echo "[+] Rule B (priority 100): all other traffic → table $VPN_TABLE (tun0)"

# ---------------------------------------------------------------------------
# Block IPv6 — prevent leaks (VPN tunnels IPv4 only)
# ---------------------------------------------------------------------------

ip6tables -C OUTPUT -j DROP 2>/dev/null || ip6tables -A OUTPUT -j DROP
ip6tables -C FORWARD -j DROP 2>/dev/null || ip6tables -A FORWARD -j DROP
echo "[+] IPv6 OUTPUT and FORWARD blocked"

# ---------------------------------------------------------------------------

echo ""
echo "VPN client routing is UP."
echo "  TUN addr : $TUN_CIDR on $TUN_DEV"
echo "  fwmark $FWMARK → main table  (VPN socket bypasses tunnel)"
echo "  everything else → $TUN_DEV"
echo "  IPv6 → blocked (no leaks)"
echo ""
echo "Start the client: sudo ./bin/PQ_VPN_Client"
