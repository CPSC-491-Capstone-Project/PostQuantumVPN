#!/bin/bash
# vpn-down.sh — Tear down client VPN routing
#
# Removes the policy rules, flushes the VPN routing table,
# restores IPv6, and deletes the tun0 interface.
#
# Run as root AFTER stopping bin/PQ_VPN_Client.

TUN_DEV="tun0"
VPN_TABLE=100
VPN_TABLE_NAME="vpn"
FWMARK=51820

if [[ $EUID -ne 0 ]]; then
    echo "Error: must run as root" >&2
    exit 1
fi

# --- Remove policy rules ---------------------------------------------------

# Rule A — VPN socket bypass
ip rule del fwmark "$FWMARK" table main 2>/dev/null || true
echo "[+] Removed rule A: fwmark $FWMARK → main"

# Rule B — catch-all (loop in case of duplicates)
while ip rule del table "$VPN_TABLE" 2>/dev/null; do :; done
echo "[+] Removed rule B: all traffic → table $VPN_TABLE"

# --- Flush VPN routing table -----------------------------------------------
ip route flush table "$VPN_TABLE" 2>/dev/null || true
echo "[+] Flushed routing table $VPN_TABLE ($VPN_TABLE_NAME)"

# --- Restore IPv6 ----------------------------------------------------------
ip6tables -D OUTPUT  -j DROP 2>/dev/null || true
ip6tables -D FORWARD -j DROP 2>/dev/null || true
echo "[+] IPv6 OUTPUT and FORWARD restored"

# --- Bring down and delete TUN device --------------------------------------
ip link set "$TUN_DEV" down 2>/dev/null || true
if ip link show "$TUN_DEV" &>/dev/null; then
    ip tuntap del dev "$TUN_DEV" mode tun
    echo "[+] Deleted: $TUN_DEV"
fi

echo ""
echo "VPN client routing is DOWN. All traffic uses the main routing table."
