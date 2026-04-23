#!/bin/bash
# vpn-down.sh — Tear down server VPN routing
#
# Removes the NAT masquerade and FORWARD rules added by vpn-up.sh.
# Also removes pqvpn0 if it persists after the server process exits
# (e.g. after a crash).
#
# Run as root AFTER stopping bin/PQ_VPN_Server.

VPN_SUBNET="10.8.0.0/24"
TUN_DEV="pqvpn0"

if [[ $EUID -ne 0 ]]; then
    echo "Error: must run as root" >&2
    exit 1
fi

# --- Detect outbound interface ---------------------------------------------
OUTBOUND=$(ip route get 8.8.8.8 2>/dev/null \
    | awk 'NR==1 { for (i=1; i<=NF; i++) if ($i == "dev") { print $(i+1); exit } }')

if [[ -n "$OUTBOUND" ]]; then
    # --- Remove NAT masquerade ---------------------------------------------
    iptables -t nat -D POSTROUTING -s "$VPN_SUBNET" -o "$OUTBOUND" \
        -j MASQUERADE 2>/dev/null || true
    echo "[+] Removed NAT masquerade: $VPN_SUBNET → $OUTBOUND"

    # --- Remove FORWARD rules ----------------------------------------------
    iptables -D FORWARD -s "$VPN_SUBNET" -o "$OUTBOUND" \
        -j ACCEPT 2>/dev/null || true
    iptables -D FORWARD -d "$VPN_SUBNET" -i "$OUTBOUND" \
        -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true
    echo "[+] Removed FORWARD rules: $VPN_SUBNET ↔ $OUTBOUND"
else
    echo "[!] Could not detect outbound interface — skipping iptables cleanup"
fi

# --- Remove TUN device if it still exists (e.g. after a crash) ------------
if ip link show "$TUN_DEV" &>/dev/null; then
    ip link set "$TUN_DEV" down 2>/dev/null || true
    ip tuntap del dev "$TUN_DEV" mode tun 2>/dev/null || true
    echo "[+] Deleted: $TUN_DEV"
fi

# --- Disable IPv4 forwarding -----------------------------------------------
sysctl -w net.ipv4.ip_forward=0 > /dev/null
echo "[+] IPv4 forwarding disabled"

echo ""
echo "VPN server routing is DOWN."
