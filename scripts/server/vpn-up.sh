#!/bin/bash
# vpn-up.sh — Server VPN routing setup
#
# Enables IP forwarding and installs NAT masquerading so that client IP
# packets (source 10.0.0.0/24) are forwarded to the internet through the
# server's outbound interface.
#
# The TUN device (pqvpn0, 10.8.0.1/24) is created and configured by the
# server binary itself via TunDevice::Open() + BringUp(), so this script
# does NOT create it.
#
# Run as root BEFORE starting bin/PQ_VPN_Server.

set -euo pipefail

VPN_SUBNET="10.8.0.0/24"   # VPN subnet — server is .1, clients are .2+
TUN_DEV="pqvpn0"            # must match SetTunInterface() in server/main.cpp

if [[ $EUID -ne 0 ]]; then
    echo "Error: must run as root" >&2
    exit 1
fi

# --- Enable IPv4 forwarding ------------------------------------------------
sysctl -w net.ipv4.ip_forward=1 > /dev/null
echo "[+] IPv4 forwarding enabled"

# --- Detect outbound interface (interface used for default route) ----------
OUTBOUND=$(ip route get 8.8.8.8 2>/dev/null \
    | awk 'NR==1 { for (i=1; i<=NF; i++) if ($i == "dev") { print $(i+1); exit } }')
if [[ -z "$OUTBOUND" ]]; then
    echo "Error: could not detect outbound interface (is there a default route?)" >&2
    exit 1
fi
echo "[+] Outbound interface: $OUTBOUND"

# --- NAT masquerade: rewrite source IP for VPN traffic leaving server ------
iptables -t nat -A POSTROUTING -s "$VPN_SUBNET" -o "$OUTBOUND" -j MASQUERADE
echo "[+] NAT masquerade: $VPN_SUBNET → $OUTBOUND"

# --- Allow forwarding between TUN and outbound interface -------------------
iptables -A FORWARD -s "$VPN_SUBNET" -o "$OUTBOUND" -j ACCEPT
iptables -A FORWARD -d "$VPN_SUBNET" -i "$OUTBOUND" \
    -m state --state RELATED,ESTABLISHED -j ACCEPT
echo "[+] FORWARD rules added: $VPN_SUBNET ↔ $OUTBOUND"

echo ""
echo "VPN server routing is UP."
echo "  Client subnet  : $VPN_SUBNET"
echo "  Outbound iface : $OUTBOUND"
echo "  TUN device     : $TUN_DEV (created by server process on startup)"
echo ""
echo "Start the server: sudo ./bin/PQ_VPN_Server"
