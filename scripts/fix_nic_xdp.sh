#!/bin/bash
# scripts/fix_nic_xdp.sh
# Network interface configuration for XDP Native (DRV_MODE)

IFACE=$1
if [ -z "$IFACE" ]; then
    echo "Usage: sudo $0 <interface>"
    exit 1
fi

echo "[*] Configuring interface $IFACE for XDP..."

# 1. Disable offloads incompatible with XDP Native
ethtool -K "$IFACE" lro off gro off 2>/dev/null

# 2. Configure hardware channels
# Set channels to 37 (hardware maximum) to match logical core count
ethtool -L "$IFACE" combined 37 2>/dev/null

# 3. Set MTU
ip link set dev "$IFACE" mtu 1500 2>/dev/null

# 4. Disable Flow Control
ethtool -A "$IFACE" rx off tx off 2>/dev/null

echo "[+] Configuration complete."
