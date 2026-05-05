#!/bin/bash
# scripts/fix_nic_xdp.sh
# Hardening da NIC Broadcom para XDP Native (DRV_MODE) - Versão Conservadora

IFACE=$1
if [ -z "$IFACE" ]; then
    echo "Uso: sudo $0 <interface>"
    exit 1
fi

echo "[*] Restaurando configuração conservadora para $IFACE..."

# Revertendo alterações agressivas para diagnosticar regressão de PPS
# 1. Desabilitar LRO e GRO (Incompatíveis com XDP Native)
# ethtool -K "$IFACE" lro off gro off 2>/dev/null

# 2. Configurar Canais Combinados
# MAX_COMBINED=$(ethtool -l "$IFACE" | grep -i "combined" | head -1 | awk '{print $2}')
# ethtool -L "$IFACE" combined "$MAX_COMBINED" 2>/dev/null

# 3. Ajustar MTU
# ip link set dev "$IFACE" mtu 1500 2>/dev/null

echo "[+] Configuração mínima aplicada."
