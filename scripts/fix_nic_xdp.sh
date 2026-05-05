#!/bin/bash
# scripts/fix_nic_xdp.sh
# Hardening da NIC Broadcom para XDP Native (DRV_MODE)

IFACE=$1
if [ -z "$IFACE" ]; then
    echo "Uso: sudo $0 <interface>"
    exit 1
fi

echo "[*] Configurando $IFACE para XDP Native..."

# 1. Desabilitar LRO e GRO (Incompatíveis com XDP Native)
echo "[*] Desabilitando LRO/GRO..."
ethtool -K "$IFACE" lro off gro off 2>/dev/null || echo "[!] Falha ao desabilitar LRO/GRO (pode não ser suportado, continuando...)"

# 2. Configurar Canais Combinados (Requisito Broadcom bnxt_en)
echo "[*] Sincronizando canais RX/TX..."
MAX_COMBINED=$(ethtool -l "$IFACE" | grep -i "combined" | head -1 | awk '{print $2}')
if [ -n "$MAX_COMBINED" ] && [ "$MAX_COMBINED" -gt 0 ]; then
    ethtool -L "$IFACE" combined "$MAX_COMBINED" 2>/dev/null || echo "[!] Falha ao definir canais combinados."
fi

# 3. Ajustar MTU para o padrão XDP
echo "[*] Definindo MTU 1500..."
ip link set dev "$IFACE" mtu 1500 2>/dev/null

# 4. (Opcional) Aumentar Ring Buffers - Removido por precaução (regressão SKB)
# MAX_RX=$(ethtool -g "$IFACE" | grep -i "RX:" | head -1 | awk '{print $2}')
# MAX_TX=$(ethtool -g "$IFACE" | grep -i "TX:" | head -1 | awk '{print $2}')
# ethtool -G "$IFACE" rx "$MAX_RX" tx "$MAX_TX" 2>/dev/null

echo "[+] NIC $IFACE pronta para XDP Native."
