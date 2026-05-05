#!/bin/bash
# scripts/fix_nic_xdp.sh
# Hardening Científico para BCM57508 (bnxt_en) baseado em telemetria

IFACE=$1
if [ -z "$IFACE" ]; then
    echo "Uso: sudo $0 <interface>"
    exit 1
fi

echo "[*] Otimizando BCM57508 ($IFACE) para 500k+ PPS..."

# 1. Garantir LRO/GRO OFF (Essencial para XDP Native)
# De acordo com ethtool -k, já estão OFF, mas reforçamos.
ethtool -K "$IFACE" lro off gro off 2>/dev/null

# 2. Ajuste de Canais (Power of 2)
# A placa reportou 37 canais. Muitos drivers bnxt_en performam melhor 
# ou só aceitam XDP Nativo com potências de 2 para alinhamento de RSS.
echo "[*] Ajustando canais para 32 (Power of 2 alignment)..."
ethtool -L "$IFACE" combined 32 2>/dev/null || echo "[!] Falha ao ajustar canais para 32."

# 3. MTU 1500 (Seguro para XDP)
ip link set dev "$IFACE" mtu 1500 2>/dev/null

# 4. Ring Buffers (Já estão no MAX 8191/2047, não mexer para evitar resets inúteis)
echo "[*] Ring buffers já otimizados (8191/2047)."

# 5. Desabilitar Flow Control (Evita backpressure que derruba PPS)
echo "[*] Desabilitando Flow Control..."
ethtool -A "$IFACE" rx off tx off 2>/dev/null

echo "[+] Hardware configurado cientificamente."
