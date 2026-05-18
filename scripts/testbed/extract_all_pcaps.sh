#!/bin/bash
# Lynceus - Batch PCAP Extractor
# Extrai as features de rede de múltiplos PCAPs sequencialmente.

PCAP_DIR="/root/CIC-IDS-2017"

if [ ! -d "$PCAP_DIR" ]; then
    echo "[!] Diretório de origem não encontrado: $PCAP_DIR"
    exit 1
fi

echo "========================================================="
echo "=== Lynceus Batch Extractor (L3/L4/L7) ==="
echo "========================================================="

echo "[*] Compilando motor eBPF (Zero-Libc)..."
OUT_DIR="/opt/eBPFNetFlowLyzer/data/interim/EBPF_RAW"
mkdir -p "$OUT_DIR"

if ! command -v tcpreplay &> /dev/null; then
    echo "[!] tcpreplay não encontrado. Instalando..."
    apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y tcpreplay
fi

echo "[*] Configurando par veth (veth0 <-> veth1) para ingestão offline..."
ip link add veth0 type veth peer name veth1 2>/dev/null || true
ip link set veth0 up
ip link set veth1 up
ip link set dev veth0 mtu 65535
ip link set dev veth1 mtu 65535

FILES=$(ls "$PCAP_DIR"/*.pcap 2>/dev/null)

if [ -z "$FILES" ]; then
    echo "[X] Nenhum PCAP encontrado para extração."
    exit 1
fi

for PCAP in $FILES; do
    # Evita extrair o PCAP massivo do teste de performance neste estagio
    if [[ "$PCAP" == *"Merged"* ]]; then
        echo "[*] Ignorando arquivo massivo de benchmark de PPS: $PCAP"
        continue
    fi
    
    echo "---------------------------------------------------------"
    echo "[*] Injetando no XDP/eBPF: $(basename "$PCAP")"
    
    CSV_NAME=$(basename "$PCAP" .pcap).csv
    
    # O motor eBPF anexa ao hook XDP da interface receptora (veth1)
    ./build/loader skb veth1 > "$OUT_DIR/$CSV_NAME" 2>/dev/null &
    LOADER_PID=$!
    
    echo "    -> Aguardando estabilização dos mapas BPF..."
    sleep 2
    
    echo "    -> Disparando tcpreplay em topspeed via veth0..."
    tcpreplay -i veth0 --topspeed "$PCAP"
    
    echo "    -> Finalizando coleta e gravando CSV..."
    kill -SIGINT $LOADER_PID
    wait $LOADER_PID 2>/dev/null
    echo "[V] Extração concluida."
done

echo "[*] Destruindo par veth..."
ip link delete veth0 2>/dev/null || true

echo "========================================================="
echo "[*] Extração em Lote Finalizada."
