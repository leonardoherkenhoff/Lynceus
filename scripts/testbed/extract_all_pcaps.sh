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
make clean
make

OUT_DIR="/opt/eBPFNetFlowLyzer/data/interim/EBPF_RAW"
mkdir -p "$OUT_DIR"

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
    
    # O motor eBPF anexa ao hook XDP da interface loopback (modo skb)
    ./build/loader skb lo > "$OUT_DIR/$CSV_NAME" 2>/dev/null &
    LOADER_PID=$!
    
    echo "    -> Aguardando estabilização dos mapas BPF..."
    sleep 2
    
    echo "    -> Disparando tcpreplay em topspeed..."
    tcpreplay -i lo --topspeed "$PCAP" > /dev/null 2>&1
    
    echo "    -> Finalizando coleta e gravando CSV..."
    kill -SIGINT $LOADER_PID
    wait $LOADER_PID 2>/dev/null
    echo "[V] Extração concluida."
done

echo "========================================================="
echo "[*] Extração em Lote Finalizada."
