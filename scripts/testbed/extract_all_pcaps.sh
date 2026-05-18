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
make clean > /dev/null 2>&1
make > /dev/null 2>&1

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
    
    # O motor Lynceus processa PCAPs localmente via SKB mode
    ./build/lynceus -i "$PCAP"
    
    if [ $? -ne 0 ]; then
        echo "[!] Aviso: Falha na extração de $PCAP. Verifique os logs."
    fi
    echo "[V] Extração concluida."
done

echo "========================================================="
echo "[*] Extração em Lote Finalizada."
