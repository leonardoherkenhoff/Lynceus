#!/usr/bin/env bash
# ==============================================================================
# Lynceus Testbed - Pipeline Executor for CIC-Bell-DNS-2024
# ------------------------------------------------------------------------------
# Scientific Milestone: v2.0 (High-Performance I/O)
#
# Research Objective:
#     Orchestrates the XDP packet injection, eBPF parsing, and ground-truth 
#     topological attribution for the CIC-Bell-DNS-2024 dataset.
# ==============================================================================

set -e

BASE_DIR="/opt/eBPFNetFlowLyzer"
PCAP_DIR="/root/CIC-Bell-DNS-2024"
OUTPUT_DIR="$BASE_DIR/data/processed/CIC_DNS_LABELED"

mkdir -p "$OUTPUT_DIR"

echo "=== CIC-Bell-DNS-2024 Testbed Pipeline ==="
echo "[*] Limpando CSVs de execuções anteriores no dir intermediário..."
rm -f "$BASE_DIR/data/interim/EBPF_RAW"/*.csv

echo "[*] Iniciando o daemon Lynceus em background..."
if [ ! -f "$BASE_DIR/src/daemon/lynceus_daemon" ]; then
    echo "[ERRO] Daemon nao encontrado. Compile com 'make' primeiro."
    exit 1
fi

$BASE_DIR/src/daemon/lynceus_daemon veth1 &
DAEMON_PID=$!
sleep 2

echo "[*] Injetando PCAPs via tcpreplay..."
find "$PCAP_DIR" -type f \( -name "*.pcap" -o -name "*.pcapng" \) | while read -r pcap_file; do
    echo "--------------------------------------------------------"
    echo " -> Processando: $pcap_file"
    
    safe_pcap_name=$(basename "$pcap_file" | sed 's/[^a-zA-Z0-9]/_/g')
    
    # Idempotência: pula se já existir o resultado final rotulado
    if ls "$OUTPUT_DIR/${safe_pcap_name}_"*.csv >/dev/null 2>&1; then
        echo "    [SKIP] CSV rotulado já detectado para este arquivo. Pulando injeção."
        continue
    fi
    
    tcpreplay-edit -i veth0 --topspeed --mtu-trunc "$pcap_file"
    
    # Aguarda o flush (timeout padrao = 5.0s)
    echo "    Aguardando flush do Lynceus (6s)..."
    sleep 6
    
    for csv_file in "$BASE_DIR/data/interim/EBPF_RAW"/*.csv; do
        if [ -f "$csv_file" ]; then
            base_csv=$(basename "$csv_file")
            target_csv="$OUTPUT_DIR/${safe_pcap_name}_${base_csv}"
            
            mv "$csv_file" "$target_csv"
            
            python3 "$BASE_DIR/scripts/preprocessing/cic_dns_labeler.py" "$target_csv" "$pcap_file"
        fi
    done
done

echo "--------------------------------------------------------"
echo "[*] Finalizando o daemon..."
kill -SIGINT $DAEMON_PID
wait $DAEMON_PID 2>/dev/null || true

echo "✅ Pipeline DNS completo! Arquivos rotulados disponiveis em: $OUTPUT_DIR"
