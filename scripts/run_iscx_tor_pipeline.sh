#!/usr/bin/env bash
# ==============================================================================
# Lynceus Testbed - Pipeline Executor for ISCX-Tor-2016
# ------------------------------------------------------------------------------
# Scientific Milestone: v2.0 (High-Performance I/O)
#
# Research Objective:
#     Orchestrates the XDP packet injection, eBPF parsing, and ground-truth 
#     topological attribution for the ISCX-Tor-2016 dataset.
# ==============================================================================

set -e

BASE_DIR="/opt/eBPFNetFlowLyzer"
PCAP_DIR="/root/ISCX-Tor-2016"
OUTPUT_DIR="$BASE_DIR/data/processed/ISCX_TOR_LABELED"

mkdir -p "$OUTPUT_DIR"
rm -f "$OUTPUT_DIR"/*.csv

echo "=== ISCX-Tor-2016 Testbed Pipeline ==="
echo "[*] Limpando CSVs de execuções anteriores..."
rm -f "$BASE_DIR/data/interim/EBPF_RAW"/*.csv

echo "[*] Iniciando o daemon Lynceus em background..."
# O daemon original deve estar compilado em /opt/eBPFNetFlowLyzer/src/daemon/lynceus_daemon
if [ ! -f "$BASE_DIR/src/daemon/lynceus_daemon" ]; then
    echo "[ERRO] Daemon nao encontrado. Compile com 'make' primeiro."
    exit 1
fi

$BASE_DIR/src/daemon/lynceus_daemon veth1 &
DAEMON_PID=$!
sleep 2 # Tempo para carregar o eBPF program

echo "[*] Injetando PCAPs via tcpreplay..."
# Encontra todos os arquivos .pcap dentro da arvore descompactada
find "$PCAP_DIR" -type f -name "*.pcap*" | while read -r pcap_file; do
    echo "--------------------------------------------------------"
    echo " -> Processando: $pcap_file"
    
    # Injeta a maxima velocidade na interface dummy/veth pareada com veth1
    # Assumimos que veth0 está conectada a veth1.
    tcpreplay-edit -i veth0 --topspeed --mtu-trunc "$pcap_file"
    
    # Aguarda o flush (timeout padrão do código intocado = 5.0s, então esperamos 6s para garantir)
    echo "    Aguardando flush do Lynceus (6s)..."
    sleep 6
    
    # Movimenta e rotula o(s) CSV(s) que surgiram no interim folder
    for csv_file in "$BASE_DIR/data/interim/EBPF_RAW"/*.csv; do
        if [ -f "$csv_file" ]; then
            # Pega apenas o timestamp ou nome aleatorio gerado
            base_csv=$(basename "$csv_file")
            
            # Gera um nome combinando o labeler e pcap
            safe_pcap_name=$(basename "$pcap_file" | sed 's/[^a-zA-Z0-9]/_/g')
            target_csv="$OUTPUT_DIR/${safe_pcap_name}_${base_csv}"
            
            mv "$csv_file" "$target_csv"
            
            # Executa o labeler passando o caminho original do PCAP
            python3 "$BASE_DIR/scripts/preprocessing/iscx_tor_labeler.py" "$target_csv" "$pcap_file"
        fi
    done
done

echo "--------------------------------------------------------"
echo "[*] Finalizando o daemon..."
kill -SIGINT $DAEMON_PID
wait $DAEMON_PID 2>/dev/null || true

echo "✅ Pipeline Tor completo! Arquivos rotulados disponiveis em: $OUTPUT_DIR"
