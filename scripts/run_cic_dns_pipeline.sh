#!/usr/bin/env bash
# ==============================================================================
# Lynceus Testbed - Modular Pipeline Executor for CIC-Bell-DNS-2024
# ------------------------------------------------------------------------------
# Scientific Milestone: v2.0 (High-Performance I/O)
#
# Research Objective:
#     Orchestrates the XDP packet injection, eBPF parsing, and ground-truth 
#     topological attribution for the CIC-Bell-DNS-2024 dataset using generic 
#     testbed modules.
# ==============================================================================

set -e

WORKSPACE="/opt/eBPFNetFlowLyzer"
PCAP_DIR="/root/CIC-Bell-DNS-2024"
RAW_OUT_DIR="$WORKSPACE/data/interim/EBPF_RAW_DNS"
LABELED_OUT_DIR="$WORKSPACE/data/processed/CIC_DNS_LABELED"
LOG_DIR="$WORKSPACE/logs_pipeline_dns"

mkdir -p "$LOG_DIR"
cd "$WORKSPACE"

echo "========================================================="
echo "=== ORQUESTRADOR MASTER: CIC-Bell-DNS-2024 ==="
echo "========================================================="
echo "[*] Todos os logs serao salvos em: $LOG_DIR"

# 1. Download (Verificacao)
echo ""
echo "[Fase 1/5] Ingestão de Datasets"
if [ ! -d "$PCAP_DIR" ] || [ -z "$(find $PCAP_DIR -type f \( -name '*.pcap' -o -name '*.pcapng' \) 2>/dev/null)" ]; then
    echo "    -> Iniciando download dos arquivos..."
    ./scripts/testbed/download_cic_bell_dns.sh | tee "$LOG_DIR/1_download.log"
    if [ ${PIPESTATUS[0]} -ne 0 ]; then echo "[X] Falha no Download"; exit 1; fi
else
    echo "    -> PCAPs detectados em $PCAP_DIR. Pulando download."
fi

# 2. Extração
echo ""
echo "[Fase 2/5] Extração de Features In-Kernel (eBPF)"
echo "    -> Extraindo pacotes para CSV em TOPSPEED (Modular)..."
./scripts/testbed/extract_all_pcaps.sh "$PCAP_DIR" "$RAW_OUT_DIR" | tee "$LOG_DIR/2_extraction.log"
if [ ${PIPESTATUS[0]} -ne 0 ]; then echo "[X] Falha na Extração"; exit 1; fi

# 3. Rotulagem
echo ""
echo "[Fase 3/5] Rotulagem Lógica (DNS Activity)"
echo "    -> Processando CSVs recém extraídos..."
python3 scripts/preprocessing/cic_dns_labeler.py "$RAW_OUT_DIR" "$LABELED_OUT_DIR" | tee "$LOG_DIR/3_labeling.log"
if [ ${PIPESTATUS[0]} -ne 0 ]; then echo "[X] Falha no Labeling"; exit 1; fi

# 4. Machine Learning
echo ""
echo "[Fase 4/5] Avaliação de Classificação L3/L4"
echo "    -> ML Benchmark (Random Forest, KNN, C4.5)..."
python3 scripts/analysis/run_dns_benchmark.py "$LABELED_OUT_DIR" | tee "$LOG_DIR/4_ml_benchmark.log"
if [ ${PIPESTATUS[0]} -ne 0 ]; then echo "[X] Falha no Treinamento ML"; exit 1; fi

# 5. Stress Test
echo ""
echo "[Fase 5/5] PPS Benchmark (Stress Test)"
echo "    -> Mesclando os PCAPs..."
MERGED_PCAP="$PCAP_DIR/DNS_Merged.pcap"
if [ ! -f "$MERGED_PCAP" ]; then
    ./scripts/testbed/merge_pcaps.sh "$PCAP_DIR" "$MERGED_PCAP" | tee "$LOG_DIR/5_merge.log"
fi

echo "    -> Executando stress test de alta vazão..."
./scripts/testbed/run_performance_test.sh "$MERGED_PCAP" | tee "$LOG_DIR/6_performance.log"

echo ""
echo "========================================================="
echo "=== PIPELINE CONCLUIDO COM SUCESSO ==="
echo "========================================================="
