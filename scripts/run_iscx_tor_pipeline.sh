#!/usr/bin/env bash
# ==============================================================================
# Lynceus Testbed - Modular Pipeline Executor for ISCX-Tor-2016
# ------------------------------------------------------------------------------
# Scientific Milestone: v2.0 (High-Performance I/O)
#
# Research Objective:
#     Orchestrates the XDP packet injection, eBPF parsing, and ground-truth 
#     topological attribution for the ISCX-Tor-2016 dataset using generic 
#     testbed modules.
# ==============================================================================

set -e

WORKSPACE="/opt/lynceus"
PCAP_DIR="/root/ISCX-Tor-2016"
RAW_OUT_DIR="$WORKSPACE/data/interim/EBPF_RAW_TOR"
LABELED_OUT_DIR="$WORKSPACE/data/processed/ISCX_TOR_LABELED"
LOG_DIR="$WORKSPACE/logs_pipeline_tor"

mkdir -p "$LOG_DIR"
cd "$WORKSPACE"

echo "========================================================="
echo "=== ORQUESTRADOR MASTER: Tor vs Non-Tor (ISCX-2016) ==="
echo "========================================================="
echo "[*] Todos os logs serao salvos em: $LOG_DIR"

# 1. Download (Verificacao)
echo ""
echo "[Fase 1/5] Ingestão de Datasets"
if [ ! -d "$PCAP_DIR" ] || [ -z "$(find $PCAP_DIR -type f -name '*.pcap' 2>/dev/null)" ]; then
    echo "    -> Iniciando download dos arquivos..."
    ./scripts/testbed/download_iscx_tor.sh | tee "$LOG_DIR/1_download.log"
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

# 2.5. Correção de Dependências Python (NumPy 2.x Breakage / PEP 668)
echo ""
echo "[Fase 2.5/5] Ajustando ambiente Python (Downgrade NumPy < 2)"
echo "    -> Prevenindo crash de compatibilidade no imbalanced-learn..."
pip install --break-system-packages "numpy<2.0.0" scikit-learn imbalanced-learn pandas polars --upgrade | tee "$LOG_DIR/2.5_pip.log"
if [ ${PIPESTATUS[0]} -ne 0 ]; then echo "[!] Aviso: pip install encontrou erros. Continuando mesmo assim..."; fi

# 3. Rotulagem
echo ""
echo "[Fase 3/5] Rotulagem Lógica (Tor vs Non-Tor / Application)"
echo "    -> Processando CSVs recém extraídos..."
python3 scripts/preprocessing/iscx_tor_labeler.py "$RAW_OUT_DIR" "$LABELED_OUT_DIR" | tee "$LOG_DIR/3_labeling.log"
if [ ${PIPESTATUS[0]} -ne 0 ]; then echo "[X] Falha no Labeling"; exit 1; fi

# 4. Machine Learning
echo ""
echo "[Fase 4/5] Avaliação de Classificação L3/L4"
echo "    -> ML Benchmark (Random Forest, KNN, C4.5)..."
python3 scripts/analysis/run_tor_benchmark.py "$LABELED_OUT_DIR" | tee "$LOG_DIR/4_ml_benchmark.log"
if [ ${PIPESTATUS[0]} -ne 0 ]; then echo "[X] Falha no Treinamento ML"; exit 1; fi

# 5. Stress Test
echo ""
echo "[Fase 5/5] PPS Benchmark (Stress Test)"
echo "    -> Mesclando os PCAPs..."
MERGED_PCAP="$PCAP_DIR/Tor_Merged.pcap"
if [ ! -f "$MERGED_PCAP" ]; then
    ./scripts/testbed/merge_pcaps.sh "$PCAP_DIR" "$MERGED_PCAP" | tee "$LOG_DIR/5_merge.log"
fi

echo "    -> Executando stress test de alta vazão..."
./scripts/testbed/run_performance_test.sh "$MERGED_PCAP" | tee "$LOG_DIR/6_performance.log"

echo ""
echo "========================================================="
echo "=== PIPELINE CONCLUIDO COM SUCESSO ==="
echo "========================================================="
