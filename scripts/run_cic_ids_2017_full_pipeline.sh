#!/bin/bash
# Lynceus - Orquestrador Master (CIC-IDS-2017)
# ---------------------------------------------------------------------------
# Automatiza o experimento inteiro de ponta a ponta sem intervencao manual.
# Fases: Download -> Extração -> Labeling -> ML -> Merge -> PPS Benchmark

PCAP_DIR="/root/CIC-IDS-2017"
LOG_DIR="./logs_pipeline"
mkdir -p "$LOG_DIR"

echo "========================================================="
echo "=== ORQUESTRADOR MASTER: LYNCEUS VS LEGADOS (CIC-IDS-2017) ==="
echo "========================================================="
echo "[*] Todos os logs serao salvos em: $LOG_DIR"

# 1. Download (Verificacao)
echo ""
echo "[Fase 1/6] Ingestão de Datasets"
if [ ! -d "$PCAP_DIR" ] || [ -z "$(ls -A $PCAP_DIR/*.pcap 2>/dev/null)" ]; then
    echo "    -> Iniciando download dos arquivos (50GB+)..."
    ./scripts/testbed/download_cic_ids_2017.sh | tee "$LOG_DIR/1_download.log"
    if [ ${PIPESTATUS[0]} -ne 0 ]; then echo "[X] Falha no Download"; exit 1; fi
else
    echo "    -> PCAPs detectados em $PCAP_DIR. Pulando download."
fi

# 1.5. Fatiamento Granular (Novo)
echo ""
echo "[Fase 1.5/6] Fatiamento Granular de Alta Precisão"
echo "    -> Isolando vetores de ataque para máxima fidelidade temporal..."
./scripts/testbed/slice_pcaps.sh | tee "$LOG_DIR/1.5_slicing.log"
if [ ${PIPESTATUS[0]} -ne 0 ]; then echo "[X] Falha no Fatiamento"; exit 1; fi

# 2. Extração
echo ""
echo "[Fase 2/6] Extração de Features In-Kernel (eBPF)"
echo "    -> Convertendo pacotes fatiados para CSV em TOPSPEED..."
./scripts/testbed/extract_all_pcaps.sh | tee "$LOG_DIR/2_extraction.log"
if [ ${PIPESTATUS[0]} -ne 0 ]; then echo "[X] Falha na Extração"; exit 1; fi

# 2.5. Correção de Dependências Python (NumPy 2.x Breakage)
echo ""
echo "[Fase 2.5/6] Ajustando ambiente Python (Downgrade NumPy < 2)"
echo "    -> Prevenindo crash de compatibilidade no imbalanced-learn..."
pip install --break-system-packages "numpy<2.0.0" scikit-learn imbalanced-learn pandas polars --upgrade | tee "$LOG_DIR/2.5_pip.log"
if [ ${PIPESTATUS[0]} -ne 0 ]; then echo "[!] Aviso: pip install encontrou erros. Continuando mesmo assim..."; fi

# 3. Rotulagem Topológica
echo ""
echo "[Fase 3/6] Rotulagem Topológica Livre de Leakage"
echo "    -> Injetando classes de ataque (BruteForce, DoS, Botnet, etc)..."
./scripts/preprocessing/cic_ids_2017_labeler.py --cleanup | tee "$LOG_DIR/3_labeling.log"
if [ ${PIPESTATUS[0]} -ne 0 ]; then echo "[X] Falha no Labeling"; exit 1; fi

# 4. Avaliação de Machine Learning
echo ""
echo "[Fase 4/6] Avaliação de Qualidade L3/L4 (Random Forest - Full Mode)"
echo "    -> Comparativo principal contra NTLFlowLyzer e CICFlowMeter..."
./scripts/analysis/run_ids2017_benchmark.py | tee "$LOG_DIR/4_ml_benchmark.log"
if [ ${PIPESTATUS[0]} -ne 0 ]; then echo "[X] Falha no Treinamento ML"; exit 1; fi

# 5. Preparação para Stress Test
echo ""
echo "[Fase 5/6] Preparação para Stress Test Massivo"
echo "    -> Mesclando os PCAPs para fluxo ininterrupto de 50GB..."
if [ ! -f "$PCAP_DIR/CIC-IDS-2017_Merged_50GB.pcap" ]; then
    ./scripts/testbed/merge_pcaps.sh | tee "$LOG_DIR/5_merge.log"
    if [ ${PIPESTATUS[0]} -ne 0 ]; then echo "[X] Falha no Merge"; exit 1; fi
else
    echo "    -> Arquivo mesclado já existe. Pulando."
fi

# 6. Stress Test
echo ""
echo "[Fase 6/6] O Duelo de PPS e Overhead (vs RustiFlow)"
echo "    -> Bombeando pacotes via tcpreplay em modo topspeed..."
./scripts/testbed/run_performance_test.sh "$PCAP_DIR/CIC-IDS-2017_Merged_50GB.pcap" | tee "$LOG_DIR/6_performance.log"
if [ ${PIPESTATUS[0]} -ne 0 ]; then echo "[X] Falha no Teste de Performance"; exit 1; fi

echo ""
echo "========================================================="
echo "=== PIPELINE CONCLUIDO COM SUCESSO ==="
echo "========================================================="
echo "[V] Os resultados completos de ML estão em: $LOG_DIR/4_ml_benchmark.log"
echo "[V] As estatisticas de PPS e Tempo estão em: $LOG_DIR/6_performance.log"
