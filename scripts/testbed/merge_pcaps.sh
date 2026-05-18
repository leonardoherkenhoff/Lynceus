#!/bin/bash
# Lynceus - Sprint 2 PCAP Merger
# Mescla todos os PCAPs diarios do CIC-IDS-2017 em um unico payload maciço 
# para o teste de stress (RustiFlow Benchmark).

PCAP_DIR="/root/CIC-IDS-2017"
OUTPUT_FILE="$PCAP_DIR/CIC-IDS-2017_Merged_50GB.pcap"

echo "========================================================="
echo "=== Lynceus PCAP Merger (CIC-IDS-2017) ==="
echo "========================================================="

# Verifica dependencias
if ! command -v mergecap &> /dev/null; then
    echo "[!] O mergecap não foi encontrado."
    echo "[*] Tentando instalar o wireshark-common automaticamente..."
    sudo apt-get update && sudo DEBIAN_FRONTEND=noninteractive apt-get install -y wireshark-common
    if [ $? -ne 0 ]; then
        echo "[X] Erro ao instalar wireshark-common. Instale manualmente: sudo apt-get install wireshark-common"
        exit 1
    fi
fi

echo "[*] Localizando PCAPs em $PCAP_DIR..."
# Pega apenas os pcaps baixados e garante a ordem alfabetica/cronologica simples
FILES=$(ls "$PCAP_DIR"/*.pcap 2>/dev/null | grep -v "Merged")

if [ -z "$FILES" ]; then
    echo "[X] Nenhum arquivo .pcap encontrado em $PCAP_DIR!"
    exit 1
fi

FILE_COUNT=$(echo "$FILES" | wc -l)
echo "[*] $FILE_COUNT arquivos PCAP encontrados para mesclagem:"
echo "$FILES"

echo "[*] Iniciando a mesclagem. Isso pode demorar e exigir bastante disco/IO..."
echo "[*] Arquivo de saida: $OUTPUT_FILE"

# Executa o mergecap
mergecap -w "$OUTPUT_FILE" $FILES

if [ $? -eq 0 ]; then
    echo "========================================================="
    echo "[V] Mesclagem concluida com sucesso!"
    ls -lh "$OUTPUT_FILE"
    echo "========================================================="
    echo "Proximo passo: ./scripts/testbed/run_performance_test.sh $OUTPUT_FILE"
else
    echo "[X] Erro durante a mesclagem dos arquivos."
    exit 1
fi
