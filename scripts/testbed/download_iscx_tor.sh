#!/usr/bin/env bash
# ==============================================================================
# Lynceus Testbed - Download Script for ISCX-Tor-NonTor-2017 Dataset
# ------------------------------------------------------------------------------
# Scientific Milestone: v2.0 (High-Performance I/O)
#
# Research Objective:
#     Automates the authenticated ingestion of the Tor and Non-Tor PCAP archives
#     from the UNB CIC Datasets portal.
# ==============================================================================

set -e

# Configurações
DEST_DIR="/root/ISCX-Tor-2016"
COOKIE_FILE="$DEST_DIR/cookies.txt"
BASE_URL="https://cicresearch.ca/CICDataset/ISCX-Tor-NonTor-2017/download.php?file=PCAPs"

# Links exatos mapeados
LINKS=(
    "$BASE_URL%2FNonTor.tar.xz"
    "$BASE_URL%2FTor.zip"
)

echo "=== ISCX-Tor-2016 Downloader ==="
echo "[*] Alvo: $DEST_DIR"

if [ ! -f "$COOKIE_FILE" ]; then
    echo "[ERRO] Arquivo de cookies nao encontrado em $COOKIE_FILE"
    echo "Por favor, crie o arquivo com o conteudo netscape cookie fornecido pelo portal."
    exit 1
fi

mkdir -p "$DEST_DIR"
cd "$DEST_DIR"

echo "[*] Iniciando download das partições PCAP..."

for link in "${LINKS[@]}"; do
    filename=$(echo "$link" | grep -o 'PCAPs%2F.*' | sed 's/PCAPs%2F//')
    if [ ! -f "$filename" ]; then
        echo " -> Baixando $filename..."
        curl -b "$COOKIE_FILE" -L -o "$filename" "$link"
    else
        echo " -> [SKIP] $filename já existe."
    fi
done

echo "[*] Downloads concluídos. Extraindo os arquivos..."

# Extração do NonTor.tar.xz
if [ -f "NonTor.tar.xz" ]; then
    echo " -> Descompactando NonTor.tar.xz..."
    tar -xf NonTor.tar.xz
    rm -f NonTor.tar.xz
fi

# Extração do Tor.zip
if [ -f "Tor.zip" ]; then
    echo " -> Descompactando Tor.zip..."
    unzip -n Tor.zip > /dev/null
    rm -f Tor.zip
fi

echo "✅ Dataset extraído com sucesso em $DEST_DIR"
