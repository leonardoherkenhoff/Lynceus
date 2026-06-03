#!/usr/bin/env bash
# ==============================================================================
# Lynceus Testbed - Download Script for ISCX-VPN-NonVPN-2016 Dataset
# ------------------------------------------------------------------------------
# Scientific Milestone: v2.0 (High-Performance I/O)
#
# Research Objective:
#     Automates the authenticated ingestion of the 5 raw PCAP archives 
#     from the UNB CIC Datasets portal.
# ==============================================================================

set -e

DEST_DIR="/root/ISCX-VPN-2016"
COOKIES_FILE="$DEST_DIR/cookies.txt"

echo "=========================================================="
echo " ISCX-VPN-2016 PCAP Downloader"
echo "=========================================================="

echo "[*] Creating destination directory $DEST_DIR..."
mkdir -p "$DEST_DIR"

if [ ! -f "$COOKIES_FILE" ]; then
    echo "[ERROR] Cookie file not found at $COOKIES_FILE."
    echo "Please create it using the format provided by the CIC portal."
    exit 1
fi

echo "[*] Beginning parallel/batch download of PCAP archives..."

cd "$DEST_DIR"

URLS=(
    "https://cicresearch.ca/CICDataset/ISCX-VPN-NonVPN-2016/download.php?file=PCAPs%2FNonVPN-PCAPs-01.zip"
    "https://cicresearch.ca/CICDataset/ISCX-VPN-NonVPN-2016/download.php?file=PCAPs%2FNonVPN-PCAPs-02.zip"
    "https://cicresearch.ca/CICDataset/ISCX-VPN-NonVPN-2016/download.php?file=PCAPs%2FNonVPN-PCAPs-03.zip"
    "https://cicresearch.ca/CICDataset/ISCX-VPN-NonVPN-2016/download.php?file=PCAPs%2FVPN-PCAPS-01.zip"
    "https://cicresearch.ca/CICDataset/ISCX-VPN-NonVPN-2016/download.php?file=PCAPs%2FVPN-PCAPS-02.zip"
)

for url in "${URLS[@]}"; do
    filename=$(echo "$url" | grep -o 'PCAPs%2F.*' | sed 's/PCAPs%2F//' | sed 's/%2F/\//g')
    if [ -z "$filename" ]; then
        filename="archive_$(date +%s).zip"
    fi
    echo " -> Baixando $filename..."
    # -C - resumes partial downloads; -L follows redirects
    curl -b "$COOKIES_FILE" -c "$COOKIES_FILE" -L -C - -O "$url"
done

echo "[*] Extracting ZIP archives..."
for z in *.zip; do
    if [ -f "$z" ]; then
        echo " -> Descompactando $z..."
        unzip -o -q "$z"
    fi
done

echo "=========================================================="
echo "[+] Download e descompactação concluídos em $DEST_DIR."
echo "=========================================================="
