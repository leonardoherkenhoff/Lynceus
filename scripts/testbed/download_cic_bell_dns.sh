#!/usr/bin/env bash
# ==============================================================================
# Lynceus Testbed - Download Script for BCCC-CIC-Bell-DNS-2024
# ------------------------------------------------------------------------------
# Scientific Milestone: v2.0 (High-Performance I/O)
#
# Research Objective:
#     Automates the authenticated ingestion of the CIC-Bell-DNS-2021 and 
#     CIC-Bell-DNS-EXF-2021 datasets, organizing them hierarchically.
# ==============================================================================

set -e

DEST_DIR="/root/CIC-Bell-DNS-2024"
COOKIE_FILE="$DEST_DIR/cookies.txt"

BASE_URL_2021="https://cicresearch.ca/CICDataset/CICBellDNS2021/download.php?file="
BASE_URL_EXF="https://cicresearch.ca/CICDataset/CICBellEXFDNS2021/download.php?file=PCAP"

# Estrutura: [Pasta_Destino]|[URL_Completa]
DOWNLOADS=(
    # CIC-Bell-DNS-2021
    "2021/FirstDayBenign|${BASE_URL_2021}FirstDayBenign.zip"
    "2021/SecondDay|${BASE_URL_2021}SecondDay.zip"
    "2021/ThirdDay|${BASE_URL_2021}ThirdDay.zip"
    
    # CIC-Bell-EXF-2021
    "EXF/Benign|${BASE_URL_EXF}%2FBenign.zip"
    "EXF/Attack_Light/Attacks|${BASE_URL_EXF}%2FAttack_Light_Benign%2FAttacks.zip"
    "EXF/Attack_Light/Benign|${BASE_URL_EXF}%2FAttack_Light_Benign%2FBenign.zip"
    "EXF/Attack_Heavy/Attacks|${BASE_URL_EXF}%2FAttack_heavy_Benign%2FAttacks.zip"
    "EXF/Attack_Heavy/Benign|${BASE_URL_EXF}%2FAttack_heavy_Benign%2FBenign.zip"
)

echo "=== CIC-Bell-DNS-2024 Downloader ==="
echo "[*] Alvo: $DEST_DIR"

if [ ! -f "$COOKIE_FILE" ]; then
    echo "[ERRO] Arquivo de cookies nao encontrado em $COOKIE_FILE"
    mkdir -p "$DEST_DIR"
    echo "Por favor, crie o arquivo com o conteudo netscape cookie fornecido pelo portal."
    exit 1
fi

for entry in "${DOWNLOADS[@]}"; do
    folder="${entry%%|*}"
    url="${entry##*|}"
    
    target_dir="$DEST_DIR/$folder"
    mkdir -p "$target_dir"
    cd "$target_dir"
    
    # O nome do arquivo zip no disco local:
    zip_name=$(basename "${url}" | sed 's/%2F/\//g' | awk -F/ '{print $NF}')
    
    # Se a pasta ja tiver arquivos pcap, ignora o download
    if ls *.pcap >/dev/null 2>&1 || ls *.pcapng >/dev/null 2>&1; then
        echo " -> [SKIP] PCAPs ja extraídos em $target_dir"
        continue
    fi
    
    if [ ! -f "$zip_name" ]; then
        echo " -> Baixando $zip_name para $folder..."
        curl -b "$COOKIE_FILE" -L -o "$zip_name" "$url"
    fi
    
    echo "    Extraindo $zip_name..."
    unzip -n "$zip_name" > /dev/null
    
    # Limpeza de disco rigorosa!
    echo "    Removendo arquivo compactado para poupar disco..."
    rm -f "$zip_name"
done

echo "✅ Dataset extraído e organizado com sucesso em $DEST_DIR"
