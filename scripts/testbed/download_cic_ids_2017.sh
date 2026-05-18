#!/bin/bash

# Script de download automatizado para o CIC-IDS-2017
# Uso: Executar no servidor bare-metal.

mkdir -p /root/CIC-IDS-2017
cd /root/CIC-IDS-2017

echo "Preparando arquivo de cookies..."
cat << 'EOF' > cookies.txt
# Netscape HTTP Cookie File
# https://curl.haxx.se/rfc/cookie_spec.html
# This is a generated file! Do not edit.

.cicresearch.ca	TRUE	/	TRUE	1779148774	Token	27im4a2plps0bu41780ncoc1mq
EOF

URLS=(
"https://cicresearch.ca/CICDataset/CIC-IDS-2017/download.php?file=CIC-IDS-2017%2FPCAPs%2FFriday-WorkingHours.md5"
"https://cicresearch.ca/CICDataset/CIC-IDS-2017/download.php?file=CIC-IDS-2017%2FPCAPs%2FFriday-WorkingHours.pcap"
"https://cicresearch.ca/CICDataset/CIC-IDS-2017/download.php?file=CIC-IDS-2017%2FPCAPs%2FMonday-WorkingHours.md5"
"https://cicresearch.ca/CICDataset/CIC-IDS-2017/download.php?file=CIC-IDS-2017%2FPCAPs%2FMonday-WorkingHours.pcap"
"https://cicresearch.ca/CICDataset/CIC-IDS-2017/download.php?file=CIC-IDS-2017%2FPCAPs%2FThursday-WorkingHours.md5"
"https://cicresearch.ca/CICDataset/CIC-IDS-2017/download.php?file=CIC-IDS-2017%2FPCAPs%2FThursday-WorkingHours.pcap"
"https://cicresearch.ca/CICDataset/CIC-IDS-2017/download.php?file=CIC-IDS-2017%2FPCAPs%2FTuesday-WorkingHours.md5"
"https://cicresearch.ca/CICDataset/CIC-IDS-2017/download.php?file=CIC-IDS-2017%2FPCAPs%2FTuesday-WorkingHours.pcap"
"https://cicresearch.ca/CICDataset/CIC-IDS-2017/download.php?file=CIC-IDS-2017%2FPCAPs%2FWednesday-workingHours.md5"
"https://cicresearch.ca/CICDataset/CIC-IDS-2017/download.php?file=CIC-IDS-2017%2FPCAPs%2FWednesday-workingHours.pcap"
)

for URL in "${URLS[@]}"; do
    # Extrai o nome do arquivo limpo a partir do parametro da URL
    FILENAME=$(echo "$URL" | sed -n 's/.*%2F\([^%]*\)$/\1/p')
    echo "============================================================"
    echo "[*] Baixando: $FILENAME"
    echo "============================================================"
    
    # O parametro -c garante que continue de onde parou caso caia a conexao
    wget -c --load-cookies cookies.txt --user-agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36" --show-progress "$URL" -O "$FILENAME"
done

echo "============================================================"
echo "[*] Verificando integridade dos arquivos (MD5)..."
md5sum -c *.md5

echo "[*] Limpando credenciais temporarias..."
rm cookies.txt

echo "[*] Download do CIC-IDS-2017 concluido."
