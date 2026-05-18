#!/bin/bash
# Lynceus - Granular PCAP Slicer
# Fatiará os PCAPs em arquivos individuais de ataque de acordo com o cronograma oficial.
# Evita agrupar ataques do mesmo dia (como DoS), garantindo métricas de extração separadas.

SRC="/root/CIC-IDS-2017"
DST="/root/CIC-IDS-2017-sliced"

echo "========================================================="
echo "=== Lynceus Granular PCAP Slicer (Wireshark Engine) ==="
echo "========================================================="

if [ "$EUID" -ne 0 ]; then
  echo "[!] Erro: Este script precisa ser executado como root."
  exit 1
fi

if [ ! -d "$SRC" ]; then
    echo "[!] Diretório original não encontrado: $SRC"
    exit 1
fi

# Instalar utilitários se necessário
if ! command -v editcap &> /dev/null; then
    echo "[*] Instalando wireshark-common para manipulação binária ultra-rápida..."
    apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y wireshark-common
fi

mkdir -p "$DST"
rm -f "$DST"/*.pcap  # Limpar fatiamentos antigos

echo "[*] Iniciando fatiamento granular estrito..."

# 1. Monday (Benign)
if [ -f "$SRC/Monday-WorkingHours.pcap" ]; then
    echo "    -> Slicing Monday-Benign (09:00 - 10:00)..."
    editcap -A "2017-07-03 09:00:00" -B "2017-07-03 10:00:00" "$SRC/Monday-WorkingHours.pcap" "$DST/Monday-WorkingHours.pcap"
fi

# 2. Tuesday (FTP-Patator e SSH-Patator)
if [ -f "$SRC/Tuesday-WorkingHours.pcap" ]; then
    echo "    -> Slicing Tuesday-FTP-Patator (09:20 - 10:20)..."
    editcap -A "2017-07-04 09:20:00" -B "2017-07-04 10:20:00" "$SRC/Tuesday-WorkingHours.pcap" "$DST/Tuesday-FTP-Patator.pcap"
    echo "    -> Slicing Tuesday-SSH-Patator (14:00 - 15:00)..."
    editcap -A "2017-07-04 14:00:00" -B "2017-07-04 15:00:00" "$SRC/Tuesday-WorkingHours.pcap" "$DST/Tuesday-SSH-Patator.pcap"
fi

# 3. Wednesday (DoS / DDoS e Heartbleed)
if [ -f "$SRC/Wednesday-workingHours.pcap" ]; then
    echo "    -> Slicing Wednesday-DoS-slowloris (09:47 - 10:10)..."
    editcap -A "2017-07-05 09:47:00" -B "2017-07-05 10:10:00" "$SRC/Wednesday-workingHours.pcap" "$DST/Wednesday-DoS-slowloris.pcap"
    echo "    -> Slicing Wednesday-DoS-Slowhttptest (10:14 - 10:35)..."
    editcap -A "2017-07-05 10:14:00" -B "2017-07-05 10:35:00" "$SRC/Wednesday-workingHours.pcap" "$DST/Wednesday-DoS-Slowhttptest.pcap"
    echo "    -> Slicing Wednesday-DoS-Hulk (10:43 - 11:00)..."
    editcap -A "2017-07-05 10:43:00" -B "2017-07-05 11:00:00" "$SRC/Wednesday-workingHours.pcap" "$DST/Wednesday-DoS-Hulk.pcap"
    echo "    -> Slicing Wednesday-DoS-GoldenEye (11:10 - 11:23)..."
    editcap -A "2017-07-05 11:10:00" -B "2017-07-05 11:23:00" "$SRC/Wednesday-workingHours.pcap" "$DST/Wednesday-DoS-GoldenEye.pcap"
    echo "    -> Slicing Wednesday-Heartbleed (15:12 - 15:32)..."
    editcap -A "2017-07-05 15:12:00" -B "2017-07-05 15:32:00" "$SRC/Wednesday-workingHours.pcap" "$DST/Wednesday-Heartbleed.pcap"
fi

# 4. Thursday (Web Attacks e Infiltration)
if [ -f "$SRC/Thursday-WorkingHours.pcap" ]; then
    echo "    -> Slicing Thursday-Web-Attack-Brute-Force (09:20 - 10:00)..."
    editcap -A "2017-07-06 09:20:00" -B "2017-07-06 10:00:00" "$SRC/Thursday-WorkingHours.pcap" "$DST/Thursday-Web-Attack-Brute-Force.pcap"
    echo "    -> Slicing Thursday-Web-Attack-XSS (10:15 - 10:35)..."
    editcap -A "2017-07-06 10:15:00" -B "2017-07-06 10:35:00" "$SRC/Thursday-WorkingHours.pcap" "$DST/Thursday-Web-Attack-XSS.pcap"
    echo "    -> Slicing Thursday-Web-Attack-SQL-Injection (10:40 - 10:42)..."
    editcap -A "2017-07-06 10:40:00" -B "2017-07-06 10:42:00" "$SRC/Thursday-WorkingHours.pcap" "$DST/Thursday-Web-Attack-SQL-Injection.pcap"
    echo "    -> Slicing Thursday-Infiltration (14:19 - 15:45)..."
    editcap -A "2017-07-06 14:19:00" -B "2017-07-06 15:45:00" "$SRC/Thursday-WorkingHours.pcap" "$DST/Thursday-Infiltration.pcap"
fi

# 5. Friday (Botnet, PortScan e DDoS)
if [ -f "$SRC/Friday-WorkingHours.pcap" ]; then
    echo "    -> Slicing Friday-Botnet (10:02 - 11:02)..."
    editcap -A "2017-07-07 10:02:00" -B "2017-07-07 11:02:00" "$SRC/Friday-WorkingHours.pcap" "$DST/Friday-Botnet.pcap"
    echo "    -> Slicing Friday-PortScan (13:55 - 15:29)..."
    editcap -A "2017-07-07 13:55:00" -B "2017-07-07 15:29:00" "$SRC/Friday-WorkingHours.pcap" "$DST/Friday-PortScan.pcap"
    echo "    -> Slicing Friday-DDoS (15:56 - 16:16)..."
    editcap -A "2017-07-07 15:56:00" -B "2017-07-07 16:16:00" "$SRC/Friday-WorkingHours.pcap" "$DST/Friday-DDoS.pcap"
fi

echo "========================================================="
echo "✅ FATIAMENTO GRANULAR COMPLETO!"
echo "   -> PCAPs fatiados salvos em: $DST"
echo "========================================================="
