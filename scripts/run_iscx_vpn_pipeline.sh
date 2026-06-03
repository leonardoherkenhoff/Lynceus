#!/usr/bin/env bash
# ==============================================================================
# Lynceus Testbed - Pipeline Executor for ISCX-VPN-2016
# ------------------------------------------------------------------------------
# Scientific Milestone: v2.0 (High-Performance I/O)
#
# Research Objective:
#     Orchestrates the XDP packet injection, eBPF parsing, and ground-truth 
#     topological attribution for the ISCX-VPN-2016 dataset.
# ==============================================================================

set -e

WORKSPACE="/opt/eBPFNetFlowLyzer"
PCAP_DIR="/root/ISCX-VPN-2016"
RAW_OUT_DIR="$WORKSPACE/data/interim/EBPF_RAW_VPN"
LABELED_OUT_DIR="$WORKSPACE/data/processed/ISCX_VPN_LABELED"
DAEMON="$WORKSPACE/build/loader"

mkdir -p "$RAW_OUT_DIR"
mkdir -p "$LABELED_OUT_DIR"

echo "=========================================================="
echo " [Fase 1] Inicialização da Arquitetura eBPF (ISCX-VPN)"
echo "=========================================================="

cd "$WORKSPACE"
echo " -> Recompilando o daemon nativo..."
make clean > /dev/null
make > /dev/null

echo " -> Garantindo a topologia de enlace veth0 <-> veth1..."
ip link show veth0 >/dev/null 2>&1 || {
    ip link add veth0 type veth peer name veth1
    ip link set veth0 up
    ip link set veth1 up
    # MTU restrito para compatibilidade de página única (XDP_DRV)
    ip link set veth0 mtu 1500
    ip link set veth1 mtu 1500
}

# Desanexa eventuais programas XDP legados
ip link set dev veth0 xdp off 2>/dev/null || true
ip link set dev veth1 xdp off 2>/dev/null || true

echo "=========================================================="
echo " [Fase 2] Extração XDP e Rotulação de Metadados"
echo "=========================================================="

if [ ! -d "$PCAP_DIR" ]; then
    echo "[!] ERRO: Diretório de PCAPs não encontrado em $PCAP_DIR."
    echo "    Execute ./scripts/testbed/download_iscx_vpn_2016.sh primeiro."
    exit 1
fi

find "$PCAP_DIR" -type f -iname "*.pcap" | while read -r pcap_path; do
    filename=$(basename "$pcap_path")
    filename_no_ext="${filename%.*}"
    
    echo "--------------------------------------------------------"
    echo " PROCESSANDO ARQUIVO: $filename"
    
    # Heurística de Contexto do Arquivo (Dataset ISCX-VPN-2016)
    vpn_status="NonVPN"
    app_label="Unknown"
    
    # Regra 1: Tunneling Status
    if echo "$filename" | grep -qi "vpn"; then
        vpn_status="VPN"
    fi
    
    # Regra 2: Application Class
    if echo "$filename" | grep -qi "skype\|voip"; then
        app_label="VoIP"
    elif echo "$filename" | grep -qi "chat\|aim\|icq\|hangouts\|facebook"; then
        app_label="Chat"
    elif echo "$filename" | grep -qi "email\|mail"; then
        app_label="Email"
    elif echo "$filename" | grep -qi "stream\|youtube\|spotify\|vimeo"; then
        app_label="Streaming"
    elif echo "$filename" | grep -qi "ft\|filetransfer\|scp\|sftp\|file\|scpDown"; then
        app_label="File_Transfer"
    elif echo "$filename" | grep -qi "p2p\|bittorrent\|torrent"; then
        app_label="P2P"
    elif echo "$filename" | grep -qi "browse\|web"; then
        app_label="Browsing"
    fi

    raw_csv="$RAW_OUT_DIR/${filename_no_ext}.csv"
    labeled_csv="$LABELED_OUT_DIR/${filename_no_ext}_labeled.csv"
    
    echo " -> [XDP] Anexando bpf_prog na interface receptora e escutando (Timeout=15s)..."
    $DAEMON veth1 > "$raw_csv" &
    LOADER_PID=$!
    
    sleep 2 # Estabilização atômica do mapa no kernel
    
    echo " -> [INJ] Injetando pacotes em topspeed via veth0..."
    tcpreplay-edit --topspeed --mtu-trunc -i veth0 "$pcap_path" || true
    
    echo " -> [XDP] Emitindo SIGINT para forçar Flush do RingBuffer..."
    kill -INT $LOADER_PID
    wait $LOADER_PID || true
    
    echo " -> [PY]  Rotulando o Stream de Fluxos gerado..."
    python3 "$WORKSPACE/scripts/preprocessing/iscx_vpn_labeler.py" "$raw_csv" "$labeled_csv" "$vpn_status" "$app_label"
    
done

echo "=========================================================="
echo " [Fase 3] Finalizado"
echo " Todos os fluxos estão purificados e tabelados em $LABELED_OUT_DIR"
echo "=========================================================="
