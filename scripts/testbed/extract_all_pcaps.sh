#!/bin/bash
# Lynceus - Batch PCAP Extractor
# Extrai as features de rede de múltiplos PCAPs sequencialmente.

# Permite injeção de variáveis via argumento posicional
PCAP_DIR="${1:-/root/CIC-IDS-2017}"
OUT_DIR="${2:-/opt/eBPFNetFlowLyzer/data/interim/EBPF_RAW}"

if [ ! -d "$PCAP_DIR" ]; then
    echo "[!] Diretório de origem não encontrado: $PCAP_DIR"
    exit 1
fi
echo "[*] Usando diretório de PCAPs: $PCAP_DIR"

echo "========================================================="
echo "=== Lynceus Batch Extractor (L3/L4/L7) ==="
echo "========================================================="

echo "[*] Preparando diretório de saída..."
mkdir -p "$OUT_DIR"
echo "[*] Purgando arquivos CSV residuais de extrações anteriores..."
rm -f "$OUT_DIR"/*.csv

if ! command -v tcpreplay &> /dev/null; then
    echo "[!] tcpreplay não encontrado. Instalando..."
    apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y tcpreplay
fi

echo "[*] Configurando par veth (veth0 <-> veth1) para Ingestão Offline (develop mode)..."
ip link delete veth0 2>/dev/null || true
ip link delete veth1 2>/dev/null || true
ip link add veth0 type veth peer name veth1
ip link set dev veth0 mtu 65535
ip link set dev veth1 mtu 65535
ip link set veth0 up
ip link set veth1 up
ip link set veth0 promisc on
ip link set veth1 promisc on
sysctl -w net.ipv6.conf.veth0.disable_ipv6=0 >/dev/null 2>&1 || true
sysctl -w net.ipv6.conf.veth1.disable_ipv6=0 >/dev/null 2>&1 || true
sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null 2>&1 || true
FILES=$(find "$PCAP_DIR" -type f \( -iname "*.pcap" -o -iname "*.pcapng" \) 2>/dev/null)

if [ -z "$FILES" ]; then
    echo "[X] Nenhum PCAP encontrado para extração."
    exit 1
fi

for PCAP in $FILES; do
    # Evita extrair o PCAP massivo do teste de performance neste estagio
    if [[ "$PCAP" == *"Merged"* ]]; then
        echo "[*] Ignorando arquivo massivo de benchmark de PPS: $PCAP"
        continue
    fi

    
    echo "---------------------------------------------------------"
    echo "[*] Injetando no XDP/eBPF: $(basename "$PCAP")"
    
    CSV_NAME=$(basename "$PCAP" .pcap).csv
    
    # O motor eBPF anexa ao hook XDP da interface receptora (veth1)
    # Salvamos o stderr para diagnóstico científico preciso de falhas de carregamento BPF
    ERR_FILE="$OUT_DIR/${CSV_NAME}.err"
    # Obter dinamicamente o MAC de veth1 para reescrita fisica de pacotes, mitigando drops por PACKET_OTHERHOST
    VETH1_MAC=$(cat /sys/class/net/veth1/address 2>/dev/null || ip link show veth1 | grep link/ether | awk '{print $2}')
    
    # Executa o daemon do Lynceus no modo nativo (drv). Para veth nativo, anexamos em ambas (veth1 e veth0) para inicializar o xdp_ring.
    ./build/loader veth1 veth0 skb > "$ERR_FILE" 2> "$ERR_FILE" &
    LOADER_PID=$!
    
    echo "    -> Aguardando estabilização dos mapas BPF..."
    while ! grep -q "XDP attached on veth1" "$ERR_FILE" 2>/dev/null; do sleep 0.5; done; echo "    -> BPF Maps estabilizados!"
    
    if ! kill -0 $LOADER_PID 2>/dev/null; then
        echo "    [X] ERRO CRÍTICO: O loader eBPF morreu imediatamente antes do replay!"
        echo "    ---> Causa provável (stderr):"
        cat "$ERR_FILE"
    fi
    
    echo "    -> Disparando tcpreplay em TOPSPEED com reescrita de DMAC ($VETH1_MAC) e MTU truncado..."
    TMP_PCAP="/tmp/norm_$(basename "$PCAP")"
    tcprewrite --dlt=enet --enet-dmac="$VETH1_MAC" --enet-smac="0a:0b:0c:0d:0e:0f" --infile="$PCAP" --outfile="$TMP_PCAP"
    tcpreplay --topspeed -i veth0 "$TMP_PCAP"
    rm -f "$TMP_PCAP"
    
    echo "    -> Aguardando escoamento dos buffers (flush)..."
    sleep 3
    
    echo "    -> Finalizando coleta e gravando CSV..."
    kill -SIGINT $LOADER_PID
    wait $LOADER_PID 2>/dev/null
    
    # Telemetria de tamanho do CSV para auditoria imediata
    if [ -f "$ERR_FILE" ]; then
        LINES=$(wc -l < "$ERR_FILE")
        SIZE=$(du -sh "$ERR_FILE" | cut -f1)
        echo "    -> [Auditoria] CSV gerado: $LINES linhas ($SIZE)"
        if [ "$LINES" -le 1 ]; then
            echo "    [!] ALERTA: CSV contém apenas cabeçalhos (0 fluxos capturados)!"
            if [ -s "$ERR_FILE" ]; then
                echo "    ---> Erros relatados pelo Daemon:"
                cat "$ERR_FILE"
            fi
        fi
    else
        echo "    [X] ERRO: Arquivo CSV não foi criado fisicamente!"
    fi
    rm -f "$ERR_FILE"
    echo "[V] Extração concluida."
done

echo "[*] Destruindo par veth..."
ip link delete veth0 2>/dev/null || true

echo "========================================================="
echo "[*] Extração em Lote Finalizada."
