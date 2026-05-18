#!/bin/bash
# Lynceus - Batch PCAP Extractor
# Extrai as features de rede de múltiplos PCAPs sequencialmente.

PCAP_DIR="/root/CIC-IDS-2017-sliced"
if [ ! -d "$PCAP_DIR" ]; then
    PCAP_DIR="/root/CIC-IDS-2017"
fi

if [ ! -d "$PCAP_DIR" ]; then
    echo "[!] Diretório de origem não encontrado: $PCAP_DIR"
    exit 1
fi
echo "[*] Usando diretório de PCAPs: $PCAP_DIR"

echo "========================================================="
echo "=== Lynceus Batch Extractor (L3/L4/L7) ==="
echo "========================================================="

echo "[*] Compilando motor eBPF (Zero-Libc)..."
OUT_DIR="/opt/eBPFNetFlowLyzer/data/interim/EBPF_RAW"
mkdir -p "$OUT_DIR"
echo "[*] Purgando arquivos CSV residuais de extrações anteriores..."
rm -f "$OUT_DIR"/*.csv

if ! command -v tcpreplay &> /dev/null; then
    echo "[!] tcpreplay não encontrado. Instalando..."
    apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y tcpreplay
fi

echo "[*] Configurando par veth (veth0 <-> veth1) para ingestão offline..."
ip link delete veth0 2>/dev/null || true
ip link delete veth1 2>/dev/null || true
ip link add veth0 type veth peer name veth1
ip link set veth0 up
ip link set veth1 up
ip link set dev veth0 mtu 65535
ip link set dev veth1 mtu 65535

FILES=$(ls "$PCAP_DIR"/*.pcap 2>/dev/null)

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
    ./build/loader skb veth1 > "$OUT_DIR/$CSV_NAME" 2> "$ERR_FILE" &
    LOADER_PID=$!
    
    echo "    -> Aguardando estabilização dos mapas BPF..."
    sleep 2
    
    if ! kill -0 $LOADER_PID 2>/dev/null; then
        echo "    [X] ERRO CRÍTICO: O loader eBPF morreu imediatamente antes do replay!"
        echo "    ---> Causa provável (stderr):"
        cat "$ERR_FILE"
    fi
    
    echo "    -> Disparando tcpreplay em TOPSPEED (Limites de Hardware) via veth0..."
    tcpreplay --topspeed -i veth0 "$PCAP"
    
    echo "    -> Finalizando coleta e gravando CSV..."
    kill -SIGINT $LOADER_PID
    wait $LOADER_PID 2>/dev/null
    
    # Telemetria de tamanho do CSV para auditoria imediata
    if [ -f "$OUT_DIR/$CSV_NAME" ]; then
        LINES=$(wc -l < "$OUT_DIR/$CSV_NAME")
        SIZE=$(du -sh "$OUT_DIR/$CSV_NAME" | cut -f1)
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
