#!/bin/bash
# Lynceus - Batch PCAP Extractor
# Extrai as features de rede de múltiplos PCAPs sequencialmente.

# Permite injeção de variáveis via argumento posicional
PCAP_DIR="${1:-/root/CIC-IDS-2017}"
OUT_DIR="${2:-/opt/lynceus/data/interim/EBPF_RAW}"

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

if ! command -v tcpreplay &> /dev/null; then
    echo "[!] tcpreplay não encontrado. Instalando..."
    apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y tcpreplay
fi

# Não é mais necessário criar veth pairs para injeção nativa,
# mas mantemos a limpeza caso tenham sobrado de execuções anteriores.
ip link delete veth0 2>/dev/null || true
ip link delete veth1 2>/dev/null || true

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
    
    # Gera nome unico baseado na pasta pai para evitar colisao
    PARENT_DIR=$(basename "$(dirname "$PCAP")")
    BASE_NAME=$(basename "$PCAP" .pcap)
    BASE_NAME=$(basename "$BASE_NAME" .pcapng)
    CSV_NAME="${PARENT_DIR}_${BASE_NAME}.csv"
    
    if [ -s "$OUT_DIR/$CSV_NAME" ]; then
        echo "---------------------------------------------------------"
        echo "[*] Cache Hit: O arquivo $CSV_NAME já foi extraído previamente. Pulando injeção."
        continue
    fi
    
    echo "---------------------------------------------------------"
    echo "[*] Injetando no XDP/eBPF: $(basename "$PCAP") ($PARENT_DIR)"
    
    # O motor eBPF processará de forma nativa e síncrona
    ERR_FILE="$OUT_DIR/${CSV_NAME}.err"
    
    # Executa o daemon do Lynceus no modo nativo (bpf_prog_test_run_opts) síncrono.
    ./build/loader --pcap "$PCAP" > "$OUT_DIR/$CSV_NAME" 2> "$ERR_FILE"
    
    # Como a execução é síncrona, a extração termina quando o comando retorna.
    
    # Telemetria de tamanho do CSV para auditoria imediata
    if [ -f "$OUT_DIR/$CSV_NAME" ]; then
        LINES=$(wc -l < "$OUT_DIR/$CSV_NAME")
        SIZE=$(du -sh "$OUT_DIR/$CSV_NAME" | cut -f1)
        echo "    -> [Auditoria] Dataset extraído: $LINES linhas ($SIZE)"
        if [ "$LINES" -le 1 ]; then
            echo "    [!] ALERTA CRÍTICO: Zero fluxos capturados. Arquivo contém apenas cabeçalhos L7."
        fi
    else
        echo "    [X] ERRO CRÍTICO: IO de gravação falhou. Arquivo $CSV_NAME não existe."
    fi
    # Extrai o benchmark do stderr e imprime na tela para registro
    if [ -s "$ERR_FILE" ]; then
        echo "    ---> Relatório de Performance (eBPF Nativo):"
        grep "\[\*\]" "$ERR_FILE" | sed 's/^/         /'
        echo "    ---> Log bruto preservado em: $ERR_FILE"
    fi
    
    echo "[V] Ingestão PCAP concluída."
done

echo "========================================================="
echo "[*] Extração em Lote Finalizada."
