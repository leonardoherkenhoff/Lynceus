#!/bin/bash
# Lynceus - Sprint 2 Performance Test (vs RustiFlow)
# Este script mede a capacidade de ingestão de pacotes offline (PPS) 
# e overhead de RAM/CPU comparativo.

if [ -z "$1" ]; then
    echo "Uso: $0 <caminho_para_o_pcap_mesclado_50GB>"
    exit 1
fi

PCAP_FILE=$1
IFACE="lo"

echo "========================================================="
echo "=== Lynceus Performance Stress-Test (Sprint 2) ==="
echo "========================================================="
echo "[*] Arquivo PCAP: $PCAP_FILE"
echo "[*] Interface Alvo: $IFACE"

echo "[*] Compilando motor Lynceus com otimizacoes maximas..."
make clean
make

echo "[*] Iniciando o Daemon do Lynceus (XDP) em background..."
# Roda o Lynceus na interface de loopback
./build/loader skb $IFACE > loader_audit.log 2>&1 &
LYNCEUS_PID=$!

echo "[*] Aguardando estabilizacao dos mapas BPF (3s)..."
sleep 3

echo "[*] Monitorando recursos da CPU/RAM do Daemon..."
# Inicia um coletor de metricas leve
top -b -d 1 -p $LYNCEUS_PID > resource_metrics.txt &
TOP_PID=$!

echo "[*] Iniciando a injeção massiva (TOPSPEED) via tcpreplay..."
echo "[*] Monitorando relogio global..."

# Executa e cronometra o tcpreplay
/usr/bin/time -v tcpreplay -i $IFACE --topspeed "$PCAP_FILE"

echo "[*] Injeção concluida! Enviando sinal de encerramento para o Daemon..."
kill -SIGINT $LYNCEUS_PID
kill $TOP_PID 2>/dev/null

echo "[*] Aguardando descarga de buffers (flush)..."
wait $LYNCEUS_PID

echo "========================================================="
echo "=== Teste de Desempenho Concluido ==="
echo "========================================================="
echo "1. O tempo exato de execucao e os gargalos estao acima (saida do /usr/bin/time)."
echo "2. O consumo de CPU/RAM em tempo real foi salvo em resource_metrics.txt."
echo "3. Os pacotes capturados e as estatisticas do kernel estao no loader_audit.log."
