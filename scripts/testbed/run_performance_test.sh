#!/bin/bash
# Lynceus - Sprint 2 Performance Test (vs RustiFlow)
# Este script mede a capacidade de ingestão de pacotes offline (PPS) 
# e overhead de RAM/CPU comparativo.

if [ -z "$1" ]; then
    echo "Uso: $0 <caminho_para_o_pcap_mesclado_50GB>"
    exit 1
fi

PCAP_FILE=$1

echo "========================================================="
echo "=== Lynceus Performance Stress-Test (Sprint 2) ==="
echo "========================================================="
echo "[*] Arquivo PCAP: $PCAP_FILE"

if ! command -v tcpreplay &> /dev/null; then
    echo "[!] tcpreplay não encontrado. Instalando..."
    apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y tcpreplay
fi

echo "[*] Configurando par veth (veth0 <-> veth1) para injeção topspeed (develop mode)..."
ip link delete veth0 2>/dev/null || true
ip link delete veth1 2>/dev/null || true
ip link add veth0 type veth peer name veth1
ip link set veth0 up
ip link set veth1 up
ip link set veth0 promisc on
ip link set veth1 promisc on
sysctl -w net.ipv6.conf.veth0.disable_ipv6=0 >/dev/null 2>&1 || true
sysctl -w net.ipv6.conf.veth1.disable_ipv6=0 >/dev/null 2>&1 || true
sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null 2>&1 || true
IFACE="veth1"
TC_IFACE="veth0"

echo "[*] Interface Receptora (XDP): $IFACE"
echo "[*] Interface Injetora (tcpreplay): $TC_IFACE"

echo "[*] Compilando motor Lynceus com otimizacoes maximas..."
make clean
make

echo "[*] Iniciando o Daemon do Lynceus (XDP) em background..."
# Roda o Lynceus na interface de loopback
./build/loader $IFACE skb > loader_audit.log 2>&1 &
LYNCEUS_PID=$!

echo "[*] Aguardando estabilizacao dos mapas BPF (3s)..."
sleep 3

echo "[*] Monitorando recursos da CPU/RAM do Daemon..."
# Inicia um coletor de metricas leve
top -b -d 1 -p $LYNCEUS_PID > resource_metrics.txt &
TOP_PID=$!

echo "[*] Iniciando a injeção massiva (TOPSPEED) via tcpreplay..."
echo "[*] Monitorando relogio global..."

# Executa e cronometra o tcpreplay na veth0
/usr/bin/time -v tcpreplay-edit -i $TC_IFACE --topspeed --mtu-trunc "$PCAP_FILE"

echo "[*] Injeção concluida! Aguardando escoamento dos buffers (3s)..."
sleep 3

echo "[*] Enviando sinal de encerramento para o Daemon..."
kill -SIGINT $LYNCEUS_PID
kill $TOP_PID 2>/dev/null

echo "[*] Aguardando descarga de buffers (flush)..."
wait $LYNCEUS_PID

echo "[*] Destruindo par veth..."
ip link delete veth0 2>/dev/null || true

echo "========================================================="
echo "=== Teste de Desempenho Concluido ==="
echo "========================================================="
echo "1. O tempo exato de execucao e os gargalos estao acima (saida do /usr/bin/time)."
echo "2. O consumo de CPU/RAM em tempo real foi salvo em resource_metrics.txt."
echo "3. Os pacotes capturados e as estatisticas do kernel estao no loader_audit.log."
