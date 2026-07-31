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

if ! command -v time &> /dev/null; then
    echo "[!] utilitário 'time' não encontrado. Instalando..."
    apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y time
fi

echo "[*] Compilando motor Lynceus com otimizacoes maximas..."
make clean
make

echo "[*] Monitorando recursos da CPU/RAM globalmente..."
# Coleta de métricas do sistema durante a execução
vmstat 1 > resource_metrics.txt &
VMSTAT_PID=$!

echo "[*] Iniciando a injeção massiva Nativa BPF..."
echo "[*] Monitorando relogio global..."

# Executa e cronometra a injeção nativa via libbpf (Sem VETH, sem tcpreplay)
/usr/bin/time -v ./build/loader --pcap "$PCAP_FILE" 2> loader_audit.log

echo "[*] Injeção concluida!"

kill $VMSTAT_PID 2>/dev/null

echo "========================================================="
echo "=== Teste de Desempenho Concluido ==="
echo "========================================================="
echo "1. O tempo exato de execucao e os gargalos estao acima (saida do /usr/bin/time)."
echo "2. O consumo de recursos do sistema foi salvo em resource_metrics.txt."
echo "3. O benchmark nativo do eBPF (PPS absoluto) foi salvo em loader_audit.log."

