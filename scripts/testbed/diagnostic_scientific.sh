#!/bin/bash
# Lynceus Scientific Diagnostic & Evidence Collector
# --------------------------------------------------

PCAP="/root/CIC-IDS-2017-sliced/Friday-DDoS.pcap"
OUT_DIR="./data/interim/EBPF_RAW"
LOG_FILE="./diagnostic_report.log"

echo "=========================================================" | tee "$LOG_FILE"
echo "=== LYNCEUS SCIENTIFIC DIAGNOSTIC PROTOCOL ===" | tee -a "$LOG_FILE"
echo "=========================================================" | tee -a "$LOG_FILE"
echo "Date: $(date)" | tee -a "$LOG_FILE"
echo "Kernel: $(uname -a)" | tee -a "$LOG_FILE"
echo "CPU Cores: $(nproc)" | tee -a "$LOG_FILE"

# 1. Purge and recreate veth interfaces
echo "" | tee -a "$LOG_FILE"
echo "[*] Recreating veth interfaces..." | tee -a "$LOG_FILE"
ip link delete veth0 2>/dev/null || true
ip link delete veth1 2>/dev/null || true
ip link add veth0 type veth peer name veth1
ip link set veth0 up
ip link set veth1 up
ip link set veth0 promisc on
ip link set veth1 promisc on

# Show interface configurations
echo "" | tee -a "$LOG_FILE"
echo "[*] Interface Configuration (ip link show):" | tee -a "$LOG_FILE"
ip link show veth0 | tee -a "$LOG_FILE"
ip link show veth1 | tee -a "$LOG_FILE"

# 2. Check Sysctl parameters
echo "" | tee -a "$LOG_FILE"
echo "[*] Sysctl Network Parameters:" | tee -a "$LOG_FILE"
sysctl -a 2>/dev/null | grep -E "net.ipv[46].conf.veth[01]" | tee -a "$LOG_FILE"

# 3. Start Tcpdump on veth1 in background
echo "" | tee -a "$LOG_FILE"
echo "[*] Launching tcpdump on veth1 in background..." | tee -a "$LOG_FILE"
tcpdump -i veth1 -n -c 10 > /tmp/diag_tcpdump.log 2>&1 &
TCPDUMP_PID=$!
sleep 1

# 4. Start Loader on veth1 in background
echo "" | tee -a "$LOG_FILE"
echo "[*] Launching Lynceus Loader on veth1 in generic (skb) mode..." | tee -a "$LOG_FILE"
./build/loader veth1 skb > /tmp/diag_loader.log 2>&1 &
LOADER_PID=$!
sleep 2

# Check BPF attachments
echo "" | tee -a "$LOG_FILE"
echo "[*] Active BPF/XDP Attachments (bpftool net list):" | tee -a "$LOG_FILE"
if command -v bpftool &> /dev/null; then
    bpftool net list 2>/dev/null | grep -E "veth[0-9]" | tee -a "$LOG_FILE"
else
    echo "bpftool not installed." | tee -a "$LOG_FILE"
fi

# Get initial link statistics
echo "" | tee -a "$LOG_FILE"
echo "[*] Initial Link Statistics (veth0 & veth1):" | tee -a "$LOG_FILE"
ip -s link show veth0 | tee -a "$LOG_FILE"
ip -s link show veth1 | tee -a "$LOG_FILE"

# 5. Inject PCAP
echo "" | tee -a "$LOG_FILE"
echo "[*] Injecting $PCAP via veth0..." | tee -a "$LOG_FILE"
tcpreplay-edit --topspeed --mtu-trunc -i veth0 "$PCAP" 2>&1 | tee -a "$LOG_FILE"

# Allow buffers to drain
sleep 3

# Get post-injection link statistics
echo "" | tee -a "$LOG_FILE"
echo "[*] Post-Injection Link Statistics (veth0 & veth1):" | tee -a "$LOG_FILE"
ip -s link show veth0 | tee -a "$LOG_FILE"
ip -s link show veth1 | tee -a "$LOG_FILE"

# Stop loader and tcpdump
echo "" | tee -a "$LOG_FILE"
echo "[*] Stopping Daemon and Tcpdump..." | tee -a "$LOG_FILE"
kill -SIGINT $LOADER_PID
kill $TCPDUMP_PID 2>/dev/null
wait $LOADER_PID 2>/dev/null
wait $TCPDUMP_PID 2>/dev/null

# 6. Collect Logs and Audit Output
echo "" | tee -a "$LOG_FILE"
echo "[*] Daemon stderr log:" | tee -a "$LOG_FILE"
cat /tmp/diag_loader.log | tee -a "$LOG_FILE"

echo "" | tee -a "$LOG_FILE"
echo "[*] Tcpdump output log:" | tee -a "$LOG_FILE"
cat /tmp/diag_tcpdump.log | tee -a "$LOG_FILE"

# 7. Collect Kernel logs (dmesg) for XDP/BPF/veth errors
echo "" | tee -a "$LOG_FILE"
echo "[*] Kernel Ring Buffer (dmesg | tail -n 50):" | tee -a "$LOG_FILE"
dmesg | tail -n 50 | tee -a "$LOG_FILE"

echo "" | tee -a "$LOG_FILE"
echo "=========================================================" | tee -a "$LOG_FILE"
echo "=== DIAGNOSTIC REPORT COMPLETED: $LOG_FILE ===" | tee -a "$LOG_FILE"
echo "=========================================================" | tee -a "$LOG_FILE"

# Cleanup created veths
ip link delete veth0 2>/dev/null || true
ip link delete veth1 2>/dev/null || true
