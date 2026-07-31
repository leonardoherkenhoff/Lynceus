#!/usr/bin/env python3
import os
import subprocess
import time
import re
import signal
import sys

PCAP_PATH = "/root/CIC-IDS-2017/Monday-WorkingHours.pcap"
RUSTIFLOW_BIN = "/home/leonardo.herkenhoff/RustiFlow/target/release/rustiflow"
LYNCEUS_BIN = "/home/leonardo.herkenhoff/Lynceus/build/loader"

def setup_veth():
    print("[*] Setting up veth pair...")
    subprocess.run("sudo ip link delete rustiflow-t0", shell=True, stderr=subprocess.DEVNULL)
    subprocess.run("sudo ip netns del rustiflow-peer", shell=True, stderr=subprocess.DEVNULL)
    
    subprocess.run("sudo ip netns add rustiflow-peer", shell=True)
    subprocess.run("sudo ip link add rustiflow-t0 numtxqueues 48 numrxqueues 48 type veth peer name rustiflow-p0 numtxqueues 48 numrxqueues 48 netns rustiflow-peer", shell=True)
    subprocess.run("sudo ip link set rustiflow-t0 up", shell=True)
    subprocess.run("sudo ip netns exec rustiflow-peer ip link set lo up", shell=True)
    subprocess.run("sudo ip netns exec rustiflow-peer ip link set rustiflow-p0 up", shell=True)
    
    # Disable gro/lro/tso
    subprocess.run("sudo ethtool -K rustiflow-t0 rx off tx off tso off gro off gso off lro off", shell=True, stderr=subprocess.DEVNULL)
    subprocess.run("sudo ip netns exec rustiflow-peer ethtool -K rustiflow-p0 rx off tx off tso off gro off gso off lro off", shell=True, stderr=subprocess.DEVNULL)
    
    # Get MAC of rustiflow-t0
    mac_cmd = "ip link show rustiflow-t0 | grep link/ether | awk '{print $2}'"
    mac = subprocess.check_output(mac_cmd, shell=True).decode().strip()
    return mac

def run_offline_benchmark():
    print("\n" + "="*50)
    print("=== SCENARIO 1: OFFLINE PCAP UPPER BOUND ===")
    print("="*50)

    # 1. RustiFlow
    print("\n[*] Running RustiFlow Offline PCAP...")
    cmd = f"sudo {RUSTIFLOW_BIN} -f rustiflow -o print pcap {PCAP_PATH} > /dev/null"
    t0 = time.time()
    try:
        res = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=120)
        t1 = time.time()
        print(f"[+] RustiFlow completed in {t1-t0:.2f} seconds.")
        if res.stderr:
            print("    [STDERR] " + res.stderr.strip()[:200])
    except Exception as e:
        print(f"[-] RustiFlow failed: {e}")

    time.sleep(2)

    # 2. Lynceus
    print("\n[*] Running Lynceus Offline PCAP...")
    cmd = f"cd /home/leonardo.herkenhoff/Lynceus && sudo {LYNCEUS_BIN} --pcap {PCAP_PATH} > /dev/null"
    t0 = time.time()
    try:
        res = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=120)
        t1 = time.time()
        pps_match = re.search(r"Speed\s*:\s*([\d\.]+)\s*PPS", res.stderr)
        pkts_match = re.search(r"(\d+) packets injected", res.stderr)
        if pps_match and pkts_match:
            print(f"[+] Lynceus completed in {t1-t0:.2f} seconds. Packets: {pkts_match.group(1)}. Speed: {pps_match.group(1)} PPS.")
        else:
            print(f"[+] Lynceus completed in {t1-t0:.2f} seconds. (Could not parse PPS)")
            if res.stderr:
                print("    [STDERR] " + res.stderr.strip()[:200])
    except Exception as e:
        print(f"[-] Lynceus failed: {e}")

def get_rx_stats(iface="rustiflow-t0"):
    try:
        res = subprocess.check_output(f"ip -s -s link show {iface}", shell=True).decode()
        lines = res.strip().split("\n")
        for idx, line in enumerate(lines):
            if "RX:" in line and "packets" in line and "dropped" in line:
                parts = lines[idx+1].split()
                return int(parts[1]), int(parts[3])
    except Exception as e:
        pass
    return 0, 0

def run_pktgen_benchmark(target_mac):
    print("\n" + "="*50)
    print("=== SCENARIO 2: NETWORK PKTGEN UPPER BOUND ===")
    print("="*50)

    pktgen_script = f"""
modprobe pktgen
for f in /proc/net/pktgen/kpktgend_*; do
    echo "rem_device_all" > $f 2>/dev/null
done

for i in $(seq 0 47); do
    echo "add_device rustiflow-p0@$i" > /proc/net/pktgen/kpktgend_$i 2>/dev/null
    dev="/proc/net/pktgen/rustiflow-p0@$i"
    if [ ! -f "$dev" ]; then
        dev="/proc/net/pktgen/rustiflow-p0"
    fi
    echo "flag QUEUE_MAP_CPU" > $dev 2>/dev/null
    echo "queue_map_min $i" > $dev 2>/dev/null
    echo "queue_map_max $i" > $dev 2>/dev/null
    echo "count 5000000" > $dev 2>/dev/null
    echo "clone_skb 1000" > $dev 2>/dev/null
    echo "pkt_size 60" > $dev 2>/dev/null
    echo "delay 0" > $dev 2>/dev/null
done
"""
    script_path = "/home/leonardo.herkenhoff/setup_pktgen.sh"
    with open(script_path, "w") as f:
        f.write(pktgen_script)
    
    def run_pktgen():
        subprocess.run(f"sudo ip netns exec rustiflow-peer bash {script_path}", shell=True)
        subprocess.Popen("sudo ip netns exec rustiflow-peer bash -c 'echo start > /proc/net/pktgen/pgctrl'", shell=True)
        time.sleep(10)
        subprocess.run("sudo ip netns exec rustiflow-peer bash -c 'echo stop > /proc/net/pktgen/pgctrl'", shell=True)
        try:
            res = subprocess.check_output("sudo ip netns exec rustiflow-peer bash -c 'cat /proc/net/pktgen/rustiflow-p0*'", shell=True).decode()
            pps_matches = re.findall(r"(\d+)pps", res)
            if pps_matches:
                total_pps = sum(int(p) for p in pps_matches)
                print(f"    [PktGen] Injected at {total_pps} PPS across {len(pps_matches)} threads")
            else:
                print("    [PktGen] Failed to parse PPS")
        except Exception as e:
            print(f"    [PktGen] Error reading stats: {e}")

    print("\n[*] Running RustiFlow Network Upper Bound...")
    pkts0, drops0 = get_rx_stats("rustiflow-t0")
    if os.path.exists("/tmp/rf_net.log"):
        os.remove("/tmp/rf_net.log")
    rf_proc = subprocess.Popen(f"sudo RUST_LOG=info {RUSTIFLOW_BIN} -f rustiflow -o print realtime rustiflow-t0 > /dev/null 2> /tmp/rf_net.log", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(2)
    run_pktgen()
    subprocess.run("sudo pkill -INT rustiflow", shell=True)
    time.sleep(2)
    pkts1, drops1 = get_rx_stats("rustiflow-t0")
    tot_pkts = pkts1 - pkts0
    tot_drops = drops1 - drops0
    drop_pct = (tot_drops / (tot_pkts + tot_drops)) * 100.0 if (tot_pkts + tot_drops) > 0 else 0.0
    print(f"    [Interface Stats] RX Packets Delivered: {tot_pkts:,} | Kernel Interface Drops: {tot_drops:,} ({drop_pct:.4f}% loss)")
    if os.path.exists("/tmp/rf_net.log"):
        rf_matched, rf_submitted, rf_dropped = 0, 0, 0
        with open("/tmp/rf_net.log", "r") as logf:
            for l in logf:
                if "eBPF counters" in l and "matched_packets=" in l:
                    print("    [RustiFlow Engine] " + l.strip().split("INFO")[-1].strip())
                    try:
                        m = re.search(r"matched_packets=(\d+), submitted_events=(\d+), dropped_packets=(\d+)", l)
                        if m:
                            rf_matched += int(m.group(1))
                            rf_submitted += int(m.group(2))
                            rf_dropped += int(m.group(3))
                    except: pass
                elif "Total dropped packets before exit:" in l:
                    print("    [RustiFlow Engine] " + l.strip().split("INFO")[-1].strip())
        tot_rf = rf_matched + rf_dropped
        rf_loss_pct = (rf_dropped / tot_rf) * 100.0 if tot_rf > 0 else 0.0
        print(f"    [RustiFlow Telemetry] Matched: {rf_matched:,} | Submitted: {rf_submitted:,} | Dropped: {rf_dropped:,} ({rf_loss_pct:.4f}% loss)")

    print("\n[*] Running Lynceus Network Upper Bound...")
    pkts0, drops0 = get_rx_stats("rustiflow-t0")
    if os.path.exists("/tmp/lyn_net.log"):
        os.remove("/tmp/lyn_net.log")
    lyn_proc = subprocess.Popen(f"cd /home/leonardo.herkenhoff/Lynceus && sudo {LYNCEUS_BIN} rustiflow-t0 > /dev/null 2> /tmp/lyn_net.log", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(2)
    run_pktgen()
    subprocess.run("sudo pkill -INT loader", shell=True)
    time.sleep(2)
    pkts1, drops1 = get_rx_stats("rustiflow-t0")
    tot_pkts = pkts1 - pkts0
    tot_drops = drops1 - drops0
    drop_pct = (tot_drops / (tot_pkts + tot_drops)) * 100.0 if (tot_pkts + tot_drops) > 0 else 0.0
    print(f"    [Interface Stats] RX Packets Delivered: {tot_pkts:,} | Kernel Interface Drops: {tot_drops:,} ({drop_pct:.4f}% loss)")
    if os.path.exists("/tmp/lyn_net.log"):
        with open("/tmp/lyn_net.log", "r") as logf:
            for l in logf:
                if any(x in l for x in ["Kernel-Space", "Telemetry Drops", "Speed:", "Topology:"]):
                    print("    [Lynceus Engine] " + l.strip())
    time.sleep(1)


if __name__ == "__main__":
    mac = setup_veth()
    run_offline_benchmark()
    run_pktgen_benchmark(mac)
    print("\n[*] Upper Bound Benchmarks Completed!")
