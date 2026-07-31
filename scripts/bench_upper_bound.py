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
    subprocess.run("sudo ip link add rustiflow-t0 numtxqueues 16 numrxqueues 16 type veth peer name rustiflow-p0 numtxqueues 16 numrxqueues 16 netns rustiflow-peer", shell=True)
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
    cmd = f"sudo taskset -c 8-23 {RUSTIFLOW_BIN} -f rustiflow -o print pcap {PCAP_PATH} > /dev/null"
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
    cmd = f"cd /home/leonardo.herkenhoff/Lynceus && sudo taskset -c 8-23 {LYNCEUS_BIN} --pcap {PCAP_PATH} > /dev/null"
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

def run_pktgen_benchmark(target_mac):
    print("\n" + "="*50)
    print("=== SCENARIO 2: NETWORK PKTGEN UPPER BOUND ===")
    print("="*50)

    pktgen_script = f"""
modprobe pktgen
# Remove all devices
for f in /proc/net/pktgen/kpktgend_*; do
    echo "rem_device_all" > $f 2>/dev/null
done

for i in $(seq 0 15); do
    core=$((8 + i))
    echo "add_device rustiflow-p0@$i" > /proc/net/pktgen/kpktgend_$core 2>/dev/null
    dev="/proc/net/pktgen/rustiflow-p0@$i"
    if [ ! -f "$dev" ]; then
        dev="/proc/net/pktgen/rustiflow-p0"
    fi
    echo "count 10000000" > $dev 2>/dev/null
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
    time.sleep(2)
    run_pktgen()
    subprocess.run("sudo pkill rustiflow", shell=True)
    time.sleep(2)

    print("\n[*] Running Lynceus Network Upper Bound...")
    lyn_proc = subprocess.Popen(f"cd /home/leonardo.herkenhoff/Lynceus && sudo taskset -c 8-23 {LYNCEUS_BIN} rustiflow-t0 > /dev/null", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(2)
    run_pktgen()
    subprocess.run("sudo pkill loader", shell=True)
    time.sleep(2)


if __name__ == "__main__":
    mac = setup_veth()
    run_offline_benchmark()
    run_pktgen_benchmark(mac)
    print("\n[*] Upper Bound Benchmarks Completed!")
