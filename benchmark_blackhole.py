#!/usr/bin/env python3
"""
Blackhole Extraction Benchmark (Zero-IO)
------------------------------------------------------------------------
Isolates the NetFlowLyzer eBPF Data Plane & Control Plane from Disk I/O.
Redirects all CSV stdout to /dev/null to measure the raw computational
ceiling of the Kernel (SKB mode) and User-Space string serialization.
"""

import subprocess
import time
import os
import glob
import re

BASE_DIR = "/opt/eBPFNetFlowLyzer"
DATA_RAW = os.path.join(BASE_DIR, "data/raw/PCAP")

INJECT_IFACE = "eno12399np0"
SENSOR_IFACE = "eno12399np0"

def setup_veth():
    # Hardware ASIC Loopback Agressivo
    print(f"[*] Attempting Hardware Link-Up on {INJECT_IFACE}...")
    
    # Executa o script de hardening para XDP Native
    subprocess.run(["bash", "scripts/fix_nic_xdp.sh", INJECT_IFACE], check=False)
    
    subprocess.run(["ip", "link", "set", INJECT_IFACE, "up"], check=False)
    subprocess.run(["ip", "link", "set", INJECT_IFACE, "promisc", "on"], check=False)
    
    # Loopback removido - Falha em Broadcom e causa erro de Netlink
    # print("[*] Optional: Attempting loopback mode...")
    # subprocess.run(["ethtool", "-K", INJECT_IFACE, "loopback", "on"], check=False)
    
    # NÃO FORÇAR SPEED 1000 em placas de 100Gb+ (BCM57508)
    # subprocess.run(["ethtool", "-s", INJECT_IFACE, "speed", "1000", "duplex", "full", "autoneg", "off"], check=False)

def teardown_veth():
    pass

def run_blackhole_test():
    print("=== eBPF Zero-IO Extraction Benchmark ===")
    
    # 1. Compile engine to ensure we have the absolute latest optimized binary
    print("[*] Recompiling Daemon (-O3 -march=native -flto)...")
    subprocess.run("make clean && make", shell=True, check=True, stdout=subprocess.DEVNULL, cwd=BASE_DIR)
    
    # 2. Setup VETH
    print("[*] Instantiating Virtual Topology...")
    setup_veth()
    
    # Get PCAPs (pick the first vector for speed test)
    pcaps = sorted(glob.glob(os.path.join(DATA_RAW, "**", "*.pcap*"), recursive=True))
    if not pcaps:
        print("No PCAPs found.")
        return
    
    # Let's test on the first 3 PCAPs to get an accurate average
    test_pcaps = pcaps[:3]
    
    try:
        # 3. Spawn Extractor pointing to log for diagnostic, but stdout to null for performance
        print("[*] Igniting Lynceus Engine (Diagnostic logs in extractor.log) -> /dev/null")
        with open("extractor.log", "w") as log_f:
            extractor = subprocess.Popen(
                ["./build/loader", SENSOR_IFACE],
                stdout=subprocess.DEVNULL, stderr=log_f, cwd=BASE_DIR
            )
        time.sleep(3) # Wait for map allocation
        
        # 4. Stream Traffic
        total_packets = 0
        start_time = time.time()
        
        for p in test_pcaps:
            print(f"     -> Top-Speed Streaming: {os.path.basename(p)}")
            cmd = f"tcpreplay -i {INJECT_IFACE} --topspeed {p} 2>&1"
            res = subprocess.run(cmd, shell=True, capture_output=True, text=True, check=False)
            matches = re.findall(r"(\d+)\s+packets", res.stdout)
            if matches:
                total_packets += int(matches[0])
                
        elapsed = time.time() - start_time
        pps = total_packets / elapsed if elapsed > 0 else 0
        
        # 5. Terminate
        print("[*] Tearing down engine...")
        extractor.terminate()
        extractor.wait()
        
        print(f"\n{'='*60}")
        print(f" 🏆 ZERO-IO PERFORMANCE METRICS")
        print(f"{'='*60}")
        print(f" Packets Processed : {total_packets:,}")
        print(f" Time Elapsed      : {elapsed:.2f} seconds")
        print(f" Maximum PPS       : {pps:,.0f} pps")
        print(f"{'='*60}")
        print(" 📌 Analysis:")
        print(" If PPS > 500k: Disk I/O (Python pipe + Ext4) is the exact bottleneck.")
        print(" If PPS < 250k: SKB Kernel Allocation / String Serialization is the limit.")
        
        print(f"\n[*] Extractor Diagnostic Log:")
        subprocess.run(["cat", "extractor.log"], check=False)
        
    finally:
        teardown_veth()

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("FATAL: Root privileges required (BPF/XDP).")
        exit(1)
    run_blackhole_test()
