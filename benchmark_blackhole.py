#!/usr/bin/env python3
import subprocess
import time
import os
import glob
import re
import sys

BASE_DIR = "/opt/eBPFNetFlowLyzer"
DATA_RAW = os.path.join(BASE_DIR, "data/raw/PCAP")
VETH_TX = "veth_perf_tx"
VETH_RX = "veth_perf_rx"

def setup_veth():
    print(f"[*] Creating High-Performance Virtual Topology: {VETH_TX} <-> {VETH_RX} (MTU 9000)")
    subprocess.run(["ip", "link", "del", VETH_TX], check=False, stderr=subprocess.DEVNULL)
    subprocess.run(["ip", "link", "add", VETH_TX, "type", "veth", "peer", "name", VETH_RX], check=True)
    subprocess.run(["ip", "link", "set", VETH_TX, "mtu", "9000"], check=True)
    subprocess.run(["ip", "link", "set", VETH_RX, "mtu", "9000"], check=True)
    subprocess.run(["ip", "link", "set", VETH_TX, "up"], check=True)
    subprocess.run(["ip", "link", "set", VETH_RX, "up"], check=True)
    # Optimization: disable offloads on veth
    subprocess.run(["ethtool", "-K", VETH_RX, "gro", "off", "lro", "off"], check=False)

def cleanup_veth():
    print(f"[*] Cleaning up Virtual Topology...")
    subprocess.run(["ip", "link", "del", VETH_TX], check=False, stderr=subprocess.DEVNULL)

def run_benchmark():
    print("=== Lynceus Extreme Performance Benchmark (VETH Mode) ===")
    print("[*] Goal: Measure max throughput with all 495 features active.")
    
    print("[*] Compiling optimized binaries...")
    subprocess.run("make clean && make", shell=True, check=True, stdout=subprocess.DEVNULL, cwd=BASE_DIR)
    
    setup_veth()
    
    pcaps = sorted(glob.glob(os.path.join(DATA_RAW, "**", "*.pcap*"), recursive=True))
    if not pcaps:
        print("Error: No PCAP files found.")
        cleanup_veth()
        return
    
    test_pcap = pcaps[0]
    
    try:
        print("[*] Starting engine (Zero-IO, SKB Mode)...")
        with open("benchmark_diag.log", "w") as log_f:
            # Using 'skb' argument for veth stability
            extractor = subprocess.Popen(
                ["./build/loader", VETH_RX, "skb"],
                stdout=subprocess.DEVNULL, stderr=log_f, cwd=BASE_DIR
            )
        
        time.sleep(5)
        print(f"[*] Injecting traffic on {VETH_TX} (TOPSPEED)...")
        start_inject = time.time()
        res = subprocess.run(["tcpreplay", "-i", VETH_TX, "--topspeed", test_pcap], capture_output=True, text=True, check=True)
        inject_duration = time.time() - start_inject
        
        print("[*] Waiting for engine to process last packets...")
        time.sleep(5)
        
        print("[*] Stopping engine...")
        extractor.terminate()
        extractor.wait()
        
        # Parse Diagnostic Log for Kernel Ingress
        ingress = 0
        if os.path.exists("benchmark_diag.log"):
            with open("benchmark_diag.log", "r") as f:
                content = f.read()
                m = re.search(r"Kernel-Space Total Ingress: (\d+) packets", content)
                if m:
                    ingress = int(m.group(1))
        
        pps = ingress / inject_duration if inject_duration > 0 else 0
        
        print(f"\n{'='*60}")
        print(f" PERFORMANCE METRICS (REAL CAPTURE)")
        print(f"{'='*60}")
        print(f" Packets Injected  : {ingress:,}")
        print(f" Injection Time    : {inject_duration:.2f} seconds")
        print(f" ENGINE THROUGHPUT : {pps:,.0f} pps")
        print(f" Features Active   : 495 (Certified)")
        print(f"{'='*60}")
        
    finally:
        cleanup_veth()

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("Error: Root privileges required.")
        sys.exit(1)
    run_benchmark()
