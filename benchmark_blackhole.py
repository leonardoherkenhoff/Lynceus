#!/usr/bin/env python3
"""
Zero-IO Performance Benchmark
------------------------------------------------------------------------
Measures raw computational throughput of the eBPF data plane and 
user-space serialization by redirecting output to /dev/null.
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

def setup_nic():
    print(f"[*] Configuring hardware: {INJECT_IFACE}")
    subprocess.run(["bash", "scripts/fix_nic_xdp.sh", INJECT_IFACE], check=False)
    subprocess.run(["ip", "link", "set", INJECT_IFACE, "up"], check=False)
    subprocess.run(["ip", "link", "set", INJECT_IFACE, "promisc", "on"], check=False)

def teardown_nic():
    pass

def run_benchmark():
    print("=== eBPF Zero-IO Performance Benchmark ===")
    
    print("[*] Compiling binaries...")
    subprocess.run("make clean && make", shell=True, check=True, stdout=subprocess.DEVNULL, cwd=BASE_DIR)
    
    setup_nic()
    
    pcaps = sorted(glob.glob(os.path.join(DATA_RAW, "**", "*.pcap*"), recursive=True))
    if not pcaps:
        print("Error: No PCAP files found.")
        return
    
    test_pcaps = pcaps[:3]
    
    try:
        print("[*] Starting engine...")
        with open("extractor.log", "w") as log_f:
            extractor = subprocess.Popen(
                ["./build/loader", SENSOR_IFACE],
                stdout=subprocess.DEVNULL, stderr=log_f, cwd=BASE_DIR
            )
        time.sleep(3)
        
        total_packets = 0
        start_time = time.time()
        
        for p in test_pcaps:
            print(f"     -> Processing: {os.path.basename(p)}")
            cmd = f"tcpreplay -i {INJECT_IFACE} --topspeed {p} 2>&1"
            res = subprocess.run(cmd, shell=True, capture_output=True, text=True, check=False)
            matches = re.findall(r"(\d+)\s+packets", res.stdout)
            if matches:
                total_packets += int(matches[0])
                
        elapsed = time.time() - start_time
        pps = total_packets / elapsed if elapsed > 0 else 0
        
        print("[*] Stopping engine...")
        extractor.terminate()
        extractor.wait()
        
        print(f"\n{'='*60}")
        print(f" PERFORMANCE METRICS")
        print(f"{'='*60}")
        print(f" Packets Processed : {total_packets:,}")
        print(f" Time Elapsed      : {elapsed:.2f} seconds")
        print(f" Maximum Throughput: {pps:,.0f} pps")
        print(f"{'='*60}")
        
        print(f"\n[*] Diagnostic Log:")
        subprocess.run(["cat", "extractor.log"], check=False)
        
    finally:
        teardown_nic()

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("Error: Root privileges required.")
        exit(1)
    run_benchmark()
