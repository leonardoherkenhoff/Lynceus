#!/usr/bin/env python3
import subprocess
import time
import os
import glob
import sys

BASE_DIR = "/opt/eBPFNetFlowLyzer"
DATA_RAW = os.path.join(BASE_DIR, "data/raw/PCAP")
VETH_TX = "veth_tx"
VETH_RX = "veth_rx"
OUT_CSV = "validation_output.csv"

def setup_veth():
    print(f"[*] Creating Virtual Topology: {VETH_TX} <-> {VETH_RX} (MTU 9000)")
    subprocess.run(["ip", "link", "del", VETH_TX], check=False, stderr=subprocess.DEVNULL)
    subprocess.run(["ip", "link", "add", VETH_TX, "type", "veth", "peer", "name", VETH_RX], check=True)
    subprocess.run(["ip", "link", "set", VETH_TX, "mtu", "9000"], check=True)
    subprocess.run(["ip", "link", "set", VETH_RX, "mtu", "9000"], check=True)
    subprocess.run(["ip", "link", "set", VETH_TX, "up"], check=True)
    subprocess.run(["ip", "link", "set", VETH_RX, "up"], check=True)

def cleanup_veth():
    print(f"[*] Cleaning up Virtual Topology...")
    subprocess.run(["ip", "link", "del", VETH_TX], check=False)

def run_test():
    print("=== Lynceus Extraction & Write Validation ===")
    
    if not os.path.exists(os.path.join(BASE_DIR, "build/loader")):
        print("[*] Compiling binaries...")
        subprocess.run("make clean && make", shell=True, check=True, stdout=subprocess.DEVNULL, cwd=BASE_DIR)
    
    setup_veth()
    
    pcaps = sorted(glob.glob(os.path.join(DATA_RAW, "**", "*.pcap*"), recursive=True))
    if not pcaps:
        print("Error: No PCAP files found.")
        cleanup_veth()
        return
    
    pcap_to_test = pcaps[0]
    
    try:
        print(f"[*] Starting engine (Output: {OUT_CSV})...")
        env = os.environ.copy()
        env["LYNCEUS_FORCE_SKB"] = "1"
        
        with open(OUT_CSV, "w") as out_f, open("validation.log", "w") as log_f:
            extractor = subprocess.Popen(
                ["./build/loader", VETH_RX],
                stdout=out_f, stderr=log_f, cwd=BASE_DIR, env=env
            )
        
        time.sleep(5)
        print(f"[*] Injecting traffic on {VETH_TX} (TOPSPEED)...")
        subprocess.run(["tcpreplay", "-i", VETH_TX, "--topspeed", pcap_to_test], check=True)
        
        print("[*] Waiting for RingBuffer and Disk Flush (10s)...")
        time.sleep(10)
        
        print("[*] Stopping engine...")
        extractor.terminate()
        extractor.wait()
        
        print(f"\n[*] Diagnostic Log (validation.log):")
        subprocess.run(["cat", "validation.log"], check=False)
        
        if os.path.exists(OUT_CSV) and os.path.getsize(OUT_CSV) > 6000:
            print(f"[+] Success: {OUT_CSV} generated ({os.path.getsize(OUT_CSV)} bytes).")
            subprocess.run(["python3", "scripts/validate_schema.py", OUT_CSV], check=False)
        else:
            print(f"[!] Error: File too small ({os.path.getsize(OUT_CSV)} bytes). Check for drops.")
            
    finally:
        cleanup_veth()

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("Error: Root privileges required.")
        sys.exit(1)
    run_test()
