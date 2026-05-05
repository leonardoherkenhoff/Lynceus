#!/usr/bin/env python3
"""
Lynceus Full-Stack Validation (Extraction + Writing)
------------------------------------------------------------------------
Utilizes a VETH pair to bypass physical NIC loopback limitations.
Proves that the Data Plane extracts features and the Control Plane
writes them to a CSV file.
"""

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
    print(f"[*] Creating Virtual Topology: {VETH_TX} <-> {VETH_RX}")
    subprocess.run(["ip", "link", "del", VETH_TX], check=False, stderr=subprocess.DEVNULL)
    subprocess.run(["ip", "link", "add", VETH_TX, "type", "veth", "peer", "name", VETH_RX], check=True)
    subprocess.run(["ip", "link", "set", VETH_TX, "up"], check=True)
    subprocess.run(["ip", "link", "set", VETH_RX, "up"], check=True)
    # Disable offloads on virtual interface for consistency
    subprocess.run(["ethtool", "-K", VETH_RX, "lro", "off", "gro", "off"], check=False)

def cleanup_veth():
    print(f"[*] Cleaning up Virtual Topology...")
    subprocess.run(["ip", "link", "del", VETH_TX], check=False)

def run_test():
    print("=== Lynceus Extraction & Write Validation ===")
    
    if not os.path.exists(os.path.join(BASE_DIR, "build/loader")):
        print("[*] Compiling binaries...")
        subprocess.run("make clean && make", shell=True, check=True, cwd=BASE_DIR)
    
    setup_veth()
    
    pcaps = sorted(glob.glob(os.path.join(DATA_RAW, "**", "*.pcap*"), recursive=True))
    if not pcaps:
        print("Error: No PCAP files found.")
        cleanup_veth()
        return
    
    pcap_to_test = pcaps[0]
    
    try:
        print(f"[*] Starting engine (Output: {OUT_CSV})...")
        with open(OUT_CSV, "w") as out_f, open("validation.log", "w") as log_f:
            extractor = subprocess.Popen(
                ["./build/loader", VETH_RX],
                stdout=out_f, stderr=log_f, cwd=BASE_DIR
            )
        
        time.sleep(2)
        print(f"[*] Injecting traffic on {VETH_TX}...")
        subprocess.run(["tcpreplay", "-i", VETH_TX, "--topspeed", pcap_to_test], check=True)
        
        print("[*] Waiting for RingBuffer and Disk Flush...")
        time.sleep(3)
        
        print("[*] Stopping engine...")
        extractor.terminate()
        extractor.wait()
        
        if os.path.exists(OUT_CSV) and os.path.getsize(OUT_CSV) > 1024:
            print(f"[+] Success: {OUT_CSV} generated ({os.path.getsize(OUT_CSV)} bytes).")
            # Call the schema validator
            subprocess.run(["python3", "scripts/validate_schema.py", OUT_CSV], check=False)
        else:
            print("[!] Error: No data written to CSV.")
            print("[*] Diagnostic Log:")
            subprocess.run(["cat", "validation.log"], check=False)
            
    finally:
        cleanup_veth()

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("Error: Root privileges required.")
        sys.exit(1)
    run_test()
