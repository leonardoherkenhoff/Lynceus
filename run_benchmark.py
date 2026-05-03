#!/usr/bin/env python3
"""
Lynceus Empirical Validation Pipeline - Parity Benchmark Orchestrator
-----------------------------------------------------------
Scientific Milestone: Comparative Architecture Validation (SBSeg)

Research Objective:
Automates the isolated benchmarking of eBPF telemetry engines under strict 
architectural parity constraints. It forces equivalent algorithmic complexity 
between Lynceus and the comparative baselines by ensuring exact L3/L4/L7 
feature extraction boundaries (Semantic Isolation).

Architecture:
1. Virtual Topology: Instantiates unidirectional VETH links (Injector -> Sensor).
2. Engine Constrainment: Compiles the eBPF Data Plane under PARITY_NETFLOWLYZER.
3. Volumetric Injection: Replays CICDDoS2019 artifacts at wire-speed via tcpreplay.
4. Preprocessing: Invokes `ebpf_labeler.py` to ground-truth the raw CSV streams.
5. Machine Learning: Invokes `ebpf_run_benchmark.py` to measure F1-Score/Accuracy.
"""

import subprocess
import time
import os
import glob
import re

# --- Project Path Matrix ---
BASE_DIR = "/opt/eBPFNetFlowLyzer"
DATA_RAW = os.path.join(BASE_DIR, "data/raw")
DATA_INTERIM = os.path.join(BASE_DIR, "data/interim/EBPF_RAW")
LABELER_SCRIPT = os.path.join(BASE_DIR, "scripts/preprocessing/ebpf_labeler.py")
ML_SCRIPT = os.path.join(BASE_DIR, "scripts/analysis/ebpf_run_benchmark.py")

# --- Topology Vectors ---
INJECT_IFACE = "veth0"
SENSOR_IFACE = "veth1"

def setup_veth():
    """
    Instantiates the virtual network stack. Establishes the bounded 
    L2 forwarding path and ensures IPv6 structural integrity.
    """
    subprocess.run(["ip", "link", "delete", INJECT_IFACE], check=False, stderr=subprocess.DEVNULL)
    subprocess.run(["ip", "link", "add", INJECT_IFACE, "type", "veth", "peer", "name", SENSOR_IFACE], check=True)
    subprocess.run(["ip", "link", "set", INJECT_IFACE, "up"], check=True)
    subprocess.run(["ip", "link", "set", SENSOR_IFACE, "up"], check=True)
    subprocess.run(["sysctl", "-w", f"net.ipv6.conf.{INJECT_IFACE}.disable_ipv6=0"], check=False, stderr=subprocess.DEVNULL)
    subprocess.run(["sysctl", "-w", f"net.ipv6.conf.{SENSOR_IFACE}.disable_ipv6=0"], check=False, stderr=subprocess.DEVNULL)

def teardown_veth():
    """Destroys the virtual topology to prevent MAC/MTU state leakage."""
    subprocess.run(["ip", "link", "delete", INJECT_IFACE], check=False, stderr=subprocess.DEVNULL)

def get_pcaps():
    """
    Dynamically scans the primary empirical datasets for traffic artifacts.
    Returns sorted lists to guarantee temporal determinism during extraction.
    """
    pcaps = []
    for category in ["PCAP", "PCAPv6"]:
        path = os.path.join(DATA_RAW, category)
        if os.path.exists(path):
            pcaps.extend(glob.glob(os.path.join(path, "**", "*.pcap*"), recursive=True))
    return sorted(pcaps)

def run_experiment():
    """
    Orchestrates the lifecycle of an empirical extraction boundary.
    Coordinates compilation, topology setup, traffic replay, and ML analysis.
    """
    print("\n[+] EXTRACTION INITIATED: Lynceus Parity NetFlowLyzer (Semantic Isolation)")
    
    # --- Step 1: Geometric Compilation ---
    print("    -> Anchoring Parity Topology in Kernel Space (-DPARITY_NETFLOWLYZER)...")
    compilation_cmd = (
        "make clean && make "
        "CFLAGS='-g -O2 -Wall -Wextra -std=gnu11 -DPARITY_NETFLOWLYZER' "
        "BPF_CFLAGS='-g -O2 -target bpf -D__TARGET_ARCH_x86 -Isrc/ebpf "
        "-Wall -Wno-missing-declarations -Wno-compare-distinct-pointer-types -DPARITY_NETFLOWLYZER'"
    )
    subprocess.run(compilation_cmd, shell=True, check=True, stdout=subprocess.DEVNULL, cwd=BASE_DIR)
    
    setup_veth()
    
    # Generate unified CSV in a dedicated directory
    parity_out_dir = os.path.join(DATA_INTERIM, "Parity_NetFlowLyzer")
    os.makedirs(parity_out_dir, exist_ok=True)
    csv_out_path = os.path.join(parity_out_dir, "flows.csv")
    
    pcaps = get_pcaps()
    
    # --- Step 2: Telemetry Engine Ignition ---
    print("    -> Spawning Observer Daemon...")
    with open(csv_out_path, 'w') as f_csv:
        extractor = subprocess.Popen(["./build/loader", SENSOR_IFACE], stdout=f_csv, stderr=subprocess.DEVNULL, cwd=BASE_DIR)
        time.sleep(3) # BPF map allocation stabilization
        
        total_packets = 0
        start_time = time.time()
        
        # --- Step 3: Wire-Speed Volumetric Injection ---
        for p in pcaps:
            print(f"    -> Streaming Artifact: {os.path.basename(p)}...")
            cmd = f"tcpreplay -i {INJECT_IFACE} --topspeed {p} 2>&1"
            try:
                res = subprocess.run(cmd, shell=True, capture_output=True, text=True, check=True)
                matches = re.findall(r"(\d+)\s+packets", res.stdout)
                if matches: total_packets += int(matches[0])
            except subprocess.CalledProcessError as e:
                print(f"   [!] Injection Critical Error: {e.stderr}")
                
        elapsed = time.time() - start_time
        pps = total_packets / elapsed if elapsed > 0 else 0
        
        # --- Step 4: Graceful Termination & Cooldown ---
        time.sleep(2) # Memory buffer flush timeout
        extractor.terminate()
        try:
            extractor.wait(timeout=10)
        except:
            subprocess.run(["kill", "-9", str(extractor.pid)], check=False)
            
    teardown_veth()
    print(f"[=] EXTRACTION COMPLETED: {total_packets} pkts | {elapsed:.2f}s | {pps:.2f} pps")
    
    # --- Step 5: Data Preprocessing (Labeling) ---
    print("    -> Initiating Ground-Truth Labeling Pipeline...")
    subprocess.run(["python3", LABELER_SCRIPT, "--path", parity_out_dir, "--cleanup"], check=True, cwd=BASE_DIR)
    
    # --- Step 6: Machine Learning Analysis ---
    print("    -> Executing Random Forest Analysis (SBSeg Parity Benchmark)...")
    subprocess.run(["python3", ML_SCRIPT, "--dataset", parity_out_dir], check=False, cwd=BASE_DIR)

if __name__ == "__main__":
    print("=== Lynceus eBPF Benchmark Pipeline (NetFlowLyzer Parity) ===")
    if not os.geteuid() == 0:
        print("FATAL: Methodological extraction mandates Root privileges (BPF bounds).")
        exit(1)
        
    pcaps = get_pcaps()
    if not pcaps:
        print("FATAL: Empty dataset vector in", DATA_RAW)
        exit(1)
        
    run_experiment()
    print("\n[✔] Structural Assessment Concluded.")
