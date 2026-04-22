#!/usr/bin/env python3
"""
Lynceus Research Pipeline - Network Topology Virtualization & Extraction (v1.0)
-----------------------------------------------------------
Scientific Milestone: v1.0 (The Definitive Foundation)

Research Objective:
Orchestrates the high-fidelity extraction of network features by simulating 
topological environments (VETH) and ingesting raw traffic (PCAP).

Architecture:
1. Topology Creation: Instantiates virtual ethernet pairs (veth0/veth1).
2. Engine Ignition: Spawns the Lynceus loader with stdout-to-pipe redirection.
3. Traffic Injection: Replays PCAP artifacts via tcpreplay into the virtual stack.
4. Telemetry Capture: Asynchronous collection of CSV streams from the engine.
"""

import subprocess
import os
import time
import glob
import json
import threading
import shutil
import re

# --- Project Path Matrix ---
BASE_DIR = "/opt/eBPFNetFlowLyzer"
DATA_RAW = os.path.join(BASE_DIR, "data/raw")
DATA_INTERIM = os.path.join(BASE_DIR, "data/interim/EBPF_RAW")
LOADER_BIN = os.path.join(BASE_DIR, "build/loader")
LABELER_SCRIPT = os.path.join(BASE_DIR, "scripts/preprocessing/ebpf_labeler.py")

# Logical execution order for experimental categories.
EXPERIMENT_ORDER = ["PCAPv6", "PCAP"]

def process_pcap_dir(pcap_dir, category):
    """
    Orchestrates the telemetric extraction of a specific experimental category.
    """
    rel_path = os.path.relpath(pcap_dir, os.path.join(DATA_RAW, category))
    output_dir = os.path.normpath(os.path.join(DATA_INTERIM, category, rel_path))
    os.makedirs(output_dir, exist_ok=True)
    
    pcaps = glob.glob(os.path.join(pcap_dir, "*.pcap*"))
    if not pcaps: return
    
    metrics_csv = os.path.join(output_dir, "resource_metrics.csv")
    experiment_name = f"{category}/{rel_path}"

    print(f"\n🚀 EXTRACTION INITIATED: {experiment_name}")
    
    # --- Step 1: Virtual Network Stack Initialization ---
    subprocess.run(["ip", "link", "delete", "veth0"], check=False, stderr=subprocess.DEVNULL)
    subprocess.run(["ip", "link", "add", "veth0", "type", "veth", "peer", "name", "veth1"], check=True)
    subprocess.run(["ip", "link", "set", "veth0", "up"], check=True)
    subprocess.run(["ip", "link", "set", "veth1", "up"], check=True)
    
    # Kernel-level forwarding and dual-stack (v4/v6) enabling.
    subprocess.run(["sysctl", "-w", "net.ipv6.conf.veth0.disable_ipv6=0"], check=False)
    subprocess.run(["sysctl", "-w", "net.ipv6.conf.veth1.disable_ipv6=0"], check=False)
    subprocess.run(["sysctl", "-w", "net.ipv6.conf.all.forwarding=1"], check=False)

    try:
        # --- Step 2: Telemetry Engine Ignition ---
        loader_log_path = os.path.join(output_dir, "loader_stderr.log")
        csv_output_path = os.path.join(output_dir, "flows.csv")
        
        # Agnostic Output: Capture engine stdout stream directly to the interim directory.
        f_csv = open(csv_output_path, 'w')
        proc_loader = subprocess.Popen(
            [LOADER_BIN, "veth1"], 
            stdout=f_csv, 
            stderr=subprocess.PIPE,
            text=True,
            cwd=BASE_DIR
        )
        
        def stream_logs(proc, log_file_path):
            """Internal monitor for engine diagnostic output."""
            try:
                with open(log_file_path, 'w') as f_log:
                    for line in iter(proc.stderr.readline, ""):
                        if not line: break
                        f_log.write(line)
                        f_log.flush()
                        print(f"   [Engine] {line.strip()}")
            except Exception: pass
        
        log_thread = threading.Thread(target=stream_logs, args=(proc_loader, loader_log_path), daemon=True)
        log_thread.start()
        time.sleep(5) 
        
        # --- Step 3: Stochastic Resource Profiling ---
        monitor_script = "scripts/testbed/monitor.py"
        proc_mon = None
        if os.path.exists(monitor_script):
            proc_mon = subprocess.Popen(["python3", monitor_script, str(proc_loader.pid), metrics_csv])
        
        # --- Step 4: Experimental Traffic Injection ---
        total_packets = 0
        start_time = time.time()
        for p in pcaps:
            print(f"   Streaming: {os.path.basename(p)}")
            cmd = f"tcpreplay -i veth0 -t {p} 2>&1"
            try:
                res = subprocess.run(cmd, shell=True, capture_output=True, text=True, check=True)
                matches = re.findall(r"(\d+)\s+packets", res.stdout)
                if matches: total_packets += int(matches[0])
            except subprocess.CalledProcessError as e:
                print(f"   ❌ Injection Error: {e.stderr}")

        elapsed = time.time() - start_time
        pps = total_packets / elapsed if elapsed > 0 else 0
        
        # --- Step 5: Graceful Termination & Synchronization ---
        print("   🛑 Synchronizing Engine Buffers...")
        if proc_mon:
            proc_mon.terminate()
            proc_mon.wait()
        
        subprocess.run(["kill", "-INT", str(proc_loader.pid)], check=False)
        try: proc_loader.wait(timeout=300)
        except subprocess.TimeoutExpired:
            subprocess.run(["kill", "-9", str(proc_loader.pid)], check=False)
            
        log_thread.join(timeout=10)

        # --- Step 6: Telemetry Formalization ---
        f_csv.flush()
        os.fsync(f_csv.fileno())
        f_csv.close()
        print(f"   📂 Telemetry formalized in {os.path.basename(csv_output_path)}")
        
        # Iterative Attribute Labeling (Ground Truth).
        print(f"   🏷️  Attributing Ground Truth for {experiment_name}...")
        label_cmd = f"python3 {LABELER_SCRIPT} --path {output_dir} --cleanup"
        subprocess.run(label_cmd, shell=True, check=False)
            
    finally:
        subprocess.run(["ip", "link", "delete", "veth0"], check=False, stderr=subprocess.DEVNULL)
    
    summary = {
        "experiment": experiment_name, "packets_sent": total_packets,
        "time_seconds": elapsed, "pps": pps, "timestamp": time.ctime()
    }
    with open(os.path.join(output_dir, "summary.json"), 'w') as f:
        json.dump(summary, f, indent=4)
        
    print(f"✅ DONE: {total_packets} pkts | {elapsed:.2f}s | {pps:.2f} pps [Lynceus Engine]")

def main():
    """Main orchestrator for the Feature Extraction phase."""
    print("=== Lynceus Telemetry Engine: High-Resolution Extraction Wrapper ===")
    if not os.path.exists(LOADER_BIN):
        print(f"❌ Error: {LOADER_BIN} not found. Invoke toolchain build.")
        return

    for category in EXPERIMENT_ORDER:
        category_path = os.path.join(DATA_RAW, category)
        if not os.path.exists(category_path): continue
        pcap_files = glob.glob(os.path.join(category_path, "**", "*.pcap*"), recursive=True)
        pcap_dirs = sorted(list(set(os.path.dirname(p) for p in pcap_files)))
        if not pcap_dirs and (glob.glob(os.path.join(category_path, "*.pcap*"))):
             pcap_dirs = [category_path]
        for pcap_dir in pcap_dirs:
            process_pcap_dir(pcap_dir, category)

if __name__ == "__main__":
    try: main()
    except KeyboardInterrupt: print("\n⚠️  Interrupted.")
