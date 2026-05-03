#!/usr/bin/env python3
"""
Lynceus Empirical Validation Pipeline - RustiFlow Parity Orchestrator
---------------------------------------------------------------------
Scientific Milestone: Comparative Architecture Validation (SBSeg)

Research Objective:
    Automates the isolated benchmarking of eBPF telemetry engines under strict
    architectural parity constraints against the RustiFlow Rust-based baseline.
    Dual-stack injection (IPv4 + IPv6), as RustiFlow supports full IPv6 parsing.

Pipeline:
    1. Virtual Topology: Instantiates unidirectional VETH links (Injector -> Sensor).
    2. Engine Constrainment: Compiles the eBPF Data Plane under -DPARITY_RUSTIFLOW.
    3. Volumetric Injection: Replays CICDDoS2019 artifacts at wire-speed via tcpreplay.
    4. Resource Profiling: Captures CPU/Memory via ``scripts/testbed/monitor.py``.
    5. Ground-Truth Labeling: Invokes ``ebpf_labeler.py`` for topological attribution.
    6. ML Analysis: Invokes ``ebpf_run_benchmark.py`` for F1-Score/Accuracy measurement.
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
# Injector -> Sensor (Isolated L2 bounds)
INJECT_IFACE = "veth0"
SENSOR_IFACE = "veth1"

# --- Orthogonal Test Matrix ---
EXPERIMENTS = [
    {
        "name": "RustiFlow_203_Features",
        "cmd": ["/opt/RustiFlow/target/release/rustiflow", "-i", SENSOR_IFACE, "-f", "rustiflow"],
        "setup_cmd": None
    },
    {
        "name": "Lynceus_Parity_RustiFlow",
        "cmd": ["./build/loader", SENSOR_IFACE],
        "setup_cmd": "make clean && make CFLAGS='-g -O2 -Wall -Wextra -std=gnu11 -DPARITY_RUSTIFLOW' BPF_CFLAGS='-g -O2 -target bpf -D__TARGET_ARCH_x86 -Isrc/ebpf -Wall -Wno-missing-declarations -Wno-compare-distinct-pointer-types -DPARITY_RUSTIFLOW'"
    }
]


def setup_veth():
    """
    Instantiate the isolated virtual network stack.

    Creates a VETH pair (veth0 <-> veth1), brings both interfaces up,
    and ensures IPv6 is enabled for dual-stack forwarding integrity.
    """
    subprocess.run(["ip", "link", "delete", INJECT_IFACE], check=False, stderr=subprocess.DEVNULL)
    subprocess.run(["ip", "link", "add", INJECT_IFACE, "type", "veth", "peer", "name", SENSOR_IFACE], check=True)
    subprocess.run(["ip", "link", "set", INJECT_IFACE, "up"], check=True)
    subprocess.run(["ip", "link", "set", SENSOR_IFACE, "up"], check=True)
    subprocess.run(["sysctl", "-w", f"net.ipv6.conf.{INJECT_IFACE}.disable_ipv6=0"], check=False, stderr=subprocess.DEVNULL)
    subprocess.run(["sysctl", "-w", f"net.ipv6.conf.{SENSOR_IFACE}.disable_ipv6=0"], check=False, stderr=subprocess.DEVNULL)


def teardown_veth():
    """Destroy the virtual topology to prevent MAC/MTU state leakage."""
    subprocess.run(["ip", "link", "delete", INJECT_IFACE], check=False, stderr=subprocess.DEVNULL)


def get_pcaps():
    """
    Discover PCAP injection artifacts from the raw dataset directory.

    Scans both IPv4 and IPv6 PCAPs (RustiFlow supports full dual-stack).

    Returns:
        list: Sorted list of absolute paths to PCAP files.
    """
    pcaps = []
    for category in ["PCAP", "PCAPv6"]:
        path = os.path.join(DATA_RAW, category)
        if os.path.exists(path):
            pcaps.extend(glob.glob(os.path.join(path, "**", "*.pcap*"), recursive=True))
    return sorted(pcaps)


def run_experiment(exp, pcaps):
    """
    Orchestrate the full lifecycle of a single parity experiment.

    Coordinates compilation, VETH topology setup, traffic replay, resource
    profiling, ground-truth labeling, and Random Forest analysis.

    Args:
        exp (dict): Experiment descriptor with keys 'name', 'cmd', 'setup_cmd'.
        pcaps (list): Sorted list of PCAP file paths to replay.
    """
    print(f"\n[+] EXTRACTION INITIATED: {exp['name']}")

    # --- Step 1: Conditional Compilation & Topology Anchoring ---
    if exp["setup_cmd"]:
        print("    -> Anchoring Parity Topology in Kernel Space...")
        subprocess.run(exp["setup_cmd"], shell=True, check=True, stdout=subprocess.DEVNULL, cwd=BASE_DIR)

    setup_veth()

    # --- Step 2: Output Directory Provisioning ---
    parity_out_dir = os.path.join(DATA_INTERIM, exp["name"])
    os.makedirs(parity_out_dir, exist_ok=True)
    csv_out_path = os.path.join(parity_out_dir, "flows.csv")

    # --- Step 3: Telemetry Engine Ignition ---
    print("    -> Spawning Observer Daemon...")
    with open(csv_out_path, 'w') as f_csv:
        extractor = subprocess.Popen(exp["cmd"], stdout=f_csv, stderr=subprocess.DEVNULL, cwd=BASE_DIR)
        time.sleep(3)  # BPF map allocation stabilization

        # --- Step 4: Resource Consumption Profiling ---
        monitor_script = "scripts/testbed/monitor.py"
        metrics_csv = os.path.join(parity_out_dir, "resource_metrics.csv")
        proc_mon = None
        if os.path.exists(monitor_script):
            proc_mon = subprocess.Popen(["python3", monitor_script, str(extractor.pid), metrics_csv], cwd=BASE_DIR)

        total_packets = 0
        start_time = time.time()

        # --- Step 5: Wire-Speed Volumetric Injection ---
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

        # --- Step 6: Graceful Termination & Cooldown ---
        print("   🛑 Synchronizing Engine Buffers...")
        if proc_mon:
            proc_mon.terminate()
            proc_mon.wait()

        time.sleep(2)  # Memory buffer flush timeout
        extractor.terminate()
        try:
            extractor.wait(timeout=10)
        except:
            subprocess.run(["kill", "-9", str(extractor.pid)], check=False)

    teardown_veth()

    print(f"[=] SYNCHRONIZED: {exp['name']} Completed.")
    print(f"    Metrics: {total_packets} pkts | {elapsed:.2f}s | {pps:.2f} pps")

    import json
    summary = {
        "experiment": exp["name"], "packets_sent": total_packets,
        "time_seconds": elapsed, "pps": pps, "timestamp": time.ctime()
    }
    with open(os.path.join(parity_out_dir, "summary.json"), 'w') as f:
        json.dump(summary, f, indent=4)

    time.sleep(5)  # Thermal CPU limit and memory allocation cooldown

    # --- Step 7: Data Preprocessing (Labeling) ---
    print("    -> Initiating Ground-Truth Labeling Pipeline...")
    subprocess.run(["python3", LABELER_SCRIPT, "--path", parity_out_dir, "--cleanup"], check=True, cwd=BASE_DIR)

    # --- Step 8: Machine Learning Analysis ---
    print("    -> Executing Random Forest Analysis (SBSeg Parity Benchmark)...")
    subprocess.run(["python3", ML_SCRIPT, "--dataset", parity_out_dir], check=False, cwd=BASE_DIR)


if __name__ == "__main__":
    print("=== Lynceus eBPF Benchmark Pipeline (RustiFlow Parity) ===")
    if not os.geteuid() == 0:
        print("FATAL: Methodological extraction mandates Root privileges (BPF bounds).")
        exit(1)

    pcaps = get_pcaps()
    if not pcaps:
        print("FATAL: Empty dataset vector in", DATA_RAW)
        exit(1)

    print(f"[*] Discovery Phase: Identified {len(pcaps)} injection artifacts.")

    for exp in EXPERIMENTS:
        run_experiment(exp, pcaps)

    print("\n[✔] Structural Assessment Concluded.")
