#!/usr/bin/env python3
"""
Lynceus Empirical Validation Pipeline - NetFlowLyzer Parity Orchestrator
------------------------------------------------------------------------
Scientific Milestone: Comparative Architecture Validation (SBSeg)

Research Objective:
    Automates the isolated benchmarking of the Lynceus eBPF engine under
    semantic parity constraints against NTLFlowLyzer and ALFlowLyzer.
    Compiles under -DPARITY_NETFLOWLYZER to suppress histogram bins and
    tunnel metadata. IPv4-only injection (legacy tools lack IPv6 support).

    Extraction is performed **per attack vector directory**, matching the
    methodology of the original ``ebpf_wrapper.py`` pipeline. Each attack
    gets its own Lynceus instance, CSV output, resource profiling, and
    ground-truth labeling.

Pipeline (per attack directory):
    1. Virtual Topology: Instantiates VETH pair (Injector -> Sensor).
    2. Engine Ignition: Spawns the Lynceus daemon, stdout -> per-attack CSV.
    3. Resource Profiling: Captures CPU/Memory via ``scripts/testbed/monitor.py``.
    4. Volumetric Injection: Replays PCAPs from a single attack directory.
    5. Graceful Termination: Synchronizes engine buffers and exports summary.json.
    6. Ground-Truth Labeling: Invokes ``ebpf_labeler.py`` on the per-attack output.

Post-Extraction:
    7. ML Analysis: Invokes ``ebpf_run_benchmark.py`` over the full labeled tree.
"""

import subprocess
import time
import os
import glob
import re
import json

# --- Project Path Matrix ---
BASE_DIR = "/opt/eBPFNetFlowLyzer"
DATA_RAW = os.path.join(BASE_DIR, "data/raw")
DATA_INTERIM = os.path.join(BASE_DIR, "data/interim/EBPF_RAW")
LABELER_SCRIPT = os.path.join(BASE_DIR, "scripts/preprocessing/ebpf_labeler.py")
ML_SCRIPT = os.path.join(BASE_DIR, "scripts/analysis/ebpf_run_benchmark.py")

# --- Topology Vectors ---
INJECT_IFACE = "veth0"
SENSOR_IFACE = "veth1"

# --- Engine Namespace ---
ENGINE_NAME = "Lynceus_Parity_NetFlowLyzer"

# --- PCAP Categories (IPv4-only: legacy tools lack IPv6 support) ---
PCAP_CATEGORIES = ["PCAP"]


def setup_veth():
    """
    Instantiate the isolated virtual network stack.

    Creates a VETH pair (veth0 <-> veth1), brings both interfaces up,
    and ensures IPv6 is enabled for structural integrity.
    """
    subprocess.run(["ip", "link", "delete", INJECT_IFACE], check=False, stderr=subprocess.DEVNULL)
    subprocess.run(["ip", "link", "add", INJECT_IFACE, "type", "veth", "peer", "name", SENSOR_IFACE], check=True)
    subprocess.run(["ip", "link", "set", INJECT_IFACE, "up"], check=True)
    subprocess.run(["ip", "link", "set", SENSOR_IFACE, "up"], check=True)
    subprocess.run(["sysctl", "-w", f"net.ipv6.conf.{INJECT_IFACE}.disable_ipv6=0"],
                   check=False, stderr=subprocess.DEVNULL)
    subprocess.run(["sysctl", "-w", f"net.ipv6.conf.{SENSOR_IFACE}.disable_ipv6=0"],
                   check=False, stderr=subprocess.DEVNULL)


def teardown_veth():
    """Destroy the virtual topology to prevent MAC/MTU state leakage."""
    subprocess.run(["ip", "link", "delete", INJECT_IFACE], check=False, stderr=subprocess.DEVNULL)


def get_attack_dirs():
    """
    Discover per-attack PCAP directories from the raw dataset.

    Each subdirectory under PCAP/{day}/ represents a single attack vector
    (e.g., PCAP/01-12/DrDoS_DNS/). Returns a sorted list of (category,
    attack_dir) tuples for deterministic execution order.

    Returns:
        list: Sorted list of (category, absolute_pcap_dir) tuples.
    """
    attack_dirs = []
    for category in PCAP_CATEGORIES:
        cat_path = os.path.join(DATA_RAW, category)
        if not os.path.exists(cat_path):
            continue
        pcap_files = glob.glob(os.path.join(cat_path, "**", "*.pcap*"), recursive=True)
        unique_dirs = sorted(set(os.path.dirname(p) for p in pcap_files))
        for d in unique_dirs:
            attack_dirs.append((category, d))
    return attack_dirs


def extract_attack(category, pcap_dir):
    """
    Execute a single-attack extraction cycle.

    Spawns a fresh Lynceus instance per attack directory, producing an isolated
    CSV, resource metrics, and performance summary.

    Args:
        category (str): PCAP category ('PCAP' or 'PCAPv6').
        pcap_dir (str): Absolute path to the attack directory containing PCAPs.

    Returns:
        dict: Summary with packets, elapsed time, PPS, and output directory.
    """
    rel_path = os.path.relpath(pcap_dir, os.path.join(DATA_RAW, category))
    output_dir = os.path.join(DATA_INTERIM, ENGINE_NAME, category, rel_path)
    os.makedirs(output_dir, exist_ok=True)

    experiment_name = f"{category}/{rel_path}"
    csv_out_path = os.path.join(output_dir, "flows.csv")
    metrics_csv = os.path.join(output_dir, "resource_metrics.csv")

    pcaps = sorted(glob.glob(os.path.join(pcap_dir, "*.pcap*")))
    if not pcaps:
        return None

    print(f"\n  🚀 EXTRACTION: {experiment_name}")

    # --- Step 1: Virtual Topology ---
    setup_veth()

    try:
        # --- Step 2: Engine Ignition ---
        f_csv = open(csv_out_path, 'w')
        extractor = subprocess.Popen(
            ["./build/loader", SENSOR_IFACE],
            stdout=f_csv, stderr=subprocess.DEVNULL, cwd=BASE_DIR
        )
        time.sleep(3)  # BPF map allocation stabilization

        # --- Step 3: Resource Profiling ---
        proc_mon = None
        monitor_script = os.path.join(BASE_DIR, "scripts/testbed/monitor.py")
        if os.path.exists(monitor_script):
            proc_mon = subprocess.Popen(
                ["python3", monitor_script, str(extractor.pid), metrics_csv],
                cwd=BASE_DIR
            )

        # --- Step 4: Traffic Injection ---
        total_packets = 0
        start_time = time.time()
        for p in pcaps:
            cmd = f"tcpreplay -i {INJECT_IFACE} --topspeed {p} 2>&1"
            try:
                res = subprocess.run(cmd, shell=True, capture_output=True, text=True, check=True)
                matches = re.findall(r"(\d+)\s+packets", res.stdout)
                if matches:
                    total_packets += int(matches[0])
            except subprocess.CalledProcessError as e:
                print(f"     [!] Injection Error: {e.stderr[:200]}")

        elapsed = time.time() - start_time
        pps = total_packets / elapsed if elapsed > 0 else 0

        # --- Step 5: Graceful Termination ---
        if proc_mon:
            proc_mon.terminate()
            proc_mon.wait()

        time.sleep(2)  # Buffer flush
        extractor.terminate()
        try:
            extractor.wait(timeout=10)
        except subprocess.TimeoutExpired:
            subprocess.run(["kill", "-9", str(extractor.pid)], check=False)

        f_csv.flush()
        os.fsync(f_csv.fileno())
        f_csv.close()

    finally:
        teardown_veth()

    # --- Step 6: Per-Attack Labeling ---
    print(f"     🏷️  Labeling {experiment_name}...")
    subprocess.run(
        ["python3", LABELER_SCRIPT, "--path", output_dir, "--cleanup"],
        check=False, cwd=BASE_DIR
    )

    # Persist summary
    summary = {
        "experiment": experiment_name, "engine": ENGINE_NAME,
        "packets_sent": total_packets, "time_seconds": round(elapsed, 2),
        "pps": round(pps, 2), "timestamp": time.ctime()
    }
    with open(os.path.join(output_dir, "summary.json"), 'w') as f:
        json.dump(summary, f, indent=4)

    print(f"     ✅ {total_packets:,} pkts | {elapsed:.1f}s | {pps:.0f} pps")
    return summary


def main():
    """
    Main orchestration entry point.

    Compiles once under -DPARITY_NETFLOWLYZER, then iterates over every
    attack directory, extracting per-attack telemetry. After all extractions,
    invokes the ML benchmark on the complete labeled tree.
    """
    print("=== Lynceus eBPF Benchmark Pipeline (NetFlowLyzer Parity) ===")
    if os.geteuid() != 0:
        print("FATAL: Root privileges required (BPF/XDP).")
        exit(1)

    attack_dirs = get_attack_dirs()
    if not attack_dirs:
        print("FATAL: No PCAP directories found in", DATA_RAW)
        exit(1)

    print(f"[*] Discovered {len(attack_dirs)} attack vectors.")

    # --- One-time Parity Compilation ---
    print("[1/3] Compiling Lynceus under -DPARITY_NETFLOWLYZER...")
    compilation_cmd = (
        "make clean && make "
        "CFLAGS='-g -O2 -Wall -Wextra -std=gnu11 -DPARITY_NETFLOWLYZER' "
        "BPF_CFLAGS='-g -O2 -target bpf -D__TARGET_ARCH_x86 -Isrc/ebpf "
        "-Wall -Wno-missing-declarations -Wno-compare-distinct-pointer-types "
        "-DPARITY_NETFLOWLYZER'"
    )
    subprocess.run(compilation_cmd, shell=True, check=True, stdout=subprocess.DEVNULL, cwd=BASE_DIR)

    # --- Per-Attack Extraction ---
    print(f"\n[2/3] Extracting {len(attack_dirs)} attack vectors...")
    summaries = []
    for category, pcap_dir in attack_dirs:
        result = extract_attack(category, pcap_dir)
        if result:
            summaries.append(result)

    # --- Global ML Analysis ---
    engine_processed = os.path.join(BASE_DIR, "data/processed/EBPF", ENGINE_NAME)
    if os.path.exists(engine_processed):
        print(f"\n[3/3] Executing Random Forest Analysis (SBSeg Parity)...")
        subprocess.run(
            ["python3", ML_SCRIPT, "--dataset", engine_processed],
            check=False, cwd=BASE_DIR
        )
    else:
        print(f"\n[3/3] ⚠️  No labeled data found at {engine_processed}")

    # --- Aggregate Report ---
    total_pkts = sum(s["packets_sent"] for s in summaries)
    total_time = sum(s["time_seconds"] for s in summaries)
    print(f"\n{'='*60}")
    print(f"  AGGREGATE: {len(summaries)} attacks | {total_pkts:,} pkts | {total_time:.1f}s")
    print(f"{'='*60}")
    print("\n[✔] NetFlowLyzer Parity Assessment Concluded.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n⚠️  Interrupted.")
        teardown_veth()
