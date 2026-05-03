#!/usr/bin/env python3
"""
Lynceus Empirical Validation Pipeline - NFX (XFAST) Parity Orchestrator
-----------------------------------------------------------------------
Scientific Milestone: Comparative Architecture Validation (SBSeg)

Research Objective:
    Automates the isolated benchmarking of eBPF telemetry engines under strict
    architectural parity constraints against the NetFeatureXtract (XFAST)
    baseline. IPv4-only injection (XFAST lacks IPv6 support).

    Extraction is performed **per attack vector directory**, matching the
    methodology of the original ``ebpf_wrapper.py`` pipeline. Each attack
    gets its own engine instance, CSV output, resource profiling, and
    ground-truth labeling.

Pipeline (per engine, per attack directory):
    1. Virtual Topology: Instantiates VETH pair (Injector -> Sensor).
    2. Engine Ignition: Spawns the engine daemon, stdout -> per-attack CSV.
    3. Resource Profiling: Captures CPU/Memory via ``scripts/testbed/monitor.py``.
    4. Volumetric Injection: Replays PCAPs from a single attack directory.
    5. Graceful Termination: Synchronizes engine buffers and exports summary.json.
    6. Ground-Truth Labeling: Invokes ``ebpf_labeler.py`` on the per-attack output.

Post-Extraction:
    7. ML Analysis: Invokes ``ebpf_run_benchmark.py`` over each engine's labeled tree.
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

# --- IPv4-only Categories (XFAST lacks IPv6 support) ---
PCAP_CATEGORIES = ["PCAP"]

# --- Orthogonal Test Matrix ---
EXPERIMENTS = [
    {
        "name": "XFAST_Adaptive_Baseline",
        "cmd": ["/opt/XFAST/ebpf/xdp_user", "-i", SENSOR_IFACE],
        "setup_cmd": None
    },
    {
        "name": "Lynceus_Parity_NFX",
        "cmd": ["./build/loader", SENSOR_IFACE],
        "setup_cmd": (
            "make clean && make "
            "CFLAGS='-g -O2 -Wall -Wextra -std=gnu11 -DPARITY_NFX' "
            "BPF_CFLAGS='-g -O2 -target bpf -D__TARGET_ARCH_x86 -Isrc/ebpf "
            "-Wall -Wno-missing-declarations -Wno-compare-distinct-pointer-types "
            "-DPARITY_NFX'"
        )
    }
]


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

    Scans only IPv4 PCAPs (XFAST does not support IPv6).

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


def extract_attack(exp, category, pcap_dir):
    """
    Execute a single-attack extraction cycle for a given engine.

    Spawns a fresh engine instance per attack directory, producing an isolated
    CSV, resource metrics, and performance summary.

    Args:
        exp (dict): Engine descriptor with keys 'name', 'cmd'.
        category (str): PCAP category ('PCAP').
        pcap_dir (str): Absolute path to the attack directory containing PCAPs.

    Returns:
        dict or None: Summary with packets, elapsed time, PPS, and output dir.
    """
    rel_path = os.path.relpath(pcap_dir, os.path.join(DATA_RAW, category))
    output_dir = os.path.join(DATA_INTERIM, exp["name"], category, rel_path)
    os.makedirs(output_dir, exist_ok=True)

    experiment_name = f"{category}/{rel_path}"
    csv_out_path = os.path.join(output_dir, "flows.csv")
    metrics_csv = os.path.join(output_dir, "resource_metrics.csv")

    pcaps = sorted(glob.glob(os.path.join(pcap_dir, "*.pcap*")))
    if not pcaps:
        return None

    print(f"\n  🚀 [{exp['name']}] {experiment_name}")

    # --- Step 1: Virtual Topology ---
    setup_veth()

    try:
        # --- Step 2: Engine Ignition ---
        f_csv = open(csv_out_path, 'w')
        extractor = subprocess.Popen(
            exp["cmd"], stdout=f_csv, stderr=subprocess.DEVNULL, cwd=BASE_DIR
        )
        time.sleep(3)  # BPF map / engine allocation stabilization

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
        "experiment": experiment_name, "engine": exp["name"],
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

    Iterates over the engine matrix (XFAST, then Lynceus parity).
    For each engine, iterates over every attack directory, extracting
    per-attack telemetry. After each engine completes, invokes ML analysis.
    """
    print("=== Lynceus eBPF Benchmark Pipeline (NFX/XFAST Parity) ===")
    if os.geteuid() != 0:
        print("FATAL: Root privileges required (BPF/XDP).")
        exit(1)

    attack_dirs = get_attack_dirs()
    if not attack_dirs:
        print("FATAL: No PCAP directories found in", DATA_RAW)
        exit(1)

    print(f"[*] Discovered {len(attack_dirs)} attack vectors.")

    for exp in EXPERIMENTS:
        print(f"\n{'='*60}")
        print(f"  ENGINE: {exp['name']}")
        print(f"{'='*60}")

        # --- Conditional Compilation ---
        if exp["setup_cmd"]:
            print(f"  Compiling under parity constraints...")
            subprocess.run(exp["setup_cmd"], shell=True, check=True,
                           stdout=subprocess.DEVNULL, cwd=BASE_DIR)

        # --- Per-Attack Extraction ---
        summaries = []
        for category, pcap_dir in attack_dirs:
            result = extract_attack(exp, category, pcap_dir)
            if result:
                summaries.append(result)

        # --- ML Analysis for this engine ---
        engine_processed = os.path.join(BASE_DIR, "data/processed/EBPF", exp["name"])
        if os.path.exists(engine_processed):
            print(f"\n  📊 ML Analysis for {exp['name']}...")
            subprocess.run(
                ["python3", ML_SCRIPT, "--dataset", engine_processed],
                check=False, cwd=BASE_DIR
            )
        else:
            print(f"\n  ⚠️  No labeled data found at {engine_processed}")

        # Aggregate
        total_pkts = sum(s["packets_sent"] for s in summaries)
        total_time = sum(s["time_seconds"] for s in summaries)
        print(f"\n  AGGREGATE [{exp['name']}]: {len(summaries)} attacks | "
              f"{total_pkts:,} pkts | {total_time:.1f}s")

        time.sleep(5)  # Cooldown between engines

    print(f"\n{'='*60}")
    print("[✔] NFX/XFAST Parity Assessment Concluded.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n⚠️  Interrupted.")
        teardown_veth()
