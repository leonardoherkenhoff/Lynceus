#!/usr/bin/env python3
"""
Lynceus Parity Experiment — RustiFlow Wrapper (V5)
---------------------------------------------
"""

import subprocess
import os
import time
import glob
import json
import shutil

BASE_DIR       = "."
RUSTIFLOW_BIN  = "/opt/RustiFlow/target/release/rustiflow"
DATA_RAW       = os.path.join(BASE_DIR, "data/raw")
DATA_INTERIM   = os.path.join(BASE_DIR, "data/interim/RUSTIFLOW_RAW")
FEATURE_SET    = "rustiflow"   # 83 features CIC-compatíveis
EXPERIMENT_ORDER = ["PCAP", "PCAPv6"]

def process_pcap_dir(pcap_dir, category, smoke_test=False, skip_labeling=False, max_events=0):
    rel_path   = os.path.relpath(pcap_dir, os.path.join(DATA_RAW, category))
    output_dir = os.path.normpath(os.path.join(DATA_INTERIM, category, rel_path))
    os.makedirs(output_dir, exist_ok=True)

    pcaps = sorted(glob.glob(os.path.join(pcap_dir, "*.pcap*")))
    if not pcaps:
        return

    if smoke_test:
        pcaps = [pcaps[0]]

    experiment_name = f"{category}/{rel_path}"
    csv_output_path = os.path.join(output_dir, "flows.csv")
    print(f"\n🚀 RUSTIFLOW EXTRACTION [{len(pcaps)} files]: {experiment_name}")

    total_packets = 0
    start_time    = time.time()
    first_file    = True

    for pcap in pcaps:
        if max_events > 0 and total_packets >= max_events:
            print(f"   🛑 Limit reached ({max_events}). Skipping remaining PCAPs.")
            break
        print(f"   Processing: {os.path.basename(pcap)}")
        tmp_out = os.path.join(output_dir, f"_tmp_{os.path.basename(pcap)}.csv")
        metrics_csv = os.path.join(output_dir, "resource_metrics.csv")
        monitor_script = os.path.join(BASE_DIR, "scripts/testbed/monitor.py")


        # Use -f rustiflow for maximum features parity
        cmd = [RUSTIFLOW_BIN, "-f", "rustiflow", "-o", "csv", "--header", "--export-path", tmp_out, "pcap", pcap]
        try:
            p_rust = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            proc_mon = subprocess.Popen(["python3", monitor_script, str(p_rust.pid), metrics_csv]) if os.path.exists(monitor_script) else None
            
            p_rust.wait(timeout=1800)
            if proc_mon: proc_mon.terminate()
            
            if p_rust.returncode != 0:
                print(f"   ⚠️  RustiFlow failed on {pcap}")
            else:
                if os.path.exists(tmp_out) and os.path.getsize(tmp_out) > 0:
                    with open(tmp_out) as src, open(csv_output_path, "a") as dst:
                        lines = src.readlines()
                        if first_file:
                            dst.writelines(lines)
                            first_file = False
                        else:
                            dst.writelines(lines[1:])
                    total_packets += max(0, len(lines) - 1)
                    os.remove(tmp_out)
        except Exception as e:
            print(f"   ❌ Error: {e}")

    if max_events > 0:
        print(f"   ✂️ Enforcing strict parity limit: Truncating to {max_events} flows")
        subprocess.run(f"head -n {max_events + 1} {csv_output_path} > {csv_output_path}.tmp && mv {csv_output_path}.tmp {csv_output_path}", shell=True)

    elapsed = time.time() - start_time
    pps     = total_packets / elapsed if elapsed > 0 else 0
    summary = {"tool": "rustiflow", "packets_sent": total_packets, "time_seconds": elapsed, "pps": pps, "timestamp": time.ctime()}
    with open(os.path.join(output_dir, "summary.json"), "w") as f:
        json.dump(summary, f, indent=4)
    print(f"✅ DONE: {total_packets} flows | {elapsed:.1f}s | {pps:.0f} fps")

def run_rustiflow_extraction(smoke_test=False, skip_labeling=False, max_events=0, filter_atk=None):
    for category in EXPERIMENT_ORDER:
        base_cat = os.path.join(DATA_RAW, category)
        if not os.path.exists(base_cat): continue
        pcap_dirs = [d[0] for d in os.walk(base_cat) if glob.glob(os.path.join(d[0], "*.pcap*"))]
        if smoke_test and pcap_dirs:
            pcap_dirs = [pcap_dirs[0]]
        for pcap_dir in pcap_dirs:
            if filter_atk and filter_atk.lower() not in pcap_dir.lower():
                continue
            process_pcap_dir(pcap_dir, category, smoke_test=smoke_test, 
                             skip_labeling=skip_labeling, max_events=max_events)
            if smoke_test: break
        if smoke_test: break

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="RustiFlow Parity Wrapper")
    parser.add_argument("--output", type=str, help="Override interim output directory")
    parser.add_argument("--smoke-test", action="store_true", help="Process only the first PCAP")
    parser.add_argument("--skip-labeling", action="store_true", help="Bypass internal labeling")
    parser.add_argument("--max-events", type=int, default=0, help="Max flows to capture")
    parser.add_argument("--filter", type=str, default=None, help="Filter PCAP directories by name (regex)")
    args = parser.parse_args()
    if args.output: DATA_INTERIM = os.path.abspath(args.output)
    run_rustiflow_extraction(smoke_test=args.smoke_test, skip_labeling=args.skip_labeling, 
                             max_events=args.max_events, filter_atk=args.filter)
