#!/usr/bin/env python3
"""
Lynceus Parity Experiment — RustiFlow Wrapper
---------------------------------------------
Extrai features de cada PCAP usando RustiFlow (modo pcap, feature set CIC-83)
e salva o CSV resultante no diretório interim para posterior labeling e benchmark.

Invocação: sudo python3 scripts/testbed/rustiflow_wrapper.py
"""

import subprocess
import os
import time
import glob
import json
import shutil

BASE_DIR       = "/opt/eBPFNetFlowLyzer"
RUSTIFLOW_BIN  = "/opt/RustiFlow/target/release/rustiflow"
DATA_RAW       = os.path.join(BASE_DIR, "data/raw")
DATA_INTERIM   = os.path.join(BASE_DIR, "data/interim/RUSTIFLOW_RAW")
FEATURE_SET    = "rustiflow"   # 83 features CIC-compatíveis
EXPERIMENT_ORDER = ["PCAPv6", "PCAP"]


def process_pcap_dir(pcap_dir, category, smoke_test=False):
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
    print(f"\n🚀 RUSTIFLOW EXTRACTION: {experiment_name}")

    total_packets = 0
    start_time    = time.time()
    first_file    = True

    for pcap in pcaps:
        print(f"   Processing: {os.path.basename(pcap)}")
        tmp_out = os.path.join(output_dir, f"_tmp_{os.path.basename(pcap)}.csv")

        cmd = [RUSTIFLOW_BIN, "pcap", "-f", FEATURE_SET, "--output", tmp_out, pcap]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            if result.returncode != 0:
                # Fallback: tenta sem --output (stdout)
                result = subprocess.run(
                    [RUSTIFLOW_BIN, "pcap", "-f", FEATURE_SET, pcap],
                    capture_output=True, text=True, timeout=600
                )
                if result.stdout:
                    with open(tmp_out, "w") as f:
                        f.write(result.stdout)

            if os.path.exists(tmp_out) and os.path.getsize(tmp_out) > 0:
                with open(tmp_out) as src, open(csv_output_path, "a") as dst:
                    lines = src.readlines()
                    if first_file:
                        dst.writelines(lines)
                        first_file = False
                    else:
                        dst.writelines(lines[1:])  # skip header on subsequent files
                # Estimate packets from line count
                total_packets += max(0, len(lines) - 1)
                os.remove(tmp_out)

        except subprocess.TimeoutExpired:
            print(f"   ⚠️  Timeout on {os.path.basename(pcap)}")
        except Exception as e:
            print(f"   ❌ Error: {e}")

    elapsed = time.time() - start_time
    pps     = total_packets / elapsed if elapsed > 0 else 0

    summary = {
        "tool": "rustiflow",
        "feature_set": FEATURE_SET,
        "experiment": experiment_name,
        "packets_sent": total_packets,
        "time_seconds": elapsed,
        "pps": pps,
        "timestamp": time.ctime()
    }
    with open(os.path.join(output_dir, "summary.json"), "w") as f:
        json.dump(summary, f, indent=4)

    print(f"✅ DONE: {total_packets} flows | {elapsed:.1f}s | {pps:.0f} fps")


def main():
    import argparse
    parser = argparse.ArgumentParser(description="RustiFlow Extraction Wrapper")
    parser.add_argument("--output", type=str, help="Override interim output directory")
    parser.add_argument("--smoke-test", action="store_true", help="Process only the first PCAP")
    args = parser.parse_args()

    if args.output:
        global DATA_INTERIM
        DATA_INTERIM = os.path.abspath(args.output)

    print(f"=== RustiFlow Parity Extraction Wrapper [Output: {DATA_INTERIM}] ===")
    if not os.path.exists(RUSTIFLOW_BIN):
        print(f"❌ RustiFlow binary not found: {RUSTIFLOW_BIN}")
        import sys
        sys.exit(1)

    for category in EXPERIMENT_ORDER:
        category_path = os.path.join(DATA_RAW, category)
        if not os.path.exists(category_path):
            continue
        pcap_files = glob.glob(os.path.join(category_path, "**", "*.pcap*"), recursive=True)
        pcap_dirs  = sorted(set(os.path.dirname(p) for p in pcap_files))
        if not pcap_dirs and glob.glob(os.path.join(category_path, "*.pcap*")):
            pcap_dirs = [category_path]
        
        if args.smoke_test and pcap_dirs:
            pcap_dirs = [pcap_dirs[0]]

        for pcap_dir in pcap_dirs:
            process_pcap_dir(pcap_dir, category, smoke_test=args.smoke_test)
            if args.smoke_test: break
        if args.smoke_test: break


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n⚠️  Interrupted.")
