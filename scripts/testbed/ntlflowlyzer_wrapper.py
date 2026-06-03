#!/usr/bin/env python3
"""
Lynceus Parity Experiment - NTLFlowLyzer Wrapper
---------------------------------------------------------------------------
Scientific Milestone: v2.0 (High-Performance I/O)

Research Objective:
    Extrai features de cada PCAP usando NTLFlowLyzer (parity-netflowlyzer).
    Gera config.json dinâmico para cada PCAP e invoca o NTLFlowLyzer via CLI.
"""

import subprocess
import os
import time
import glob
import json
import shutil
import tempfile

BASE_DIR       = "/opt/eBPFNetFlowLyzer"
NTL_DIR        = "/opt/NTLFlowLyzer"
NTL_BIN        = "ntlflowlyzer"   # instalado via setup.py
DATA_RAW       = os.path.join(BASE_DIR, "data/raw")
DATA_INTERIM   = os.path.join(BASE_DIR, "data/interim/NTL_RAW")
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
    print(f"\n🚀 NTLFlowLyzer EXTRACTION: {experiment_name}")

    total_flows = 0
    start_time  = time.time()
    first_file  = True

    for pcap in pcaps:
        print(f"   Processing: {os.path.basename(pcap)}")
        tmp_out = os.path.join(output_dir, f"_tmp_{os.path.basename(pcap)}.csv")

        # Gera config dinâmico
        config = {
            "pcap_file_address": pcap,
            "output_file_address": tmp_out,
            "label": "UNKNOWN",
            "number_of_threads": 8,
            "feature_extractor_min_flows": 100,
            "writer_min_rows": 500,
            "read_packets_count_value_log_info": 100000,
            "check_flows_ending_min_flows": 100,
            "capturer_updating_flows_min_value": 100,
            "max_flow_duration": 3600,
            "activity_timeout": 300,
            "floating_point_unit": ".4f",
            "max_rows_number": 5000000,
            "features_ignore_list": []
        }
        cfg_path = os.path.join(output_dir, "_tmp_config.json")
        with open(cfg_path, "w") as f:
            json.dump(config, f, indent=4)

        try:
            result = subprocess.run(
                [NTL_BIN, cfg_path],
                capture_output=True, text=True, timeout=900,
                cwd=NTL_DIR
            )
            if result.returncode != 0 and not os.path.exists(tmp_out):
                # Fallback: tentar como módulo Python
                result = subprocess.run(
                    ["python3", "-m", "NTLFlowLyzer", cfg_path],
                    capture_output=True, text=True, timeout=900,
                    cwd=NTL_DIR
                )

            if os.path.exists(tmp_out) and os.path.getsize(tmp_out) > 0:
                with open(tmp_out) as src, open(csv_output_path, "a") as dst:
                    lines = src.readlines()
                    if first_file:
                        dst.writelines(lines)
                        first_file = False
                    else:
                        dst.writelines(lines[1:])
                total_flows += max(0, len(lines) - 1)
                os.remove(tmp_out)

        except subprocess.TimeoutExpired:
            print(f"   ⚠️  Timeout on {os.path.basename(pcap)}")
        except Exception as e:
            print(f"   ❌ Error: {e}")
        finally:
            if os.path.exists(cfg_path):
                os.remove(cfg_path)

    elapsed = time.time() - start_time
    summary = {
        "tool": "ntlflowlyzer",
        "experiment": experiment_name,
        "flows_extracted": total_flows,
        "time_seconds": elapsed,
        "timestamp": time.ctime()
    }
    with open(os.path.join(output_dir, "summary.json"), "w") as f:
        json.dump(summary, f, indent=4)

    print(f"✅ DONE: {total_flows} flows | {elapsed:.1f}s")


def main():
    import argparse
    parser = argparse.ArgumentParser(description="NTLFlowLyzer Extraction Wrapper")
    parser.add_argument("--output", type=str, help="Override interim output directory")
    parser.add_argument("--smoke-test", action="store_true", help="Process only the first PCAP")
    args = parser.parse_args()

    if args.output:
        global DATA_INTERIM
        DATA_INTERIM = os.path.abspath(args.output)

    print(f"=== NTLFlowLyzer Parity Extraction Wrapper [Output: {DATA_INTERIM}] ===")
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
