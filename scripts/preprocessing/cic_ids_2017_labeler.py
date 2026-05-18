#!/usr/bin/env python3
"""
Lynceus Pre-processing - CIC-IDS-2017 Topological Attributor
---------------------------------------------------------------------------
Scientific Milestone: Sprint 1 (NTLFlowLyzer Cross-Validation)

Research Objective:
    Performs deterministic labeling of CIC-IDS-2017 extraction results based on 
    the official testbed topology.
    
    Attacker Network (Outsiders): 205.174.165.73, 205.174.165.69, 205.174.165.70, 205.174.165.71
    Victim Network (Insiders): 192.168.10.0/24

Methodology:
    1. Matches Source IP against the CIC-IDS-2017 'Attacker Matrix'.
    2. Assigns attack categories based on the PCAP day (Tuesday=BruteForce, etc).
"""

import os
import glob
import argparse
import multiprocessing
from concurrent.futures import ProcessPoolExecutor, as_completed

try:
    import polars as pl
    USE_POLARS = True
except ImportError:
    import pandas as pd
    import numpy as np
    USE_POLARS = False

# --- Topological Configuration ---
BASE_DIR = "/opt/eBPFNetFlowLyzer"
INPUT_DIR = os.path.join(BASE_DIR, "data/interim/EBPF_RAW")
OUTPUT_DIR = os.path.join(BASE_DIR, "data/processed/EBPF")

# CIC-IDS-2017 Attacker IPs (Kali Linux and Windows Attackers)
ATTACKER_IPS = [
    "205.174.165.73",
    "205.174.165.69",
    "205.174.165.70",
    "205.174.165.71",
    "205.174.165.80",
    "172.16.0.1"
]
ATTACKER_IPS_SET = frozenset(ATTACKER_IPS)
CHUNK_SIZE = 1_000_000

IP_CANDIDATES = ['src_ip', 'Src IP', 'Source IP', 'source_ip', 'src']

# Mapping Days to Attack Classes for Multiclass
DAY_ATTACK_MAP = {
    "monday": "BENIGN", # Monday is purely benign background traffic
    "tuesday": "BruteForce", # FTP-Patator, SSH-Patator
    "wednesday": "DoS", # DoS Hulk, Slowloris, GoldenEye, Slowhttptest, Heartbleed
    "thursday": "WebAttack", # Web Attack, Infiltration
    "friday": "DDoS_PortScan", # Botnet, PortScan, DDoS
}

def _detect_ip_column(columns):
    for col in IP_CANDIDATES:
        if col in columns:
            return col
    return None

def _get_attack_category(file_path):
    lower_path = file_path.lower()
    for day, category in DAY_ATTACK_MAP.items():
        if day in lower_path:
            return category
    return "ATTACK" # Fallback

def _process_polars(file_path, category, output_file):
    if os.path.getsize(file_path) == 0:
        return 0
        
    try:
        all_cols = pl.read_csv(file_path, n_rows=0, infer_schema_length=0).columns
        structural_keywords = ["ip", "src", "dst", "port", "protocol", "label", "timestamp"]
        overrides = {}
        for col in all_cols:
            c_low = col.lower()
            if any(key in c_low for key in structural_keywords):
                overrides[col] = pl.Utf8
            else:
                overrides[col] = pl.Float64

        q = pl.scan_csv(file_path, schema_overrides=overrides, ignore_errors=True)
        
        ip_col = _detect_ip_column(all_cols)
        dst_col = "dst_ip" if "dst_ip" in all_cols else ("Dst IP" if "Dst IP" in all_cols else "destination_ip")
        
        if ip_col:
            # For Monday, everything is benign regardless of IP
            if category == "BENIGN":
                q = q.with_columns(pl.lit("BENIGN").alias("Label"))
            else:
                condition = pl.col(ip_col).is_in(ATTACKER_IPS)
                if dst_col in all_cols:
                    condition = condition | pl.col(dst_col).is_in(ATTACKER_IPS)
                
                q = q.with_columns(
                    pl.when(condition)
                      .then(pl.lit(category))
                      .otherwise(pl.lit("BENIGN"))
                      .alias("Label")
                )
        
        q.sink_csv(output_file)
        return pl.scan_csv(output_file).select(pl.len()).collect().item()
    except Exception as e:
        print(f"   ⚠️ Polars Streaming Error: {e}")
        return -1

def _process_pandas(file_path, category, output_file):
    import pandas as pd
    import numpy as np

    header = pd.read_csv(file_path, nrows=0)
    ip_col = _detect_ip_column(header.columns.tolist())
    dst_col = "dst_ip" if "dst_ip" in header.columns else ("Dst IP" if "Dst IP" in header.columns else "destination_ip")

    total_rows = 0
    first_chunk = True
    reader = pd.read_csv(file_path, chunksize=CHUNK_SIZE, low_memory=False)
    for chunk in reader:
        if ip_col and ip_col in chunk.columns:
            if category == "BENIGN":
                chunk['Label'] = 'BENIGN'
            else:
                is_attacker = chunk[ip_col].astype(str).isin(ATTACKER_IPS_SET)
                if dst_col in chunk.columns:
                    is_attacker = is_attacker | chunk[dst_col].astype(str).isin(ATTACKER_IPS_SET)
                
                chunk['Label'] = np.where(is_attacker, category, 'BENIGN')
        chunk.to_csv(output_file, mode='a', header=first_chunk, index=False)
        first_chunk = False
        total_rows += len(chunk)

    return total_rows

def process_file_auto(file_path):
    try:
        category = _get_attack_category(file_path)
        rel_path = os.path.relpath(os.path.dirname(file_path), INPUT_DIR)
        output_folder = os.path.join(OUTPUT_DIR, rel_path)
        os.makedirs(output_folder, exist_ok=True)

        output_file_name = os.path.splitext(os.path.basename(file_path))[0]
        output_file = os.path.join(output_folder, f"labeled_{output_file_name}.csv")

        if USE_POLARS:
            total_rows = _process_polars(file_path, category, output_file)
        else:
            total_rows = _process_pandas(file_path, category, output_file)

        success = total_rows > 0
        return (file_path, success, max(0, total_rows))
    except Exception as e:
        print(f"   ❌ Attribution Error for {file_path}: {e}")
        return (file_path, False, 0)

def main():
    parser = argparse.ArgumentParser(description="Lynceus Topological Attributor (CIC-IDS-2017)")
    parser.add_argument("--path", type=str, help="Specific interim directory to attribute")
    parser.add_argument("--input", type=str, help="Override INPUT_DIR (interim root)")
    parser.add_argument("--output", type=str, help="Override OUTPUT_DIR (processed root)")
    parser.add_argument("--cleanup", action="store_true", help="Deterministic purge of interim files")
    parser.add_argument("--workers", type=int, default=min(4, multiprocessing.cpu_count()),
                        help="Number of parallel workers")
    args = parser.parse_args()

    global INPUT_DIR, OUTPUT_DIR
    if args.input: INPUT_DIR = os.path.abspath(args.input)
    if args.output: 
        OUTPUT_DIR = os.path.abspath(args.output)
        os.makedirs(OUTPUT_DIR, exist_ok=True)

    backend = "Polars (multi-threaded)" if USE_POLARS else "Pandas (single-threaded)"
    print(f"=== Lynceus CIC-IDS-2017 Topological Attribution [{backend}] ===")

    if args.path:
        target_dir = os.path.abspath(args.path)
        files = glob.glob(os.path.join(target_dir, "*.csv"))
    else:
        files = glob.glob(os.path.join(INPUT_DIR, "**", "*.csv"), recursive=True)

    files = [f for f in files if not os.path.basename(f).startswith("resource_metrics")]

    if not files:
        print(f"⚠️  No telemetric artifacts found in {INPUT_DIR}.")
        return

    print(f"   📂 Discovered {len(files)} CSV files. Workers: {args.workers}")

    processed_count = 0
    total_rows = 0

    if len(files) == 1 or args.workers <= 1:
        for f in files:
            _, success, rows = process_file_auto(f)
            if success:
                processed_count += 1
                total_rows += rows
                if args.cleanup: os.remove(f)
    else:
        with ProcessPoolExecutor(max_workers=args.workers) as executor:
            futures = {executor.submit(process_file_auto, f): f for f in files}
            for future in as_completed(futures):
                fpath, success, rows = future.result()
                if success:
                    processed_count += 1
                    total_rows += rows
                    if args.cleanup: os.remove(fpath)

    print(f"✅ ATTRIBUTION COMPLETE: {processed_count} files | {total_rows:,} rows formalized.")
    if args.cleanup: print("   🧹 Local interim storage purged.")

if __name__ == "__main__":
    main()
