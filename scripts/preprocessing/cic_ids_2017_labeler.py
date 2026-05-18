#!/usr/bin/env python3
"""
Lynceus Pre-processing - CIC-IDS-2017 Granular Attributor (v3.0)
---------------------------------------------------------------------------
Scientific Milestone: Sprint 1 (NTLFlowLyzer Granular Parity)

Research Objective:
    Performs deterministic, granular labeling of CIC-IDS-2017 extraction results
    by individual attack type (e.g., FTP-Patator, SSH-Patator, DoS Hulk, etc.)
    using ratio-based temporal mapping and port classification.

Methodology:
    1. Port-Based Attribution: Separates Tuesday Patator attacks and Wednesday Heartbleed.
    2. Temporal Ratio-Based Attribution: Separates overlapping attacks by relative 
       elapsed ratios, ensuring immunity to replay speed (topspeed) and wall-clock shifts.
    3. SIMD Acceleration: Uses Polars streaming architecture with custom chunk mapping.
"""

import os
import glob
import argparse
import multiprocessing
import numpy as np
from concurrent.futures import ProcessPoolExecutor, as_completed

try:
    import polars as pl
    USE_POLARS = True
except ImportError:
    import pandas as pd
    USE_POLARS = False

# --- Topological Configuration ---
BASE_DIR = "/opt/eBPFNetFlowLyzer"
INPUT_DIR = os.path.join(BASE_DIR, "data/interim/EBPF_RAW")
OUTPUT_DIR = os.path.join(BASE_DIR, "data/processed/EBPF")

EXTERNAL_ATTACKERS = {
    "205.174.165.73",
    "205.174.165.69",
    "205.174.165.70",
    "205.174.165.71",
    "205.174.165.80",
    "172.16.0.1"
}
CHUNK_SIZE = 1_000_000

def get_attackers_for_day(day):
    attackers = set(EXTERNAL_ATTACKERS)
    if day == "thursday":
        attackers.add("192.168.10.8")
    return list(attackers)

IP_CANDIDATES = ['src_ip', 'Src IP', 'Source IP', 'source_ip', 'src']
DAY_ATTACK_MAP = {
    "monday": "BENIGN",
    "tuesday": "BruteForce",
    "wednesday": "DoS",
    "thursday": "WebAttack",
    "friday": "DDoS_PortScan",
}

def _detect_ip_column(columns):
    for col in IP_CANDIDATES:
        if col in columns:
            return col
    return None

def _get_attack_category_and_day(file_path):
    lower_path = file_path.lower()
    for day, category in DAY_ATTACK_MAP.items():
        if day in lower_path:
            return category, day
    return "ATTACK", "unknown"

def label_series(pdf, day, t_min, t_max):
    """
    Vectorized labeling engine using ratio-based temporal windowing and ports.
    """
    import pandas as pd
    labels = np.full(len(pdf), "BENIGN", dtype=object)
    
    ip_col = _detect_ip_column(pdf.columns)
    dst_col = next((c for c in ['dst_ip', 'Dst IP', 'destination_ip', 'dst'] if c in pdf.columns), None)
    dst_port_col = next((c for c in ['dst_port', 'Dst Port', 'destination_port', 'dstport', 'port'] if c in pdf.columns), None)
    src_port_col = next((c for c in ['src_port', 'Src Port', 'source_port', 'srcport'] if c in pdf.columns), None)
    ts_col = next((c for c in ['timestamp', 'Timestamp', 'flow_start', 'time'] if c in pdf.columns), None)
    
    if not ip_col:
        return labels
        
    day_attackers = get_attackers_for_day(day)
    is_attacker = pdf[ip_col].astype(str).isin(day_attackers)
    if dst_col:
        is_attacker = is_attacker | pdf[dst_col].astype(str).isin(day_attackers)
        
    if day == "monday":
        return labels
        
    epochs = pd.to_numeric(pdf[ts_col], errors='coerce').values
    duration = t_max - t_min
    ratios = (epochs - t_min) / duration if duration > 0 else np.zeros(len(pdf))
    
    dst_ports = pd.to_numeric(pdf[dst_port_col], errors='coerce').values if dst_port_col else np.nan
    src_ports = pd.to_numeric(pdf[src_port_col], errors='coerce').values if src_port_col else np.nan
    
    # 1. Tuesday (Brute Force)
    if day == "tuesday":
        is_ftp = is_attacker & ((dst_ports == 21) | (src_ports == 21))
        is_ssh = is_attacker & ((dst_ports == 22) | (src_ports == 22))
        labels[is_ftp] = "FTP-Patator"
        labels[is_ssh] = "SSH-Patator"
        
    # 2. Wednesday (DoS)
    elif day == "wednesday":
        is_hb = is_attacker & ((dst_ports == 444) | (src_ports == 444))
        labels[is_hb] = "Heartbleed"
        
        is_slowloris = is_attacker & (ratios >= 0.090) & (ratios <= 0.150) & ~is_hb
        is_slowhttp = is_attacker & (ratios >= 0.150) & (ratios <= 0.205) & ~is_hb
        is_hulk = is_attacker & (ratios >= 0.205) & (ratios <= 0.260) & ~is_hb
        is_goldeneye = is_attacker & (ratios >= 0.260) & (ratios <= 0.310) & ~is_hb
        
        labels[is_slowloris] = "DoS slowloris"
        labels[is_slowhttp] = "DoS Slowhttptest"
        labels[is_hulk] = "DoS Hulk"
        labels[is_goldeneye] = "DoS GoldenEye"
        
    # 3. Thursday (Web Attacks)
    elif day == "thursday":
        is_infil = is_attacker & ((pdf[ip_col].astype(str) == "192.168.10.8") | (pdf[dst_col].astype(str) == "192.168.10.8"))
        
        is_web_bf = is_attacker & (ratios >= 0.035) & (ratios <= 0.135) & ~is_infil
        is_web_xss = is_attacker & (ratios >= 0.145) & (ratios <= 0.235) & ~is_infil
        is_web_sql = is_attacker & (ratios >= 0.240) & (ratios <= 0.285) & ~is_infil
        
        labels[is_infil] = "Infiltration"
        labels[is_web_bf] = "Web Attack - Brute Force"
        labels[is_web_xss] = "Web Attack - XSS"
        labels[is_web_sql] = "Web Attack - SQL Injection"
        
    # 4. Friday (Botnet / PortScan / DDoS)
    elif day == "friday":
        is_botnet = is_attacker & (ratios >= 0.115) & (ratios <= 0.265)
        is_portscan = is_attacker & (ratios >= 0.600) & (ratios <= 0.710)
        is_ddos = is_attacker & (ratios >= 0.850) & (ratios <= 0.920)
        
        labels[is_botnet] = "Botnet"
        labels[is_portscan] = "PortScan"
        labels[is_ddos] = "DDoS"
        
    # Fallback to general daily categories for unmatched attacker flows
    unmatched_attack = is_attacker & (labels == "BENIGN")
    labels[unmatched_attack] = DAY_ATTACK_MAP[day]
    
    return labels

def _process_polars(file_path, category, day, output_file):
    if os.path.getsize(file_path) == 0:
        return 0
        
    try:
        # Read headers to get structure
        all_cols = pl.read_csv(file_path, n_rows=0, infer_schema_length=0).columns
        structural_keywords = ["ip", "src", "dst", "port", "protocol", "label", "timestamp"]
        overrides = {}
        for col in all_cols:
            c_low = col.lower()
            if any(key in c_low for key in structural_keywords):
                overrides[col] = pl.Utf8
            else:
                overrides[col] = pl.Float64

        # Dynamic column detection
        ip_col = _detect_ip_column(all_cols)
        dst_col = next((c for c in ['dst_ip', 'Dst IP', 'destination_ip', 'dst'] if c in all_cols), None)
        dst_port_col = next((c for c in ['dst_port', 'Dst Port', 'destination_port', 'dstport', 'port'] if c in all_cols), None)
        src_port_col = next((c for c in ['src_port', 'Src Port', 'source_port', 'srcport'] if c in all_cols), None)
        ts_col = next((c for c in ['timestamp', 'Timestamp', 'flow_start', 'time'] if c in all_cols), None)

        if not ip_col or not ts_col:
            # Fallback to benign if columns are missing
            pl.scan_csv(file_path, schema_overrides=overrides, ignore_errors=True) \
              .with_columns(pl.lit("BENIGN").alias("Label")) \
              .sink_csv(output_file)
            return 0

        # Pass 1: Grab min and max timestamp using memory-efficient scan
        ts_stats = pl.scan_csv(file_path, schema_overrides=overrides, ignore_errors=True) \
                     .select([
                         pl.col(ts_col).cast(pl.Float64).min().alias("t_min"),
                         pl.col(ts_col).cast(pl.Float64).max().alias("t_max")
                     ]).collect()
        t_min = ts_stats["t_min"][0]
        t_max = ts_stats["t_max"][0]
        
        if t_min is None or t_max is None:
            t_min, t_max = 0.0, 1.0

        # Define custom polars Struct batch mapping
        struct_cols = [c for c in [ip_col, dst_col, dst_port_col, src_port_col, ts_col] if c is not None]
        
        def pl_label_batch(struct_series):
            import pandas as pd
            series_dict = {
                field: struct_series.struct.field(field).to_pandas()
                for field in struct_series.struct.fields
            }
            df = pd.DataFrame(series_dict)
            labels = label_series(df, day, t_min, t_max)
            return pl.Series("Label", labels)

        # Pass 2: Lazy evaluation and streaming sink
        q = pl.scan_csv(file_path, schema_overrides=overrides, ignore_errors=True)
        q = q.with_columns(
            pl.struct(struct_cols).map_batches(pl_label_batch, return_dtype=pl.Utf8).alias("Label")
        )
        
        q.sink_csv(output_file)
        return pl.scan_csv(output_file).select(pl.len()).collect().item()
    except Exception as e:
        print(f"   ⚠️ Polars Streaming Error: {e}")
        return -1

def _process_pandas(file_path, category, day, output_file):
    import pandas as pd
    
    header = pd.read_csv(file_path, nrows=0)
    ts_col = next((c for c in ['timestamp', 'Timestamp', 'flow_start', 'time'] if c in header.columns), None)
    
    # Pass 1: Probe min and max timestamps
    t_min, t_max = None, None
    reader = pd.read_csv(file_path, chunksize=CHUNK_SIZE, usecols=[ts_col] if ts_col else None, low_memory=False)
    for chunk in reader:
        epochs = pd.to_numeric(chunk[ts_col], errors='coerce')
        c_min, c_max = epochs.min(), epochs.max()
        t_min = c_min if t_min is None else min(t_min, c_min)
        t_max = c_max if t_max is None else max(t_max, c_max)
        
    if t_min is None or t_max is None:
        t_min, t_max = 0.0, 1.0

    # Pass 2: Label in chunks
    total_rows = 0
    first_chunk = True
    reader = pd.read_csv(file_path, chunksize=CHUNK_SIZE, low_memory=False)
    for chunk in reader:
        labels = label_series(chunk, day, t_min, t_max)
        chunk['Label'] = labels
        chunk.to_csv(output_file, mode='a', header=first_chunk, index=False)
        first_chunk = False
        total_rows += len(chunk)

    return total_rows

def process_file_auto(file_path):
    try:
        category, day = _get_attack_category_and_day(file_path)
        rel_path = os.path.relpath(os.path.dirname(file_path), INPUT_DIR)
        output_folder = os.path.join(OUTPUT_DIR, rel_path)
        os.makedirs(output_folder, exist_ok=True)

        output_file_name = os.path.splitext(os.path.basename(file_path))[0]
        output_file = os.path.join(output_folder, f"labeled_{output_file_name}.csv")

        if USE_POLARS:
            total_rows = _process_polars(file_path, category, day, output_file)
        else:
            total_rows = _process_pandas(file_path, category, day, output_file)

        success = total_rows > 0
        return (file_path, success, max(0, total_rows))
    except Exception as e:
        print(f"   ❌ Attribution Error for {file_path}: {e}")
        return (file_path, False, 0)

def main():
    parser = argparse.ArgumentParser(description="Lynceus Granular Attributor (CIC-IDS-2017)")
    parser.add_argument("--path", type=str, help="Specific interim directory to attribute")
    parser.add_argument("--input", type=str, help="Override INPUT_DIR")
    parser.add_argument("--output", type=str, help="Override OUTPUT_DIR")
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
    print(f"=== Lynceus CIC-IDS-2017 Granular Attribution [{backend}] ===")

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

    print(f"✅ GRANULAR ATTRIBUTION COMPLETE: {processed_count} files | {total_rows:,} rows formalized.")
    if args.cleanup: print("   🧹 Local interim storage purged.")

if __name__ == "__main__":
    main()
