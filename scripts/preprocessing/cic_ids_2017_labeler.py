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

import pandas as pd
try:
    import polars as pl
    USE_POLARS = True
except ImportError:
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
    Vectorized labeling engine using official 2017 Unix Epoch timestamps.
    Automatically handles 2026 replay time-distortion by mapping/scaling.
    """
    import pandas as pd
    labels = np.full(len(pdf), "BENIGN", dtype=object)
    
    # Official 2017 PCAP schedules (EDT / UTC-4)
    DAY_SCHEDULES = {
        "tuesday": {"start": 1499173200, "end": 1499202000},
        "wednesday": {"start": 1499259600, "end": 1499288400},
        "thursday": {"start": 1499346000, "end": 1499374800},
        "friday": {"start": 1499432400, "end": 1499461200},
    }
    
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
    
    # Check if the timestamps are in 2026 (replayed time)
    if len(epochs) > 0 and np.nanmax(epochs) > 1700000000:
        # Scale/Shift 2026 timestamps back to 2017 historical epochs!
        hist_start = DAY_SCHEDULES[day]["start"]
        hist_end = DAY_SCHEDULES[day]["end"]
        hist_duration = hist_end - hist_start
        duration = t_max - t_min
        if duration > 0:
            epochs = hist_start + ((epochs - t_min) / duration) * hist_duration
        else:
            epochs = np.full_like(epochs, hist_start)
            
    dst_ports = pd.to_numeric(pdf[dst_port_col], errors='coerce').values if dst_port_col else np.nan
    src_ports = pd.to_numeric(pdf[src_port_col], errors='coerce').values if src_port_col else np.nan
    
    # 1. Tuesday (Brute Force)
    if day == "tuesday":
        # Tuesday: FTP-Patator (9:20 - 10:20 EDT), SSH-Patator (14:00 - 15:00 EDT)
        is_ftp = is_attacker & ((dst_ports == 21) | (src_ports == 21)) & (epochs >= 1499174400) & (epochs <= 1499178000)
        is_ssh = is_attacker & ((dst_ports == 22) | (src_ports == 22)) & (epochs >= 1499191200) & (epochs <= 1499194800)
        
        labels[is_ftp] = "FTP-Patator"
        labels[is_ssh] = "SSH-Patator"
        
    # 2. Wednesday (DoS)
    elif day == "wednesday":
        is_hb = is_attacker & ((dst_ports == 444) | (src_ports == 444)) & (epochs >= 1499281920) & (epochs <= 1499283120)
        labels[is_hb] = "Heartbleed"
        
        is_slowloris = is_attacker & (epochs >= 1499262420) & (epochs <= 1499263800) & ~is_hb
        is_slowhttp = is_attacker & (epochs >= 1499264040) & (epochs <= 1499265300) & ~is_hb
        is_hulk = is_attacker & (epochs >= 1499265780) & (epochs <= 1499266800) & ~is_hb
        is_goldeneye = is_attacker & (epochs >= 1499267400) & (epochs <= 1499268180) & ~is_hb
        
        labels[is_slowloris] = "DoS slowloris"
        labels[is_slowhttp] = "DoS Slowhttptest"
        labels[is_hulk] = "DoS Hulk"
        labels[is_goldeneye] = "DoS GoldenEye"
        
    # 3. Thursday (Web Attacks)
    elif day == "thursday":
        is_infil = is_attacker & ((pdf[ip_col].astype(str) == "192.168.10.8") | (pdf[dst_col].astype(str) == "192.168.10.8"))
        
        is_web_bf = is_attacker & (epochs >= 1499347200) & (epochs <= 1499349600) & ~is_infil
        is_web_xss = is_attacker & (epochs >= 1499350500) & (epochs <= 1499352600) & ~is_infil
        is_web_sql = is_attacker & (epochs >= 1499353200) & (epochs <= 1499353920) & ~is_infil
        
        labels[is_infil] = "Infiltration"
        labels[is_web_bf] = "Web Attack - Brute Force"
        labels[is_web_xss] = "Web Attack - XSS"
        labels[is_web_sql] = "Web Attack - SQL Injection"
        
    # 4. Friday (Botnet / PortScan / DDoS)
    elif day == "friday":
        is_botnet = is_attacker & (epochs >= 1499436120) & (epochs <= 1499439720)
        is_portscan = is_attacker & (epochs >= 1499450100) & (epochs <= 1499452500)
        is_ddos = is_attacker & (epochs >= 1499457360) & (epochs <= 1499458560)
        
        labels[is_botnet] = "Botnet"
        labels[is_portscan] = "PortScan"
        labels[is_ddos] = "DDoS"
        
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

        # Official 2017 PCAP schedules (EDT / UTC-4)
        DAY_SCHEDULES = {
            "tuesday": {"start": 1499173200, "end": 1499202000},
            "wednesday": {"start": 1499259600, "end": 1499288400},
            "thursday": {"start": 1499346000, "end": 1499374800},
            "friday": {"start": 1499432400, "end": 1499461200},
        }

        # Build lazy query plan
        q = pl.scan_csv(file_path, schema_overrides=overrides, ignore_errors=True)
        
        day_attackers = get_attackers_for_day(day)
        
        # Attacker condition
        is_attacker = pl.col(ip_col).is_in(day_attackers)
        if dst_col:
            is_attacker = is_attacker | pl.col(dst_col).is_in(day_attackers)
            
        if day == "monday":
            expr = pl.lit("BENIGN")
        else:
            hist_start = DAY_SCHEDULES[day]["start"]
            hist_end = DAY_SCHEDULES[day]["end"]
            hist_duration = hist_end - hist_start
            duration = t_max - t_min
            
            # Timestamp parsing and scaling natively
            raw_epochs = pl.col(ts_col).cast(pl.Float64)
            if duration > 0 and t_max > 1700000000:
                epochs = hist_start + ((raw_epochs - t_min) / duration) * hist_duration
            else:
                epochs = raw_epochs
                
            dst_ports = pl.col(dst_port_col).cast(pl.Float64) if dst_port_col else pl.lit(None)
            src_ports = pl.col(src_port_col).cast(pl.Float64) if src_port_col else pl.lit(None)
            
            # 1. Tuesday (Brute Force)
            if day == "tuesday":
                is_ftp = is_attacker & ((dst_ports == 21) | (src_ports == 21)) & (epochs >= 1499174400) & (epochs <= 1499178000)
                is_ssh = is_attacker & ((dst_ports == 22) | (src_ports == 22)) & (epochs >= 1499191200) & (epochs <= 1499194800)
                
                expr = pl.when(is_ftp).then(pl.lit("FTP-Patator")) \
                         .when(is_ssh).then(pl.lit("SSH-Patator")) \
                         .otherwise(pl.lit("BENIGN"))
                         
            # 2. Wednesday (DoS)
            elif day == "wednesday":
                is_hb = is_attacker & ((dst_ports == 444) | (src_ports == 444)) & (epochs >= 1499281920) & (epochs <= 1499283120)
                
                is_slowloris = is_attacker & (epochs >= 1499262420) & (epochs <= 1499263800) & ~is_hb
                is_slowhttp = is_attacker & (epochs >= 1499264040) & (epochs <= 1499265300) & ~is_hb
                is_hulk = is_attacker & (epochs >= 1499265780) & (epochs <= 1499266800) & ~is_hb
                is_goldeneye = is_attacker & (epochs >= 1499267400) & (epochs <= 1499268180) & ~is_hb
                
                expr = pl.when(is_hb).then(pl.lit("Heartbleed")) \
                         .when(is_slowloris).then(pl.lit("DoS slowloris")) \
                         .when(is_slowhttp).then(pl.lit("DoS Slowhttptest")) \
                         .when(is_hulk).then(pl.lit("DoS Hulk")) \
                         .when(is_goldeneye).then(pl.lit("DoS GoldenEye")) \
                         .otherwise(pl.lit("BENIGN"))
                         
            # 3. Thursday (Web Attacks)
            elif day == "thursday":
                is_infil = is_attacker & ((pl.col(ip_col) == "192.168.10.8") | (pl.col(dst_col) == "192.168.10.8"))
                
                is_web_bf = is_attacker & (epochs >= 1499347200) & (epochs <= 1499349600) & ~is_infil
                is_web_xss = is_attacker & (epochs >= 1499350500) & (epochs <= 1499352600) & ~is_infil
                is_web_sql = is_attacker & (epochs >= 1499353200) & (epochs <= 1499353920) & ~is_infil
                
                expr = pl.when(is_infil).then(pl.lit("Infiltration")) \
                         .when(is_web_bf).then(pl.lit("Web Attack - Brute Force")) \
                         .when(is_web_xss).then(pl.lit("Web Attack - XSS")) \
                         .when(is_web_sql).then(pl.lit("Web Attack - SQL Injection")) \
                         .otherwise(pl.lit("BENIGN"))
                         
            # 4. Friday (Botnet / PortScan / DDoS)
            elif day == "friday":
                is_botnet = is_attacker & (epochs >= 1499436120) & (epochs <= 1499439720)
                is_portscan = is_attacker & (epochs >= 1499450100) & (epochs <= 1499452500)
                is_ddos = is_attacker & (epochs >= 1499457360) & (epochs <= 1499458560)
                
                expr = pl.when(is_botnet).then(pl.lit("Botnet")) \
                         .when(is_portscan).then(pl.lit("PortScan")) \
                         .when(is_ddos).then(pl.lit("DDoS")) \
                         .otherwise(pl.lit("BENIGN"))
            else:
                expr = pl.lit("BENIGN")

        # Native compiled projection and stream sink
        q = q.with_columns(expr.alias("Label"))
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
        if output_file_name.startswith("labeled_"):
            output_file_name = output_file_name[len("labeled_"):]
            
        output_file = os.path.join(output_folder, f"labeled_{output_file_name}.csv")

        # Atomic in-place write protection via temporary file
        use_temp = (os.path.abspath(file_path) == os.path.abspath(output_file))
        actual_output = output_file + ".tmp" if use_temp else output_file
        if os.path.exists(actual_output):
            os.remove(actual_output)

        if USE_POLARS:
            total_rows = _process_polars(file_path, category, day, actual_output)
        else:
            total_rows = _process_pandas(file_path, category, day, actual_output)

        if use_temp and total_rows > 0:
            os.replace(actual_output, output_file)

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
