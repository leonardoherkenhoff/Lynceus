#!/usr/bin/env python3
"""
Lynceus Pre-processing - CIC-IDS-2017 Granular Attributor (v4.0)
---------------------------------------------------------------------------
Scientific Milestone: Sprint 1 (NTLFlowLyzer Granular Parity)

Research Objective:
    Performs deterministic, granular labeling of CIC-IDS-2017 extraction results
    by individual attack type (e.g., FTP-Patator, SSH-Patator, DoS Hulk, etc.)
    using ratio-based temporal mapping and port classification.

Architecture:
    100% Pure Polars, multi-threaded streaming compiled Rust backend.
    Zero Pandas dependencies, eliminating GIL bottlenecks and NameErrors.
"""

import os
import glob
import argparse
import multiprocessing
from concurrent.futures import ProcessPoolExecutor, as_completed
import polars as pl

# --- Topological Configuration ---
BASE_DIR = "."
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

def get_attackers_for_day(day):
    attackers = set(EXTERNAL_ATTACKERS)
    if day == "thursday":
        # On Thursday afternoon, Windows Vista (192.168.10.8) acts as an insider attacker
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

        # Official 2017 PCAP schedules (EDT / UTC-4) for individual attacks
        FILE_SCHEDULES = {
            "ftp-patator": {"start": 1499174400, "end": 1499178000},
            "ssh-patator": {"start": 1499191200, "end": 1499194800},
            "dos-slowloris": {"start": 1499262420, "end": 1499263800},
            "dos-slowhttptest": {"start": 1499264040, "end": 1499265300},
            "dos-hulk": {"start": 1499265780, "end": 1499266800},
            "dos-goldeneye": {"start": 1499267400, "end": 1499268180},
            "heartbleed": {"start": 1499281920, "end": 1499283120},
            "web-attack-brute-force": {"start": 1499347200, "end": 1499349600},
            "web-attack-xss": {"start": 1499350500, "end": 1499351700},
            "web-attack-sql-injection": {"start": 1499352000, "end": 1499352120},
            "infiltration": {"start": 1499365140, "end": 1499370300},
            "botnet": {"start": 1499436120, "end": 1499439720},
            "portscan": {"start": 1499450100, "end": 1499455740},
            "ddos": {"start": 1499457360, "end": 1499458320},
            # Whole-day fallbacks
            "tuesday": {"start": 1499173200, "end": 1499202000},
            "wednesday": {"start": 1499259600, "end": 1499288400},
            "thursday": {"start": 1499346000, "end": 1499374800},
            "friday": {"start": 1499432400, "end": 1499461200},
            "monday": {"start": 1499082000, "end": 1499110800},
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
            # Detect schedule based on granular file name
            lower_file = os.path.basename(file_path).lower()
            sched = None
            for key, val in FILE_SCHEDULES.items():
                if key in lower_file:
                    sched = val
                    break
            if sched is None:
                sched = FILE_SCHEDULES.get(day, {"start": 1499126400, "end": 1499212800})
                
            hist_start = sched["start"]
            hist_end = sched["end"]
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
                         
            # 3. Thursday (Web Attacks / Infiltration)
            elif day == "thursday":
                is_infil = is_attacker & (
                    (pl.col(ip_col) == "192.168.10.8") | (pl.col(dst_col) == "192.168.10.8") |
                    (pl.col(ip_col) == "192.168.10.25") | (pl.col(dst_col) == "192.168.10.25")
                ) & (epochs >= 1499365140) & (epochs <= 1499370300)
                
                is_web_bf = is_attacker & (epochs >= 1499347200) & (epochs <= 1499349600) & ~is_infil
                is_web_xss = is_attacker & (epochs >= 1499350500) & (epochs <= 1499351700) & ~is_infil
                is_web_sql = is_attacker & (epochs >= 1499352000) & (epochs <= 1499352120) & ~is_infil
                
                expr = pl.when(is_infil).then(pl.lit("Infiltration")) \
                         .when(is_web_bf).then(pl.lit("Web Attack - Brute Force")) \
                         .when(is_web_xss).then(pl.lit("Web Attack - XSS")) \
                         .when(is_web_sql).then(pl.lit("Web Attack - SQL Injection")) \
                         .otherwise(pl.lit("BENIGN"))
                         
            # 4. Friday (Botnet / PortScan / DDoS)
            elif day == "friday":
                is_botnet = is_attacker & (epochs >= 1499436120) & (epochs <= 1499439720)
                is_portscan = is_attacker & (epochs >= 1499450100) & (epochs <= 1499455740)
                is_ddos = is_attacker & (epochs >= 1499457360) & (epochs <= 1499458320)
                
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

        total_rows = _process_polars(file_path, category, day, actual_output)

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

    print("=== Lynceus CIC-IDS-2017 Granular Attribution [Polars Only (Rust-Compiled Backend)] ===")

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
