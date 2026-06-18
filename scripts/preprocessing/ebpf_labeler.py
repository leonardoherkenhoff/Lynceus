#!/usr/bin/env python3
"""
Lynceus Pre-processing - Topological Ground-Truth Attributor (v2.0)
---------------------------------------------------------------------------
Scientific Milestone: v2.0 (High-Performance I/O)

Research Objective:
    Performs deterministic labeling of extraction results based on network
    topology and known attacker vectors.

Performance:
    Uses Polars (Rust-backed) for multi-threaded CSV parsing when available,
    falling back to Pandas for compatibility. Polars achieves 5-10x speedup
    on large CSVs via SIMD-accelerated, zero-copy columnar reads.

Methodology:
    1. Recursive Discovery: Traverses interim directories to find raw CSV telemetry.
    2. Topological Attribution: Matches Source IP against an 'Attacker Matrix'.
    3. Parallel Processing: Uses ProcessPoolExecutor for multi-file concurrency.
    4. Iterative Cleanup: Purges source files post-labeling to maintain storage integrity.
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
BASE_DIR = "."
INPUT_DIR = os.path.join(BASE_DIR, "data/interim/EBPF_RAW")
OUTPUT_DIR = os.path.join(BASE_DIR, "data/processed/EBPF")

# ATTACKER_IPS must be calibrated to the specific research testbed topology.
# ATTACKER_IPS must be calibrated to the specific research testbed topology.
# Includes both compressed and expanded IPv6 formats to match loader.c serialization.
ATTACKER_IPS = [
    "172.16.0.5",
    "2001:db8:acad:10::5",
    "2001:0db8:acad:0010:0000:0000:0000:0005",
    "2001:db8:1:20::abd",
    "2001:0db8:0001:0020:0000:0000:0000:0abd",
    "2001:db8:1:20::abe",
    "2001:0db8:0001:0020:0000:0000:0000:0abe",
    "fe80::215:5dff:fe00:5",
    "fe80:0000:0000:0000:0215:5dff:fe00:0005",
]
ATTACKER_IPS_SET = frozenset(ATTACKER_IPS)
CHUNK_SIZE = 1_000_000  # Pandas fallback only

# Candidate source IP column names across competitor schemas.
IP_CANDIDATES = ['src_ip', 'Src IP', 'Source IP', 'source_ip', 'src']


def _detect_ip_column(columns):
    """
    Detect the source IP column name from a heterogeneous schema.

    Args:
        columns (list): List of column names from the CSV header.

    Returns:
        str or None: The matched column name, or None if no candidate is found.
    """
    for col in IP_CANDIDATES:
        if col in columns:
            return col
    return None


def _process_polars(file_path, category, output_file):
    """
    Label a CSV file using Polars Lazy API (streaming).
    Ensures constant memory usage regardless of file size.
    """
    if os.path.getsize(file_path) == 0:
        return 0
        
    try:
        # Read only header to identify columns (ignore types at this stage)
        all_cols = pl.read_csv(file_path, n_rows=0, infer_schema_length=0).columns

        # HARDENED SCHEMATIZATION: Force Utf8 for identity/structural columns, Float64 for metrics

        structural_keywords = ["ip", "src", "dst", "port", "protocol", "label", "timestamp"]
        overrides = {}
        for col in all_cols:
            c_low = col.lower()
            if any(key in c_low for key in structural_keywords):
                overrides[col] = pl.Utf8
            else:
                overrides[col] = pl.Float64

        
        # Scan with explicit overrides
        q = pl.scan_csv(file_path, schema_overrides=overrides, ignore_errors=True)
        
        # Detect IP column for labeling
        ip_col = _detect_ip_column(all_cols)
        if ip_col:
            q = q.with_columns(
                pl.when(pl.col(ip_col).is_in(ATTACKER_IPS))
                  .then(pl.lit(category))
                  .otherwise(pl.lit("BENIGN"))
                  .alias("Label")
            )


        
        # Sink to CSV (streaming write)
        q.sink_csv(output_file)
        
        # Get count for reporting (requires one pass)
        return pl.scan_csv(output_file).select(pl.len()).collect().item()
    except Exception as e:
        print(f"   ⚠️ Polars Streaming Error: {e}")
        return -1


def _process_pandas(file_path, category, output_file):
    """
    Label a CSV file using Pandas (single-threaded fallback).

    Args:
        file_path (str): Path to the raw CSV.
        category (str): Attack category label to apply.
        output_file (str): Destination path for the labeled CSV.

    Returns:
        int: Number of rows processed.
    """
    import pandas as pd
    import numpy as np

    header = pd.read_csv(file_path, nrows=0)
    ip_col = _detect_ip_column(header.columns.tolist())

    total_rows = 0
    first_chunk = True
    reader = pd.read_csv(file_path, chunksize=CHUNK_SIZE, low_memory=False)
    for chunk in reader:
        if ip_col and ip_col in chunk.columns:
            chunk['Label'] = np.where(
                chunk[ip_col].astype(str).isin(ATTACKER_IPS_SET),
                category, 'BENIGN'
            )
        chunk.to_csv(output_file, mode='a', header=first_chunk, index=False)
        first_chunk = False
        total_rows += len(chunk)

    return total_rows


def process_file_auto(file_path):
    """
    Apply the topological labeling rule to a single extraction result set.

    Dispatches to Polars or Pandas backend based on availability.

    Args:
        file_path (str): Absolute path to the raw CSV telemetry file.

    Returns:
        tuple: (file_path, success_bool, row_count) for progress reporting.
    """
    try:
        rel_from_input = os.path.relpath(file_path, INPUT_DIR)
        path_parts = rel_from_input.split(os.sep)
        category = path_parts[-2] if len(path_parts) > 1 else "UNKNOWN"
        rel_path = os.path.relpath(os.path.dirname(file_path), INPUT_DIR)
        output_folder = os.path.join(OUTPUT_DIR, rel_path)
        os.makedirs(output_folder, exist_ok=True)

        output_file_name = (os.path.basename(os.path.dirname(file_path))
                            if os.path.dirname(file_path) != INPUT_DIR else category)
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
    """
    Entry point for the Lynceus Topological Attributor.

    Parses CLI arguments, discovers raw CSV files, and dispatches parallel
    labeling workers via ProcessPoolExecutor. Optionally purges interim files.
    """
    parser = argparse.ArgumentParser(description="Lynceus Topological Attributor")
    parser.add_argument("--path", type=str, help="Specific interim directory to attribute")
    parser.add_argument("--input", type=str, help="Override INPUT_DIR (interim root)")
    parser.add_argument("--output", type=str, help="Override OUTPUT_DIR (processed root)")
    parser.add_argument("--cleanup", action="store_true", help="Deterministic purge of interim files")
    parser.add_argument("--workers", type=int, default=min(4, multiprocessing.cpu_count()),
                        help="Number of parallel labeling workers (default: min(4, cpu_count))")
    args = parser.parse_args()

    # Override global dirs if provided
    global INPUT_DIR, OUTPUT_DIR
    if args.input:
        INPUT_DIR = os.path.abspath(args.input)
    if args.output:
        OUTPUT_DIR = os.path.abspath(args.output)
        os.makedirs(OUTPUT_DIR, exist_ok=True)

    backend = "Polars (multi-threaded)" if USE_POLARS else "Pandas (single-threaded)"
    print(f"=== Lynceus Pre-processing: Topological Ground-Truth Attribution [{backend}] ===")

    if args.path:
        target_dir = os.path.abspath(args.path)
        files = glob.glob(os.path.join(target_dir, "*.csv"))
    else:
        files = glob.glob(os.path.join(INPUT_DIR, "**", "*.csv"), recursive=True)

    # Exclude resource consumption metrics from ground-truth labeling.
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
                if args.cleanup:
                    os.remove(f)
    else:
        with ProcessPoolExecutor(max_workers=args.workers) as executor:
            futures = {executor.submit(process_file_auto, f): f for f in files}
            for future in as_completed(futures):
                fpath, success, rows = future.result()
                if success:
                    processed_count += 1
                    total_rows += rows
                    if args.cleanup:
                        os.remove(fpath)

    print(f"✅ ATTRIBUTION COMPLETE: {processed_count} files | {total_rows:,} rows formalized.")
    if args.cleanup:
        print("   🧹 Local interim storage purged.")


if __name__ == "__main__":
    main()
