#!/usr/bin/env python3
"""
Lynceus Pre-processing - Topological Ground-Truth Attributor (v1.1)
---------------------------------------------------------------------------
Scientific Milestone: v1.1 (Parallel I/O)

Research Objective:
    Performs deterministic labeling of extraction results based on network
    topology and known attacker vectors.

Methodology:
    1. Recursive Discovery: Traverses interim directories to find raw CSV telemetry.
    2. Topological Attribution: Matches Source IP against an 'Attacker Matrix'.
    3. Parallel Processing: Uses ProcessPoolExecutor for multi-file concurrency.
    4. Iterative Cleanup: Purges source files post-labeling to maintain storage integrity.
"""

import pandas as pd
import numpy as np
import os
import glob
import argparse
from concurrent.futures import ProcessPoolExecutor, as_completed
import multiprocessing

# --- Topological Configuration ---
BASE_DIR = "/opt/eBPFNetFlowLyzer"
INPUT_DIR = os.path.join(BASE_DIR, "data/interim/EBPF_RAW")
OUTPUT_DIR = os.path.join(BASE_DIR, "data/processed/EBPF")

# ATTACKER_IPS must be calibrated to the specific research testbed topology.
ATTACKER_IPS_SET = frozenset(["172.16.0.5", "2001:db8:acad:10::5", "fe80::215:5dff:fe00:5"])
CHUNK_SIZE = 1_000_000


def _detect_ip_column(columns):
    """
    Detect the source IP column name from a heterogeneous schema.

    Args:
        columns (list): List of column names from the CSV header.

    Returns:
        str or None: The matched column name, or None if no candidate is found.
    """
    for col in ['src_ip', 'Src IP', 'Source IP', 'source_ip', 'src']:
        if col in columns:
            return col
    return None


def process_file_auto(file_path):
    """
    Apply the topological labeling rule to a single extraction result set.

    Uses vectorized pandas operations with large chunks for maximum throughput.
    The IP column is detected once from the header and reused across all chunks.

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

        output_file_name = os.path.basename(os.path.dirname(file_path)) if os.path.dirname(file_path) != INPUT_DIR else category
        output_file = os.path.join(output_folder, f"labeled_{output_file_name}.csv")
        first_chunk = not os.path.exists(output_file)

        # Detect IP column from header only (avoids per-chunk detection).
        header = pd.read_csv(file_path, nrows=0)
        ip_col = _detect_ip_column(header.columns.tolist())

        total_rows = 0
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

        return (file_path, True, total_rows)
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
    parser.add_argument("--cleanup", action="store_true", help="Deterministic purge of interim files")
    parser.add_argument("--workers", type=int, default=min(4, multiprocessing.cpu_count()),
                        help="Number of parallel labeling workers (default: min(4, cpu_count))")
    args = parser.parse_args()

    print("=== Lynceus Pre-processing: Topological Ground-Truth Attribution ===")

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
        # Single-file path: sequential (avoids fork overhead for one file).
        for f in files:
            _, success, rows = process_file_auto(f)
            if success:
                processed_count += 1
                total_rows += rows
                if args.cleanup:
                    os.remove(f)
    else:
        # Multi-file path: parallel processing.
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
