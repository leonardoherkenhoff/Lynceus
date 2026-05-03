#!/usr/bin/env python3
"""
Lynceus Pre-processing - Topological Ground-Truth Attributor (v1.0)
---------------------------------------------------------------------------
Scientific Milestone: v1.0 (The Definitive Foundation)

Research Objective:
Performs deterministic labeling of extraction results based on network 
topology and known attacker vectors. 

Methodology:
1. Recursive Discovery: Traverses interim directories to find raw CSV telemetry.
2. Topological Attribution: Matches Source IP against an 'Attacker Matrix'.
3. Iterative Cleanup: Purges source files post-labeling to maintain storage integrity.
"""

import pandas as pd
import numpy as np
import os
import glob
import argparse

# --- Topological Configuration ---
BASE_DIR = "/opt/eBPFNetFlowLyzer"
INPUT_DIR = os.path.join(BASE_DIR, "data/interim/EBPF_RAW")
OUTPUT_DIR = os.path.join(BASE_DIR, "data/processed/EBPF")

# ATTACKER_IPS must be calibrated to the specific research testbed topology.
ATTACKER_IPS = ["172.16.0.5", "2001:db8:acad:10::5", "fe80::215:5dff:fe00:5"] 
CHUNK_SIZE = 500000 

def process_file_auto(file_path):
    """
    Apply the topological labeling rule to a single extraction result set.

    Args:
        file_path (str): Absolute path to the raw CSV telemetry file.

    Returns:
        bool: True if the file was processed and attributed successfully, False otherwise.
    """
    try:
        rel_from_input = os.path.relpath(file_path, INPUT_DIR)
        path_parts = rel_from_input.split(os.sep)
        # Use the leaf folder as the specific attack category
        category = path_parts[-2] if len(path_parts) > 1 else "UNKNOWN"
        rel_path = os.path.relpath(os.path.dirname(file_path), INPUT_DIR)
        output_folder = os.path.join(OUTPUT_DIR, rel_path)
        os.makedirs(output_folder, exist_ok=True)
        
        output_file_name = os.path.basename(os.path.dirname(file_path)) if os.path.dirname(file_path) != INPUT_DIR else category
        output_file = os.path.join(output_folder, f"labeled_{output_file_name}.csv")
        first_chunk = not os.path.exists(output_file)
        
        # Memory-efficient chunking for massive PCAP-extracted telemetry.
        reader = pd.read_csv(file_path, chunksize=CHUNK_SIZE, low_memory=False)
        for chunk in reader:
            data = chunk.copy()
            # --- Universal Competitor Schema Mapping ---
            # Lynceus: 'src_ip', RustiFlow: 'Src IP', XFAST: 'source_ip'
            ip_col = None
            candidate_cols = ['src_ip', 'Src IP', 'Source IP', 'source_ip', 'src']
            for col in candidate_cols:
                if col in data.columns:
                    ip_col = col
                    break
                    
            if ip_col:
                src_ips = data[ip_col].astype(str)
                is_attack = src_ips.isin(ATTACKER_IPS)
                data['Label'] = np.where(is_attack, category, 'BENIGN')
            data.to_csv(output_file, mode='a', header=first_chunk, index=False)
            first_chunk = False
            
        return True
    except Exception as e:
        print(f"   ❌ Attribution Error for {file_path}: {e}")
        return False

def main():
    """
    Entry point for the Lynceus Topological Attributor.

    Parses CLI arguments, discovers raw CSV files iteratively, and orchestrates
    the labeling process. Optionally purges the interim files post-processing.
    """
    parser = argparse.ArgumentParser(description="Lynceus Topological Attributor")
    parser.add_argument("--path", type=str, help="Specific interim directory to attribute")
    parser.add_argument("--cleanup", action="store_true", help="Deterministic purge of interim files")
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

    processed_count = 0
    for f in files:
        if process_file_auto(f):
            processed_count += 1
            if args.cleanup: os.remove(f)
    
    print(f"✅ ATTRIBUTION COMPLETE: {processed_count} files formalized.")
    if args.cleanup: print("   🧹 Local interim storage purged.")

if __name__ == "__main__":
    main()
