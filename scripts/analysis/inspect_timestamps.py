#!/usr/bin/env python3
"""
Inspect Replay Durations and Timestamps for All Partition Files
"""

import os
import glob
import pandas as pd

PROCESSED_DIR = "/opt/eBPFNetFlowLyzer/data/processed/EBPF"
INTERIM_DIR = "/opt/eBPFNetFlowLyzer/data/interim/EBPF_RAW"

def inspect_all_files():
    files = glob.glob(os.path.join(PROCESSED_DIR, "labeled_*.csv"))
    if not files:
        files = glob.glob(os.path.join(INTERIM_DIR, "**", "*.csv"), recursive=True)
        
    if not files:
        print("[ERROR] No CSV files found.")
        return
        
    print("=== PCAP REPLAY TIME AUDIT ===")
    for f in sorted(files):
        file_name = os.path.basename(f)
        try:
            df = pd.read_csv(f, usecols=['timestamp'])
            t_min = df['timestamp'].min()
            t_max = df['timestamp'].max()
            duration_sec = t_max - t_min
            
            print(f"\nFile: {file_name}")
            print(f"  -> Min Timestamp: {t_min:.4f} ({pd.to_datetime(t_min, unit='s', utc=True)})")
            print(f"  -> Max Timestamp: {t_max:.4f} ({pd.to_datetime(t_max, unit='s', utc=True)})")
            print(f"  -> Total Replayed Duration: {duration_sec:.2f} seconds ({duration_sec/60:.2f} minutes or {duration_sec/3600:.2f} hours)")
        except Exception as e:
            print(f"[ERROR] Failed reading {file_name}: {e}")

if __name__ == "__main__":
    inspect_all_files()
