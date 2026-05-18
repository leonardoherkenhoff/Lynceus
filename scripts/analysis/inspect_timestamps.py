#!/usr/bin/env python3
"""
Inspect Timestamps in Extracted Telemetry
Allows the user to check the exact format of the timestamp column in their CSVs.
"""

import os
import glob
import pandas as pd

PROCESSED_DIR = "/opt/eBPFNetFlowLyzer/data/processed/EBPF"
INTERIM_DIR = "/opt/eBPFNetFlowLyzer/data/interim/EBPF_RAW"

def inspect_file(file_path):
    print(f"\n==================================================")
    print(f"INSPECTING: {os.path.basename(file_path)}")
    print(f"==================================================")
    
    try:
        # Load first 5 rows
        df = pd.read_csv(file_path, nrows=5)
        
        # Check column names
        ts_cols = [c for c in df.columns if 'time' in c.lower()]
        print(f"[COLUMNS] Found time-related columns: {ts_cols}")
        print(f"[SCHEMA] All columns: {list(df.columns[:10])}... ({len(df.columns)} total)")
        
        if not ts_cols:
            print("[ERROR] No timestamp column found!")
            return
            
        ts_col = ts_cols[0]
        print(f"\n[SAMPLES] First 5 raw values of '{ts_col}':")
        for i, val in enumerate(df[ts_col]):
            print(f"  {i}: {val} (Type: {type(val).__name__})")
            
            # Try parsing as float (epoch)
            try:
                float_val = float(val)
                # Convert to UTC datetime
                utc_dt = pd.to_datetime(float_val, unit='s', utc=True)
                # Convert to EST (GMT-4)
                est_dt = utc_dt.tz_convert('America/New_York')
                print(f"    -> Parsed as Unix Epoch: UTC={utc_dt} | EST (GMT-4)={est_dt}")
            except Exception as e_float:
                # Try parsing as datetime string
                try:
                    dt = pd.to_datetime(val)
                    print(f"    -> Parsed as DateTime String: {dt}")
                except Exception as e_str:
                    print(f"    -> Failed parsing: Float={e_float} | String={e_str}")
                    
    except Exception as e:
        print(f"[ERROR] Failed reading file: {e}")

def main():
    # Try finding files in processed first
    files = glob.glob(os.path.join(PROCESSED_DIR, "*.csv"))
    if not files:
        # Try interim
        files = glob.glob(os.path.join(INTERIM_DIR, "**", "*.csv"), recursive=True)
        
    if not files:
        print(f"[ERROR] No CSV files found in {PROCESSED_DIR} or {INTERIM_DIR}.")
        print("Please ensure your extraction pipeline has generated CSV files.")
        return
        
    # Inspect first found file
    inspect_file(files[0])

if __name__ == "__main__":
    main()
