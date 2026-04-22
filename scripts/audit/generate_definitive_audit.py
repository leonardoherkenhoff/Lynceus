#!/usr/bin/env python3
"""
Lynceus Definitive Auditor (v1.0)
---------------------------------
Aggregates telemetric and resource metrics from all experimental phases.
"""

import os
import json
import pandas as pd
import glob

BASE_DIR = "/opt/eBPFNetFlowLyzer"
INTERIM_DIR = os.path.join(BASE_DIR, "data/interim/EBPF_RAW")
PROCESSED_DIR = os.path.join(BASE_DIR, "data/processed/EBPF")

def audit_extraction():
    print("\n" + "="*60)
    print(f"{'PHASE 2: EXTRACTION PERFORMANCE AUDIT':^60}")
    print("="*60)
    
    # Try both interim and processed in case of cleanup
    summaries = glob.glob(os.path.join(INTERIM_DIR, "**", "summary.json"), recursive=True)
    summaries += glob.glob(os.path.join(PROCESSED_DIR, "**", "summary.json"), recursive=True)
    
    if not summaries:
        print("⚠️  No extraction summaries found.")
        return

    results = []
    seen = set()
    for s in summaries:
        try:
            with open(s, 'r') as f:
                data = json.load(f)
                if data['experiment'] not in seen:
                    results.append(data)
                    seen.add(data['experiment'])
        except Exception: pass
    
    df = pd.DataFrame(results)
    if not df.empty:
        print(df[['experiment', 'packets_sent', 'pps', 'time_seconds']].to_string(index=False))

def audit_resources():
    print("\n" + "="*60)
    print(f"{'PHASE 3: COMPUTATIONAL COST AUDIT':^60}")
    print("="*60)
    
    metrics = glob.glob(os.path.join(INTERIM_DIR, "**", "resource_metrics.csv"), recursive=True)
    metrics += glob.glob(os.path.join(PROCESSED_DIR, "**", "resource_metrics.csv"), recursive=True)
        
    if not metrics:
        print("⚠️  No resource consumption metrics found.")
        return

    for m in metrics:
        try:
            df = pd.read_csv(m)
            exp_name = os.path.relpath(os.path.dirname(m), BASE_DIR)
            print(f"\n🚀 Experiment: {exp_name}")
            print(f"   - Peak CPU: {df['cpu_percent'].max():.2f}%")
            print(f"   - Peak RAM: {df['ram_mb'].max():.2f} MB")
            print(f"   - Avg RAM:  {df['ram_mb'].mean():.2f} MB")
        except Exception: pass

def main():
    print("\n" + "#"*60)
    print(f"{'LYNCEUS DEFINITIVE EXPERIMENT AUDIT':^60}")
    print("#"*60)
    audit_extraction()
    audit_resources()
    print("\n" + "#"*60)
    print(f"{'AUDIT COMPLETE':^60}")
    print("#"*60 + "\n")

if __name__ == "__main__":
    main()
