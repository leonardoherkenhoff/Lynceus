#!/usr/bin/env python3
"""
Lynceus Research Pipeline - Stochastic Performance Validator (v1.2)
-----------------------------------------------------------
Scientific Milestone: v1.0 (The Definitive Foundation)

Research Objective:
Optimized stochastic validation using Random Forest. Maintains the original 
methodology (in-memory training on 2M samples) with extreme memory efficiency.
"""

import pandas as pd
import numpy as np
import os
import glob
import gc
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import f1_score

def run_benchmark():
    processed_dir = "/opt/eBPFNetFlowLyzer/data/processed/EBPF"
    processed_files = glob.glob(os.path.join(processed_dir, "**", "*.csv"), recursive=True)
    
    if not processed_files:
        print("❌ [Experimental Error] No labeled datasets found. Pipeline sequence failure.")
        return

    print(f"\n{'='*60}")
    print(f"{'LYNCEUS STOCHASTIC VALIDATION (OPTIMIZED)':^60}")
    print(f"{'='*60}\n")

    for file_path in processed_files:
        if os.path.basename(file_path).startswith("resource_metrics"): continue
        
        # Enhanced Attack Taxonomy: Path-based identification (e.g. PCAP/01-12/DrDoS_DNS)
        parts = file_path.split(os.sep)
        try:
            ebpf_idx = parts.index("EBPF")
            attack_name = "/".join(parts[ebpf_idx+1:-1])
            if not attack_name: attack_name = os.path.basename(file_path)
        except ValueError:
            attack_name = os.path.basename(file_path).replace('labeled_', '').replace('.csv', '')
            
        print(f"\n>>> VALIDATING DETECTION: {attack_name} <<<")
        gc.collect()

        try:
            # OPTIMIZATION Phase 1: Filter columns at I/O level
            sample_df = pd.read_csv(file_path, nrows=1, low_memory=False)
            drop_cols = ['flow_id', 'timestamp', 'src_ip', 'dst_ip', 'src_port', 'dst_port']
            use_cols = [c for c in sample_df.columns if c not in drop_cols]
            
            X_list, y_list = [], []
            # Methodology: Consistent 2,000,000 samples for high-fidelity comparison
            reader = pd.read_csv(file_path, chunksize=200000, usecols=use_cols, low_memory=False)
            
            total_loaded = 0
            for chunk in reader:
                if 'Label' not in chunk.columns: continue
                
                # OPTIMIZATION Phase 2: Downcasting to float32 and uint8
                # This reduces the matrix memory footprint from ~8GB to ~4GB.
                y_chunk = (chunk['Label'].str.upper() != 'BENIGN').astype(np.uint8)
                X_chunk = chunk.drop(columns=['Label'])
                X_chunk = X_chunk.apply(pd.to_numeric, errors='coerce').fillna(0).astype(np.float32)
                
                X_list.append(X_chunk)
                y_list.append(y_chunk)
                total_loaded += len(X_chunk)
                
                if total_loaded >= 2000000: break 
            
            if not X_list: continue
            X = pd.concat(X_list, copy=False)
            y = pd.concat(y_list, copy=False)
            
            # Explicit cleanup of temporary lists
            del X_list, y_list
            gc.collect()

            if len(np.unique(y)) < 2: 
                print(f"    ⚠️  Inadequate Class Variance: Stochastic modeling aborted.")
                continue

            # Research-grade Split (70/30) with reproducible seed.
            X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)
            
            # OPTIMIZATION Phase 3: Hardware-capping parallelism (n_jobs=12)
            # Prevents OOM caused by excessive worker overhead on a 48-core/30GB machine.
            clf = RandomForestClassifier(n_estimators=100, n_jobs=12, random_state=42)
            clf.fit(X_train, y_train)
            
            y_pred = clf.predict(X_test)
            f1 = f1_score(y_test, y_pred)
            
            print(f"\n    ✅ MODEL VALIDATED")
            print(f"    {'F1-Score:':<20} {f1:.4f}")
            print(f"    {'Samples:':<20} {len(X)}")
            print(f"    {'Features:':<20} {X.shape[1]}")
            
            importances = pd.Series(clf.feature_importances_, index=X.columns).sort_values(ascending=False)
            print("\n    CRITICAL ATTACK SIGNATURES (Top 5):")
            for feature, val in importances.head(5).items():
                print(f"      - {feature:<25} {val:.4f}")

            # Total cleanup before next iteration
            del X, y, X_train, X_test, y_train, y_test, clf
            gc.collect()

        except Exception as e:
            print(f"    ❌ Empirical Error during validation: {e}")

    print(f"\n{'='*60}\n")

if __name__ == "__main__":
    run_benchmark()
