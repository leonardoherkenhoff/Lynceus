#!/usr/bin/env python3
"""
Lynceus Research Pipeline - Stochastic Performance Validator (v1.0)
-----------------------------------------------------------
Scientific Milestone: v1.0 (The Definitive Foundation)

Research Objective:
Evaluates detection convergence and classification fidelity of eBPF-extracted 
features via Stochastic Modeling (Random Forest).

Methodology:
1. Feature Pruning: Removal of identifiers (IP, MAC, Port) to ensure generalization.
2. Binary Classification: Stochastic attribution of Benign vs. Malicious entropy.
3. Feature Ranking: Identifying critical attack signatures via Mean Decrease Impurity.

Validation Metrics:
- F1-Score: Harmonic mean of precision and recall (robust for imbalanced data).
- Confusion Matrix: Empirical distribution of classification errors.
"""

import pandas as pd
import numpy as np
import os
import glob
import gc
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import f1_score, classification_report

def process_dataframe(df):
    """
    Standardizes feature selection for supervised learning.
    Ensures identifiers are excluded to avoid overfitting on network topology.
    """
    drop_cols = ['flow_id', 'timestamp', 'src_ip', 'dst_ip', 'src_port', 'dst_port', 'Label']
    if 'Label' not in df.columns: return None, None
        
    y = df['Label']
    X = df.drop(columns=[c for c in drop_cols if c in df.columns])
    X = X.apply(pd.to_numeric, errors='coerce').fillna(0)
    y_binary = y.apply(lambda x: 0 if str(x).upper() == 'BENIGN' else 1)
    return X, y_binary

def run_benchmark():
    processed_dir = "/opt/eBPFNetFlowLyzer/data/processed/EBPF"
    processed_files = glob.glob(os.path.join(processed_dir, "**", "*.csv"), recursive=True)
    
    if not processed_files:
        print("❌ [Experimental Error] No labeled datasets found. Pipeline sequence failure.")
        return

    print(f"\n{'='*60}")
    print(f"{'LYNCEUS STOCHASTIC VALIDATION (v1.0)':^60}")
    print(f"{'='*60}\n")

    for file_path in processed_files:
        if os.path.basename(file_path).startswith("resource_metrics"): continue
        attack_name = os.path.basename(file_path).replace('labeled_', '').replace('.csv', '')
        gc.collect() 
        
        print(f"\n>>> STATISTICAL CONVERGENCE TEST: {attack_name} <<<")
        try:
            X_list, y_list = [], []
            # Memory-aware ingestion for high-entropy datasets.
            reader = pd.read_csv(file_path, chunksize=200000, low_memory=False)
            for chunk in reader:
                X_chunk, y_chunk = process_dataframe(chunk)
                if X_chunk is not None:
                    X_list.append(X_chunk)
                    y_list.append(y_chunk)
                if len(X_list) >= 10: break 
            
            if not X_list: continue
            X, y = pd.concat(X_list), pd.concat(y_list)
            
            if len(y.unique()) < 2: 
                print(f"    ⚠️  Inadequate Class Variance: Stochastic modeling aborted.")
                continue

            # Research-grade Split (70/30) with reproducible seed.
            X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)
            clf = RandomForestClassifier(n_estimators=100, n_jobs=-1, random_state=42)
            clf.fit(X_train, y_train)
            
            y_pred = clf.predict(X_test)
            f1 = f1_score(y_test, y_pred)
            
            print(f"\n    ✅ CONVERGENCE ACHIEVED")
            print(f"    {'F1-Score:':<20} {f1:.4f}")
            print(f"    {'Cardinality:':<20} {len(X)}")
            print(f"    {'Dimensionality:':<20} {X.shape[1]}")
            
            importances = pd.Series(clf.feature_importances_, index=X.columns).sort_values(ascending=False)
            print("\n    CRITICAL FEATURE IMPORTANCE (Top 5):")
            for feature, val in importances.head(5).items():
                print(f"      - {feature:<25} {val:.4f}")

        except Exception as e:
            print(f"    ❌ Empirical Error: {e}")

    print(f"\n{'='*60}")
    print(f"{'BENCHMARK COMPLETE':^60}")
    print(f"{'='*60}\n")

if __name__ == "__main__":
    run_benchmark()
