#!/usr/bin/env python3
"""
Lynceus Segregated Dataset Validation Protocol (CIC-IDS-2017)
Standard: Scientific Parity & Peer-Review Standard
"""

import os
import glob
import gc
import json
import argparse
import warnings
warnings.filterwarnings("ignore")
import numpy as np
import polars as pl
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, f1_score
from joblib import parallel_backend

# --- Configuration ---
PROCESSED_DIR = "/opt/lynceus/data/processed/EBPF"

# Identity Purge list to prevent trivial classification leaks
IDENTITY_DROP = [
    'flow_id', 'timestamp', 'src_ip', 'dst_ip', 'src_port', 'dst_port',
    'src_mac', 'dst_mac', 'protocol', 'ip_ver', 'eth_proto',
    'traffic_class', 'flow_label', 'TunnelId', 'TunnelType'
]

def run_split_validation(file_path, args):
    """
    Executes a standard 70/30 stratified holdout split validation on a single partition file,
    matching the segregated evaluation protocol of NTL and RustiFlow papers.
    """
    file_name = os.path.basename(file_path)
    print(f"\n>>> EVALUATING PARTITION: {file_name} <<<", flush=True)
    
    # 1. Read schema and dynamically prune identity/topology features
    schema = pl.read_csv(file_path, n_rows=0).schema
    feature_cols = [c for c in schema.keys() if c not in IDENTITY_DROP and c != "Label"]
    num_features = len(feature_cols)
    
    # 2. Probe partition length
    total_rows = pl.scan_csv(file_path).select(pl.len()).collect().item()
    print(f"[INFO] Partition sequence length: {total_rows} samples.", flush=True)
    
    # 3. Stream data into memory using projection and memory-optimal float32 casting
    print(f"[INFO] Allocating contiguous memory matrices: {total_rows}x{num_features} (float32).", flush=True)
    
    df = pl.scan_csv(file_path, infer_schema_length=10000) \
           .select(feature_cols + ["Label"]) \
           .with_columns([
               pl.col(c).cast(pl.Float32) for c in feature_cols
           ]) \
           .collect(engine="streaming")
           
    X = df.select(feature_cols).to_numpy()
    labels = df["Label"].to_list()
    
    # Immediately purge Polars DataFrame to free memory
    del df
    gc.collect()
    
    # 4. Map labels to integers and verify class variance
    unique_labels = sorted(list(set(labels)))
    if len(unique_labels) < 2:
        print(f"[WARNING] Skipping partition {file_name} due to inadequate class variance (only 1 class detected).", flush=True)
        return
        
    label_map = {lbl: idx for idx, lbl in enumerate(unique_labels)}
    y = np.array([label_map[l] for l in labels], dtype=np.uint8)
    
    print("[INFO] Empirical class distribution:", flush=True)
    for lbl, idx in label_map.items():
        count = np.sum(y == idx)
        print(f"    {lbl}: {count}", flush=True)
        
    # 5. Execute Stratified Holdout Split (70/30)
    print("[PROCESS] Executing stratified holdout split (70/30)...", flush=True)
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42, stratify=y)
    
    # Purge primary arrays
    del X, y
    gc.collect()
    
    # 6. Train Random Forest (Literature Standard: 100 trees, fully grown unless max_depth is set)
    print("[MODEL] Training Random Forest Classifier (n_estimators=100)...", flush=True)
    clf = RandomForestClassifier(n_estimators=100, n_jobs=-1, max_depth=args.max_depth, random_state=42)
    
    # Use Joblib Threading Backend to completely prevent process duplication OOM
    with parallel_backend('threading', n_jobs=-1):
        clf.fit(X_train, y_train)
        
    # 7. Model Evaluation & Persistent Export
    print("[EVAL] Generating peer-to-peer classification matrix...", flush=True)
    y_pred = clf.predict(X_test)
    
    print("\n" + "="*60, flush=True)
    print(f"       EXPERIMENTAL METRICS REPORT: {file_name}", flush=True)
    print("="*60, flush=True)
    
    report_str = classification_report(y_test, y_pred, target_names=unique_labels, digits=4)
    print(report_str, flush=True)
    
    f1_macro = f1_score(y_test, y_pred, average='macro')
    print(f"-> MACRO F1-SCORE: {f1_macro:.4f}", flush=True)
    print("="*60, flush=True)
    
    # Export metrics to structured JSON and formatted raw Text files
    report_dict = classification_report(y_test, y_pred, target_names=unique_labels, output_dict=True)
    export_data = {
        "partition": file_name,
        "n_samples": total_rows,
        "n_features": num_features,
        "macro_f1": f1_macro,
        "metrics": report_dict
    }
    
    base_output_path = file_path.replace(".csv", "")
    json_path = f"{base_output_path}_results.json"
    txt_path = f"{base_output_path}_report.txt"
    
    with open(json_path, "w") as jf:
        json.dump(export_data, jf, indent=4)
    with open(txt_path, "w") as tf:
        tf.write(report_str + f"\n-> MACRO F1-SCORE: {f1_macro:.4f}\n")
        
    print(f"[EXPORT] Results persisted to:\n    -> {json_path}\n    -> {txt_path}", flush=True)
    
    # Clean up estimator structures
    del X_train, X_test, y_train, y_test, clf
    gc.collect()

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--dir", type=str, default=PROCESSED_DIR, help="Directory containing labeled CSVs")
    parser.add_argument("--max-depth", type=int, default=None, help="Maximum depth of trees (set to prevent OOM, e.g. 15)")
    args = parser.parse_args()
    
    print("=== LYNCEUS SEGREGATED VALIDATION PROTOCOL (CIC-IDS-2017) ===", flush=True)
    
    csv_files = glob.glob(os.path.join(args.dir, "**", "labeled_*.csv"), recursive=True)
    csv_files = sorted([f for f in csv_files if os.path.basename(f) != "labeled_EBPF_RAW.csv"])
    
    if not csv_files:
        print(f"[ERROR] No labeled CSV partition files detected in: {args.dir}", flush=True)
        return
        
    print(f"[INFO] Identified {len(csv_files)} partition files for evaluation.", flush=True)
    
    for f in csv_files:
        run_split_validation(f, args)
        gc.collect()

if __name__ == "__main__":
    main()
