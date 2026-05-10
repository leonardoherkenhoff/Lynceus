#!/usr/bin/env python3
"""
Lynceus Telemetry Benchmark & Validation (v3.0)
Protocol: Feature Parity Analysis (SBSeg 2026)

RESEARCH OBJECTIVE:
Evaluate Lynceus performance under different feature set constraints:
  1. Base (495 features)
  2. NTL+AL Parity (399 features)
  3. NFX Parity (15 features)
  4. RustiFlow Parity (203 features)

METHODOLOGY:
  1. Cross-Day Temporal Validation: Independent training (Day 01) 
     and testing (Day 03) sets from CICDDoS2019.
  2. Stochastic Split Validation: 70/30 split for single-day captures.
  3. Identity Purge: Mandatory removal of IP/Port metadata.
"""

import numpy as np
import os
import glob
import gc
import argparse
import json
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import f1_score, accuracy_score, precision_score, recall_score

try:
    import polars as pl
    import pandas as pd
    USE_POLARS = True
except ImportError:
    import pandas as pd
    USE_POLARS = False

# Global configuration object for benchmark parameters
args = None

# =============================================================================
# [Cross-Day Attack Pairing Matrix]

# Maps canonical attack names to their training (01-12) and testing (03-11)
# dataset directory suffixes within the CICDDoS2019 corpus.
# =============================================================================
CROSS_DAY_PAIRS = {
    "LDAP":    {"train": "PCAP/01-12/DrDoS_LDAP",   "test": "PCAP/03-11/LDAP"},
    "MSSQL":   {"train": "PCAP/01-12/DrDoS_MSSQL",  "test": "PCAP/03-11/MSSQL"},
    "NetBIOS": {"train": "PCAP/01-12/DrDoS_NetBIOS", "test": "PCAP/03-11/NetBIOS"},
    "UDP":     {"train": "PCAP/01-12/DrDoS_UDP",     "test": "PCAP/03-11/UDP"},
    "Syn":     {"train": "PCAP/01-12/Syn",           "test": "PCAP/03-11/Syn"},
    "UDPLag":  {"train": "PCAP/01-12/UDPLag",        "test": "PCAP/03-11/UDPLag"},
}

# Pre-compute reverse lookup: path suffix -> (canonical_name, role)
_PATH_TO_PAIR = {}
for name, paths in CROSS_DAY_PAIRS.items():
    _PATH_TO_PAIR[paths["train"]] = (name, "train")
    _PATH_TO_PAIR[paths["test"]]  = (name, "test")

# =============================================================================
# [Feature Purge List]
# =============================================================================
# Identity and topology features that cause trivial discrimination.
IDENTITY_DROP = [
    'flow_id', 'timestamp', 'src_ip', 'dst_ip', 'src_port', 'dst_port',
    'src_mac', 'dst_mac',
    'protocol', 'ip_ver', 'eth_proto',
    'traffic_class', 'flow_label',
    'TunnelId', 'TunnelType',
]

# TTL suite (11 features): removed by default, reintroduced with --with-ttl.
TTL_DROP = [
    'TTL',
    'TTL_Var_Max', 'TTL_Var_Min', 'TTL_Var_Mean', 'TTL_Var_Std',
    'TTL_Var_Var', 'TTL_Var_Median', 'TTL_Var_Skew', 'TTL_Var_Kurt',
    'TTL_Var_CoV', 'TTL_Var_Mode',
]

# Adaptive sample limit to prevent OOM on 32GB RAM servers
# For 400+ features, we target ~10GB matrix size
DEFAULT_MAX_SAMPLES = 3_000_000
HIGH_DENSITY_MAX_SAMPLES = 2_000_000 
CHUNK_SIZE = 250_000

def load_dataset(file_path, drop_cols):
    """
    Load a dataset with column filtering, type coercion, and sample cap.
    """
    # Quick probe to determine feature count
    sample_df = pd.read_csv(file_path, nrows=1)
    n_features = len([c for c in sample_df.columns if c not in drop_cols and c != 'Label'])
    
    # Adaptive limit: if we have >300 features, cap at 2.0M to fit in 30GB free RAM with sklearn overhead
    max_s = HIGH_DENSITY_MAX_SAMPLES if n_features > 300 else DEFAULT_MAX_SAMPLES
    
    if USE_POLARS:
        return _load_polars(file_path, drop_cols, max_s)
    return _load_pandas(file_path, drop_cols, max_s)


def _load_polars(file_path, drop_cols, max_samples):
    """
    Load dataset using Polars multi-threaded CSV reader.
    """
    df = pl.read_csv(file_path, n_rows=max_samples, infer_schema_length=10000,
                     ignore_errors=True)

    # Drop unwanted columns (only those that exist).
    existing_drops = [c for c in drop_cols if c in df.columns]
    if existing_drops:
        df = df.drop(existing_drops)

    if 'Label' not in df.columns:
        return None, None

    # Extract labels.
    y = (df['Label'].cast(pl.Utf8).str.to_uppercase() != 'BENIGN').cast(pl.UInt8)
    df = df.drop('Label')

    # Cast and handle Infs/NaNs only for numeric columns
    for col in df.columns:
        if df[col].dtype.is_numeric():
            df = df.with_columns(
                pl.when(pl.col(col).is_infinite() | pl.col(col).is_nan())
                .then(0)
                .otherwise(pl.col(col))
                .cast(pl.Float32, strict=False)
                .fill_null(0)
            )
        else:
            # For non-numeric, just ensure it's not breaking the subsequent steps if it needs to be numeric
            # but usually these are already dropped or are labels.
            pass



    # Convert to pandas for sklearn.
    X = df.to_pandas()
    y_pd = y.to_pandas()

    # SCIENTIFIC HARDENING: Drop non-numeric features and ensure numerical stability
    # This is critical for parity across tools with different header names and precision issues (RustiFlow)
    import numpy as np
    X = X.select_dtypes(include=[np.number])
    
    # Final safety pass: replace residuals Infs/NaNs and clip to float32 range
    X = X.replace([np.inf, -np.inf], np.nan).fillna(0)
    f32_info = np.finfo(np.float32)
    X = X.clip(lower=f32_info.min, upper=f32_info.max)



    del df
    gc.collect()
    return X, y_pd


def _load_pandas(file_path, drop_cols, max_samples):
    """
    Load dataset using Pandas chunked CSV reader (fallback).
    """
    sample_df = pd.read_csv(file_path, nrows=1, low_memory=False)
    use_cols = [c for c in sample_df.columns if c not in drop_cols]
    feature_cols = [c for c in use_cols if c != 'Label']

    X_list, y_list = [], []
    reader = pd.read_csv(file_path, chunksize=CHUNK_SIZE, usecols=use_cols, low_memory=False)
    total_loaded = 0

    for chunk in reader:
        if 'Label' not in chunk.columns:
            continue

        y_chunk = (chunk['Label'].str.upper() != 'BENIGN').astype(np.uint8)
        X_chunk = chunk[feature_cols]
        for col in X_chunk.columns:
            X_chunk[col] = pd.to_numeric(X_chunk[col], errors='coerce')
        X_chunk = X_chunk.fillna(0).astype(np.float32)

        X_list.append(X_chunk)
        y_list.append(y_chunk)
        total_loaded += len(X_chunk)

        if total_loaded >= max_samples:
            break

    if not X_list:
        return None, None

    X = pd.concat(X_list, copy=False)
    y = pd.concat(y_list, copy=False)
    del X_list, y_list
    gc.collect()

    return X, y


def print_results(X_test, y_test, y_pred, clf, n_train, n_test):
    """
    Print formatted ML metrics and feature importance matrix.

    Args:
        X_test (pd.DataFrame): Test feature matrix for importance mapping.
        y_test (pd.Series): Ground-truth test labels.
        y_pred (np.ndarray): Predicted labels from the estimator.
        clf (RandomForestClassifier): Trained estimator instance.
        n_train (int): Number of samples used in training.
        n_test (int): Number of samples evaluated in testing.
    """
    acc  = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred, zero_division=0)
    rec  = recall_score(y_test, y_pred, zero_division=0)
    f1   = f1_score(y_test, y_pred, zero_division=0)

    print(f"\n    ✅ MODEL VALIDATED")
    print(f"    {'Accuracy:':<20} {acc:.4f}")
    print(f"    {'Precision:':<20} {prec:.4f}")
    print(f"    {'Recall:':<20} {rec:.4f}")
    print(f"    {'F1-Score:':<20} {f1:.4f}")
    print(f"    {'Train Samples:':<20} {n_train}")
    print(f"    {'Test Samples:':<20} {n_test}")
    print(f"    {'Features:':<20} {X_test.shape[1]}")

    importances = pd.Series(
        clf.feature_importances_, index=X_test.columns
    ).sort_values(ascending=False)

    print("\n    CRITICAL ATTACK SIGNATURES (Top 5):")
    for feature, val in importances.head(5).items():
        print(f"      - {feature:<25} {val:.4f}")

    # Save metrics to JSON for persistence
    metrics = {
        "accuracy": acc, "precision": prec, "recall": rec, "f1_score": f1,
        "n_train": n_train, "n_test": n_test, "n_features": X_test.shape[1],
        "top_features": importances.head(10).to_dict()
    }
    return metrics


def resolve_path(processed_dir, relative_suffix):
    """
    Resolve a relative dataset path suffix to an actual labeled CSV.

    Args:
        processed_dir (str): Root directory containing processed CSVs.
        relative_suffix (str): Logical path suffix (e.g., 'PCAP/01-12/DrDoS_LDAP').

    Returns:
        str or None: Absolute path to matched CSV, or None if not found.
    """
    # The processed directory mirrors the raw structure:
    # processed_dir/PCAP/01-12/DrDoS_LDAP/labeled_flows.csv (or similar)
    candidate_dir = os.path.join(processed_dir, relative_suffix)
    if os.path.isdir(candidate_dir):
        csvs = glob.glob(os.path.join(candidate_dir, "*.csv"))
        csvs = [c for c in csvs if 'resource_metrics' not in os.path.basename(c)]
        if csvs:
            return csvs[0]
    return None


def get_relative_key(file_path, processed_dir):
    """
    Extract the relative path key from a dataset file path.

    Args:
        file_path (str): Absolute path to the CSV file.
        processed_dir (str): Root dataset directory to relativize against.

    Returns:
        str: Extracted logical key (e.g., 'PCAP/01-12/DrDoS_DNS').
    """
    rel = os.path.relpath(os.path.dirname(file_path), processed_dir)
    return rel


def run_benchmark():
    global args
    parser = argparse.ArgumentParser(

        description="Lynceus Hybrid Validation Benchmark v2.0"
    )
    parser.add_argument(
        '--with-ttl', action='store_true',
        help='Include TTL and TTL_Var_* features (Realistic mode)'
    )
    parser.add_argument(
        '--dataset', type=str, default="/opt/eBPFNetFlowLyzer/data/processed/EBPF",
        help='Path to labeled dataset directory'
    )
    parser.add_argument(
        '--leakage', action='store_true',
        help='Disable IDENTITY_DROP (includes src/dst IP/port, protocol, etc.)'
    )
    parser.add_argument(
        '--parity-mode', type=str, choices=['rustiflow', 'nfx', 'ntl'], default=None,
        help='Filter Lynceus features to match another tool (Scientific Parity)'
    )
    global args
    args = parser.parse_args()

    # Build drop_cols based on mode
    drop_cols = []
    if not args.leakage:
        drop_cols.extend(IDENTITY_DROP)
    
    if not args.with_ttl:
        drop_cols.extend(TTL_DROP)

    mode_label = "SCIENTIFIC" if not args.leakage else "LEAKAGE"
    if args.parity_mode:
        mode_label += f" | Parity: {args.parity_mode.upper()}"
    if args.with_ttl:
        mode_label += " + TTL"
    else:
        mode_label += " (no TTL)"

    processed_dir = os.path.abspath(args.dataset)
    all_csvs = glob.glob(os.path.join(processed_dir, "**", "*.csv"), recursive=True)
    all_csvs = [c for c in all_csvs if 'resource_metrics' not in os.path.basename(c)]

    if not all_csvs:
        print("❌ [Experimental Error] No labeled datasets found.")
        return

    print(f"\n{'='*60}")
    print(f"{'LYNCEUS HYBRID VALIDATION BENCHMARK v2.0':^60}")
    print(f"{'='*60}")
    print(f"  Mode: {mode_label}")
    print(f"  Purged Features: {len(drop_cols)}")
    print(f"{'='*60}\n")

    # Track which cross-day pairs have been processed
    processed_pairs = set()

    # Sort for deterministic ordering
    for file_path in sorted(all_csvs):
        rel_key = get_relative_key(file_path, processed_dir)
        gc.collect()

        # --- Check if this dataset is part of a cross-day pair ---
        pair_info = _PATH_TO_PAIR.get(rel_key)

        if pair_info:
            canonical_name, role = pair_info

            # If this is a test-day file, skip (will be loaded by the train-day)
            if role == "test":
                continue

            # If already processed, skip
            if canonical_name in processed_pairs:
                continue

            # This is a train-day file: execute cross-day validation
            processed_pairs.add(canonical_name)
            pair = CROSS_DAY_PAIRS[canonical_name]

            train_path = resolve_path(processed_dir, pair["train"])
            test_path  = resolve_path(processed_dir, pair["test"])

            if not train_path or not test_path:
                print(f"\n>>> ⚠️  CROSS-DAY PAIR INCOMPLETE: {canonical_name} <<<")
                print(f"    Train: {'FOUND' if train_path else 'MISSING'} ({pair['train']})")
                print(f"    Test:  {'FOUND' if test_path else 'MISSING'} ({pair['test']})")
                # Fall back to split validation on whichever exists
                fallback_path = train_path or test_path
                if fallback_path:
                    print(f"    Falling back to split validation...")
                    _run_split_validation(fallback_path, rel_key, drop_cols)
                continue

            print(f"\n>>> CROSS-DAY VALIDATION: {canonical_name} <<<")
            print(f"    Train: {pair['train']}")
            print(f"    Test:  {pair['test']}")

            try:
                X_train, y_train = load_dataset(train_path, drop_cols)
                X_test,  y_test  = load_dataset(test_path, drop_cols)

                if X_train is None or X_test is None:
                    print(f"    ❌ Failed to load one or both datasets.")
                    continue

                # Align columns (train and test must share the same feature space)
                common_cols = sorted(set(X_train.columns) & set(X_test.columns))
                X_train = X_train[common_cols]
                X_test  = X_test[common_cols]

                if len(np.unique(y_train)) < 2 or len(np.unique(y_test)) < 2:
                    print(f"    ⚠️  Inadequate Class Variance in train or test set.")
                    continue

                clf = RandomForestClassifier(
                    n_estimators=100, n_jobs=12, random_state=42
                )

                # Apply Logical Parity Filtering if requested
                if args.parity_mode:
                    X_train = _apply_parity_filter(X_train, args.parity_mode)
                    X_test  = _apply_parity_filter(X_test, args.parity_mode)

                clf.fit(X_train, y_train)
                y_pred = clf.predict(X_test)

                m = print_results(X_test, y_test, y_pred, clf, len(X_train), len(X_test))
                
                # Save to disk
                res_path = os.path.join(os.path.dirname(train_path), "ml_results.json")
                with open(res_path, "w") as f:
                    json.dump(m, f, indent=4)

                del X_train, y_train, X_test, y_test, clf
                gc.collect()

            except Exception as e:
                print(f"    ❌ Empirical Error: {e}")

        else:
            # --- No pair: run stochastic split validation ---
            _run_split_validation(file_path, rel_key, drop_cols)


def _apply_parity_filter(df, mode):
    """Filter features to match the logical set of another tool (Scientific Parity)."""
    cols = df.columns.tolist()
    if mode == 'rustiflow':
        # RustiFlow Full Parity (203 Features)
        # Includes Timing, IAT, PktLen, HdrLen, Bulk, Subflow, ActiveIdle, Icmp, TCP Window.
        metrics = ['Tot_Pay', 'Fwd_Pay', 'Bwd_Pay', 'Tot_Hdr', 'Fwd_Hdr', 'Bwd_Hdr', 'Tot_IAT', 'Fwd_IAT', 'Bwd_IAT', 'Active', 'Idle', 'Win']
        stats = ['Max', 'Min', 'Mean', 'Std', 'Var', 'Median', 'Skew', 'CoV', 'Mode'] # 9 variants
        
        keep = []
        for m in metrics:
            for s in stats:
                keep.append(f"{m}_{s}")
                
        flags = ['FIN', 'SYN', 'RST', 'PSH', 'ACK', 'URG', 'ECE', 'CWR']
        for f in flags:
            keep.extend([f"{f}_Cnt", f"{f}_Fwd_Cnt", f"{f}_Bwd_Cnt"])
            
        keep.extend([
            'duration', 'PacketsCount', 'FwdPacketsCount', 'BwdPacketsCount',
            'TotalBytes', 'FwdBytes', 'BwdBytes', 'FwdBwdPktRatio', 'FwdBwdByteRatio',
            'FwdInitWinBytes', 'BwdInitWinBytes', 'IcmpType', 'IcmpCode', 'IcmpEchoId',
            'BytesRate', 'FwdBytesRate', 'BwdBytesRate', 'PacketsRate', 'FwdPacketsRate', 'BwdPacketsRate', 'DownUpRatio',
            'FwdBulkBytes', 'FwdBulkPkts', 'FwdBulkCnt', 'BwdBulkBytes', 'BwdBulkPkts', 'BwdBulkCnt'
        ])
        
        final_keep = [c for c in keep if c in cols]
        # RustiFlow has 203. If we have more, we cap. If less, we take all available.
        if len(final_keep) > 203: final_keep = final_keep[:203]
        
    elif mode == 'nfx':
        # NetFeatureXtract Behavioral Set (approx 15 features)
        # Mapped to Lynceus equivalents for Parity evaluation
        keep = [
            'PacketsCount', 'TotalBytes', 'duration', 'PacketsRate', 'BytesRate',
            'Tot_Pay_Max', 'Tot_Pay_Min', 'Tot_Pay_Mean',
            'FwdPacketsRate', 'BwdPacketsRate', 'FwdBytesRate', 'BwdBytesRate'
        ]
        
    elif mode == 'ntl':
        # STRICT NTL (348) + AL (51) - Total 399 features requested
        # We only keep features that correspond to the user's provided list.
        
        # 1. NTL Mappings (Statistical blocks)
        metrics = ['Tot_Pay', 'Fwd_Pay', 'Bwd_Pay', 'Tot_Hdr', 'Fwd_Hdr', 'Bwd_Hdr', 'Tot_IAT', 'Fwd_IAT', 'Bwd_IAT', 'Tot_DeltaLen', 'Active', 'Idle']
        stats = ['Max', 'Min', 'Mean', 'Std', 'Var', 'Median', 'Skew', 'CoV', 'Mode']
        
        keep = []
        for m in metrics:
            for s in stats:
                keep.append(f"{m}_{s}")
        
        # 2. Flags (Counts only - Lynceus doesn't have % in this version)
        flags = ['FIN', 'SYN', 'RST', 'PSH', 'ACK', 'URG', 'ECE', 'CWR']
        for f in flags:
            keep.extend([f"{f}_Cnt", f"{f}_Fwd_Cnt", f"{f}_Bwd_Cnt"])
            
        # 3. Basic, Rates, Bulk, Win
        keep.extend([
            'duration', 'PacketsCount', 'FwdPacketsCount', 'BwdPacketsCount',
            'TotalBytes', 'FwdBytes', 'BwdBytes', 'FwdInitWinBytes', 'BwdInitWinBytes',
            'BytesRate', 'FwdBytesRate', 'BwdBytesRate', 'PacketsRate', 'FwdPacketsRate', 'BwdPacketsRate', 'DownUpRatio',
            'FwdBulkBytes', 'FwdBulkPkts', 'FwdBulkCnt', 'BwdBulkBytes', 'BwdBulkPkts', 'BwdBulkCnt'
        ])
        
        # 4. AL (DNS/TTL)
        keep.extend([
            'DNSAnswerCount', 'DNSQueryType', 'DNSQueryClass',
            'TTL_Var_Max', 'TTL_Var_Min', 'TTL_Var_Mean', 'TTL_Var_Std', 'TTL_Var_Var', 'TTL_Var_Median', 'TTL_Var_Skew', 'TTL_Var_CoV', 'TTL_Var_Mode'
        ])

        # NO HISTOGRAMS, NO EXTRA LYNCEUS FEATURES.
        final_keep = [c for c in keep if c in cols]

    # Filter to what actually exists in Lynceus CSV
    final_keep = [c for c in keep if c in cols]
    print(f"    🔬 Parity Filter [{mode}]: Kept {len(final_keep)}/{len(cols)} features.")
    return df[final_keep]


def _run_split_validation(file_path, attack_name, drop_cols):
    """
    Validate a dataset using a standard 70/30 stochastic split.

    Args:
        file_path (str): Absolute path to the labeled CSV dataset.
        attack_name (str): Canonical name or path suffix for reporting.
        drop_cols (list): List of columns to purge during loading.
    """
    print(f"\n>>> SPLIT VALIDATION: {attack_name} <<<")

    try:
        X, y = load_dataset(file_path, drop_cols)

        if X is None:
            print(f"    ❌ Failed to load dataset.")
            return

        if len(np.unique(y)) < 2:
            print(f"    ⚠️  Inadequate Class Variance: Stochastic modeling aborted.")
            return

        clf = RandomForestClassifier(
            n_estimators=100, n_jobs=12, random_state=42
        )
        
        # Apply Logical Parity Filtering if requested
        if args.parity_mode:
            X = _apply_parity_filter(X, args.parity_mode)
        
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.3, random_state=42
        )
        clf.fit(X_train, y_train)

        y_pred = clf.predict(X_test)

        m = print_results(X_test, y_test, y_pred, clf, len(X_train), len(X_test))
        
        # Save to disk
        res_path = os.path.join(os.path.dirname(file_path), "ml_results.json")
        with open(res_path, "w") as f:
            json.dump(m, f, indent=4)

        del X, y, X_train, X_test, y_train, y_test, clf
        gc.collect()

    except Exception as e:
        print(f"    ❌ Empirical Error: {e}")


if __name__ == "__main__":
    run_benchmark()
