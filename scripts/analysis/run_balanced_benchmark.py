#!/usr/bin/env python3
"""
Lynceus Balanced Sanity Benchmark (50/50 Random Undersampling)
=============================================================
Evaluates feature discriminative power under strictly balanced class
distribution (1:1 Attack:Benign) using RandomUnderSampler.

Methodology replicated from ddos-feature-engineering-benchmark for
direct comparison with CICFlowMeter (76 features) and NTLFlowLyzer
(265 features) results.

Key design decisions:
  1. RandomUnderSampler forces 1:1 ratio on BOTH train and test sets.
  2. class_weight='balanced' is NOT used (redundant with RUS).
  3. Anti-leakage sanitization uses explicit column lists derived from
     each extractor's actual CSV output schema (not regex guesses).
  4. RandomForestClassifier(n_estimators=40, max_depth=15) — same as
     the reference benchmark for fair comparison.
"""

import pandas as pd
import numpy as np
import os
import sys
import gc
import warnings
import argparse
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import f1_score, precision_score, recall_score, confusion_matrix
from sklearn.preprocessing import LabelEncoder

try:
    from imblearn.under_sampling import RandomUnderSampler
except ImportError:
    print("ERROR: imbalanced-learn not installed.")
    print("  Install: pip install imbalanced-learn")
    sys.exit(1)

warnings.simplefilter(action='ignore', category=FutureWarning)

# =============================================================================
# [Configuration]
# =============================================================================

ATTACK_KEYWORDS = [
    'DNS', 'LDAP', 'MSSQL', 'NetBIOS', 'NTP', 'SNMP',
    'SSDP', 'UDP', 'Syn', 'TFTP', 'UDPLag', 'Portmap'
]

# Cross-Day Temporal Validation Pairs (CICDDoS2019)
# Train on Day 1 (01-12), Test on Day 2 (03-11)
CROSS_DAY_PAIRS = {
    'LDAP':    {'train': '01-12/DrDoS_LDAP',   'test': '03-11/LDAP'},
    'MSSQL':   {'train': '01-12/DrDoS_MSSQL',  'test': '03-11/MSSQL'},
    'NetBIOS': {'train': '01-12/DrDoS_NetBIOS', 'test': '03-11/NetBIOS'},
    'UDP':     {'train': '01-12/DrDoS_UDP',     'test': '03-11/UDP'},
    'Syn':     {'train': '01-12/Syn',           'test': '03-11/Syn'},
    'UDPLag':  {'train': '01-12/UDPLag',        'test': '03-11/UDPLag'},
}

# =============================================================================
# [Anti-Leakage: Explicit column purge lists per extractor schema]
# Derived from actual CSV headers (head -n 1) on the server.
# =============================================================================

LEAKAGE_COLUMNS = {
    # Lynceus v1.0 — 15 identity columns from csv_schema.md sections 1 and 4
    'LYNCEUS': {
        'flow_id', 'src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol',
        'ip_ver', 'eth_proto', 'traffic_class', 'flow_label',
        'src_mac', 'dst_mac', 'timestamp',
        'TunnelId', 'TunnelType',
    },
    # RustiFlow — identity and topology columns from its schema
    'RUSTIFLOW': {
        'flow_id', 'source_ip', 'source_port', 'destination_ip',
        'destination_port', 'protocol', 'ip_version',
        'source_ip_scope', 'destination_ip_scope', 'path_locality',
        'timestamp_first', 'timestamp_last',
        'flags',  # string representation of TCP flag combo
    },
    # NFX (NetFlow eXporter) — minimal schema: 5 identity + 2 features + Label
    'NFX': {
        'src_ip', 'src_port', 'dst_ip', 'dst_port', 'protocol',
    },
}

# Map directory names to leakage schema
EXTRACTOR_SCHEMA_MAP = {
    'LYNCEUS_FULL':            'LYNCEUS',
    'EBPF_PARITY_NTL':        'LYNCEUS',
    'EBPF_PARITY_NFX':        'LYNCEUS',
    'EBPF_PARITY_RUSTIFLOW':  'LYNCEUS',
    'RUSTIFLOW':               'RUSTIFLOW',
    'NFX':                     'NFX',
}

# Residual safety net: any column containing these substrings is also purged
LEAKAGE_SUBSTRINGS = ['unnamed', 'mac', 'vlan']

# Resource limits for 32GB RAM
SAFE_THRESHOLD = 500 * 1024 * 1024  # 500 MB
CHUNK_SIZE = 200_000
MAX_ROWS_PER_FILE = 2_500_000

# =============================================================================
# [Data Processing Functions]
# =============================================================================

def detect_extractor_schema(extractor_dir_name):
    """Map extractor directory name to its leakage schema."""
    schema = EXTRACTOR_SCHEMA_MAP.get(extractor_dir_name)
    if schema is None:
        # Fallback: try prefix matching
        for key, val in EXTRACTOR_SCHEMA_MAP.items():
            if key in extractor_dir_name.upper():
                return val
        return 'LYNCEUS'  # conservative default
    return schema


def purge_leakage_columns(df, schema_name):
    """Remove all identifier/metadata columns that cause data leakage.

    Uses the explicit per-extractor purge list plus a residual substring filter.
    Returns only behavioral/statistical features.
    """
    known_leakage = LEAKAGE_COLUMNS.get(schema_name, set())
    cols_to_drop = []

    for col in df.columns:
        col_lower = col.strip().lower()
        # Exact match against known leakage set (case-insensitive)
        if col in known_leakage:
            cols_to_drop.append(col)
        # Substring safety net
        elif any(sub in col_lower for sub in LEAKAGE_SUBSTRINGS):
            cols_to_drop.append(col)

    df_clean = df.drop(columns=cols_to_drop, errors='ignore')
    return df_clean, cols_to_drop


def process_chunk(df_chunk, schema_name):
    """Sanitize chunk: remove leakage, encode categoricals, handle NaN/Inf."""
    # Identify label column
    possible_labels = [c for c in df_chunk.columns if c.lower() in ('label', 'class')]
    if not possible_labels:
        # Broader search
        possible_labels = [c for c in df_chunk.columns if 'label' in c.lower() or 'class' in c.lower()]
    if not possible_labels:
        return None, None

    target_col = possible_labels[-1]

    # Extract target before purging
    y_raw = df_chunk[target_col]
    if isinstance(y_raw, pd.DataFrame):
        y_raw = y_raw.iloc[:, -1]

    # Binary encoding: 1 = Attack, 0 = Benign
    y_bin = y_raw.astype(str).str.lower().str.contains('benign').astype(int)
    y_bin = 1 - y_bin

    # Drop label columns before feature purge
    df_chunk = df_chunk.drop(columns=possible_labels, errors='ignore')

    # Anti-leakage purge
    X, dropped = purge_leakage_columns(df_chunk, schema_name)

    # Label-encode any remaining string columns
    # (e.g., DNSQueryType, NTP_Mode, SNMP_PDU_Type, SSDP_Method — legitimate L7 features)
    for col in X.columns:
        if X[col].dtype == 'object':
            X[col] = X[col].astype(str)
            le = LabelEncoder()
            X[col] = le.fit_transform(X[col])

    # Downcasting for RAM efficiency
    for col in X.select_dtypes(include=['float64']).columns:
        X[col] = X[col].astype('float32')
    for col in X.select_dtypes(include=['int64']).columns:
        X[col] = X[col].astype('int32')

    # Mathematical sanitization
    X.replace([np.inf, -np.inf], np.nan, inplace=True)
    X.fillna(0, inplace=True)

    return X, y_bin


def load_dataset(filepath, schema_name):
    """Load CSV entirely or via reservoir sampling if above SAFE_THRESHOLD."""
    if not os.path.exists(filepath):
        return None, None
    fsize = os.path.getsize(filepath)

    if fsize < SAFE_THRESHOLD:
        try:
            df = pd.read_csv(filepath, low_memory=False)
            return process_chunk(df, schema_name)
        except Exception as e:
            print(f"      ⚠️  Load error: {e}")
            return None, None
    else:
        # Reservoir sampling for large files
        buffer_X, buffer_y = [], []
        total_rows = 0
        try:
            estimated_rows = (fsize / (1024**3)) * 2_000_000
            sample_rate = min(1.0, MAX_ROWS_PER_FILE / estimated_rows) if estimated_rows > 0 else 0.5
            rng = np.random.RandomState(42)

            for chunk in pd.read_csv(filepath, chunksize=CHUNK_SIZE, low_memory=False):
                X_c, y_c = process_chunk(chunk, schema_name)
                if X_c is None:
                    continue
                if sample_rate < 1.0:
                    n = int(len(X_c) * sample_rate)
                    if n > 0:
                        idx = rng.choice(X_c.index, n, replace=False)
                        X_c, y_c = X_c.loc[idx], y_c.loc[idx]
                buffer_X.append(X_c)
                buffer_y.append(y_c)
                total_rows += len(X_c)
                if total_rows > MAX_ROWS_PER_FILE:
                    break

            if not buffer_X:
                return None, None
            return pd.concat(buffer_X, ignore_index=True), pd.concat(buffer_y, ignore_index=True)
        except Exception as e:
            print(f"      ⚠️  Chunked load error: {e}")
            return None, None


def balance_dataset(X, y):
    """Apply RandomUnderSampler to force 1:1 class ratio."""
    if len(y.unique()) < 2:
        return None, None
    rus = RandomUnderSampler(sampling_strategy='majority', random_state=42)
    X_bal, y_bal = rus.fit_resample(X, y)
    return X_bal, y_bal


# =============================================================================
# [File Discovery]
# =============================================================================

def find_csv(base_dir, day_dir, keyword):
    """Search for labeled CSV matching attack keyword in a day directory.

    Handles CICDDoS2019 naming: DrDoS_LDAP, DrDoS_DNS, Syn, TFTP, etc.
    Special case: 'UDP' must NOT match 'UDPLag'.
    """
    search_path = os.path.join(base_dir, 'PCAP', day_dir) if day_dir else os.path.join(base_dir, 'PCAP')
    if not os.path.exists(search_path):
        return None

    keyword_lower = keyword.lower().replace('drdos_', '')

    for root, dirs, files in os.walk(search_path):
        dirname = os.path.basename(root).lower()
        # Normalize: remove 'drdos_' prefix for matching
        dirname_clean = dirname.replace('drdos_', '')

        for f in files:
            if not f.endswith('.csv'):
                continue

            # Exact directory match (case-insensitive, normalized)
            if keyword_lower == 'udp' and 'lag' in dirname_clean:
                continue
            if keyword_lower == dirname_clean:
                return os.path.join(root, f)

    return None


def discover_extractors(processed_root):
    """Discover all available extractors in data/processed/."""
    extractors = []
    if not os.path.exists(processed_root):
        return extractors

    for entry in sorted(os.listdir(processed_root)):
        full_path = os.path.join(processed_root, entry)
        if not os.path.isdir(full_path):
            continue
        if entry == 'EBPF':
            # Known empty directory
            continue
        # Check if it has any CSVs
        has_csv = False
        for _, _, files in os.walk(full_path):
            if any(f.endswith('.csv') for f in files):
                has_csv = True
                break
        if has_csv:
            extractors.append(entry)

    return extractors


# =============================================================================
# [Main Benchmark Loop]
# =============================================================================

def run_balanced_benchmark():
    parser = argparse.ArgumentParser(
        description="Lynceus Balanced Sanity Benchmark (50/50 RUS)"
    )
    parser.add_argument(
        '--dataset', type=str,
        default='/opt/eBPFNetFlowLyzer/data/processed',
        help='Root directory containing processed extractor outputs'
    )
    parser.add_argument(
        '--extractor', type=str, nargs='+', default=None,
        help='Filter to specific extractors (e.g., LYNCEUS_FULL RUSTIFLOW)'
    )
    parser.add_argument(
        '--output-dir', type=str,
        default='/opt/eBPFNetFlowLyzer/results/balanced',
        help='Output directory for results CSV'
    )
    args = parser.parse_args()

    processed_root = os.path.abspath(args.dataset)
    output_dir = os.path.abspath(args.output_dir)
    os.makedirs(output_dir, exist_ok=True)

    # Discover extractors
    available = discover_extractors(processed_root)
    if args.extractor:
        available = [e for e in available if e in args.extractor]

    if not available:
        print("❌ No extractors found in", processed_root)
        return

    ml_results_db = []

    print("=" * 70)
    print("  BALANCED SANITY BENCHMARK (50/50 Random Undersampling)")
    print(f"  Extractors: {' | '.join(available)}")
    print("=" * 70)
    print("Anti-Leakage: Identity columns removed per extractor schema.")
    print("Balanceamento: RandomUnderSampler (majority → minority count)")
    print("Classificador: RandomForestClassifier(n_estimators=40, max_depth=15)")
    print("               SEM class_weight='balanced' (redundante com RUS)")
    print("=" * 70)

    for ext_name in available:
        ext_dir = os.path.join(processed_root, ext_name)
        schema = detect_extractor_schema(ext_name)

        print(f"\n{'#' * 60}")
        print(f"  EXTRACTOR: {ext_name} (schema: {schema})")
        print(f"{'#' * 60}")

        for attack in ATTACK_KEYWORDS:
            gc.collect()

            print(f"\n{'=' * 50}")
            print(f">>> CENÁRIO: {attack} [{ext_name}]")
            print(f"{'=' * 50}")

            # --- Locate files ---
            pair = CROSS_DAY_PAIRS.get(attack)

            if pair:
                # Cross-day temporal validation
                train_path = find_csv(ext_dir, pair['train'].split('/')[0], attack)
                test_path = find_csv(ext_dir, pair['test'].split('/')[0], attack)

                if not train_path:
                    # Try direct day folder
                    train_path = find_csv(ext_dir, '01-12', attack)
                if not test_path:
                    test_path = find_csv(ext_dir, '03-11', attack)

                if train_path and test_path:
                    result = _run_temporal_validation(
                        train_path, test_path, ext_name, schema, attack
                    )
                elif train_path:
                    print(f"    ⚠️  Apenas Dia 1 encontrado. Fallback para Split 70/30.")
                    result = _run_split_validation(
                        train_path, ext_name, schema, attack
                    )
                elif test_path:
                    print(f"    ⚠️  Apenas Dia 2 encontrado. Fallback para Split 70/30.")
                    result = _run_split_validation(
                        test_path, ext_name, schema, attack
                    )
                else:
                    print(f"    ❌ Nenhum CSV encontrado para {attack}.")
                    continue
            else:
                # Single-day: split validation
                # Try 01-12 first, then 03-11
                file_path = find_csv(ext_dir, '01-12', attack)
                if not file_path:
                    file_path = find_csv(ext_dir, '03-11', attack)
                if not file_path:
                    # Broad search
                    file_path = find_csv(ext_dir, '', attack)

                if not file_path:
                    print(f"    ❌ Nenhum CSV encontrado para {attack}.")
                    continue

                result = _run_split_validation(
                    file_path, ext_name, schema, attack
                )

            if result:
                ml_results_db.append(result)

            gc.collect()

    # --- Export ---
    if ml_results_db:
        df_ml = pd.DataFrame(ml_results_db)
        output_csv = os.path.join(output_dir, 'balanced_ml_metrics.csv')
        df_ml.to_csv(output_csv, index=False, float_format='%.6f')
        print(f"\n{'=' * 70}")
        print(f"[+] Exportação Concluída: {output_csv}")
        print(f"[+] Total de cenários avaliados: {len(ml_results_db)}")
        print(f"{'=' * 70}")
    else:
        print("\n❌ Nenhum resultado gerado.")


def _run_temporal_validation(train_path, test_path, ext_name, schema, attack):
    """Cross-Day Temporal Validation: Train on Day 1, Test on Day 2."""
    strategy = 'Temporal'
    print(f"    Validação TEMPORAL (Treino Dia 1 → Teste Dia 2)...")
    print(f"    Train: {os.path.relpath(train_path)}")
    print(f"    Test:  {os.path.relpath(test_path)}")

    try:
        X_train, y_train = load_dataset(train_path, schema)
        if X_train is None or len(y_train.unique()) < 2:
            print(f"    ❌ Dados de treino inválidos ou < 2 classes.")
            return None

        print(f"    Features após anti-leakage: {X_train.shape[1]} colunas")
        print(f"    Distribuição PRÉ-balanceamento (Treino): "
              f"Ataque={int((y_train == 1).sum())} | "
              f"Benigno={int((y_train == 0).sum())}")

        # Balance training set
        X_train_bal, y_train_bal = balance_dataset(X_train, y_train)
        if X_train_bal is None:
            print(f"    ❌ Balanceamento de treino falhou (classe única).")
            return None

        print(f"    Distribuição PÓS-balanceamento (Treino): "
              f"Ataque={int((y_train_bal == 1).sum())} | "
              f"Benigno={int((y_train_bal == 0).sum())}")

        train_samples = len(y_train_bal)
        n_features = X_train_bal.shape[1]

        # Train RF
        rf = RandomForestClassifier(
            n_estimators=40, max_depth=15,
            random_state=42, n_jobs=-1
        )
        rf.fit(X_train_bal, y_train_bal)
        train_cols = X_train_bal.columns.tolist()
        importances = rf.feature_importances_

        del X_train, y_train, X_train_bal, y_train_bal
        gc.collect()

        # Load and balance test set
        X_test, y_test = load_dataset(test_path, schema)
        if X_test is None or len(y_test.unique()) < 2:
            print(f"    ❌ Dados de teste inválidos ou < 2 classes.")
            return None

        X_test_bal, y_test_bal = balance_dataset(X_test, y_test)
        if X_test_bal is None:
            print(f"    ❌ Balanceamento de teste falhou (classe única).")
            return None

        print(f"    Distribuição PÓS-balanceamento (Teste): "
              f"Ataque={int((y_test_bal == 1).sum())} | "
              f"Benigno={int((y_test_bal == 0).sum())}")

        # Align columns
        for c in (set(train_cols) - set(X_test_bal.columns)):
            X_test_bal[c] = 0
        X_test_bal = X_test_bal.reindex(columns=train_cols, fill_value=0)

        y_pred = rf.predict(X_test_bal)

        return _compute_metrics(
            y_test_bal, y_pred, importances, train_cols, rf,
            ext_name, attack, strategy, train_samples, n_features
        )

    except Exception as e:
        print(f"    ❌ Erro: {e}")
        import traceback
        traceback.print_exc()
        return None


def _run_split_validation(file_path, ext_name, schema, attack):
    """Split Validation (70/30 Stratified)."""
    strategy = 'Split'
    print(f"    Validação SPLIT (70/30)...")
    print(f"    File: {os.path.relpath(file_path)}")

    try:
        X, y = load_dataset(file_path, schema)
        if X is None or len(y.unique()) < 2:
            print(f"    ❌ Dados inválidos ou < 2 classes.")
            return None

        print(f"    Features após anti-leakage: {X.shape[1]} colunas")
        print(f"    Distribuição PRÉ-balanceamento: "
              f"Ataque={int((y == 1).sum())} | "
              f"Benigno={int((y == 0).sum())}")

        # Balance the full dataset
        X_bal, y_bal = balance_dataset(X, y)
        if X_bal is None:
            print(f"    ❌ Balanceamento falhou (classe única).")
            return None

        print(f"    Distribuição PÓS-balanceamento: "
              f"Ataque={int((y_bal == 1).sum())} | "
              f"Benigno={int((y_bal == 0).sum())}")

        del X, y
        gc.collect()

        # Stratified split
        X_train, X_test, y_train, y_test = train_test_split(
            X_bal, y_bal,
            test_size=0.3, random_state=42, stratify=y_bal
        )

        # Train RF
        rf = RandomForestClassifier(
            n_estimators=40, max_depth=15,
            random_state=42, n_jobs=-1
        )
        rf.fit(X_train, y_train)
        y_pred = rf.predict(X_test)

        importances = rf.feature_importances_
        train_cols = X_bal.columns.tolist()
        train_samples = len(y_train)
        n_features = X_bal.shape[1]

        return _compute_metrics(
            y_test, y_pred, importances, train_cols, rf,
            ext_name, attack, strategy, train_samples, n_features
        )

    except Exception as e:
        print(f"    ❌ Erro: {e}")
        import traceback
        traceback.print_exc()
        return None


def _compute_metrics(y_true, y_pred, importances, feature_names, rf,
                     ext_name, attack, strategy, train_samples, n_features):
    """Compute and display all metrics. Return result dict."""
    f1 = f1_score(y_true, y_pred, average='weighted')
    prec = precision_score(y_true, y_pred, average='weighted', zero_division=0)
    rec = recall_score(y_true, y_pred, average='weighted', zero_division=0)
    cm = confusion_matrix(y_true, y_pred)

    tn = cm[0][0] if cm.shape[0] > 1 else 0
    fp = cm[0][1] if cm.shape[0] > 1 else 0
    fn = cm[1][0] if cm.shape[0] > 1 else 0
    tp = cm[1][1] if cm.shape[0] > 1 else 0

    print(f"    ✅ F1={f1:.4f} | Precision={prec:.4f} | Recall={rec:.4f}")
    print(f"    📊 Confusion Matrix: TN={tn} FP={fp} FN={fn} TP={tp}")
    print(f"    📏 Train Samples (balanced): {train_samples} | Features: {n_features}")

    # Top 10 Features with mean ± std
    importances_std = np.std(
        [tree.feature_importances_ for tree in rf.estimators_], axis=0
    )
    indices = np.argsort(importances)[::-1]

    print(f"    📋 Top 10 Features:")
    top_10 = []
    for i in range(min(10, len(indices))):
        idx = indices[i]
        feat = feature_names[idx]
        mean_w = importances[idx]
        std_w = importances_std[idx]
        top_10.append(f"{feat} ({mean_w:.3f}±{std_w:.3f})")
        print(f"       {i+1:2d}. {feat:<30s} {mean_w:.4f} ± {std_w:.4f}")

    # LaTeX-ready line
    tex_str = ", ".join(top_10).replace('_', '\\_')
    print(f"    📋 LATEX: {attack} & {ext_name} & {strategy} & "
          f"{prec:.4f} & {rec:.4f} & {f1:.4f} & "
          f"\\scriptsize{{{tex_str}}} \\\\ \\hline\n")

    return {
        'Extractor': ext_name,
        'Attack': attack,
        'Strategy': strategy,
        'F1-Score': f1,
        'Precision': prec,
        'Recall': rec,
        'TN': tn,
        'FP': fp,
        'FN': fn,
        'TP': tp,
        'Train_Samples_Balanced': train_samples,
        'Features_Count': n_features,
    }


if __name__ == '__main__':
    run_balanced_benchmark()
