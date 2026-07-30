#!/usr/bin/env python3
"""
Lynceus Analysis - ML Benchmark (ISCX-VPN-2016)
---------------------------------------------------------------------------
Scientific Milestone: v2.0 (High-Performance I/O - Polars Architecture)

Research Objective:
    Reproduces the exact machine learning pipeline methodology of the CICFlowMeter VPN Paper.
    "Characterization of Encrypted and VPN Traffic using Time-related Features" (Draper-Gil et al., 2016).

Methodology:
    1. Cross Validation: 10-fold Stratified K-Fold.
    2. Scenarios:
       A.1: VPN vs Non-VPN Binary Classification
       A.2: Application Type (separated by VPN / Non-VPN contexts)
       B: 14-class unified classification
    3. Feature Space: Exclusively time-based metrics (duration, IATs, active/idle).
"""

import sys
import gc
import polars as pl
import numpy as np
from sklearn.model_selection import cross_validate, StratifiedKFold
from sklearn.ensemble import RandomForestClassifier
from joblib import parallel_backend
from sklearn.tree import DecisionTreeClassifier
from sklearn.neighbors import KNeighborsClassifier
from pathlib import Path


def evaluate_model(X, y, name, clf):
    cv = StratifiedKFold(n_splits=10, shuffle=True, random_state=42)
    scoring = ['precision_weighted', 'recall_weighted', 'f1_weighted']
    
    # Validação cruzada sem wrappers restritivos. Scikit-Learn decidirá o backend (loky/openmp)
    scores = cross_validate(clf, X, y, cv=cv, scoring=scoring, n_jobs=1)
    
    prec = scores['test_precision_weighted'].mean()
    rec = scores['test_recall_weighted'].mean()
    f1 = scores['test_f1_weighted'].mean()
    
    print(f"[{name}] Precision: {prec:.4f} | Recall: {rec:.4f} | F1: {f1:.4f}")

def main(csv_dir):
    print("==========================================================")
    print(" LYNCEUS vs CICFlowMeter - ISCX-VPN-2016")
    print("==========================================================")
    
    path = Path(csv_dir)
    files = list(path.glob('*_labeled.csv'))
    if not files:
        print("Nenhum CSV rotulado encontrado.")
        return
        
    print(f"[*] Carregando {len(files)} arquivos CSV (modo Polars Lazy Evaluation)...")
    
    time_features = [
        'duration', 'Fwd_IAT_Mean', 'Fwd_IAT_Min', 'Fwd_IAT_Max', 'Fwd_IAT_Std',
        'Bwd_IAT_Mean', 'Bwd_IAT_Min', 'Bwd_IAT_Max', 'Bwd_IAT_Std',
        'Tot_IAT_Mean', 'Tot_IAT_Min', 'Tot_IAT_Max', 'Tot_IAT_Std',
        'Active_Mean', 'Active_Min', 'Active_Max', 'Active_Std',
        'Idle_Mean', 'Idle_Min', 'Idle_Max', 'Idle_Std',
        'BytesRate', 'PacketsRate'
    ]
    cols_to_use = time_features + ['VPN_Status', 'Application_Type']
    
    queries = []
    for f in files:
        try:
            is_vpn = "VPN" if f.name.lower().startswith("vpn_") else "NonVPN"
            q = pl.scan_csv(str(f), infer_schema_length=10000).select(time_features + ['Application_Type']).with_columns([
                pl.col(c).cast(pl.Float32) for c in time_features
            ]).with_columns(
                pl.lit(is_vpn).alias("VPN_Status")
            )
            queries.append(q)
        except Exception as e:
            print(f"Erro scaneando {f}: {e}")
            
    # Executa a coleta sob demanda com a engine de streaming em Rust
    df_pl = pl.concat(queries).collect(engine="streaming")
    queries.clear()
    gc.collect()
    
    import polars.selectors as cs
    df_pl = df_pl.filter(
        ~pl.any_horizontal(pl.all().is_null(), cs.float().is_nan(), cs.float().is_infinite())
    )
    
    y_vpn = df_pl.select("VPN_Status").to_numpy().flatten().astype(str)
    y_app = df_pl.select("Application_Type").to_numpy().flatten().astype(str)
    y_unified = np.array([f"{v}-{a}" for v, a in zip(y_vpn, y_app)])
    
    X_full = df_pl.select(time_features).to_numpy()
    
    del df_pl
    gc.collect()
    
    y_vpn = np.char.strip(y_vpn)
    y_app = np.char.strip(y_app)
    mask_nonvpn = (y_vpn == "NonVPN")
    mask_vpn = (y_vpn != "NonVPN")
    

    
    # Classificadores (C4.5 equivalente é DecisionTree, e Random Forest que Lynceus usa)
    # Paralelismo contido nas instâncias limitadas a 8 threads para evitar OOM no OpenBLAS/KNN
    classifiers = {
        "C4.5 (J48)": DecisionTreeClassifier(random_state=42),
        "KNN": KNeighborsClassifier(n_neighbors=5, n_jobs=-1),
        "Random Forest (Lynceus)": RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
    }
    
    print("\n--- [SCENARIO A.1] VPN vs Non-VPN (Binario) ---")
    if len(np.unique(y_vpn)) > 1:
        for name, clf in classifiers.items():
            evaluate_model(X_full, y_vpn, name, clf)
    else:
        print("[!] Dataset possui apenas 1 classe de tráfego. Impossível realizar Scenario A.1 (Binário). Pulando...")
        
    print("\n--- [SCENARIO A.2] Application Characterization (Somente Non-VPN) ---")
    if len(X_full[mask_nonvpn]) > 0:
        for name, clf in classifiers.items():
            evaluate_model(X_full[mask_nonvpn], y_app[mask_nonvpn], name, clf)
    else:
        print("[!] Nenhum tráfego NonVPN detectado. Pulando Scenario A.2...")
        
    print("\n--- [SCENARIO A.2] Application Characterization (Somente VPN) ---")
    if len(X_full[mask_vpn]) > 0:
        for name, clf in classifiers.items():
            evaluate_model(X_full[mask_vpn], y_app[mask_vpn], name, clf)
    else:
        print("[!] Nenhum tráfego VPN detectado na base de dados. Pulando Scenario A.2...")
        
    print("\n--- [SCENARIO B] Unified 14-Class Classification ---")
    if len(np.unique(y_unified)) > 1:
        for name, clf in classifiers.items():
            evaluate_model(X_full, y_unified, name, clf)
    else:
        print("[!] Dataset possui apenas 1 classe unificada. Pulando Scenario B...")

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Uso: run_vpn_benchmark.py <diretorio_com_csvs_rotulados>")
        sys.exit(1)
    main(sys.argv[1])
