#!/usr/bin/env python3
"""
Lynceus Analysis - ML Benchmark (CIC-Bell-DNS-2024)
---------------------------------------------------------------------------
Scientific Milestone: v2.0 (High-Performance I/O - Polars Architecture)

Research Objective:
    Reproduces the machine learning pipeline methodology of the CIC-Bell-DNS-EX-2024 Dataset:
    "Detection and Characterization of Malicious DNS Exfiltration".

Methodology:
    1. Cross Validation: 10-fold Stratified K-Fold.
    2. Scenarios:
       A: Benign vs Malicious (Binary)
       B: Malicious Type Characterization (Heavy, Light, etc.)
    3. Feature Space: 31 Flow-based features + DNS-specific features.
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
from sklearn.dummy import DummyClassifier
from pathlib import Path


def evaluate_model(X, y, name, clf):
    cv = StratifiedKFold(n_splits=10, shuffle=True, random_state=42)
    scoring = ['precision_weighted', 'recall_weighted', 'f1_weighted']
    
    # Forçando o backend 'threading' para bloquear o OOM do 'loky' em partições massivas
    with parallel_backend('threading', n_jobs=-1):
        scores = cross_validate(clf, X, y, cv=cv, scoring=scoring, n_jobs=1)
    
    prec = scores['test_precision_weighted'].mean()
    rec = scores['test_recall_weighted'].mean()
    f1 = scores['test_f1_weighted'].mean()
    
    print(f"[{name}] Precision: {prec:.4f} | Recall: {rec:.4f} | F1: {f1:.4f}")

def main(csv_dir):
    print("==========================================================")
    print(" LYNCEUS vs CICFlowMeter - CIC-Bell-DNS-2024")
    print("==========================================================")
    
    path = Path(csv_dir)
    files = list(path.glob('*_labeled.csv'))
    if not files:
        files = list(path.glob('*.csv'))
        
    if not files:
        print(f"Nenhum CSV encontrado em {csv_dir}.")
        return
        
    print(f"[*] Carregando {len(files)} arquivos CSV (modo Polars Lazy Evaluation)...")
    
    dns_features = [
        'duration', 'Fwd_IAT_Mean', 'Fwd_IAT_Min', 'Fwd_IAT_Max', 'Fwd_IAT_Std',
        'Bwd_IAT_Mean', 'Bwd_IAT_Min', 'Bwd_IAT_Max', 'Bwd_IAT_Std',
        'Tot_IAT_Mean', 'Tot_IAT_Min', 'Tot_IAT_Max', 'Tot_IAT_Std',
        'Active_Mean', 'Active_Min', 'Active_Max', 'Active_Std',
        'Idle_Mean', 'Idle_Min', 'Idle_Max', 'Idle_Std',
        'BytesRate', 'PacketsRate',
        'FwdBytes', 'BwdBytes', 'TotalBytes',
        'FwdPacketsCount', 'BwdPacketsCount', 'PacketsCount',
        'DNSQueryType', 'DNSQueryClass', 'DNSAnswerCount'
    ]
    cols_to_use = dns_features + ['Activity']
    
    queries = []
    for f in files:
        try:
            q = pl.scan_csv(str(f), infer_schema_length=10000).select(cols_to_use).with_columns([
                pl.col(c).cast(pl.Float32) for c in dns_features
            ])
            queries.append(q)
        except Exception as e:
            print(f"Erro scaneando {f}: {e}")
            
    df_pl = pl.concat(queries).collect(engine="streaming")
    queries.clear()
    import gc
    gc.collect()
    
    import polars.selectors as cs
    # Tratamento de NAs e Infinitos usando Polars estrito
    # is_nan e is_infinite apenas em colunas numericas flutuantes
    df_pl = df_pl.filter(
        ~pl.any_horizontal(pl.all().is_null(), cs.float().is_nan(), cs.float().is_infinite())
    )
    
    # Raw Activity array
    y_raw = df_pl.select('Activity').to_numpy().flatten()
    
    X_full = df_pl.select(dns_features).to_numpy()
    
    del df_pl
    gc.collect()
    
    # Binary Label (Benign vs Malicious)
    y_bin = np.where(y_raw == 'Benign', 'Benign', 'Malicious')
    
    # Multiclass Label (Malicious types only)
    mask_malicious = (y_bin == 'Malicious')
    X_malicious = X_full[mask_malicious]
    y_type = y_raw[mask_malicious]
    

    # Paralelismo contido nas instâncias limitadas a 8 threads para evitar OOM no OpenBLAS/KNN
    classifiers = {
        "ZeroR (Baseline)": DummyClassifier(strategy="most_frequent"),
        "C4.5 (J48)": DecisionTreeClassifier(random_state=42),
        "KNN": KNeighborsClassifier(n_neighbors=5, n_jobs=-1),
        "Random Forest (Lynceus)": RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
    }
    
    print("\n--- [SCENARIO A] Benign vs Malicious (Binary) ---")
    if len(np.unique(y_bin)) > 1:
        for name, clf in classifiers.items():
            evaluate_model(X_full, y_bin, name, clf)
    else:
        print("[!] Ignorado: O dataset não possui exemplos de ambas as classes (Benigno e Malicioso).")
        
    print("\n--- [SCENARIO B] Malicious Characterization (Exfiltration Types) ---")
    if len(np.unique(y_type)) > 1:
        for name, clf in classifiers.items():
            evaluate_model(X_malicious, y_type, name, clf)
    else:
        print("[!] Ignorado: Variedade insuficiente de classes no tráfego Malicioso capturado.")

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Uso: run_dns_benchmark.py <diretorio_com_csvs_processados>")
        sys.exit(1)
    main(sys.argv[1])
