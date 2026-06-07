#!/usr/bin/env python3
"""
Lynceus Analysis - ML Benchmark (CIC-Bell-DNS-2024)
---------------------------------------------------------------------------
Scientific Milestone: v2.0 (High-Performance I/O - Polars Architecture)

Research Objective:
    Validates if L3/L4 flow features (eBPF) can detect L7 DNS attacks 
    (Malware, Spam, Phishing, Exfiltration) with accuracy comparable to 
    the Application-layer ALFlowLyzer (120+ features).

Methodology:
    1. Cross Validation: 10-fold Stratified K-Fold.
    2. Algorithms: C4.5 (Decision Tree), KNN, Random Forest, ZeroR.
    3. Feature Space: Exclusively the time and flow-based metrics from Lynceus.
"""

import sys
import gc
import polars as pl
import pandas as pd
import numpy as np
from joblib import parallel_backend
from sklearn.model_selection import cross_val_score, StratifiedKFold
from sklearn.ensemble import RandomForestClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.neighbors import KNeighborsClassifier
from sklearn.dummy import DummyClassifier
from pathlib import Path

def get_lynceus_l3_features(df):
    """
    Lista de features nativas do eBPFNetFlowLyzer (L3/L4 Time-based).
    Ignorando qualquer coisa fora do escopo L3/L4.
    """
    time_features = [
        'duration', 
        'Fwd_IAT_Mean', 'Fwd_IAT_Min', 'Fwd_IAT_Max', 'Fwd_IAT_Std',
        'Bwd_IAT_Mean', 'Bwd_IAT_Min', 'Bwd_IAT_Max', 'Bwd_IAT_Std',
        'Tot_IAT_Mean', 'Tot_IAT_Min', 'Tot_IAT_Max', 'Tot_IAT_Std',
        'Active_Mean', 'Active_Min', 'Active_Max', 'Active_Std',
        'Idle_Mean', 'Idle_Min', 'Idle_Max', 'Idle_Std',
        'BytesRate', 'PacketsRate',
        'TotalFwdPkts', 'TotalBwdPkts', 'TotalLengthFwdPkts', 'TotalLengthBwdPkts'
    ]
    available = [c for c in time_features if c in df.columns]
    return df[available]

def evaluate_model(X, y, name, clf):
    cv = StratifiedKFold(n_splits=10, shuffle=True, random_state=42)
    with parallel_backend('threading', n_jobs=-1):
        prec = cross_val_score(clf, X, y, cv=cv, scoring='precision_weighted')
        rec = cross_val_score(clf, X, y, cv=cv, scoring='recall_weighted')
        f1 = cross_val_score(clf, X, y, cv=cv, scoring='f1_weighted')
    print(f"[{name}] Precision: {prec.mean():.4f} | Recall: {rec.mean():.4f} | F1: {f1.mean():.4f}")

def main(csv_dir):
    print("==========================================================")
    print(" LYNCEUS (L3/L4) vs ALFlowLyzer (L7) - CIC-Bell-DNS-2024")
    print("==========================================================")
    
    path = Path(csv_dir)
    files = list(path.glob('*_labeled.csv'))
    if not files:
        files = list(path.glob('*.csv'))
        
    if not files:
        print(f"Nenhum CSV encontrado em {csv_dir}.")
        return
        
    print(f"[*] Carregando {len(files)} arquivos CSV (modo Polars Lazy Evaluation)...")
    
    time_features = [
        'duration', 'Fwd_IAT_Mean', 'Fwd_IAT_Min', 'Fwd_IAT_Max', 'Fwd_IAT_Std',
        'Bwd_IAT_Mean', 'Bwd_IAT_Min', 'Bwd_IAT_Max', 'Bwd_IAT_Std',
        'Tot_IAT_Mean', 'Tot_IAT_Min', 'Tot_IAT_Max', 'Tot_IAT_Std',
        'Active_Mean', 'Active_Min', 'Active_Max', 'Active_Std',
        'Idle_Mean', 'Idle_Min', 'Idle_Max', 'Idle_Std',
        'BytesRate', 'PacketsRate',
        'TotalFwdPkts', 'TotalBwdPkts', 'TotalLengthFwdPkts', 'TotalLengthBwdPkts'
    ]
    cols_to_use = time_features + ['Activity']
    
    queries = []
    for f in files:
        try:
            q = pl.scan_csv(str(f), infer_schema_length=10000).select(cols_to_use).with_columns([
                pl.col(c).cast(pl.Float32) for c in time_features
            ])
            queries.append(q)
        except Exception as e:
            print(f"Erro scaneando {f}: {e}")
            
    df_pl = pl.concat(queries).collect(engine="streaming")
    df_pd = df_pl.to_pandas()
    del df_pl
    queries.clear()
    gc.collect()
    
    df_pd = df_pd.replace([np.inf, -np.inf], np.nan).dropna()
    
    # Remover fluxos classificados como "Unknown" que o labeler não soube classificar
    df_pd = df_pd[df_pd['Activity'] != 'Unknown']
    
    X = get_lynceus_l3_features(df_pd).astype(np.float32).values
    y = df_pd['Activity'].values
    
    del df_pd
    gc.collect()
    
    classifiers = {
        "ZeroR (Baseline)": DummyClassifier(strategy="most_frequent"),
        "C4.5 (J48)": DecisionTreeClassifier(random_state=42),
        "KNN": KNeighborsClassifier(n_neighbors=5),
        "Random Forest (Lynceus L3/L4)": RandomForestClassifier(n_estimators=100, random_state=42)
    }
    
    print("\n--- Multiclass DNS Attack Detection (5 Classes) ---")
    counts = pd.Series(y).value_counts()
    for cls, count in counts.items():
        print(f"  - {cls}: {count} fluxos")
        
    if len(np.unique(y)) > 1:
        for name, clf in classifiers.items():
            evaluate_model(X, y, name, clf)
    else:
        print("[!] Ignorado: O dataset só possui uma classe válida mapeada.")

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Uso: run_dns_benchmark.py <diretorio_com_csvs_processados>")
        sys.exit(1)
    main(sys.argv[1])
