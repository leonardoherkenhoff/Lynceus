#!/usr/bin/env python3
"""
Lynceus Analysis - ML Benchmark (CIC-Bell-DNS-2024)
---------------------------------------------------------------------------
Scientific Milestone: v2.0 (High-Performance I/O)

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
import pandas as pd
import numpy as np
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
        'flow_duration', 
        'f_iat_mean', 'f_iat_min', 'f_iat_max', 'f_iat_std',
        'b_iat_mean', 'b_iat_min', 'b_iat_max', 'b_iat_std',
        'flow_iat_mean', 'flow_iat_min', 'flow_iat_max', 'flow_iat_std',
        'active_mean', 'active_min', 'active_max', 'active_std',
        'idle_mean', 'idle_min', 'idle_max', 'idle_std',
        'flow_bytes_s', 'flow_packets_s',
        'tot_f_pkts', 'tot_b_pkts', 'tot_len_f_pkt', 'tot_len_b_pkt'
    ]
    available = [c for c in time_features if c in df.columns]
    return df[available]

def evaluate_model(X, y, name, clf):
    cv = StratifiedKFold(n_splits=10, shuffle=True, random_state=42)
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
        
    print(f"[*] Carregando {len(files)} arquivos CSV rotulados...")
    df_list = [pd.read_csv(f) for f in files]
    df = pd.concat(df_list, ignore_index=True)
    
    df = df.replace([np.inf, -np.inf], np.nan).dropna()
    
    # Remover fluxos classificados como "Unknown" que o labeler não soube classificar
    df = df[df['Activity'] != 'Unknown']
    
    X = get_lynceus_l3_features(df)
    y = df['Activity']
    
    classifiers = {
        "ZeroR (Baseline)": DummyClassifier(strategy="most_frequent"),
        "C4.5 (J48)": DecisionTreeClassifier(random_state=42),
        "KNN": KNeighborsClassifier(n_neighbors=5),
        "Random Forest (Lynceus L3/L4)": RandomForestClassifier(n_estimators=100, random_state=42)
    }
    
    print("\n--- Multiclass DNS Attack Detection (5 Classes) ---")
    counts = y.value_counts()
    for cls, count in counts.items():
        print(f"  - {cls}: {count} fluxos")
        
    if len(y.unique()) > 1:
        for name, clf in classifiers.items():
            evaluate_model(X, y, name, clf)
    else:
        print("[!] Ignorado: O dataset só possui uma classe válida mapeada.")

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Uso: run_dns_benchmark.py <diretorio_com_csvs_processados>")
        sys.exit(1)
    main(sys.argv[1])
