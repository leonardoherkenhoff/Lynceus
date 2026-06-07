#!/usr/bin/env python3
"""
Lynceus Analysis - ML Benchmark (ISCX-Tor-2016)
---------------------------------------------------------------------------
Scientific Milestone: v2.0 (High-Performance I/O - Polars Architecture)

Research Objective:
    Reproduces the exact machine learning pipeline methodology of the CIC Tor Paper:
    "Characterization of Tor Traffic using Time based Features" (Habibi Lashkari et al., 2017).

Methodology:
    1. Cross Validation: 10-fold Stratified K-Fold.
    2. Scenarios:
       A: Tor vs Non-Tor Binary Classification
       B: Application Type Characterization (8 Classes within Tor traffic)
    3. Feature Space: Exclusively the 23 time-based metrics defined in the paper.
    4. Algorithms: C4.5 (Decision Tree), KNN, Random Forest, ZeroR (Baseline).
"""

import sys
import gc
import polars as pl
import pandas as pd
import numpy as np
from sklearn.model_selection import cross_val_score, StratifiedKFold
from sklearn.ensemble import RandomForestClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.neighbors import KNeighborsClassifier
from sklearn.dummy import DummyClassifier
from pathlib import Path

def get_23_time_based_features(df):
    """
    O artigo isola estritamente 23 features baseadas no tempo e taxa.
    """
    time_features = [
        'duration', 
        'Fwd_IAT_Mean', 'Fwd_IAT_Min', 'Fwd_IAT_Max', 'Fwd_IAT_Std',
        'Bwd_IAT_Mean', 'Bwd_IAT_Min', 'Bwd_IAT_Max', 'Bwd_IAT_Std',
        'Tot_IAT_Mean', 'Tot_IAT_Min', 'Tot_IAT_Max', 'Tot_IAT_Std',
        'Active_Mean', 'Active_Min', 'Active_Max', 'Active_Std',
        'Idle_Mean', 'Idle_Min', 'Idle_Max', 'Idle_Std',
        'BytesRate', 'PacketsRate'
    ]
    # Retorna apenas colunas que realmente existem na extração do Lynceus
    available = [c for c in time_features if c in df.columns]
    return df[available]

def evaluate_model(X, y, name, clf):
    # Paper usa 10-fold CV
    cv = StratifiedKFold(n_splits=10, shuffle=True, random_state=42)
    prec = cross_val_score(clf, X, y, cv=cv, scoring='precision_weighted', n_jobs=1)
    rec = cross_val_score(clf, X, y, cv=cv, scoring='recall_weighted', n_jobs=1)
    f1 = cross_val_score(clf, X, y, cv=cv, scoring='f1_weighted', n_jobs=1)
    print(f"[{name}] Precision: {prec.mean():.4f} | Recall: {rec.mean():.4f} | F1: {f1.mean():.4f}")

def main(csv_dir):
    print("==========================================================")
    print(" LYNCEUS vs CICFlowMeter - ISCX-Tor-2016")
    print("==========================================================")
    
    path = Path(csv_dir)
    files = list(path.glob('*_labeled.csv'))
    if not files:
        # Tenta também caso os arquivos não tenham o sufixo _labeled no nome final
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
        'BytesRate', 'PacketsRate'
    ]
    cols_to_use = time_features + ['Tor_Status', 'Application_Type']
    
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
    
    # Tratamento de NAs e Infinitos gerados por divisão por zero no extrator
    df_pd = df_pd.replace([np.inf, -np.inf], np.nan).dropna()
    
    # Prepara o Sub-espaço de Features Requisitado (23 features temporais)
    X_full = get_23_time_based_features(df_pd).astype(np.float32).values
    
    # Cenário A: Tor vs NonTor
    y_tor = df_pd['Tor_Status'].values
    
    # Cenário B: Tipos de Aplicação APENAS para tráfego Tor
    mask_tor = (df_pd['Tor_Status'] == "Tor").values
    X_scenario_b = X_full[mask_tor]
    y_app = df_pd.loc[mask_tor, 'Application_Type'].values
    
    del df_pd
    gc.collect()
    
    # Algoritmos mapeados no Paper
    # ZeroR é simulado no scikit-learn pelo DummyClassifier (strategy="prior" ou "most_frequent")
    # Paralelismo contido nas instâncias limitadas a 8 threads para evitar OOM no OpenBLAS/KNN
    classifiers = {
        "ZeroR (Baseline)": DummyClassifier(strategy="most_frequent"),
        "C4.5 (J48)": DecisionTreeClassifier(random_state=42),
        "KNN": KNeighborsClassifier(n_neighbors=5, n_jobs=8),
        "Random Forest (Lynceus)": RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=8)
    }
    
    print("\n--- [SCENARIO A] Tor vs Non-Tor (Binary) ---")
    if len(np.unique(y_tor)) > 1:
        for name, clf in classifiers.items():
            evaluate_model(X_full, y_tor, name, clf)
    else:
        print("[!] Ignorado: O dataset não possui exemplos de ambas as classes (Tor e NonTor).")
        
    print("\n--- [SCENARIO B] Application Characterization (Tor-only 8 Classes) ---")
    if len(np.unique(y_app)) > 1:
        for name, clf in classifiers.items():
            evaluate_model(X_scenario_b, y_app, name, clf)
    else:
        print("[!] Ignorado: Variedade insuficiente de classes no tráfego Tor capturado.")

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Uso: run_tor_benchmark.py <diretorio_com_csvs_processados>")
        sys.exit(1)
    main(sys.argv[1])
