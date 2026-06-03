#!/usr/bin/env python3
"""
Lynceus Analysis - ML Benchmark (ISCX-Tor-2016)
---------------------------------------------------------------------------
Scientific Milestone: v2.0 (High-Performance I/O)

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
        'flow_duration', 
        'f_iat_mean', 'f_iat_min', 'f_iat_max', 'f_iat_std',
        'b_iat_mean', 'b_iat_min', 'b_iat_max', 'b_iat_std',
        'flow_iat_mean', 'flow_iat_min', 'flow_iat_max', 'flow_iat_std',
        'active_mean', 'active_min', 'active_max', 'active_std',
        'idle_mean', 'idle_min', 'idle_max', 'idle_std',
        'flow_bytes_s', 'flow_packets_s'
    ]
    # Retorna apenas colunas que realmente existem na extração do Lynceus
    available = [c for c in time_features if c in df.columns]
    return df[available]

def evaluate_model(X, y, name, clf):
    # Paper usa 10-fold CV
    cv = StratifiedKFold(n_splits=10, shuffle=True, random_state=42)
    prec = cross_val_score(clf, X, y, cv=cv, scoring='precision_weighted')
    rec = cross_val_score(clf, X, y, cv=cv, scoring='recall_weighted')
    f1 = cross_val_score(clf, X, y, cv=cv, scoring='f1_weighted')
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
        
    print(f"[*] Carregando {len(files)} arquivos CSV rotulados...")
    df_list = [pd.read_csv(f) for f in files]
    df = pd.concat(df_list, ignore_index=True)
    
    # Tratamento de NAs e Infinitos gerados por divisão por zero no extrator
    df = df.replace([np.inf, -np.inf], np.nan).dropna()
    
    # Prepara o Sub-espaço de Features Requisitado (23 features temporais)
    X_full = get_23_time_based_features(df)
    
    # Cenário A: Tor vs NonTor
    y_tor = df['Tor_Status'] 
    
    # Cenário B: Tipos de Aplicação APENAS para tráfego Tor
    mask_tor = df['Tor_Status'] == "Tor"
    X_scenario_b = X_full[mask_tor]
    y_app = df.loc[mask_tor, 'Application_Type']
    
    # Algoritmos mapeados no Paper
    # ZeroR é simulado no scikit-learn pelo DummyClassifier (strategy="prior" ou "most_frequent")
    classifiers = {
        "ZeroR (Baseline)": DummyClassifier(strategy="most_frequent"),
        "C4.5 (J48)": DecisionTreeClassifier(random_state=42),
        "KNN": KNeighborsClassifier(n_neighbors=5),
        "Random Forest (Lynceus)": RandomForestClassifier(n_estimators=100, random_state=42)
    }
    
    print("\n--- [SCENARIO A] Tor vs Non-Tor (Binary) ---")
    if len(y_tor.unique()) > 1:
        for name, clf in classifiers.items():
            evaluate_model(X_full, y_tor, name, clf)
    else:
        print("[!] Ignorado: O dataset não possui exemplos de ambas as classes (Tor e NonTor).")
        
    print("\n--- [SCENARIO B] Application Characterization (Tor-only 8 Classes) ---")
    if len(y_app.unique()) > 1:
        for name, clf in classifiers.items():
            evaluate_model(X_scenario_b, y_app, name, clf)
    else:
        print("[!] Ignorado: Variedade insuficiente de classes no tráfego Tor capturado.")

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Uso: run_tor_benchmark.py <diretorio_com_csvs_processados>")
        sys.exit(1)
    main(sys.argv[1])
