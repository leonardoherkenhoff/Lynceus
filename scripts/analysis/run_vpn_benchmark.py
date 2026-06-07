#!/usr/bin/env python3
"""
Lynceus Analysis - ML Benchmark (ISCX-VPN-2016)
---------------------------------------------------------------------------
Scientific Milestone: v2.0 (High-Performance I/O)

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
import pandas as pd
import numpy as np
from sklearn.model_selection import cross_val_score, StratifiedKFold
from sklearn.ensemble import RandomForestClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.neighbors import KNeighborsClassifier
from sklearn.metrics import make_scorer, precision_score, recall_score, f1_score
from pathlib import Path

def get_time_based_features(df):
    """
    O artigo isola estritamente features baseadas no tempo e taxa.
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
    cv = StratifiedKFold(n_splits=10, shuffle=True, random_state=42)
    prec = cross_val_score(clf, X, y, cv=cv, scoring='precision_weighted')
    rec = cross_val_score(clf, X, y, cv=cv, scoring='recall_weighted')
    f1 = cross_val_score(clf, X, y, cv=cv, scoring='f1_weighted')
    print(f"[{name}] Precision: {prec.mean():.4f} | Recall: {rec.mean():.4f} | F1: {f1.mean():.4f}")

def main(csv_dir):
    print("==========================================================")
    print(" LYNCEUS vs CICFlowMeter - ISCX-VPN-2016")
    print("==========================================================")
    
    path = Path(csv_dir)
    files = list(path.glob('*_labeled.csv'))
    if not files:
        print("Nenhum CSV rotulado encontrado.")
        return
        
    print(f"[*] Carregando {len(files)} arquivos CSV...")
    df_list = [pd.read_csv(f) for f in files]
    df = pd.concat(df_list, ignore_index=True)
    
    # Tratamento de NAs e Infinitos
    df = df.replace([np.inf, -np.inf], np.nan).dropna()
    
    X_full = get_time_based_features(df)
    y_vpn = df['VPN_Status'] # "VPN" ou "NonVPN"
    y_app = df['Application_Type'] # "VoIP", "Chat", etc.
    y_unified = df['VPN_Status'] + "-" + df['Application_Type']
    
    # Classificadores (C4.5 equivalente é DecisionTree, e Random Forest que Lynceus usa)
    classifiers = {
        "C4.5 (J48)": DecisionTreeClassifier(random_state=42),
        "KNN": KNeighborsClassifier(n_neighbors=5),
        "Random Forest (Lynceus)": RandomForestClassifier(n_estimators=100, random_state=42)
    }
    
    print("\n--- [SCENARIO A.1] VPN vs Non-VPN (Binario) ---")
    for name, clf in classifiers.items():
        evaluate_model(X_full, y_vpn, name, clf)
        
    print("\n--- [SCENARIO A.2] Application Characterization (Somente Non-VPN) ---")
    mask_nonvpn = df['VPN_Status'] == "NonVPN"
    for name, clf in classifiers.items():
        evaluate_model(X_full[mask_nonvpn], y_app[mask_nonvpn], name, clf)
        
    print("\n--- [SCENARIO A.2] Application Characterization (Somente VPN) ---")
    mask_vpn = df['VPN_Status'] == "VPN"
    for name, clf in classifiers.items():
        evaluate_model(X_full[mask_vpn], y_app[mask_vpn], name, clf)
        
    print("\n--- [SCENARIO B] Unified 14-Class Classification ---")
    for name, clf in classifiers.items():
        evaluate_model(X_full, y_unified, name, clf)

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Uso: run_vpn_benchmark.py <diretorio_com_csvs_rotulados>")
        sys.exit(1)
    main(sys.argv[1])
