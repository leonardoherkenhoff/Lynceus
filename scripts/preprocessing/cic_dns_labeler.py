#!/usr/bin/env python3
"""
Lynceus Pre-processing - Topological Ground-Truth Attributor (CIC-Bell-DNS-2024)
---------------------------------------------------------------------------
Scientific Milestone: v2.0 (High-Performance I/O)

Research Objective:
    Performs deterministic labeling based on network topology and filename 
    heuristics for the 5 classes: Benign, Malware, Spam, Phishing, Exfiltration.

Methodology:
    1. Iterative Parsing: Receives raw flow CSV from Lynceus daemon.
    2. Contextual Mapping: Appends Activity Label based on file and directory context.
"""

import sys
import os
import pandas as pd
from pathlib import Path

def determine_label(filepath_str):
    path_lower = filepath_str.lower()
    filename_lower = os.path.basename(path_lower)
    
    label = "Unknown"
    
    # Heurística para o EXF Dataset (Exfiltration)
    if "/exf/" in path_lower:
        if "attack" in path_lower and "benign" not in filename_lower:
            label = "Exfiltration"
        elif "benign" in path_lower:
            label = "Benign"
            
    # Heurística para o 2021 Dataset Original
    elif "/2021/" in path_lower:
        if "firstdaybenign" in path_lower or "benign" in filename_lower:
            label = "Benign"
        elif "malware" in filename_lower or "malware" in path_lower:
            label = "Malware"
        elif "spam" in filename_lower or "spam" in path_lower:
            label = "Spam"
        elif "phishing" in filename_lower or "phishing" in path_lower:
            label = "Phishing"
        
        # Fallback (as vezes SecondDay.zip inteiro é Malware ou Spam)
        # Na ausencia da classe no filename, tenta pelo nome da pasta se houver.
        
    return label

def main(input_csv, source_pcap):
    if not os.path.exists(input_csv):
        print(f"[ERRO] Arquivo CSV {input_csv} nao encontrado.")
        sys.exit(1)
        
    label = determine_label(source_pcap)
    
    # Carrega o CSV gerado pelo Lynceus
    df = pd.read_csv(input_csv)
    
    # Anexa o ground-truth
    df['Activity'] = label
    
    # Sobrescreve
    df.to_csv(input_csv, index=False)
    print(f"   [+] Labeled: {input_csv} -> [Activity: {label}]")

if __name__ == '__main__':
    if len(sys.argv) < 3:
        print("Uso: cic_dns_labeler.py <csv_gerado.csv> <caminho_pcap_original>")
        sys.exit(1)
    main(sys.argv[1], sys.argv[2])
