#!/usr/bin/env python3
"""
Lynceus Pre-processing - Topological Ground-Truth Attributor (CIC-Bell-DNS-2024)
---------------------------------------------------------------------------
Scientific Milestone: v2.0 (High-Performance I/O)

Research Objective:
    Performs deterministic labeling based on network topology and filename 
    heuristics for the 5 classes: Benign, Malware, Spam, Phishing, Exfiltration.

Methodology:
    1. Directory Crawl: Locates all raw CSV streams.
    2. Contextual Mapping: Appends Activity Label based on file and directory context.
"""

import sys
import os
import glob
import pandas as pd

def determine_label(filepath_str):
    path_lower = filepath_str.lower()
    filename_lower = os.path.basename(path_lower)
    
    label = "Unknown"
    
    # Heurística baseada no filename, já que o caminho não é passado inteiro agora.
    # Na extração batch (extract_all_pcaps.sh), o nome do pcap fica "embutido" no prefixo do nome do csv
    # mas o nome não foi passado pra esse script.
    # Vamos usar apenas filename_lower, visto que extract_all_pcaps.sh salva o PCAP original no DB ou renomeia?
    # O extract_all_pcaps atual salva os arquivos gerados sem o nome do pcap, só usa data/hora, exceto 
    # se modificarmos o extract_all_pcaps.sh para salvar com o prefixo.
    # Espera! O extract_all_pcaps.sh do CIC-IDS-2017 renomeia sim: mv csv "$2/${base_pcap}_${hora}.csv"
    # Assim, `filename_lower` já tem o prefixo do nome do PCAP original.
    
    if "firstdaybenign" in filename_lower or "benign" in filename_lower:
        label = "Benign"
    elif "malware" in filename_lower:
        label = "Malware"
    elif "spam" in filename_lower:
        label = "Spam"
    elif "phishing" in filename_lower:
        label = "Phishing"
    elif "attack" in filename_lower or "exf" in filename_lower:
        label = "Exfiltration"
        
    return label

def process_directory(in_dir, out_dir):
    os.makedirs(out_dir, exist_ok=True)
    csv_files = glob.glob(os.path.join(in_dir, "*.csv"))
    
    if not csv_files:
        print(f"[ERRO] Nenhum arquivo CSV encontrado em {in_dir}")
        return
        
    for in_path in csv_files:
        filename = os.path.basename(in_path)
        out_path = os.path.join(out_dir, filename.replace(".csv", "_labeled.csv"))
        
        label = determine_label(filename)
        
        try:
            # Substituição do Pandas por Polars Streaming (Mitigação do OOM Killer em CSVs de 13GB)
            import polars as pl
            
            # Executa a adição da coluna em streaming contínuo sem alocar a base inteira em RAM
            pl.scan_csv(in_path, ignore_errors=True) \
              .with_columns(pl.lit(label).alias("Activity")) \
              .sink_csv(out_path)
              
            print(f"   [+] Labeled (Streaming): {filename} -> [Activity: {label}]")
        except Exception as e:
            print(f"   [!] Erro processando {filename}: {e}")

if __name__ == '__main__':
    if len(sys.argv) != 3:
        print("Uso: cic_dns_labeler.py <input_dir> <output_dir>")
        sys.exit(1)
        
    process_directory(sys.argv[1], sys.argv[2])
