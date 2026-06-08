#!/usr/bin/env python3
"""
Lynceus Pre-processing - Topological Ground-Truth Attributor (ISCX-Tor-2016)
---------------------------------------------------------------------------
Scientific Milestone: v2.0 (High-Performance I/O)

Research Objective:
    Performs deterministic labeling of extraction results based on network
    topology and filename heuristics defined by Habibi Lashkari et al. (2017).

Methodology:
    1. Directory Crawl: Locates all raw CSV streams.
    2. Contextual Mapping: Appends Application Type and Tor Status features 
       based on original filename semantics.
"""

import sys
import os
import glob
import polars as pl

def determine_labels(filepath_str):
    """
    Deduz os rótulos de Tor Status e Application Type baseado no path do arquivo.
    """
    path_lower = filepath_str.lower()
    
    # 1. Tor Status (Scenario A)
    tor_status = "NonTor" if "nontor" in path_lower else "Tor"
    
    # 2. Application Type (Scenario B)
    app_type = "Unknown"
    if "browsing" in path_lower:
        app_type = "Browsing"
    elif "chat" in path_lower:
        app_type = "Chat"
    elif "audio" in path_lower or "spotify" in path_lower:
        app_type = "Audio-Streaming"
    elif "video" in path_lower or "youtube" in path_lower or "vimeo" in path_lower:
        app_type = "Video-Streaming"
    elif "mail" in path_lower or "email" in path_lower:
        app_type = "Mail"
    elif "voip" in path_lower or "skype" in path_lower or "hangouts" in path_lower or "facebook" in path_lower:
        app_type = "VoIP" 
    elif "p2p" in path_lower or "torrent" in path_lower or "vuze" in path_lower:
        app_type = "P2P"
    elif "ft" in path_lower or "filetransfer" in path_lower or "sftp" in path_lower or "ftps" in path_lower:
        app_type = "File-Transfer"
    
    if app_type == "Unknown" and "streaming" in path_lower:
        app_type = "Video-Streaming"
            
    return tor_status, app_type

def process_directory(in_dir, out_dir):
    os.makedirs(out_dir, exist_ok=True)
    csv_files = glob.glob(os.path.join(in_dir, "*.csv"))
    
    if not csv_files:
        print(f"[ERRO] Nenhum arquivo CSV encontrado em {in_dir}")
        return
        
    for in_path in csv_files:
        filename = os.path.basename(in_path)
        out_path = os.path.join(out_dir, filename.replace(".csv", "_labeled.csv"))
        
        tor_status, app_type = determine_labels(filename)
        
        try:
            # Pega esquema primeiro para ver se arquivo não está vazio
            df_probe = pl.read_csv(in_path, n_rows=1)
            if df_probe.height == 0:
                print(f"   [!] Arquivo Vazio: {filename}")
                continue
                
            # Sink streaming em Polars
            pl.scan_csv(in_path).with_columns([
                pl.lit(tor_status).alias("Tor_Status"),
                pl.lit(app_type).alias("Application_Type")
            ]).sink_csv(out_path)
            
            print(f"   [+] Labeled: {filename} -> [Status: {tor_status} | App: {app_type}]")
        except Exception as e:
            print(f"   [!] Erro lendo {filename}: {e}")

if __name__ == '__main__':
    if len(sys.argv) != 3:
        print("Uso: iscx_tor_labeler.py <input_dir> <output_dir>")
        sys.exit(1)
        
    process_directory(sys.argv[1], sys.argv[2])
