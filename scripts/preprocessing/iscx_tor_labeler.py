#!/usr/bin/env python3
"""
Lynceus Pre-processing - Topological Ground-Truth Attributor (ISCX-Tor-2016)
---------------------------------------------------------------------------
Scientific Milestone: v2.0 (High-Performance I/O)

Research Objective:
    Performs deterministic labeling of extraction results based on network
    topology and filename heuristics defined by Habibi Lashkari et al. (2017).

Methodology:
    1. Iterative Parsing: Receives raw flow CSV from Lynceus daemon.
    2. Contextual Mapping: Appends Application Type and Tor Status features based on file context.
"""

import sys
import os
import pandas as pd
from pathlib import Path

def determine_labels(filepath_str):
    """
    Deduz os rótulos de Tor Status e Application Type baseado no path do arquivo injetado.
    Tor.zip e NonTor.tar.xz geram arvores de diretorios que refletem a classe.
    """
    path_lower = filepath_str.lower()
    
    # 1. Tor Status (Scenario A)
    # Se "nontor" estiver no caminho ou nome de arquivo, eh Non-Tor.
    # Caso contrario, assume-se Tor.
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
        app_type = "VoIP" # O paper agrupa hangouts, facebook voice e skype aqui, mas pode conflitar se skype for chat/ft.
    elif "p2p" in path_lower or "torrent" in path_lower or "vuze" in path_lower:
        app_type = "P2P"
    elif "ft" in path_lower or "filetransfer" in path_lower or "sftp" in path_lower or "ftps" in path_lower:
        app_type = "File-Transfer"
    
    # Heurística extra de disambiguação por palavras-chave
    if app_type == "Unknown":
        if "streaming" in path_lower:
            app_type = "Video-Streaming" # Default guess for streaming if audio/video isn't explicit
            
    return tor_status, app_type

def main(input_csv, source_pcap):
    if not os.path.exists(input_csv):
        print(f"[ERRO] Arquivo CSV {input_csv} nao encontrado.")
        sys.exit(1)
        
    tor_status, app_type = determine_labels(source_pcap)
    
    # Carrega o CSV gerado pelo Lynceus (Pandas fallback seguro p/ pequenos lotes de pcap individual)
    df = pd.read_csv(input_csv)
    
    # Anexa o ground-truth
    df['Tor_Status'] = tor_status
    df['Application_Type'] = app_type
    
    # Sobrescreve o mesmo arquivo (pois esta operando na pasta processed/ ja isolada)
    df.to_csv(input_csv, index=False)
    print(f"   [+] Labeled: {input_csv} -> [Status: {tor_status} | App: {app_type}]")

if __name__ == '__main__':
    if len(sys.argv) < 3:
        print("Uso: iscx_tor_labeler.py <csv_gerado.csv> <caminho_pcap_original>")
        sys.exit(1)
    main(sys.argv[1], sys.argv[2])
