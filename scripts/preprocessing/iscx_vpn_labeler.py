#!/usr/bin/env python3
"""
Lynceus Pre-processing - Topological Ground-Truth Attributor (ISCX-VPN-2016)
---------------------------------------------------------------------------
Scientific Milestone: v2.0 (High-Performance I/O)

Research Objective:
    Performs deterministic labeling of extraction results based on network
    topology and filename heuristics defined by Draper-Gil et al. (2016).

Methodology:
    1. Directory Crawl: Locates all raw CSV streams.
    2. Contextual Mapping: Appends Application Type and VPN Status features 
       based on original filename semantics.
"""

import sys
import os
import csv
import glob
import logging

logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')

def get_labels_from_filename(filename):
    fname = filename.lower()
    vpn_status = "NonVPN"
    app_label = "Unknown"
    
    if "vpn" in fname:
        vpn_status = "VPN"
        
    if "skype" in fname or "voip" in fname:
        app_label = "VoIP"
    elif any(x in fname for x in ["chat", "aim", "icq", "hangouts", "facebook"]):
        app_label = "Chat"
    elif "email" in fname or "mail" in fname:
        app_label = "Email"
    elif any(x in fname for x in ["stream", "youtube", "spotify", "vimeo"]):
        app_label = "Streaming"
    elif any(x in fname for x in ["ft", "filetransfer", "scp", "sftp", "file", "scpdown"]):
        app_label = "File_Transfer"
    elif any(x in fname for x in ["p2p", "bittorrent", "torrent"]):
        app_label = "P2P"
    elif "browse" in fname or "web" in fname:
        app_label = "Browsing"
        
    return vpn_status, app_label

def process_directory(in_dir, out_dir):
    os.makedirs(out_dir, exist_ok=True)
    csv_files = glob.glob(os.path.join(in_dir, "*.csv"))
    
    if not csv_files:
        logging.error(f"Nenhum arquivo CSV encontrado em {in_dir}")
        return
        
    for in_path in csv_files:
        filename = os.path.basename(in_path)
        out_path = os.path.join(out_dir, filename.replace(".csv", "_labeled.csv"))
        
        vpn_label, app_label = get_labels_from_filename(filename)
        
        count = 0
        with open(in_path, 'r', encoding='utf-8') as f_in, open(out_path, 'w', encoding='utf-8', newline='') as f_out:
            reader = csv.reader(f_in)
            writer = csv.writer(f_out)
            
            try:
                header = next(reader)
            except StopIteration:
                logging.warning(f"Arquivo Vazio: {in_path}")
                continue
                
            header.extend(["VPN_Status", "Application_Type"])
            writer.writerow(header)
            
            for row in reader:
                if not row or not "".join(row).strip():
                    continue
                row.extend([vpn_label, app_label])
                writer.writerow(row)
                count += 1
                
        logging.info(f"[{vpn_label} | {app_label}] {filename} -> {count} fluxos")

if __name__ == '__main__':
    if len(sys.argv) != 3:
        print("Uso: iscx_vpn_labeler.py <input_dir> <output_dir>")
        sys.exit(1)
        
    process_directory(sys.argv[1], sys.argv[2])

