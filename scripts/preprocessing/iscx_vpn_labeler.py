#!/usr/bin/env python3
"""
Lynceus ISCX-VPN Labeler
Mapeia os fluxos extraídos no CSV baseando-se no contexto topológico (nome do arquivo PCAP original).
"""

import sys
import csv
import logging

logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')

def process_file(in_path, out_path, vpn_label, app_label):
    count = 0
    with open(in_path, 'r', encoding='utf-8') as f_in, open(out_path, 'w', encoding='utf-8', newline='') as f_out:
        reader = csv.reader(f_in)
        writer = csv.writer(f_out)
        
        try:
            header = next(reader)
        except StopIteration:
            logging.warning(f"Arquivo Vazio: {in_path}")
            return
            
        header.extend(["VPN_Status", "Application_Type"])
        writer.writerow(header)
        
        for row in reader:
            if not row or not "".join(row).strip():
                continue
            row.extend([vpn_label, app_label])
            writer.writerow(row)
            count += 1
            
    logging.info(f"Rotulados {count} fluxos. -> {out_path} [VPN: {vpn_label} | APP: {app_label}]")

if __name__ == '__main__':
    if len(sys.argv) != 5:
        print("Uso: iscx_vpn_labeler.py <input.csv> <output.csv> <vpn_status_label> <application_label>")
        sys.exit(1)
        
    process_file(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4])
