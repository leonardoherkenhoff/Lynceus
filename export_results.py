#!/usr/bin/env python3
"""
Lynceus Parity Result Exporter
------------------------------
Consolidates essential experiment outputs (CSVs, Logs, Metrics) 
into a single compressed archive for scientific review.
"""

import os
import shutil
import tarfile
from datetime import datetime

# Configuration
BASE_DIR = "/opt/eBPFNetFlowLyzer"
RESULTS_DIR = os.path.join(BASE_DIR, "results_parity")
EXPORT_DIR = os.path.join(BASE_DIR, "parity_export_final")
TIMESTAMP = datetime.now().strftime("%Y%m%d_%H%M%S")
ARCHIVE_NAME = f"lynceus_parity_results_{TIMESTAMP}.tar.gz"

def export():
    print(f"🚀 INITIATING EXPORT: {RESULTS_DIR}")
    
    if os.path.exists(EXPORT_DIR):
        shutil.rmtree(EXPORT_DIR)
    os.makedirs(EXPORT_DIR)

    # Walk through results_parity
    for tool_id in os.listdir(RESULTS_DIR):
        tool_path = os.path.join(RESULTS_DIR, tool_id)
        if not os.path.isdir(tool_path): continue
        
        print(f"[*] Packaging: {tool_id}")
        dest_tool_path = os.path.join(EXPORT_DIR, tool_id)
        os.makedirs(dest_tool_path)

        # 1. Copy Logs
        log_src = os.path.join(tool_path, "logs")
        if os.path.exists(log_src):
            shutil.copytree(log_src, os.path.join(dest_tool_path, "logs"))

        # 2. Copy Processed CSVs (Recursive)
        processed_src = os.path.join(tool_path, "data/processed")
        if os.path.exists(processed_src):
            dest_csv_path = os.path.join(dest_tool_path, "telemetry")
            # Selective copy of CSV files only
            for root, dirs, files in os.walk(processed_src):
                for file in files:
                    if file.endswith(".csv"):
                        rel_dir = os.path.relpath(root, processed_src)
                        target_dir = os.path.join(dest_csv_path, rel_dir)
                        os.makedirs(target_dir, exist_ok=True)
                        shutil.copy2(os.path.join(root, file), target_dir)

    # Create Tarball
    print(f"\n📦 CREATING ARCHIVE: {ARCHIVE_NAME}...")
    with tarfile.open(os.path.join(BASE_DIR, ARCHIVE_NAME), "w:gz") as tar:
        tar.add(EXPORT_DIR, arcname=os.path.basename(EXPORT_DIR))

    print(f"\n✅ EXPORT COMPLETE!")
    print(f"   Archive: {os.path.join(BASE_DIR, ARCHIVE_NAME)}")
    print(f"   Total Size: {os.path.getsize(os.path.join(BASE_DIR, ARCHIVE_NAME)) / (1024*1024):.2f} MB")

if __name__ == "__main__":
    if not os.path.exists(RESULTS_DIR):
        print(f"❌ Error: {RESULTS_DIR} not found. Run the experiment first.")
    else:
        export()
