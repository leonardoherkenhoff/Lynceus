#!/usr/bin/env python3
"""
Lynceus Turbo Parity Experiment — Parallel NFX Wrapper
-------------------------------------------------------
Aceleração massiva para recuperação de dados pós-incidente.
"""

import os
import subprocess
import time
import signal
import glob
import re
import sys
import json
import multiprocessing
from concurrent.futures import ProcessPoolExecutor

# Paths
BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
NFX_DIR = "/opt/NetFeatureXtract"
if not os.path.exists(NFX_DIR):
    NFX_DIR = "/opt/XFAST/ebpf"

NFX_BIN = os.path.join(NFX_DIR, "xdp_user")
INTERIM_DIR = os.path.join(BASE_DIR, "data/interim/NFX_RAW")
PCAP_DIR = os.path.join(BASE_DIR, "data/raw")

def _sanitize_nfx_csv(raw_path, clean_path):
    if not os.path.exists(raw_path): return
    with open(raw_path, "r") as f:
        content = f.read()
    pattern = r"Flow:\s+([\d\.]+):(\d+)\s+->\s+([\d\.]+):(\d+)\s+\(IPv4, Proto:\s+(\d+)\)\s+Packets:\s+(\d+)\s+Bytes:\s+(\d+)"
    matches = re.findall(pattern, content)
    with open(clean_path, "w") as f:
        f.write("src_ip,src_port,dst_ip,dst_port,protocol,packets,bytes\n")
        for m in matches:
            f.write(f"{m[0]},{m[1]},{m[2]},{m[3]},{m[4]},{m[5]},{m[6]}\n")

def process_single_pcap(args):
    pcap, idx, total, smoke_test = args
    category = os.path.basename(os.path.dirname(pcap))
    out_dir = os.path.join(INTERIM_DIR, category)
    os.makedirs(out_dir, exist_ok=True)
    
    # Unique names for parallel safety
    pcap_name = os.path.basename(pcap)
    out_file = os.path.join(out_dir, f"flows_{pcap_name}.csv")
    raw_file = out_file + ".raw"
    veth0 = f"veth{idx}_0"
    veth1 = f"veth{idx}_1"
    
    print(f"[*] [{idx+1}/{total}] Starting Parallel Extraction: {pcap_name}")
    
    # Setup Unique VETH
    subprocess.run(f"ip link delete {veth0} 2>/dev/null || true", shell=True)
    subprocess.run(f"ip link add {veth0} type veth peer name {veth1} || true", shell=True)
    subprocess.run(f"ip link set {veth0} up", shell=True)
    subprocess.run(f"ip link set {veth1} up", shell=True)

    start_time = time.time()
    try:
        with open(raw_file, "w") as f_raw:
            proc = subprocess.Popen([NFX_BIN, veth1], stdout=f_raw, stderr=subprocess.DEVNULL, cwd=NFX_DIR, preexec_fn=os.setsid)
            time.sleep(1)
            
            limit_flag = ["--limit", "5000"] if smoke_test else []
            cmd = f"tcpreplay -i {veth0} {' '.join(limit_flag)} {pcap}"
            subprocess.run(cmd, shell=True, capture_output=True, text=True, check=True, timeout=1800)
            
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
            proc.wait(timeout=5)
    except Exception as e:
        print(f"   ⚠️ Error {pcap_name}: {e}")
    finally:
        elapsed = time.time() - start_time
        subprocess.run(f"ip link delete {veth0} 2>/dev/null || true", shell=True)
        _sanitize_nfx_csv(raw_file, out_file)
        print(f"   ✅ Finished {pcap_name} in {elapsed:.1f}s")

def run_nfx_extraction_parallel(smoke_test=False):
    if not os.path.exists(NFX_BIN):
        print(f"❌ NFX Binary not found at {NFX_BIN}"); sys.exit(1)

    os.makedirs(INTERIM_DIR, exist_ok=True)
    pcaps = []
    for cat in ["PCAP", "PCAPv6"]:
        cat_dir = os.path.join(PCAP_DIR, cat)
        if os.path.exists(cat_dir):
            for root, _, files in os.walk(cat_dir):
                for f in files:
                    if f.endswith('.pcap') or f.endswith('.pcapng'):
                        pcaps.append(os.path.join(root, f))
    pcaps = sorted(pcaps)
    if smoke_test: pcaps = pcaps[:1]

    print(f"🚀 TURBO MODE: Parallelizing {len(pcaps)} PCAPs using {multiprocessing.cpu_count()} cores.")
    
    # Map tasks
    tasks = [(p, i, len(pcaps), smoke_test) for i, p in enumerate(pcaps)]
    
    with ProcessPoolExecutor(max_workers=multiprocessing.cpu_count()) as executor:
        list(executor.map(process_single_pcap, tasks))

    # Consolidation Step: Combine all flows_<pcap>.csv into category/flows.csv
    print("[*] Consolidating results...")
    for cat in os.listdir(INTERIM_DIR):
        cat_path = os.path.join(INTERIM_DIR, cat)
        if not os.path.isdir(cat_path): continue
        final_csv = os.path.join(cat_path, "flows.csv")
        pcap_csvs = glob.glob(os.path.join(cat_path, "flows_*.csv"))
        if not pcap_csvs: continue
        
        with open(final_csv, "w") as f_out:
            f_out.write("src_ip,src_port,dst_ip,dst_port,protocol,packets,bytes\n")
            for pc in pcap_csvs:
                with open(pc) as f_in:
                    lines = f_in.readlines()[1:] # skip header
                    f_out.writelines(lines)
                os.remove(pc)
                if os.path.exists(pc + ".raw"): os.remove(pc + ".raw")

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--smoke-test", action="store_true")
    args = parser.parse_args()
    run_nfx_extraction_parallel(smoke_test=args.smoke_test)
