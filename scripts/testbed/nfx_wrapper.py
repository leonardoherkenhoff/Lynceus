#!/usr/bin/env python3
"""
Lynceus Parity Experiment — NetFeatureXtract (NFX) Wrapper
-----------------------------------------------------------
Baseado no repositório: https://github.com/geinsfeldt/NetFeatureXtract
"""

import os
import subprocess
import time
import signal
import glob
import re
import sys

# Paths
NFX_DIR = "/opt/NetFeatureXtract"
if not os.path.exists(NFX_DIR):
    NFX_DIR = "/opt/XFAST/ebpf"

NFX_BIN = os.path.join(NFX_DIR, "xdp_user")
INTERIM_DIR = "/opt/eBPFNetFlowLyzer/data/interim/XFAST_RAW"
PCAP_DIR = "/opt/eBPFNetFlowLyzer/data/raw"

def _sanitize_nfx_csv(raw_path, clean_path):
    unique_flows = {}
    header = None
    if not os.path.exists(raw_path): return
    with open(raw_path, "r") as f:
        for line in f:
            line = line.strip()
            if not line or "DEBUG" in line or "Map" in line: continue
            if "," in line:
                parts = line.split(",")
                if "src_ip" in line or "packets" in line:
                    if header is None: header = line
                    continue
                if len(parts) >= 5:
                    key = tuple(parts[:5])
                    unique_flows[key] = line
    with open(clean_path, "w") as f:
        if header: f.write(header + "\n")
        else: f.write("src_ip,dst_ip,src_port,dst_port,protocol,packets,bytes,duration,pps,bps,max_pkt_len,min_pkt_len,max_pps,min_pps,max_bps,min_bps,avg_pps,avg_bps,avg_bpp\n")
        for key in sorted(unique_flows.keys()):
            f.write(unique_flows[key] + "\n")

def run_nfx_extraction(smoke_test=False):
    if not os.path.exists(NFX_BIN):
        print(f"❌ NFX Binary not found at {NFX_BIN}")
        sys.exit(1)

    os.makedirs(INTERIM_DIR, exist_ok=True)
    pcaps = sorted(glob.glob(os.path.join(PCAP_DIR, "**", "*.pcap*"), recursive=True))
    print(f"   [DEBUG] Found {len(pcaps)} PCAPs in {PCAP_DIR}")
    if not pcaps:
        print(f"   ❌ No PCAPs found in {PCAP_DIR}!")
        return

    if smoke_test:
        print(f"   [DEBUG] Smoke test: processing only {pcaps[0]}")
        pcaps = [pcaps[0]]
    
    for i, pcap in enumerate(pcaps):
        category = os.path.basename(os.path.dirname(pcap))
        out_dir = os.path.join(INTERIM_DIR, category)
        os.makedirs(out_dir, exist_ok=True)
        out_file = os.path.join(out_dir, "flows.csv")
        raw_file = out_file + ".raw"
        
        print(f"[*] [{i+1}/{len(pcaps)}] NFX Extracting: {pcap} (Category: {category})")
        
        # Setup VETH
        subprocess.run("ip link delete veth0 2>/dev/null || true", shell=True)
        subprocess.run("ip link add veth0 type veth peer name veth1 || true", shell=True)
        subprocess.run("ip link set veth0 up", shell=True)
        subprocess.run("ip link set veth1 up", shell=True)

        try:
            with open(raw_file, "w") as f_raw:
                proc = subprocess.Popen([NFX_BIN, "veth1"], 
                                        stdout=f_raw, stderr=subprocess.STDOUT,
                                        preexec_fn=os.setsid)
                time.sleep(2)
                print(f"   Replaying {os.path.basename(pcap)}...")
                limit_flag = ["--limit", "5000"] if smoke_test else []
                subprocess.run(["tcpreplay", "-i", "veth0"] + limit_flag + [pcap], 
                               check=True, timeout=300)
                time.sleep(2)
                os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
                proc.wait(timeout=5)
        except Exception as e:
            print(f"   ⚠️  Error replaying {pcap}: {e}")
        finally:
            subprocess.run("ip link delete veth0 2>/dev/null || true", shell=True)
            _sanitize_nfx_csv(raw_file, out_file)
            print(f"   ✅ Done. Saved to {out_file}")

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="NFX Extraction Wrapper")
    parser.add_argument("--output", type=str, help="Override interim output directory")
    parser.add_argument("--smoke-test", action="store_true", help="Process only the first PCAP")
    args = parser.parse_args()
    if args.output: INTERIM_DIR = os.path.abspath(args.output)
    run_nfx_extraction(smoke_test=args.smoke_test)
