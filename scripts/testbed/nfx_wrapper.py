#!/usr/bin/env python3
"""
Lynceus Parity Experiment — NetFeatureXtract (NFX) Wrapper
-----------------------------------------------------------
Versão Sequencial Estável com Timeout de 1800s.
"""

import os
import subprocess
import time
import signal
import glob
import re
import sys
import json

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

def run_nfx_extraction(smoke_test=False, max_events=0, skip_labeling=False):
    global INTERIM_DIR
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

    total_flows = 0
    for i, pcap in enumerate(pcaps):
        if max_events > 0 and total_flows >= max_events:
            print(f"   🛑 Limit reached ({max_events}). Skipping remaining PCAPs.")
            break
        category = os.path.basename(os.path.dirname(pcap))
        out_dir = os.path.join(INTERIM_DIR, category)
        os.makedirs(out_dir, exist_ok=True)
        out_file = os.path.join(out_dir, "flows.csv")
        raw_file = out_file + ".raw"
        
        print(f"[*] [{i+1}/{len(pcaps)}] NFX Extracting: {pcap}")
        metrics_csv = os.path.join(out_dir, "resource_metrics.csv")
        monitor_script = os.path.join(BASE_DIR, "scripts/testbed/monitor.py")
        
        subprocess.run("ip link delete veth0 2>/dev/null || true", shell=True)
        subprocess.run("ip link add veth0 type veth peer name veth1 || true", shell=True)
        subprocess.run("ip link set veth0 up", shell=True)
        subprocess.run("ip link set veth1 up", shell=True)

        start_time = time.time()
        try:
            with open(raw_file, "a") as f_raw:
                proc = subprocess.Popen([NFX_BIN, "veth1"], stdout=f_raw, stderr=subprocess.STDOUT, cwd=NFX_DIR, preexec_fn=os.setsid)
                time.sleep(2)
                proc_mon = subprocess.Popen(["python3", monitor_script, str(proc.pid), metrics_csv]) if os.path.exists(monitor_script) else None

                cmd = f"tcpreplay -i veth0 {pcap}"
                proc_tcpreplay = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
                
                while True:
                    if proc_tcpreplay.poll() is not None:
                        break
                    if proc.poll() is not None:
                        proc_tcpreplay.terminate()
                        break
                    time.sleep(0.5)
                
                os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
                proc.wait(timeout=5)
                if proc_mon: proc_mon.terminate()
        except Exception as e:
            print(f"   ⚠️ Error: {e}")
        finally:
            elapsed = time.time() - start_time
            subprocess.run("ip link delete veth0 2>/dev/null || true", shell=True)
            _sanitize_nfx_csv(raw_file, out_file)
            
            if max_events > 0 and os.path.exists(out_file):
                print(f"   ✂️ Enforcing strict parity limit: Truncating to {max_events} flows")
                subprocess.run(f"head -n {max_events + 1} {out_file} > {out_file}.tmp && mv {out_file}.tmp {out_file}", shell=True)

            # Rough estimate of new flows
            if os.path.exists(out_file):
                with open(out_file) as f:
                    new_flows = sum(1 for _ in f) - 1
                    total_flows += max(0, new_flows)
            print(f"   ✅ Done in {elapsed:.1f}s")

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--smoke-test", action="store_true")
    parser.add_argument("--max-events", type=int, default=0)
    parser.add_argument("--output", type=str, help="Override interim output directory")
    parser.add_argument("--skip-labeling", action="store_true", help="Bypass internal labeling")
    args = parser.parse_args()
    if args.output: INTERIM_DIR = os.path.abspath(args.output)
    run_nfx_extraction(smoke_test=args.smoke_test, max_events=args.max_events, skip_labeling=args.skip_labeling)
