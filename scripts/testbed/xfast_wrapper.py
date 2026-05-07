#!/usr/bin/env python3
"""
Lynceus Parity Experiment — NetFeatureXtract (NFX) Wrapper
-----------------------------------------------------------
Baseado no repositório: https://github.com/geinsfeldt/NetFeatureXtract

Invocação: sudo python3 scripts/testbed/xfast_wrapper.py
"""

import os
import subprocess
import time
import signal
import glob
import re

# Paths
NFX_DIR = "/opt/XFAST/ebpf" # Pasta no servidor conforme ls anterior
if not os.path.exists(NFX_DIR):
    NFX_DIR = "/opt/NetFeatureXtract/ebpf"

NFX_BIN = os.path.join(NFX_DIR, "xdp_user")
INTERIM_DIR = "/opt/eBPFNetFlowLyzer/data/interim/XFAST_RAW"
PCAP_DIR = "/opt/eBPFNetFlowLyzer/data/raw"

def _sanitize_nfx_csv(raw_path, clean_path):
    """
    NetFeatureXtract imprime a tabela de fluxos a cada segundo.
    Removemos cabeçalhos repetidos e pegamos a versão mais recente de cada fluxo.
    """
    unique_flows = {}
    header = None
    
    if not os.path.exists(raw_path):
        return
        
    with open(raw_path, "r") as f:
        for line in f:
            line = line.strip()
            if not line or "DEBUG" in line or "Map" in line:
                continue
            if "," in line:
                parts = line.split(",")
                if "src_ip" in line or "packets" in line:
                    if header is None: header = line
                    continue
                # Chave de fluxo: src_ip, dst_ip, src_p, dst_p, proto
                if len(parts) >= 5:
                    key = tuple(parts[:5])
                    unique_flows[key] = line
                    
    with open(clean_path, "w") as f:
        if header:
            f.write(header + "\n")
        else:
            # Fallback header se não encontrado
            f.write("src_ip,dst_ip,src_port,dst_port,protocol,packets,bytes,duration,pps,bps,max_pkt_len,min_pkt_len,max_pps,min_pps,max_bps,min_bps,avg_pps,avg_bps,avg_bpp\n")
            
        for key in sorted(unique_flows.keys()):
            f.write(unique_flows[key] + "\n")

def run_nfx_extraction():
    if not os.path.exists(NFX_BIN):
        print(f"❌ NFX Binary not found at {NFX_BIN}")
        return

    os.makedirs(INTERIM_DIR, exist_ok=True)
    pcaps = glob.glob(os.path.join(PCAP_DIR, "**", "*.pcap*"), recursive=True)
    
    for pcap in pcaps:
        category = os.path.basename(os.path.dirname(pcap))
        out_dir = os.path.join(INTERIM_DIR, category)
        os.makedirs(out_dir, exist_ok=True)
        out_file = os.path.join(out_dir, "flows.csv")
        raw_file = out_file + ".raw"
        
        print(f"[*] NFX Extracting: {pcap} (Category: {category})")
        
        # Setup VETH (NFX precisa de interface real/veth)
        subprocess.run("ip link add veth0 type veth peer name veth1 || true", shell=True)
        subprocess.run("ip link set veth0 up && ip link set veth1 up", shell=True)
        
        # 1. Start NFX on veth1
        with open(raw_file, "w") as f_raw:
            proc = subprocess.Popen([NFX_BIN, "veth1"], 
                                    stdout=f_raw, stderr=subprocess.PIPE,
                                    preexec_fn=os.setsid)
            
            time.sleep(3) # Tempo para o BPF carregar e mapas resetarem
            
            # 2. Injetar tráfego
            print(f"   Replaying {os.path.basename(pcap)}...")
            subprocess.run(["tcpreplay", "-i", "veth0", pcap], check=True, capture_output=True)
            
            time.sleep(5) # Espera o NFX imprimir o último loop
            
            # 3. Parar NFX
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
            proc.wait()
            
        # 4. Sanitizar CSV
        _sanitize_nfx_csv(raw_file, out_file)
        print(f"   ✅ Done. Saved to {out_file}")
        
        # Limpar veth
        subprocess.run("ip link delete veth0", shell=True, stderr=subprocess.DEVNULL)

if __name__ == "__main__":
    run_nfx_extraction()
