import subprocess, time, re, sys

RUSTIFLOW_BIN = "/root/.cargo/bin/rustiflow"
LYNCEUS_BIN = "build/loader"

DATASETS = {
    "CIC-IDS-2017 (Mixed)": "/root/CIC-IDS-2017/Monday-WorkingHours.pcap",
    "CICDDoS2019 (Syn)": "/root/CICDDoS2019/PCAP/01-12/Syn/20181201-153030_ate_20181201-153231.pcap"
}

def run_offline_benchmark():
    for name, pcap in DATASETS.items():
        print("\n" + "="*60)
        print(f"=== OFFLINE PCAP NATIVE INJECTION: {name} ===")
        print("="*60)
        
        # 1. RustiFlow
        print("\n[*] Running RustiFlow...")
        cmd_rf = f"sudo {RUSTIFLOW_BIN} -f rustiflow -o print pcap {pcap} > /dev/null"
        t0 = time.time()
        try:
            subprocess.run(cmd_rf, shell=True, timeout=300)
            t1 = time.time()
            print(f"[+] RustiFlow completed in {t1-t0:.2f} seconds.")
        except Exception as e:
            print(f"[-] RustiFlow failed: {e}")

        time.sleep(2)
        
        # 2. Lynceus
        print("\n[*] Running Lynceus...")
        cmd_lyn = f"cd /opt/lynceus && sudo {LYNCEUS_BIN} --pcap {pcap} > /dev/null"
        t0 = time.time()
        try:
            res = subprocess.run(cmd_lyn, shell=True, capture_output=True, text=True, timeout=300)
            t1 = time.time()
            pps_match = re.search(r"Speed\s*:\s*([\d\.]+)\s*PPS", res.stderr)
            pkts_match = re.search(r"(\d+) packets injected", res.stderr)
            if pps_match and pkts_match:
                print(f"[+] Lynceus completed in {t1-t0:.2f} seconds. Packets: {pkts_match.group(1)}. Speed: {pps_match.group(1)} PPS.")
            else:
                print(f"[+] Lynceus completed in {t1-t0:.2f} seconds. (Could not parse PPS)")
                if res.stderr: print("    [STDERR] " + res.stderr.strip()[:200])
        except Exception as e:
            print(f"[-] Lynceus failed: {e}")

if __name__ == "__main__":
    run_offline_benchmark()
