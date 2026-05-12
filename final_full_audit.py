import os
import re
import sys

def get_pcap_name(line):
    # Try different patterns for PCAP identification
    patterns = [
        r"Streaming: ([^ ]+)",
        r"Processing: ([^ ]+)",
        r"Extracting: .*?PCAP/(.*\.pcap)",
        r"Extracting: (.*\.pcap)"
    ]
    for p in patterns:
        m = re.search(p, line)
        if m:
            return m.group(1).split("/")[-1]
    return None

def audit_pilar(pilar_path):
    ext_log = os.path.join(pilar_path, "logs/extraction.log")
    ml_log = os.path.join(pilar_path, "logs/ml_benchmark.log")
    
    results = {}
    
    # Parse Extraction
    if os.path.exists(ext_log):
        current_pcap = "Unknown"
        with open(ext_log, 'r') as f:
            for line in f:
                pcap = get_pcap_name(line)
                if pcap:
                    current_pcap = pcap
                
                if "DONE:" in line or "Done in" in line:
                    metrics = line.strip()
                    # Clean up the line a bit
                    metrics = metrics.replace("✅ ", "").replace("[Lynceus Engine]", "").strip()
                    results[current_pcap] = {"perf": metrics, "ml": "N/A"}

    # Parse ML
    if os.path.exists(ml_log):
        current_attack = "Unknown"
        with open(ml_log, 'r') as f:
            for line in f:
                if ">>>" in line and "VALIDATION:" in line:
                    current_attack = line.strip().replace(">>> ", "").replace(" <<<", "")
                    # Try to normalize attack name to match PCAP if possible, or just keep it
                
                if "F1-Score:" in line:
                    f1 = line.split(":")[1].strip()
                    if current_attack not in results:
                        results[current_attack] = {"perf": "N/A", "ml": f1}
                    else:
                        results[current_attack]["ml"] = f1

    return results

def main():
    base = "parity_export_final"
    pilars = [
        ("Full (Lynceus)", "lynceus_full"),
        ("Paridade NTL", "lynceus_vs_ntl"),
        ("Paridade NFX", "lynceus_vs_nfx"),
        ("Paridade Rustiflow", "lynceus_vs_rustiflow"),
        ("NFX Original", "nfx_full"),
        ("Rustiflow Original", "rustiflow_full")
    ]
    
    for label, folder in pilars:
        path = os.path.join(base, folder)
        print(f"\n\033[1;33m==== {label.upper()} ====\033[0m")
        if not os.path.exists(path):
            print(f"Diretório {path} não encontrado.")
            continue
            
        data = audit_pilar(path)
        for key in sorted(data.keys()):
            perf = data[key]["perf"]
            ml = data[key]["ml"]
            # Colorize output
            print(f"\033[1;36m[{key}]\033[0m")
            print(f"  Perf: {perf}")
            print(f"  ML:   F1-Score: {ml}")

if __name__ == "__main__":
    main()
