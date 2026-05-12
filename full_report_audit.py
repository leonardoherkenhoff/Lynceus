import os
import re

def get_dir_name(line):
    # Detects the attack directory/vector
    patterns = [
        r"EXTRACTION INITIATED: ([^ ]+)",
        r"RUSTIFLOW EXTRACTION \[.*\]: ([^ ]+)",
        r"NFX Extracting: .*?data/raw/([^ ]+)/"
    ]
    for p in patterns:
        m = re.search(p, line)
        if m: return m.group(1).strip("./")
    return None

def audit_pilar(pilar_path):
    ext_log = os.path.join(pilar_path, "logs/extraction.log")
    ml_log = os.path.join(pilar_path, "logs/ml_benchmark.log")
    
    results = {}
    
    # Parse Extraction (Performance grouped by directory)
    if os.path.exists(ext_log):
        current_dir = "General"
        with open(ext_log, 'r') as f:
            for line in f:
                d = get_dir_name(line)
                if d: current_dir = d
                
                if "DONE:" in line or "Done in" in line:
                    metrics = line.strip().replace("✅ ", "").split("[")[0].strip()
                    if current_dir not in results:
                        results[current_dir] = {"perf": [], "ml": {}}
                    results[current_dir]["perf"].append(metrics)

    # Parse ML (Full Metrics + Top Features)
    if os.path.exists(ml_log):
        current_atk = "Unknown"
        with open(ml_log, 'r') as f:
            content = f.read()
            # Split by validation blocks
            blocks = content.split(">>> ")
            for block in blocks:
                if not block.strip(): continue
                lines = block.split("\n")
                header = lines[0].replace(" <<<", "").replace("VALIDATION: ", "").strip()
                # Try to map header (e.g. "PCAP/01-12/DrDoS_DNS") to results key
                atk_key = header
                if atk_key not in results:
                    results[atk_key] = {"perf": ["N/A"], "ml": {}}
                
                metrics = results[atk_key]["ml"]
                features = []
                capture_features = False
                
                for l in lines:
                    if ":" in l:
                        parts = l.split(":")
                        key = parts[0].strip()
                        val = parts[1].strip()
                        if key in ["Accuracy", "Precision", "Recall", "F1-Score", "Train Samples", "Test Samples"]:
                            metrics[key] = val
                    if "CRITICAL ATTACK SIGNATURES" in l:
                        capture_features = True
                        continue
                    if capture_features and l.strip().startswith("-"):
                        features.append(l.strip())
                    elif capture_features and not l.strip():
                        capture_features = False
                
                if features:
                    metrics["Top Features"] = ", ".join(features[:3]) # Top 3 for brevity

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
    
    C_YEL, C_CYN, C_GRN, C_BLU, C_END = "\033[1;33m", "\033[1;36m", "\033[1;32m", "\033[1;34m", "\033[0m"

    for label, folder in pilars:
        path = os.path.join(base, folder)
        print(f"\n{C_YEL}{'='*100}\n{label.upper()}\n{'='*100}{C_END}")
        if not os.path.exists(path):
            print(f"Directory {path} not found.")
            continue
            
        data = audit_pilar(path)
        for atk in sorted(data.keys()):
            print(f"\n{C_CYN}[ ATQUE / VETOR: {atk} ]{C_END}")
            # Extraction
            perfs = data[atk]["perf"]
            if perfs:
                print(f"  {C_GRN}Performance (Extração):{C_END}")
                for p in perfs[-2:]: # Show last 2 entries if many
                    print(f"    - {p}")
            
            # ML
            ml = data[atk]["ml"]
            if ml:
                print(f"  {C_BLU}Métricas ML:{C_END}")
                print(f"    F1: {ml.get('F1-Score','N/A'):<8} | Acc: {ml.get('Accuracy','N/A'):<8} | Prec: {ml.get('Precision','N/A'):<8} | Rec: {ml.get('Recall','N/A')}")
                print(f"    Amostras: Treino={ml.get('Train Samples','N/A'):<8} | Teste={ml.get('Test Samples','N/A')}")
                print(f"    Features: {ml.get('Top Features','N/A')}")

if __name__ == "__main__":
    main()
