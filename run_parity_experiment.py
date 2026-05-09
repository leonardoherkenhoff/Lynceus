#!/usr/bin/env python3
"""
Lynceus Parity Experiment Orchestrator
---------------------------------------
Executa o protocolo científico de 6 etapas para validar paridade.
Sem vazamento (leakage) em nenhuma etapa.
"""

import subprocess
import os
import sys
import time
import shutil
import argparse
import json
import glob

BASE_DIR     = os.path.dirname(os.path.abspath(__file__))
RESULTS_BASE = os.path.join(BASE_DIR, "results_parity")
LABELER      = os.path.join(BASE_DIR, "scripts/preprocessing/ebpf_labeler.py")
BENCHMARK    = os.path.join(BASE_DIR, "scripts/analysis/ebpf_run_benchmark.py")

# Parity Benchmarking Orchestrator
# Protocol: Base vs. Parity (NTL+AL, NFX, RustiFlow)

TOOLS = {
    "lynceus_full": {
        "wrapper":   "scripts/testbed/ebpf_wrapper.py",
        "interim":   "data/interim/LYNCEUS_FULL",
        "processed": "data/processed/LYNCEUS_FULL",
        "label":     "Lynceus (Base)",
        "bench_args": "",
        "branch":    "develop"
    },
    "lynceus_vs_ntl": {
        "branch":    "parity-netflowlyzer",
        "wrapper":   "scripts/testbed/ebpf_wrapper.py",
        "interim":   "data/interim/EBPF_PARITY_NTL",
        "processed": "data/processed/EBPF_PARITY_NTL",
        "label":     "Lynceus (NTL+AL Parity)",
        "bench_args": "--parity-mode ntl"
    },
    "nfx_full": {
        "wrapper":   "scripts/testbed/nfx_wrapper.py",
        "interim":   "data/interim/NFX_RAW",
        "processed": "data/processed/NFX",
        "label":     "NFX (Original)",
        "bench_args": ""
    },
    "rustiflow_full": {
        "wrapper":   "scripts/testbed/rustiflow_wrapper.py",
        "interim":   "data/interim/RUSTIFLOW_RAW",
        "processed": "data/processed/RUSTIFLOW",
        "label":     "RustiFlow (Original)",
        "bench_args": ""
    },
    "lynceus_vs_nfx": {
        "branch":    "parity-nfx",
        "wrapper":   "scripts/testbed/ebpf_wrapper.py",
        "interim":   "data/interim/EBPF_PARITY_NFX",
        "processed": "data/processed/EBPF_PARITY_NFX",
        "label":     "Lynceus (NFX Parity)",
        "bench_args": "--parity-mode nfx"
    },
    "lynceus_vs_rustiflow": {
        "branch":    "parity-rustiflow",
        "wrapper":   "scripts/testbed/ebpf_wrapper.py",
        "interim":   "data/interim/EBPF_PARITY_RUSTIFLOW",
        "processed": "data/processed/EBPF_PARITY_RUSTIFLOW",
        "label":     "Lynceus (RustiFlow Parity)",
        "bench_args": "--parity-mode rustiflow"
    }
}

# Execution Order (Strict Scientific Sequence)
EXECUTION_ORDER = [
    "lynceus_full", "lynceus_vs_ntl", 
    "nfx_full", "rustiflow_full", 
    "lynceus_vs_nfx", "lynceus_vs_rustiflow"
]

def run(cmd, label, log_path=None):
    print(f"[*] {label}")
    start = time.time()
    
    if log_path:
        os.makedirs(os.path.dirname(log_path), exist_ok=True)
        # We use subprocess.Popen with a pipe to capture and print simultaneously
        with open(log_path, "w") as f:
            proc = subprocess.Popen(cmd, shell=True, cwd=BASE_DIR,
                                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                    text=True, bufsize=1)
            for line in proc.stdout:
                print(f"    {line.strip()}")
                f.write(line)
            proc.wait()
            return_code = proc.returncode
    else:
        r = subprocess.run(cmd, shell=True, cwd=BASE_DIR)
        return_code = r.returncode

    dt = time.time() - start
    if return_code == 0:
        print(f"    [OK] dt={dt:.1f}s")
        return True
    else:
        print(f"    [FAIL] dt={dt:.1f}s")
        return False
    return True

def clean_dirs(tool_cfg):
    for d in [tool_cfg["interim"], tool_cfg["processed"]]:
        full = os.path.join(BASE_DIR, d)
        if os.path.exists(full):
            shutil.rmtree(full)
        os.makedirs(full, exist_ok=True)

def save_results(tool_name, tool_cfg):
    dest = os.path.join(RESULTS_BASE, tool_name)
    os.makedirs(dest, exist_ok=True)

    for src_rel in [tool_cfg["interim"], tool_cfg["processed"]]:
        src = os.path.join(BASE_DIR, src_rel)
        dst = os.path.join(dest, src_rel)
        if os.path.exists(src):
            os.makedirs(dst, exist_ok=True)
            # Selective copy: logs, jsons, txts, etc. EXCLUDE MASSIVE CSVs
            for root, dirs, files in os.walk(src):
                rel_path = os.path.relpath(root, src)
                target_dir = os.path.join(dst, rel_path)
                os.makedirs(target_dir, exist_ok=True)
                for file in files:
                    if not file.endswith('.csv') or file == "resource_metrics.csv":
                        shutil.copy2(os.path.join(root, file), target_dir)


    meta = {"tool": tool_name, "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "hostname": os.uname().nodename, "label": tool_cfg["label"]}
    with open(os.path.join(dest, "experiment_meta.json"), "w") as f:
        json.dump(meta, f, indent=2)

def run_tool(tool_name, tool_cfg, resume=False):
    print(f"\n--- {tool_cfg['label']} ---")
    log_dir = os.path.join(RESULTS_BASE, tool_name, "logs")
    os.makedirs(log_dir, exist_ok=True)
    
    # Check if we can resume (data already in processed/ and not empty)
    processed_path = os.path.join(BASE_DIR, tool_cfg["processed"])
    has_data = os.path.exists(processed_path) and any(f.endswith('.csv') for _, _, files in os.walk(processed_path) for f in files)
    
    if resume and has_data:
        print(f"[*] Resuming: Found existing processed data. Skipping extraction and labeling.")
    else:
        clean_dirs(tool_cfg)

    # 1. Git Checkout & Build (if NOT resuming)
    if not (resume and has_data):
        current_branch = subprocess.check_output("git rev-parse --abbrev-ref HEAD", shell=True, text=True).strip()
        target_branch = tool_cfg.get("branch")
        
        if target_branch and target_branch != current_branch:
            if not run(f"git checkout -f {target_branch}", f"Checkout {target_branch}"):
                return False
            # Sync branch with origin to pull latest smoke-test/wrapper fixes
            run(f"git fetch origin {target_branch}", f"Fetch {target_branch} from origin")
            if not run(f"git reset --hard origin/{target_branch}", f"Hard Reset to origin/{target_branch}"):
                return False
            if not run("git status", "Git Status Check", log_path=os.path.join(log_dir, "git.log")):
                return False

        # FAULT TOLERANCE: Always rebuild the Lynceus Engine to guarantee binaries exist
        if not run("make clean && make", "Rebuilding Lynceus Engine", log_path=os.path.join(log_dir, "build.log")):
            print("❌ FATAL: Compilation failed. Aborting experiment to prevent false positives.")
            if target_branch and target_branch != current_branch:
                run(f"git checkout {current_branch}", "Returning to safety")
            return False

    # 2. Extração
    extraction_ok = True
    if not (resume and has_data):
        extraction_cmd = f"sudo python3 -u {tool_cfg['wrapper']} --output {os.path.join(BASE_DIR, tool_cfg['interim'])} --skip-labeling"
        extraction_ok = run(extraction_cmd, f"Extração — {tool_cfg['label']}", log_path=os.path.join(log_dir, "extraction.log"))

    
    # Return to original branch immediately after extraction
    if target_branch and target_branch != current_branch:
        run(f"git checkout {current_branch}", f"Returning to {current_branch}")

    if not extraction_ok:
        return False

    # 3. Labeling
    labeling_ok = True
    if not (resume and has_data):
        labeler_cmd = (f"sudo python3 -u {LABELER} --input {os.path.join(BASE_DIR, tool_cfg['interim'])} "
                       f"--output {os.path.join(BASE_DIR, tool_cfg['processed'])}")
        labeling_ok = run(labeler_cmd, f"Labeling — {tool_cfg['label']}", log_path=os.path.join(log_dir, "labeling.log"))
        
        # ⚠️  CRITICAL: Cleanup will happen AFTER save_results to preserve metrics
        if not labeling_ok:
            return False

    # Benchmark
    bench_cmd = (f"sudo python3 {BENCHMARK} --dataset {os.path.join(BASE_DIR, tool_cfg['processed'])} {tool_cfg['bench_args']}")
    bench_ok = run(bench_cmd, f"Benchmark — {tool_cfg['label']}", log_path=os.path.join(log_dir, "ml_benchmark.log"))

    # Always save results (including resource_metrics.csv and summary.json)
    save_results(tool_name, tool_cfg)
    
    # Now safe to cleanup massive CSVs
    print(f"[*] Cleaning interim data to free space...")
    shutil.rmtree(os.path.join(BASE_DIR, tool_cfg["interim"]), ignore_errors=True)
    
    return bench_ok

def _get_resource_peaks(tool_dest):
    metrics_files = glob.glob(os.path.join(tool_dest, "**", "resource_metrics.csv"), recursive=True)
    peak_ram = 0.0
    peak_cpu = 0.0
    for mf in metrics_files:
        try:
            with open(mf) as f:
                lines = f.readlines()[1:] # skip header
                for line in lines:
                    parts = line.strip().split(',')
                    if len(parts) >= 3:
                        cpu = float(parts[1])
                        ram = float(parts[2])
                        if cpu > peak_cpu: peak_cpu = cpu
                        if ram > peak_ram: peak_ram = ram
        except Exception: continue
    return peak_ram, peak_cpu

def _get_extraction_summary(tool_dest):
    summary_files = glob.glob(os.path.join(tool_dest, "**", "summary.json"), recursive=True)
    total_pkts = 0
    avg_pps = 0.0
    count = 0
    for sf in summary_files:
        try:
            with open(sf) as f:
                data = json.load(f)
                total_pkts += data.get("packets_sent", 0)
                avg_pps += data.get("pps", 0.0)
                count += 1
        except Exception: continue
    return total_pkts, (avg_pps / count if count > 0 else 0.0)

def generate_comparison_report(results=None):
    report = {"results": {}, "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")}
    
    # Discovery: Look for any results in the results_parity directory
    found_tools = [d for d in os.listdir(RESULTS_BASE) if os.path.isdir(os.path.join(RESULTS_BASE, d))]
    
    for tool_name in found_tools:
        if tool_name not in TOOLS: continue
        tool_dest = os.path.join(RESULTS_BASE, tool_name)
        
        # 1. Resource Metrics
        peak_ram, peak_cpu = _get_resource_peaks(tool_dest)
        
        # 2. Extraction Summary
        total_pkts, avg_pps = _get_extraction_summary(tool_dest)
        
        # 3. ML Metrics
        ml_files  = glob.glob(os.path.join(tool_dest, "**", "ml_results.json"), recursive=True)
        tool_metrics = {}
        for mf in sorted(ml_files):
            proc_subdir = TOOLS[tool_name]["processed"]
            try:
                rel_path = os.path.relpath(os.path.dirname(mf), os.path.join(tool_dest, proc_subdir))
                attack = rel_path.replace(os.sep, "/")
                with open(mf) as f:
                    tool_metrics[attack] = json.load(f)
            except Exception: continue
            
        report["results"][tool_name] = {
            "label": TOOLS[tool_name]["label"], 
            "status": "LOADED",
            "performance": {
                "peak_ram_mb": peak_ram,
                "peak_cpu_pct": peak_cpu,
                "total_packets": total_pkts,
                "avg_pps": avg_pps
            },
            "metrics_by_attack": tool_metrics
        }

    with open(os.path.join(RESULTS_BASE, "comparison_report.json"), "w") as f:
        json.dump(report, f, indent=2)

    print(f"\n{'='*110}\n  SCIENTIFIC PARITY REPORT — Performance & Detection Matrix\n{'='*110}")
    all_attacks = set()
    for t in report["results"].values(): all_attacks.update(t["metrics_by_attack"].keys())

    for attack in sorted(all_attacks):
        if not attack or attack == ".": continue
        print(f"\n  [Vetor: {attack}]")
        print(f"  {'Tool/Step':<30} {'F1':>7} {'Acc':>7} {'Prec':>7} {'Rec':>7} | {'Packets':>10} {'PPS':>8} {'RAM':>8} {'CPU':>6}")
        print(f"  {'-'*30} {'-'*7} {'-'*7} {'-'*7} {'-'*7} | {'-'*10} {'-'*8} {'-'*8} {'-'*6}")
        
        for tname in EXECUTION_ORDER:
            if tname not in report["results"]: continue
            tdata = report["results"][tname]
            m = tdata["metrics_by_attack"].get(attack, {})
            p = tdata["performance"]
            
            if m:
                print(f"  {tdata['label']:<30} {m.get('f1_score',0):>7.4f} {m.get('accuracy',0):>7.4f} {m.get('precision',0):>7.4f} {m.get('recall',0):>7.4f} | "
                      f"{p.get('total_packets',0):>10} {p.get('avg_pps',0):>8.0f} {p.get('peak_ram_mb',0):>8.1f} {p.get('peak_cpu_pct',0):>6.1f}%")
            else:
                print(f"  {tdata['label']:<30} {'N/A':>7}")


def main():
    parser = argparse.ArgumentParser(description="Lynceus Parity Orchestrator")
    parser.add_argument("--steps", nargs="+", default=EXECUTION_ORDER, choices=list(TOOLS.keys()))
    parser.add_argument("--resume", action="store_true", help="Skip extraction/labeling if processed data exists")
    parser.add_argument("--smoke-test", action="store_true", help="Quick validation of the full pipeline")
    args = parser.parse_args()

    if os.geteuid() != 0:
        print("[!] Root required."); sys.exit(1)

    os.makedirs(RESULTS_BASE, exist_ok=True)
    
    results = {}; t_global = time.time()

    
    for tool_name in args.steps:
        t0 = time.time()
        cfg = TOOLS[tool_name].copy()
        if args.smoke_test:
            cfg["wrapper"] += " --smoke-test"
            
        ok = run_tool(tool_name, cfg, resume=args.resume)
        results[tool_name] = "OK" if ok else "FAIL"
        print(f"  [{tool_name}] {results[tool_name]} ({time.time()-t0:.0f}s)")
        if args.smoke_test and not ok:
            print(f"❌ Smoke test failed at step {tool_name}. Aborting.")
            break

    generate_comparison_report(results)
    print(f"\n[+] Total Time: {time.time()-t_global:.0f}s")

if __name__ == "__main__":
    main()
