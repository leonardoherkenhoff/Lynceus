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

BASE_DIR     = "/opt/eBPFNetFlowLyzer"
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
        "wrapper":   "scripts/testbed/ebpf_wrapper.py",
        "interim":   "data/interim/EBPF_PARITY_NTL",
        "processed": "data/processed/EBPF_PARITY_NTL",
        "label":     "Lynceus (NTL+AL Parity)",
        "bench_args": "--parity-mode ntl",
        "branch":    "parity-netflowlyzer"
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
        "wrapper":   "scripts/testbed/ebpf_wrapper.py",
        "interim":   "data/interim/EBPF_PARITY_NFX",
        "processed": "data/processed/EBPF_PARITY_NFX",
        "label":     "Lynceus (NFX Parity)",
        "bench_args": "--parity-mode nfx",
        "branch":    "parity-nfx"
    },
    "lynceus_vs_rustiflow": {
        "wrapper":   "scripts/testbed/ebpf_wrapper.py",
        "interim":   "data/interim/EBPF_PARITY_RUSTIFLOW",
        "processed": "data/processed/EBPF_PARITY_RUSTIFLOW",
        "label":     "Lynceus (RustiFlow Parity)",
        "bench_args": "--parity-mode rustiflow",
        "branch":    "parity-rustiflow"
    }
}

# Execution Order (Strict Scientific Sequence)
EXECUTION_ORDER = [
    "lynceus_full", "lynceus_vs_ntl", 
    "nfx_full", "rustiflow_full", 
    "lynceus_vs_nfx", "lynceus_vs_rustiflow"
]

def run(cmd, desc, log_path=None, check=True):
    print(f"\n[*] {desc}")
    f = open(log_path, "w") if log_path else None
    t0 = time.time()
    r = subprocess.run(cmd, shell=True, cwd=BASE_DIR,
                       stdout=f, stderr=subprocess.STDOUT if f else None)
    dt = time.time() - t0
    if f:
        f.close()
    status = "OK" if r.returncode == 0 else "FAIL"
    print(f"    [{status}] dt={dt:.1f}s")
    if check and r.returncode != 0:
        print(f"[!] Falha em: {desc}")
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
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            shutil.copytree(src, dst, dirs_exist_ok=True)

    meta = {"tool": tool_name, "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "hostname": os.uname().nodename, "label": tool_cfg["label"]}
    with open(os.path.join(dest, "experiment_meta.json"), "w") as f:
        json.dump(meta, f, indent=2)

def run_tool(tool_name, tool_cfg):
    print(f"\n--- {tool_cfg['label']} ---")
    log_dir = os.path.join(RESULTS_BASE, tool_name, "logs")
    os.makedirs(log_dir, exist_ok=True)
    clean_dirs(tool_cfg)

    # 1. Git Checkout & Build (if branch specified)
    current_branch = subprocess.check_output("git rev-parse --abbrev-ref HEAD", shell=True, text=True).strip()
    target_branch = tool_cfg.get("branch")
    
    if target_branch and target_branch != current_branch:
        if not run(f"git checkout {target_branch}", f"Checkout {target_branch}", log_path=os.path.join(log_dir, "git.log")):
            return False
        if not run("make clean && make", "Rebuilding Lynceus Parity Engine", log_path=os.path.join(log_dir, "build.log")):
            run(f"git checkout {current_branch}", "Returning to safety")
            return False

    # 2. Extração
    extraction_cmd = f"sudo python3 {tool_cfg['wrapper']} --output {os.path.join(BASE_DIR, tool_cfg['interim'])}"
    extraction_ok = run(extraction_cmd, f"Extração — {tool_cfg['label']}", log_path=os.path.join(log_dir, "extraction.log"))
    
    # Return to original branch immediately after extraction
    if target_branch and target_branch != current_branch:
        run(f"git checkout {current_branch}", f"Returning to {current_branch}")

    if not extraction_ok:
        return False

    # Labeling
    labeler_cmd = (f"sudo python3 {LABELER} --input {os.path.join(BASE_DIR, tool_cfg['interim'])} "
                   f"--output {os.path.join(BASE_DIR, tool_cfg['processed'])}")
    if not run(labeler_cmd, f"Labeling — {tool_cfg['label']}", log_path=os.path.join(log_dir, "labeling.log")):
        return False

    # Benchmark
    bench_cmd = (f"sudo python3 {BENCHMARK} --dataset {os.path.join(BASE_DIR, tool_cfg['processed'])} {tool_cfg['bench_args']}")
    if not run(bench_cmd, f"Benchmark — {tool_cfg['label']}", log_path=os.path.join(log_dir, "ml_benchmark.log")):
        return False

    save_results(tool_name, tool_cfg)
    return True

def generate_comparison_report(results):
    report = {"results": {}, "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")}
    for tool_name in results:
        tool_dest = os.path.join(RESULTS_BASE, tool_name)
        ml_files  = glob.glob(os.path.join(tool_dest, "**", "ml_results.json"), recursive=True)
        tool_metrics = {}
        for mf in sorted(ml_files):
            rel_path = os.path.relpath(os.path.dirname(mf), os.path.join(tool_dest, TOOLS[tool_name]["processed"]))
            attack = rel_path.replace(os.sep, "/")
            try:
                with open(mf) as f:
                    tool_metrics[attack] = json.load(f)
            except: pass
        report["results"][tool_name] = {"label": TOOLS[tool_name]["label"], "status": results[tool_name], "metrics_by_attack": tool_metrics}

    with open(os.path.join(RESULTS_BASE, "comparison_report.json"), "w") as f:
        json.dump(report, f, indent=2)

    print(f"\n{'='*85}\n  COMPARISON REPORT — Lynceus Scientific Parity\n{'='*85}")
    all_attacks = set()
    for t in report["results"].values(): all_attacks.update(t["metrics_by_attack"].keys())

    for attack in sorted(all_attacks):
        if not attack or attack == ".": continue
        print(f"\n  [{attack}]")
        print(f"  {'Tool/Step':<40} {'F1':>8} {'Acc':>8} {'Prec':>8} {'Features':>10}")
        print(f"  {'-'*40} {'-'*8} {'-'*8} {'-'*8} {'-'*10}")
        for tname in EXECUTION_ORDER:
            if tname not in report["results"]: continue
            tdata = report["results"][tname]
            m = tdata["metrics_by_attack"].get(attack, {})
            if m: print(f"  {tdata['label']:<40} {m.get('f1_score',0):>8.4f} {m.get('accuracy',0):>8.4f} {m.get('precision',0):>8.4f} {m.get('n_features',0):>10}")
            else: print(f"  {tdata['label']:<40} {'N/A':>8}")

def main():
    parser = argparse.ArgumentParser(description="Lynceus Parity Orchestrator")
    parser.add_argument("--steps", nargs="+", default=EXECUTION_ORDER, choices=list(TOOLS.keys()))
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
            
        ok = run_tool(tool_name, cfg)
        results[tool_name] = "OK" if ok else "FAIL"
        print(f"  [{tool_name}] {results[tool_name]} ({time.time()-t0:.0f}s)")
        if args.smoke_test and not ok:
            print(f"❌ Smoke test failed at step {tool_name}. Aborting.")
            break

    generate_comparison_report(results)
    print(f"\n[+] Total Time: {time.time()-t_global:.0f}s")

if __name__ == "__main__":
    main()
