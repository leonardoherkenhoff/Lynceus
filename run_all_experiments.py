#!/usr/bin/env python3
"""
Lynceus Multi-Branch Experiment Runner
--------------------------------------
Executa o pipeline completo (build -> extraction -> labeling -> benchmark)
sequencialmente em cada branch de paridade, isolando resultados por diretório.

Uso: sudo python3 run_all_experiments.py [--branches b1 b2 ...] [--skip-build]
"""

import subprocess
import os
import sys
import time
import shutil
import argparse
import json

BASE_DIR = "/opt/eBPFNetFlowLyzer"
ALL_BRANCHES = ["develop", "parity-rustiflow", "parity-nfx", "parity-netflowlyzer"]
RESULTS_BASE = os.path.join(BASE_DIR, "results_multi_branch")

INTERIM_DIR = os.path.join(BASE_DIR, "data/interim/EBPF_RAW")
PROCESSED_DIR = os.path.join(BASE_DIR, "data/processed/EBPF")

def run(cmd, desc, check=True, log_path=None):
    print(f"\n[*] {desc}")
    if log_path:
        print(f"    [Logging to: {log_path}]")
        f = open(log_path, "w")
    else:
        f = None
    
    t0 = time.time()
    r = subprocess.run(cmd, shell=True, cwd=BASE_DIR, stdout=f, stderr=subprocess.STDOUT)
    dt = time.time() - t0
    
    if f: f.close()
    
    status = "OK" if r.returncode == 0 else "FAIL"
    print(f"    [{status}] dt={dt:.1f}s")
    if check and r.returncode != 0:
        print(f"[!] Abortando branch por falha em: {desc}")
        return False
    return True

def clean_interim():
    """Remove dados intermediários para evitar contaminação entre branches."""
    for d in [INTERIM_DIR, PROCESSED_DIR]:
        if os.path.exists(d):
            shutil.rmtree(d)
            os.makedirs(d, exist_ok=True)

def save_results(branch):
    """Copia resultados para diretório isolado por branch."""
    dest = os.path.join(RESULTS_BASE, branch)
    os.makedirs(dest, exist_ok=True)

    for src_rel in ["data/interim/EBPF_RAW", "data/processed/EBPF"]:
        src = os.path.join(BASE_DIR, src_rel)
        if os.path.exists(src):
            dst = os.path.join(dest, src_rel)
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            shutil.copytree(src, dst, dirs_exist_ok=True)

    # Salva metadados
    meta = {
        "branch": branch,
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "hostname": os.uname().nodename,
    }
    with open(os.path.join(dest, "experiment_meta.json"), "w") as f:
        json.dump(meta, f, indent=2)

    print(f"[+] Resultados salvos em: {dest}")

def run_branch(branch, skip_build=False):
    print(f"\n{'='*60}")
    print(f"  BRANCH: {branch}")
    print(f"{'='*60}")

    log_dir = os.path.join(RESULTS_BASE, branch, "logs")
    os.makedirs(log_dir, exist_ok=True)

    if not run(f"git checkout {branch}", f"Checkout {branch}"):
        return False
    if not run(f"git pull origin {branch}", f"Pull {branch}", check=False):
        pass  # Pull pode falhar se não houver remote, continua

    if not skip_build:
        if not run("make clean && make 2>&1", "Compilacao", 
                   log_path=os.path.join(log_dir, "build.log")):
            return False
    
    clean_interim()

    if not run("sudo python3 scripts/testbed/ebpf_wrapper.py",
               "Extracao (VETH + tcpreplay)",
               log_path=os.path.join(log_dir, "extraction.log")):
        return False

    if not run("sudo python3 scripts/preprocessing/ebpf_labeler.py",
               "Labeling (Ground-Truth)",
               log_path=os.path.join(log_dir, "labeling.log")):
        return False

    if not run("sudo python3 scripts/analysis/ebpf_run_benchmark.py",
               "Benchmark (Random Forest)",
               log_path=os.path.join(log_dir, "ml_benchmark.log")):
        return False

    save_results(branch)
    return True

def main():
    parser = argparse.ArgumentParser(description="Lynceus Multi-Branch Experiment Runner")
    parser.add_argument("--branches", nargs="+", default=ALL_BRANCHES,
                        help="Branches para executar")
    parser.add_argument("--skip-build", action="store_true",
                        help="Pular compilacao (usar binario existente)")
    args = parser.parse_args()

    if os.geteuid() != 0:
        print("[!] Requer root para XDP attachment.")
        sys.exit(1)

    os.makedirs(RESULTS_BASE, exist_ok=True)
    
    results = {}
    t_global = time.time()

    for branch in args.branches:
        t_branch = time.time()
        ok = run_branch(branch, args.skip_build)
        dt = time.time() - t_branch
        results[branch] = {"status": "OK" if ok else "FAIL", "duration_s": round(dt, 1)}

    # Retorna para develop
    subprocess.run("git checkout develop", shell=True, cwd=BASE_DIR)

    # Sumario final
    total_dt = time.time() - t_global
    print(f"\n{'='*60}")
    print(f"  SUMARIO FINAL (dt_total={total_dt:.0f}s)")
    print(f"{'='*60}")
    for b, r in results.items():
        print(f"  {b:30s} {r['status']:6s} ({r['duration_s']:.0f}s)")

    with open(os.path.join(RESULTS_BASE, "global_summary.json"), "w") as f:
        json.dump({"results": results, "total_duration_s": round(total_dt, 1),
                    "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")}, f, indent=2)

if __name__ == "__main__":
    main()
