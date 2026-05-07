#!/usr/bin/env python3
"""
Lynceus Parity Experiment Orchestrator
---------------------------------------
Executa o pipeline completo de paridade:
  1. Lynceus (develop)    → data/interim/EBPF_RAW    → labeling → benchmark
  2. RustiFlow            → data/interim/RUSTIFLOW_RAW → labeling → benchmark
  3. XFAST (NFX)          → data/interim/XFAST_RAW    → labeling → benchmark
  4. NTLFlowLyzer         → data/interim/NTL_RAW      → labeling → benchmark

Salva resultados em results_parity/<tool>/
Gera comparison_report.json com tabela comparativa final.

Uso: sudo python3 run_parity_experiment.py [--tools lynceus rustiflow xfast ntl]
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

# Mapa: tool → (wrapper, interim_dir, processed_dir)
TOOLS = {
    "lynceus": {
        "wrapper":   "scripts/testbed/ebpf_wrapper.py",
        "interim":   "data/interim/EBPF_RAW",
        "processed": "data/processed/EBPF",
        "label":     "Lynceus (eBPF/XDP)",
    },
    "rustiflow": {
        "wrapper":   "scripts/testbed/rustiflow_wrapper.py",
        "interim":   "data/interim/RUSTIFLOW_RAW",
        "processed": "data/processed/RUSTIFLOW",
        "label":     "RustiFlow (CIC-83)",
    },
    "xfast": {
        "wrapper":   "scripts/testbed/xfast_wrapper.py",
        "interim":   "data/interim/XFAST_RAW",
        "processed": "data/processed/XFAST",
        "label":     "XFAST/NFX (XDP)",
    },
    "ntl": {
        "wrapper":   "scripts/testbed/ntlflowlyzer_wrapper.py",
        "interim":   "data/interim/NTL_RAW",
        "processed": "data/processed/NTL",
        "label":     "NTLFlowLyzer",
    },
}


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
            "hostname": os.uname().nodename}
    with open(os.path.join(dest, "experiment_meta.json"), "w") as f:
        json.dump(meta, f, indent=2)

    print(f"[+] Resultados salvos em: {dest}")


def run_tool(tool_name, tool_cfg):
    print(f"\n{'='*60}")
    print(f"  TOOL: {tool_cfg['label']}")
    print(f"{'='*60}")

    log_dir = os.path.join(RESULTS_BASE, tool_name, "logs")
    os.makedirs(log_dir, exist_ok=True)

    clean_dirs(tool_cfg)

    # Extração
    if not run(f"sudo python3 {tool_cfg['wrapper']}",
               f"Extração — {tool_cfg['label']}",
               log_path=os.path.join(log_dir, "extraction.log")):
        return False

    # Labeling — injeta o processed_dir correto
    labeler_cmd = (f"sudo python3 {LABELER} "
                   f"--input {os.path.join(BASE_DIR, tool_cfg['interim'])} "
                   f"--output {os.path.join(BASE_DIR, tool_cfg['processed'])}")
    if not run(labeler_cmd, f"Labeling — {tool_cfg['label']}",
               log_path=os.path.join(log_dir, "labeling.log")):
        return False

    # Benchmark
    bench_cmd = (f"sudo python3 {BENCHMARK} "
                 f"--dataset {os.path.join(BASE_DIR, tool_cfg['processed'])}")
    if not run(bench_cmd, f"Benchmark — {tool_cfg['label']}",
               log_path=os.path.join(log_dir, "ml_benchmark.log")):
        return False

    save_results(tool_name, tool_cfg)
    return True


def generate_comparison_report(results):
    """Lê ml_results.json de cada tool e gera tabela comparativa."""
    report = {"tools": {}, "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")}

    for tool_name in results:
        tool_dest = os.path.join(RESULTS_BASE, tool_name)
        ml_files  = glob.glob(os.path.join(tool_dest, "**", "ml_results.json"), recursive=True)
        tool_metrics = {}
        for mf in sorted(ml_files):
            attack = os.path.basename(os.path.dirname(mf))
            try:
                with open(mf) as f:
                    tool_metrics[attack] = json.load(f)
            except Exception:
                pass
        report["tools"][tool_name] = {
            "label": TOOLS[tool_name]["label"],
            "status": results[tool_name],
            "metrics_by_attack": tool_metrics
        }

    report_path = os.path.join(RESULTS_BASE, "comparison_report.json")
    with open(report_path, "w") as f:
        json.dump(report, f, indent=2)

    # Imprime tabela resumo
    print(f"\n{'='*70}")
    print(f"  COMPARISON REPORT — Lynceus Parity Experiment")
    print(f"{'='*70}")
    all_attacks = set()
    for t in report["tools"].values():
        all_attacks.update(t["metrics_by_attack"].keys())

    for attack in sorted(all_attacks):
        print(f"\n  [{attack}]")
        print(f"  {'Tool':<20} {'F1':>8} {'Acc':>8} {'Prec':>8} {'Rec':>8} {'Features':>10}")
        print(f"  {'-'*20} {'-'*8} {'-'*8} {'-'*8} {'-'*8} {'-'*10}")
        for tname, tdata in report["tools"].items():
            m = tdata["metrics_by_attack"].get(attack, {})
            if m:
                print(f"  {tdata['label']:<20} "
                      f"{m.get('f1_score',0):>8.4f} "
                      f"{m.get('accuracy',0):>8.4f} "
                      f"{m.get('precision',0):>8.4f} "
                      f"{m.get('recall',0):>8.4f} "
                      f"{m.get('n_features',0):>10}")
            else:
                print(f"  {tdata['label']:<20} {'N/A':>8}")

    print(f"\n[+] Relatório completo em: {report_path}")


def main():
    parser = argparse.ArgumentParser(description="Lynceus Parity Experiment Orchestrator")
    parser.add_argument("--tools", nargs="+", default=list(TOOLS.keys()),
                        choices=list(TOOLS.keys()),
                        help="Ferramentas a executar (padrão: todas)")
    args = parser.parse_args()

    if os.geteuid() != 0:
        print("[!] Requer root para XDP attachment.")
        sys.exit(1)

    os.makedirs(RESULTS_BASE, exist_ok=True)
    results  = {}
    t_global = time.time()

    for tool_name in args.tools:
        t_tool = time.time()
        ok = run_tool(tool_name, TOOLS[tool_name])
        results[tool_name] = "OK" if ok else "FAIL"
        print(f"\n  [{tool_name}] {results[tool_name]} ({time.time()-t_tool:.0f}s)")

    print(f"\n{'='*60}")
    print(f"  SUMÁRIO FINAL (dt_total={time.time()-t_global:.0f}s)")
    print(f"{'='*60}")
    for t, r in results.items():
        print(f"  {TOOLS[t]['label']:30s} {r}")

    generate_comparison_report(results)


if __name__ == "__main__":
    main()
