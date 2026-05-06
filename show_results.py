#!/usr/bin/env python3
"""Consolida e exibe resultados de todas as branches."""
import os, json, glob, csv

BASE = "/opt/eBPFNetFlowLyzer/results_multi_branch"
BRANCHES = ["develop", "parity-rustiflow", "parity-nfx", "parity-netflowlyzer"]

def count_csv(path):
    """Conta linhas e colunas de um CSV."""
    try:
        with open(path) as f:
            reader = csv.reader(f)
            header = next(reader)
            rows = sum(1 for _ in reader)
            return len(header), rows
    except Exception:
        return 0, 0

def main():
    # Global summary
    gs = os.path.join(BASE, "global_summary.json")
    if os.path.exists(gs):
        with open(gs) as f:
            g = json.load(f)
        print(f"{'='*70}")
        print(f"  SUMARIO GLOBAL  |  dt_total={g.get('total_duration_s',0):.0f}s  |  {g.get('timestamp','')}")
        print(f"{'='*70}")
        for b, r in g.get("results", {}).items():
            print(f"  {b:30s}  {r['status']:6s}  {r['duration_s']:.0f}s")
        print()

    for branch in BRANCHES:
        bdir = os.path.join(BASE, branch)
        if not os.path.isdir(bdir):
            continue

        print(f"\n{'='*70}")
        print(f"  BRANCH: {branch}")
        print(f"{'='*70}")

        # Meta
        meta_f = os.path.join(bdir, "experiment_meta.json")
        if os.path.exists(meta_f):
            with open(meta_f) as f:
                meta = json.load(f)
            print(f"  Host: {meta.get('hostname','-')}  |  {meta.get('timestamp','-')}")

        # Extraction summaries
        summaries = sorted(glob.glob(os.path.join(bdir, "**", "summary.json"), recursive=True))
        if summaries:
            print(f"\n  --- Extracao ({len(summaries)} experimentos) ---")
            print(f"  {'Experimento':<40s} {'Packets':>12s} {'Tempo(s)':>10s} {'PPS':>12s}")
            print(f"  {'-'*40} {'-'*12} {'-'*10} {'-'*12}")
            total_pkts, total_time = 0, 0
            for sf in summaries:
                with open(sf) as f:
                    s = json.load(f)
                exp = s.get("experiment", os.path.basename(os.path.dirname(sf)))
                pkts = s.get("packets_sent", 0)
                t = s.get("time_seconds", 0)
                pps = s.get("pps", 0)
                total_pkts += pkts
                total_time += t
                print(f"  {exp:<40s} {pkts:>12,} {t:>10.1f} {pps:>12,.0f}")
            if total_time > 0:
                print(f"  {'TOTAL':<40s} {total_pkts:>12,} {total_time:>10.1f} {total_pkts/total_time:>12,.0f}")

        # CSV outputs
        csvs = sorted(glob.glob(os.path.join(bdir, "**", "*.csv"), recursive=True))
        flow_csvs = [c for c in csvs if "flows" in os.path.basename(c) or "labeled" in os.path.basename(c)]
        if flow_csvs:
            print(f"\n  --- Datasets Gerados ---")
            print(f"  {'Arquivo':<50s} {'Colunas':>8s} {'Linhas':>10s} {'Tamanho':>10s}")
            print(f"  {'-'*50} {'-'*8} {'-'*10} {'-'*10}")
            for cf in flow_csvs:
                cols, rows = count_csv(cf)
                sz = os.path.getsize(cf)
                sz_str = f"{sz/(1024*1024):.1f} MB" if sz > 1024*1024 else f"{sz/1024:.0f} KB"
                rel = os.path.relpath(cf, bdir)
                print(f"  {rel:<50s} {cols:>8d} {rows:>10,} {sz_str:>10s}")

        # Benchmark results (look for any output from ebpf_run_benchmark.py)
        bench_files = sorted(glob.glob(os.path.join(bdir, "**", "*benchmark*"), recursive=True) +
                            glob.glob(os.path.join(bdir, "**", "*results*"), recursive=True) +
                            glob.glob(os.path.join(bdir, "**", "*metrics*"), recursive=True))
        bench_csvs = [b for b in bench_files if b.endswith(".csv") and "resource" not in b]
        if bench_csvs:
            print(f"\n  --- Benchmark ---")
            for bf in bench_csvs:
                print(f"  {os.path.relpath(bf, bdir)}")

    # Auto-tune logs
    print(f"\n{'='*70}")
    print(f"  AUTO-TUNE LOGS")
    print(f"{'='*70}")
    for branch in BRANCHES:
        bdir = os.path.join(BASE, branch)
        logs = glob.glob(os.path.join(bdir, "**", "loader_stderr.log"), recursive=True)
        for lf in logs[:1]:
            try:
                with open(lf) as f:
                    for line in f:
                        if "auto-tune" in line:
                            print(f"  [{branch}] {line.strip()}")
            except Exception:
                pass

if __name__ == "__main__":
    main()
