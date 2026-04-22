#!/usr/bin/env python3
"""
Lynceus Research Pipeline - Full Experiment Orchestrator (v1.0)
-----------------------------------------------------------
Scientific Milestone: v1.0 (The Definitive Foundation)
Architecture: MAPE-K Loop (Monitor Phase)

Research Objective:
Executes the comprehensive end-to-end experimental workflow, ensuring 
methodological rigor from source compilation to stochastic validation.

Pipeline Phases (Sequential Execution):
1. [Build]: Static compilation of BPF object and User-space control plane.
2. [Extraction]: Network topology virtualization and stream-based feature ingestion.
3. [Labeling]: Topological ground-truth attribution for supervised learning.
4. [Benchmark]: Multi-class classification via Random Forest for performance validation.

Reproducibility:
Ensures idempotent execution of each phase, generating telemetry logs
compliant with academic artifact requirements (SeloD, F, S, R).
"""

import subprocess
import os
import sys
import time

def run_command(cmd, description):
    """
    Executes a shell command with rigorous logging and error handling.
    
    Args:
        cmd (str): Command-line instruction.
        description (str): Formal description of the experimental phase.
    """
    print(f"\n" + "="*60)
    print(f"🚀 [PHASE] {description}")
    print(f"="*60)
    start_time = time.time()
    try:
        subprocess.run(cmd, shell=True, check=True)
        elapsed = time.time() - start_time
        print(f"\n✅ COMPLETE: {description} (dt: {elapsed:.2f}s)")
    except subprocess.CalledProcessError as e:
        print(f"\n❌ CRITICAL FAILURE: {description} [Exit Code: {e.returncode}]")
        sys.exit(1)

def main():
    """Main execution entry point for the Lynceus Research Pipeline."""
    print("=== Lynceus Telemetry Engine: End-to-End Experimental Validation ===")
    
    # --- Phase 1: Toolchain Invocation ---
    run_command("make clean && make all", "Static Compilation (eBPF Core + Daemon)")
    
    # --- Phase 2: High-Resolution Telemetry Extraction ---
    run_command("python3 scripts/testbed/ebpf_wrapper.py", "Stream-based Feature Extraction (Virtual Topology)")
    
    # --- Phase 3: Dataset Formalization ---
    run_command("python3 scripts/preprocessing/ebpf_labeler.py", "Topological Ground-Truth Attribution")
    
    # --- Phase 4: Statistical Validation ---
    run_command("python3 scripts/analysis/ebpf_run_benchmark.py", "Stochastic Performance Profiling (Random Forest)")

    print("\n" + "="*60)
    print("🏆 EXPERIMENTAL PIPELINE EXECUTED WITH METHODOLOGICAL INTEGRITY")
    print("="*60)
    print("Telemetric artifacts stored in: data/processed/EBPF/")

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("⚠️  Privilege Warning: Root/Sudo required for XDP attachment and map manipulation.")
    main()
