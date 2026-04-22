#!/usr/bin/env python3
"""
Lynceus Research Infrastructure - Resource Consumption Profiler (v1.0)
-----------------------------------------------------------
Scientific Milestone: v1.0 (The Definitive Foundation)

Research Objective:
Performs asynchronous sampling of CPU and Memory footprints for the 
Lynceus Telemetry Engine during experimental workloads.

Methodology:
1. Process Identification: Targets the engine PID provided by the orchestrator.
2. Stochastic Sampling: Captures metrics at a deterministic 1Hz frequency.
3. Persistence: Exports time-series data to CSV for resource overhead analysis.
"""

import psutil
import time
import sys
import os

def monitor_pid(pid, output_file):
    """
    Stochastically samples resource utilization for a specific process ID.
    """
    try:
        proc = psutil.Process(pid)
    except psutil.NoSuchProcess:
        return

    print(f"   📊 Profiling PID {pid} [Resource Consumption]")
    
    with open(output_file, 'w') as f:
        # Header for resource time-series dataset.
        f.write("timestamp,cpu_percent,memory_rss_mb,memory_vms_mb,num_threads\n")
        
        while proc.is_running():
            try:
                # Capture empirical metrics via psutil interface.
                cpu = proc.cpu_percent(interval=1.0)
                mem = proc.memory_info()
                rss_mb = mem.rss / (1024 * 1024)
                vms_mb = mem.vms / (1024 * 1024)
                threads = proc.num_threads()
                
                f.write(f"{time.time()},{cpu},{rss_mb:.2f},{vms_mb:.2f},{threads}\n")
                f.flush()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                break
            except Exception as e:
                print(f"   ⚠️ Profiler Warning: {e}")
                break

if __name__ == "__main__":
    if len(sys.argv) < 3:
        sys.exit(1)
        
    target_pid = int(sys.argv[1])
    metrics_path = sys.argv[2]
    
    # Initialize profiling loop.
    monitor_pid(target_pid, metrics_path)
