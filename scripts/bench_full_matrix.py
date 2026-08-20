#!/usr/bin/env python3
import os
import time
import subprocess
import argparse
import re
import csv
import signal
from datetime import datetime

# CPU Allocations based on RustiFlow Matrix
GEN_CPUS = "0-7"
RF_CPUS = "8-23"
CTRL_CPUS = "24-31"

IPERF_SERVER_IP = "10.203.0.1"
IPERF_CLIENT_IP = "10.203.0.2"
VETH_INTF = "rustiflow-t0"
PEER_INTF = "rustiflow-p0"
PCAP_PATH = "/root/CIC-IDS-2017/Monday-WorkingHours.pcap" # Default on testbed

class Benchmark:
    def __init__(self, target, output_file):
        self.target = target
        self.output_file = output_file
        self.results = []
        self.ensure_network_setup()
        
        # Ensure output file has headers if new
        if not os.path.exists(self.output_file):
            with open(self.output_file, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['Timestamp', 'Scenario', 'Target', 'Duration', 'Achieved_Bitrate', 'Dropped_Packets', 'Notes'])

    def ensure_network_setup(self):
        print("Checking and enforcing testbed VETH IP configuration...")
        subprocess.run(f"sudo ip link set dev {VETH_INTF} up", shell=True, check=True)
        subprocess.run(f"sudo ip netns exec rustiflow-peer ip link set dev {PEER_INTF} up", shell=True, check=True)
        
        # Disable offloading to ensure true packet-by-packet processing
        subprocess.run(f"sudo ethtool -K {VETH_INTF} gso off tso off gro off", shell=True, stderr=subprocess.DEVNULL)
        subprocess.run(f"sudo ip netns exec rustiflow-peer ethtool -K {PEER_INTF} gso off tso off gro off", shell=True, stderr=subprocess.DEVNULL)
        
        subprocess.run(f"sudo ip addr add {IPERF_SERVER_IP}/30 dev {VETH_INTF} 2>/dev/null", shell=True)
        subprocess.run(f"sudo ip netns exec rustiflow-peer ip addr add {IPERF_CLIENT_IP}/30 dev {PEER_INTF} 2>/dev/null", shell=True)
        # Removed MTU 9000 and GRO isolations to perfectly match authors' blind environment (MTU 1500 / default GRO)

    def log_result(self, scenario, duration, bitrate, dropped, notes=""):
        with open(self.output_file, 'a', newline='') as f:
            writer = csv.writer(f)
            writer.writerow([datetime.now().isoformat(), scenario, self.target, duration, bitrate, dropped, notes])
        print(f"[{scenario}] {self.target} | Rate: {bitrate} | Drops: {dropped} | Note: {notes}")

    def start_extractor(self, scenario):
        print(f"Starting {self.target} extractor for {scenario}...")
        err_log = f"/tmp/{scenario}_{self.target}_err.log"
        if os.path.exists(err_log):
            try: os.remove(err_log)
            except: pass
        if self.target == "rustiflow":
            # Injected --idle-timeout 120 --active-timeout 3600 precisely as they hardcoded in realtime_performance_test.py
            cmd = f"sudo RUST_LOG=info taskset -c {RF_CPUS} /home/leonardo.herkenhoff/RustiFlow/target/release/rustiflow -f rustiflow --idle-timeout 120 --active-timeout 3600 -o print realtime {VETH_INTF} > /dev/null 2> {err_log}"
            proc = subprocess.Popen(cmd, shell=True, preexec_fn=os.setsid)
            proc.err_log = err_log
            return proc
        elif self.target == "rustiflow-organic":
            # Realistic timeouts for a scrubbing center (15s idle, 30s active)
            cmd = f"sudo RUST_LOG=info taskset -c {RF_CPUS} /home/leonardo.herkenhoff/RustiFlow/target/release/rustiflow -f rustiflow --idle-timeout 15 --active-timeout 30 -o print realtime {VETH_INTF} > /dev/null 2> {err_log}"
            proc = subprocess.Popen(cmd, shell=True, preexec_fn=os.setsid)
            proc.err_log = err_log
            return proc
        elif self.target == "lynceus":
            cmd = f"cd /home/leonardo.herkenhoff/Lynceus && sudo taskset -c {RF_CPUS} /home/leonardo.herkenhoff/Lynceus/build/loader {VETH_INTF} > /dev/null 2> {err_log}"
            proc = subprocess.Popen(cmd, shell=True, preexec_fn=os.setsid)
            proc.err_log = err_log
            return proc
        return None

    def stop_extractor(self, proc):
        if proc:
            if self.target.startswith("rustiflow"):
                subprocess.run("sudo pkill -INT rustiflow", shell=True, stderr=subprocess.DEVNULL)
            elif self.target == "lynceus":
                subprocess.run("sudo pkill -INT loader", shell=True, stderr=subprocess.DEVNULL)
            time.sleep(2)
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            except: pass
            
            err_log = getattr(proc, 'err_log', None)
            if err_log and os.path.exists(err_log):
                with open(err_log, "r", errors="ignore") as f:
                    content = f.read()
                if self.target.startswith("rustiflow"):
                    rf_matched, rf_submitted, rf_dropped = 0, 0, 0
                    for line in content.splitlines():
                        if "eBPF counters" in line and "matched_packets=" in line:
                            m = re.search(r"matched_packets=(\d+), submitted_events=(\d+), dropped_packets=(\d+)", line)
                            if m:
                                rf_matched += int(m.group(1))
                                rf_submitted += int(m.group(2))
                                rf_dropped += int(m.group(3))
                    if rf_matched > 0 or rf_dropped > 0:
                        loss_pct = (rf_dropped / (rf_matched if rf_matched > 0 else 1)) * 100.0
                        return f"{rf_dropped:,} ({loss_pct:.2f}%)"
                    for line in reversed(content.splitlines()):
                        if "Total dropped packets before exit:" in line:
                            m = re.search(r":\s*(\d+)", line)
                            if m and int(m.group(1)) > 0:
                                return f"{int(m.group(1)):,} drops"
                elif self.target == "lynceus":
                    for line in reversed(content.splitlines()):
                        if "Telemetry Drops" in line:
                            m = re.search(r": (\d+) events \(([\d.]+)% loss\)", line)
                            if m:
                                return f"{int(m.group(1)):,} ({float(m.group(2)):.2f}%)"
            return "0 (0.00%)"
        return "N/A"

    def parse_iperf_output(self, output):
        best_rate = "Unknown"
        for line in reversed(output.strip().split('\n')):
            if ("receiver" in line or "sender" in line) and any(unit in line for unit in ["Gbits/sec", "Mbits/sec", "Kbits/sec", "bits/sec"]):
                parts = line.split()
                for unit in ["Gbits/sec", "Mbits/sec", "Kbits/sec", "bits/sec"]:
                    if unit in parts:
                        idx = parts.index(unit)
                        if idx >= 1:
                            best_rate = f"{parts[idx-1]} {unit}"
                            if "[SUM]" in line and "receiver" in line:
                                return best_rate
                if "[SUM]" in line and best_rate != "Unknown":
                    return best_rate
        return best_rate

    def run_throughput_scenario(self, scenario_id, throughput):
        print(f"--- Running {scenario_id} (Throughput: {throughput}) ---")
        duration = 120
        subprocess.run("sudo pkill iperf3", shell=True, stderr=subprocess.DEVNULL)
        
        server_cmd = f"sudo taskset -c {GEN_CPUS} iperf3 -s -B {IPERF_SERVER_IP} -p 5201 --daemon"
        subprocess.run(server_cmd, shell=True)
        time.sleep(1)
        
        extractor_proc = self.start_extractor(scenario_id)
        time.sleep(2)

        # Matched authors exact parameters: no -P 8, standard -Z -b
        cmd = f"sudo ip netns exec rustiflow-peer taskset -c {CTRL_CPUS} iperf3 -c {IPERF_SERVER_IP} -B {IPERF_CLIENT_IP} -p 5201 -t {duration} -Z -b {throughput}"
        try:
            output = subprocess.check_output(cmd, shell=True, text=True)
            achieved_bitrate = self.parse_iperf_output(output)
        except subprocess.CalledProcessError as e:
            achieved_bitrate = "Error"
            print("iperf3 failed:", e)

        drops = self.stop_extractor(extractor_proc)
        subprocess.run("sudo pkill iperf3", shell=True, stderr=subprocess.DEVNULL)
        self.log_result(scenario_id, f"{duration}s", achieved_bitrate, drops, f"Target: {throughput}")

    def run_pcap_scenario(self, scenario_id, pcap_file):
        print(f"--- Running {scenario_id} (PCAP Replay) ---")
        import signal
        import select
        
        extractor_proc = self.start_extractor(scenario_id)
        time.sleep(2)
        
        cmd = f"stdbuf -oL -eL ip netns exec rustiflow-peer taskset -c {GEN_CPUS} tcpreplay --stats=1 --intf1={PEER_INTF} --topspeed --loop=1 {pcap_file} 2>&1"
        print(f"[*] Starting tcpreplay with dynamic watchdog...")
        proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, text=True, errors="ignore", preexec_fn=os.setsid)
        
        last_progress_time = time.time()
        tcpreplay_drops = 0
        enobufs_count = 0
        watchdog_triggered = False
        
        while True:
            if proc.poll() is not None:
                break
                
            r, _, _ = select.select([proc.stdout], [], [], 1.0)
            if r:
                line = proc.stdout.readline()
                if line:
                    if "Failed packets" in line:
                        m = re.search(r"Failed packets:\s*(\d+)", line)
                        if m:
                            tcpreplay_drops = int(m.group(1))
                    elif "ENOBUFS" in line:
                        enobufs_count += 1
                    elif "Warning in txring" not in line:
                        # Parse Actual stats line to catch 0 bps livelock
                        if "Actual: " in line:
                            m = re.search(r"Actual:\s*(\d+)\s*packets", line)
                            if m and int(m.group(1)) == 0:
                                # It printed stats but 0 packets were sent! Livelock!
                                pass
                            else:
                                last_progress_time = time.time()
                        else:
                            last_progress_time = time.time()
            else:
                if time.time() - last_progress_time > 15.0:
                    print(f"[!] Watchdog triggered! tcpreplay made no progress for >15s (livelock). Sending SIGINT...")
                    watchdog_triggered = True
                    os.killpg(os.getpgid(proc.pid), signal.SIGINT)
                    time.sleep(2)
                    break
                    
        for line in proc.stdout.readlines():
            if "Failed packets" in line:
                m = re.search(r"Failed packets:\s*(\d+)", line)
                if m:
                    tcpreplay_drops = int(m.group(1))
            elif "ENOBUFS" in line:
                enobufs_count += 1
                    
        if tcpreplay_drops == 0:
            tcpreplay_drops = enobufs_count
            
        drops_rustiflow = self.stop_extractor(extractor_proc)
        
        if tcpreplay_drops > 0:
            drops = f"{tcpreplay_drops:,} falhas TX ENOBUFS"
        else:
            drops = drops_rustiflow
            
        achieved = "Topspeed Replay"
        if watchdog_triggered:
            achieved += " (Livelock Aborted)"
            
        self.log_result(scenario_id, "Dynamic", achieved, drops, pcap_file)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run Strict Replication Benchmark")
    parser.add_argument("--target", choices=["rustiflow", "lynceus", "control", "rustiflow-organic"], required=True)
    parser.add_argument("--output", default="full_matrix_results.csv")
    parser.add_argument("--pcap", default=PCAP_PATH)
    args = parser.parse_args()

    bench = Benchmark(args.target, args.output)
    
    # 1. Throughput tests exactly as in realtime_performance_test.py
    bench.run_throughput_scenario("T1", "1M")
    bench.run_throughput_scenario("T2", "10M")
    bench.run_throughput_scenario("T3", "100M")
    bench.run_throughput_scenario("T4", "1G")
    bench.run_throughput_scenario("T5", "10G")
    bench.run_throughput_scenario("T6", "0") # 0 = Max in iperf3
    
    # 2. PCAP test exactly as in pcap_performance_test.py
    # bench.run_pcap_scenario("PCAP1", args.pcap)

