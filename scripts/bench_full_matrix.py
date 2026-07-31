#!/usr/bin/env python3
import os
import time
import subprocess
import argparse
import csv
import signal
from datetime import datetime

# CPU Allocations based on RustiFlow Matrix
GEN_CPUS = "0-7"
RF_CPUS = "8-23"
CTRL_CPUS = "24-31"

IPERF_SERVER_IP = "10.203.0.2"
IPERF_CLIENT_IP = "10.203.0.1"
VETH_INTF = "rustiflow-t0"
PEER_INTF = "rustiflow-p0"
PCAP_PATH = "/root/CIC-IDS-2017/Monday-WorkingHours.pcap" # Default on testbed

class Benchmark:
    def __init__(self, target, output_file):
        self.target = target
        self.output_file = output_file
        self.results = []
        
        # Ensure output file has headers if new
        if not os.path.exists(self.output_file):
            with open(self.output_file, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['Timestamp', 'Scenario', 'Target', 'Duration', 'Achieved_Bitrate', 'Dropped_Packets', 'Notes'])

    def log_result(self, scenario, duration, bitrate, dropped, notes=""):
        with open(self.output_file, 'a', newline='') as f:
            writer = csv.writer(f)
            writer.writerow([datetime.now().isoformat(), scenario, self.target, duration, bitrate, dropped, notes])
        print(f"[{scenario}] {self.target} | Rate: {bitrate} | Drops: {dropped} | Note: {notes}")

    def start_extractor(self, scenario):
        print(f"Starting {self.target} extractor for {scenario}...")
        if self.target == "rustiflow":
            cmd = f"sudo taskset -c {RF_CPUS} rustiflow -f rustiflow -o csv --export-path /tmp/{scenario}_rf.csv realtime {VETH_INTF}"
            proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, preexec_fn=os.setsid)
            return proc
        elif self.target == "lynceus":
            cmd = f"sudo taskset -c {RF_CPUS} /home/leonardo.herkenhoff/Lynceus/build/loader -i {VETH_INTF}"
            proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, preexec_fn=os.setsid)
            return proc
        return None

    def stop_extractor(self, proc):
        if proc:
            os.killpg(os.getpgid(proc.pid), signal.SIGINT)
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            
            # TODO: Parse stderr/stdout for dropped packets based on tool output
            return "0" # Placeholder for dropped packets

    def run_iperf_scenario(self, scenario_id, duration, bitrate, length, protocol="-u"):
        print(f"--- Running {scenario_id} ---")
        extractor_proc = self.start_extractor(scenario_id)
        time.sleep(2) # Give extractor time to hook

        # Start generator inside namespace
        cmd = f"sudo ip netns exec rustiflow-peer taskset -c {CTRL_CPUS} iperf3 -c {IPERF_SERVER_IP} -B {IPERF_CLIENT_IP} -p 5201 {protocol} -b {bitrate} -l {length} -P 8 -t {duration} -R"
        try:
            output = subprocess.check_output(cmd, shell=True, text=True)
            achieved_bitrate = self.parse_iperf_output(output)
        except subprocess.CalledProcessError as e:
            achieved_bitrate = "Error"
            print("iperf3 failed:", e)

        drops = self.stop_extractor(extractor_proc)
        self.log_result(scenario_id, f"{duration}s", achieved_bitrate, drops)

    def parse_iperf_output(self, output):
        # Extremely basic parser for iperf3 sender/receiver bitrates
        for line in output.split('\n'):
            if "sender" in line and "bits/sec" in line:
                parts = line.split()
                try:
                    idx = parts.index("bits/sec")
                    return f"{parts[idx-2]} {parts[idx-1]} bps"
                except ValueError:
                    pass
        return "Unknown"

    def run_b1(self):
        self.run_iperf_scenario("B1", duration=30, bitrate="20G", length=1400)

    def run_b3(self):
        self.run_iperf_scenario("B3", duration=30, bitrate="10G", length=512)

    def run_b4(self):
        self.run_iperf_scenario("B4", duration=30, bitrate="5G", length=256)

    def run_b8(self, pcap_file):
        print(f"--- Running B8 (PCAP Replay) ---")
        extractor_proc = self.start_extractor("B8")
        time.sleep(2)
        
        cmd = f"sudo ip netns exec rustiflow-peer taskset -c {GEN_CPUS} tcpreplay --intf1={PEER_INTF} --topspeed -W --loop=1 {pcap_file}"
        try:
            subprocess.run(cmd, shell=True, check=True)
            achieved = "Topspeed Replay"
        except subprocess.CalledProcessError:
            achieved = "Error"
            
        drops = self.stop_extractor(extractor_proc)
        self.log_result("B8", "PCAP loop", achieved, drops, pcap_file)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run Benchmark Matrix")
    parser.add_argument("--target", choices=["rustiflow", "lynceus", "control"], required=True)
    parser.add_argument("--output", default="full_matrix_results.csv")
    parser.add_argument("--pcap", default=PCAP_PATH)
    args = parser.parse_args()

    bench = Benchmark(args.target, args.output)
    
    # Execução básica da matriz para validação (B1, B3, B4, B8)
    bench.run_b1()
    bench.run_b3()
    bench.run_b4()
    bench.run_b8(args.pcap)
