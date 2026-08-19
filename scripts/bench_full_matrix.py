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
    def __init__(self, target, output_file, gro="default"):
        self.target = target
        self.output_file = output_file
        self.gro = gro
        self.results = []
        self.ensure_network_setup()
        
        # Ensure output file has headers if new
        if not os.path.exists(self.output_file):
            with open(self.output_file, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['Timestamp', 'Scenario', 'Target', 'Duration', 'Achieved_Bitrate', 'Dropped_Packets', 'Notes'])

    def ensure_network_setup(self):
        print("Checking and enforcing testbed VETH IP configuration...")
        subprocess.run(f"sudo ip addr add {IPERF_SERVER_IP}/30 dev {VETH_INTF} 2>/dev/null", shell=True)
        subprocess.run(f"sudo ip netns exec rustiflow-peer ip addr add {IPERF_CLIENT_IP}/30 dev {PEER_INTF} 2>/dev/null", shell=True)
        subprocess.run(f"sudo ip link set {VETH_INTF} mtu 9000 up", shell=True)
        subprocess.run(f"sudo ip netns exec rustiflow-peer ip link set {PEER_INTF} mtu 9000 up", shell=True)
        if self.gro in ["on", "off"]:
            print(f"Enforcing GRO {self.gro.upper()} on veth pair...")
            subprocess.run(f"sudo ethtool -K {VETH_INTF} gro {self.gro}", shell=True, stderr=subprocess.DEVNULL)
            subprocess.run(f"sudo ip netns exec rustiflow-peer ethtool -K {PEER_INTF} gro {self.gro}", shell=True, stderr=subprocess.DEVNULL)

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
            cmd = f"sudo RUST_LOG=info taskset -c {RF_CPUS} /home/leonardo.herkenhoff/RustiFlow/target/release/rustiflow -f rustiflow -o print realtime {VETH_INTF} > /dev/null 2> {err_log}"
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
            if self.target == "rustiflow":
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
                if self.target == "rustiflow":
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

    def run_iperf_scenario(self, scenario_id, duration, bitrate, length, protocol="-u"):
        print(f"--- Running {scenario_id} ---")
        # Ensure no stale servers
        subprocess.run("sudo pkill iperf3", shell=True, stderr=subprocess.DEVNULL)
        # Start server on host
        server_cmd = f"sudo taskset -c {GEN_CPUS} iperf3 -s -B {IPERF_SERVER_IP} -p 5201 --daemon"
        subprocess.run(server_cmd, shell=True)
        time.sleep(1)
        
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
        subprocess.run("sudo pkill iperf3", shell=True, stderr=subprocess.DEVNULL)
        self.log_result(scenario_id, f"{duration}s", achieved_bitrate, drops)

    def parse_iperf_output(self, output):
        # Robust parser looking for receiver sum or individual receiver/sender summary
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

    def run_b1(self):
        self.run_iperf_scenario("B1", duration=30, bitrate="20G", length=1400)

    def run_b2(self):
        self.run_iperf_scenario("B2", duration=30, bitrate="25G", length=1400)

    def run_b3(self):
        self.run_iperf_scenario("B3", duration=30, bitrate="10G", length=512)

    def run_b4(self):
        self.run_iperf_scenario("B4", duration=30, bitrate="5G", length=256)

    def run_b5(self, duration=30):
        print(f"--- Running B5 (Mixed UDP + TCP) ---")
        subprocess.run("sudo pkill iperf3", shell=True, stderr=subprocess.DEVNULL)
        # Start two iperf3 servers on ports 5201 (UDP) and 5202 (TCP)
        subprocess.run(f"sudo taskset -c 0-3 iperf3 -s -B {IPERF_SERVER_IP} -p 5201 --daemon", shell=True)
        subprocess.run(f"sudo taskset -c 4-7 iperf3 -s -B {IPERF_SERVER_IP} -p 5202 --daemon", shell=True)
        time.sleep(1)
        
        extractor_proc = self.start_extractor("B5")
        time.sleep(2)
        
        cmd_udp = f"sudo ip netns exec rustiflow-peer taskset -c 24-27 iperf3 -c {IPERF_SERVER_IP} -B {IPERF_CLIENT_IP} -p 5201 -u -b 10G -l 1400 -P 4 -t {duration} -R"
        cmd_tcp = f"sudo ip netns exec rustiflow-peer taskset -c 28-31 iperf3 -c {IPERF_SERVER_IP} -B {IPERF_CLIENT_IP} -p 5202 -P 4 -t {duration} -R"
        try:
            proc_udp = subprocess.Popen(cmd_udp, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            proc_tcp = subprocess.Popen(cmd_tcp, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            out_udp, _ = proc_udp.communicate()
            out_tcp, _ = proc_tcp.communicate()
            rate_udp = self.parse_iperf_output(out_udp)
            rate_tcp = self.parse_iperf_output(out_tcp)
            achieved = f"UDP: {rate_udp} | TCP: {rate_tcp}"
        except Exception as e:
            achieved = "Error"
            print("iperf3 failed in B5:", e)
            
        drops = self.stop_extractor(extractor_proc)
        subprocess.run("sudo pkill iperf3", shell=True, stderr=subprocess.DEVNULL)
        self.log_result("B5", f"{duration}s", achieved, drops, "Mixed UDP 10G + TCP")

    def run_b6(self, iterations=30):
        print(f"--- Running B6 (Short-lived Flow Churn) ---")
        subprocess.run("sudo pkill iperf3", shell=True, stderr=subprocess.DEVNULL)
        subprocess.run(f"sudo taskset -c {GEN_CPUS} iperf3 -s -B {IPERF_SERVER_IP} -p 5201 --daemon", shell=True)
        time.sleep(1)
        
        extractor_proc = self.start_extractor("B6")
        time.sleep(2)
        
        success_count = 0
        start_time = time.time()
        for i in range(iterations):
            cmd = f"sudo ip netns exec rustiflow-peer taskset -c {CTRL_CPUS} iperf3 -c {IPERF_SERVER_IP} -B {IPERF_CLIENT_IP} -p 5201 -P 8 -t 1 -R"
            try:
                subprocess.run(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
                success_count += 1
            except subprocess.CalledProcessError:
                pass
        elapsed = int(time.time() - start_time)
        achieved = f"{success_count}/{iterations} churn cycles completed"
        
        drops = self.stop_extractor(extractor_proc)
        subprocess.run("sudo pkill iperf3", shell=True, stderr=subprocess.DEVNULL)
        self.log_result("B6", f"{elapsed}s", achieved, drops, f"Flow churn ({success_count} iterations)")

    def run_b7(self, duration=180):
        print(f"--- Running B7 (Long Soak Stress Test - {duration}s) ---")
        self.run_iperf_scenario("B7", duration=duration, bitrate="20G", length=1400)

    def run_b8(self, pcap_file):
        print(f"--- Running B8 (PCAP Replay) ---")
        import signal
        import select
        
        extractor_proc = self.start_extractor("B8")
        time.sleep(2)
        
        # Implement dynamic watchdog: run tcpreplay with --stats=1 and filter out txring warnings
        cmd = f"stdbuf -oL -eL ip netns exec rustiflow-peer taskset -c {GEN_CPUS} tcpreplay --stats=1 --intf1={PEER_INTF} --topspeed --loop=1 {pcap_file} 2>&1 | stdbuf -oL grep -v 'Warning in txring'"
        
        print(f"[*] Starting tcpreplay with dynamic watchdog...")
        proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, text=True, errors="ignore", preexec_fn=os.setsid)
        
        last_output_time = time.time()
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
                    last_output_time = time.time()
                    if "Failed packets" in line:
                        m = re.search(r"Failed packets:\s*(\d+)", line)
                        if m:
                            tcpreplay_drops = int(m.group(1))
                    elif "ENOBUFS" in line:
                        enobufs_count += 1
            else:
                if time.time() - last_output_time > 15.0:
                    print(f"[!] Watchdog triggered! tcpreplay hung for >15s. Sending SIGINT...")
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
            achieved += " (Watchdog Killed)"
            
        self.log_result("B8", "Dynamic Watchdog", achieved, drops, pcap_file)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run Benchmark Matrix (B1-B8)")
    parser.add_argument("--target", choices=["rustiflow", "lynceus", "control"], required=True)
    parser.add_argument("--output", default="full_matrix_results.csv")
    parser.add_argument("--pcap", default=PCAP_PATH)
    parser.add_argument("--soak-duration", type=int, default=180, help="Duration in seconds for B7 long soak test")
    parser.add_argument("--test", default="ALL", choices=["ALL", "B1", "B2", "B3", "B4", "B5", "B6", "B7", "B8"], help="Specific test scenario to execute")
    parser.add_argument("--gro", choices=["on", "off", "default"], default="default", help="Control GRO offload state")
    args = parser.parse_args()

    bench = Benchmark(args.target, args.output, args.gro)
    
    # Execução da matriz completa (B1 a B8) ou teste individual
    if args.test in ["ALL", "B1"]:
        bench.run_b1()
    if args.test in ["ALL", "B2"]:
        bench.run_b2()
    if args.test in ["ALL", "B3"]:
        bench.run_b3()
    if args.test in ["ALL", "B4"]:
        bench.run_b4()
    if args.test in ["ALL", "B5"]:
        bench.run_b5()
    if args.test in ["ALL", "B6"]:
        bench.run_b6()
    if args.test in ["ALL", "B7"]:
        bench.run_b7(duration=args.soak_duration)
    if args.test in ["ALL", "B8"]:
        bench.run_b8(args.pcap)
