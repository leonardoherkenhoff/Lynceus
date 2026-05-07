#!/usr/bin/env python3
"""
Lynceus Parity Experiment — XFAST (NFX) Wrapper
------------------------------------------------
Extrai features de cada PCAP usando XFAST (parity-nfx).
XFAST é XDP-based como o Lynceus — requer VETH + tcpreplay.

Invocação: sudo python3 scripts/testbed/xfast_wrapper.py
"""

import subprocess
import os
import time
import glob
import json
import threading
import re

BASE_DIR   = "/opt/eBPFNetFlowLyzer"
XFAST_BIN  = "/opt/XFAST/ebpf/xdp_user"
DATA_RAW   = os.path.join(BASE_DIR, "data/raw")
DATA_INTERIM = os.path.join(BASE_DIR, "data/interim/XFAST_RAW")
EXPERIMENT_ORDER = ["PCAPv6", "PCAP"]


def process_pcap_dir(pcap_dir, category):
    rel_path   = os.path.relpath(pcap_dir, os.path.join(DATA_RAW, category))
    output_dir = os.path.normpath(os.path.join(DATA_INTERIM, category, rel_path))
    os.makedirs(output_dir, exist_ok=True)

    pcaps = sorted(glob.glob(os.path.join(pcap_dir, "*.pcap*")))
    if not pcaps:
        return

    experiment_name = f"{category}/{rel_path}"
    csv_output_path = os.path.join(output_dir, "flows.csv")
    loader_log_path = os.path.join(output_dir, "xfast_stderr.log")
    print(f"\n🚀 XFAST EXTRACTION: {experiment_name}")

    # Setup VETH
    subprocess.run(["ip", "link", "delete", "veth0"], check=False, stderr=subprocess.DEVNULL)
    subprocess.run(["ip", "link", "add", "veth0", "type", "veth", "peer", "name", "veth1"], check=True)
    subprocess.run(["ip", "link", "set", "veth0", "up"], check=True)
    subprocess.run(["ip", "link", "set", "veth1", "up"], check=True)
    subprocess.run(["sysctl", "-w", "net.ipv6.conf.all.forwarding=1"], check=False, capture_output=True)

    try:
        f_csv = open(csv_output_path, "w")
        # XFAST provavelmente aceita interface como argumento (como o loader do Lynceus)
        proc_xfast = subprocess.Popen(
            [XFAST_BIN, "veth1"],
            stdout=f_csv,
            stderr=subprocess.PIPE,
            text=True,
            cwd=BASE_DIR
        )

        def stream_logs(proc, log_path):
            try:
                with open(log_path, "w") as f:
                    for line in iter(proc.stderr.readline, ""):
                        if not line:
                            break
                        f.write(line)
                        f.flush()
                        print(f"   [XFAST] {line.strip()}")
            except Exception:
                pass

        log_thread = threading.Thread(target=stream_logs, args=(proc_xfast, loader_log_path), daemon=True)
        log_thread.start()
        time.sleep(5)

        total_packets = 0
        start_time    = time.time()

        for pcap in pcaps:
            print(f"   Streaming: {os.path.basename(pcap)}")
            cmd = f"tcpreplay -i veth0 -t {pcap} 2>&1"
            try:
                res = subprocess.run(cmd, shell=True, capture_output=True, text=True, check=True)
                matches = re.findall(r"(\d+)\s+packets", res.stdout)
                if matches:
                    total_packets += int(matches[0])
            except subprocess.CalledProcessError as e:
                print(f"   ❌ Injection Error: {e.stderr}")

        elapsed = time.time() - start_time
        pps = total_packets / elapsed if elapsed > 0 else 0

        print("   🛑 Synchronizing XFAST buffers...")
        subprocess.run(["kill", "-INT", str(proc_xfast.pid)], check=False)
        try:
            proc_xfast.wait(timeout=120)
        except subprocess.TimeoutExpired:
            subprocess.run(["kill", "-9", str(proc_xfast.pid)], check=False)

        log_thread.join(timeout=10)
        f_csv.flush()
        os.fsync(f_csv.fileno())
        f_csv.close()

        summary = {
            "tool": "xfast",
            "experiment": experiment_name,
            "packets_sent": total_packets,
            "time_seconds": elapsed,
            "pps": pps,
            "timestamp": time.ctime()
        }
        with open(os.path.join(output_dir, "summary.json"), "w") as f:
            json.dump(summary, f, indent=4)

        print(f"✅ DONE: {total_packets} pkts | {elapsed:.1f}s | {pps:.0f} pps")

    finally:
        subprocess.run(["ip", "link", "delete", "veth0"], check=False, stderr=subprocess.DEVNULL)


def main():
    print("=== XFAST (NFX) Parity Extraction Wrapper ===")
    if not os.path.exists(XFAST_BIN):
        print(f"❌ XFAST binary not found: {XFAST_BIN}")
        return

    for category in EXPERIMENT_ORDER:
        category_path = os.path.join(DATA_RAW, category)
        if not os.path.exists(category_path):
            continue
        pcap_files = glob.glob(os.path.join(category_path, "**", "*.pcap*"), recursive=True)
        pcap_dirs  = sorted(set(os.path.dirname(p) for p in pcap_files))
        if not pcap_dirs and glob.glob(os.path.join(category_path, "*.pcap*")):
            pcap_dirs = [category_path]
        for pcap_dir in pcap_dirs:
            process_pcap_dir(pcap_dir, category)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n⚠️  Interrupted.")
