import subprocess, time, re, os

RUSTIFLOW_BIN = "/root/.cargo/bin/rustiflow"
LYNCEUS_BIN = "build/loader"

def setup_veth():
    print("[*] Setting up veth pair...")
    subprocess.run("sudo ip netns add rustiflow-peer", shell=True, stderr=subprocess.DEVNULL)
    subprocess.run("sudo ip link add rustiflow-t0 type veth peer name rustiflow-p0", shell=True, stderr=subprocess.DEVNULL)
    subprocess.run("sudo ip link set rustiflow-p0 netns rustiflow-peer", shell=True, stderr=subprocess.DEVNULL)
    subprocess.run("sudo ip link set rustiflow-t0 up", shell=True)
    subprocess.run("sudo ip netns exec rustiflow-peer ip link set lo up", shell=True)
    subprocess.run("sudo ip netns exec rustiflow-peer ip link set rustiflow-p0 up", shell=True)
    subprocess.run("sudo ethtool -K rustiflow-t0 rx off tx off tso off gro off gso off lro off", shell=True, stderr=subprocess.DEVNULL)
    subprocess.run("sudo ip netns exec rustiflow-peer ethtool -K rustiflow-p0 rx off tx off tso off gro off gso off lro off", shell=True, stderr=subprocess.DEVNULL)
    mac_cmd = "ip link show rustiflow-t0 | grep link/ether | awk '{print $2}'"
    mac = subprocess.check_output(mac_cmd, shell=True).decode().strip()
    return mac

def get_rx_stats(iface="rustiflow-t0"):
    try:
        res = subprocess.check_output(f"ip -s -s link show {iface}", shell=True).decode()
        lines = res.strip().split("\n")
        for idx, line in enumerate(lines):
            if "RX:" in line and "packets" in line and "dropped" in line:
                parts = lines[idx+1].split()
                return int(parts[1]), int(parts[3])
    except: pass
    return 0, 0

def run_pktgen_benchmark(target_mac):
    print("\n" + "="*50)
    print("=== SCENARIO 2: NETWORK PKTGEN UPPER BOUND ===")
    print("="*50)

    pktgen_script = f"""
modprobe pktgen
for f in /proc/net/pktgen/kpktgend_*; do echo "rem_device_all" > $f 2>/dev/null; done
for i in $(seq 0 47); do
    echo "add_device rustiflow-p0@$i" > /proc/net/pktgen/kpktgend_$i 2>/dev/null
    dev="/proc/net/pktgen/rustiflow-p0@$i"
    if [ ! -f "$dev" ]; then dev="/proc/net/pktgen/rustiflow-p0"; fi
    echo "flag QUEUE_MAP_CPU" > $dev 2>/dev/null
    echo "queue_map_min $i" > $dev 2>/dev/null
    echo "queue_map_max $i" > $dev 2>/dev/null
    echo "count 5000000" > $dev 2>/dev/null
    echo "clone_skb 1000" > $dev 2>/dev/null
    echo "pkt_size 60" > $dev 2>/dev/null
    echo "delay 0" > $dev 2>/dev/null
done
"""
    script_path = "/tmp/setup_pktgen.sh"
    with open(script_path, "w") as f: f.write(pktgen_script)
    
    def run_pktgen():
        subprocess.run(f"sudo ip netns exec rustiflow-peer bash {script_path}", shell=True)
        subprocess.Popen("sudo ip netns exec rustiflow-peer bash -c 'echo start > /proc/net/pktgen/pgctrl'", shell=True)
        time.sleep(10)
        subprocess.run("sudo ip netns exec rustiflow-peer bash -c 'echo stop > /proc/net/pktgen/pgctrl'", shell=True)
        try:
            res = subprocess.check_output("sudo ip netns exec rustiflow-peer bash -c 'cat /proc/net/pktgen/rustiflow-p0*'", shell=True).decode()
            pps_matches = re.findall(r"(\d+)pps", res)
            if pps_matches:
                total_pps = sum(int(p) for p in pps_matches)
                print(f"    [PktGen] Injected at {total_pps} PPS across {len(pps_matches)} threads")
        except: pass

    print("\n[*] Running RustiFlow Network Upper Bound...")
    pkts0, drops0 = get_rx_stats("rustiflow-t0")
    if os.path.exists("/tmp/rf_net.log"): os.remove("/tmp/rf_net.log")
    rf_proc = subprocess.Popen(f"sudo RUST_LOG=info {RUSTIFLOW_BIN} -f rustiflow -o print realtime rustiflow-t0 > /dev/null 2> /tmp/rf_net.log", shell=True)
    time.sleep(2)
    run_pktgen()
    subprocess.run("sudo pkill -INT rustiflow", shell=True)
    time.sleep(2)
    pkts1, drops1 = get_rx_stats("rustiflow-t0")
    print(f"    [Interface Stats] RX Packets Delivered: {pkts1-pkts0:,} | Kernel Interface Drops: {drops1-drops0:,}")
    if os.path.exists("/tmp/rf_net.log"):
        with open("/tmp/rf_net.log", "r") as logf:
            for l in logf:
                if "matched_packets=" in l or "Total dropped" in l: print("    [RustiFlow Engine] " + l.strip())

    print("\n[*] Running Lynceus Network Upper Bound...")
    pkts0, drops0 = get_rx_stats("rustiflow-t0")
    if os.path.exists("/tmp/lyn_net.log"): os.remove("/tmp/lyn_net.log")
    lyn_proc = subprocess.Popen(f"cd /opt/lynceus && sudo {LYNCEUS_BIN} rustiflow-t0 > /dev/null 2> /tmp/lyn_net.log", shell=True)
    time.sleep(2)
    run_pktgen()
    subprocess.run("sudo pkill -INT loader", shell=True)
    time.sleep(2)
    pkts1, drops1 = get_rx_stats("rustiflow-t0")
    print(f"    [Interface Stats] RX Packets Delivered: {pkts1-pkts0:,} | Kernel Interface Drops: {drops1-drops0:,}")
    if os.path.exists("/tmp/lyn_net.log"):
        with open("/tmp/lyn_net.log", "r") as logf:
            for l in logf:
                if any(x in l for x in ["Kernel-Space", "Telemetry Drops", "Speed:"]): print("    [Lynceus Engine] " + l.strip())

if __name__ == "__main__":
    mac = setup_veth()
    run_pktgen_benchmark(mac)
