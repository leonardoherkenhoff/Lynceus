import os, time, subprocess, sys

def run_remote(cmd, detach=False):
    base = 'ssh -i /home/leonardo.herkenhoff/.ssh/id_rsa -o KexAlgorithms=curve25519-sha256 -o StrictHostKeyChecking=no leonardo.herkenhoff@10.50.1.92'
    if detach:
        subprocess.Popen(f'{base} "{cmd}"', shell=True)
    else:
        return subprocess.check_output(f'{base} "{cmd}"', shell=True, text=True)

def run_local(cmd):
    return subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

def get_missed_errors():
    out = run_local("ip -s -s link show dev eno12399np0 | grep -A 1 'RX:' | tail -n 1 | awk '{print $5}'")
    try: return int(out.stdout.strip())
    except: return 0

print("Finding PCAPs on Server A...")
raw_pcaps = run_remote('find /dados/CIC-IDS-2017-sliced /dados/CICDDoS2019 -type f -name \'*.pcap*\'').splitlines()
all_pcaps = [p.strip() for p in raw_pcaps if p.strip()]

out_csv = '/tmp/parity_results_legacy_100g.csv'
processed = set()
if os.path.exists(out_csv):
    with open(out_csv, 'r') as f:
        for line in f:
            if ',' in line: processed.add(line.split(',')[0])
else:
    with open(out_csv, 'w') as f:
        f.write('PCAP,Extractor,RAM_KB,CPU_Percent,Flows_Generated,Processed_Pkts,Missed_Drops\n')

print(f"Found {len(all_pcaps)} PCAPs to process.")

for pcap in all_pcaps:
    name = os.path.basename(pcap)
    if name in processed:
        continue
    
    print(f"Processing {name}...")
    
    # 1. XFlowLyzer (Lynceus)
    run_local('sudo pkill -9 loader; sudo pkill -9 rustiflow')
    run_local('sudo tc qdisc del dev eno12399np0 clsact 2>/dev/null')
    run_local('sudo ip link set dev eno12399np0 xdp off 2>/dev/null')
    time.sleep(1)
    
    missed_before = get_missed_errors()
    lyn_log = f'/tmp/lyn_out.log'
    run_local(f'cd /home/leonardo.herkenhoff/Lynceus && sudo nohup /usr/bin/time -v ./build/loader -i eno12399np0 > {lyn_log} 2>&1 < /dev/null &')
    time.sleep(2)
    try:
        run_remote(f'python3 /home/leonardo.herkenhoff/push_pcap.py {pcap}')
    except Exception as e:
        print(f"TRex error on {pcap}: {e}")
    time.sleep(1)
    run_local('sudo pkill -2 loader')
    time.sleep(2)
    run_local('sudo pkill -9 loader')
    
    missed_after = get_missed_errors()
    lyn_missed_diff = max(0, missed_after - missed_before)
    
    lyn_processed_pkts = 0
    try:
        with open(lyn_log, 'r') as f: txt = f.read()
        ram = txt.split('Maximum resident set size (kbytes): ')[1].split('\n')[0].strip() if 'Maximum resident set size' in txt else '0'
        cpu = txt.split('Percent of CPU this job got: ')[1].split('\n')[0].strip().replace('%','') if 'Percent of CPU' in txt else '0'
        lyn_processed_pkts = int(txt.split('Total Ingress: ')[1].split(' packets')[0].strip()) if 'Total Ingress:' in txt else 0
        flows = subprocess.check_output(f'grep -c "," {lyn_log} || echo 0', shell=True).strip().decode()
        
        with open(out_csv, 'a') as f:
            f.write(f'{name},Lynceus,{ram},{cpu},{flows},{lyn_processed_pkts},{lyn_missed_diff}\n')
    except:
        pass

    # 2. RustiFlow
    run_local('sudo pkill -9 loader; sudo pkill -9 rustiflow')
    run_local('sudo tc qdisc del dev eno12399np0 clsact 2>/dev/null')
    run_local('sudo ip link set dev eno12399np0 xdp off 2>/dev/null')
    time.sleep(1)
    
    missed_before = get_missed_errors()
    rf_log = f'/tmp/rf_out.log'
    rf_csv = f'/tmp/rf_out.csv'
    run_local(f'sudo nohup /usr/bin/time -v /home/leonardo.herkenhoff/RustiFlow/target/release/rustiflow -f rustiflow -o csv --export-path {rf_csv} realtime eno12399np0 > {rf_log} 2>&1 < /dev/null &')
    time.sleep(2)
    try:
        run_remote(f'python3 /home/leonardo.herkenhoff/push_pcap.py {pcap}')
    except: pass
    time.sleep(2)
    run_local('sudo pkill -2 rustiflow')
    time.sleep(2)
    run_local('sudo pkill -9 rustiflow') 
    
    missed_after = get_missed_errors()
    rf_missed_diff = max(0, missed_after - missed_before)
    
    try:
        with open(rf_log, 'r') as f: txt = f.read()
        ram = txt.split('Maximum resident set size (kbytes): ')[1].split('\n')[0].strip() if 'Maximum resident set size' in txt else '0'
        cpu = txt.split('Percent of CPU this job got: ')[1].split('\n')[0].strip().replace('%','') if 'Percent of CPU' in txt else '0'
        flows = subprocess.check_output(f'wc -l < {rf_csv} 2>/dev/null || echo 0', shell=True).strip().split()[0].decode()
        rf_processed_pkts = max(0, lyn_processed_pkts - rf_missed_diff)
        
        with open(out_csv, 'a') as f:
            f.write(f'{name},RustiFlow,{ram},{cpu},{flows},{rf_processed_pkts},{rf_missed_diff}\n')
            
        run_local(f'sudo rm -f {rf_csv} {rf_log} {lyn_log}')
    except:
        pass

print("FINISHED LEGACY 100G EXPERIMENT")
