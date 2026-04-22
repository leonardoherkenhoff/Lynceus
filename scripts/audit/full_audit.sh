#!/bin/bash
set -e

echo "Starting Lynceus Audit..."

# 1. Clean previous state
rm -f flows.csv

# 2. Start loader in background
./build/loader veth0 > loader_audit.log 2>&1 &
LOADER_PID=$!
echo "Loader started with PID $LOADER_PID"

# 3. Wait for BPF initialization
sleep 2

# 4. Replay Audit Traffic
echo "Replaying audit traffic..."
tcpreplay -i veth1 audit_traffic.pcap

# 5. Wait for flows to timeout or be flushed
sleep 5

echo "Stopping loader..."
kill -SIGINT $LOADER_PID || true
wait $LOADER_PID || true

echo "Audit capture complete. Running verification..."

python3 <<EOF
import pandas as pd
import numpy as np

try:
    df = pd.read_csv("flows.csv")
    print(f"Total flows captured: {len(df)}")
    
    def check_feature(name, condition, expected_desc):
        subset = df[condition]
        if not subset.empty:
            print(f"{expected_desc}: OK")
            return True
        else:
            print(f"{expected_desc}: FAIL")
            return False

    results = []
    results.append(check_feature("DNS A", (df['DNSQueryType'] == 1), "DNS A"))
    results.append(check_feature("DNS AAAA", (df['DNSQueryType'] == 28), "DNS AAAA"))
    results.append(check_feature("SNMP", (df['SNMP_PDU_Type'] == 160), "SNMP GetRequest"))
    results.append(check_feature("NTP", (df['NTP_Mode'] == 3), "NTP Client Mode"))
    results.append(check_feature("SSDP", (df['SSDP_Method'] == 1), "SSDP M-SEARCH"))
    results.append(check_feature("GRE", (df['TunnelId'] == 1234), "GRE Tunnel (Key 1234)"))
    results.append(check_feature("VXLAN", (df['TunnelId'] == 5678), "VXLAN Tunnel (VNI 5678)"))

    if all(results):
        print("\n✅ AUDIT PASSED: All 1.0 objectives validated.")
    else:
        print("\n❌ AUDIT FAILED: Missing features.")

except Exception as e:
    print(f"Audit verification error: {e}")
EOF
