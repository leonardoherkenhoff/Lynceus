from scapy.all import *
import numpy as np
import os

def generate_complex_audit(filename):
    pkts = []
    
    # 1. Flow A: Normal Distribution of Sizes (Tests Welford & Histograms)
    # 50 packets, Mean=500, Std=100
    sizes = np.random.normal(500, 100, 50).astype(int)
    sizes = np.clip(sizes, 64, 1500)
    for i, s in enumerate(sizes):
        payload = b"X" * (s - 54) # Simple payload to match size
        pkts.append(Ether()/IP(dst="1.1.1.1")/TCP(sport=1000, dport=80, flags="PA")/Raw(load=payload))
        
    # 2. Flow B: Extreme Skew/Kurtosis (Outliers)
    # 40 packets of 100 bytes, 10 packets of 1500 bytes
    for i in range(40):
        pkts.append(Ether()/IP(dst="2.2.2.2")/TCP(sport=2000, dport=443, flags="A")/Raw(load=b"A"*46))
    for i in range(10):
        pkts.append(Ether()/IP(dst="2.2.2.2")/TCP(sport=2000, dport=443, flags="A")/Raw(load=b"B"*1446))
        
    # 3. Flow C: All TCP Flags
    flags = ["S", "SA", "A", "PA", "FA", "R", "E", "C"]
    for f in flags:
        pkts.append(Ether()/IP(dst="3.3.3.3")/TCP(sport=3000, dport=22, flags=f))
        
    # 4. Flow D: L7 Mixed (DNS + NTP + SNMP + SSDP)
    # Using different sports to ensure separate flows or same flow with mixed L7
    pkts.append(Ether()/IP(dst="8.8.8.8")/UDP(sport=53, dport=53)/DNS(rd=1, qd=DNSQR(qname="test.com")))
    pkts.append(Ether()/IP(dst="4.4.4.4")/UDP(sport=123, dport=123)/Raw(load=b"\x1b"+b"\x00"*47))
    snmp_payload = b"\x30\x26\x02\x01\x01\x04\x06\x70\x75\x62\x6c\x69\x63\xa0\x19\x02\x04\x12\x34\x56\x78\x02\x01\x00\x02\x01\x00\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00"
    pkts.append(Ether()/IP(dst="5.5.5.5")/UDP(sport=161, dport=161)/Raw(load=snmp_payload))
    
    # 5. Flow E: Tunnels (GRE + VXLAN)
    pkts.append(Ether()/IP(dst="10.0.0.1")/GRE(key_present=1, key=9999)/IP(src="192.168.10.1", dst="192.168.10.2")/UDP(sport=99, dport=99))
    pkts.append(Ether()/IP(dst="10.0.0.2")/UDP(dport=4789)/VXLAN(vni=8888)/Ether()/IP(src="172.16.10.1", dst="172.16.10.2")/UDP(sport=88, dport=88))

    wrpcap(filename, pkts)
    print(f"Definitive Audit PCAP generated: {filename} ({len(pkts)} packets)")

if __name__ == "__main__":
    generate_complex_audit("definitive_audit.pcap")
