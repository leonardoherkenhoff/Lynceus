#!/usr/bin/env python3
"""
Lynceus Audit Infrastructure - Synthetic Traffic Generator (v1.0)
-----------------------------------------------------------
Scientific Milestone: v1.0 (The Definitive Foundation)

Research Objective:
Generates deterministic synthetic traffic patterns to validate the parity 
and extraction fidelity of the Lynceus BPF Data Plane.

Coverage Matrix:
1. DNS: Recursive queries (A, AAAA) for L7 parser validation.
2. SNMP: BER/DER encoded PDUs for ASN.1 skip-logic verification.
3. NTP: Stratum/Mode field extraction.
4. SSDP: M-SEARCH method heuristic matching.
5. GRE/VXLAN: Virtual stack decapsulation and inner-flow tracking.
"""

from scapy.all import *
import os

def generate_audit_pcap(filename):
    """
    Constructs a deterministic multi-protocol PCAP artifact.
    """
    pkts = []
    
    # 1. DNS (Section Validation)
    pkts.append(Ether()/IP(dst="8.8.8.8")/UDP(sport=5353, dport=53)/DNS(rd=1, qd=DNSQR(qname="google.com", qtype="A")))
    pkts.append(Ether()/IP(dst="8.8.8.8")/UDP(sport=5354, dport=53)/DNS(rd=1, qd=DNSQR(qname="example.org", qtype="AAAA")))
    
    # 2. SNMP (ASN.1 PDU Validation)
    snmp_payload = b"\x30\x26\x02\x01\x01\x04\x06\x70\x75\x62\x6c\x69\x63\xa0\x19\x02\x04\x12\x34\x56\x78\x02\x01\x00\x02\x01\x00\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00"
    pkts.append(Ether()/IP(dst="1.2.3.4")/UDP(sport=161, dport=161)/Raw(load=snmp_payload))
    
    # 3. NTP (Control Field Validation)
    ntp_payload = b"\x1b" + b"\x00" * 47
    pkts.append(Ether()/IP(dst="2.3.4.5")/UDP(sport=123, dport=123)/Raw(load=ntp_payload))
    
    # 4. SSDP (Heuristic Method Validation)
    ssdp_payload = b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\nST: ssdp:all\r\n\r\n"
    pkts.append(Ether()/IP(dst="239.255.255.250")/UDP(sport=1900, dport=1900)/Raw(load=ssdp_payload))
    
    # 5. GRE (Virtual Stack Decapsulation Validation)
    pkts.append(Ether()/IP(dst="10.0.0.1")/GRE(key_present=1, key=1234)/IP(src="192.168.1.1", dst="192.168.1.2")/ICMP())
    
    # 6. VXLAN (VNI/Inner-Flow Validation)
    pkts.append(Ether()/IP(dst="10.0.0.2")/UDP(dport=4789)/VXLAN(vni=5678)/Ether()/IP(src="172.16.0.1", dst="172.16.0.2")/UDP(sport=4444, dport=5555))
    
    wrpcap(filename, pkts)
    print(f"✅ Audit Artifact Generated: {filename} ({len(pkts)} packets construction)")

if __name__ == "__main__":
    generate_audit_pcap("audit_traffic.pcap")
