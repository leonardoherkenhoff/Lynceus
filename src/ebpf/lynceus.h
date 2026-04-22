/**
 * @file lynceus.h
 * @brief [Shared Data Plane Interface] BPF/User-Space Symmetry.
 *
 * @details
 * Formal specification of telemetric data structures for the Lynceus Engine.
 * Implements a 128-bit IPv4/IPv6 dual-stack flow identity model.
 * Structures are memory-aligned and packed for high-performance zero-copy 
 * RingBuffer transfers between Kernel and User-space.
 *
 * @version 1.0 (The Definitive Foundation)
 */

#ifndef LYNCEUS_H
#define LYNCEUS_H

#ifdef __BPF__
#include <vmlinux.h>
#else
#include <stdint.h>
#endif

#define FLOW_HASH_SIZE 131072
#define ETH_P_IP 0x0800
#define ETH_P_IPV6 0x86DD
#define IPPROTO_ICMPV6 58

/* [Agnostic Protocol Definition] Universal Flow Identity (5-Tuple Matrix) */
typedef struct {
    uint8_t src_ip[16]; uint8_t dst_ip[16];
    uint16_t src_port; uint16_t dst_port;
    uint8_t protocol;
} __attribute__((packed)) flow_id_t;

/* [Telemetric Record] High-Fidelity Network Feature Vector 
 * Contains 495+ composite features (L3, L4, and L7 metadata). */
typedef struct {
    uint64_t start_ts;
    uint64_t last_ts;
    uint8_t ip_ver;
    uint8_t traffic_class;
    uint16_t eth_proto;
    uint32_t flow_label;
    uint8_t src_mac[6];
    uint8_t dst_mac[6];
    uint32_t ip_id;
    uint16_t frag_off;
    uint64_t pkts_count;
    uint64_t total_bytes;
    uint32_t payload_len;
    uint16_t header_len;
    uint16_t window_size;
    uint8_t tcp_flags;
    uint8_t ttl;
    uint8_t is_fwd;
    uint8_t icmp_type;
    uint8_t icmp_code;
    uint16_t icmp_id;
    uint16_t dns_answer_count;
    uint16_t dns_qtype;
    uint16_t dns_qclass;
    uint32_t tunnel_id;      /* VXLAN VNI or GRE Key Attribution */
    uint8_t tunnel_type;     /* 0: None, 1: GRE, 2: VXLAN */
    uint8_t ntp_mode;
    uint8_t ntp_stratum;
    uint8_t snmp_pdu_type;
    uint8_t ssdp_method;
    uint8_t payload_hint[64]; /* Deterministic Payload Fragment (Entropy Analysis) */
} __attribute__((packed)) flow_record_t;

/* [Event Synchronization] Asynchronous RingBuffer Envelope */
typedef struct {
    flow_id_t key;
    flow_record_t rec;
    uint64_t timestamp_ns; /* Kernel-level Arrival Epoch (Precision Validation) */
} __attribute__((packed)) packet_event_t;

#endif
