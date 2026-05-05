/**
 * @file main.bpf.c
 * @brief Kernel-Space Data Plane - XDP Feature Extractor.
 *
 * @details
 * Performs recursive packet dissection and flow state tracking.
 * Implements RingBuffer-based event export for L4/L7 metadata.
 * Optimised for high-fidelity extraction on kernels >= 5.15 (LTS).
 *
 * @version 1.0 (The Definitive Foundation)
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "lynceus.h"

char LICENSE[] SEC("license") = "GPL";

/* --- [Kernel State Maps] --- */

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, FLOW_HASH_SIZE);
    __type(key, flow_id_t);
    __type(value, flow_record_t);
} flow_table SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} global_stats SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4096 * 4096); /* 16MB per core */
} inner_rb SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
    __uint(max_entries, 256);
    __type(key, __u32);
    __array(values, typeof(inner_rb));
} pkt_ringbuf_map SEC(".maps");

/* --- [L7 Dissection Engine] --- */

static __always_inline void parse_dns(void *data, void *data_end, flow_record_t *rec) {
    struct {
        __u16 id; __u16 flags; __u16 q_count; __u16 ans_count;
        __u16 auth_count; __u16 add_count;
    } *dns = data;

    if ((void *)(dns + 1) > data_end) return;
    rec->dns_answer_count = bpf_ntohs(dns->ans_count);

    if (bpf_ntohs(dns->q_count) == 0) return;

    __u8 *ptr = (__u8 *)(dns + 1);
    /* Standard DNS label traversal. Limited to 16 iterations to maintain
     * verifier state-space compatibility on older kernels (e.g. 5.15). */
    #pragma unroll
    for (int i = 0; i < 16; i++) {
        if (ptr + 1 > (__u8 *)data_end) return;
        __u8 len = *ptr;
        if ((len & 0xC0) == 0xC0) { ptr += 2; goto found; }
        if (len == 0) { ptr++; goto found; }
        if (len > 63) return; 
        if (ptr + len + 1 > (__u8 *)data_end) return;
        ptr += (len + 1);
    }
    return;

found:
    if (ptr + 4 > (__u8 *)data_end) return;
    __u16 qt, qc;
    __builtin_memcpy(&qt, ptr, 2);
    __builtin_memcpy(&qc, ptr + 2, 2);
    rec->dns_qtype = bpf_ntohs(qt);
    rec->dns_qclass = bpf_ntohs(qc);
}

static __always_inline void parse_snmp(void *data, void *data_end, flow_record_t *rec) {
    __u8 *ptr = data;
    if (ptr + 2 > (__u8 *)data_end) return;
    /* ASN.1 BER/DER Dissection: Sequence(0x30) -> Len -> Version(0x02) -> Len -> Value */
    if (ptr[0] != 0x30) return;
    ptr += 2;
    if (ptr + 3 > (__u8 *)data_end) return;
    if (ptr[0] != 0x02) return; /* Integer tag for version */
    __u8 ver_len = ptr[1];
    ptr += (2 + ver_len);
    /* Community string skip */
    if (ptr + 2 > (__u8 *)data_end) return;
    if (ptr[0] != 0x04) return; /* OctetString tag */
    __u8 comm_len = ptr[1];
    ptr += (2 + comm_len);
    /* PDU Type */
    if (ptr + 1 > (__u8 *)data_end) return;
    rec->snmp_pdu_type = ptr[0];
}

SEC("xdp")
int xdp_prog(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    __u32 cpu_id = bpf_get_smp_processor_id();
    __u32 stats_key = 0;
    __u64 *total_pkts = bpf_map_lookup_elem(&global_stats, &stats_key);
    if (total_pkts) __sync_fetch_and_add(total_pkts, 1);

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;
    
    flow_id_t key = {0};
    flow_record_t new_rec = {0};
    __u8 protocol = 0;
    __u16 src_p = 0, dst_p = 0, win = 0;
    __u8 flags = 0;
    void *p_ptr = NULL;

    if (eth->h_proto == bpf_htons(ETH_P_IP)) {
        struct iphdr *ip = (void *)(eth + 1);
        if ((void *)(ip + 1) > data_end) return XDP_PASS;

        __builtin_memcpy(&key.src_ip[12], &ip->saddr, 4);
        __builtin_memcpy(&key.dst_ip[12], &ip->daddr, 4);
        protocol = ip->protocol;
        
        new_rec.ip_ver = 4;
        new_rec.ttl = ip->ttl;
        new_rec.ip_id = bpf_ntohs(ip->id);
        new_rec.frag_off = bpf_ntohs(ip->frag_off);
        new_rec.total_bytes = bpf_ntohs(ip->tot_len);
        new_rec.header_len = (ip->ihl * 4);
        new_rec.payload_len = new_rec.total_bytes - new_rec.header_len;
        p_ptr = (void *)((__u8 *)ip + new_rec.header_len);

    } else if (eth->h_proto == bpf_htons(ETH_P_IPV6)) {
        struct ipv6hdr *ip6 = (void *)(eth + 1);
        if ((void *)(ip6 + 1) > data_end) return XDP_PASS;

        __builtin_memcpy(key.src_ip, &ip6->saddr, 16);
        __builtin_memcpy(key.dst_ip, &ip6->daddr, 16);
        protocol = ip6->nexthdr;

        new_rec.ip_ver = 6;
        new_rec.traffic_class = (bpf_ntohs(*(uint16_t *)ip6) >> 4) & 0xFF;
        new_rec.flow_label = bpf_ntohl(*(uint32_t *)ip6) & 0x000FFFFF;
        new_rec.ttl = ip6->hop_limit;
        new_rec.ip_id = 0; 
        new_rec.frag_off = 0;
        new_rec.header_len = 40;
        new_rec.total_bytes = bpf_ntohs(ip6->payload_len) + 40;
        new_rec.payload_len = bpf_ntohs(ip6->payload_len);
        p_ptr = (void *)(ip6 + 1);
    } else {
        return XDP_PASS;
    }

    /* --- [Virtual Network Stack Decapsulation] --- */
    if (protocol == 47) { /* GRE */
        struct { __u16 flags; __u16 proto; } *gre = p_ptr;
        if ((void *)(gre + 1) <= data_end) {
            __u16 g_flags = bpf_ntohs(gre->flags);
            __u16 g_proto = bpf_ntohs(gre->proto);
            p_ptr = (void *)(gre + 1);
            if (g_flags & 0x8000) { /* Checksum/Routing present (4 bytes) */
                p_ptr = (void *)((__u32 *)p_ptr + 1);
            }
            if (g_flags & 0x2000) { /* Key present */
                if ((void *)((__u32 *)p_ptr + 1) <= data_end) {
                    new_rec.tunnel_id = bpf_ntohl(*(__u32 *)p_ptr);
                    p_ptr = (void *)((__u32 *)p_ptr + 1);
                }
            }
            if (g_proto == 0x0800) { /* ETH_P_IP */
                struct iphdr *iph_in = p_ptr;
                if ((void *)(iph_in + 1) <= data_end) {
                    __builtin_memcpy(&key.src_ip[12], &iph_in->saddr, 4);
                    __builtin_memcpy(&key.dst_ip[12], &iph_in->daddr, 4);
                    protocol = iph_in->protocol;
                    p_ptr = (void *)((__u8 *)iph_in + (iph_in->ihl * 4));
                    new_rec.tunnel_type = 1; /* GRE */
                }
            }
        }
    }

    key.protocol = protocol;

    if (protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = p_ptr;
        if ((void *)(tcp + 1) <= data_end) {
            src_p = tcp->source; dst_p = tcp->dest;
            win = tcp->window; flags = ((__u8 *)tcp)[13];
            new_rec.window_size = bpf_ntohs(win);
            new_rec.tcp_flags = flags;
        }
    } else if (protocol == IPPROTO_UDP) {
        struct udphdr *udp = p_ptr;
        if ((void *)(udp + 1) <= data_end) {
            src_p = udp->source; dst_p = udp->dest;
            p_ptr = (void *)(udp + 1);

            /* VXLAN Decapsulation (UDP 4789) */
            if (dst_p == bpf_htons(4789)) {
                struct { __u32 flags; __u32 vni; } *vxlan = p_ptr;
                if ((void *)(vxlan + 1) <= data_end) {
                    new_rec.tunnel_id = bpf_ntohl(vxlan->vni) >> 8;
                    struct ethhdr *eth_in = (void *)(vxlan + 1);
                    if ((void *)(eth_in + 1) <= data_end) {
                        if (eth_in->h_proto == bpf_htons(ETH_P_IP)) {
                            struct iphdr *iph_in = (void *)(eth_in + 1);
                            if ((void *)(iph_in + 1) <= data_end) {
                                __builtin_memcpy(&key.src_ip[12], &iph_in->saddr, 4);
                                __builtin_memcpy(&key.dst_ip[12], &iph_in->daddr, 4);
                                protocol = iph_in->protocol;
                                key.protocol = protocol;
                                p_ptr = (void *)((__u8 *)iph_in + (iph_in->ihl * 4));
                                new_rec.tunnel_type = 2; /* VXLAN */
                                /* Continue with inner L4 if possible */
                                if (protocol == IPPROTO_UDP && (void *)((struct udphdr *)p_ptr + 1) <= data_end) {
                                    struct udphdr *udp_in = p_ptr;
                                    src_p = udp_in->source; dst_p = udp_in->dest;
                                    p_ptr = (void *)(udp_in + 1);
                                }
                            }
                        }
                    }
                }
            }

            /* [Application Layer Protocol Discovery] */
            __u16 sp = bpf_ntohs(src_p), dp = bpf_ntohs(dst_p);
            if (sp == 53 || dp == 53) {
                parse_dns(p_ptr, data_end, &new_rec);
            } else if (sp == 123 || dp == 123) {
                if ((void *)((__u8 *)p_ptr + 4) <= data_end) {
                    __u8 *ntp = p_ptr;
                    new_rec.ntp_mode = ntp[0] & 0x07;
                    new_rec.ntp_stratum = ntp[1];
                }
            } else if (sp == 161 || dp == 161) {
                parse_snmp(p_ptr, data_end, &new_rec);
            } else if (dp == 1900) {
                if ((void *)((__u8 *)p_ptr + 8) <= data_end) {
                    __u8 *m = p_ptr;
                    if (m[0] == 'M' && m[1] == '-' && m[2] == 'S' && m[3] == 'E' &&
                        m[4] == 'A' && m[5] == 'R' && m[6] == 'C' && m[7] == 'H') {
                        new_rec.ssdp_method = 1;
                    }
                }
            }
        }
    }
    
    key.src_port = src_p;
    key.dst_port = dst_p;

    flow_record_t *rec = bpf_map_lookup_elem(&flow_table, &key);
    if (!rec) {
        new_rec.start_ts = bpf_ktime_get_ns();
        if (new_rec.start_ts == 0) new_rec.start_ts = 1; /* prevent zero */
        new_rec.last_ts = new_rec.start_ts;
        new_rec.eth_proto = eth->h_proto;
        __builtin_memcpy(new_rec.src_mac, eth->h_source, 6);
        __builtin_memcpy(new_rec.dst_mac, eth->h_dest, 6);
        new_rec.pkts_count = 1;
        new_rec.window_size = win;
        new_rec.tcp_flags = flags;

        if (protocol == IPPROTO_ICMP || protocol == IPPROTO_ICMPV6) {
            struct icmphdr *icmp = p_ptr; 
            if ((void *)((__u8 *)icmp + 8) <= data_end) {
                new_rec.icmp_type = icmp->type;
                new_rec.icmp_code = icmp->code;
                new_rec.icmp_id = bpf_ntohs(icmp->un.echo.id);
            }
        }

        /* [Payload Hint Extraction]
         * VERIFIER OPTIMIZATION: We use a single boundary check before copying
         * the 64-byte block. This avoids state explosion (E2BIG) in the 
         * kernel verifier by reducing branches from O(N) to O(1). */
        if (p_ptr + 64 <= data_end) {
            #pragma unroll
            for (int i = 0; i < 64; i++) {
                new_rec.payload_hint[i] = ((__u8 *)p_ptr)[i];
            }
        }

        bpf_map_update_elem(&flow_table, &key, &new_rec, BPF_ANY);
        
        void *rb = bpf_map_lookup_elem(&pkt_ringbuf_map, &cpu_id);
        if (rb) {
            packet_event_t *event = bpf_ringbuf_reserve(rb, sizeof(packet_event_t), 0);
            if (event) {
                event->key = key;
                event->rec = new_rec;
                event->timestamp_ns = bpf_ktime_get_ns();
                bpf_ringbuf_submit(event, 0);
            }
        }
    } else {
        void *rb = bpf_map_lookup_elem(&pkt_ringbuf_map, &cpu_id);
        if (rb) {
            packet_event_t *event = bpf_ringbuf_reserve(rb, sizeof(packet_event_t), 0);
            if (event) {
                event->key = key;
                event->rec = new_rec; 
                event->timestamp_ns = bpf_ktime_get_ns();
                bpf_ringbuf_submit(event, 0);
            }
        }
        rec->pkts_count++;
        rec->total_bytes += new_rec.total_bytes;
        rec->last_ts = bpf_ktime_get_ns();
        rec->tcp_flags |= flags;
    }

    return XDP_PASS;
}
