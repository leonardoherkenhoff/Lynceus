/**
 * @file loader.c
 * @brief User-Space Control Plane - High Performance Network Feature Extractor.
 *
 * @version 1.2 (Turbo Serialization & Zero-Copy Optimization)
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdatomic.h>
#include <string.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/resource.h>
#include <signal.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <linux/if_link.h>
#include <time.h>
#include <math.h>
#include <pthread.h>
#include <sched.h>
#include <sys/stat.h>
#include <errno.h>

#include "../ebpf/lynceus.h"

#define IDLE_THRESHOLD      1.0
#define HIST_BINS           80
#ifndef IPPROTO_ICMPV6
#define IPPROTO_ICMPV6 58
#endif
#define HIST_STEP           20
#define BULK_THRESHOLD      1.0
#define IDLE_FLOW_TIMEOUT_S 5.0
#define IDLE_SCAN_BATCH     10000

#define SPSC_SLOTS    1024
#define MAX_RECORD    32768

struct spsc_queue {
    char     data[SPSC_SLOTS][MAX_RECORD];
    size_t   lens[SPSC_SLOTS];
    _Atomic uint32_t head;
    _Atomic uint32_t tail;
} __attribute__((aligned(64)));

struct welford_stat {
    uint64_t n; double M1, M2, M3, M4; uint32_t max, min;
    double pq[5]; int pn[5];
};

static void w_init(struct welford_stat *w) {
    memset(w, 0, sizeof(*w));
    w->min = 0xFFFFFFFF;
    w->pn[0]=1; w->pn[1]=2; w->pn[2]=3; w->pn[3]=4; w->pn[4]=5;
}

static inline void w_update(struct welford_stat *w, double x) {
    uint64_t n1 = w->n; w->n++;
    double delta = x - w->M1, delta_n = delta / w->n, delta_n2 = delta_n * delta_n, term1 = delta * delta_n * n1;
    w->M1 += delta_n;
    w->M4 += term1 * delta_n2 * (w->n * w->n - 3 * w->n + 3) + 6 * delta_n2 * w->M2 - 4 * delta_n * w->M3;
    w->M3 += term1 * delta_n * (w->n - 2) - 3 * delta_n * w->M2;
    w->M2 += term1;
    if (x > (double)w->max) w->max = (uint32_t)x; if (x < (double)w->min) w->min = (uint32_t)x;
    uint64_t cnt = w->n;
    if (cnt <= 5) {
        w->pq[cnt-1] = x;
        if (cnt == 5) {
            for (int i=1; i<5; i++) {
                double tmp=w->pq[i]; int j=i-1;
                while (j>=0 && w->pq[j]>tmp) { w->pq[j+1]=w->pq[j]; j--; }
                w->pq[j+1]=tmp;
            }
        }
        return;
    }
    int k;
    if (x < w->pq[0]) { w->pq[0]=x; k=0; }
    else if (x < w->pq[1]) { k=0; }
    else if (x < w->pq[2]) { k=1; }
    else if (x < w->pq[3]) { k=2; }
    else if (x <=w->pq[4]) { k=3; }
    else { w->pq[4]=x; k=3; }
    for (int i=k+1; i<5; i++) w->pn[i]++;
    double np[5]; double fc=(double)cnt;
    np[0]=1.0; np[1]=1.0+fc/4.0; np[2]=1.0+fc/2.0; np[3]=1.0+3.0*fc/4.0; np[4]=fc;
    for (int i=1; i<=3; i++) {
        double d = np[i] - w->pn[i];
        if ((d>=1.0 && w->pn[i+1]-w->pn[i]>1)||(d<=-1.0 && w->pn[i-1]-w->pn[i]<-1)) {
            int s = (d>=0.0)?1:-1;
            double denom1=(double)(w->pn[i+1]-w->pn[i-1]);
            double q_par = w->pq[i] + (double)s/denom1 *
                (((double)(w->pn[i]-w->pn[i-1]+s))*(w->pq[i+1]-w->pq[i])/(double)(w->pn[i+1]-w->pn[i]) +
                 ((double)(w->pn[i+1]-w->pn[i]-s))*(w->pq[i]-w->pq[i-1])/(double)(w->pn[i]-w->pn[i-1]));
            if (w->pq[i-1] < q_par && q_par < w->pq[i+1]) w->pq[i] = q_par;
            else w->pq[i] += (double)s*(w->pq[i+s]-w->pq[i])/(double)(w->pn[i+s]-w->pn[i]);
            w->pn[i] += s;
        }
    }
}

static inline double w_mean(struct welford_stat *w) { return w->n > 0 ? w->M1 : 0; }
static inline double w_var(struct welford_stat *w)  { return (w->n > 1) ? w->M2 / (w->n - 1) : 0; }
static inline double w_std(struct welford_stat *w)  { return sqrt(w_var(w)); }
static inline double w_skew(struct welford_stat *w) { return (w->M2 > 1e-9) ? sqrt(w->n) * w->M3 / pow(w->M2, 1.5) : 0; }
static inline double w_kurt(struct welford_stat *w) { return (w->M2 > 1e-9) ? (double)w->n * w->M4 / (w->M2 * w->M2) - 3.0 : 0; }
static inline double w_median(struct welford_stat *w) { return (w->n < 5) ? w->M1 : w->pq[2]; }

static inline double calculate_entropy(const uint8_t *data, size_t len) {
    if (len == 0) return 0;
    uint32_t counts[256] = {0};
    for (size_t i = 0; i < len; i++) counts[data[i]]++;
    double entropy = 0, inv_len = 1.0 / (double)len;
    for (int i = 0; i < 256; i++) {
        if (counts[i] > 0) {
            double p = (double)counts[i] * inv_len;
            entropy -= p * log2(p);
        }
    }
    return entropy;
}

static uint64_t boot_time_ns = 0;
static void init_boot_time() {
    struct timespec ts, tk;
    clock_gettime(CLOCK_REALTIME, &ts);
    clock_gettime(CLOCK_MONOTONIC, &tk);
    boot_time_ns = (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec - ((uint64_t)tk.tv_sec * 1000000000ULL + tk.tv_nsec);
}

struct flow_state {
    flow_id_t key;
    uint8_t ip_ver; uint16_t eth_proto;
    uint8_t traffic_class; uint32_t flow_label;
    uint8_t src_mac[6], dst_mac[6];
    struct welford_stat t_pay, f_pay, b_pay, t_hdr, f_hdr, b_hdr, t_iat, f_iat, b_iat, t_delta, f_delta, b_delta, active_s, idle_s, win_s, ip_id_s, frag_s, ttl_s;
    uint64_t t_hist[HIST_BINS], f_hist[HIST_BINS], b_hist[HIST_BINS];
    uint64_t f_bytes, b_bytes, f_last, b_last, t_last;
    uint16_t f_win_init, b_win_init;
    uint64_t flags[8], f_flags[8], b_flags[8];
    uint64_t f_bulk_bytes, b_bulk_bytes, f_bulk_pkts, b_bulk_pkts, f_bulk_cnt, b_bulk_cnt;
    uint64_t active_start;
    uint32_t last_f_pay, last_b_pay, last_t_pay;
    uint8_t last_icmp_type, last_icmp_code, last_ttl;
    uint16_t last_icmp_id, dns_answer_count, dns_qtype, dns_qclass;
    uint32_t tunnel_id; uint8_t tunnel_type, ntp_mode, ntp_stratum, snmp_pdu_type, ssdp_method;
    int active;
};

struct worker_t {
    pthread_t thread; int rb_fd; struct ring_buffer *rb;
    struct flow_state *flow_table;
    int id; uint64_t processed_events; uint32_t scan_ptr;
};

static struct worker_t *workers;
static int num_workers = 1;
static volatile bool exiting = false;
static void sig_handler(int sig) { (void)sig; exiting = true; }

static FILE *g_out_f = NULL;
static struct spsc_queue *g_queues = NULL;
static pthread_t g_writer_thread;

static void *writer_fn(void *arg) {
    (void)arg; bool flushed;
    do {
        flushed = false;
        for (int i = 0; i < num_workers; i++) {
            struct spsc_queue *q = &g_queues[i];
            uint32_t h = atomic_load_explicit(&q->head, memory_order_relaxed);
            uint32_t t = atomic_load_explicit(&q->tail, memory_order_acquire);
            while (h != t) {
                uint32_t idx = h & (SPSC_SLOTS - 1);
                fwrite(q->data[idx], 1, q->lens[idx], g_out_f);
                h++; flushed = true;
                atomic_store_explicit(&q->head, h, memory_order_release);
            }
        }
        if (!flushed && !exiting) { struct timespec ts = {0, 1000000}; nanosleep(&ts, NULL); }
    } while (!exiting || flushed);
    return NULL;
}

static inline double median_from_hist(const uint64_t *hist, uint64_t n) {
    if (n == 0) return 0.0;
    uint64_t half = (n + 1) >> 1, acc = 0;
    for (int i = 0; i < HIST_BINS; i++) {
        acc += hist[i];
        if (acc >= half) return (double)(i * HIST_STEP);
    }
    return (double)((HIST_BINS - 1) * HIST_STEP);
}

static inline void fast_ip_to_str(char *buf, int *off, uint8_t ver, const uint8_t *addr) {
    if (ver == 4) {
        *off += sprintf(buf + *off, "%u.%u.%u.%u", addr[12], addr[13], addr[14], addr[15]);
    } else {
        *off += sprintf(buf + *off, "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
            addr[0], addr[1], addr[2], addr[3], addr[4], addr[5], addr[6], addr[7],
            addr[8], addr[9], addr[10], addr[11], addr[12], addr[13], addr[14], addr[15]);
    }
}

static void flush_flow_record(struct worker_t *w, struct flow_state *s, uint64_t now_ns) {
    if (!s->active || s->t_pay.n == 0) return;
    struct spsc_queue *q = &g_queues[w->id];
    uint32_t t = atomic_load_explicit(&q->tail, memory_order_relaxed);
    uint32_t h = atomic_load_explicit(&q->head, memory_order_acquire);
    if ((t - h) >= SPSC_SLOTS) return;
    uint32_t idx = t & (SPSC_SLOTS - 1);
    char *buf = (char *)q->data[idx]; int off = 0;
    uint64_t norm_now = (now_ns > 1700000000000000000ULL) ? (now_ns - boot_time_ns) : now_ns;
    uint64_t norm_start = (s->active_start > 1700000000000000000ULL) ? (s->active_start - boot_time_ns) : s->active_start;
    double ts_val = (double)(norm_now + boot_time_ns) / 1e9, duration = (norm_now > norm_start) ? (double)(norm_now - norm_start) / 1e9 : 0.001;

    /* Part 1: IP & Base Flow (Fast) */
    fast_ip_to_str(buf, &off, s->ip_ver, s->key.src_ip); buf[off++] = '-';
    fast_ip_to_str(buf, &off, s->ip_ver, s->key.dst_ip);
    off += sprintf(buf + off, "-%u-%u-%u,", ntohs(s->key.src_port), ntohs(s->key.dst_port), s->key.protocol);
    fast_ip_to_str(buf, &off, s->ip_ver, s->key.src_ip); buf[off++] = ',';
    fast_ip_to_str(buf, &off, s->ip_ver, s->key.dst_ip);
    off += sprintf(buf + off, ",%u,%u,%u,%u,%u,%u,%02x:%02x:%02x:%02x:%02x:%02x,%02x:%02x:%02x:%02x:%02x:%02x,%.6f,%.6f,%lu,%lu,%lu,%lu,%lu,%lu,%.2f,%.2f,",
        ntohs(s->key.src_port), ntohs(s->key.dst_port), (uint32_t)s->key.protocol, (uint32_t)s->ip_ver, (uint32_t)ntohs(s->eth_proto), (uint32_t)s->traffic_class,
        s->src_mac[0], s->src_mac[1], s->src_mac[2], s->src_mac[3], s->src_mac[4], s->src_mac[5],
        s->dst_mac[0], s->dst_mac[1], s->dst_mac[2], s->dst_mac[3], s->dst_mac[4], s->dst_mac[5],
        ts_val, duration, s->t_pay.n, s->f_pay.n, s->b_pay.n, (uint64_t)(s->f_bytes + s->b_bytes), (uint64_t)s->f_bytes, (uint64_t)s->b_bytes,
        (s->b_pay.n > 0 ? (double)s->f_pay.n/s->b_pay.n : (double)s->f_pay.n), (s->b_bytes > 0 ? (double)s->f_bytes/s->b_bytes : (double)s->f_bytes));

    /* Part 2: Statistical Metrics (Heavy) */
    struct welford_stat *st[] = {&s->t_pay,&s->f_pay,&s->b_pay,&s->t_hdr,&s->f_hdr,&s->b_hdr,&s->t_iat,&s->f_iat,&s->b_iat,&s->t_delta,&s->f_delta,&s->b_delta,&s->win_s,&s->ip_id_s,&s->frag_s,&s->ttl_s};
    for (int i=0; i<16; i++) {
        double med = (i < 3) ? median_from_hist((i==0?s->t_hist:(i==1?s->f_hist:s->b_hist)), st[i]->n) : w_median(st[i]);
        off += snprintf(buf + off, MAX_RECORD - off, "%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,0.00,",
            (double)st[i]->max, (double)st[i]->min, w_mean(st[i]), w_std(st[i]), w_var(st[i]), med, w_skew(st[i]), w_kurt(st[i]), (w_mean(st[i])>0?w_std(st[i])/w_mean(st[i]):0));
    }

    /* Part 3: Rest of Features */
    off += sprintf(buf + off, "%u,%u,", s->f_win_init, s->b_win_init);
    for (int i=0; i<8; i++) off += sprintf(buf + off, "%lu,%lu,%lu,", s->flags[i], s->f_flags[i], s->b_flags[i]);
    off += snprintf(buf + off, MAX_RECORD - off, "%.2f,%u,%u,%u,%u,", calculate_entropy(s->ip_ver == 4 ? &s->key.src_ip[12] : s->key.src_ip, s->ip_ver == 4 ? 4 : 16),
        (uint32_t)s->last_icmp_type, (uint32_t)s->last_icmp_code, (uint32_t)s->last_ttl, (uint32_t)s->last_icmp_id);
    struct welford_stat *ext[] = {&s->active_s, &s->idle_s};
    for (int i=0; i<2; i++) off += snprintf(buf + off, MAX_RECORD - off, "%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,0.00,",
        (double)ext[i]->max, (double)ext[i]->min, w_mean(ext[i]), w_std(ext[i]), w_var(ext[i]), w_median(ext[i]), w_skew(ext[i]), w_kurt(ext[i]), (w_mean(ext[i])>0?w_std(ext[i])/w_mean(ext[i]):0));
    off += snprintf(buf + off, MAX_RECORD - off, "%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%lu,%lu,%lu,%lu,%lu,%lu,%u,%u,%u,%u,%u,%u,%u,%u,%u,",
        (duration > 0 ? (double)(s->f_bytes+s->b_bytes)/duration : 0), (duration > 0 ? (double)s->f_bytes/duration : 0), (duration > 0 ? (double)s->b_bytes/duration : 0),
        (duration > 0 ? (double)s->t_pay.n/duration : 0), (duration > 0 ? (double)s->f_pay.n/duration : 0), (duration > 0 ? (double)s->b_pay.n/duration : 0),
        (s->f_pay.n > 0 ? (double)s->b_pay.n/s->f_pay.n : 0), s->f_bulk_bytes, s->f_bulk_pkts, s->f_bulk_cnt, s->b_bulk_bytes, s->b_bulk_pkts, s->b_bulk_cnt,
        s->dns_answer_count, s->dns_qtype, s->dns_qclass, s->tunnel_id, s->tunnel_type, s->ntp_mode, s->ntp_stratum, s->snmp_pdu_type, s->ssdp_method);
    for (int i=0; i<HIST_BINS; i++) off += sprintf(buf + off, "%lu,", s->t_hist[i]);
    for (int i=0; i<HIST_BINS; i++) off += sprintf(buf + off, "%lu,", s->f_hist[i]);
    for (int i=0; i<HIST_BINS; i++) off += sprintf(buf + off, "%lu%s", s->b_hist[i], (i == HIST_BINS-1 ? "" : ","));
    buf[off++] = '\n'; q->lens[idx] = off; atomic_store_explicit(&q->tail, t + 1, memory_order_release);
}

static int handle_event(void *ctx, void *data, size_t data_sz) {
    (void)data_sz; struct worker_t *w = ctx; const packet_event_t *e = data;
    uint32_t h = 0; const uint8_t *p = (const uint8_t *)&e->key;
    for (size_t i = 0; i < sizeof(flow_id_t); i++) h = h * 31 + p[i];
    uint32_t idx = h % FLOW_HASH_SIZE, probes = 0;
    while (w->flow_table[idx].active && memcmp(&w->flow_table[idx].key, &e->key, sizeof(flow_id_t)) != 0) {
        idx = (idx + 1) % FLOW_HASH_SIZE; if (++probes > 4096) return 0;
    }
    struct flow_state *s = &w->flow_table[idx];
    if (!s->active) {
        memset(s, 0, sizeof(*s)); s->key = e->key; s->active = 1;
        s->active_start = e->rec.start_ts ? e->rec.start_ts : e->timestamp_ns;
        s->ip_ver = e->rec.ip_ver; s->eth_proto = e->rec.eth_proto;
        s->traffic_class = e->rec.traffic_class; s->flow_label = e->rec.flow_label;
        memcpy(s->src_mac, e->rec.src_mac, 6); memcpy(s->dst_mac, e->rec.dst_mac, 6);
        w_init(&s->t_pay); w_init(&s->f_pay); w_init(&s->b_pay);
        w_init(&s->t_hdr); w_init(&s->f_hdr); w_init(&s->b_hdr);
        w_init(&s->t_iat); w_init(&s->f_iat); w_init(&s->b_iat);
        w_init(&s->t_delta); w_init(&s->f_delta); w_init(&s->b_delta);
        w_init(&s->win_s); w_init(&s->ip_id_s); w_init(&s->frag_s); w_init(&s->ttl_s);
        w_init(&s->active_s); w_init(&s->idle_s); s->f_win_init = e->rec.window_size;
    }
    s->last_icmp_type = e->rec.icmp_type; s->last_icmp_code = e->rec.icmp_code; s->last_icmp_id = e->rec.icmp_id; s->last_ttl = e->rec.ttl;
    if (s->t_last > 0) {
        double iat = (double)(e->timestamp_ns - s->t_last) / 1e9; w_update(&s->t_iat, iat);
        if (iat > IDLE_THRESHOLD) { w_update(&s->active_s, (double)(s->t_last - s->active_start) / 1e9); w_update(&s->idle_s, iat); s->active_start = e->timestamp_ns; }
    }
    s->t_last = e->timestamp_ns;
    w_update(&s->t_pay, e->rec.payload_len); w_update(&s->t_hdr, e->rec.header_len); w_update(&s->win_s, e->rec.window_size);
    w_update(&s->ip_id_s, e->rec.ip_id); w_update(&s->frag_s, e->rec.frag_off); w_update(&s->ttl_s, e->rec.ttl);
    if (s->t_pay.n > 1) w_update(&s->t_delta, abs((int)e->rec.payload_len - (int)s->last_t_pay));
    s->last_t_pay = e->rec.payload_len; s->dns_answer_count = e->rec.dns_answer_count; s->dns_qtype = e->rec.dns_qtype; s->dns_qclass = e->rec.dns_qclass;
    s->tunnel_id = e->rec.tunnel_id; s->tunnel_type = e->rec.tunnel_type; s->ntp_mode = e->rec.ntp_mode; s->ntp_stratum = e->rec.ntp_stratum;
    s->snmp_pdu_type = e->rec.snmp_pdu_type; s->ssdp_method = e->rec.ssdp_method;
    uint32_t b_idx = e->rec.payload_len / HIST_STEP; if (b_idx >= HIST_BINS) b_idx = HIST_BINS - 1;
    s->t_hist[b_idx]++;
    if (e->rec.is_fwd) {
        if (s->f_last > 0) {
            double iat = (double)(e->timestamp_ns - s->f_last) / 1e9; w_update(&s->f_iat, iat);
            if (iat < BULK_THRESHOLD) { s->f_bulk_bytes += e->rec.payload_len; s->f_bulk_pkts++; }
            else { if (s->f_bulk_pkts >= 3) s->f_bulk_cnt++; s->f_bulk_bytes = e->rec.payload_len; s->f_bulk_pkts = 1; }
        }
        s->f_last = e->timestamp_ns; w_update(&s->f_pay, e->rec.payload_len); w_update(&s->f_hdr, e->rec.header_len);
        if (s->f_pay.n > 1) w_update(&s->f_delta, abs((int)e->rec.payload_len - (int)s->last_f_pay));
        s->last_f_pay = e->rec.payload_len; s->f_hist[b_idx]++; s->f_bytes += e->rec.payload_len;
        for (int i=0; i<8; i++) if (e->rec.tcp_flags & (1<<i)) { s->flags[i]++; s->f_flags[i]++; }
    } else {
        if (s->b_last > 0) {
            double iat = (double)(e->timestamp_ns - s->b_last) / 1e9; w_update(&s->b_iat, iat);
            if (iat < BULK_THRESHOLD) { s->b_bulk_bytes += e->rec.payload_len; s->b_bulk_pkts++; }
            else { if (s->b_bulk_pkts >= 3) s->b_bulk_cnt++; s->b_bulk_bytes = e->rec.payload_len; s->b_bulk_pkts = 1; }
        }
        s->b_last = e->timestamp_ns; w_update(&s->b_pay, e->rec.payload_len); w_update(&s->b_hdr, e->rec.header_len);
        if (s->b_pay.n > 1) w_update(&s->b_delta, abs((int)e->rec.payload_len - (int)s->last_b_pay));
        s->last_b_pay = e->rec.payload_len; s->b_hist[b_idx]++; s->b_bytes += e->rec.payload_len;
        for (int i=0; i<8; i++) if (e->rec.tcp_flags & (1<<i)) { s->flags[i]++; s->b_flags[i]++; }
    }
    if (s->t_pay.n >= 10000 || (e->rec.tcp_flags & 0x05)) { flush_flow_record(w, s, e->timestamp_ns); s->active = 0; }
    w->processed_events++; return 0;
}

void *worker_fn(void *arg) {
    struct worker_t *w = arg; cpu_set_t cpuset; CPU_ZERO(&cpuset); CPU_SET(w->id % 256, &cpuset);
    pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset);
    w->flow_table = calloc(FLOW_HASH_SIZE, sizeof(struct flow_state));
    w->rb = ring_buffer__new(w->rb_fd, handle_event, w, NULL);
    const uint64_t timeout_ns = (uint64_t)(IDLE_FLOW_TIMEOUT_S * 1e9);
    while (!exiting) {
        ring_buffer__poll(w->rb, 100);
        struct timespec ts_idle; clock_gettime(CLOCK_REALTIME, &ts_idle);
        uint64_t now_idle = (uint64_t)ts_idle.tv_sec * 1000000000ULL + ts_idle.tv_nsec;
        for (int k = 0; k < IDLE_SCAN_BATCH; k++) {
            uint32_t idx = w->scan_ptr; w->scan_ptr = (w->scan_ptr + 1) % FLOW_HASH_SIZE;
            struct flow_state *fs = &w->flow_table[idx];
            if (fs->active && fs->t_last > 0 && (now_idle - fs->t_last) > timeout_ns) { flush_flow_record(w, fs, now_idle); fs->active = 0; }
        }
    }
    struct timespec ts_now; clock_gettime(CLOCK_REALTIME, &ts_now);
    uint64_t now_ns = (uint64_t)ts_now.tv_sec * 1000000000ULL + ts_now.tv_nsec;
    for (int i = 0; i < FLOW_HASH_SIZE; i++) flush_flow_record(w, &w->flow_table[i], now_ns);
    free(w->flow_table); ring_buffer__free(w->rb); return NULL;
}

static void detach_xdp_links_on_iface(int ifindex) {
    __u32 id = 0, next_id;
    while (bpf_link_get_next_id(id, &next_id) == 0) {
        id = next_id; int lfd = bpf_link_get_fd_by_id(id); if (lfd < 0) continue;
        struct bpf_link_info info = {}; __u32 info_len = sizeof(info);
        if (bpf_obj_get_info_by_fd(lfd, &info, &info_len) == 0) {
            if (info.type == BPF_LINK_TYPE_XDP && (int)info.xdp.ifindex == ifindex) bpf_link_detach(lfd);
        }
        close(lfd);
    }
}

int main(int argc, char **argv) {
    init_boot_time(); if (argc < 2) return 1;
    struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY}; setrlimit(RLIMIT_MEMLOCK, &r);
    signal(SIGINT, sig_handler); signal(SIGTERM, sig_handler);
    mkdir("worker_telemetry", 0777);
    int cores = sysconf(_SC_NPROCESSORS_ONLN); num_workers = cores;
    workers = calloc(num_workers, sizeof(struct worker_t));
    struct bpf_object *obj = bpf_object__open_file("build/main.bpf.o", NULL);
    if (!obj || bpf_object__load(obj)) { fprintf(stderr, "FATAL: BPF load failed\n"); return 1; }
    int outer_fd = bpf_object__find_map_fd_by_name(obj, "pkt_ringbuf_map");
    for (int i = 0; i < num_workers; i++) {
        workers[i].id = i;
        workers[i].rb_fd = bpf_map_create(BPF_MAP_TYPE_RINGBUF, NULL, 0, 0, 32 * 1024 * 1024, NULL);
        bpf_map_update_elem(outer_fd, &i, &workers[i].rb_fd, BPF_ANY);
    }
    g_out_f = stdout; setvbuf(g_out_f, NULL, _IOFBF, 4 * 1024 * 1024);
    fprintf(g_out_f, "flow_id,src_ip,dst_ip,src_port,dst_port,protocol,ip_ver,eth_proto,traffic_class,flow_label,src_mac,dst_mac,timestamp,duration,"
                     "PacketsCount,FwdPacketsCount,BwdPacketsCount,TotalBytes,FwdBytes,BwdBytes,FwdBwdPktRatio,FwdBwdByteRatio,");
    const char *metrics[] = {"Tot_Pay","Fwd_Pay","Bwd_Pay","Tot_Hdr","Fwd_Hdr","Bwd_Hdr","Tot_IAT","Fwd_IAT","Bwd_IAT","Tot_DeltaLen","Fwd_DeltaLen","Bwd_DeltaLen","Win","IpId","Frag","TTL_Var"};
    for (int i=0; i<16; i++) fprintf(g_out_f, "%s_Max,%s_Min,%s_Mean,%s_Std,%s_Var,%s_Median,%s_Skew,%s_Kurt,%s_CoV,%s_Mode,", metrics[i],metrics[i],metrics[i],metrics[i],metrics[i],metrics[i],metrics[i],metrics[i],metrics[i],metrics[i]);
    fprintf(g_out_f, "FwdInitWinBytes,BwdInitWinBytes,");
    const char *flags[] = {"FIN","SYN","RST","PSH","ACK","URG","ECE","CWR"};
    for (int i=0; i<8; i++) fprintf(g_out_f, "%s_Cnt,%s_Fwd_Cnt,%s_Bwd_Cnt,", flags[i],flags[i],flags[i]);
    fprintf(g_out_f, "PayloadEntropy,IcmpType,IcmpCode,TTL,IcmpEchoId,");
    const char *ext[] = {"Active","Idle"};
    for (int i=0; i<2; i++) fprintf(g_out_f, "%s_Max,%s_Min,%s_Mean,%s_Std,%s_Var,%s_Median,%s_Skew,%s_Kurt,%s_CoV,%s_Mode,", ext[i],ext[i],ext[i],ext[i],ext[i],ext[i],ext[i],ext[i],ext[i],ext[i]);
    fprintf(g_out_f, "BytesRate,FwdBytesRate,BwdBytesRate,PacketsRate,FwdPacketsRate,BwdPacketsRate,DownUpRatio,FwdBulkBytes,FwdBulkPkts,FwdBulkCnt,BwdBulkBytes,BwdBulkPkts,BwdBulkCnt,DNSAnswerCount,DNSQueryType,DNSQueryClass,TunnelId,TunnelType,NTP_Mode,NTP_Stratum,SNMP_PDU_Type,SSDP_Method,");
    for (int i=0; i<HIST_BINS; i++) fprintf(g_out_f, "Hist_Tot_%d,", i);
    for (int i=0; i<HIST_BINS; i++) fprintf(g_out_f, "Hist_Fwd_%d,", i);
    for (int i=0; i<HIST_BINS; i++) fprintf(g_out_f, "Hist_Bwd_%d%s", i, (i == HIST_BINS-1 ? "" : ","));
    fprintf(g_out_f, "\n"); fflush(g_out_f);
    g_queues = calloc(num_workers, sizeof(struct spsc_queue));
    pthread_create(&g_writer_thread, NULL, writer_fn, NULL);
    for (int i = 0; i < num_workers; i++) pthread_create(&workers[i].thread, NULL, worker_fn, &workers[i]);
    struct bpf_program *prog = bpf_object__find_program_by_name(obj, "xdp_prog");
    int prog_fd = bpf_program__fd(prog);
    int *ifindexes = calloc(argc - 1, sizeof(int)); int num_ifaces = 0;
    for (int i = 1; i < argc; i++) {
        int ifindex = if_nametoindex(argv[i]); if (ifindex == 0) continue;
        detach_xdp_links_on_iface(ifindex);
        bpf_xdp_detach(ifindex, XDP_FLAGS_DRV_MODE, NULL); bpf_xdp_detach(ifindex, XDP_FLAGS_SKB_MODE, NULL);
        int flags = XDP_FLAGS_DRV_MODE;
        if (bpf_xdp_attach(ifindex, prog_fd, flags, NULL) < 0) {
            flags = XDP_FLAGS_SKB_MODE;
            if (bpf_xdp_attach(ifindex, prog_fd, flags, NULL) < 0) {
                fprintf(stderr, "ERR: Failed to attach XDP on %d\n", ifindex);
            } else {
                printf("[*] XDP attached on ifindex %d (SKB_MODE - Fallback)\n", ifindex);
            }
        } else {
            printf("[*] XDP attached on ifindex %d (DRV_MODE - Native)\n", ifindex);
        }
        ifindexes[num_ifaces++] = ifindex;
    }
    for (int i = 0; i < num_workers; i++) pthread_join(workers[i].thread, NULL);
    pthread_join(g_writer_thread, NULL);
    for (int i = 0; i < num_ifaces; i++) bpf_xdp_detach(ifindexes[i], XDP_FLAGS_SKB_MODE, NULL);
    fflush(g_out_f); free(ifindexes); bpf_object__close(obj); return 0;
}
