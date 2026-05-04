/**
 * @file loader.c
 * @brief User-Space Control Plane - General Purpose Network Feature Extractor.
 *
 * @details
 * High-performance extraction engine for MAPE-K (Monitor) loops.
 * Features: Welford Moments, P² Medians, L7 Metadata, and Payload Histograms.
 * Built for high-fidelity network introspection and autonomous security.
 *
 * @version 1.0
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
#define HIST_STEP           20
#define BULK_THRESHOLD      1.0
#define IDLE_FLOW_TIMEOUT_S 5.0
#define IDLE_SCAN_BATCH     10000

/* [Lock-Free Concurrency] Single-Producer Single-Consumer (SPSC) Rings */
#define SPSC_SLOTS    1024     /* per-worker queue depth (power of 2) */
#define MAX_RECORD    16384    /* max serialized record size (incl. histograms) */

struct spsc_queue {
    char     data[SPSC_SLOTS][MAX_RECORD];
    size_t   lens[SPSC_SLOTS];
    _Atomic uint32_t head;  /* writer advances head (consumer) */
    _Atomic uint32_t tail;  /* worker advances tail (producer)  */
} __attribute__((aligned(64))); /* cache-line align to prevent false sharing */

/* [Core Analytics] Numerical Moment Tracking & P² Quantiles */

struct welford_stat {
    uint64_t n; double M1, M2, M3, M4; uint32_t max, min;
    /* P² online median estimator (Jain & Chlamtac 1985).
     * 5 markers: q0=min q1=p25 q2=median q3=p75 q4=max.
     * Memory: 5×double + 5×int = 60 bytes per suite. */
    double pq[5]; /* marker heights */
    int    pn[5]; /* marker positions */
};

static void w_init(struct welford_stat *w) {
    memset(w, 0, sizeof(*w));
    w->min = 0xFFFFFFFF;
    /* P²: initial marker positions 1..5 */
    w->pn[0]=1; w->pn[1]=2; w->pn[2]=3; w->pn[3]=4; w->pn[4]=5;
}
static inline void w_update(struct welford_stat *w, double x) {
    /* Online Welford Algorithm: Higher-Order Statistical Moments (Kurtosis/Skewness) */
    uint64_t n1 = w->n; w->n++;
    double delta = x - w->M1, delta_n = delta / w->n, delta_n2 = delta_n * delta_n, term1 = delta * delta_n * n1;
    w->M1 += delta_n;
    w->M4 += term1 * delta_n2 * (w->n * w->n - 3 * w->n + 3) + 6 * delta_n2 * w->M2 - 4 * delta_n * w->M3;
    w->M3 += term1 * delta_n * (w->n - 2) - 3 * delta_n * w->M2;
    w->M2 += term1;
    if (x > w->max) w->max = (uint32_t)x; if (x < w->min) w->min = (uint32_t)x;
    /* P² (Piecewise-Parabolic) Online Quantile Estimation (Jain & Chlamtac) */
    uint64_t cnt = w->n; /* already incremented */
    if (cnt <= 5) {
        w->pq[cnt-1] = x;
        if (cnt == 5) { /* insertion-sort first 5 observations */
            for (int i=1; i<5; i++) {
                double tmp=w->pq[i]; int j=i-1;
                while (j>=0 && w->pq[j]>tmp) { w->pq[j+1]=w->pq[j]; j--; }
                w->pq[j+1]=tmp;
            }
        }
        return;
    }
    /* find cell k such that pq[k] <= x < pq[k+1] */
    int k;
    if      (x < w->pq[0]) { w->pq[0]=x; k=0; }
    else if (x < w->pq[1]) { k=0; }
    else if (x < w->pq[2]) { k=1; }
    else if (x < w->pq[3]) { k=2; }
    else if (x <=w->pq[4]) { k=3; }
    else                   { w->pq[4]=x; k=3; }
    for (int i=k+1; i<5; i++) w->pn[i]++;
    /* desired positions for quartile markers */
    double np[5]; double fc=(double)cnt;
    np[0]=1.0; np[1]=1.0+fc/4.0; np[2]=1.0+fc/2.0; np[3]=1.0+3.0*fc/4.0; np[4]=fc;
    /* adjust middle markers */
    for (int i=1; i<=3; i++) {
        double d = np[i] - w->pn[i];
        if ((d>=1.0 && w->pn[i+1]-w->pn[i]>1)||(d<=-1.0 && w->pn[i-1]-w->pn[i]<-1)) {
            int s = (d>=0.0)?1:-1;
            double denom1=(double)(w->pn[i+1]-w->pn[i-1]);
            double q_par = w->pq[i] + (double)s/denom1 *
                (((double)(w->pn[i]-w->pn[i-1]+s))*(w->pq[i+1]-w->pq[i])/(double)(w->pn[i+1]-w->pn[i]) +
                 ((double)(w->pn[i+1]-w->pn[i]-s))*(w->pq[i]-w->pq[i-1])/(double)(w->pn[i]-w->pn[i-1]));
            if (w->pq[i-1] < q_par && q_par < w->pq[i+1])
                w->pq[i] = q_par;
            else
                w->pq[i] += (double)s*(w->pq[i+s]-w->pq[i])/(double)(w->pn[i+s]-w->pn[i]);
            w->pn[i] += s;
        }
    }
}

static inline double w_mean(struct welford_stat *w) { return w->M1; }
static inline double w_std(struct welford_stat *w)  { return (w->n > 1) ? sqrt(w->M2 / (w->n - 1)) : 0; }
static inline double w_var(struct welford_stat *w)  { return (w->n > 1) ? w->M2 / (w->n - 1) : 0; }
static inline double w_skew(struct welford_stat *w) { return (w->M2 > 1e-9) ? sqrt(w->n) * w->M3 / pow(w->M2, 1.5) : 0; }
static inline double w_kurt(struct welford_stat *w) { return (w->M2 > 1e-9) ? (double)w->n * w->M4 / (w->M2 * w->M2) - 3.0 : 0; }
static inline double w_p2_median(struct welford_stat *w) {
    if (w->n == 0) return 0.0;
    if (w->n < 5) { /* sort partial buffer and return middle element */
        double tmp[5]; int k=(int)w->n;
        for(int i=0;i<k;i++) tmp[i]=w->pq[i];
        for(int i=1;i<k;i++){double t=tmp[i];int j=i-1;while(j>=0&&tmp[j]>t){tmp[j+1]=tmp[j];j--;}tmp[j+1]=t;}
        return tmp[k/2];
    }
    return w->pq[2]; /* P² median marker */
}

static uint64_t boot_time_ns = 0;
static void init_boot_time() {
    struct timespec ts, tk;
    clock_gettime(CLOCK_REALTIME, &ts);
    clock_gettime(CLOCK_MONOTONIC, &tk);
    boot_time_ns = (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec - 
                   ((uint64_t)tk.tv_sec * 1000000000ULL + tk.tv_nsec);
}

struct flow_state {
    flow_id_t key;
    uint8_t ip_ver; uint16_t eth_proto;
    uint8_t traffic_class; uint32_t flow_label;
    uint8_t src_mac[6]; uint8_t dst_mac[6];
    struct welford_stat t_pay, f_pay, b_pay, t_hdr, f_hdr, b_hdr, t_iat, f_iat, b_iat, t_delta, f_delta, b_delta, active_s, idle_s, win_s, ip_id_s, frag_s, ttl_s;
    uint64_t t_hist[HIST_BINS], f_hist[HIST_BINS], b_hist[HIST_BINS];
    uint64_t f_bytes, b_bytes, f_last, b_last, t_last;
    uint16_t f_win_init, b_win_init;
    uint64_t flags[8], f_flags[8], b_flags[8];
    uint64_t f_bulk_bytes, b_bulk_bytes, f_bulk_pkts, b_bulk_pkts, f_bulk_cnt, b_bulk_cnt;
    uint64_t active_start;
    uint32_t last_f_pay, last_b_pay, last_t_pay;
    uint8_t last_icmp_type; uint8_t last_icmp_code; uint8_t last_ttl;
    uint16_t last_icmp_id;   
    uint16_t dns_answer_count;
    uint16_t dns_qtype;      
    uint16_t dns_qclass;     
    uint32_t tunnel_id;      /* VXLAN VNI / GRE Key */
    uint8_t tunnel_type;     /* 0: None, 1: GRE, 2: VXLAN */
    uint8_t ntp_mode; uint8_t ntp_stratum;
    uint8_t snmp_pdu_type; uint8_t ssdp_method;
    int active;
};

struct worker_t {
    pthread_t thread; int rb_fd; struct ring_buffer *rb;
    struct flow_state *flow_table;
    int id; uint64_t processed_events;
    uint32_t scan_ptr; /* rolling index for idle-timeout scan */
};

static struct worker_t *workers;
static int num_workers = 1;
static volatile bool exiting = false;
static void sig_handler(int sig) { (void)sig; exiting = true; }

/* [Agnostic Data Export] Unified Lock-Free Pipe (v2.0 SHM Ready) */
static FILE            *g_out_f  = NULL;
static struct spsc_queue *g_queues = NULL;   /* one per worker */
static pthread_t        g_writer_thread;

static void *writer_fn(void *arg) {
    (void)arg;
    bool flushed;
    do {
        flushed = false;
        for (int i = 0; i < num_workers; i++) {
            struct spsc_queue *q = &g_queues[i];
            uint32_t h = atomic_load_explicit(&q->head, memory_order_relaxed);
            uint32_t t = atomic_load_explicit(&q->tail, memory_order_acquire);
            while (h != t) {
                uint32_t idx = h & (SPSC_SLOTS - 1);
                fwrite(q->data[idx], 1, q->lens[idx], g_out_f);
                h++;
                flushed = true;
                atomic_store_explicit(&q->head, h, memory_order_release);
            }
        }
        if (!flushed && !exiting) {
            struct timespec ts = {0, 1000000}; /* 1ms sleep to save CPU if idle */
            nanosleep(&ts, NULL);
        }
    } while (!exiting || flushed);
    /* Final drain */
    for (int i = 0; i < num_workers; i++) {
        struct spsc_queue *q = &g_queues[i];
        uint32_t h = atomic_load_explicit(&q->head, memory_order_relaxed);
        uint32_t t = atomic_load_explicit(&q->tail, memory_order_acquire);
        while (h != t) {
            uint32_t idx = h & (SPSC_SLOTS - 1);
            fwrite(q->data[idx], 1, q->lens[idx], g_out_f);
            h++;
            atomic_store_explicit(&q->head, h, memory_order_release);
        }
    }
    fflush(g_out_f);
    return NULL;
}

static double calculate_entropy(const uint8_t *data, size_t len) {
    if (len == 0) return 0;
    uint64_t counts[256] = {0};
    for (size_t i = 0; i < len; i++) counts[data[i]]++;
    double ent = 0;
    for (int i = 0; i < 256; i++) {
        if (counts[i] > 0) {
            double p = (double)counts[i] / len;
            ent -= p * log2(p);
        }
    }
    return ent;
}

/* Numerical Estimation: Histogram-based Median via Linear Interpolation */
static double median_from_hist(const uint64_t *hist, int bins, int step, uint64_t n) {
    if (n == 0) return 0.0;
    uint64_t half = (n + 1) / 2, acc = 0;
    for (int i = 0; i < bins; i++) {
        if (hist[i] == 0) continue;
        uint64_t prev = acc;
        acc += hist[i];
        if (acc >= half)
            return (double)(i * step) + (double)step * (double)(half - prev) / (double)hist[i];
    }
    return (double)((bins - 1) * step);
}

/* Forward declaration */
struct worker_t;
static void flush_flow_record(struct worker_t *w, struct flow_state *s, uint64_t now_ns);

/* Emit one Welford suite (10 stats). Median/Mode hardcoded to 0.00 — legacy fallback. */
#define FMT_W_EXACT(w_ptr, fp) fprintf((fp), "%.2f,%.2f,%.2f,%.2f,%.2f,0.00,%.2f,%.2f,%.2f,0.00,", \
    (double)(w_ptr).max, (double)(w_ptr).min, w_mean(&(w_ptr)), w_std(&(w_ptr)), w_var(&(w_ptr)), \
    w_skew(&(w_ptr)), w_kurt(&(w_ptr)), (w_mean(&(w_ptr))>0?w_std(&(w_ptr))/w_mean(&(w_ptr)):0))

/* Payload suites: median from histogram (higher resolution than P² for bounded distributions). */
#define FMT_W_MED(w_ptr, med, fp) fprintf((fp), "%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,0.00,", \
    (double)(w_ptr).max, (double)(w_ptr).min, w_mean(&(w_ptr)), w_std(&(w_ptr)), w_var(&(w_ptr)), \
    (double)(med), w_skew(&(w_ptr)), w_kurt(&(w_ptr)), (w_mean(&(w_ptr))>0?w_std(&(w_ptr))/w_mean(&(w_ptr)):0))

/* P² (Piecewise-Parabolic) Suite: Quartile and Moment Convergence Tracking */
#define FMT_W_P2(w_ptr, fp) fprintf((fp), "%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,0.00,", \
    (double)(w_ptr).max, (double)(w_ptr).min, w_mean(&(w_ptr)), w_std(&(w_ptr)), w_var(&(w_ptr)), \
    w_p2_median(&(w_ptr)), w_skew(&(w_ptr)), w_kurt(&(w_ptr)), (w_mean(&(w_ptr))>0?w_std(&(w_ptr))/w_mean(&(w_ptr)):0))

static int handle_event(void *ctx, void *data, size_t data_sz) {
    (void)data_sz; struct worker_t *w = ctx; const packet_event_t *e = data;
    uint32_t h = 0; const uint8_t *p = (const uint8_t *)&e->key;
    for (size_t i = 0; i < sizeof(flow_id_t); i++) h = h * 31 + p[i];
    uint32_t idx = h % FLOW_HASH_SIZE, probes = 0;
    while (w->flow_table[idx].active && memcmp(&w->flow_table[idx].key, &e->key, sizeof(flow_id_t)) != 0) {
        idx = (idx + 1) % FLOW_HASH_SIZE;
        if (++probes > 4096) return 0;
    }

    struct flow_state *s = &w->flow_table[idx];
    if (!s->active) {
        memset(s, 0, sizeof(*s));
        s->key = e->key; s->active = 1;
        s->active_start = e->rec.start_ts ? e->rec.start_ts : e->timestamp_ns;
        s->ip_ver = e->rec.ip_ver; s->eth_proto = e->rec.eth_proto;
        s->traffic_class = e->rec.traffic_class; s->flow_label = e->rec.flow_label;
        memcpy(s->src_mac, e->rec.src_mac, 6); memcpy(s->dst_mac, e->rec.dst_mac, 6);
        w_init(&s->t_pay); w_init(&s->f_pay); w_init(&s->b_pay);
        w_init(&s->t_hdr); w_init(&s->f_hdr); w_init(&s->b_hdr);
        w_init(&s->t_iat); w_init(&s->f_iat); w_init(&s->b_iat);
        w_init(&s->t_delta); w_init(&s->f_delta); w_init(&s->b_delta);
        w_init(&s->win_s); w_init(&s->ip_id_s); w_init(&s->frag_s); w_init(&s->ttl_s);
        w_init(&s->active_s); w_init(&s->idle_s);
        s->f_win_init = e->rec.window_size;
    }
    s->last_icmp_type = e->rec.icmp_type; s->last_icmp_code = e->rec.icmp_code;
    s->last_icmp_id = e->rec.icmp_id; s->last_ttl = e->rec.ttl;


    if (s->t_last > 0) {
        double iat = (double)(e->timestamp_ns - s->t_last) / 1e9;
        w_update(&s->t_iat, iat);
        if (iat > IDLE_THRESHOLD) {
            w_update(&s->active_s, (double)(s->t_last - s->active_start) / 1e9);
            w_update(&s->idle_s, iat);
            s->active_start = e->timestamp_ns;
        }
    }
    s->t_last = e->timestamp_ns;
    w_update(&s->t_pay, e->rec.payload_len); w_update(&s->t_hdr, e->rec.header_len); w_update(&s->win_s, e->rec.window_size);
    w_update(&s->ip_id_s, e->rec.ip_id); w_update(&s->frag_s, e->rec.frag_off); w_update(&s->ttl_s, e->rec.ttl);
    if (s->t_pay.n > 1) w_update(&s->t_delta, abs((int)e->rec.payload_len - (int)s->last_t_pay));
    s->last_t_pay = e->rec.payload_len;

    /* L7 Metadata Update (Agnostic) */
    s->dns_answer_count = e->rec.dns_answer_count;
    s->dns_qtype = e->rec.dns_qtype;
    s->dns_qclass = e->rec.dns_qclass;
    s->tunnel_id = e->rec.tunnel_id;
    s->tunnel_type = e->rec.tunnel_type;
    s->ntp_mode = e->rec.ntp_mode;
    s->ntp_stratum = e->rec.ntp_stratum;
    s->snmp_pdu_type = e->rec.snmp_pdu_type;
    s->ssdp_method = e->rec.ssdp_method;

    uint32_t b_idx = e->rec.payload_len / HIST_STEP;
    if (b_idx >= HIST_BINS) b_idx = HIST_BINS - 1;
    s->t_hist[b_idx]++;

    if (e->rec.is_fwd) {
        if (s->f_last > 0) {
            double iat = (double)(e->timestamp_ns - s->f_last) / 1e9;
            w_update(&s->f_iat, iat);
            if (iat < BULK_THRESHOLD) { s->f_bulk_bytes += e->rec.payload_len; s->f_bulk_pkts++; }
            else { if (s->f_bulk_pkts >= 3) s->f_bulk_cnt++; s->f_bulk_bytes = e->rec.payload_len; s->f_bulk_pkts = 1; }
        }
        s->f_last = e->timestamp_ns; w_update(&s->f_pay, e->rec.payload_len); w_update(&s->f_hdr, e->rec.header_len);
        if (s->f_pay.n > 1) w_update(&s->f_delta, abs((int)e->rec.payload_len - (int)s->last_f_pay));
        s->last_f_pay = e->rec.payload_len; s->f_hist[b_idx]++;
        s->f_bytes += e->rec.payload_len;
        for (int i=0; i<8; i++) if (e->rec.tcp_flags & (1<<i)) { s->flags[i]++; s->f_flags[i]++; }
    } else {
        if (s->b_last > 0) {
            double iat = (double)(e->timestamp_ns - s->b_last) / 1e9;
            w_update(&s->b_iat, iat);
            if (iat < BULK_THRESHOLD) { s->b_bulk_bytes += e->rec.payload_len; s->b_bulk_pkts++; }
            else { if (s->b_bulk_pkts >= 3) s->b_bulk_cnt++; s->b_bulk_bytes = e->rec.payload_len; s->b_bulk_pkts = 1; }
        }
        s->b_last = e->timestamp_ns; w_update(&s->b_pay, e->rec.payload_len); w_update(&s->b_hdr, e->rec.header_len);
        if (s->b_pay.n > 1) w_update(&s->b_delta, abs((int)e->rec.payload_len - (int)s->last_b_pay));
        s->last_b_pay = e->rec.payload_len; s->b_hist[b_idx]++;
        s->b_bytes += e->rec.payload_len;
        for (int i=0; i<8; i++) if (e->rec.tcp_flags & (1<<i)) { s->flags[i]++; s->b_flags[i]++; }
    }

    /* Instant Flush for high-volume flows or TCP completion */
    /* ENHANCED: Threshold set to 10000 to balance string-formatting overhead and temporal resolution. */
    if (s->t_pay.n >= 10000 || (e->rec.tcp_flags & 0x05)) {
        flush_flow_record(w, s, e->timestamp_ns);
        s->active = 0; /* Reset state after flush */
    }
    w->processed_events++;
    return 0;
}

static void flush_flow_record(struct worker_t *w, struct flow_state *s, uint64_t now_ns) {
    if (!s->active || s->t_pay.n == 0) return;

    /* SPSC Slot Allocation (Lock-free) */
    struct spsc_queue *q = &g_queues[w->id];
    uint32_t t = atomic_load_explicit(&q->tail, memory_order_relaxed);
    uint32_t h = atomic_load_explicit(&q->head, memory_order_acquire);
    if ((t - h) >= SPSC_SLOTS) return; /* Queue full (backpressure) */
    uint32_t idx = t & (SPSC_SLOTS - 1);
    
    /* Serialization into memory buffer using direct pointer arithmetic for max PPS */
    char *buf = (char *)q->data[idx];
    int off = 0;

    uint64_t norm_now = (now_ns > 1700000000000000000ULL) ? (now_ns - boot_time_ns) : now_ns;
    uint64_t norm_start = (s->active_start > 1700000000000000000ULL) ? (s->active_start - boot_time_ns) : s->active_start;
    double ts = (double)(norm_now + boot_time_ns) / 1e9;
    double duration = (norm_now > norm_start) ? (double)(norm_now - norm_start) / 1e9 : 0.001;
    char sip[64], dip[64];
    if (s->ip_ver == 4) { inet_ntop(AF_INET, &s->key.src_ip[12], sip, 64); inet_ntop(AF_INET, &s->key.dst_ip[12], dip, 64); }
    else { inet_ntop(AF_INET6, s->key.src_ip, sip, 64); inet_ntop(AF_INET6, s->key.dst_ip, dip, 64); }
    char smac[20], dmac[20];
    sprintf(smac, "%02x:%02x:%02x:%02x:%02x:%02x", s->src_mac[0], s->src_mac[1], s->src_mac[2], s->src_mac[3], s->src_mac[4], s->src_mac[5]);
    sprintf(dmac, "%02x:%02x:%02x:%02x:%02x:%02x", s->dst_mac[0], s->dst_mac[1], s->dst_mac[2], s->dst_mac[3], s->dst_mac[4], s->dst_mac[5]);

    off += snprintf(buf + off, MAX_RECORD - off, "%s-%s-%u-%u-%u,%s,%s,%u,%u,%u,%u,%u,%u,%u,%s,%s,%.6f,%.6f,%lu,%lu,%lu,%lu,%lu,%lu,%.2f,%.2f,",
            sip, dip, ntohs(s->key.src_port), ntohs(s->key.dst_port), s->key.protocol,
            sip, dip, ntohs(s->key.src_port), ntohs(s->key.dst_port), s->key.protocol,
            s->ip_ver, ntohs(s->eth_proto), s->traffic_class, s->flow_label, smac, dmac, ts, duration,
            s->t_pay.n, s->f_pay.n, s->b_pay.n, s->f_bytes + s->b_bytes, s->f_bytes, s->b_bytes,
            (s->b_pay.n > 0 ? (double)s->f_pay.n/s->b_pay.n : (double)s->f_pay.n),
            (s->b_bytes > 0 ? (double)s->f_bytes/s->b_bytes : (double)s->f_bytes));

    off += snprintf(buf + off, MAX_RECORD - off, "%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%u,%u,",
            median_from_hist(s->t_hist, HIST_BINS, HIST_STEP, s->t_pay.n), median_from_hist(s->f_hist, HIST_BINS, HIST_STEP, s->f_pay.n), median_from_hist(s->b_hist, HIST_BINS, HIST_STEP, s->b_pay.n),
            s->t_hdr.m1, s->t_hdr.m2, s->f_hdr.m1, s->f_hdr.m2, s->b_hdr.m1, s->b_hdr.m2,
            s->t_iat.m1, s->t_iat.m2, s->f_iat.m1, s->f_iat.m2, s->b_iat.m1, s->b_iat.m2,
            s->t_delta.m1, s->t_delta.m2, s->f_delta.m1, s->f_delta.m2, s->b_delta.m1, s->b_delta.m2,
            s->win_s.m1, s->win_s.m2, s->ip_id_s.m1, s->ip_id_s.m2, s->frag_s.m1, s->frag_s.m2, s->ttl_s.m1, s->ttl_s.m2,
            s->f_win_init, s->b_win_init);

    for (int i=0; i<8; i++) off += snprintf(buf + off, MAX_RECORD - off, "%lu,%lu,%lu,", s->flags[i], s->f_flags[i], s->b_flags[i]);
    off += snprintf(buf + off, MAX_RECORD - off, "0.00,%u,%u,%u,%u,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,",
            s->last_icmp_type, s->last_icmp_code, s->last_ttl, s->last_icmp_id,
            s->active_s.m1, s->active_s.m2, s->idle_s.m1, s->idle_s.m2,
            (duration > 0 ? (s->f_bytes+s->b_bytes)/duration : 0), (duration > 0 ? s->f_bytes/duration : 0), (duration > 0 ? s->b_bytes/duration : 0),
            (duration > 0 ? s->t_pay.n/duration : 0), (duration > 0 ? s->f_pay.n/duration : 0), (duration > 0 ? s->b_pay.n/duration : 0),
            (s->f_pay.n > 0 ? (double)s->b_pay.n/s->f_pay.n : 0),
            s->f_bulk_bytes, s->f_bulk_pkts, s->f_bulk_cnt, s->b_bulk_bytes, s->b_bulk_pkts, s->b_bulk_cnt);

    off += snprintf(buf + off, MAX_RECORD - off, "%u,%u,%u,%u,%u,%u,%u,%u,%u,",
            s->dns_answer_count, s->dns_qtype, s->dns_qclass, s->tunnel_id, s->tunnel_type, s->ntp_mode, s->ntp_stratum,
            s->snmp_pdu_type, s->ssdp_method);

    for (int i=0; i<HIST_BINS; i++) off += snprintf(buf + off, MAX_RECORD - off, "%lu,", s->t_hist[i]);
    for (int i=0; i<HIST_BINS; i++) off += snprintf(buf + off, MAX_RECORD - off, "%lu,", s->f_hist[i]);
    for (int i=0; i<HIST_BINS; i++) off += snprintf(buf + off, MAX_RECORD - off, "%lu%s", s->b_hist[i], (i == HIST_BINS - 1 ? "" : ","));
    off += snprintf(buf + off, MAX_RECORD - off, "\n");
    
    q->lens[idx] = off;
    atomic_store_explicit(&q->tail, t + 1, memory_order_release);
}

void *worker_fn(void *arg) {
    struct worker_t *w = arg; cpu_set_t cpuset; CPU_ZERO(&cpuset); CPU_SET(w->id % 256, &cpuset);
    pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset);
    /* CSV Header is written once by main() into g_out_f before threads start */

    w->flow_table = calloc(FLOW_HASH_SIZE, sizeof(struct flow_state));
    w->rb = ring_buffer__new(w->rb_fd, handle_event, w, NULL);

    /* [Main Execution Loop] Async RingBuffer Polling + Amortized Idle Flow Sweeping */
    const uint64_t timeout_ns = (uint64_t)(IDLE_FLOW_TIMEOUT_S * 1e9);
    while (!exiting) {
        ring_buffer__poll(w->rb, 100);
        /* Amortised idle scan: IDLE_SCAN_BATCH entries per poll cycle.
         * At 100ms poll + 10k batch, full 1M table covered in ~10s.     */
        struct timespec ts_idle; clock_gettime(CLOCK_REALTIME, &ts_idle);
        uint64_t now_idle = (uint64_t)ts_idle.tv_sec * 1000000000ULL + ts_idle.tv_nsec;
        for (int k = 0; k < IDLE_SCAN_BATCH; k++) {
            uint32_t idx = w->scan_ptr;
            w->scan_ptr = (w->scan_ptr + 1) % FLOW_HASH_SIZE;
            struct flow_state *fs = &w->flow_table[idx];
            if (fs->active && fs->t_last > 0 && (now_idle - fs->t_last) > timeout_ns) {
                flush_flow_record(w, fs, now_idle);
                fs->active = 0;
            }
        }
    }

    /* Terminal flush: dump all remaining active flows on SIGINT */
    struct timespec ts_now; clock_gettime(CLOCK_REALTIME, &ts_now);
    uint64_t now_ns = (uint64_t)ts_now.tv_sec * 1000000000ULL + ts_now.tv_nsec;
    for (int i = 0; i < FLOW_HASH_SIZE; i++) flush_flow_record(w, &w->flow_table[i], now_ns);

    free(w->flow_table); ring_buffer__free(w->rb);
    return NULL;
}

/* Detach any BPF XDP *link objects* on an interface.
 * bpf_xdp_detach() only removes direct XDP attachments; XDP links (created
 * via bpf_xdp_link_create / ip link set xdp object ...) must be destroyed
 * through the link API. We iterate all system links, match by type+ifindex,
 * and call bpf_link_detach to release them before re-attaching. */
static void detach_xdp_links_on_iface(int ifindex) {
    __u32 id = 0, next_id;
    while (bpf_link_get_next_id(id, &next_id) == 0) {
        id = next_id;
        int lfd = bpf_link_get_fd_by_id(id);
        if (lfd < 0) continue;
        struct bpf_link_info info = {};
        __u32 info_len = sizeof(info);
        if (bpf_obj_get_info_by_fd(lfd, &info, &info_len) == 0) {
            if (info.type == BPF_LINK_TYPE_XDP &&
                (int)info.xdp.ifindex == ifindex) {
                int r = bpf_link_detach(lfd);
                fprintf(stderr, "[detach] XDP link id=%u on ifindex=%d: %s\n",
                        id, ifindex, r == 0 ? "OK" : strerror(errno));
            }
        }
        close(lfd);
    }
}

int main(int argc, char **argv) {
    init_boot_time();
    if (argc < 2) return 1;
    struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY}; setrlimit(RLIMIT_MEMLOCK, &r);
    signal(SIGINT, sig_handler); signal(SIGTERM, sig_handler);
    mkdir("worker_telemetry", 0777);
    int cores = sysconf(_SC_NPROCESSORS_ONLN); num_workers = cores;
    workers = calloc(num_workers, sizeof(struct worker_t));
    struct bpf_object *obj = bpf_object__open_file("build/main.bpf.o", NULL);
    if (!obj || bpf_object__load(obj)) { fprintf(stderr, "FATAL: BPF load failed\n"); return 1; }

    int outer_fd = bpf_object__find_map_fd_by_name(obj, "pkt_ringbuf_map");
    if (outer_fd < 0) { fprintf(stderr, "FATAL: pkt_ringbuf_map not found\n"); return 1; }

    for (int i = 0; i < num_workers; i++) {
        workers[i].id = i;
        /* BPF_F_INNER_MAP is NOT in RINGBUF_CREATE_FLAG_MASK on Linux >= 6.x
         * (kernel/bpf/ringbuf.c), causing bpf_map_create to return EINVAL.
         * The flag was needed on 5.10–5.14 where bpf_map_update_elem rejected
         * unlabeled inner maps; kernels >= 5.15 dropped that restriction and
         * accept any matching-type ringbuf FD in ARRAY_OF_MAPS without the flag. */
        workers[i].rb_fd = bpf_map_create(BPF_MAP_TYPE_RINGBUF, NULL, 0, 0, 32 * 1024 * 1024, NULL);
        if (workers[i].rb_fd < 0) { fprintf(stderr, "FATAL: ringbuf create failed for cpu %d: %s\n", i, strerror(errno)); return 1; }
        int ret = bpf_map_update_elem(outer_fd, &i, &workers[i].rb_fd, BPF_ANY);
        if (ret) fprintf(stderr, "FATAL: failed to register ringbuf for cpu %d: %s\n", i, strerror(errno));
    }

    /* CSV output to stdout for total decoupling and pipeline integration.
     * This prepares for v2.0 SHM/HugePages transition. */
    g_out_f = stdout;
    setvbuf(g_out_f, NULL, _IOFBF, 4 * 1024 * 1024); /* 4MB write buffer */
    fprintf(g_out_f, "flow_id,src_ip,dst_ip,src_port,dst_port,protocol,ip_ver,eth_proto,traffic_class,flow_label,src_mac,dst_mac,timestamp,duration,"
                     "PacketsCount,FwdPacketsCount,BwdPacketsCount,TotalBytes,FwdBytes,BwdBytes,FwdBwdPktRatio,FwdBwdByteRatio,");
    const char *metrics[] = {"Tot_Pay","Fwd_Pay","Bwd_Pay","Tot_Hdr","Fwd_Hdr","Bwd_Hdr",
                              "Tot_IAT","Fwd_IAT","Bwd_IAT","Tot_DeltaLen","Fwd_DeltaLen","Bwd_DeltaLen","Win",
                              "IpId","Frag","TTL_Var"};
    for (int i=0; i<16; i++)
        fprintf(g_out_f, "%s_Max,%s_Min,%s_Mean,%s_Std,%s_Var,%s_Median,%s_Skew,%s_Kurt,%s_CoV,%s_Mode,",
                metrics[i],metrics[i],metrics[i],metrics[i],metrics[i],
                metrics[i],metrics[i],metrics[i],metrics[i],metrics[i]);
    fprintf(g_out_f, "FwdInitWinBytes,BwdInitWinBytes,");
    const char *flags[] = {"FIN","SYN","RST","PSH","ACK","URG","ECE","CWR"};
    for (int i=0; i<8; i++) fprintf(g_out_f, "%s_Cnt,%s_Fwd_Cnt,%s_Bwd_Cnt,", flags[i],flags[i],flags[i]);
    fprintf(g_out_f, "PayloadEntropy,IcmpType,IcmpCode,TTL,IcmpEchoId,");
    const char *ext[] = {"Active","Idle"};
    for (int i=0; i<2; i++)
        fprintf(g_out_f, "%s_Max,%s_Min,%s_Mean,%s_Std,%s_Var,%s_Median,%s_Skew,%s_Kurt,%s_CoV,%s_Mode,",
                ext[i],ext[i],ext[i],ext[i],ext[i],ext[i],ext[i],ext[i],ext[i],ext[i]);
    fprintf(g_out_f, "BytesRate,FwdBytesRate,BwdBytesRate,PacketsRate,FwdPacketsRate,BwdPacketsRate,DownUpRatio,"
                     "FwdBulkBytes,FwdBulkPkts,FwdBulkCnt,BwdBulkBytes,BwdBulkPkts,BwdBulkCnt,"
                     "DNSAnswerCount,DNSQueryType,DNSQueryClass,"
                     "TunnelId,TunnelType,NTP_Mode,NTP_Stratum,SNMP_PDU_Type,SSDP_Method,");
    for (int i=0; i<HIST_BINS; i++) fprintf(g_out_f, "Hist_Tot_%d,", i);
    for (int i=0; i<HIST_BINS; i++) fprintf(g_out_f, "Hist_Fwd_%d,", i);
    for (int i=0; i<HIST_BINS; i++) fprintf(g_out_f, "Hist_Bwd_%d%s", i, (i == HIST_BINS-1 ? "" : ","));
    fprintf(g_out_f, "\n");
    fflush(g_out_f);

    g_queues = calloc(num_workers, sizeof(struct spsc_queue));
    if (!g_queues) { fprintf(stderr, "FATAL: cannot allocate queues\n"); return 1; }
    pthread_create(&g_writer_thread, NULL, writer_fn, NULL);

    for (int i = 0; i < num_workers; i++) pthread_create(&workers[i].thread, NULL, worker_fn, &workers[i]);



    struct bpf_program *prog = bpf_object__find_program_by_name(obj, "xdp_prog");
    int prog_fd = bpf_program__fd(prog);
    int *ifindexes = calloc(argc - 1, sizeof(int));
    int num_ifaces = 0;
    for (int i = 1; i < argc; i++) {
        int ifindex = if_nametoindex(argv[i]);
        if (ifindex == 0) { fprintf(stderr, "WARN: interface '%s' not found\n", argv[i]); continue; }
        /* Step 1: destroy any BPF XDP link objects (bpf_link_detach) */
        detach_xdp_links_on_iface(ifindex);
        /* Step 2: remove any legacy direct XDP attachments (DRV + SKB) */
        bpf_xdp_detach(ifindex, XDP_FLAGS_DRV_MODE, NULL);
        bpf_xdp_detach(ifindex, XDP_FLAGS_SKB_MODE, NULL);
        /* Step 3: Auto-Negotiate XDP Attach Mode 
         * Attempt Native Driver Mode (DRV_MODE) for SmartNICs (Intel/Broadcom)
         * to achieve millions of PPS (Zero-Copy). If it fails (e.g., on VETH or LO),
         * fallback gracefully to SKB_MODE. */
        int flags = XDP_FLAGS_DRV_MODE;
        int ret = bpf_xdp_attach(ifindex, prog_fd, flags, NULL);
        if (ret < 0) {
            fprintf(stderr, "[-] Native DRV_MODE failed. Falling back to Generic SKB_MODE...\n");
            flags = XDP_FLAGS_SKB_MODE;
            ret = bpf_xdp_attach(ifindex, prog_fd, flags, NULL);
        }
        if (ret) { fprintf(stderr, "FATAL: XDP attach on '%s' failed: %s\n", argv[i], strerror(-ret)); return 1; }
        ifindexes[num_ifaces++] = ifindex;
        fprintf(stderr, "✅ XDP attached to %s (ifindex=%d, mode=%s)\n", argv[i], ifindex, 
                (flags == XDP_FLAGS_DRV_MODE) ? "DRV/Native" : "SKB/Generic");
    }

    printf("🚀 [v1.0] %d Workers | Total Hash Cap: %.1fM | Flush: FIN/RST + N=100 + Idle(%.0fs)\n",
           num_workers, (double)(num_workers * FLOW_HASH_SIZE) / 1000000.0, IDLE_FLOW_TIMEOUT_S);
    for (int i = 0; i < num_workers; i++) pthread_join(workers[i].thread, NULL);
    pthread_join(g_writer_thread, NULL);


    /* Cleanup: detach XDP from all interfaces */
    for (int i = 0; i < num_ifaces; i++) bpf_xdp_detach(ifindexes[i], XDP_FLAGS_SKB_MODE, NULL);
    /* Final flush and cleanup. We don't fclose(stdout). */
    fflush(g_out_f);
    free(ifindexes); bpf_object__close(obj);
    return 0;
}
