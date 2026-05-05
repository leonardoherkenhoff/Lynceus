# Lynceus Engineering State - 2026-05-05

## 1. Project Objective
Achieve maximum throughput (Target 100Gbps / 600K+ PPS) for an eBPF-based telemetry engine with strict 495-feature parity for the SBSeg 2026 conference research.

## 2. Architectural Components
- **Kernel-Space (XDP)**: High-speed packet dissection, flow hashing (FNV-1a), and per-CPU RingBuffer exports.
- **User-Space (Daemon)**: Parallel workers (48 threads) consuming RingBuffers, maintaining flow states via Welford's Online Algorithm, and performing Zero-Libc serialization.
- **Serialization Layer**: Manual ASCII conversion (`fast_itoa`, `fast_dtoa`, `fast_mac_to_str`) to eliminate `libc` formatting overhead.

## 3. Performance Record (Scientific Audit)
- **Verified Baseline (VETH-SKB)**: ~218,000 PPS (Real Ingress, 495 features, 4 decimal precision).
- **Theoretical Peak (DRV_MODE)**: Estimated 600K+ PPS (requires physical DAC loopback on Broadcom 100Gbps NICs).
- **Bottlenecks Identified**: 
    - `snprintf`/`sprintf`: Eliminated via manual converters.
    - Kernel-to-User path: VETH SKB mode is the current physical ceiling (~220k pps).
    - Precision: 4 decimal places add incremental FPU load but are mandatory for research.

## 4. 495-Feature Schema Status
- **Parity**: Fully maintained across all branches (`parity-netflowlyzer`, `parity-rustiflow`, `parity-nfx`).
- **Data Types**: Mixed (uint64, double, hex-MAC).
- **Validation**: Pass on `scripts/validate_schema.py`.

## 5. Next Steps for Continuity
- **Hardware Validation**: Connect DAC cable between `eno12399np0` and `eno12409np1` to test `DRV_MODE`.
- **FPU Optimization**: Consider Fixed-Point arithmetic for statistical metrics to replace `double`.
- **SIMD Serialization**: Evaluate AVX-512 for bulk integer-to-ASCII conversion of histograms.

## 6. Critical Technical Notes
- **MAX_RECORD**: 32KB (Safe buffer for high-entropy IPv6 records).
- **RingBuffer Size**: 32MB per CPU.
- **Worker Affinity**: Pinned to physical cores (CPU 0-47).
