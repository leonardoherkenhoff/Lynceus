# Changelog

All notable changes to the **Lynceus** project will be documented in this file.

---

## [1.0] - 2026-04-21
### Definitive Foundation (Scientific & Industrial Parity)
- **High-Performance Data Plane**: 100% C-eBPF/XDP engine with dual-stack support (IPv4-mapped-IPv6).
- **Native Tunnel Decapsulation**: Integrated GRE and VXLAN dissection in the fast-path.
- **Robust L7 Visibility**: Deep kernel-space parsing for DNS (compression-safe), NTP, SNMP, and SSDP.
- **Lock-free SPSC Architecture**: Industrial-grade I/O using C11 Atomics and per-core circular buffers.
- **Statistical Fidelity**: Iterative O(1) calculation of 494 features including 4th-order moments (Skewness/Kurtosis) and P² online medians.
- **Unified Telemetry Stream**: Consistent, zero-contention serialization to `flows.csv`.
- **Parallel Shared-Nothing Model**: Dynamic core scalability via BPF Map-in-Map and CPU affinity pinning.

---

**Lynceus: High-Fidelity Network Telemetry.**
