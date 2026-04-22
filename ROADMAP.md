# 🗺️ Lynceus: Requirements Matrix, Technical Specification, and Definitive Roadmap

This document serves as the technical authority record for the **Lynceus** engine. It details every component, algorithm, and metric implemented, serving as the verification guide for the project's scientific "Totality."

---

## 🏛️ 1. Architecture and Design Philosophy
*Lynceus was built to eliminate contention bottlenecks and ensure absolute statistical fidelity.*

### 1.1. Core Parallelism: Shared-Nothing
- **Dynamic Detection**: The system utilizes `sysconf(_SC_NPROCESSORS_ONLN)` to identify the host's CPU topology.
- **Unified I/O Strategy**: Each core submits events to a private **SPSC Lock-free Queue** (C11 Atomics). A dedicated writer thread consumes these queues to generate a single, coherent `flows.csv` without thread contention.
- **NUMA Affinity**: Threads are pinned to physical cores via `pthread_setaffinity_np` to maximize L1/L2 cache locality and minimize bus latency.

---

## 🛡️ 2. Data Plane: Visibility and Dissection (eBPF/XDP)
*The capture engine operates at Layer 2 for total visibility before the kernel network stack.*

### 2.1. Normalization and Protocols
- **Native Dual-Stack**: Mapping of IPv4 addresses into the 128-bit IPv6 space for processing uniformity.
- **Recursive Tunnel Dissection**: The parser iterates over **GRE** and **VXLAN** headers, extracting features from the inner payload.
- **VLAN & QinQ**: Iterative support for multiple 802.1Q and 802.1ad headers.
- **ICMP/v6 Granularity**: Flow differentiation based not only on IP but on the `Type/Code` pair and the **Identifier (Echo ID)**, allowing tracking of individual ping sessions.

---

## 📊 3. Statistical Engine: The 494-Feature Matrix
*Rigorous unification of NTLFlowLyzer and ALFlowLyzer with 4th-order precision.*

### 3.1. Welford Algorithm (Numerical Stability)
- **Online Calculation**: Mean, Variance, Standard Deviation, Skewness, and Kurtosis calculated in $O(1)$ per packet.
- **Statistical Sets (15 Sets)**:
  - **Payload**: Total, Forward, Backward.
  - **Header**: Total, Forward, Backward.
  - **IAT (Inter-Arrival Time)**: Total, Forward, Backward.
  - **Size Deltas**: Total, Forward, Backward.
  - **Flow Dynamics**: Active Time, Idle Time, TCP Window Dynamics.

### 3.2. High-Density Histograms (240 Features)
- **Configuration**: 3 sets (Total, Fwd, Bwd) $\times$ 80 bins each.
- **Resolution**: **20-byte** step per bin, covering from 0 to 1600 bytes.
- **Function**: Captures the "image" of payload distribution, essential for detecting multimodal attacks that simple averages mask.

### 3.3. Bulk and Sub-flow Characteristics
- **Bulk Definition**: Uninterrupted sequences in one direction with $IAT < 1.0s$.
- **Metrics**: `bulk_bytes`, `bulk_packets`, `bulk_count` (For Fwd and Bwd).

---

## ⚙️ 4. Control Plane: State Management and I/O
### 4.1. Flow-Level Paradigm
- **Micro-Temporal Segmentation**: The engine flushes statistics every **100 packets** ($N=100$), allowing high-resolution time-series analysis.
- **Export Triggers**:
  - **Event-Driven**: Receipt of TCP FIN or RST flags.
  - **Volume-Driven**: Reaching the 100-packet threshold.
    - **Time-Driven**: 60-second Idle Timeout for inactive flows.
- **SPSC Unified Persistence**: The writer thread drains worker queues in a round-robin fashion, ensuring atomic row writing to the central telemetry file.

---

## 🚀 5. Strategic Evolution Roadmap

### Phase 2: Extreme Performance & Zero-Copy Architecture (v2.0)
- [ ] **Shared Memory Telemetry (SHM)**: Implementation of 1GB HugePages-backed shared memory for zero-copy IPC between Lynceus and external mitigators.
- [ ] **SIMD Statistics Acceleration**: Refactoring of Welford moments and Histogram updates using **AVX-512** vector instructions.
- [ ] **Adaptive Kernel Batching**: Implementation of $N$-packet aggregation logic within the XDP data plane to scale beyond 10M PPS.
- [ ] **Binary Export (FlatBuffers)**: Replacement of CSV/Text streams with high-efficiency binary serialization.

### Phase 3: Autonomous Mitigation (MAPE-K Closed Loop)
- [ ] **In-Kernel Mitigation**: Implementation of dynamic `XDP_DROP` / `XDP_REDIRECT` filters controlled via a dedicated BPF control map.
- [ ] **Hardware Offloading (AF_XDP/SmartNIC)**: Support for Zero-Copy AF_XDP and SmartNIC offloading for Terabit-scale operations.
- [ ] **AI-Driven Thresholding**: Real-time adjustment of sampling and extraction depth based on traffic entropy.

---
**Lynceus: Precise Vision, Absolute Integrity.**
