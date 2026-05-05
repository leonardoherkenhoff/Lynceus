# Lynceus Cognitive Memory: The 495-Feature Journey (2026)

## 1. Project Genesis & Philosophy
Lynceus was born from the need for **Scientific Parity**. Unlike commercial NetFlow extractors, Lynceus targets 100% feature parity with datasets like CICDDoS2019 to enable valid ML research. 
- **Core Philosophy**: No data leakage. No identity features. Pure behavioral telemetry.

## 2. Key Architectural Decisions (The "Why")
### Online Statistics (Welford's Algorithm)
We chose Welford's over standard mean/variance to avoid storing raw packet values in memory. This allows calculating M1-M4 (Mean, Variance, Skewness, Kurtosis) in a single pass with O(1) space per flow.

### Parallel Monster Architecture (v5.0.0)
The system evolved from a single-threaded bottleneck to a 48-core parallel engine.
- **Decision**: Used `ARRAY_OF_MAPS` to map each physical CPU to a dedicated user-space worker thread via per-CPU RingBuffers.
- **Benefit**: Zero lock contention between workers.

## 3. Major Crises & Resolutions
### The Map-in-Map Deadlock (Session de3b407c)
- **Crisis**: Packet events were being generated in kernel but never reached user-space.
- **Root Cause**: An structural error in `main.bpf.c` where the inner RingBuffer was incorrectly declared with `SEC(".maps")`, causing the kernel to use it as a template rather than an instance.
- **Resolution**: Refactored the BPF map declaration to use anonymous inner types, allowing the user-space loader to inject real FDs dynamically.

### The Serialization Ceiling (Current Session)
- **Crisis**: Performance peaked at 218k PPS despite 48 cores.
- **Root Cause**: `snprintf` is a synchronous bottleneck. Formatting 495 columns 218,000 times per second saturated the workers' CPU cycles in string parsing.
- **Resolution**: Implemented **Zero-Libc Serialization** (`fast_itoa`, `fast_dtoa`). String formatting is now pure arithmetic, freeing the workers to handle higher line rates.

## 4. Failed Hypotheses (What NOT to repeat)
- **Generic XDP on VETH**: We attempted to hit 600k PPS on VETH. **Scientific Fact**: VETH-SKB is limited by the kernel's software interrupt overhead. Do not expect >300k PPS without physical DAC cables and DRV_MODE.
- **Entropy LUT**: Attempted a pre-calculated log2 LUT for entropy. On high-core systems, cache thrashing outweighed the mathematical gain. Simple `log2()` or a very small, cache-aligned LUT is preferred.

## 5. Technical DNA for the Next Agent
- **Data Parity**: Mandatory 4 decimal places for `double`.
- **Worker Load**: Workers are currently under-utilized in CPU but limited by RingBuffer throughput.
- **The 100Gbps Goal**: Requires `XDP_FLAGS_DRV_MODE`. If the engine doesn't start in DRV_MODE, the hardware is not configured correctly (cables/drivers).
