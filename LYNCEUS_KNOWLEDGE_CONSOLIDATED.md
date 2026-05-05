# Lynceus Consolidated Knowledge Base (KIs)

## 1. Arquitetura do Sistema
O Lynceus opera como um motor de extração eBPF/XDP de alta fidelidade.
- **Data Plane (Kernel)**: XDP_PROG realiza a dissecação de protocolos (L2-L4) e extração de metadados.
- **Control Plane (User-space)**: Workers multi-thread processam eventos via RingBuffer e mantêm o estado de fluxo.
- **Memory Model**: Map-in-Map (ARRAY_OF_MAPS) garantindo isolamento per-CPU.

## 2. Roadmap de Desenvolvimento
- **Fase 1-5**: Estabilização do core, suporte multi-protocolo (DNS/NTP/SNMP), suporte IPv6. (Concluído)
- **Fase 6**: Migração para Native DRV_MODE e benchmark em 100Gbps. (Pendente)
- **Fase 7**: Implementação de SIMD (AVX-512) para serialização ultra-rápida. (Planejado)

## 3. CSV Schema (495 Features)
- **Base**: 5-tuple (SrcIP, DstIP, SrcPort, DstPort, Proto).
- **Stat Metrics**: Max, Min, Mean, Std, Var, Median, Skew, Kurt, CoV, Mode para Payloads, Headers, IAT e DeltaLengths.
- **Protocol Specific**: DNS (Answer Count, QType), NTP (Mode, Stratum), ICMP (Type, Code, EchoID).
- **Global**: BytesRate, PacketsRate, Bulk metrics, Histograms (80 bins per flow).
