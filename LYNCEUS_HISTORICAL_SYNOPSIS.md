# Lynceus Historical Synopsis (Archived Logs Summary)

## 1. Sessão f9a6ab40: Arquitetura "Monster v5.0.0"
- **Objetivo**: Escalar a extração para 495 features com paridade total CICDDoS2019.
- **Marcos**:
    - Implementação do algoritmo de Welford para cálculo de estatísticas (M1-M4) sem armazenamento de histórico bruto.
    - Estruturação de `flow_state` alinhado em memória para performance de cache.
    - Implementação de RingBuffers per-CPU para evitar contenção de locks em sistemas multi-core (48+ threads).
    - Design do MAPE-K Loop como orquestrador central.

## 2. Sessão de3b407c: Debugging RingBuffer Map-in-Map
- **Problema**: Eventos do kernel não alcançavam o user-space.
- **Diagnóstico**: O `inner_rb` estava sendo declarado com `SEC(".maps")`, o que levava o libbpf a criar um FD real que o kernel usava apenas como template estático.
- **Resolução**: Remoção da seção `SEC` do inner map, permitindo que o loader criasse e inserisse dinamicamente os FDs de RingBuffer nos slots do `ARRAY_OF_MAPS`.

## 3. Sessão 52b74cce: Validação Metodológica
- **Foco**: Eliminação de "Data Leakage" (remover portas efêmeras, IPs e timestamps das features de treinamento).
- **Resultado**: Validação temporal cross-day para garantir que o modelo aprenda comportamento e não identidades.

## 4. Sessão Atual (75db9671): Otimização de Serialização
- **Foco**: Romper o teto de 218k PPS eliminando o overhead de `snprintf`.
- **Resultado**: Implementação de Zero-Libc Serialization e estabilização da baseline em VETH.
