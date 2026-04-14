# Projeto de Mestrado: Super Extrator de Características Híbrido (eBPF + Go)

## Objetivo Principal
Unificar as capacidades avançadas de extração descritiva de tráfego de L3/L4 (NTLFlowLyzer - 348 features) e L7 DNS (ALFlowLyzer - ~50 features) utilizando captura inline e de altíssimo desempenho via **eBPF/XDP**, sem dependência de bibliotecas custosas como libpcap ou Java.

## A Arquitetura Concordada (A Estratégia do Tubo / RingBuffer)
A arquitetura baseia-se na divisão estrita de responsabilidades pelas limitações inerentes de cálculos em espaço de Kernel:

### 1. Data Plane (Kernel-Space em C / XDP)
- Age como o porteiro e agrupador primário de rede.
- Captura os pacotes cruciais sem deixá-los consumir a pilha do sistema operacional.
- Agrega fluxos através de tabelas restritas (5-tuple), mas ao invés de calcular variâncias ou ler payloads pesados no Kernel, ele "grita" os metadados brutos do pacote (Tamanhos de bit, Timestamps em nanossegundos, Flags TCP base e partes binárias de UDP porta 53) para uma fila de alta peformance no user-space: o **BPF Perf RingBuffer**.

### 2. Control Plane / Cérebro Matemático (User-Space em Golang)
- Escuta o *BPF RingBuffer* incessantemente num modelo multithread e concorrente nativo da linguagem (Goroutines).
- Para **tráfego L3/L4**, pega os dados recebidos e preenche bibliotecas matemáticas instantâneas para formular os 348 atributos clássicos do NTLFlowLyzer (Médias, Desvios, Assimetrias frente às janelas de tempo *Forward* e *Backward*).
- Para **tráfego de DNS (Porta 53)**, processa o payload e extrai os campos textuais para formar as ~50 features nativas de L7 avaliadas pelo ALFlowLyzer.
- Ao final (Timeout ou recebimento de RST/FIN), ele exporta esse fluxo resolvido para o banco de dados final (`.csv`), constituindo nosso *Ground-Truth* de altíssima performance.

## Fases do Roteiro Geral

- **Fase 1 (Disciplina Atual):** Inicializar esse ecossistema do Super Extrator. Criar a estrutura C + Go, subir o Testbed com geradores de intrusão, validar que a extração aguenta a pancada sem queda de pacote, e apresentar o andamento inicial.
- **Fase 2:** Aplicar as predições de IA (Random Forest treinado) aos `.csv` produzidos provando o Information Gain contra as saídas das antigas ferramentas.
- **Fase 3 (Fim do Mestrado):** Usar o mesmo motor de Go treinado para devolver um comando de `XDP_DROP` ao eBPF In-Line, provando a detecção + mitigação autônoma.
