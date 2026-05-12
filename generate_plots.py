import matplotlib.pyplot as plt
import numpy as np

# Style configurations
plt.rcParams['font.family'] = 'serif'
plt.rcParams['font.size'] = 12

# 1. F1-Score of Legacy Extractors (From Artigo 5)
def plot_legacy_f1():
    labels = ['DNS', 'LDAP', 'MSSQL', 'NetBIOS', 'NTP', 'UDP']
    cic_f1 = [0.9998, 0.9471, 0.9978, 0.9995, 0.9955, 0.9943]
    ntl_f1 = [0.9823, 0.9147, 0.9584, 0.9875, 0.9841, 0.8499]

    x = np.arange(len(labels))
    width = 0.35

    fig, ax = plt.subplots(figsize=(8, 4))
    ax.bar(x - width/2, cic_f1, width, label='CICFlowMeter', color='#1f77b4')
    ax.bar(x + width/2, ntl_f1, width, label='NTLFlowLyzer', color='#ff7f0e')

    ax.set_ylabel('F1-Score')
    ax.set_title('Miopia Temporal: Desempenho de Extratores Legados (User-space)')
    ax.set_xticks(x)
    ax.set_xticklabels(labels)
    ax.legend()
    ax.set_ylim([0.8, 1.05])
    plt.grid(axis='y', linestyle='--', alpha=0.7)
    plt.tight_layout()
    plt.savefig('f1_legados.pdf', format='pdf', bbox_inches='tight')

# 2. Performance: PPS vs RAM
def plot_performance():
    labels = ['Lynceus Base\n(495 feat)', 'Lynceus NFX\nParity (12 feat)', 'Lynceus Rust\nParity (159 feat)', 'RustiFlow\nOriginal']
    pps = [134845, 182701, 174638, 65481]
    
    fig, ax1 = plt.subplots(figsize=(8, 4))

    color = 'tab:blue'
    ax1.set_ylabel('Vazão Máxima (PPS)', color=color)
    ax1.bar(labels, pps, color=color, alpha=0.7)
    ax1.tick_params(axis='y', labelcolor=color)
    ax1.set_ylim([0, 200000])

    plt.title('Performance Absoluta: Vazão (eBPF Lockless vs Rust User-space)')
    plt.tight_layout()
    plt.savefig('pps_ram.pdf', format='pdf', bbox_inches='tight')

# 3. Purity: RustiFlow vs Lynceus Parity F1
def plot_parity_f1():
    labels = ['DrDoS_DNS', 'DrDoS_LDAP', 'ICMPv6 (ICMPv6)', 'DrDoS_MSSQL']
    rust_f1 = [1.0000, 0.9290, 0.7027, 0.9999]
    lyn_f1 = [0.9998, 0.9997, 0.9943, 0.9994]

    x = np.arange(len(labels))
    width = 0.35

    fig, ax = plt.subplots(figsize=(8, 4))
    ax.bar(x - width/2, rust_f1, width, label='RustiFlow Original (User-space)', color='#d62728')
    ax.bar(x + width/2, lyn_f1, width, label='Lynceus Parity (Kernel-space)', color='#2ca02c')

    ax.set_ylabel('F1-Score')
    ax.set_title('Recuperação de Pureza Temporal (Mesmas 159 características L4)')
    ax.set_xticks(x)
    ax.set_xticklabels(labels)
    ax.legend(loc='lower left')
    ax.set_ylim([0.65, 1.05])
    plt.grid(axis='y', linestyle='--', alpha=0.7)
    plt.tight_layout()
    plt.savefig('f1_parity.pdf', format='pdf', bbox_inches='tight')

# 4. Gini Shift
def plot_gini():
    features = ['ACK_Cnt (L4)', 'SYN_Cnt (L4)', 'Win_Median (L4)', 'BwdPacketsRate (L3)', 'PacketsCount (L3)', 'TotalBytes (L3)']
    rust_par = [9.07, 9.04, 8.52, 0, 0, 0]
    nfx_par = [0, 0, 0, 18.99, 17.99, 15.00]

    y = np.arange(len(features))
    
    fig, ax = plt.subplots(figsize=(8, 4))
    ax.barh(y, rust_par, label='Paridade RustiFlow', color='#9467bd', alpha=0.8)
    ax.barh(y, nfx_par, left=rust_par, label='Paridade NFX', color='#8c564b', alpha=0.8)

    ax.set_xlabel('Peso de Importância Gini (%)')
    ax.set_title('Deslocamento Dimensional do Random Forest')
    ax.set_yticks(y)
    ax.set_yticklabels(features)
    ax.legend()
    plt.tight_layout()
    plt.savefig('gini_shift.pdf', format='pdf', bbox_inches='tight')

if __name__ == '__main__':
    plot_legacy_f1()
    plot_performance()
    plot_parity_f1()
    plot_gini()
