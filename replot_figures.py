import matplotlib.pyplot as plt
import numpy as np
import os

plt.rcParams['font.family'] = 'serif'
plt.rcParams['font.size'] = 14

def plot_memory_bloat():
    labels = ['Legacy\n(User-Space)', 'RustiFlow\n(TC)', 'XFlowLyzer\n(XDP)']
    means = [13380, 4716, 128]
    errors = [1500, 800, 0]  # std dev
    colors = ['gray', '#d62728', '#1f77b4']

    fig, ax = plt.subplots(figsize=(4, 4.5))
    
    x_pos = np.arange(len(labels))
    bars = ax.bar(x_pos, means, yerr=errors, align='center', alpha=1.0, 
                  color=colors, capsize=10, edgecolor='black', error_kw={'linewidth': 2})

    ax.set_ylabel('Peak Memory - Log Scale (MB)', fontweight='bold')
    ax.set_xticks(x_pos)
    ax.set_xticklabels(labels)
    ax.set_yscale('log')
    ax.set_ylim(10, 30000)

    # Annotate bars
    for i, bar in enumerate(bars):
        yval = bar.get_height()
        ax.text(bar.get_x() + bar.get_width()/2.0, yval * 1.3, f"{int(yval)} MB", ha='center', va='bottom', fontweight='bold', fontsize=12)

    plt.tight_layout()
    plt.savefig('/opt/eBPFNetFlowLyzer/fig_memory_bloat.pdf', format='pdf', bbox_inches='tight')

def plot_survival():
    labels = ['RustiFlow (TC)', 'XFlowLyzer (XDP)']
    means = [21.8, 100.0]
    colors = ['#d62728', '#1f77b4']

    fig, ax = plt.subplots(figsize=(4, 4.5))
    
    x_pos = np.arange(len(labels))
    bars = ax.bar(x_pos, means, align='center', alpha=1.0, 
                  color=colors, edgecolor='black', hatch=['///', ''])

    ax.set_ylabel('Telemetry Retention (%)', fontweight='bold')
    ax.set_xticks(x_pos)
    ax.set_xticklabels(labels)
    ax.set_ylim(0, 115)

    # Annotate bars
    for bar in bars:
        yval = bar.get_height()
        ax.text(bar.get_x() + bar.get_width()/2.0, yval + 2, f"{yval}%", ha='center', va='bottom', fontweight='bold', fontsize=12)

    plt.tight_layout()
    plt.savefig('/opt/eBPFNetFlowLyzer/fig_survival.pdf', format='pdf', bbox_inches='tight')

if __name__ == '__main__':
    plot_memory_bloat()
    plot_survival()
