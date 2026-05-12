import os
import re

dump_file = "full_audit_dump.txt"
tex_file = "report_full.tex"

# Parse the dump file
db = {
    'NetFlowLyzer (Base/495f)': {},
    'NetFlowLyzer (NetFlowLyzer Parity)': {},
    'RustiFlow (Original)': {},
    'NetFlowLyzer (NFX Parity)': {},
    'NetFlowLyzer (RustiFlow Parity)': {},
    'NetFeatureXtract (Original)': {}
}

pillar_map = {
    'FULL (LYNCEUS)': 'NetFlowLyzer (Base/495f)',
    'PARIDADE NTL': 'NetFlowLyzer (NetFlowLyzer Parity)',
    'RUSTIFLOW ORIGINAL': 'RustiFlow (Original)',
    'PARIDADE NFX': 'NetFlowLyzer (NFX Parity)',
    'PARIDADE RUSTIFLOW': 'NetFlowLyzer (RustiFlow Parity)',
    'NFX ORIGINAL': 'NetFeatureXtract (Original)'
}

tex_vectors = [
    "DrDoS_DNS", "DrDoS_NTP", "DrDoS_SNMP", "DrDoS_SSDP", "LDAP", "MSSQL",
    "NetBIOS", "PCAPv6", "Portmap", "Syn", "TFTP", "UDP", "UDPLag"
]

with open(dump_file, "r") as f:
    content = f.read()

import json
current_pillar = None
blocks = re.split(r'==== (.*?) ====', content)
for i in range(1, len(blocks), 2):
    pillar_name = blocks[i].strip()
    if pillar_name not in pillar_map:
        continue
    p_key = pillar_map[pillar_name]
    
    # Process vector sections
    vector_blocks = blocks[i+1].split("[ ATQUE / VETOR: ")
    for vb in vector_blocks[1:]:
        lines = vb.strip().split('\n')
        v_name_raw = lines[0].replace(']', '').strip()
        
        # Match to TeX vector name
        v_key = None
        for tv in tex_vectors:
            if tv in v_name_raw:
                v_key = tv
                break
        if not v_key:
            continue
            
        perf_data = "N/A"
        ml_data = {}
        features = []
        
        mode = None
        for line in lines[1:]:
            line = line.strip()
            if "Performance (Extração):" in line:
                mode = 'perf'
            elif "Métricas ML:" in line:
                mode = 'ml'
            elif line.startswith('- DONE:'):
                perf_data = line
            elif line.startswith('F1:'):
                # F1: 0.9969   | Acc: 0.9938   | Prec: 1.0000   | Rec: 0.9938
                parts = line.split('|')
                ml_data['F1'] = parts[0].split(':')[1].strip()
                ml_data['Acc'] = parts[1].split(':')[1].strip()
                ml_data['Prec'] = parts[2].split(':')[1].strip()
                ml_data['Rec'] = parts[3].split(':')[1].strip()
            elif line.startswith('Amostras:'):
                # Amostras: Treino=800000   | Teste=800000
                parts = line.split('|')
                ml_data['Treino'] = parts[0].split('=')[1].strip()
                ml_data['Teste'] = parts[1].split('=')[1].strip()
            elif line.startswith('Features:'):
                # Features: - ACK_Cnt 0.1069, - Frag_Mean 0.0996, - Frag_Median 0.0970
                f_str = line.replace('Features:', '').strip()
                if f_str and f_str != 'N/A':
                    f_list = f_str.split(',')
                    for feat in f_list:
                        feat = feat.replace('-', '').strip()
                        parts = feat.split()
                        if len(parts) >= 2:
                            features.append(f"{parts[0]} ({parts[1]})")

        db[p_key][v_key] = {
            'perf': perf_data,
            'ml': ml_data,
            'features': features
        }

# Helper to format metrics
def get_ml_row(p_key, v_key):
    data = db[p_key].get(v_key, {}).get('ml', {})
    if not data:
        return f"{p_key} & N/A & N/A & N/A & N/A & N/A & N/A \\\\"
    return f"{p_key} & {data.get('F1','N/A')} & {data.get('Acc','N/A')} & {data.get('Prec','N/A')} & {data.get('Rec','N/A')} & {data.get('Treino','N/A')} & {data.get('Teste','N/A')} \\\\"

def get_perf_row(p_key, v_key):
    perf = db[p_key].get(v_key, {}).get('perf', 'N/A')
    # Parse perf
    if perf == 'N/A' or 'N/A' in perf:
        return f"{p_key} & N/A & N/A & N/A \\\\"
    
    # - DONE: 2012712 flows | 59.0s | 34119 fps
    m = re.search(r'DONE:\s*(.*?)\s*\|\s*(.*?)\s*\|\s*(.*?)$', perf)
    if m:
        ev = m.group(1).replace('pkts', '').strip()
        if 'file' in ev: ev = "Falha estrutural"
        tm = m.group(2).replace('s', '').strip()
        pps = m.group(3).replace('pps', '').replace('fps', '').strip()
        return f"{p_key} & {ev} & {tm} & {pps} \\\\"
    return f"{p_key} & N/A & N/A & N/A \\\\"

# Process the TeX file
with open(tex_file, "r") as f:
    tex_content = f.read()

# Replace Analytics table
for v_key in tex_vectors:
    # Analytics Table
    regex_ml = r'(\\caption\{Matriz de Detecção e Amostragem \(' + re.escape(v_key) + r'\)\.\}\s*\\end\{table\})'
    
    def repl_ml(match):
        new_tabular = "\\begin{tabular}{lcccccc}\n\\toprule\n\\textbf{Ferramenta/Etapa} & \\textbf{F1-Score} & \\textbf{Acurácia} & \\textbf{Precisão} & \\textbf{Recall} & \\textbf{Treino} & \\textbf{Teste} \\\\\n\\midrule\n"
        for p in db.keys():
            new_tabular += get_ml_row(p, v_key) + "\n"
        new_tabular += "\\bottomrule\n\\end{tabular}\n\\end{threeparttable}}"
        
        # We need to find the tabular environment that precedes the caption
        return new_tabular + "\n" + match.group(1)

    # Simple substitution via string manipulation to avoid complex regex for multiline tabulars
    # Find section
    sec_idx = tex_content.find(f"\\section{{Análise do Vetor: {v_key}}}")
    if sec_idx != -1:
        next_sec_idx = tex_content.find("\\section{Análise", sec_idx + 1)
        if next_sec_idx == -1: next_sec_idx = len(tex_content)
        
        chunk = tex_content[sec_idx:next_sec_idx]
        
        # ML Table Replace
        ml_start = chunk.find("\\begin{tabular}{lcc")
        if ml_start != -1:
            ml_end = chunk.find("\\end{tabular}", ml_start) + len("\\end{tabular}")
            new_ml = "\\begin{tabular}{lcccccc}\n\\toprule\n\\textbf{Ferramenta/Etapa} & \\textbf{F1-Score} & \\textbf{Acurácia} & \\textbf{Precisão} & \\textbf{Recall} & \\textbf{Treino} & \\textbf{Teste} \\\\\n\\midrule\n"
            for p in db.keys():
                new_ml += get_ml_row(p, v_key).replace('_', '\\_') + "\n"
            new_ml += "\\bottomrule\n\\end{tabular}"
            chunk = chunk[:ml_start] + new_ml + chunk[ml_end:]
            
        # Perf Table Replace
        perf_start = chunk.find("\\begin{tabular}{lccc}")
        if perf_start != -1:
            perf_end = chunk.find("\\end{tabular}", perf_start) + len("\\end{tabular}")
            new_perf = "\\begin{tabular}{lccc}\n\\toprule\n\\textbf{Ferramenta/Etapa} & \\textbf{Pacotes/Eventos} & \\textbf{Tempo (s)} & \\textbf{Vazão (PPS/FPS)} \\\\\n\\midrule\n"
            for p in db.keys():
                new_perf += get_perf_row(p, v_key).replace('_', '\\_') + "\n"
            new_perf += "\\bottomrule\n\\end{tabular}"
            chunk = chunk[:perf_start] + new_perf + chunk[perf_end:]
            
        # Feat Table Replace
        feat_start = chunk.find("\\begin{tabular}{l|l|")
        if feat_start == -1: feat_start = chunk.find("\\begin{tabular}{l")
        if feat_start != -1:
            # check if it is within a resizebox
            feat_end = chunk.find("\\end{tabular}", feat_start) + len("\\end{tabular}")
            new_feat = "\\begin{tabular}{l|l|l|l|l|l}\n\\toprule\n\\textbf{Base(495f)} & \\textbf{Parity(NTL)} & \\textbf{Parity(NFX)} & \\textbf{Parity(Rust)} & \\textbf{Rust Original} & \\textbf{NFX Original} \\\\\n\\midrule\n"
            
            p_keys = list(db.keys())
            for i in range(3): # max 3 features
                row_cells = []
                for p in p_keys:
                    feats = db[p].get(v_key, {}).get('features', [])
                    if len(feats) > i:
                        row_cells.append(feats[i].replace('_', '\\_'))
                    else:
                        row_cells.append("-")
                new_feat += " & ".join(row_cells) + " \\\\\n"
                
            new_feat += "\\bottomrule\n\\end{tabular}"
            chunk = chunk[:feat_start] + new_feat + chunk[feat_end:]
            
        tex_content = tex_content[:sec_idx] + chunk + tex_content[next_sec_idx:]

with open("report_full.tex", "w") as f:
    f.write(tex_content)
    
print("LaTeX updated successfully.")
