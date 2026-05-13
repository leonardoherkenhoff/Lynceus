import json

dump_file = "full_audit_dump_clean.txt"

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

def map_vector(v_name_raw):
    # PCAPv6 special case
    if "PCAPv6" in v_name_raw: return "PCAPv6"
    
    # Prefix matches
    for tv in ["DrDoS_DNS", "DrDoS_NTP", "DrDoS_SNMP", "DrDoS_SSDP"]:
        if tv in v_name_raw: return tv
        
    # The others shouldn't be matched inside DrDoS_ variants
    if "DrDoS_" in v_name_raw: return None
    
    # Now exact suffix or token matching
    tokens = v_name_raw.replace('/', ' ').split()
    for tv in ["LDAP", "MSSQL", "NetBIOS", "Portmap", "Syn", "TFTP", "UDPLag", "UDP"]: # UDPLag before UDP
        if tv in tokens:
            return tv
            
    # For SPLIT/CROSS-DAY, the token is exactly the name
    if "UDPLag" in v_name_raw: return "UDPLag"
    if "UDP" in v_name_raw: return "UDP"
    if "LDAP" in v_name_raw: return "LDAP"
    if "MSSQL" in v_name_raw: return "MSSQL"
    if "NetBIOS" in v_name_raw: return "NetBIOS"
    if "Syn" in v_name_raw: return "Syn"
    if "TFTP" in v_name_raw: return "TFTP"
    if "Portmap" in v_name_raw: return "Portmap"
    
    return None

with open(dump_file, "r") as f:
    lines = f.readlines()

current_pillar = None
current_vector_key = None

for line in lines:
    line = line.strip()
    if not line: continue
    
    is_pillar = False
    for p_label, p_key in pillar_map.items():
        if line == p_label:
            current_pillar = p_key
            current_vector_key = None
            is_pillar = True
            break
            
    if is_pillar: continue
    if not current_pillar: continue
        
    if line.startswith("[ ATQUE / VETOR:"):
        v_name_raw = line.replace("[ ATQUE / VETOR:", "").replace("]", "").strip()
        v_key = map_vector(v_name_raw)
        current_vector_key = v_key
        
        if current_vector_key and current_vector_key not in db[current_pillar]:
             db[current_pillar][current_vector_key] = {'perf': 'N/A', 'ml': {}, 'features': []}
        continue
        
    if not current_vector_key:
        continue
        
    p = current_pillar
    v = current_vector_key
    
    if line.startswith("- DONE:"):
        db[p][v]['perf'] = line
    elif line.startswith("F1:"):
        parts = line.split("|")
        db[p][v]['ml']['F1'] = parts[0].split(":")[1].strip()
        db[p][v]['ml']['Acc'] = parts[1].split(":")[1].strip()
        db[p][v]['ml']['Prec'] = parts[2].split(":")[1].strip()
        db[p][v]['ml']['Rec'] = parts[3].split(":")[1].strip()
    elif line.startswith("Amostras:"):
        parts = line.split("|")
        db[p][v]['ml']['Treino'] = parts[0].split("=")[1].strip()
        db[p][v]['ml']['Teste'] = parts[1].split("=")[1].strip()
    elif line.startswith("Features:"):
        f_str = line.replace("Features:", "").strip()
        if f_str and f_str != 'N/A':
            f_list = f_str.split(",")
            features = []
            for feat in f_list:
                feat = feat.replace("-", "").strip()
                parts = feat.split()
                if len(parts) >= 2:
                    features.append(f"{parts[0]} ({parts[1]})")
            if len(features) > 0:
                db[p][v]['features'] = features

with open("audit_db.json", "w") as f:
    json.dump(db, f, indent=4)
    
stats = {}
for p, vectors in db.items():
    stats[p] = len(vectors.keys())
print("Vectors mapped per pillar:")
for k, v in stats.items():
    print(f"  {k}: {v} vectors")
