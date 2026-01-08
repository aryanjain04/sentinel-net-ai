from scapy.all import rdpcap, IP, TCP, UDP
import pandas as pd
import os

def get_flow_key(pkt):
    if not pkt.haslayer(IP): return None
    
    src = pkt[IP].src
    dst = pkt[IP].dst
    proto = pkt[IP].proto
    
    if pkt.haslayer(TCP):
        return (src, dst, pkt[TCP].sport, pkt[TCP].dport, proto)
    elif pkt.haslayer(UDP):
        return (src, dst, pkt[UDP].sport, pkt[UDP].dport, proto)
    return (src, dst, 0, 0, proto)

def process_pcap_to_flows(file_path):
    if not os.path.exists(file_path): return None
    
    packets = rdpcap(file_path)
    flows = {} # Key: 5-tuple, Value: Stats

    for pkt in packets:
        key = get_flow_key(pkt)
        if not key: continue
        
        if key not in flows:
            flows[key] = {
                "start_time": pkt.time,
                "end_time": pkt.time,
                "packet_count": 0,
                "byte_count": 0,
                "flags": set()
            }
        
        f = flows[key]
        f["packet_count"] += 1
        f["byte_count"] += len(pkt)
        f["end_time"] = pkt.time
        if pkt.haslayer(TCP):
            f["flags"].add(str(pkt[TCP].flags))

    # Calculate duration and finalize
    flow_list = []
    for key, data in flows.items():
        flow_list.append({
            "src_ip": key[0],
            "dst_ip": key[1],
            "src_port": key[2],
            "dst_port": key[3],
            "proto": key[4],
            "duration": float(data["end_time"] - data["start_time"]),
            "packet_count": data["packet_count"],
            "byte_count": data["byte_count"],
            "flags": ",".join(list(data["flags"]))
        })
    
    return pd.DataFrame(flow_list)

if __name__ == "__main__":
    df = process_pcap_to_flows("sample.pcap")
    if df is not None:
        print(df)