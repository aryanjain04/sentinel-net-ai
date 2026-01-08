from scapy.all import rdpcap, IP, TCP, UDP
import pandas as pd
import os

def extract_features(pkt):

    if not pkt.haslayer(IP):
        return None

    feat = {
        "timestamp": pkt.time,
        "src_ip": pkt[IP].src,
        "dst_ip": pkt[IP].dst,
        "proto": pkt[IP].proto,
        "length": len(pkt),
        "ttl": pkt[IP].ttl 
    }

    if pkt.haslayer(TCP):
        feat["src_port"] = pkt[TCP].sport
        feat["dst_port"] = pkt[TCP].dport
        feat["tcp_flags"] = str(pkt[TCP].flags) 
    elif pkt.haslayer(UDP):
        feat["src_port"] = pkt[UDP].sport
        feat["dst_port"] = pkt[UDP].dport
        feat["tcp_flags"] = None

    return feat

def process_pcap(file_path):
    if not os.path.exists(file_path):
        print(f"Error: {file_path} not found.")
        return None

    print(f"Dissecting {file_path}...")
    packets = rdpcap(file_path)
    data = [extract_features(p) for p in packets if extract_features(p) is not None]
    return pd.DataFrame(data)

if __name__ == "__main__":
    df = process_pcap("sample.pcap")
    if df is not None:
        print(df.head(10))