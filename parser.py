# parser.py
from scapy.all import PcapReader, IP, IPv6, TCP, UDP
import pandas as pd
import os

# tune this for your use-case
IDLE_TIMEOUT = 60.0  # seconds of inactivity to end a flow

def canonical_key(src, dst, sport, dport, proto):
    """Return canonical ordering so (A,sport)->(B,dport) and (B,dport)->(A,sport) map to same 5-tuple."""
    a = (src, int(sport))
    b = (dst, int(dport))
    if a <= b:
        return (src, dst, int(sport), int(dport), int(proto))
    return (dst, src, int(dport), int(sport), int(proto))

def extract_packet_fields(pkt):
    """Return (src, dst, sport, dport, proto, ts, is_tcp) or None if non-IP."""
    if pkt.haslayer(IP):
        layer = IP
        proto = pkt[layer].proto
        src = pkt[layer].src
        dst = pkt[layer].dst
    elif pkt.haslayer(IPv6):
        layer = IPv6
        proto = pkt[layer].nh
        src = pkt[layer].src
        dst = pkt[layer].dst
    else:
        return None

    sport = dport = 0
    is_tcp = False
    if pkt.haslayer(TCP):
        sport = pkt[TCP].sport
        dport = pkt[TCP].dport
        is_tcp = True
    elif pkt.haslayer(UDP):
        sport = pkt[UDP].sport
        dport = pkt[UDP].dport

    ts = float(getattr(pkt, "time", 0.0))
    
    payload_len = len(pkt[TCP].payload) if pkt.haslayer(TCP) else (len(pkt[UDP].payload) if pkt.haslayer(UDP) else 0)
    header_len = len(pkt) - payload_len
    
    # Return these to the aggregator
    return src, dst, sport, dport, proto, ts, is_tcp, payload_len, header_len

def process_pcap_to_flows_stream(file_path, idle_timeout=IDLE_TIMEOUT):
    """
    Stream a pcap and return a DataFrame of flows.
    Each flow is canonicalized and sessionized by idle_timeout seconds.
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(file_path)

    flows = {}  # key -> stats dict

    with PcapReader(file_path) as reader:
        for pkt in reader:
            extracted = extract_packet_fields(pkt)
            if extracted is None:
                continue
            src, dst, sport, dport, proto, ts, is_tcp = extracted
            key = canonical_key(src, dst, sport, dport, proto)

            # If no existing flow, create new
            if key not in flows:
                flows[key] = {
                    "start_time": ts,
                    "end_time": ts,
                    "last_packet_time": ts,
                    "packet_count": 1,
                    "byte_count": len(pkt),
                    "flags": set()
                }
                # initial flags if TCP
                if is_tcp:
                    flows[key]["flags"].add(str(pkt[TCP].flags))
                continue

            # existing flow: check idle timeout
            f = flows[key]
            if ts - f["last_packet_time"] > idle_timeout:
                # finalize old flow by creating a new subflow keyed with start timestamp
                # use deterministic suffix to avoid mixing; store separate key as tuple of length 6
                new_key = key + (int(ts),)
                flows[new_key] = {
                    "start_time": ts,
                    "end_time": ts,
                    "last_packet_time": ts,
                    "packet_count": 1,
                    "byte_count": len(pkt),
                    "flags": set()
                }
                if is_tcp:
                    flows[new_key]["flags"].add(str(pkt[TCP].flags))
            else:
                # update existing flow
                f["packet_count"] += 1
                f["byte_count"] += len(pkt)
                f["end_time"] = ts
                f["last_packet_time"] = ts
                if is_tcp:
                    f["flags"].add(str(pkt[TCP].flags))

    # convert flows dict to row list
    rows = []
    for key, d in flows.items():
        # take first 5 elements as canonical 5-tuple
        src_ip, dst_ip, src_port, dst_port, proto = key[:5]
        duration = float(d["end_time"] - d["start_time"]) if d.get("end_time") and d.get("start_time") else 0.0
        rows.append({
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": int(src_port),
            "dst_port": int(dst_port),
            "proto": int(proto),
            "duration": duration,
            "packet_count": int(d["packet_count"]),
            "byte_count": int(d["byte_count"]),
            "flags": ",".join(sorted(list(d["flags"])))
        })

    return pd.DataFrame(rows)

if __name__ == "__main__":
    df = process_pcap_to_flows_stream("sample.pcap")
    print(df)
