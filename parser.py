"""PCAP -> sessionized, bidirectional flow features.

Practical scope:
- Flow-level (not full DPI) features
- Bidirectional counters (fwd/rev packets + bytes)
- Sessionization using an idle timeout

This provides enough signal for rule-based detection + ML gating.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

import pandas as pd
from scapy.all import IP, IPv6, PcapReader, TCP, UDP

IDLE_TIMEOUT = 60.0


def canonical_endpoints(src: str, dst: str, sport: int, dport: int):
    a = (src, int(sport))
    b = (dst, int(dport))
    return (a, b) if a <= b else (b, a)


def flow_key(src: str, dst: str, sport: int, dport: int, proto: int):
    (a_ip, a_port), (b_ip, b_port) = canonical_endpoints(src, dst, sport, dport)
    return (a_ip, b_ip, int(a_port), int(b_port), int(proto))

def extract_packet_fields(pkt):
    if pkt.haslayer(IP):
        layer = IP
        proto, src, dst = pkt[layer].proto, pkt[layer].src, pkt[layer].dst
    elif pkt.haslayer(IPv6):
        layer = IPv6
        proto, src, dst = pkt[layer].nh, pkt[layer].src, pkt[layer].dst
    else:
        return None

    sport = dport = 0
    is_tcp = False
    if pkt.haslayer(TCP):
        sport, dport, is_tcp = pkt[TCP].sport, pkt[TCP].dport, True
    elif pkt.haslayer(UDP):
        sport, dport = pkt[UDP].sport, pkt[UDP].dport

    ts = float(getattr(pkt, "time", 0.0))
    p_len = len(pkt[TCP].payload) if pkt.haslayer(TCP) else (len(pkt[UDP].payload) if pkt.haslayer(UDP) else 0)
    h_len = len(pkt) - p_len
    
    return src, dst, int(sport), int(dport), int(proto), ts, is_tcp, p_len, h_len


@dataclass
class _FlowState:
    key: tuple
    session_index: int
    start_time: float
    end_time: float
    last_packet_time: float

    a_ip: str
    b_ip: str
    a_port: int
    b_port: int
    proto: int

    packet_count: int = 0
    byte_count: int = 0
    payload_bytes: int = 0
    header_bytes: int = 0

    fwd_packets: int = 0
    fwd_bytes: int = 0
    rev_packets: int = 0
    rev_bytes: int = 0

    tcp_flags: set[str] | None = None

    def as_row(self):
        duration = float(max(0.0, self.end_time - self.start_time))
        flags = ",".join(sorted(self.tcp_flags)) if self.tcp_flags else ""

        server_port = int(min(self.a_port, self.b_port))
        client_port = int(max(self.a_port, self.b_port))

        return {
            "flow_id": f"{self.a_ip}:{self.a_port}-{self.b_ip}:{self.b_port}-p{self.proto}-s{self.session_index}",
            "src_ip": self.a_ip,
            "dst_ip": self.b_ip,
            "src_port": int(self.a_port),
            "dst_port": int(self.b_port),
            "proto": int(self.proto),
            "start_time": float(self.start_time),
            "end_time": float(self.end_time),
            "duration": duration,
            "packet_count": int(self.packet_count),
            "byte_count": int(self.byte_count),
            "payload_bytes": int(self.payload_bytes),
            "header_bytes": int(self.header_bytes),
            "fwd_packets": int(self.fwd_packets),
            "fwd_bytes": int(self.fwd_bytes),
            "rev_packets": int(self.rev_packets),
            "rev_bytes": int(self.rev_bytes),
            "tcp_flags": flags,
            "server_port": server_port,
            "client_port": client_port,
        }


def process_pcap_to_flows_stream(file_path: str, idle_timeout: float = IDLE_TIMEOUT) -> pd.DataFrame:
    if not os.path.exists(file_path):
        raise FileNotFoundError(file_path)

    active: dict[tuple, _FlowState] = {}
    session_counters: dict[tuple, int] = {}
    rows: list[dict] = []

    with PcapReader(file_path) as reader:
        for pkt in reader:
            ex = extract_packet_fields(pkt)
            if ex is None:
                continue

            src, dst, sport, dport, proto, ts, is_tcp, p_len, h_len = ex
            key = flow_key(src, dst, sport, dport, proto)
            a_ip, b_ip, a_port, b_port, proto = key

            state = active.get(key)
            if state is None:
                idx = session_counters.get(key, 0)
                session_counters[key] = idx
                state = _FlowState(
                    key=key,
                    session_index=idx,
                    start_time=ts,
                    end_time=ts,
                    last_packet_time=ts,
                    a_ip=a_ip,
                    b_ip=b_ip,
                    a_port=int(a_port),
                    b_port=int(b_port),
                    proto=int(proto),
                    tcp_flags=set() if is_tcp else None,
                )
                active[key] = state
            else:
                if ts - state.last_packet_time > idle_timeout:
                    rows.append(state.as_row())
                    idx = session_counters.get(key, 0) + 1
                    session_counters[key] = idx
                    state = _FlowState(
                        key=key,
                        session_index=idx,
                        start_time=ts,
                        end_time=ts,
                        last_packet_time=ts,
                        a_ip=a_ip,
                        b_ip=b_ip,
                        a_port=int(a_port),
                        b_port=int(b_port),
                        proto=int(proto),
                        tcp_flags=set() if is_tcp else None,
                    )
                    active[key] = state

            packet_len = len(pkt)
            state.packet_count += 1
            state.byte_count += packet_len
            state.payload_bytes += int(p_len)
            state.header_bytes += int(h_len)
            state.end_time = ts
            state.last_packet_time = ts

            # Direction relative to canonical endpoints
            is_fwd = (src == state.a_ip and int(sport) == state.a_port and dst == state.b_ip and int(dport) == state.b_port)
            if is_fwd:
                state.fwd_packets += 1
                state.fwd_bytes += packet_len
            else:
                state.rev_packets += 1
                state.rev_bytes += packet_len

            if is_tcp and state.tcp_flags is not None and pkt.haslayer(TCP):
                state.tcp_flags.add(str(pkt[TCP].flags))

    for state in active.values():
        rows.append(state.as_row())

    return pd.DataFrame(rows)