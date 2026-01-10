"""CLI entrypoint.

PCAP -> (sessionized bidirectional flows) -> (rules + ML gating) -> (RAG + LLM JSON on a budget)
"""

from __future__ import annotations

import argparse
import json
import os
from datetime import datetime

import pandas as pd

from analyzer import TrafficAnalyzer
from detection import LLMGatingPolicy, RuleEngine, aggregate_score
from parser import process_pcap_to_flows_stream


def _now_id() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def run_sentinel(pcap_path: str, idle_timeout: float, max_llm_calls: int, llm_min_score: float):
    print("--- SentinelNet-AI: Starting Flow Pipeline ---")
    print(f"PCAP: {pcap_path}")

    if not os.path.exists(pcap_path):
        print(f"PCAP not found: {pcap_path}")
        print("Provide a PCAP via --pcap or set PCAP_PATH in .env")
        return

    df = process_pcap_to_flows_stream(pcap_path, idle_timeout=idle_timeout)
    if df.empty:
        print("No flows extracted.")
        return

    analyzer = TrafficAnalyzer()
    rules = RuleEngine()
    gating = LLMGatingPolicy(min_score=llm_min_score, max_calls_per_run=max_llm_calls)

    alerts: list[dict] = []
    scored_rows: list[dict] = []

    # Score all flows first (cheap) so we can prioritize.
    for _, row in df.iterrows():
        flow = row.to_dict()
        matches = rules.score_flow(flow)
        score = aggregate_score(matches)
        ml_flag = bool(analyzer.ml_bouncer(flow))
        flow["rule_score"] = float(score)
        flow["ml_flag"] = bool(ml_flag)
        flow["rule_matches"] = [m.__dict__ for m in matches]
        scored_rows.append(flow)

    scored_rows.sort(key=lambda x: (x.get("rule_score", 0.0), x.get("ml_flag", False)), reverse=True)

    for flow in scored_rows:
        # Deep path is reserved for flows that justify the cost.
        if not gating.allow(float(flow.get("rule_score", 0.0)), bool(flow.get("ml_flag", False))):
            continue

        result = analyzer.analyze_flow(flow)
        if not result:
            continue

        alerts.append(
            {
                "flow_id": flow.get("flow_id"),
                "src": f"{flow.get('src_ip')}:{flow.get('src_port')}",
                "dst": f"{flow.get('dst_ip')}:{flow.get('dst_port')}",
                "server_port": flow.get("server_port"),
                "duration": flow.get("duration"),
                "packet_count": flow.get("packet_count"),
                "byte_count": flow.get("byte_count"),
                "rule_score": flow.get("rule_score"),
                "ml_flag": flow.get("ml_flag"),
                "rule_matches": flow.get("rule_matches"),
                "llm": result,
            }
        )
        print(f"[DEEP] {result.get('classification','?')} score={flow.get('rule_score'):.2f} {flow.get('flow_id')}")

    run_id = _now_id()
    os.makedirs("runs", exist_ok=True)
    run_dir = os.path.join("runs", run_id)
    os.makedirs(run_dir, exist_ok=True)

    df.to_csv(os.path.join(run_dir, "flows.csv"), index=False)
    with open(os.path.join(run_dir, "scored_flows.json"), "w", encoding="utf-8") as f:
        json.dump(scored_rows, f, indent=2)
    with open(os.path.join(run_dir, "alerts.json"), "w", encoding="utf-8") as f:
        json.dump(alerts, f, indent=2)

    print(f"\nSaved run: {run_dir}")
    print(f"Flows: {len(df)} | Deep analyses: {len(alerts)} (budget {max_llm_calls})")


def _build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="SentinelNet-AI: PCAP -> flows -> hybrid detection -> LLM analysis")
    p.add_argument("--pcap", default=os.getenv("PCAP_PATH", ""), help="Path to a PCAP file")
    p.add_argument("--idle-timeout", type=float, default=float(os.getenv("IDLE_TIMEOUT", "60")))
    p.add_argument("--max-llm-calls", type=int, default=int(os.getenv("MAX_LLM_CALLS_PER_RUN", "10")))
    p.add_argument("--llm-min-score", type=float, default=float(os.getenv("LLM_MIN_SCORE", "0.6")))
    return p


if __name__ == "__main__":
    args = _build_arg_parser().parse_args()
    run_sentinel(
        pcap_path=args.pcap,
        idle_timeout=args.idle_timeout,
        max_llm_calls=args.max_llm_calls,
        llm_min_score=args.llm_min_score,
    )