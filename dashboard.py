from __future__ import annotations

import json
import os
from datetime import datetime
from pathlib import Path

import pandas as pd
import streamlit as st

from analyzer import TrafficAnalyzer
from detection import LLMGatingPolicy, RuleEngine, aggregate_score
from parser import process_pcap_to_flows_stream


def _now_id() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def _save_run(run_id: str, flows_df: pd.DataFrame, scored_flows: list[dict], alerts: list[dict]) -> str:
    Path("runs").mkdir(exist_ok=True)
    run_dir = Path("runs") / run_id
    run_dir.mkdir(exist_ok=True)

    flows_df.to_csv(run_dir / "flows.csv", index=False)
    (run_dir / "scored_flows.json").write_text(json.dumps(scored_flows, indent=2), encoding="utf-8")
    (run_dir / "alerts.json").write_text(json.dumps(alerts, indent=2), encoding="utf-8")
    return str(run_dir)


def _load_runs() -> list[str]:
    runs_dir = Path("runs")
    if not runs_dir.exists():
        return []
    return sorted([p.name for p in runs_dir.iterdir() if p.is_dir()], reverse=True)


def _load_run(run_id: str):
    run_dir = Path("runs") / run_id
    flows_path = run_dir / "flows.csv"
    scored_path = run_dir / "scored_flows.json"
    alerts_path = run_dir / "alerts.json"

    flows_df = pd.read_csv(flows_path) if flows_path.exists() else pd.DataFrame()
    scored = json.loads(scored_path.read_text(encoding="utf-8")) if scored_path.exists() else []
    alerts = json.loads(alerts_path.read_text(encoding="utf-8")) if alerts_path.exists() else []
    return flows_df, scored, alerts


st.set_page_config(page_title="SentinelNet-AI", layout="wide")

st.title("SentinelNet-AI — LLM Network Traffic Analysis")
st.caption("Flow-level analysis with rule scoring + cost-aware LLM deep dives (Gemini 1.5 Pro)")

with st.sidebar:
    st.header("Run Settings")
    idle_timeout = st.number_input("Idle timeout (seconds)", min_value=1.0, max_value=600.0, value=float(os.getenv("IDLE_TIMEOUT", "60")))
    max_llm_calls = st.number_input("Max LLM calls per run", min_value=0, max_value=100, value=int(os.getenv("MAX_LLM_CALLS_PER_RUN", "10")))
    llm_min_score = st.slider("LLM min rule score", min_value=0.0, max_value=1.0, value=float(os.getenv("LLM_MIN_SCORE", "0.6")), step=0.05)

    st.divider()
    st.header("History")
    existing_runs = _load_runs()
    selected_run = st.selectbox("Open previous run", options=[""] + existing_runs)


tab_analyze, tab_history = st.tabs(["Analyze PCAP", "Browse History"])

with tab_analyze:
    uploaded = st.file_uploader("Upload a PCAP", type=["pcap", "pcapng"])

    col_a, col_b = st.columns([1, 1])
    with col_a:
        run_btn = st.button("Run Analysis", type="primary", use_container_width=True, disabled=uploaded is None)
    with col_b:
        st.write("")

    if run_btn and uploaded is not None:
        tmp_dir = Path(".tmp")
        tmp_dir.mkdir(exist_ok=True)
        pcap_path = tmp_dir / uploaded.name
        pcap_path.write_bytes(uploaded.getbuffer())

        with st.status("Extracting flows (sessionized + bidirectional)...", expanded=False):
            flows_df = process_pcap_to_flows_stream(str(pcap_path), idle_timeout=float(idle_timeout))

        if flows_df.empty:
            st.warning("No flows extracted from this PCAP.")
        else:
            rules = RuleEngine()
            analyzer = TrafficAnalyzer()
            gating = LLMGatingPolicy(min_score=float(llm_min_score), max_calls_per_run=int(max_llm_calls))

            scored: list[dict] = []
            for _, row in flows_df.iterrows():
                flow = row.to_dict()
                matches = rules.score_flow(flow)
                score = aggregate_score(matches)
                ml_flag = bool(analyzer.ml_bouncer(flow))
                flow["rule_score"] = float(score)
                flow["ml_flag"] = bool(ml_flag)
                flow["rule_matches"] = [m.__dict__ for m in matches]
                scored.append(flow)

            scored.sort(key=lambda x: (x.get("rule_score", 0.0), x.get("ml_flag", False)), reverse=True)

            with st.status("Deep analysis (LLM) on a budget...", expanded=False):
                alerts: list[dict] = []
                for flow in scored:
                    if not gating.allow(float(flow.get("rule_score", 0.0)), bool(flow.get("ml_flag", False))):
                        continue
                    llm_json = analyzer.analyze_flow(flow)
                    alerts.append({"flow_id": flow.get("flow_id"), "rule_score": flow.get("rule_score"), "ml_flag": flow.get("ml_flag"), "flow": flow, "llm": llm_json})

            run_id = _now_id()
            run_dir = _save_run(run_id, flows_df, scored, alerts)

            st.success(f"Saved run: {run_dir}")

            st.subheader("Summary")
            c1, c2, c3, c4 = st.columns(4)
            c1.metric("Flows", len(flows_df))
            c2.metric("Deep analyses", len(alerts))
            c3.metric("Max LLM calls", int(max_llm_calls))
            c4.metric("LLM min score", float(llm_min_score))

            st.subheader("Top suspicious flows")
            top_df = pd.DataFrame(scored).head(50)
            st.dataframe(
                top_df[["flow_id", "server_port", "proto", "duration", "packet_count", "byte_count", "rule_score", "ml_flag"]],
                use_container_width=True,
                hide_index=True,
            )

            st.subheader("LLM outputs")
            if alerts:
                for a in alerts:
                    with st.expander(f"{a['flow_id']} (score={a['rule_score']:.2f}, ml={a['ml_flag']})", expanded=False):
                        st.json(a["llm"])
            else:
                st.info("No flows met the deep-analysis criteria.")


with tab_history:
    if not selected_run:
        st.info("Pick a run from the sidebar to browse it.")
    else:
        flows_df, scored, alerts = _load_run(selected_run)

        st.subheader(f"Run: {selected_run}")
        c1, c2 = st.columns(2)
        c1.metric("Flows", len(flows_df) if not flows_df.empty else 0)
        c2.metric("Alerts", len(alerts))

        if scored:
            top_df = pd.DataFrame(scored)
            st.dataframe(
                top_df[["flow_id", "server_port", "proto", "duration", "packet_count", "byte_count", "rule_score", "ml_flag"]].head(100),
                use_container_width=True,
                hide_index=True,
            )

        if alerts:
            st.subheader("Alerts")
            for a in alerts:
                flow_id = a.get("flow_id")
                with st.expander(str(flow_id), expanded=False):
                    st.json(a.get("llm"))
        else:
            st.info("No alerts stored for this run.")
