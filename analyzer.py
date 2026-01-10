"""Layer-3 LLM analysis for suspicious flows.

This module intentionally supports two LLM modes:
- Gemini (cloud) via GOOGLE_API_KEY
- Ollama (local) via a running Ollama server

If no LLM is configured, the analyzer still returns a structured, rule-backed
result so the end-to-end demo works offline.
"""

import json
import os
import re
import time

import joblib
import pandas as pd
from dotenv import load_dotenv
from langchain_core.prompts import ChatPromptTemplate

from vector_store import HybridKnowledgeBase

load_dotenv()

class TrafficAnalyzer:
    def __init__(self, db_path="./chroma_db", model_path="baseline_rf.joblib"):
        db_path = os.getenv("CHROMA_PATH", db_path)
        model_path = os.getenv("MODEL_PATH", model_path)

        if not os.path.exists(model_path):
            from trainer import train_baseline

            train_baseline(output_path=model_path)
        self.ml_model = joblib.load(model_path)
        self.kb = HybridKnowledgeBase(db_path=db_path)
        self.kb.ensure_ingested()

        self.llm = self._build_llm()

    def _build_llm(self):
        provider = (os.getenv("LLM_PROVIDER") or "gemini").strip().lower()
        if provider == "gemini":
            api_key = os.getenv("GOOGLE_API_KEY")
            if not api_key:
                return None
            from langchain_google_genai import ChatGoogleGenerativeAI

            requested = (os.getenv("GEMINI_MODEL") or "gemini-2.0-flash").strip()
            if requested.startswith("models/"):
                requested = requested[len("models/") :]
            alias_map = {
                # Common shorthand / legacy names
                "gemini-flash-2.0": "gemini-2.0-flash",
                "gemini-2.0-flash": "gemini-2.0-flash",
                "gemini-flash-latest": "gemini-flash-latest",
                "gemini-pro-latest": "gemini-pro-latest",
            }
            model_name = alias_map.get(requested, requested)

            # Try requested model, then fall back to a widely available flash model.
            fallback_candidates = [
                model_name,
                "gemini-2.0-flash",
                "gemini-2.0-flash-001",
                "gemini-flash-latest",
                "gemini-2.0-flash-lite",
                "gemini-flash-lite-latest",
            ]

            seen = set()
            ordered = []
            for c in fallback_candidates:
                c = (c or "").strip()
                if not c or c in seen:
                    continue
                seen.add(c)
                ordered.append(c)

            for candidate in ordered:
                try:
                    return ChatGoogleGenerativeAI(
                        model=candidate,
                        temperature=0,
                        google_api_key=api_key,
                    )
                except Exception as e:
                    msg = str(e)
                    if "NOT_FOUND" in msg or "not found" in msg.lower() or "ListModels" in msg:
                        continue
                    # For non-model-availability errors (auth, network), don't hide the failure.
                    raise

            return None

        if provider == "ollama":
            model = os.getenv("OLLAMA_MODEL", "llama3")
            from langchain_community.chat_models import ChatOllama

            return ChatOllama(model=model, temperature=0)

        return None

    def ml_bouncer(self, flow):
        # Features: [duration, packet_count, byte_count, server_port, client_port]
        features = {
            "duration": float(flow.get("duration", 0.0) or 0.0),
            "packet_count": float(flow.get("packet_count", 0) or 0),
            "byte_count": float(flow.get("byte_count", 0) or 0),
            "server_port": float(flow.get("server_port", 0) or 0),
            "client_port": float(flow.get("client_port", 0) or 0),
        }
        X = pd.DataFrame([features])
        return self.ml_model.predict(X)[0] == 1

    def analyze_flow(self, flow):
        narrative = (
            f"Flow: {flow.get('src_ip')}:{flow.get('src_port')} -> {flow.get('dst_ip')}:{flow.get('dst_port')} "
            f"proto={flow.get('proto')}. Duration={flow.get('duration')}s, Packets={flow.get('packet_count')}, "
            f"Bytes={flow.get('byte_count')}, Flags={flow.get('tcp_flags')}."
        )
        context_docs = self.kb.hybrid_search(narrative, top_k=2)
        
        prompt = ChatPromptTemplate.from_messages([
            (
                "system",
                """You are a Senior SOC Analyst.
Use the provided MITRE technique context (if any) to interpret the network flow.
Return ONLY valid JSON (no markdown), with keys:
- classification (Benign|Suspicious|Malicious)
- confidence (0-1)
- mitre_techniques (list of strings)
- reasoning (short string)
- recommended_actions (list of strings)""",
            ),
            ("human", "MITRE Context (may be empty):\n{context}\n\nFlow Data:\n{flow_info}")
        ])

        # Offline fallback: still produce a useful, structured result.
        if self.llm is None:
            return {
                "classification": "Suspicious",
                "confidence": 0.5,
                "mitre_techniques": [],
                "reasoning": "No LLM configured. Returned rule-backed fallback.",
                "recommended_actions": [
                    "Validate whether the destination port/service is expected",
                    "Check source host for recent process/network anomalies",
                    "Correlate with DNS/HTTP logs if available",
                ],
                "context_used": context_docs,
            }

        max_retries = int(os.getenv("LLM_MAX_RETRIES", "0"))
        stop_on_rate_limit = (os.getenv("LLM_STOP_ON_RATE_LIMIT", "1").strip().lower() not in ("0", "false", "no"))

        def _extract_retry_after_seconds(message: str) -> float | None:
            m = re.search(r"Please retry in\s+([0-9.]+)s", message)
            if m:
                return float(m.group(1))
            m = re.search(r"retryDelay'\s*:\s*'([0-9.]+)s'", message)
            if m:
                return float(m.group(1))
            m = re.search(r"retryDelay\"\s*:\s*\"([0-9.]+)s\"", message)
            if m:
                return float(m.group(1))
            return None

        def _is_rate_limited(message: str) -> bool:
            u = message.upper()
            return "RESOURCE_EXHAUSTED" in u or "429" in u or "QUOTA" in u

        def _invoke_once():
            response = (prompt | self.llm).invoke({"flow_info": narrative, "context": "\n".join(context_docs)})
            content = (response.content or "").strip()
            content = content.replace("```json", "").replace("```", "").strip()
            return json.loads(content)

        attempts = 0
        while True:
            try:
                return _invoke_once()
            except Exception as e:
                attempts += 1
                msg = str(e)
                retry_after = _extract_retry_after_seconds(msg)

                if _is_rate_limited(msg):
                    result = {
                        "classification": "Suspicious",
                        "confidence": 0.3,
                        "mitre_techniques": [],
                        "reasoning": f"LLM rate-limited/quota exhausted: {msg}",
                        "recommended_actions": [
                            "Reduce MAX_LLM_CALLS_PER_RUN",
                            "Raise LLM_MIN_SCORE so fewer flows trigger deep analysis",
                            "Check Gemini API quota/billing settings",
                        ],
                        "context_used": context_docs,
                        "rate_limited": True,
                        "retry_after_seconds": retry_after,
                    }
                    if stop_on_rate_limit:
                        return result

                if attempts > max_retries:
                    return {
                        "classification": "Suspicious",
                        "confidence": 0.3,
                        "mitre_techniques": [],
                        "reasoning": f"LLM request failed: {msg}",
                        "recommended_actions": [
                            "Verify whether this connection is expected",
                            "Check endpoint process/network telemetry",
                            "Correlate with DNS/HTTP logs if available",
                        ],
                        "context_used": context_docs,
                    }

                # If we are retrying, do a small bounded sleep. (Don't block the UI for long.)
                sleep_s = 1.0
                if retry_after is not None:
                    sleep_s = min(5.0, max(0.5, float(retry_after)))
                time.sleep(sleep_s)