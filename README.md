# SentinelNet-AI — LLM Network Traffic Analysis (PCAP → Flows → RAG → JSON)

Flow-level network traffic analysis that converts PCAPs into sessionized, bidirectional flows, scores them with interpretable rules + lightweight ML gating, and (optionally) performs RAG + Gemini deep analysis to output structured JSON recommendations.

Modern IDS tools flag traffic but rarely explain *why*. SentinelNet-AI bridges low-level packet data and high-level threat reasoning by combining flow analytics, interpretable rules, and LLM-based analysis grounded in a MITRE-style knowledge base.

## Features

- PCAP → **sessionized, bidirectional flows** (forward/reverse packet+byte stats)
- **Hybrid detection**: interpretable rules + optional ML baseline as a bouncer
- **Cost-aware LLM gating**: fast path vs deep path, with a hard per-run budget
- **RAG grounding**: ChromaDB (semantic) + BM25 (keyword) over a tiny MITRE-style KB
- Streamlit UI to run analysis + browse historical runs

## Architecture (High Level)

1. **Flow extraction** (sessionization + bidirectional stats)
2. **Rule scoring** (cheap, explainable)
3. **ML bouncer** (lightweight ML signal for gating)
4. **RAG retrieval** (semantic + keyword)
5. **LLM deep analysis** (Gemini) with JSON-only output

## Example Output (LLM Deep Path)

```json
{
  "flow_id": "10.0.0.5:80-192.168.1.10:1234-p6-s0",
  "src": "10.0.0.5:80",
  "dst": "192.168.1.10:1234",
  "server_port": 80,
  "duration": 0.0,
  "packet_count": 1,
  "byte_count": 40,
  "rule_score": 0.8,
  "ml_flag": true,
  "rule_matches": [
    {
      "rule_id": "R1001",
      "name": "Possible Port Scan (SYN probe)",
      "score": 0.75,
      "reason": "Short TCP SYN-like flow to privileged port"
    },
    {
      "rule_id": "R2001",
      "name": "Common Service",
      "score": 0.05,
      "reason": "Traffic to common port 80"
    }
  ],
  "llm": {
    "classification": "Suspicious",
    "confidence": 0.5,
    "mitre_techniques": [],
    "reasoning": "No LLM configured. Returned deterministic rule-backed analysis.",
    "recommended_actions": [
      "Validate whether the destination port/service is expected",
      "Check source host for recent process or network anomalies",
      "Correlate with DNS or HTTP logs if available"
    ],
    "context_used": [
      "Adversaries may attempt to enumerate networked services to find vulnerabilities.",
      "Adversaries may communicate using standard protocols like HTTP, DNS, or HTTPS."
    ]
  }
}
```

## Quickstart

### 1) Setup

Create `.env` from `.env.example` and fill your Gemini API key:

- `GOOGLE_API_KEY=...`
- `LLM_PROVIDER=gemini`
- `GEMINI_MODEL=gemini-2.0-flash` (recommended) or `gemini-flash-latest`

Install dependencies (Windows PowerShell):

`./venv/Scripts/python.exe -m pip install -r requirements.txt`

### 2) Run CLI

`./venv/Scripts/python.exe main.py --pcap path/to/traffic.pcap --max-llm-calls 2`

Outputs are stored under `runs/<timestamp>/`:

- `flows.csv` — extracted flows
- `scored_flows.json` — flows + rule scores
- `alerts.json` — LLM JSON outputs (deep path)

### 3) Run Streamlit

`./venv/Scripts/python.exe -m streamlit run dashboard.py`

Upload a PCAP and review the top suspicious flows + LLM JSON results.

## Configuration

Environment variables (copy `.env.example` → `.env`):

- `GOOGLE_API_KEY` — Gemini API key
- `LLM_PROVIDER` — `gemini` (default) or `ollama`
- `GEMINI_MODEL` — model name (e.g. `gemini-2.0-flash` or `gemini-flash-latest`)
- `MAX_LLM_CALLS_PER_RUN` — hard budget per run
- `LLM_MIN_SCORE` — minimum rule score to call LLM (unless ML flags)
- `IDLE_TIMEOUT` — sessionization timeout

If you hit Gemini quota/rate limits, reduce `MAX_LLM_CALLS_PER_RUN` and/or increase `LLM_MIN_SCORE` so fewer flows trigger deep analysis.