# SentinelNet-AI — LLM Network Traffic Analysis (PCAP → Flows → RAG → JSON)

Flow-level network traffic analysis that converts PCAPs into sessionized, bidirectional flows, scores them with interpretable rules + lightweight ML gating, and (optionally) performs RAG + Gemini 1.5 Pro deep analysis to output structured JSON recommendations.

## Features

- PCAP → **sessionized, bidirectional flows** (forward/reverse packet+byte stats)
- **Hybrid detection**: interpretable rules + optional ML baseline as a bouncer
- **Cost-aware LLM gating**: fast path vs deep path, with a hard per-run budget
- **RAG grounding**: ChromaDB (semantic) + BM25 (keyword) over a tiny MITRE-style KB
- Streamlit UI to run analysis + browse historical runs

## Architecture (High Level)

1. **Flow extraction** (sessionization + bidirectional stats)
2. **Rule scoring** (cheap, explainable)
3. **ML bouncer** (cheap signal for gating)
4. **RAG retrieval** (semantic + keyword)
5. **LLM deep analysis** (Gemini 1.5 Pro) with JSON-only output

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

Note: this repo does not commit sample PCAPs.

Outputs are stored under `runs/<timestamp>/`:

- `flows.csv` — extracted flows
- `scored_flows.json` — flows + rule scores
- `alerts.json` — LLM JSON outputs (deep path)

### 3) Run Streamlit

`./venv/Scripts/python.exe -m streamlit run dashboard.py`

Upload a PCAP and review the top suspicious flows + LLM JSON results.

## Limitations (Intentional)

- No deep packet inspection (DPI), protocol parsing, or TLS decryption
- ML baseline is synthetic and used for gating/demo purposes
- Not a production IDS

## Configuration

Environment variables (copy `.env.example` → `.env`):

- `GOOGLE_API_KEY` — Gemini API key
- `LLM_PROVIDER` — `gemini` (default) or `ollama`
- `MAX_LLM_CALLS_PER_RUN` — hard budget per run
- `LLM_MIN_SCORE` — minimum rule score to call LLM (unless ML flags)
- `IDLE_TIMEOUT` — sessionization timeout