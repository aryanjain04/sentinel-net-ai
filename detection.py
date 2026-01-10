"""Rule scoring + cost-aware LLM gating.

Design goals:
- Small set of interpretable heuristics (rules)
- Optional ML bouncer
- Budget-aware deep analysis (LLM) only for top/high-risk flows

This is NOT meant to be a full IDS.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class RuleMatch:
    rule_id: str
    name: str
    score: float
    reason: str


class RuleEngine:
    """A tiny rule engine that produces a suspicion score and reasons."""

    def score_flow(self, flow: dict) -> list[RuleMatch]:
        matches: list[RuleMatch] = []

        duration = float(flow.get("duration", 0.0) or 0.0)
        packets = int(flow.get("packet_count", 0) or 0)
        bytes_ = int(flow.get("byte_count", 0) or 0)
        server_port = int(flow.get("server_port", 0) or 0)
        proto = int(flow.get("proto", 0) or 0)
        flags = str(flow.get("tcp_flags", "") or "")

        pps = (packets / duration) if duration > 0 else float(packets)

        # Port-scan-ish single-flow signatures
        if ("S" in flags or "SYN" in flags) and duration < 0.2 and packets <= 3 and bytes_ < 250 and server_port <= 1024:
            matches.append(
                RuleMatch(
                    rule_id="R1001",
                    name="Possible Port Scan (SYN probe)",
                    score=0.75,
                    reason="Short TCP SYN-like flow to privileged port",
                )
            )

        # DoS/flood-ish
        if duration < 2.0 and (packets >= 300 or pps >= 500):
            matches.append(
                RuleMatch(
                    rule_id="R1002",
                    name="Possible Flood/DoS",
                    score=0.85,
                    reason=f"High packet rate: {pps:.1f} pkt/s",
                )
            )

        # Suspiciously empty bytes (can indicate scanning / malformed traffic)
        if packets >= 2 and bytes_ == 0:
            matches.append(
                RuleMatch(
                    rule_id="R1003",
                    name="Zero-byte Flow",
                    score=0.4,
                    reason="Packets observed but byte_count==0",
                )
            )

        # Keep DNS/HTTP/HTTPS as low-score context (not inherently malicious)
        if server_port in (53, 80, 443):
            matches.append(
                RuleMatch(
                    rule_id="R2001",
                    name="Common Service",
                    score=0.05,
                    reason=f"Traffic to common port {server_port}",
                )
            )

        # Basic unknown port hint
        if server_port not in (0, 53, 80, 443) and server_port <= 1024:
            matches.append(
                RuleMatch(
                    rule_id="R2002",
                    name="Privileged Port",
                    score=0.2,
                    reason=f"Traffic to privileged port {server_port}",
                )
            )

        # UDP high-rate heuristic (proto 17)
        if proto == 17 and duration < 2.0 and (packets >= 500 or pps >= 700):
            matches.append(
                RuleMatch(
                    rule_id="R1004",
                    name="Possible UDP Flood",
                    score=0.8,
                    reason=f"High UDP packet rate: {pps:.1f} pkt/s",
                )
            )

        return matches


def aggregate_score(matches: list[RuleMatch]) -> float:
    # Simple saturating sum of scores.
    score = 0.0
    for m in matches:
        score += float(m.score)
    return float(min(1.0, score))


class LLMGatingPolicy:
    """Decides whether a flow deserves an LLM call."""

    def __init__(self, min_score: float = 0.6, max_calls_per_run: int = 10):
        self.min_score = float(min_score)
        self.max_calls_per_run = int(max_calls_per_run)
        self.calls_used = 0

    def allow(self, suspicion_score: float, ml_flag: bool) -> bool:
        if self.calls_used >= self.max_calls_per_run:
            return False
        if ml_flag:
            self.calls_used += 1
            return True
        if suspicion_score >= self.min_score:
            self.calls_used += 1
            return True
        return False
