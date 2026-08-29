"""Score one attempted action against an agent's behavioural baseline (PRD §28).

Pure. ``profile`` is the ``BehaviorProfile`` row as a plain dict (or None).
"""

from __future__ import annotations

from dataclasses import dataclass, field

_VOLUME_KEYS = ("records", "count", "limit", "rows", "batch_size", "quantity", "n")
_COLD_START_MIN = 8


@dataclass
class AnomalyResult:
    score: int  # 0–100
    signals: list[str] = field(default_factory=list)

    @property
    def is_anomalous(self) -> bool:
        return self.score >= 60


def _max_volume(parameters: dict) -> int:
    best = 0
    for k in _VOLUME_KEYS:
        v = parameters.get(k)
        if isinstance(v, bool):
            continue
        if isinstance(v, (int, float)):
            best = max(best, int(v))
    return best


def _clamp(v: float) -> int:
    return max(0, min(100, round(v)))


def score_anomaly(
    profile: dict | None,
    *,
    tool: str,
    parameters: dict,
    context: dict,
    classification: str | None,
) -> AnomalyResult:
    parameters = parameters or {}
    context = context or {}

    total = int((profile or {}).get("total_calls", 0))
    if profile is None or total < _COLD_START_MIN:
        return AnomalyResult(10, ["baseline not yet established"])

    tool_counts: dict = profile.get("tool_counts", {})
    tool_max_volume: dict = profile.get("tool_max_volume", {})
    destinations = set(profile.get("destinations", []))
    classifications = set(profile.get("classifications", []))
    recent = list(profile.get("recent_sequence", []))

    score = 0.0
    signals: list[str] = []

    seen = tool_counts.get(tool, 0)
    if seen == 0:
        score += 45
        signals.append(f"first observed use of '{tool}'")
    else:
        freq = seen / total
        if freq < 0.03:
            score += 12
            signals.append(f"'{tool}' is rare for this agent ({freq:.1%})")

    volume = _max_volume(parameters)
    prev_max = int(tool_max_volume.get(tool, 0))
    if volume and volume > max(prev_max * 3, 500):
        spike = min(50, 15 + (volume / max(prev_max, 1)) * 2)
        score += spike
        signals.append(f"volume {volume:,} vs baseline max {prev_max:,}")

    dest = str(context.get("destination") or context.get("destination_url") or "")
    if dest and destinations and dest not in destinations:
        score += 25
        signals.append(f"new destination '{dest}'")

    if classification and classifications and classification not in classifications:
        score += 18
        signals.append(f"first time handling '{classification}' data")

    if len(recent) >= 5 and all(t == tool for t in recent[-5:]):
        score += 30
        signals.append(f"'{tool}' repeated {len(recent)}+ times (possible loop)")

    return AnomalyResult(_clamp(score), signals or ["consistent with baseline"])
