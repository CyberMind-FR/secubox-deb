# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>

"""SOC risk scoring algorithm — multi-signal aggregation with transparent breakdown.

Inputs : threat-intel matches, DGA candidates, beaconing patterns, raw SOC events.
Output : final score (0-100, capped) + per-category breakdown + human-readable explanation.

Design : no opaque ML. Each signal has a known weight, every score is explainable.
"""
from __future__ import annotations

from typing import TypedDict


class ScoreBreakdown(TypedDict):
    category: str
    raw_signal_count: int
    weight_subtotal: int
    examples: list[str]


def compute_score(
    threat_intel_matches: list[dict],
    dga_candidates: list[dict],
    beaconing_candidates: list[dict],
    raw_soc_events: list[dict],
) -> dict:
    """Aggregate signals into a 0-100 score + breakdown.

    Returns :
      {
        "score": 0-100,
        "label": "LOW" | "MEDIUM" | "HIGH",
        "breakdown": [ScoreBreakdown, ...],
        "explanation": "human-readable summary",
        "indicators_summary": [str, ...]
      }
    """
    breakdown: list[ScoreBreakdown] = []
    total = 0
    indicators: list[str] = []

    # ── 1. Threat-intel matches ──
    if threat_intel_matches:
        # Each match contributes its `weight` field (40-60 typically), capped at 80
        sub = 0
        examples = []
        for m in threat_intel_matches[:5]:
            w = int(m.get("weight", 0))
            sub += min(w, 60)
            label = m.get("label") or "?"
            src = m.get("source") or "?"
            host = m.get("ioc") or m.get("ip") or "?"
            examples.append(f"[{src}/{w}] {label} : {host}")
        sub = min(sub, 80)
        total += sub
        indicators.append(f"{len(threat_intel_matches)} match(es) feeds malware (poids {sub})")
        breakdown.append({
            "category": "threat_intel",
            "raw_signal_count": len(threat_intel_matches),
            "weight_subtotal": sub,
            "examples": examples,
        })

    # ── 2. DGA candidates ──
    if dga_candidates:
        # Each DGA candidate contributes its `score` field (0-100 individual),
        # we take the MAX (one high-confidence DGA is enough to flag) capped at 40
        max_score = max(c.get("score", 0) for c in dga_candidates)
        sub = min(int(max_score * 0.4), 40)  # scale individual score to category subtotal
        total += sub
        examples = [f"[{c.get('score')}] {c.get('host')} ({','.join(c.get('indicators',[]))})"
                    for c in dga_candidates[:3]]
        indicators.append(f"{len(dga_candidates)} domaine(s) DGA-suspect(s) (poids {sub})")
        breakdown.append({
            "category": "dga",
            "raw_signal_count": len(dga_candidates),
            "weight_subtotal": sub,
            "examples": examples,
        })

    # ── 3. Beaconing patterns ──
    if beaconing_candidates:
        # Each beacon contributes its `score` (20-50), take top 3 averaged + capped at 50
        top = beaconing_candidates[:3]
        avg = sum(b.get("score", 0) for b in top) // max(len(top), 1)
        sub = min(avg, 50)
        total += sub
        examples = [f"[{b.get('score')}] {b.get('host')} (median={b.get('median_seconds')}s, cv={b.get('cv')})"
                    for b in top]
        indicators.append(f"{len(beaconing_candidates)} pattern(s) beaconing (poids {sub})")
        breakdown.append({
            "category": "beaconing",
            "raw_signal_count": len(beaconing_candidates),
            "weight_subtotal": sub,
            "examples": examples,
        })

    # ── 4. Raw SOC events (from local_store SOC source — suspicious patterns) ──
    if raw_soc_events:
        sub = min(sum(int(e.get("weight", 15)) for e in raw_soc_events[:10]), 40)
        total += sub
        examples = [f"[{e.get('weight',15)}] {e.get('kind','?')} : {e.get('host','?')}"
                    for e in raw_soc_events[:5]]
        indicators.append(f"{len(raw_soc_events)} indicateur(s) SOC raw (poids {sub})")
        breakdown.append({
            "category": "raw_soc",
            "raw_signal_count": len(raw_soc_events),
            "weight_subtotal": sub,
            "examples": examples,
        })

    # Final cap + label
    score = min(total, 100)
    if score < 30:
        label = "LOW"
    elif score < 70:
        label = "MEDIUM"
    else:
        label = "HIGH"

    # Build a 1-paragraph explanation
    if score == 0:
        explanation = (
            "Aucun signal de compromission détecté pendant ta session. "
            "Ton appareil semble propre. Continue les bonnes pratiques (2FA, mises à jour)."
        )
    elif score < 30:
        explanation = (
            f"Quelques signaux faibles détectés ({score}/100) — probable faux positifs ou "
            "activité tierce légitime (CDN, télémétrie). Rien d'alarmant."
        )
    elif score < 70:
        explanation = (
            f"Score modéré ({score}/100). Plusieurs signaux à vérifier individuellement "
            "(voir détails ci-dessous). Recommandation : passer en revue les apps "
            "installées récemment et vérifier les permissions."
        )
    else:
        explanation = (
            f"⚠ Score élevé ({score}/100). Plusieurs indicateurs convergent vers une "
            "compromission probable. Recommandations : isoler l'appareil du réseau, "
            "examiner les apps installées, réinitialiser si nécessaire, changer les "
            "mots de passe sensibles depuis un autre appareil."
        )

    return {
        "score": score,
        "label": label,
        "breakdown": breakdown,
        "explanation": explanation,
        "indicators_summary": indicators,
    }
