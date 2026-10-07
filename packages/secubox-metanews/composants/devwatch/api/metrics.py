# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: DevWatch — vulgarisation & émancipation.

Ici, et NULLE PART ailleurs, on transforme les faits bruts du dépôt en chiffres
« parlants » : temps cumulé, coût de reconstruction, empreinte carbone, et l'état
de la campagne de soutien. Tout ce qui sort d'ici est une ESTIMATION assumée —
chaque valeur porte `est: true` pour que l'interface la marque comme telle.

Deux origines de données, jamais confondues :
  • dérivé  (est)   — calculé depuis l'activité publique, via des heuristiques
                      transparentes et réglables (tarif, minutes/commit, carbone).
  • saisi   (flows) — flux STATIQUES entrés par l'admin (webmin) : dépenses
                      cumulées, soutien reçu, abonnements mensuels. Des faits
                      d'exploitation que GitHub ne connaît pas.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any, Optional

# Poids d'IMPORTANCE par type de saut sémantique — pour la hauteur des barres.
# Un majeur pèse ; un correctif de pré-version, peu. C'est ce qui « met en avant
# les plus importants » sans rien inventer : le type se lit dans le tag.
_POIDS = {"major": 100, "minor": 60, "patch": 34, "pre": 20, "?": 26}


def _semver(tag: str):
    """(major, minor, patch, prerelease?) depuis un tag — tolérant (v1.2.3-rc1)."""
    t = re.sub(r"^[vV]", "", (tag or "").strip())
    pre = "-" in t or bool(re.search(r"(alpha|beta|rc|dev|pre)", t, re.I))
    core = t.split("-", 1)[0]
    nums = []
    for p in core.split(".")[:3]:
        m = re.match(r"\d+", p)
        nums.append(int(m.group()) if m else 0)
    while len(nums) < 3:
        nums.append(0)
    return nums[0], nums[1], nums[2], pre


def _saut(prev, cur) -> str:
    """Type de saut entre deux versions (majeur/mineur/correctif)."""
    if cur[3]:
        return "pre"
    if prev is None:
        # Sans précédent : on déduit du niveau (x.0.0 = majeur, x.y.0 = mineur).
        return "major" if cur[1] == 0 and cur[2] == 0 else "minor" if cur[2] == 0 else "patch"
    if cur[0] > prev[0]:
        return "major"
    if cur[1] > prev[1]:
        return "minor"
    if cur[2] > prev[2]:
        return "patch"
    return "?"


def evolutions(raw: dict) -> list:
    """Évolution des VERSIONS pour le bargraphe comparatif (#1370).

    Une barre par release récente, en ordre chronologique ; hauteur = importance
    du saut sémantique ; écart en jours depuis la précédente ; la dernière et les
    majeures sont marquées pour la mise en avant. Purement dérivé des tags/dates.
    """
    rec = list(raw.get("releases_recent") or [])
    if not rec:
        return []
    # GitHub rend la plus récente en tête : on remet en ordre chronologique.
    rec = list(reversed(rec))
    out, prev_ver, prev_dt = [], None, None
    for x in rec:
        ver = _semver(x.get("tag", ""))
        typ = _saut(prev_ver, ver)
        dt = _iso(x.get("published_at", ""))
        gap = None
        if dt and prev_dt:
            gap = max(0, round((dt - prev_dt).total_seconds() / 86400.0))
        out.append({
            "tag": x.get("tag", ""),
            "name": x.get("name", ""),
            "date": x.get("published_at", ""),
            "url": x.get("url", ""),
            "type": typ,
            "weight": _POIDS.get(typ, 26),
            "gap_days": gap,
            "prerelease": x.get("prerelease", False),
        })
        prev_ver, prev_dt = ver, dt
    if out:
        out[-1]["latest"] = True
    return out


def _iso(s: str) -> Optional[datetime]:
    try:
        return datetime.fromisoformat((s or "").replace("Z", "+00:00"))
    except Exception:
        return None


def _flesh(cur: float, prev: float) -> dict:
    """Une flèche d'efficience : sens + variation %, sans jugement de valeur.

    Le SENS (hausse/baisse) est neutre ; c'est l'interface qui décide si une
    baisse est bonne (latence) ou mauvaise (cadence). On ne rend donc que le
    fait : de combien ça bouge, et dans quel sens.
    """
    if prev <= 0:
        return {"dir": "flat", "pct": 0.0}
    d = (cur - prev) / prev * 100.0
    return {"dir": "up" if d > 1 else "down" if d < -1 else "flat", "pct": round(d, 1)}


def daily_series(weeks: list[dict]) -> list[int]:
    """Aplati les semaines GitHub en une série quotidienne (30 derniers jours)."""
    days: list[int] = []
    for w in weeks or []:
        d = w.get("days") or []
        days.extend(int(x) for x in d)
    return days[-30:]


def compute(raw: dict, cfg: dict, flows: dict) -> dict:
    """Assemble le résumé complet servi à la carte et au tableau de bord."""
    weeks = raw.get("weeks") or []
    days = daily_series(weeks)

    # ── Cadence & flèches d'efficience (dérivé) ────────────────────────────
    last7 = sum(days[-7:]) if len(days) >= 1 else 0
    prev7 = sum(days[-14:-7]) if len(days) >= 8 else 0
    today = days[-1] if days else 0
    per_day = round(last7 / 7.0, 1)
    weekly_tot = [w.get("total", 0) for w in weeks]
    cur_week = weekly_tot[-1] if weekly_tot else 0
    prev_week = weekly_tot[-2] if len(weekly_tot) >= 2 else 0

    commits_total = raw.get("commits_total") or 0

    # Cadence de release : tags sur ~52 semaines / durée en semaines.
    created = _iso(raw.get("created_at", ""))
    weeks_alive = 1
    if created:
        weeks_alive = max(1, (datetime.now(timezone.utc) - created).days / 7.0)
    tags_total = raw.get("tags_total") or raw.get("releases_total") or 0
    rel_per_week = round(tags_total / weeks_alive, 1) if tags_total else 0.0

    review_h = raw.get("review_latency_h")

    cadence = {
        "today": today,
        "per_day": per_day,
        "last7": last7,
        "daily": days,
        "arrows": {
            # commits/jour : hausse = bien.
            "commits_per_day": {"value": per_day, "good": "up", **_flesh(last7, prev7)},
            # activité hebdo : hausse = bien.
            "weekly": {"value": cur_week, "good": "up", **_flesh(cur_week, prev_week)},
            # latence de revue (h) : baisse = bien. Pas de tendance fiable en un
            # seul instantané — on rend la valeur, la flèche reste neutre.
            "review_latency": {"value": review_h, "good": "down", "dir": "flat", "pct": 0.0},
            # cadence de release : hausse = bien.
            "release_cadence": {"value": rel_per_week, "good": "up", "dir": "flat", "pct": 0.0},
        },
    }

    # ── Émancipation : temps / coût / carbone (ESTIMATIONS) ────────────────
    mpc = float(cfg.get("min_par_commit", 22))
    tjm = float(cfg.get("tarif_horaire", 65))
    co2h = float(cfg.get("co2_kg_par_heure", 0.17))
    km_per_kg = float(cfg.get("km_par_kg_co2", 5.3))  # ~0.19 kg/km thermique

    hours = commits_total * mpc / 60.0
    cost = hours * tjm
    co2_kg = hours * co2h

    eman = {
        "time": {
            "est": True,
            "hours": round(hours),
            "days_dev": round(hours / 24.0, 1),
            "detail": f"{commits_total} commits × ~{int(mpc)} min",
        },
        "cost": {
            "est": True,
            "eur": round(cost),
            "keur": round(cost / 1000.0, 1),
            "detail": f"{round(hours)} h × {int(tjm)} €/h",
        },
        "carbon": {
            "est": True,
            "co2_kg": round(co2_kg, 1),
            "co2_t": round(co2_kg / 1000.0, 2),
            "km_car": round(co2_kg * km_per_kg),
            "detail": "CI + calcul + poste",
        },
    }

    # ── Campagne perpétuelle (SAISI par l'admin) ───────────────────────────
    depenses = float(flows.get("depenses_cumulees", 0) or 0)
    recu = float(flows.get("sponsor_recu", 0) or 0)
    mensuel = float(flows.get("abonnement_mensuel", 0) or 0)
    pct = round(recu / depenses * 100.0, 1) if depenses > 0 else 0.0
    fund = {
        "saisi": True,
        "depenses_cumulees": round(depenses),
        "sponsor_recu": round(recu),
        "abonnement_mensuel": round(mensuel),
        "pct": min(100.0, pct),
        "seeking": recu < depenses,
        "note": flows.get("note", ""),
    }

    # ── Chantiers ouverts / évolutions résiduelles ─────────────────────────
    issues = []
    for it in (raw.get("issues") or [])[:9]:
        labels = [l.lower() for l in (it.get("labels") or [])]
        prio = "new"
        if any(k in labels for k in ("priority", "urgent", "critical", "high", "bug")):
            prio = "hi"
        elif any(k in labels for k in ("enhancement", "feature", "api")):
            prio = "md"
        elif labels:
            prio = "lo"
        issues.append({
            "number": it.get("number"),
            "title": it.get("title", ""),
            "prio": prio,
            "labels": it.get("labels", [])[:3],
            "url": it.get("url", ""),
        })

    return {
        "ok": raw.get("ok", False),
        "repo": {
            "owner": raw.get("owner"),
            "name": raw.get("repo"),
            "full": f"{raw.get('owner')}/{raw.get('repo')}",
            "description": raw.get("description", ""),
            "html_url": raw.get("html_url", ""),
            "created_at": raw.get("created_at", ""),
            "pushed_at": raw.get("pushed_at", ""),
        },
        "totals": {
            "commits": commits_total,
            "contributors": raw.get("contributors"),
            "releases": raw.get("releases_total"),
            "tags": raw.get("tags_total"),
            "stars": raw.get("stars", 0),
            "forks": raw.get("forks", 0),
            "open_issues": raw.get("open_issues"),
            "open_prs": raw.get("open_prs"),
        },
        "cadence": cadence,
        "emancipation": eman,
        "fund": fund,
        "latest_commits": raw.get("latest_commits", []),
        "latest_release": raw.get("latest_release"),
        "evolutions": evolutions(raw),
        "issues": issues,
        "meta": {
            "fetched_at": raw.get("fetched_at"),
            "rate_left": raw.get("rate_left"),
            "error": raw.get("error"),
            "params": {
                "min_par_commit": mpc, "tarif_horaire": tjm,
                "co2_kg_par_heure": co2h, "km_par_kg_co2": km_per_kg,
            },
        },
    }
