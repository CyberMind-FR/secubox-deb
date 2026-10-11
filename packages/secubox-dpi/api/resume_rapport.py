# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Résumé DPI pour le rapport quotidien (#2299).

Le rapport PDF (paquet metrics, utilisateur `secubox`) ne lit pas l'API du DPI : elle demande un jeton. Ce module écrit, atomiquement, un résumé AGRÉGÉ et en lecture seule dans
`/var/cache/secubox/dpi/resume-rapport.json` : les mêmes compteurs que ceux du Hall (stats, usages, pays, appareils, suggestions), tronqués. Une mesure qu'on ne sait pas lire reste absente
(`None`), jamais zéro. Lancé par `secubox-dpi-resume.timer`.
"""
import json
import os
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Callable, Optional

RESUME = Path("/var/cache/secubox/dpi/resume-rapport.json")
TOP = 8


def _lire(f: Callable[[], Any]) -> Any:
    try:
        return f()
    except Exception:  # noqa: BLE001 — une source muette ne doit pas empêcher les autres
        return None


def _liste(v: Any, n: int = TOP) -> Optional[list]:
    return v[:n] if isinstance(v, list) else None


def _appareil(c: dict) -> dict:
    return {"nom": c.get("name") or c.get("device"), "octets": c.get("bytes"), "montant": c.get("up_bytes"), "descendant": c.get("down_bytes"), "flux": c.get("flows"),
            "usages": [{"nom": u.get("name"), "octets": u.get("bytes")} for u in (c.get("usages") or [])[:3]],
            "destinations": [{"hote": d.get("host"), "octets": d.get("bytes")} for d in (c.get("top_dst") or [])[:3]]}


def construire(sources: dict, now: Optional[float] = None) -> dict:
    """`sources` : stats, usage, pays, clients, suggestions — des fonctions sans argument."""
    stats = _lire(sources["stats"])
    usage = _lire(sources["usage"])
    pays = _lire(sources["pays"])
    clients = _lire(sources["clients"])
    sugg = _lire(sources["suggestions"])
    return {
        "genere_le": int(now if now is not None else time.time()),
        "stats": ({"connecte": stats.get("connected"), "flux": stats.get("total_flows"), "octets": stats.get("total_bytes"), "maj": stats.get("updated_at"),
                   "protocoles": [{"nom": p.get("name"), "octets": p.get("bytes"), "pct": p.get("pct")} for p in (stats.get("protocols") or [])[:TOP]]}
                  if isinstance(stats, dict) else None),
        "usages": ([{"nom": u.get("name"), "octets": u.get("bytes"), "pct": u.get("pct")} for u in (usage.get("usages") or [])[:TOP]] if isinstance(usage, dict) else None),
        "pays": ([{"cc": p.get("cc"), "nom": p.get("name"), "octets": p.get("bytes")} for p in _liste(pays, 12)] if isinstance(pays, list) else None),
        "appareils": ([_appareil(c) for c in sorted(clients, key=lambda c: -(c.get("bytes") or 0))[:TOP]] if isinstance(clients, list) else None),
        "appareils_total": len(clients) if isinstance(clients, list) else None,
        "suggestions": ([{"domaine": s.get("domain"), "octets": s.get("bytes"), "raison": s.get("reason")} for s in _liste(sugg, 6)] if isinstance(sugg, list) else None),
    }


def ecrire(resume: dict, chemin: Path = RESUME) -> None:
    chemin.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(chemin.parent), prefix=".resume-")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(resume, f, ensure_ascii=False)
        os.chmod(tmp, 0o640)
        os.replace(tmp, chemin)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def main() -> int:
    try:
        from . import main as M
    except ImportError:  # python3 -m api.resume_rapport depuis la racine du paquet
        import importlib
        M = importlib.import_module("api.main")
    r = construire({"stats": M._derive_stats, "usage": M._derive_usage, "pays": M._derive_countries, "clients": M._derive_clients, "suggestions": M._derive_suggestions})
    if all(r[k] is None for k in ("stats", "usages", "pays", "appareils")):
        print("résumé DPI : aucune source lisible, rien écrit", file=sys.stderr)
        return 1
    ecrire(r)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
