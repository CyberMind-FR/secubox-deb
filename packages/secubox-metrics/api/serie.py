# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox-Deb :: metrics :: historique des courbes (#2765, remplace Grafana).

Un relevé par minute (timer secubox-metrics-serie), 7 jours en JSON-lignes. On stocke des COMPTEURS bruts (jiffies de /proc/stat, octets de
/proc/net/dev) : le CPU et les débits se déduisent entre deux relevés à la lecture, donc un redémarrage (compteurs remis à zéro) donne un trou,
jamais un pic négatif ou énorme.

Stdlib seule : le relevé ne doit pas peser sur la box qu'il surveille."""
from __future__ import annotations

import argparse
import json
import os
import time
from pathlib import Path
from typing import Dict, List, Optional

FICHIER = Path("/var/lib/secubox/metrics/series.jsonl")
RETENTION_S = 7 * 86400
PAS_S = 60
MAX_POINTS = 600
MIN_DUREE_S = 60
SERIES = ("cpu", "mem", "charge", "rx", "tx", "conn", "disque")
_EXCLUES = ("lo", "veth", "br", "lxcbr", "docker", "virbr")


def _lire(chemin: Path) -> Optional[str]:
    try:
        return Path(chemin).read_text()
    except OSError:
        return None


def releve(proc="/proc", racine: str = "/", maintenant: Optional[float] = None) -> dict:
    proc = Path(proc)
    r: dict = {"t": float(maintenant if maintenant is not None else time.time()), "cpu_tot": None, "cpu_idle": None, "mem_pct": None, "load1": None,
               "rx": None, "tx": None, "conn": None, "disque_pct": None}
    s = _lire(proc / "stat")
    if s:
        try:
            v = [int(x) for x in s.splitlines()[0].split()[1:9]]
            r["cpu_tot"], r["cpu_idle"] = sum(v), v[3] + v[4]
        except (ValueError, IndexError):
            pass
    s = _lire(proc / "meminfo")
    if s:
        try:
            m = {k: int(x.split()[0]) for k, _, x in (l.partition(":") for l in s.splitlines() if ":" in l)}
            r["mem_pct"] = round(100.0 * (m["MemTotal"] - m["MemAvailable"]) / m["MemTotal"], 1)
        except (KeyError, ValueError, IndexError, ZeroDivisionError):
            pass
    s = _lire(proc / "loadavg")
    if s:
        try:
            r["load1"] = float(s.split()[0])
        except (ValueError, IndexError):
            pass
    s = _lire(proc / "net" / "dev")
    if s:
        rx = tx = 0
        trouve = False
        for l in s.splitlines()[2:]:
            if ":" not in l:
                continue
            nom, _, reste = l.partition(":")
            if nom.strip().startswith(_EXCLUES):
                continue
            v = reste.split()
            try:
                rx += int(v[0])
                tx += int(v[8])
                trouve = True
            except (ValueError, IndexError):
                continue
        if trouve:
            r["rx"], r["tx"] = rx, tx
    n, vu = 0, False
    for nom in ("tcp", "tcp6"):
        s = _lire(proc / "net" / nom)
        if s is None:
            continue
        vu = True
        n += sum(1 for l in s.splitlines()[1:] if len(l.split()) > 3 and l.split()[3] == "01")
    if vu:
        r["conn"] = n
    try:
        st = os.statvfs(racine)
        utilise = st.f_blocks - st.f_bfree
        total = utilise + st.f_bavail
        r["disque_pct"] = round(100.0 * utilise / total, 1) if total > 0 else None
    except OSError:
        pass
    return r


def lire(chemin: Path = FICHIER, depuis: float = 0) -> List[dict]:
    out = []
    try:
        with open(chemin) as f:
            for l in f:
                try:
                    d = json.loads(l)
                except ValueError:
                    continue
                if isinstance(d, dict) and isinstance(d.get("t"), (int, float)) and d["t"] >= depuis:
                    out.append(d)
    except OSError:
        pass
    return out


def ajoute(r: dict, chemin: Path = FICHIER, maintenant: Optional[float] = None) -> None:
    """Ajoute un relevé ; ce qui a plus de RETENTION_S est écarté (réécriture atomique seulement quand le plus vieux dépasse d'une heure, pour ne pas réécrire chaque minute)."""
    chemin = Path(chemin)
    maintenant = float(maintenant if maintenant is not None else r.get("t", time.time()))
    chemin.parent.mkdir(parents=True, exist_ok=True)
    anciens = lire(chemin, 0)
    coupe = maintenant - RETENTION_S
    if anciens and anciens[0]["t"] < coupe - 3600:
        gardes = [d for d in anciens if d["t"] >= coupe] + [r]
        tmp = chemin.with_suffix(".tmp")
        tmp.write_text("".join(json.dumps(d, separators=(",", ":")) + "\n" for d in gardes))
        os.replace(tmp, chemin)
        return
    with open(chemin, "a") as f:
        f.write(json.dumps(r, separators=(",", ":")) + "\n")


def _taux(a: dict, b: dict, cle: str) -> Optional[float]:
    dt = b["t"] - a["t"]
    x, y = a.get(cle), b.get(cle)
    if dt <= 0 or x is None or y is None or y < x:
        return None
    return (y - x) / dt


def _cpu(a: dict, b: dict) -> Optional[float]:
    vals = [a.get("cpu_tot"), b.get("cpu_tot"), a.get("cpu_idle"), b.get("cpu_idle")]
    if any(v is None for v in vals):
        return None
    dt, di = b["cpu_tot"] - a["cpu_tot"], b["cpu_idle"] - a["cpu_idle"]
    if dt <= 0 or di < 0 or di > dt:
        return None
    return round(100.0 * (1.0 - di / dt), 2)


def _derives(brut: List[dict]) -> List[dict]:
    """Un point par relevé (sauf le premier) : valeurs instantanées + CPU et débits déduits du relevé précédent."""
    out = []
    for a, b in zip(brut, brut[1:]):
        out.append({"t": b["t"], "cpu": _cpu(a, b), "mem": b.get("mem_pct"), "charge": b.get("load1"), "rx": _taux(a, b, "rx"), "tx": _taux(a, b, "tx"),
                    "conn": b.get("conn"), "disque": b.get("disque_pct")})
    return out


def vue(duree_s: Optional[float], points: int = 240, chemin: Path = FICHIER, maintenant: Optional[float] = None,
        depuis: Optional[float] = None, jusqua: Optional[float] = None) -> dict:
    """Séries en `points` tranches régulières (moyenne par tranche, `null` quand rien). Fenêtre : les `duree_s` dernières secondes, ou [depuis, jusqua]."""
    maintenant = float(maintenant if maintenant is not None else time.time())
    fin = float(jusqua) if jusqua is not None else maintenant
    deb = float(depuis) if depuis is not None else fin - float(duree_s if duree_s is not None else 3600)
    if fin - deb < MIN_DUREE_S:
        deb = fin - MIN_DUREE_S
    deb = max(deb, fin - RETENTION_S)
    # Jamais plus de tranches que de relevés possibles (un par PAS_S) : des tranches plus fines laissent chaque point isolé entre des tranches vides,
    # et aucune courbe ne se dessine (#2770).
    n = max(2, min(int(points), MAX_POINTS, int((fin - deb) / PAS_S)))
    pas = (fin - deb) / n
    brut = lire(chemin, deb - 2 * PAS_S)
    brut.sort(key=lambda d: d["t"])
    dv = [d for d in _derives(brut) if deb <= d["t"] <= fin]
    tranches: Dict[str, List[List[float]]] = {k: [[] for _ in range(n)] for k in SERIES}
    for d in dv:
        i = min(n - 1, int((d["t"] - deb) / pas))
        for k in SERIES:
            v = d.get(k)
            if v is not None:
                tranches[k][i].append(float(v))
    series = {k: [round(sum(t) / len(t), 2) if t else None for t in tranches[k]] for k in SERIES}
    return {"t": [round(deb + (i + .5) * pas, 1) for i in range(n)], "series": series, "pas_s": round(pas, 1), "duree_s": round(fin - deb, 1),
            "points": len(dv), "releve_s": PAS_S}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--proc", default="/proc")
    ap.add_argument("--fichier", default=str(FICHIER))
    a = ap.parse_args(argv)
    ajoute(releve(a.proc), Path(a.fichier))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
