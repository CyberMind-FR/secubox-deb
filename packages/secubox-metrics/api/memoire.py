# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox-Deb :: metrics :: historique de la memoire de la box (#2146).

Un releve toutes les 5 minutes (timer secubox-metrics-memoire), garde 7 jours en JSON-lignes.
Il surveille surtout la memoire NOYAU non recuperable (`SUnreclaim`) : sur gk2 elle est montee a
4,2 Go sans que rien ne le releve, jusqu'a saturer la box. Les seuils sont des parts de la RAM
(la meme regle vaut pour une box 2 Go et une box 8 Go) ; la CROISSANCE est signalee avant le seuil.

Stdlib seule : le releve ne doit pas peser sur la box qu'il surveille.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

FICHIER = Path("/var/lib/secubox/metrics/memoire.jsonl")
RETENTION_S = 7 * 86400
PAS_S = 300

# Seuils, en part de la RAM : memoire noyau non recuperable, memoire disponible, swap utilise.
SEUIL_NOYAU = 0.10
SEUIL_DISPONIBLE = 0.06
SEUIL_SWAP = 0.25
# Croissance du noyau jugee anormale (Mo/h) sur au moins une demi-heure de releves.
SEUIL_CROISSANCE_MB_H = 50.0
MIN_POINTS = 6

# Étouffement d'un conteneur ou d'un service borné (#3941) : il relit ses pages sans fin au lieu d'être tué.
CGROUPS = Path("/sys/fs/cgroup")
AUDIT = Path("/var/log/secubox/audit.log")
ETAT_ETOUFFEMENT = "etouffement.json"
SEUIL_REFAULTS_S = 1000
SEUIL_PART = 0.93
SEUIL_PSI = 20.0
DUREE_DURABLE_S = 600
MAX_CGROUPS = 400
# Un débit ne se calcule qu'entre deux relevés proches ; au-delà, l'état n'est plus servi non plus.
ECART_MIN_S, ECART_MAX_S = 30, 3 * PAS_S


def _meminfo(chemin: str) -> dict:
    out = {}
    with open(chemin) as f:
        for ligne in f:
            p = ligne.split()
            if len(p) >= 2 and p[1].isdigit():
                out[p[0].rstrip(":")] = int(p[1])
    return out


def releve(meminfo: str = "/proc/meminfo", loadavg: str = "/proc/loadavg",
           maintenant: Optional[float] = None) -> dict:
    """Un releve en Mo (le noyau donne des ko)."""
    m = _meminfo(meminfo)
    total = m.get("MemTotal", 0)
    dispo = m.get("MemAvailable", m.get("MemFree", 0))
    try:
        load1 = float(open(loadavg).read().split()[0])
    except (OSError, ValueError, IndexError):
        load1 = 0.0
    return {
        "t": int(maintenant if maintenant is not None else time.time()),
        "total_mb": total // 1024,
        "used_mb": total // 1024 - dispo // 1024,
        "avail_mb": dispo // 1024,
        "slab_unrecl_mb": m.get("SUnreclaim", 0) // 1024,
        "slab_recl_mb": m.get("SReclaimable", 0) // 1024,
        "swap_mb": max(0, m.get("SwapTotal", 0) - m.get("SwapFree", 0)) // 1024,
        "load1": load1,
    }


def croissance_mb_h(serie: list, cle: str) -> Optional[float]:
    """Pente moyenne (Mo/h) de `cle` entre le premier et le dernier point ; None sous trois points."""
    pts = [(r["t"], r[cle]) for r in serie if cle in r and "t" in r]
    if len(pts) < 3 or pts[-1][0] <= pts[0][0]:
        return None
    return (pts[-1][1] - pts[0][1]) / ((pts[-1][0] - pts[0][0]) / 3600.0)


def alertes(r: dict, serie: Optional[list] = None) -> list:
    """Messages d'alerte pour ce releve (et la croissance sur `serie`, releves recents)."""
    out = []
    total = r.get("total_mb") or 1
    if r.get("slab_unrecl_mb", 0) > SEUIL_NOYAU * total:
        out.append(f"memoire noyau non recuperable a {r['slab_unrecl_mb']} Mo "
                   f"({100 * r['slab_unrecl_mb'] // total} % de la RAM) : fuite probable")
    if r.get("avail_mb", total) < SEUIL_DISPONIBLE * total:
        out.append(f"memoire disponible a {r['avail_mb']} Mo ({100 * r['avail_mb'] // total} % de la RAM)")
    if r.get("swap_mb", 0) > SEUIL_SWAP * total:
        out.append(f"swap utilise a {r['swap_mb']} Mo")
    if serie and len(serie) >= MIN_POINTS:
        g = croissance_mb_h(serie, "slab_unrecl_mb")
        if g is not None and g > SEUIL_CROISSANCE_MB_H:
            out.append(f"memoire noyau non recuperable croit de {g:.0f} Mo/h")
    return out


def lire_historique(chemin: Path = FICHIER, depuis: float = 0) -> list:
    """Les releves plus recents que `depuis` ; une ligne cassee est ignoree, un fichier absent rend []."""
    out = []
    try:
        with open(chemin) as f:
            for ligne in f:
                try:
                    r = json.loads(ligne)
                except ValueError:
                    continue
                if isinstance(r, dict) and r.get("t", 0) >= depuis:
                    out.append(r)
    except OSError:
        return []
    return out


def ajoute(r: dict, chemin: Path = FICHIER, maintenant: Optional[float] = None) -> None:
    """Ajoute un releve et ecarte ce qui a plus de RETENTION_S (reecriture atomique)."""
    chemin = Path(chemin)
    chemin.parent.mkdir(parents=True, exist_ok=True)
    maintenant = maintenant if maintenant is not None else time.time()
    gardes = lire_historique(chemin, depuis=maintenant - RETENTION_S) + [r]
    tmp = chemin.with_name(chemin.name + ".tmp")
    tmp.write_text("".join(json.dumps(x, separators=(",", ":")) + "\n" for x in gardes))
    os.replace(tmp, chemin)


def _lire(chemin: Path) -> str:
    try:
        return chemin.read_text()
    except OSError:
        return ""


def _limite(texte: str) -> Optional[int]:
    t = texte.strip()
    return int(t) if t.isdigit() else None


def _psi_some60(texte: str) -> Optional[float]:
    for ligne in texte.splitlines():
        if ligne.startswith("some "):
            for mot in ligne.split():
                if mot.startswith("avg60="):
                    try:
                        return float(mot[6:])
                    except ValueError:
                        return None
    return None


def _refaults(stat: str) -> Optional[int]:
    vals = [p[1] for p in (x.split() for x in stat.splitlines())
            if len(p) == 2 and p[0] in ("workingset_refault_anon", "workingset_refault_file", "workingset_refault")]
    return sum(int(v) for v in vals if v.isdigit()) if vals else None


def _cgroups(racine: Path):
    """(clé, nom, genre, dossier) : conteneurs LXC, puis services. Un listage de dossier, aucun parcours de processus."""
    n = 0
    for parent, prefixe, suffixe, genre in ((racine, "lxc.payload.", "", "conteneur"),
                                            (racine / "system.slice", "", ".service", "service"),
                                            (racine / "secubox.slice", "", ".service", "service")):
        try:
            noms = sorted(d for d in os.listdir(parent) if d.startswith(prefixe) and d.endswith(suffixe))
        except OSError:
            continue
        for d in noms:
            if n >= MAX_CGROUPS:
                return
            n += 1
            cle = d if parent == racine else f"{parent.name}/{d}"
            yield cle, d[len(prefixe):], genre, parent / d


def _dict(val) -> dict:
    return val if isinstance(val, dict) else {}


def etouffement(racine: Path, precedent: dict, maintenant: float) -> dict:
    """Un releve : refaults/s (contre le releve precedent), PSI some avg60, courant contre limite (frein ou plafond).

    Étouffé : (refaults > 1 000/s ET courant > 93 % de la limite) OU PSI some avg60 > 20."""
    avant, depuis = _dict(precedent.get("refaults")), _dict(precedent.get("depuis"))
    t0 = precedent.get("t")
    ecart = maintenant - t0 if isinstance(t0, (int, float)) else 0
    out = {"t": int(maintenant), "refaults": {}, "depuis": {}, "etouffes": [], "audites": precedent.get("audites", [])}
    for cle, nom, genre, d in _cgroups(Path(racine)):
        psi = _psi_some60(_lire(d / "memory.pressure"))
        limites = [x for x in (_limite(_lire(d / "memory.max")), _limite(_lire(d / "memory.high"))) if x]
        limite = min(limites) if limites else None
        presse = psi is not None and psi > SEUIL_PSI
        if limite is None and genre == "service" and not presse:
            continue
        courant = _limite(_lire(d / "memory.current")) or 0
        total = _refaults(_lire(d / "memory.stat"))
        debit = None
        if total is not None:
            out["refaults"][cle] = total
            prec = avant.get(cle)
            if isinstance(prec, int) and total >= prec and ECART_MIN_S <= ecart <= ECART_MAX_S:
                debit = round((total - prec) / ecart)
        part = courant / limite if limite else None
        if not (presse or (debit is not None and debit > SEUIL_REFAULTS_S and part is not None and part > SEUIL_PART)):
            continue
        debut = depuis.get(cle)
        if not isinstance(debut, (int, float)) or debut > maintenant or ecart > ECART_MAX_S:
            debut = int(maintenant)
        out["depuis"][cle] = debut
        out["etouffes"].append({"cle": cle, "nom": nom, "genre": genre, "refaults_s": debit, "psi_some_avg60": psi,
                                "courant_mb": courant // 1048576, "limite_mb": limite // 1048576 if limite else None,
                                "part": int(100 * part) if part is not None else None,
                                "depuis_s": int(maintenant - debut)})
    return out


def lire_etouffement(chemin: Path = FICHIER) -> dict:
    """L'etat du dernier releve, a cote de l'historique ; absent ou casse : {}."""
    try:
        with open(Path(chemin).with_name(ETAT_ETOUFFEMENT)) as f:
            return _dict(json.load(f))
    except (OSError, ValueError):
        return {}


def _auditer(journal: Path, evenement: str, details: dict) -> None:
    """Une ligne JSON en ajout seul ; le journal commun n'est jamais cree ici."""
    ligne = json.dumps({"ts": datetime.now(timezone.utc).isoformat(), "type": "memoire", "evenement": evenement, **details})
    try:
        fd = os.open(journal, os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW)
        try:
            os.write(fd, (ligne + "\n").encode())
        finally:
            os.close(fd)
    except OSError as e:
        print(f"audit.log non ecrit ({e.__class__.__name__}) : {ligne}", file=sys.stderr)


def suivre_etouffement(chemin: Path, racine: Path, maintenant: float, journal: Path = AUDIT) -> dict:
    """Un releve enregistre ; une ligne d'audit quand l'episode passe dix minutes, une a sa fin."""
    chemin = Path(chemin)
    etat = etouffement(racine, lire_etouffement(chemin), maintenant)
    deja = {c for c in etat["audites"] if isinstance(c, str)} if isinstance(etat["audites"], list) else set()
    actuels = {e["cle"] for e in etat["etouffes"]}
    for e in etat["etouffes"]:
        if e["depuis_s"] >= DUREE_DURABLE_S and e["cle"] not in deja:
            _auditer(journal, "etouffement", e)
            deja.add(e["cle"])
    for c in sorted(deja - actuels):
        _auditer(journal, "fin_etouffement", {"cle": c})
    etat["audites"] = sorted(deja & actuels)
    chemin.parent.mkdir(parents=True, exist_ok=True)
    tmp = chemin.with_name(ETAT_ETOUFFEMENT + ".tmp")
    tmp.write_text(json.dumps(etat, separators=(",", ":")))
    os.replace(tmp, chemin.with_name(ETAT_ETOUFFEMENT))
    return etat


def etouffes(chemin: Path = FICHIER, maintenant: Optional[float] = None) -> list:
    """Les conteneurs et services étouffés au dernier releve ; [] si ce releve est périmé."""
    maintenant = maintenant if maintenant is not None else time.time()
    etat = lire_etouffement(chemin)
    t = etat.get("t")
    if not isinstance(t, (int, float)) or maintenant - t > ECART_MAX_S or not isinstance(etat.get("etouffes"), list):
        return []
    return [e for e in etat["etouffes"] if isinstance(e, dict)]


def etouffes_durables(chemin: Path = FICHIER, maintenant: Optional[float] = None) -> list:
    return [e for e in etouffes(chemin, maintenant) if e.get("depuis_s", 0) >= DUREE_DURABLE_S]


def alerte_etouffement(e: dict) -> str:
    d = [f"{e.get('genre')} {e.get('nom')} étouffé depuis {e.get('depuis_s', 0) // 60} min"]
    if e.get("limite_mb"):
        d.append(f"{e.get('courant_mb')} Mo sur {e['limite_mb']} ({e.get('part')} %)")
    if e.get("refaults_s") is not None:
        d.append(f"{e['refaults_s']} relectures de pages/s")
    if e.get("psi_some_avg60") is not None:
        d.append(f"pression mémoire {e['psi_some_avg60']:.0f} %")
    return " : ".join([d[0], ", ".join(d[1:])]) if len(d) > 1 else d[0]


def vue(heures: float = 24, chemin: Path = FICHIER, maintenant: Optional[float] = None) -> dict:
    """Ce que sert l'API : la serie des `heures` dernieres heures (bornee a 7 jours), les alertes, la croissance."""
    maintenant = maintenant if maintenant is not None else time.time()
    heures = max(0.1, min(float(heures), RETENTION_S / 3600))
    serie = lire_historique(chemin, depuis=maintenant - heures * 3600)
    return {
        "serie": serie,
        "alertes": (alertes(serie[-1], serie[-36:]) if serie else [])
        + [alerte_etouffement(e) for e in etouffes_durables(chemin, maintenant)[:10]],
        "etouffes": etouffes(chemin, maintenant),
        "croissance_noyau_mb_h": croissance_mb_h(serie[-36:], "slab_unrecl_mb"),
        "pas_s": PAS_S,
    }


def main(argv=None) -> int:
    """Point d'entree du timer : un releve, ajoute a l'historique ; les alertes vont au journal."""
    ap = argparse.ArgumentParser()
    ap.add_argument("--meminfo", default="/proc/meminfo")
    ap.add_argument("--loadavg", default="/proc/loadavg")
    ap.add_argument("--fichier", default=str(FICHIER))
    ap.add_argument("--cgroups", default=str(CGROUPS))
    a = ap.parse_args(argv)
    r = releve(a.meminfo, a.loadavg)
    ajoute(r, Path(a.fichier))
    recents = lire_historique(Path(a.fichier), depuis=r["t"] - 3 * 3600)
    for msg in alertes(r, recents):
        print(f"ALERTE memoire : {msg}", file=sys.stderr)
    suivre_etouffement(Path(a.fichier), Path(a.cgroups), time.time())
    for e in etouffes_durables(Path(a.fichier)):
        print(f"ALERTE memoire : {alerte_etouffement(e)}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
