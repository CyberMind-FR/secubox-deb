# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Relevés bruts de la LED de supervision (ref #3361).

Lit les compteurs que publient déjà les modules SecuBox (caches JSON, /proc,
base SQLite d'ad-guard en lecture seule). Aucune source n'est obligatoire :
une source absente, illisible ou mal formée donne simplement des clés absentes,
jamais une exception. Le module ne lance aucun processus : `fw.bloques` (somme
des compteurs nftables `sbx_drop_*`) est ajouté par le collecteur, qui appelle
`nft -j list counters` puis `compteurs_nft`.
"""
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

LIMITE_JSON = 4 * 1024 * 1024  # 4 Mio
DELAI_SQLITE_S = 1.0
PREFIXE_NFT = "sbx_drop_"


def _json(chemin: Path):
    """Charge un JSON borné à 4 Mio ; None si absent, trop gros ou invalide."""
    try:
        with open(chemin, "rb") as f:
            brut = f.read(LIMITE_JSON + 1)
        if len(brut) > LIMITE_JSON:
            return None
        return json.loads(brut)
    except (OSError, ValueError, RecursionError):
        return None


def _nombre(valeur):
    """Renvoie la valeur si c'est un entier ou flottant réel (pas un booléen), sinon None."""
    if isinstance(valeur, bool) or not isinstance(valeur, (int, float)):
        return None
    return valeur


def _dict(valeur) -> dict:
    return valeur if isinstance(valeur, dict) else {}


def _proc_net_dev(racine: Path, wan: str, out: dict) -> None:
    """Octets et paquets rx/tx de l'interface WAN d'après /proc/net/dev."""
    try:
        lignes = (racine / "proc/net/dev").read_text().splitlines()
    except (OSError, UnicodeDecodeError):
        return
    for ligne in lignes:
        nom, sep, reste = ligne.partition(":")
        if not sep or nom.strip() != wan:
            continue
        try:
            c = [float(x) for x in reste.split()]
            if len(c) < 10:
                return
            out["reseau.octets_in"], out["fw.paquets_in"] = c[0], c[1]
            out["reseau.octets_out"], out["fw.paquets_out"] = c[8], c[9]
        except ValueError:
            for k in ("reseau.octets_in", "fw.paquets_in", "reseau.octets_out", "fw.paquets_out"):
                out.pop(k, None)
        return


def _conntrack(racine: Path, out: dict) -> None:
    try:
        out["reseau.connexions"] = float(
            (racine / "proc/sys/net/netfilter/nf_conntrack_count").read_text().strip())
    except (OSError, ValueError, UnicodeDecodeError):
        pass


def _metriques(racine: Path, out: dict) -> None:
    d = _json(racine / "var/cache/secubox/metrics-cache.json")
    if not isinstance(d, dict):
        return
    for cle, (groupe, champ) in {
        "waf.requetes": ("connections", "https"),
        "waf.blocages": ("waf", "waf_blocked"),
        "waf.attaques": ("waf", "alerts_today"),
    }.items():
        n = _nombre(_dict(d.get(groupe)).get(champ))
        if n is not None:
            out[cle] = float(n)


def _actor(racine: Path, out: dict) -> None:
    d = _json(racine / "run/secubox/actord-mesures.json")
    mesures = d.get("mesures") if isinstance(d, dict) else None
    if not isinstance(mesures, list):
        return
    niveaux = [_nombre(_dict(m).get("niveau")) for m in mesures]
    niveaux = [n for n in niveaux if n is not None]
    out["actor.evenements"] = float(len(mesures))
    out["actor.suspects"] = float(sum(1 for n in niveaux if n >= 2))
    out["actor.critiques"] = float(sum(1 for n in niveaux if n >= 4))


def _adguard(racine: Path, out: dict) -> None:
    chemin = racine / "var/lib/secubox/ad-guard/ad-guard.db"
    if not chemin.is_file():
        return
    jour = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    try:
        base = sqlite3.connect(f"file:{chemin}?mode=ro", uri=True, timeout=DELAI_SQLITE_S)
        try:
            requetes = base.execute("SELECT MAX(id) FROM detections").fetchone()[0]
            trackers = base.execute("SELECT COUNT(*) FROM detections WHERE timestamp LIKE ?",
                                    (jour + "%",)).fetchone()[0]
            appareils = base.execute("SELECT COUNT(*) FROM devices").fetchone()[0]
        finally:
            base.close()
    except (sqlite3.Error, OSError, ValueError):
        return
    out["adguard.requetes"] = float(requetes or 0)
    out["adguard.trackers"] = float(trackers)
    out["adguard.appareils"] = float(appareils)


def _services(racine: Path, out: dict) -> None:
    d = _json(racine / "var/cache/secubox/health-doctor.json")
    if not isinstance(d, dict):
        return
    checks = d.get("checks")
    ok = _nombre(_dict(d.get("summary")).get("ok"))
    if ok is None or not isinstance(checks, dict):
        return
    degrades = arretes = 0
    for c in checks.values():
        actif = _dict(_dict(c).get("details")).get("systemd_active")
        if not isinstance(actif, bool):
            continue
        if not actif:
            arretes += 1
        elif _dict(c).get("ok") is False:
            degrades += 1
    out["services.actifs"] = float(ok)
    out["services.degrades"] = float(degrades)
    out["services.arretes"] = float(arretes)


def releves(racine: Path = Path("/"), wan: str = "eth2") -> dict[str, float]:
    """Relève les compteurs bruts disponibles ; une source indisponible n'ajoute aucune clé.

    `racine` permet de simuler l'arborescence en test ; `wan` est l'interface
    dont on lit les octets et paquets. `fw.bloques` n'en fait pas partie.
    """
    racine = Path(racine)
    out: dict[str, float] = {}
    for etape in (lambda: _proc_net_dev(racine, wan, out), lambda: _conntrack(racine, out),
                  lambda: _metriques(racine, out), lambda: _actor(racine, out),
                  lambda: _adguard(racine, out), lambda: _services(racine, out)):
        try:
            etape()
        except Exception:  # noqa: BLE001 - aucune source ne doit faire échouer le relevé
            pass
    return out


def compteurs_nft(sortie_json: str) -> float:
    """Somme des paquets des compteurs nftables dont le nom commence par `sbx_drop_`.

    Prend la sortie de `nft -j list counters`. Toute entrée invalide donne 0.0.
    """
    try:
        d = json.loads(sortie_json)
        total = 0.0
        for e in d["nftables"]:
            c = e.get("counter") if isinstance(e, dict) else None
            if not isinstance(c, dict):
                continue
            nom, paquets = c.get("name"), _nombre(c.get("packets"))
            if isinstance(nom, str) and nom.startswith(PREFIXE_NFT) and paquets is not None:
                total += float(paquets)
        return total
    except (TypeError, ValueError, KeyError, RecursionError):
        return 0.0
