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
import math
import os
import sqlite3
import stat
from datetime import datetime, timedelta, timezone
from pathlib import Path

LIMITE_JSON = 4 * 1024 * 1024  # 4 Mio
DELAI_SQLITE_S = 1.0
PREFIXE_NFT = "sbx_drop_"


REQUETE_TRACKERS = "SELECT COUNT(*) FROM detections WHERE timestamp >= ? AND timestamp < ?"


def _lire(chemin: Path):
    """Lit au plus 4 Mio d'un fichier ordinaire ; None sinon.

    /run/secubox est en 1777 : un autre compte peut y déposer un FIFO ou un
    lien symbolique. Ouverture sans suivre les liens et sans bloquer, descripteur
    exigé ordinaire et non inscriptible par tous, lecture bornée.
    """
    fd = None
    try:
        fd = os.open(chemin, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC)
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_mode & stat.S_IWOTH:
            return None
        brut = os.read(fd, LIMITE_JSON + 1)
        while 0 < len(brut) <= LIMITE_JSON:
            suite = os.read(fd, LIMITE_JSON + 1 - len(brut))
            if not suite:
                break
            brut += suite
        return brut if len(brut) <= LIMITE_JSON else None
    except OSError:
        return None
    finally:
        if fd is not None:
            os.close(fd)


def _json(chemin: Path):
    """Charge un JSON borné à 4 Mio ; None si absent, refusé, trop gros ou invalide."""
    brut = _lire(chemin)
    if brut is None:
        return None
    try:
        return json.loads(brut)
    except (ValueError, RecursionError):
        return None


def _nombre(valeur):
    """Renvoie la valeur si c'est un nombre fini (ni booléen, NaN ni infini), sinon None."""
    if isinstance(valeur, bool) or not isinstance(valeur, (int, float)):
        return None
    if isinstance(valeur, float) and not math.isfinite(valeur):
        return None
    return valeur


def _dict(valeur) -> dict:
    return valeur if isinstance(valeur, dict) else {}


def _proc_net_dev(racine: Path, wan: str, out: dict) -> None:
    """Octets et paquets rx/tx de l'interface WAN d'après /proc/net/dev."""
    brut = _lire(racine / "proc/net/dev")
    if brut is None:
        return
    lignes = brut.decode("utf-8", "replace").splitlines()
    for ligne in lignes:
        nom, sep, reste = ligne.partition(":")
        if not sep or nom.strip() != wan:
            continue
        try:
            c = [float(x) for x in reste.split()]
            if len(c) < 10 or not all(math.isfinite(x) for x in c):
                return
            out["reseau.octets_in"], out["fw.paquets_in"] = c[0], c[1]
            out["reseau.octets_out"], out["fw.paquets_out"] = c[8], c[9]
        except ValueError:
            pass
        return


def _conntrack(racine: Path, out: dict) -> None:
    brut = _lire(racine / "proc/sys/net/netfilter/nf_conntrack_count")
    try:
        n = float(brut.decode("ascii").strip()) if brut is not None else None
    except ValueError:
        return
    if n is not None and math.isfinite(n):
        out["reseau.connexions"] = n


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
    try:
        if not stat.S_ISREG(os.lstat(chemin).st_mode):
            return
    except OSError:
        return
    aujourdhui = datetime.now(timezone.utc).date()
    jour = aujourdhui.isoformat()
    lendemain = (aujourdhui + timedelta(days=1)).isoformat()
    try:
        base = sqlite3.connect(f"file:{chemin}?mode=ro", uri=True, timeout=DELAI_SQLITE_S)
        try:
            requetes = base.execute("SELECT MAX(id) FROM detections").fetchone()[0]
            trackers = base.execute(REQUETE_TRACKERS, (jour, lendemain)).fetchone()[0]
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
    `adguard.requetes` vaut MAX(id) de `detections` : un compteur cumulé (le
    collecteur en dérive le débit).
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


def compteurs_nft(sortie_json: str) -> float | None:
    """Somme des paquets des compteurs nftables dont le nom commence par `sbx_drop_`.

    Prend la sortie de `nft -j list counters`. Sortie illisible ou sans aucune entrée
    « counter » exploitable (nom texte, paquets numériques) : None, jamais 0.0 — un
    zéro ferait un faux pic au relevé valide suivant.
    """
    try:
        d = json.loads(sortie_json)
        total = 0.0
        exploitables = 0
        for e in d["nftables"]:
            c = e.get("counter") if isinstance(e, dict) else None
            if not isinstance(c, dict):
                continue
            nom, paquets = c.get("name"), _nombre(c.get("packets"))
            if not isinstance(nom, str) or paquets is None:
                continue
            exploitables += 1
            if nom.startswith(PREFIXE_NFT):
                total += float(paquets)
        return total if exploitables else None
    except (TypeError, ValueError, KeyError, RecursionError):
        return None
