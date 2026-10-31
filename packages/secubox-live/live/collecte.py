# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox-Deb :: live :: collecteur de l'état public du réseau (live.secubox.in, #3351).

Agrège des sources EXISTANTES du maître, en lecture seule, et écrit /var/cache/secubox/live/etat.json (0644) :
- nœuds : la base du pilotage (`pilotage.db`, ouverte en lecture seule) + le maître relevé localement ;
- menaces : le journal de sbxwaf (waf-threats.log, .1 et les rotations .N.gz au rattrapage), par catégorie, par minute
  et par jour ; les totaux par jour sont persistés (menaces-etat.json, JOURS_MAX jours) et survivent aux rotations ;
- visites : le cache de secubox-metrics (vhost_stats.json), par jour et par pays ;
- bans : le journal de bans de sbxwaf (bans.jsonl, ban/unban append-only, celui que sbxwaf relit au démarrage pour
  réinjecter ses bans dans nft) : bans posés par jour et bans actifs ; aucun DPI (décision du propriétaire) ;
- développement : l'API publique de GitHub, sans jeton, gardée en cache 10 min.

RÈGLES (page publique) : aucune adresse IP ni privée, aucun nom de compte ni d'appareil, aucun secret. Les pays sont
agrégés. Une source absente ou illisible donne `null` : la page affiche « indisponible », jamais une valeur inventée.
`nettoyer` est la dernière garde : toute chaîne qui contient une adresse est retirée avant l'écriture.
"""
from __future__ import annotations

import datetime as dt
import gzip
import hashlib
import ipaddress
import json
import os
import re
import sqlite3
import subprocess
import time
import tomllib
import urllib.request
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

SORTIE = Path("/var/cache/secubox/live/etat.json")
EN_LIGNE_S = 300                 # un nœud vu il y a moins de 5 min est en ligne
GITHUB_DEPOT = "CyberMind-FR/secubox-deb"
GITHUB_TTL = 600
JOURS_MAX = 400                  # totaux par jour gardés (au-delà, les plus anciens tombent)
ACTIONS_BLOQUANTES = {"block", "ban", "deny", "drop", "reject", "blocked", "banned"}

_RE_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_RE_IPV6 = re.compile(r"(?i)[0-9a-f:]*:[0-9a-f:]*:[0-9a-f:.]*(?:%\w+)?")


@dataclass
class Sources:
    pilotage_db: Path = Path("/var/lib/secubox/pilotage/pilotage.db")
    menaces: list = field(default_factory=lambda: [Path("/var/log/secubox/waf/waf-threats.log"),
                                                   Path("/var/log/secubox/waf/waf-threats.log.1")])
    vhost_stats: Path = Path("/var/cache/secubox/metrics/vhost_stats.json")
    bans: Path = Path("/var/lib/secubox/waf/bans.jsonl")
    haproxy_toml: Path = Path("/etc/secubox/haproxy.toml")
    configuration: Path = Path("/etc/secubox/live.toml")
    github_cache: Path = Path("/var/cache/secubox/live/github.json")
    geoip: list = field(default_factory=lambda: [Path("/var/lib/secubox/geoip/GeoLite2-Country.mmdb"),
                                                 Path("/usr/share/GeoIP/GeoLite2-Country.mmdb"),
                                                 Path("/var/lib/GeoIP/GeoLite2-Country.mmdb")])
    etat_menaces: Path = Path("/var/cache/secubox/live/menaces-etat.json")
    etat_visites: Path = Path("/var/cache/secubox/live/visites-etat.json")
    local_nom: Optional[str] = None


# ---------------------------------------------------------------------------------------------------------------- garde

def _a_une_adresse(s: str) -> bool:
    """Vrai si la chaîne contient une adresse IPv4 ou IPv6 VALIDE (une heure « 08:30:00 » n'en est pas une)."""
    for m in _RE_IPV4.findall(s):
        try:
            ipaddress.ip_address(m)
            return True
        except ValueError:
            pass
    for m in _RE_IPV6.findall(s):
        try:
            ipaddress.ip_address(m.split("%")[0])
            return True
        except ValueError:
            pass
    return False


def nettoyer(obj):
    """Dernière garde avant publication : une chaîne qui contient une adresse IP disparaît (remplacée par null)."""
    if isinstance(obj, dict):
        return {k: nettoyer(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [nettoyer(v) for v in obj]
    if isinstance(obj, str) and _a_une_adresse(obj):
        return None
    return obj


# ---------------------------------------------------------------------------------------------------------------- utilitaires

def _json(p: Path):
    try:
        return json.loads(Path(p).read_text())
    except (OSError, ValueError):
        return None


def _jour(ts: float) -> str:
    return dt.datetime.fromtimestamp(ts, dt.timezone.utc).strftime("%Y-%m-%d")


def _horodatage(s) -> Optional[float]:
    if not isinstance(s, str):
        return None
    try:
        return dt.datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None


def _conf(p: Path) -> dict:
    try:
        with open(p, "rb") as f:
            return tomllib.load(f)
    except (OSError, tomllib.TOMLDecodeError):
        return {}


# ---------------------------------------------------------------------------------------------------------------- nœuds

def marche(secondes) -> Optional[str]:
    """Classe de durée de marche, jamais la valeur exacte (#3351, relecture : l'uptime exact date les redémarrages)."""
    if not isinstance(secondes, (int, float)) or isinstance(secondes, bool) or secondes < 0:
        return None
    if secondes < 86400:
        return "redémarré il y a moins de 24 h"
    if secondes < 7 * 86400:
        j = int(secondes // 86400)
        return f"en marche depuis {j} jour" + ("s" if j > 1 else "")
    sem = round(secondes / (7 * 86400))
    return f"en marche depuis {sem} semaine" + ("s" if sem > 1 else "")


def _maitre_local(nom: str) -> dict:
    """Le maître ne passe pas par le pilotage : relevé local (/proc), sans adresse."""
    n = {"nom": nom, "materiel": None, "etat": "en ligne", "cpu": None, "memoire": None, "uptime_s": None}
    try:
        n["materiel"] = Path("/proc/device-tree/model").read_text().strip("\x00\n ") or None
    except OSError:
        try:
            for ligne in Path("/proc/cpuinfo").read_text().splitlines():
                if ligne.startswith("model name"):
                    n["materiel"] = ligne.split(":", 1)[1].strip()
                    break
        except OSError:
            pass
    try:
        mem = {li.split(":")[0]: int(li.split()[1]) for li in Path("/proc/meminfo").read_text().splitlines() if li.split()[1:2]}
        if mem.get("MemTotal"):
            n["memoire"] = round(100 * (1 - mem.get("MemAvailable", 0) / mem["MemTotal"]))
        n["uptime_s"] = int(float(Path("/proc/uptime").read_text().split()[0]))
        charge = float(Path("/proc/loadavg").read_text().split()[0])
        n["cpu"] = min(100, round(100 * charge / (os.cpu_count() or 1)))
    except (OSError, ValueError, IndexError):
        pass
    return n


def noeuds(src: Sources, maintenant: float, roles: dict, materiels: dict) -> Optional[list]:
    res = []
    if src.local_nom:
        res.append(_maitre_local(src.local_nom))
    try:
        cx = sqlite3.connect(f"file:{src.pilotage_db}?mode=ro", uri=True, timeout=5)
    except sqlite3.Error:
        cx = None
    if cx is not None:
        try:
            for cle, nom, vu_le in cx.execute("SELECT cle, nom, vu_le FROM boites ORDER BY nom"):
                inv = {c: json.loads(v) for c, v in cx.execute(
                    "SELECT chemin, valeur_json FROM inventaire WHERE cle = ? AND (chemin LIKE 'Device.DeviceInfo.%' "
                    "OR chemin = 'Device.X_SECUBOX_Pilotage.Interface')", (cle,))}
                tot = inv.get("Device.DeviceInfo.MemoryStatus.Total")
                libre = inv.get("Device.DeviceInfo.MemoryStatus.X_SECUBOX_Available",
                                inv.get("Device.DeviceInfo.MemoryStatus.Free"))
                en_ligne = maintenant - (vu_le or 0) < EN_LIGNE_S
                etat = "hors ligne"
                if en_ligne:
                    etat = "interface distante" if inv.get("Device.X_SECUBOX_Pilotage.Interface") == "distante" else "en ligne"
                res.append({"nom": str(nom), "materiel": inv.get("Device.DeviceInfo.ModelName"), "etat": etat,
                            "cpu": inv.get("Device.DeviceInfo.ProcessStatus.CPUUsage"),
                            "memoire": round(100 * (1 - libre / tot)) if isinstance(tot, (int, float)) and tot
                            and isinstance(libre, (int, float)) else None,
                            "uptime_s": inv.get("Device.DeviceInfo.UpTime")})
        except (sqlite3.Error, ValueError):
            pass
        finally:
            cx.close()
    if not res:
        return None
    for n in res:
        n["role"] = roles.get(n["nom"], "")
        n["materiel"] = materiels.get(n["nom"], n["materiel"])
        n["marche"] = marche(n.pop("uptime_s", None))
    return res


# ---------------------------------------------------------------------------------------------------------------- menaces

def _lecteur_geoip(chemins):
    for p in chemins:
        if Path(p).exists():
            try:
                import geoip2.database  # noqa: PLC0415
                return geoip2.database.Reader(str(p))
            except Exception:  # noqa: BLE001 — base absente ou illisible : aucun pays
                return None
    return None


def _lignes_nouvelles(chemins, etat: dict):
    """Lignes ajoutées depuis le dernier passage (position + inode par fichier) ; après une rotation, la fin de l'ancien
    fichier (devenu `.1`) est lue d'abord, puis le nouveau depuis le début. Rend (lignes, au_moins_un_fichier_lu)."""
    pos = etat.setdefault("positions", {})
    lignes, lu = [], False
    inodes = {}
    for p in chemins:
        try:
            inodes[str(p)] = os.stat(p).st_ino
        except OSError:
            pass
    for p in reversed(list(chemins)):                 # .1 (ancien) d'abord, puis le courant
        try:
            st = os.stat(p)
        except OSError:
            continue
        lu = True
        cle = str(st.st_ino)
        debut = pos.get(cle, 0)
        if debut > st.st_size:
            debut = 0
        if p != chemins[0] and cle not in pos:
            continue                                  # un .1 jamais suivi : déjà compté avant cette version ou trop ancien
        with open(p, "rb") as f:
            f.seek(debut)
            for brut in f:
                lignes.append(brut.decode("utf-8", "replace"))
            pos[cle] = f.tell()
    etat["positions"] = {k: v for k, v in pos.items() if k in map(str, inodes.values())}
    return lignes, lu


def _archives(courant: Path) -> list:
    """Rotations compressées de logrotate (`.N.gz`), de la plus ancienne à la plus récente."""
    def rang(p: Path) -> int:
        m = re.fullmatch(re.escape(courant.name) + r"\.(\d+)\.gz", p.name)
        return int(m.group(1)) if m else -1
    return sorted((p for p in courant.parent.glob(courant.name + ".*.gz") if rang(p) >= 0), key=rang, reverse=True)


def _premier_jour(p: Path) -> Optional[str]:
    """Jour de la première ligne datée d'un journal (lecture en flux, gzip compris)."""
    try:
        with (gzip.open(p, "rt", errors="replace") if p.suffix == ".gz" else open(p, errors="replace")) as f:
            for i, ligne in enumerate(f):
                try:
                    ts = _horodatage(json.loads(ligne).get("timestamp"))
                except (ValueError, AttributeError):
                    ts = None
                if ts is not None:
                    return _jour(ts)
                if i > 100:
                    return None
    except (OSError, EOFError):
        return None
    return None


def _toutes_les_lignes(chemins):
    for p in chemins:
        try:
            with (gzip.open(p, "rt", errors="replace") if p.suffix == ".gz" else open(p, errors="replace")) as f:
                yield from f
        except (OSError, EOFError):
            continue


def _compter(e: dict, etat: dict, jours: dict, geo) -> None:
    ts = _horodatage(e.get("timestamp"))
    if ts is None:
        return
    action = str(e.get("action") or "").lower()
    bloque = action in ACTIONS_BLOQUANTES
    j = jours.setdefault(_jour(ts), {"total": 0, "bloq": 0})
    j["total"] += 1
    j["bloq"] += bloque
    h = etat["heures"].setdefault(str(int(ts // 3600)), {"total": 0, "bloq": 0, "cats": {}, "pays": {}})
    h["total"] += 1
    h["bloq"] += bloque
    cat = str(e.get("category") or "autre").split(":")[0][:40]
    h["cats"][cat] = h["cats"].get(cat, 0) + 1
    if geo is not None:
        try:
            cc = geo.country(str(e.get("client_ip"))).country.iso_code
        except Exception:  # noqa: BLE001 — adresse privée ou inconnue : pas de pays
            cc = None
        if cc and re.fullmatch(r"[A-Z]{2}", cc):
            h["pays"][cc] = h["pays"].get(cc, 0) + 1
    if bloque:
        m = str(int(ts // 60))
        etat["minutes"][m] = etat["minutes"].get(m, 0) + 1


def _borner(jours: dict) -> dict:
    return dict(sorted(jours.items())[-JOURS_MAX:])


def menaces(src: Sources, maintenant: float):
    """Compteurs persistants (par jour et par heure) mis à jour par incréments du journal de sbxwaf ; None si aucun journal.

    Rattrapage : au premier passage, ou si un journal présent commence avant le premier jour mesuré, tout est relu
    (rotations .N.gz en flux, .1, courant) ; chaque jour prend le maximum de l'ancien total et du recompte (jamais de
    double compte, jamais un jour effacé), puis la lecture reprend par incréments."""
    etat = _json(src.etat_menaces)
    if not isinstance(etat, dict) or etat.get("version") not in (1, 2):
        etat = {}
    etat = {"version": 2, "jours": {k: {"total": int(v.get("total") or 0), "bloq": int(v.get("bloq") or 0)}
                                    for k, v in (etat.get("jours") or {}).items() if isinstance(v, dict)},
            "heures": etat.get("heures") or {}, "minutes": etat.get("minutes") or {},
            "positions": etat.get("positions") or {}, "depuis": etat.get("depuis"), "bans": etat.get("bans")}
    chemins = list(src.menaces)
    geo = _lecteur_geoip(src.geoip)
    presents = [p for p in _archives(chemins[0]) + list(reversed(chemins)) if p.exists()]
    if not presents:
        return None
    debuts = [d for d in (_premier_jour(p) for p in presents) if d]
    plus_ancien = min(debuts) if debuts else None
    if etat["depuis"] is None or (plus_ancien and plus_ancien < etat["depuis"]):
        etat["heures"], etat["minutes"], recompte = {}, {}, {}
        for ligne in _toutes_les_lignes(presents):
            try:
                e = json.loads(ligne)
            except ValueError:
                continue
            if isinstance(e, dict):
                _compter(e, etat, recompte, geo)
        for k, v in recompte.items():
            ancien = etat["jours"].get(k)
            etat["jours"][k] = v if not ancien or v["total"] >= ancien["total"] else ancien
        etat["positions"] = {}
        for p in chemins:
            try:
                st = os.stat(p)
                etat["positions"][str(st.st_ino)] = st.st_size
            except OSError:
                pass
        connus = [d for d in (plus_ancien, etat["depuis"]) if d]
        etat["depuis"] = min(connus) if connus else _jour(maintenant)
    else:
        lignes, _ = _lignes_nouvelles(chemins, etat)
        for ligne in lignes:
            try:
                e = json.loads(ligne)
            except ValueError:
                continue
            if isinstance(e, dict):
                _compter(e, etat, etat["jours"], geo)
    # fenêtres glissantes : 25 h d'heures, 61 min de minutes ; les jours restent (historique), bornés à JOURS_MAX
    etat["heures"] = {k: v for k, v in etat["heures"].items() if int(k) > maintenant // 3600 - 25}
    etat["minutes"] = {k: v for k, v in etat["minutes"].items() if int(k) > maintenant // 60 - 61}
    etat["jours"] = _borner(etat["jours"])
    bans = _sur(_bans, src, etat, maintenant)
    ecrire(src.etat_menaces, etat, mode=0o600)
    h24 = [v for k, v in etat["heures"].items() if int(k) * 3600 > maintenant - 86400]
    cats, pays = Counter(), Counter()
    for v in h24:
        cats.update(v["cats"])
        pays.update(v["pays"])
    m0 = int(maintenant // 60)
    return {"categories": [{"categorie": c, "n": n} for c, n in cats.most_common(8)],
            "minutes": [{"rang": i, "bloquees": etat["minutes"].get(str(m0 - 59 + i), 0)} for i in range(60)],
            "jours": {k: v["total"] for k, v in etat["jours"].items()}, "depuis": etat["depuis"], "bans": bans,
            "pays": [{"code": c, "n": n} for c, n in pays.most_common(30)] if geo is not None else None,
            "total24": sum(v["total"] for v in h24), "bloq24": sum(v["bloq"] for v in h24)}


def _bans(src: Sources, etat: dict, maintenant: float) -> Optional[dict]:
    """Bans posés par jour et bans actifs, d'après le journal de bans de sbxwaf (ban/unban, append-only, jamais tourné).
    Lu par incréments (inode + position). L'état ne garde des adresses qu'une empreinte tronquée, et seulement le temps
    du ban ; rien n'en sort hormis deux comptes."""
    try:
        st = os.stat(src.bans)
    except OSError:
        return None
    b = etat.get("bans") if isinstance(etat.get("bans"), dict) else None
    if b is None or b.get("ino") != st.st_ino or b.get("pos", 0) > st.st_size:
        b = {"ino": st.st_ino, "pos": 0, "jours": (b or {}).get("jours", {}) if b else {}, "actifs": {},
             "depuis": (b or {}).get("depuis")}
        refait = True
    else:
        refait = False
    recompte = {}
    with open(src.bans, "rb") as f:
        f.seek(b["pos"])
        for brut in f:
            try:
                r = json.loads(brut)
                at, ip, action = int(r["at"]), str(r["ip"]), str(r.get("action"))
            except (ValueError, KeyError, TypeError):
                continue
            cle = hashlib.sha256(ip.encode()).hexdigest()[:16]
            if action == "ban":
                recompte[_jour(at)] = recompte.get(_jour(at), 0) + 1
                b["actifs"][cle] = int(r.get("exp") or 0)
                if b["depuis"] is None or _jour(at) < b["depuis"]:
                    b["depuis"] = _jour(at)
            elif action == "unban":
                b["actifs"].pop(cle, None)
        b["pos"] = f.tell()
    for k, n in recompte.items():
        b["jours"][k] = max(n, b["jours"].get(k, 0)) if refait else b["jours"].get(k, 0) + n
    b["jours"] = _borner(b["jours"])
    b["actifs"] = {k: e for k, e in b["actifs"].items() if e == 0 or e > maintenant}
    etat["bans"] = b
    return {"jours": dict(b["jours"]), "actifs": len(b["actifs"]), "depuis": b["depuis"]}


# ---------------------------------------------------------------------------------------------------------------- visites

def visites(src: Sources):
    d = _json(src.vhost_stats)
    if not isinstance(d, dict) or not isinstance(d.get("jours"), dict):
        return None
    par_jour, pays = Counter(), Counter()
    req = {}
    for jour, vh in d["jours"].items():
        if not isinstance(vh, dict):
            continue
        for s in vh.values():
            if isinstance(s, dict):
                par_jour[jour] += int(s.get("visites") or 0)
                req[jour] = req.get(jour, 0) + int(s.get("requetes") or 0)
                for cc, n in (s.get("pays") or {}).items():
                    if re.fullmatch(r"[A-Z]{2}", str(cc)):
                        pays[cc] += int(n or 0)
    # vhost_stats.json ne garde que 30 jours glissants : les totaux par jour (visites, requêtes, pays) sont persistés
    # ici, bornés à JOURS_MAX, pour que l'historique s'allonge. Un jour encore présent dans la source prend le maximum
    # (le jour courant grossit) ; un jour sorti de la source garde sa dernière valeur.
    etat = _json(src.etat_visites)
    if not isinstance(etat, dict) or etat.get("version") != 1:
        etat = {"version": 1, "jours": {}}
    for jour, vh in d["jours"].items():
        if not isinstance(vh, dict) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}", str(jour)):
            continue
        pj = Counter()
        for s in vh.values():
            if isinstance(s, dict):
                pj.update({cc: int(n or 0) for cc, n in (s.get("pays") or {}).items() if re.fullmatch(r"[A-Z]{2}", str(cc))})
        ancien = etat["jours"].get(jour) or {}
        if par_jour[jour] >= int(ancien.get("visites") or 0):
            etat["jours"][jour] = {"visites": par_jour[jour], "requetes": req.get(jour, 0), "pays": dict(pj)}
    etat["jours"] = _borner(etat["jours"])
    ecrire(src.etat_visites, etat, mode=0o600)
    return {"jours": {k: v["visites"] for k, v in etat["jours"].items()}, "requetes": req,
            "pays": [{"code": c, "n": n} for c, n in pays.most_common(30)]}


# ---------------------------------------------------------------------------------------------------------------- divers

def sites_publies(src: Sources) -> Optional[int]:
    try:
        with open(src.haproxy_toml, "rb") as f:
            vh = tomllib.load(f).get("vhosts") or {}
    except (OSError, tomllib.TOMLDecodeError):
        return None
    return sum(1 for v in vh.values() if isinstance(v, dict) and v.get("enabled", True))


def date_production(conf: dict) -> Optional[str]:
    """Date du maître : `mise_en_production` du fichier de configuration, sinon la naissance de /etc/secubox (installation
    initiale), lue par stat ; jamais inventée."""
    v = conf.get("mise_en_production")
    if isinstance(v, (dt.date, str)) and re.fullmatch(r"\d{4}-\d{2}-\d{2}", str(v)):
        return str(v)
    try:
        r = subprocess.run(["stat", "-c", "%W", "/etc/secubox"], capture_output=True, text=True, timeout=5)
        t = int(r.stdout.strip())
        return _jour(t) if t > 0 else None
    except (OSError, ValueError, subprocess.SubprocessError):
        return None


def _github_get(url: str):
    req = urllib.request.Request(url, headers={"Accept": "application/vnd.github+json", "User-Agent": "secubox-live"})
    with urllib.request.urlopen(req, timeout=10) as r:  # noqa: S310 — URL fixe https://api.github.com
        return json.loads(r.read(2_000_000))


def developpement(src: Sources, maintenant: float, reseau: bool) -> Optional[dict]:
    cache = _json(src.github_cache)
    if isinstance(cache, dict) and maintenant - cache.get("le", 0) < GITHUB_TTL:
        return cache.get("dev")
    if not reseau:
        return cache.get("dev") if isinstance(cache, dict) else None
    base = f"https://api.github.com/repos/{GITHUB_DEPOT}"
    try:
        depuis = _jour(maintenant - 7 * 86400)
        fusions = _github_get(f"https://api.github.com/search/issues?q=repo:{GITHUB_DEPOT}+is:pr+is:merged+merged:>={depuis}"
                              "&sort=updated&order=desc&per_page=6")
        issues = _github_get(f"https://api.github.com/search/issues?q=repo:{GITHUB_DEPOT}+is:issue+is:open&per_page=1")
        runs = _github_get(f"{base}/actions/runs?branch=master&per_page=1")
        dernier = (runs.get("workflow_runs") or [{}])[0]
        dev = {"fusions_7j": fusions.get("total_count"), "issues_ouvertes": issues.get("total_count"),
               "ci_master": dernier.get("conclusion") or dernier.get("status"),
               "dernieres": [{"num": i.get("number"), "titre": str(i.get("title"))[:140],
                              "le": (i.get("pull_request") or {}).get("merged_at") or i.get("closed_at")}
                             for i in (fusions.get("items") or [])[:6]]}
    except Exception:  # noqa: BLE001 — GitHub injoignable : on garde l'ancien relevé, sinon rien
        return cache.get("dev") if isinstance(cache, dict) else None
    ecrire(src.github_cache, {"le": maintenant, "dev": dev})
    return dev


# ---------------------------------------------------------------------------------------------------------------- assemblage

def _sur(fn, *a):
    """Une source qui casse (format inattendu) donne None, jamais une collecte perdue."""
    try:
        return fn(*a)
    except (TypeError, ValueError, KeyError, AttributeError, OSError, sqlite3.Error):
        return None


# Liste blanche des champs publiés (relecture #3351) : tout autre champ est retiré avant l'écriture.
CHAMPS = {
    "": {"version", "genere_le", "production", "etat_global", "tuiles", "noeuds", "waf_heure", "menaces", "cartes",
         "histo", "dev", "feuille_de_route"},
    "production": {"depuis", "historique_depuis"},
    "tuiles": {"noeuds_en_ligne", "noeuds_total", "requetes_24h", "menaces_24h", "bloquees_24h", "bans_actifs",
               "disponibilite_30j", "sites_publies"},
    "noeuds": {"nom", "role", "materiel", "etat", "cpu", "memoire", "marche"},
    "waf_heure": {"rang", "bloquees"},
    "menaces": {"categorie", "n"},
    "cartes": {"attaques", "visiteurs"},
    "cartes.*": {"code", "n"},
    "histo": {"jour", "visites", "attaques", "bans"},
    "dev": {"fusions_7j", "issues_ouvertes", "ci_master", "dernieres"},
    "dev.dernieres": {"num", "titre", "le"},
    "feuille_de_route": {"nom", "etat"},
}


def filtrer(obj, chemin: str = ""):
    garde = CHAMPS.get(chemin)
    if isinstance(obj, dict):
        return {k: filtrer(v, (f"{chemin}.{k}" if chemin else k) if f"{chemin}.{k}" in CHAMPS or (not chemin and k in CHAMPS)
                           else ("cartes.*" if chemin == "cartes" else chemin))
                for k, v in obj.items() if garde is None or k in garde}
    if isinstance(obj, list):
        return [filtrer(v, chemin) for v in obj]
    return obj


def collecter(src: Sources, maintenant: Optional[float] = None, reseau: bool = True) -> dict:
    maintenant = time.time() if maintenant is None else maintenant
    conf = _conf(src.configuration)
    roles = {str(k): str(v) for k, v in (conf.get("roles") or {}).items()}
    materiels = {str(k): str(v) for k, v in (conf.get("materiels") or {}).items()}
    publics = [str(n) for n in conf.get("noeuds_publics") or [] if isinstance(n, str)]
    nd = _sur(noeuds, src, maintenant, roles, materiels)
    if nd is not None:
        nd = [n for n in nd if n["nom"] in publics]              # liste blanche : jamais une box non nommée
    mn = _sur(menaces, src, maintenant)
    vs = _sur(visites, src)
    bn = (mn or {}).get("bans")
    jours = sorted(set((vs or {}).get("jours", {})) | set((mn or {}).get("jours", {})) | set((bn or {}).get("jours", {})))

    def serie(d: Optional[dict], depuis: Optional[str], j: str):
        # Jour avant la première mesure de la source : null (« non mesuré »), jamais 0.
        if d is None or depuis is None or j < depuis:
            return None
        return d.get(j, 0)

    vj = (vs or {}).get("jours")
    histo = [{"jour": j, "visites": serie(vj, min(vj) if vj else None, j),
              "attaques": serie((mn or {}).get("jours"), (mn or {}).get("depuis"), j),
              "bans": serie((bn or {}).get("jours"), (bn or {}).get("depuis"), j)} for j in jours]
    aujourd = _jour(maintenant)
    en_ligne = sum(1 for n in nd or [] if n["etat"] != "hors ligne")
    etat = {
        "version": 1,
        "genere_le": int(maintenant),
        "production": {"depuis": date_production(conf), "historique_depuis": jours[0] if jours else None},
        "etat_global": None if nd is None else ("ok" if en_ligne == len(nd) else "degrade"),
        "tuiles": {"noeuds_en_ligne": en_ligne if nd is not None else None, "noeuds_total": len(nd) if nd else None,
                   "requetes_24h": (vs or {}).get("requetes", {}).get(aujourd) if vs else None,
                   "menaces_24h": mn["total24"] if mn else None, "bloquees_24h": mn["bloq24"] if mn else None,
                   "bans_actifs": bn["actifs"] if bn else None, "disponibilite_30j": None,
                   "sites_publies": _sur(sites_publies, src)},
        "noeuds": nd,
        "waf_heure": mn["minutes"] if mn else None,
        "menaces": mn["categories"] if mn else None,
        "cartes": {"attaques": mn["pays"] if mn else None, "visiteurs": vs["pays"] if vs else None},
        "histo": histo or None,
        "dev": _sur(developpement, src, maintenant, reseau),
        "feuille_de_route": [{"nom": str(f.get("nom"))[:60], "etat": str(f.get("etat"))[:30]}
                             for f in (conf.get("feuille_de_route") or []) if isinstance(f, dict)] or None,
    }
    return nettoyer(filtrer(etat))


def ecrire(cible: Path, donnees, mode: int = 0o644) -> None:
    """Écriture atomique (temporaire, fsync, renommage) ; 0644 pour l'état public, 0600 pour l'état interne."""
    cible = Path(cible)
    cible.parent.mkdir(parents=True, exist_ok=True)
    tmp = cible.with_name(f".{cible.name}.{os.getpid()}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(donnees, f, ensure_ascii=False, separators=(",", ":"))
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, mode)
        os.replace(tmp, cible)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise


def main() -> int:
    import socket  # noqa: PLC0415
    src = Sources(local_nom=socket.gethostname().split(".")[0])
    ecrire(SORTIE, collecter(src))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
