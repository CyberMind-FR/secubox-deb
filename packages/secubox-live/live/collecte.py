# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox-Deb :: live :: collecteur de l'état public du réseau (live.secubox.in, #3351).

Agrège des sources EXISTANTES du maître, en lecture seule, et écrit /var/cache/secubox/live/etat.json (0644) :
- nœuds : la base du pilotage (`pilotage.db`, ouverte en lecture seule « immutable ») + le maître relevé localement ;
- menaces : le journal de sbxwaf (waf-threats.log), par catégorie, par minute et par jour ;
- visites : le cache de secubox-metrics (vhost_stats.json), par jour et par pays ;
- bans actifs : l'état publié par sbxwaf (nft-etat.json) ; DPI : le résumé de secubox-dpi (usages seulement) ;
- développement : l'API publique de GitHub, sans jeton, gardée en cache 10 min.

RÈGLES (page publique) : aucune adresse IP ni privée, aucun nom de compte ni d'appareil, aucun secret. Les pays sont
agrégés. Une source absente ou illisible donne `null` : la page affiche « indisponible », jamais une valeur inventée.
`nettoyer` est la dernière garde : toute chaîne qui contient une adresse est retirée avant l'écriture.
"""
from __future__ import annotations

import datetime as dt
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
ACTIONS_BLOQUANTES = {"block", "ban", "deny", "drop", "reject", "blocked", "banned"}

_RE_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_RE_IPV6 = re.compile(r"(?i)[0-9a-f:]*:[0-9a-f:]*:[0-9a-f:.]*(?:%\w+)?")


@dataclass
class Sources:
    pilotage_db: Path = Path("/var/lib/secubox/pilotage/pilotage.db")
    menaces: list = field(default_factory=lambda: [Path("/var/log/secubox/waf/waf-threats.log"),
                                                   Path("/var/log/secubox/waf/waf-threats.log.1")])
    vhost_stats: Path = Path("/var/cache/secubox/metrics/vhost_stats.json")
    nft_etat: Path = Path("/var/cache/secubox/waf/nft-etat.json")
    dpi: Path = Path("/var/cache/secubox/dpi/resume-rapport.json")
    haproxy_toml: Path = Path("/etc/secubox/haproxy.toml")
    configuration: Path = Path("/etc/secubox/live.toml")
    github_cache: Path = Path("/var/cache/secubox/live/github.json")
    geoip: list = field(default_factory=lambda: [Path("/var/lib/secubox/geoip/GeoLite2-Country.mmdb"),
                                                 Path("/usr/share/GeoIP/GeoLite2-Country.mmdb"),
                                                 Path("/var/lib/GeoIP/GeoLite2-Country.mmdb")])
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
        cx = sqlite3.connect(f"file:{src.pilotage_db}?mode=ro&immutable=1", uri=True)
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


def menaces(src: Sources, maintenant: float):
    """(par catégorie, par minute sur 1 h, par jour, pays d'attaque, total 24 h, bloquées 24 h) — None si aucun journal."""
    lus = False
    cats, pays, jours, bans_j = Counter(), Counter(), Counter(), Counter()
    minutes = [0] * 60
    total24 = bloq24 = 0
    geo = _lecteur_geoip(src.geoip)
    for p in src.menaces:
        try:
            f = open(p, encoding="utf-8", errors="replace")
        except OSError:
            continue
        lus = True
        with f:
            for ligne in f:
                try:
                    e = json.loads(ligne)
                except ValueError:
                    continue
                ts = _horodatage(e.get("timestamp"))
                if ts is None:
                    continue
                action = str(e.get("action") or "").lower()
                bloque = action in ACTIONS_BLOQUANTES
                jours[_jour(ts)] += 1
                if action in ("ban", "banned"):
                    bans_j[_jour(ts)] += 1
                if maintenant - ts <= 86400:
                    total24 += 1
                    bloq24 += bloque
                    cats[str(e.get("category") or "autre").split(":")[0][:40]] += 1
                    if geo is not None:
                        try:
                            cc = geo.country(str(e.get("client_ip"))).country.iso_code
                            if cc:
                                pays[cc] += 1
                        except Exception:  # noqa: BLE001 — adresse privée ou inconnue : pas de pays
                            pass
                if bloque and 0 <= maintenant - ts < 3600:
                    minutes[59 - int((maintenant - ts) // 60)] += 1
    if not lus:
        return None
    return {"categories": [{"categorie": c, "n": n} for c, n in cats.most_common(8)],
            "minutes": [{"rang": i, "bloquees": n} for i, n in enumerate(minutes)],
            "jours": jours, "bans_jours": bans_j,
            "pays": [{"code": c, "n": n} for c, n in pays.most_common(30)] if geo is not None else None,
            "total24": total24, "bloq24": bloq24}


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
    return {"jours": par_jour, "requetes": req, "pays": [{"code": c, "n": n} for c, n in pays.most_common(30)]}


# ---------------------------------------------------------------------------------------------------------------- divers

def bans_actifs(src: Sources) -> Optional[int]:
    d = _json(src.nft_etat)
    if isinstance(d, dict):
        for k in ("total", "bans", "elements", "count", "nombre"):
            v = d.get(k)
            if isinstance(v, int) and not isinstance(v, bool):
                return v
            if isinstance(v, list):
                return len(v)
    return None


def dpi(src: Sources) -> Optional[list]:
    d = _json(src.dpi)
    us = d.get("usages") if isinstance(d, dict) else None
    if not isinstance(us, list):
        return None
    return [{"nom": str(u.get("nom"))[:40], "pct": u.get("pct")} for u in us
            if isinstance(u, dict) and u.get("nom") and isinstance(u.get("pct"), (int, float))][:8] or None


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

def collecter(src: Sources, maintenant: Optional[float] = None, reseau: bool = True) -> dict:
    maintenant = time.time() if maintenant is None else maintenant
    conf = _conf(src.configuration)
    roles = {str(k): str(v) for k, v in (conf.get("roles") or {}).items()}
    materiels = {str(k): str(v) for k, v in (conf.get("materiels") or {}).items()}
    nd = noeuds(src, maintenant, roles, materiels)
    mn = menaces(src, maintenant)
    vs = visites(src)
    jours = sorted(set((vs or {}).get("jours", {})) | set((mn or {}).get("jours", {})))
    histo = [{"jour": j, "visites": (vs or {}).get("jours", {}).get(j, 0) if vs else None,
              "attaques": (mn or {}).get("jours", {}).get(j, 0) if mn else None,
              "bans": (mn or {}).get("bans_jours", {}).get(j, 0) if mn else None} for j in jours]
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
                   "bans_actifs": bans_actifs(src), "disponibilite_30j": None, "sites_publies": sites_publies(src)},
        "noeuds": nd,
        "waf_heure": mn["minutes"] if mn else None,
        "menaces": mn["categories"] if mn else None,
        "cartes": {"attaques": mn["pays"] if mn else None, "visiteurs": vs["pays"] if vs else None},
        "dpi": dpi(src),
        "histo": histo or None,
        "dev": developpement(src, maintenant, reseau),
        "feuille_de_route": [{"nom": str(f.get("nom"))[:60], "etat": str(f.get("etat"))[:30]}
                             for f in (conf.get("feuille_de_route") or []) if isinstance(f, dict)] or None,
    }
    return nettoyer(etat)


def ecrire(cible: Path, donnees) -> None:
    """Écriture atomique (temporaire, fsync, renommage), 0644 : le fichier est public."""
    cible = Path(cible)
    cible.parent.mkdir(parents=True, exist_ok=True)
    tmp = cible.with_name(f".{cible.name}.{os.getpid()}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(donnees, f, ensure_ascii=False, separators=(",", ":"))
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, 0o644)
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
