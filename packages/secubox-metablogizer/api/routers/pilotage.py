# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Poste de pilotage d'un site (#1322) — la vue détail commande chaque maillon.

LA CHAÎNE D'ENREGISTREMENT A SIX MAILLONS, et l'assistant s'arrêtait au premier
cassé sans qu'on puisse reprendre depuis la page du site : `wall.gk2.net` a été
« publié » sans DNS ni certificat, et rien dans la vue ne le montrait. Ce
routeur rend chaque maillon LISIBLE (un verdict par maillon) et ACTIONNABLE
(une route par geste), pour que la page détail soit le tableau de bord de la
chaîne et non un formulaire de métadonnées.

Maillons, dans l'ordre où une requête les traverse :
  1. contenu   — un index.html dans la racine servie ;
  2. domaine   — déclaré dans site.json (ou hérité du répertoire) ;
  3. vhost     — un bloc `server` dans le nginx monolithique (:8900) ;
  4. route     — une entrée sbxwaf (haproxy-routes.json) : c'est l'EXPOSITION
                 WAN ; sans elle le site n'est joignable que sur le LAN ;
  5. dns       — le nom résout, vu d'un résolveur PUBLIC, vers l'IP publique
                 de la box (le résolveur local fait du split-DNS et mentirait) ;
  6. cert      — un certificat servi pour ce nom (wildcard *.gk2 ou dédié).

Tout travail privilégié passe par `secubox-publishctl` (sudo -n), comme dans
publish.py : ce module tourne sans privilège.
"""
from __future__ import annotations

import asyncio
import json
import logging
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from secubox_core.auth import require_jwt

import sites_scan
from publish.certs import is_wildcard_domain, provision_cert
from publish.routing import _sudo_publishctl, apply_route
from routers.publish import BASE_PORT, DEFAULT_DOMAIN_SUFFIX, SITES_ROOT, marque_publie

logger = logging.getLogger("metablogizer.pilotage")
router = APIRouter()

# Crochets déposés par api/main.py (l'importer serait circulaire, cf. publish.py).
regenerer_nginx = None
NGINX_METABLOGS_CONF = Path("/etc/nginx/sites-enabled/metablogizer")
NGINX_ENABLED_DIR = Path("/etc/nginx/sites-enabled")
NGINX_VHOST_DIR = Path("/etc/nginx/sites-available")
SHOTS_CACHE_DIR = Path("/var/cache/secubox/metablogizer/shots")
invalider_cache_sites = lambda: None  # noqa: E731 — remplacé par main

WAF_ROUTES_FILE = Path("/etc/secubox/waf/haproxy-routes.json")
# Le wildcard *.gk2.secubox.in vit dans le dépôt de certs d'HAProxy (haproxy:secubox
# 640 : lisible par le service), pas dans letsencrypt/live.
CERTS_DIRS = (Path("/etc/letsencrypt/live"), Path("/etc/haproxy/certs"),
              Path("/data/haproxy/certs"))
# Résolveurs publics : le résolveur de la box répond 192.168.1.200 pour
# gk2.secubox.in (split-DNS) — un contrôle « vu de l'extérieur » doit sortir.
RESOLVEURS_PUBLICS = ["1.1.1.1", "9.9.9.9"]
# Le nom dont l'adresse publique sert de RÉFÉRENCE : tout site doit résoudre
# vers la même IP que le suffixe par défaut (la box elle-même).
DOMAINE_REFERENCE = DEFAULT_DOMAIN_SUFFIX.lstrip(".")


# ─────────────────────────────────────────────────────────────────────────
# Lecture des maillons
# ─────────────────────────────────────────────────────────────────────────

def _site_dir(name: str) -> Path:
    if not name.replace("-", "").replace("_", "").isalnum():
        raise HTTPException(400, "invalid site name")
    d = SITES_ROOT / name
    if not d.exists():
        raise HTTPException(404, "Site not found")
    return d


def _cfg(site_dir: Path) -> dict:
    return sites_scan.read_site_config(site_dir)


def maillon_contenu(site_dir: Path) -> dict:
    public = site_dir / "public"
    racine = public if public.exists() else site_dir
    index = racine / "index.html"
    return {"ok": index.is_file(), "racine": str(racine),
            "detail": "index.html présent" if index.is_file() else "pas d'index.html dans la racine servie"}


def maillon_vhost(site_dir: Path) -> dict:
    servi = sites_scan.site_est_servi(site_dir, NGINX_METABLOGS_CONF)
    # Un `<nom>.conf` par site est un VESTIGE du modèle un-fichier-par-site : il
    # double le bloc unifié et c'est l'ordre alphabétique qui tranche (#1016).
    vestige = (NGINX_ENABLED_DIR / f"{site_dir.name}.conf").exists()
    return {"ok": servi, "vestige_par_site": vestige,
            "detail": "bloc server dans le nginx unifié" if servi else "aucun bloc server — le domaine tomberait sur le premier bloc du port"}


def lire_routes_waf() -> dict:
    try:
        data = json.loads(WAF_ROUTES_FILE.read_text())
        return data if isinstance(data, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def maillon_route(domain: str, routes: dict | None = None) -> dict:
    routes = lire_routes_waf() if routes is None else routes
    r = routes.get(domain)
    return {"ok": bool(r), "cible": r,
            "detail": f"route sbxwaf → {r[0]}:{r[1]}" if r else "pas de route sbxwaf : joignable sur le LAN seulement"}


def _resoudre(nom: str, rrtype: str) -> tuple[list, str | None]:
    """(adresses, erreur) vu d'un résolveur public. `nxdomain` est distingué
    d'une simple absence d'enregistrement : c'est LA cause à montrer."""
    try:
        import dns.resolver  # dnspython, présent sur la box
        res = dns.resolver.Resolver(configure=False)
        res.nameservers = RESOLVEURS_PUBLICS
        res.lifetime = 4.0
        try:
            return sorted(r.to_text() for r in res.resolve(nom, rrtype)), None
        except dns.resolver.NXDOMAIN:
            return [], "nxdomain"
        except dns.resolver.NoAnswer:
            return [], None
        except Exception as e:  # noqa: BLE001 — délai, SERVFAIL…
            return [], type(e).__name__.lower()
    except ImportError:
        # Repli : dig, présent avec dnsutils.
        try:
            p = subprocess.run(["dig", "+short", "+time=3", "+tries=1", rrtype, nom, f"@{RESOLVEURS_PUBLICS[0]}"],
                               capture_output=True, text=True, timeout=8)
            addrs = [l.strip() for l in p.stdout.splitlines() if l.strip() and not l.startswith(";")]
            return sorted(addrs), None
        except (OSError, subprocess.TimeoutExpired) as e:
            return [], str(e)


def maillon_dns(domain: str) -> dict:
    a, err = _resoudre(domain, "A")
    aaaa, _ = _resoudre(domain, "AAAA")
    attendu, _ = _resoudre(DOMAINE_REFERENCE, "A")
    ok = bool(a) and (not attendu or bool(set(a) & set(attendu)))
    if err == "nxdomain":
        detail = f"NXDOMAIN — aucun enregistrement pour {domain} (à créer chez le registrar)"
    elif not a:
        detail = f"pas d'enregistrement A ({err or 'sans réponse'})"
    elif attendu and not (set(a) & set(attendu)):
        detail = f"résout vers {', '.join(a)} mais la box est {', '.join(attendu)}"
    else:
        detail = f"résout vers {', '.join(a)}"
    return {"ok": ok, "a": a, "aaaa": aaaa, "attendu": attendu, "nxdomain": err == "nxdomain",
            "detail": detail}


def _chemins_cert(domain: str) -> list[Path]:
    noms = [domain]
    if is_wildcard_domain(domain):
        noms.append("*" + DEFAULT_DOMAIN_SUFFIX)
    out = []
    for n in noms:
        out.append(CERTS_DIRS[0] / n / "fullchain.pem")
        for d in CERTS_DIRS[1:]:
            out.append(d / f"{n}.pem")
    return out


def maillon_cert(domain: str) -> dict:
    chemin = next((p for p in _chemins_cert(domain) if p.is_file()), None)
    if chemin is None:
        return {"ok": False, "existe": False, "wildcard": is_wildcard_domain(domain),
                "detail": "aucun certificat pour ce nom"}
    try:
        p = subprocess.run(["openssl", "x509", "-in", str(chemin), "-noout",
                            "-subject", "-issuer", "-enddate", "-ext", "subjectAltName"],
                           capture_output=True, text=True, timeout=5)
    except (OSError, subprocess.TimeoutExpired) as e:
        return {"ok": False, "existe": True, "chemin": str(chemin), "detail": f"openssl : {e}"}
    if p.returncode != 0:
        return {"ok": False, "existe": True, "chemin": str(chemin),
                "detail": f"illisible : {p.stderr.strip()[:120] or 'openssl a échoué'}"}
    info: dict = {"ok": True, "existe": True, "chemin": str(chemin),
                  "wildcard": chemin.name.startswith("*")}
    san = []
    for ligne in p.stdout.splitlines():
        ligne = ligne.strip()
        if ligne.startswith("subject="):
            info["sujet"] = ligne[len("subject="):].strip()
        elif ligne.startswith("issuer="):
            info["emetteur"] = ligne[len("issuer="):].strip()
        elif ligne.startswith("notAfter="):
            brut = ligne[len("notAfter="):].strip()
            try:
                exp = datetime.strptime(brut, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                info["expire"] = exp.date().isoformat()
                info["jours_restants"] = (exp - datetime.now(timezone.utc)).days
            except ValueError:
                info["expire"] = brut
        elif "DNS:" in ligne:
            san += [s.strip()[4:] for s in ligne.split(",") if s.strip().startswith("DNS:")]
    info["san"] = san
    jours = info.get("jours_restants")
    if jours is not None and jours < 0:
        info["ok"] = False
        info["detail"] = f"EXPIRÉ depuis {-jours} j ({info.get('sujet', '')})"
    else:
        info["detail"] = (f"{info.get('sujet', chemin.name)} — expire le {info.get('expire', '?')}"
                          + (f" ({jours} j)" if jours is not None else ""))
    return info


def chaine_du_site(site_dir: Path) -> dict:
    """Les six verdicts + l'état de publication et d'exposition, en un appel."""
    cfg = _cfg(site_dir)
    domain = sites_scan.domaine_du_site(site_dir)
    routes = lire_routes_waf()
    maillons = {
        "contenu": maillon_contenu(site_dir),
        "domaine": {"ok": bool(domain), "valeur": domain,
                    "declare": sites_scan.domaine_est_declare(site_dir),
                    "detail": domain + (" (déclaré)" if sites_scan.domaine_est_declare(site_dir) else " (hérité du répertoire)")},
        "vhost": maillon_vhost(site_dir),
        "route": maillon_route(domain, routes),
        "dns": maillon_dns(domain),
        "cert": maillon_cert(domain),
    }
    intention = cfg.get("published")
    return {
        "name": site_dir.name,
        "domain": domain,
        "aliases": [a for a in (cfg.get("aliases") or []) if isinstance(a, str)],
        # `published` = servi ET voulu ; `intention` seule = ce que dit site.json.
        "published": maillons["vhost"]["ok"] and intention is not False,
        "intention": intention,
        "exposition": "wan" if maillons["route"]["ok"] else "lan",
        "wildcard": is_wildcard_domain(domain),
        "maillons": maillons,
        "ok": all(m["ok"] for m in maillons.values()),
    }


# ─────────────────────────────────────────────────────────────────────────
# Routes de lecture
# ─────────────────────────────────────────────────────────────────────────

@router.get("/site/{name}/chaine", dependencies=[Depends(require_jwt)])
async def get_chaine(name: str):
    site_dir = _site_dir(name)
    # DNS + openssl = réseau et sous-processus : hors de la boucle (#1105).
    return await asyncio.to_thread(chaine_du_site, site_dir)


@router.get("/site/{name}/dns", dependencies=[Depends(require_jwt)])
async def get_dns(name: str):
    site_dir = _site_dir(name)
    domain = sites_scan.domaine_du_site(site_dir)
    return {"domain": domain, **await asyncio.to_thread(maillon_dns, domain)}


# ─────────────────────────────────────────────────────────────────────────
# Gestes
# ─────────────────────────────────────────────────────────────────────────

def _purger_vestige_par_site(name: str) -> bool:
    """Retire le `<nom>.conf` du modèle un-fichier-par-site s'il existe encore :
    il double le bloc unifié, et le générateur s'efface devant lui (#1016)."""
    purge = False
    for p in (NGINX_ENABLED_DIR / f"{name}.conf", NGINX_VHOST_DIR / f"{name}.conf"):
        try:
            if p.is_symlink() or p.exists():
                p.unlink()
                purge = True
        except OSError as e:
            logger.warning("vestige %s non retiré : %s", p, e)
    return purge


def _regenerer() -> dict:
    if regenerer_nginx is None:
        return {"ok": False, "detail": "générateur nginx indisponible"}
    try:
        ok, nombre, message = regenerer_nginx()
    except Exception as e:  # noqa: BLE001 — touche /etc et systemctl
        return {"ok": False, "detail": f"régénération nginx : {e}"}
    return {"ok": bool(ok), "detail": message, "sites": nombre}


def publier(site_dir: Path) -> dict:
    """Publier = voulu (site.json) + servi (bloc nginx) + exposé (route sbxwaf).

    L'exposition WAN est le défaut de l'assistant ; un site déjà restreint au
    LAN (route absente PAR CHOIX) le reste : on n'ajoute la route que si le
    site n'en a jamais eu — l'état LAN explicite est conservé par `exposer`.
    """
    name = site_dir.name
    domain = sites_scan.domaine_du_site(site_dir)
    etapes: dict = {}
    etapes["intention"] = marque_publie(site_dir, True)
    etapes["vestige"] = {"ok": True, "purge": _purger_vestige_par_site(name)}
    etapes["vhost"] = _regenerer()
    if not maillon_route(domain)["ok"]:
        etapes["route"] = apply_route(domain, BASE_PORT)
    invalider_cache_sites()
    return {"ok": bool(etapes["vhost"].get("ok")) and sites_scan.site_est_servi(site_dir, NGINX_METABLOGS_CONF),
            "etapes": etapes, "chaine": chaine_du_site(site_dir)}


def depublier(site_dir: Path) -> dict:
    """Dépublier = ni voulu, ni servi, ni exposé. La route PART avec le bloc :
    une route vers un domaine sans bloc tombe sur le premier bloc du port et
    sert le site d'un voisin (#1016) — pire qu'un 421."""
    name = site_dir.name
    domain = sites_scan.domaine_du_site(site_dir)
    etapes: dict = {}
    etapes["intention"] = marque_publie(site_dir, False)
    etapes["vestige"] = {"ok": True, "purge": _purger_vestige_par_site(name)}
    etapes["vhost"] = _regenerer()
    etapes["route"] = _sudo_publishctl("vhost-del", domain)
    invalider_cache_sites()
    return {"ok": not sites_scan.site_est_servi(site_dir, NGINX_METABLOGS_CONF),
            "etapes": etapes, "chaine": chaine_du_site(site_dir)}


@router.post("/site/{name}/publish", dependencies=[Depends(require_jwt)])
async def post_publish(name: str):
    return await asyncio.to_thread(publier, _site_dir(name))


@router.post("/site/{name}/unpublish", dependencies=[Depends(require_jwt)])
async def post_unpublish(name: str):
    return await asyncio.to_thread(depublier, _site_dir(name))


@router.post("/site/{name}/vhost", dependencies=[Depends(require_jwt)])
async def post_vhost(name: str):
    """Appliquer le vhost après une édition (domaine, alias) : régénère nginx
    et, si le site est exposé, réaligne la route sbxwaf sur le domaine courant."""
    site_dir = _site_dir(name)

    def _appliquer() -> dict:
        domain = sites_scan.domaine_du_site(site_dir)
        etapes = {"vhost": _regenerer()}
        if maillon_route(domain)["ok"]:
            etapes["route"] = apply_route(domain, BASE_PORT)
        invalider_cache_sites()
        return {"ok": bool(etapes["vhost"].get("ok")), "etapes": etapes, "chaine": chaine_du_site(site_dir)}
    return await asyncio.to_thread(_appliquer)


class Exposition(BaseModel):
    wan: bool


@router.post("/site/{name}/exposure", dependencies=[Depends(require_jwt)])
async def post_exposure(name: str, body: Exposition):
    """WAN = route sbxwaf (+ vhost HAProxy) ; LAN = on la retire, le vhost
    nginx reste et le site répond en *.gk2 depuis le réseau local."""
    site_dir = _site_dir(name)

    def _exposer() -> dict:
        domain = sites_scan.domaine_du_site(site_dir)
        if body.wan:
            res = apply_route(domain, BASE_PORT)
            ok = bool(res.get("route_ok"))
        else:
            res = _sudo_publishctl("vhost-del", domain)
            ok = bool(res.get("ok"))
        invalider_cache_sites()
        return {"ok": ok, "exposition": "wan" if maillon_route(domain)["ok"] else "lan",
                "etapes": res, "chaine": chaine_du_site(site_dir)}
    return await asyncio.to_thread(_exposer)


@router.post("/site/{name}/cert", dependencies=[Depends(require_jwt)])
async def post_cert(name: str):
    """(Re)demander le certificat. Wildcard : instantané, attendu. Domaine
    custom : certbot HTTP-01, lent → tâche de fond, la page ré-interroge
    /chaine ensuite (même logique que l'assistant, #1105)."""
    site_dir = _site_dir(name)
    domain = sites_scan.domaine_du_site(site_dir)
    dns = await asyncio.to_thread(maillon_dns, domain)
    if not is_wildcard_domain(domain) and dns.get("nxdomain"):
        # Inutile de consommer une tentative Let's Encrypt (5 échecs/h/nom) :
        # sans DNS, le défi HTTP-01 ne peut pas aboutir.
        return {"ok": False, "mode": "refuse", "detail": dns["detail"], "dns": dns}
    if is_wildcard_domain(domain):
        res = await asyncio.to_thread(provision_cert, domain)
        return {"ok": res.get("mode") != "pending", **res}
    asyncio.create_task(asyncio.to_thread(provision_cert, domain))
    return {"ok": True, "mode": "provisioning",
            "detail": "certbot (webroot HTTP-01) en cours — le certificat arrive en tâche de fond"}


@router.post("/site/{name}/snapshot", dependencies=[Depends(require_jwt)])
async def post_snapshot(name: str):
    """Capturer la vignette MAINTENANT, hors du tour du shotter. Un seul
    chromium à la fois (verrou partagé avec metablog-shots) et jamais sous
    charge : la règle #956 vaut aussi pour une demande explicite."""
    site_dir = _site_dir(name)
    import os
    import shots
    seuil = float(os.environ.get("METABLOG_SHOTS_LOAD_THRESHOLD", shots.DEFAULT_LOAD_THRESHOLD))
    if not shots.load_ok(seuil):
        return {"ok": False, "detail": f"charge trop élevée (> {seuil:g}) — capture différée au shotter"}
    lock = shots.acquire_lock(SHOTS_CACHE_DIR / shots.LOCK_NAME)
    if lock is None:
        return {"ok": False, "detail": "une capture est déjà en cours"}
    try:
        res = await asyncio.wait_for(
            shots.capture_site(SITES_ROOT, SHOTS_CACHE_DIR, site_dir.name), timeout=90)
    except asyncio.TimeoutError:
        res = {"ok": False, "name": name, "error": "délai de capture dépassé (90 s)"}
    finally:
        try:
            lock.release()
        except Exception:  # noqa: BLE001
            pass
    res.setdefault("detail", res.get("error", "vignette rafraîchie" if res.get("ok") else "échec"))
    return res
