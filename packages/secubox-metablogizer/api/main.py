"""SecuBox MetaBlogizer API - Static Site Publisher

Three-fold perspective:
1. Components: Nginx runtime + Tor optional
2. Status: Site count, published sites
3. Access: Site URLs and domains

SecuBox is an appliance and network model - distributed peer applications.
"""
import re
import subprocess
import os
import sys
import json
import shutil
from pathlib import Path

# Self-bootstrap api/ onto sys.path so `from site_schema import …` and
# `from rmtree import …` resolve under `uvicorn api.main:app` (where only
# the parent dir is auto-added). Tests use PYTHONPATH=api so the
# insert is a no-op in that path. See #109.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from typing import Optional, List, Dict, Any
from fastapi import FastAPI, Depends, HTTPException, BackgroundTasks, UploadFile, File, Request
from fastapi.responses import FileResponse
from pydantic import BaseModel
from secubox_core.auth import require_jwt
from secubox_core.config import get_config
from secubox_core import screenshots as _screenshots

app = FastAPI(title="SecuBox MetaBlogizer", version="1.2.0")
config = get_config("metablogizer")

SITES_ROOT = Path(config.get("sites_root", "/srv/metablogizer/sites") if config else "/srv/metablogizer/sites")
AUTO_PUBLISH = config.get("auto_publish", True) if config else True
DATA_PATH = Path(config.get("data_path", "/srv/metablogizer") if config else "/srv/metablogizer")
# Vignettes du mur mosaïque (#956) : produites hors-ligne par
# metablog-shots.timer (voir api/shots.py), jamais par ce process. Ce chemin
# ne fait QUE les servir — voir get_site_screenshot() ci-dessous.
SHOTS_CACHE_DIR = Path(os.environ.get("METABLOG_SHOTS_CACHE", "/var/cache/secubox/metablogizer/shots"))
# Site-list cache (#974): produced hors-ligne par metablog-audit.timer
# (api/sites_scan.py), never by this process — GET /sites below only ever
# READS it. Same rationale/pattern as SHOTS_CACHE_DIR above.
SITES_CACHE_PATH = Path(os.environ.get("METABLOG_SITES_CACHE", "/var/cache/secubox/metablogizer/sites.json"))
NGINX_VHOST_DIR = Path("/etc/nginx/sites-available")
NGINX_ENABLED_DIR = Path("/etc/nginx/sites-enabled")
NGINX_METABLOGS_CONF = Path("/etc/nginx/sites-enabled/metablogizer")
BASE_PORT = 8900
DEFAULT_DOMAIN_SUFFIX = ".gk2.secubox.in"
# Internal IP where nginx listens for metablogizer sites
NGINX_BACKEND_IP = "192.168.1.200"
# Un nom de domaine, et rien d'autre : voir alias_du_site().
_NOM_DOMAINE = re.compile(r"[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+")

import logging
import sites_scan
from rmtree import force_remove as _rmtree_force
from webhook import (
    classify_payload,
    git_pull,
    git_commit_push,
    list_deploys as _list_deploys,
    load_secret,
    site_lock,
    verify_signature,
    _record_deploy,
)
import routers.publish
from routers.publish import router as publish_router
app.include_router(publish_router)

logger = logging.getLogger("metablogizer")


def run_cmd(cmd: list, timeout: int = 30) -> tuple:
    """Run command and return (success, stdout, stderr)"""
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return result.returncode == 0, result.stdout.strip(), result.stderr.strip()
    except subprocess.TimeoutExpired:
        return False, "", "Command timed out"
    except Exception as e:
        return False, "", str(e)


def nginx_running() -> bool:
    """Check if nginx is running"""
    success, _, _ = run_cmd(["pgrep", "nginx"])
    return success


# Moved to sites_scan.read_site_config() (#974) — kept as a thin alias here
# because _read_domain() and a handful of per-site detail routes below still
# need a single site's config outside of a full scan.
_load_site_json = sites_scan.read_site_config


# In-memory cache for load_sites(). 166 sites × (enrich+validate+du -sh)
# is ~5-10s per call (measured ~14.6s / 172 sites on the board under load —
# see sites_scan.py docstring). This live path is ONLY for write flows that
# need an up-to-the-second view right after a mutation (site create/delete/
# publish, nginx regen, startup) — never for read-only display, which is
# GET /sites below, served from the out-of-band cache instead (#974).
# Cache for 30s, invalidated by _invalidate_sites_cache() in every write
# path (POST/DELETE/publish).
_SITES_CACHE: Optional[List[dict]] = None
_SITES_CACHE_AT: float = 0.0
_SITES_CACHE_TTL: float = 30.0


def _trigger_sites_cache_refresh() -> Optional[str]:
    """Fire-and-forget `systemctl --no-block start metablog-audit.service`
    (#974). Shared by every write path (via `_invalidate_sites_cache()`
    below) and by `POST /sites/refresh`. Deliberately NEVER calls
    `sites_scan.scan_sites()` / `.main()` inline — that would just move the
    blocking recompute into whichever request happens to trigger it.
    Repeated triggers (e.g. several writes in a row) coalesce: systemd
    ignores/queues a `start` on a unit that's already starting rather than
    running it twice in parallel — same fire-and-forget pattern as
    secubox-hub's `_trigger_cache_refresh()`.

    Returns `None` on success, an error string on failure (sudo/systemctl
    missing — expected in a dev/test sandbox, tolerated everywhere).
    """
    try:
        subprocess.Popen(
            ["sudo", "-n", "/usr/bin/systemctl", "--no-block", "start",
             "metablog-audit.service"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        return None
    except (FileNotFoundError, OSError) as e:
        logger.warning("sites cache refresh trigger failed: %s", e)
        return str(e)


def _invalidate_sites_cache() -> None:
    """Drop the cached site list and kick off an out-of-band cache refresh.

    Without the refresh trigger, a write (create/publish/delete/upload/
    deploy) would be invisible in the Mosaic/Sites tabs for up to 5 minutes
    (the metablog-audit.timer cadence) even though the change is already
    live on disk — the in-memory `_SITES_CACHE` this drops is NOT what
    GET /sites reads anymore (#974), only the on-disk cache is. Triggering
    a rescan here keeps writes visible within a few seconds instead.
    """
    global _SITES_CACHE, _SITES_CACHE_AT
    _SITES_CACHE = None
    _SITES_CACHE_AT = 0.0
    _trigger_sites_cache_refresh()


def load_sites() -> List[dict]:
    """Live, synchronous full scan (cached in-process, 30s TTL).

    Only call this from write paths that need current truth right after a
    mutation (regenerate_nginx_config, startup auto-publish, /republish-all)
    — it forks git+du per site and WILL block the event loop for seconds on
    a loaded board. Read-only display (the Mosaic tab, the Sites tab, the
    dashboard header) must use GET /sites, which reads the out-of-band
    cache written by metablog-audit.timer instead — see sites_scan.py.
    """
    global _SITES_CACHE, _SITES_CACHE_AT
    import time
    now = time.monotonic()
    if _SITES_CACHE is not None and (now - _SITES_CACHE_AT) < _SITES_CACHE_TTL:
        return _SITES_CACHE

    sites_sorted = sites_scan.scan_sites(SITES_ROOT, NGINX_METABLOGS_CONF,
                                          shots_cache_dir=SHOTS_CACHE_DIR)
    _SITES_CACHE = sites_sorted
    _SITES_CACHE_AT = now
    return sites_sorted


def domaines_deja_servis() -> dict:
    """Les domaines declares par un AUTRE vhost nginx active (#1016).

    POURQUOI LE GENERATEUR DOIT S'EFFACER. Cinq domaines etaient declares deux
    fois sur le port 8900 : une fois ici, une fois dans un fichier maintenu a la
    main. nginx garde le PREMIER charge — c'est-a-dire, en pratique, l'ordre
    alphabetique des noms de fichiers. `ganimed.fr.conf` passe avant
    `metablogizer` et gagne ; `wall.ganimed.fr.conf` passe apres et perd. Rien
    dans le code ne le decidait.

    Ce hasard portait a consequence : `ganimed.fr.conf` contient le point ACME
    (`/.well-known/acme-challenge/`) et la redirection `www` vers l'apex, que le
    bloc genere n'a pas. Si le genere l'emportait, le renouvellement de
    certificat casserait — et il ne l'emporte que parce que « g » vient avant
    « m ».

    Un fichier maintenu a la main porte une intention ; un bloc genere n'est
    qu'un defaut. Le second cede donc au premier, explicitement.

    Rend {domaine: fichier}. Un repertoire illisible n'est pas une erreur : on
    rend ce qu'on a pu lire, et le pire cas est le comportement d'avant.
    """
    vus = {}
    try:
        fichiers = sorted(NGINX_ENABLED_DIR.iterdir())
    except OSError:
        return vus
    for f in fichiers:
        # Le fichier genere est justement celui qu'on est en train de refaire :
        # s'y comparer ferait tout disparaitre au deuxieme passage.
        if f.name == NGINX_METABLOGS_CONF.name:
            continue
        try:
            texte = f.read_text(errors="replace")
        except OSError:
            continue
        for m in re.finditer(r"^\s*server_name\s+([^;]+);", texte, re.M):
            for d in m.group(1).split():
                vus.setdefault(d, f.name)
    return vus


def racine_servable(racine: Path) -> tuple:
    """Rattrape un contenu depose un cran trop bas (#1023).

    LE CAS. `zip -r site.zip site/` prefixe tous ses membres par `site/`. Les
    archives deja deballees avant le correctif ont donc leur `index.html` dans
    `public/site/`, jamais dans `public/` : le site est complet, sur le disque,
    et pourtant injoignable.

    ON NE DEPLACE PAS LES FICHIERS DE L'UTILISATEUR. Remonter le contenu d'un
    cran serait une reecriture silencieuse de son depot, irreversible et faite
    dans son dos. On se contente de SERVIR le bon dossier — meme resultat visible,
    aucun octet touche, et un nouveau televersement remet tout d'aplomb puisque
    l'assistant deballe desormais a la source.

    LA CONDITION EST STRICTE : pas d'index a la racine, exactement un
    sous-dossier, et un index dedans. Descendre des qu'on trouve un index
    quelque part choisirait au hasard entre deux candidats, et servirait un
    sous-site a la place du site.

    Rend (racine_a_servir, sous_dossier_ou_None).
    """
    try:
        if (racine / "index.html").exists():
            return str(racine), None
        entrees = [e for e in racine.iterdir() if not e.name.startswith(".")]
    except OSError:
        return str(racine), None
    sous = [e for e in entrees if e.is_dir()]
    if len(sous) != 1 or any(e.is_file() for e in entrees):
        return str(racine), None
    if not (sous[0] / "index.html").exists():
        return str(racine), None
    return str(sous[0]), sous[0].name


def alias_du_site(cfg: dict) -> list:
    """Les noms supplementaires servant le meme site (#1023).

    POURQUOI UN CHAMP PLUTOT QU'UN FICHIER A LA MAIN. `gk2.net` et
    `www.gk2.net` doivent rendre ce que rend `www.gk2.secubox.in`. Ecrire un
    second bloc nginx a cote reviendrait a maintenir deux verites : la
    regeneration suivante ne connaitrait pas la premiere, et le jour ou le site
    change de racine, l'alias resterait pointe sur l'ancienne.

    LA VALIDATION EST ICI, PAS DANS LE GABARIT. Un nom arbitraire recopie dans
    `server_name` peut fermer un point-virgule et ouvrir un bloc : le motif
    n'est pas de la cosmetique, c'est ce qui separe une valeur de configuration
    d'une injection.
    """
    bruts = cfg.get("aliases") or []
    if not isinstance(bruts, list):
        return []
    out = []
    for a in bruts:
        if not isinstance(a, str):
            continue
        a = a.strip().lower().rstrip(".")
        if _NOM_DOMAINE.fullmatch(a) and a not in out:
            out.append(a)
    return out


def regenerate_nginx_config() -> tuple:
    """Regenerate the unified nginx config for all metablogizer sites.

    Returns (success, sites_count, message)
    """
    sites = load_sites()
    if not sites:
        return True, 0, "No sites to publish"

    config_lines = ["# Metablogizer nginx config - auto-generated\n"]

    # Un domaine n'est emis QU'UNE FOIS, et jamais s'il est deja servi ailleurs
    # (#1016). Sans ces deux gardes, nginx ignorait le doublon EN SILENCE : le
    # panneau montrait deux sites publies alors qu'un seul repondait, et c'est
    # l'ordre alphabetique des fichiers qui tranchait.
    deja_servis = domaines_deja_servis()
    emis: dict = {}
    ecartes: list = []
    rattrapes: list = []

    # A EGALITE, L'INTENTION L'EMPORTE SUR LE DEFAUT (#1016). Deux sites
    # peuvent reclamer le meme domaine : l'un parce qu'il l'ECRIT dans son
    # site.json, l'autre parce qu'il HERITE du nom de son repertoire. Sans ce
    # tri, c'est l'ordre de scan qui tranchait — et sur gk2 il donnait
    # `zem.gk2.secubox.in` a un repertoire sans index.html, d'ou un 403 sur un
    # domaine dont un autre site revendiquait explicitement la charge.
    #
    # Le tri est STABLE : deux sites egalement explicites gardent leur ordre,
    # et leur conflit reste signale plutot que tranche en douce.
    sites = sorted(
        sites,
        key=lambda s: 0 if sites_scan.domaine_est_declare(Path(s["directory"])) else 1)

    for site in sites:
        name = site["name"]
        domain = site["domain"]

        if domain in deja_servis:
            # Un fichier maintenu a la main porte une intention — le point ACME
            # et la redirection www de `ganimed.fr.conf`, par exemple. Un bloc
            # genere n'est qu'un defaut : il cede.
            ecartes.append(f"{name} ({domain}) — deja servi par {deja_servis[domain]}")
            continue
        if domain in emis:
            # Deux sites configures sur le meme domaine. Le choix appartient a
            # l'operateur ; le code se contente de le rendre VISIBLE.
            ecartes.append(f"{name} ({domain}) — domaine deja pris par {emis[domain]}")
            continue
        emis[domain] = name

        # LES ALIAS PASSENT PAR LES MEMES GARDES QUE LE DOMAINE PRINCIPAL. Un
        # alias deja servi ailleurs est ecarte SANS emporter le site : on perd
        # l'alias, pas le site — l'inverse serait un remede pire que le mal.
        noms = [domain]
        for a in alias_du_site(site):
            if a in deja_servis:
                ecartes.append(f"{name} (alias {a}) — deja servi par {deja_servis[a]}")
                continue
            if a in emis:
                ecartes.append(f"{name} (alias {a}) — deja pris par {emis[a]}")
                continue
            emis[a] = name
            noms.append(a)
        server_names = " ".join(noms)

        port = site.get("port", BASE_PORT)
        site_dir = Path(site["directory"])

        # Use public/ subdirectory if exists, otherwise site root
        public_dir = site_dir / "public"
        root_dir = str(public_dir) if public_dir.exists() else str(site_dir)
        root_dir, descendu = racine_servable(Path(root_dir))
        if descendu:
            rattrapes.append(f"{name} ({domain}) → {descendu}")

        # LA BONNE QUESTION EST « AI-JE UN INDEX A SERVIR ? », PAS « CE DOSSIER
        # PESE-T-IL QUELQUE CHOSE ? » (#1023). Le critere d'origine exigeait une
        # taille nulle : un dossier de 12 Mio sans `index.html` — le cas exact
        # d'une archive deballee un cran trop bas — echappait donc a la page
        # d'accueil et rendait le `403 Forbidden` nu de nginx, celui qui ne dit
        # ni quel site, ni pourquoi, ni quoi faire. Six sites sur gk2 etaient
        # dans ce cas. Un site pesant mais sans index n'est pas plus servable
        # qu'un site vide ; il est seulement plus trompeur, parce que l'operateur
        # voit les octets et en conclut que ca marche.
        is_empty = not (Path(root_dir) / "index.html").exists()

        if is_empty:
            # LA PAGE D'ACCUEIL EST RENDUE AVEC UN VRAI 404, pas un 200. Un
            # substitut servi en 200 se fait indexer comme s'il ETAIT le site :
            # le jour ou le contenu arrive, les moteurs ont deja retenu la page
            # d'attente. `error_page` + `return 404` donne la belle page ET le
            # bon code ; `X-Robots-Tag` acheve de fermer la porte.
            config_lines.append(f"""
server {{
    listen 0.0.0.0:{port};
    server_name {server_names};
    root /usr/share/secubox/www/metablogizer;
    add_header X-Robots-Tag "noindex, nofollow" always;
    error_page 404 /empty-site.html;
    location = /empty-site.html {{ internal; }}
    location / {{ return 404; }}
}}
""")
        else:
            # Normal site with content
            config_lines.append(f"""
server {{
    listen 0.0.0.0:{port};
    server_name {server_names};
    root {root_dir};
    index index.html;

    # AUCUN FICHIER CACHE N'EST SERVI (#1029).
    #
    # Un site adosse a git porte un `.git/` DANS son docroot : sans cette
    # regle, `https://<site>/.git/config` repond 200 et l'historique complet du
    # depot se reconstitue avec un outil public. Constate sur anibal-amiot.fr.
    # Le depot etait public, donc sans consequence cette fois — la meme
    # configuration sur un depot prive aurait livre son contenu entier.
    #
    # La regle porte sur TOUT nom commencant par un point, pas seulement `.git` :
    # `.env`, `.htpasswd`, `.ssh` posent le meme probleme, et enumerer les cas
    # connus revient a attendre le premier qu'on n'a pas prevu.
    location ~ /\\. {{
        deny all;
        return 404;
    }}

    location / {{
        try_files $uri $uri/ /index.html;
    }}
}}
""")

    # Write config
    try:
        NGINX_METABLOGS_CONF.parent.mkdir(parents=True, exist_ok=True)
        NGINX_METABLOGS_CONF.write_text("".join(config_lines))

        # Test nginx config (use sudo if needed)
        success, _, err = run_cmd(["sudo", "-n", "nginx", "-t"])
        if not success:
            # Try without sudo (if running as root)
            success, _, err = run_cmd(["nginx", "-t"])
            if not success:
                # Skip test and just reload - let systemd handle it
                logger.warning(f"Nginx test skipped: {err}")

        # Reload nginx (use sudo if needed)
        success, _, _ = run_cmd(["sudo", "-n", "systemctl", "reload", "nginx"])
        if not success:
            run_cmd(["systemctl", "reload", "nginx"])

        logger.info(f"Published {len(sites)} metablogizer sites")
        # LES ECARTES SONT DITS, PAS AVALES (#1016). Un doublon signale se
        # corrige ; un doublon muet ne se voit jamais — c'est precisement ce
        # que nginx faisait, et pourquoi le panneau affichait deux sites
        # publies quand un seul repondait.
        for e in ecartes:
            logger.warning("nginx: bloc non emis — %s", e)
        # LE RATTRAPAGE EST DIT, PAS SILENCIEUX. Servir un sous-dossier a la
        # place de la racine est une decision prise a la place de l'operateur :
        # elle doit se lire dans le journal, sinon il cherchera longtemps
        # pourquoi son site repond alors que son docroot est vide.
        for r in rattrapes:
            logger.info("nginx: contenu trouve un cran plus bas, servi tel quel — %s", r)
        publies = len(sites) - len(ecartes)
        if ecartes:
            return True, publies, (f"Published {publies} sites, "
                                   f"{len(ecartes)} ecarte(s) : " + " ; ".join(ecartes))
        return True, publies, f"Published {publies} sites"
    except Exception as e:
        return False, 0, str(e)


# L'ASSISTANT DE PUBLICATION A BESOIN DE CE GENERATEUR (#1023) : sans lui, un
# site publié n'obtient jamais son bloc `server` et tombe sur le premier bloc du
# port 8900. Il ne peut pas l'importer — main importe le routeur au chargement,
# l'import serait circulaire — alors on le lui DEPOSE, une fois défini.
routers.publish.regenerer_nginx = regenerate_nginx_config


# =============================================================================
# STARTUP - Auto-publish on service start
# =============================================================================

@app.on_event("startup")
async def startup_event():
    """Auto-publish all sites when service starts"""
    if AUTO_PUBLISH:
        logger.info("Auto-publishing metablogizer sites on startup...")
        success, count, msg = regenerate_nginx_config()
        if success:
            logger.info(f"Startup auto-publish complete: {msg}")
        else:
            logger.warning(f"Startup auto-publish failed: {msg}")


# =============================================================================
# STATUS - Module state and health
# =============================================================================

@app.get("/status")
async def status():
    """Get unified MetaBlogizer status (public endpoint).

    Site counts are served from the out-of-band cache (#974), same as
    GET /sites below — this header renders on every tab of the same page,
    so it shares the exact bug/fix as the Mosaic tab (recomputing here was
    part of the same 90s+ hang).
    """
    cache = sites_scan.read_cache(SITES_CACHE_PATH)
    sites = cache["sites"]
    published = sum(1 for s in sites if s.get("published"))

    return {
        "module": "metablogizer",
        "version": "1.0.0",
        "enabled": config.get("enabled", True) if config else True,
        "components": {
            "nginx": {
                "name": "nginx",
                "installed": True,
                "running": nginx_running(),
            }
        },
        "site_count": len(sites),
        "published_count": published,
        "sites_root": str(SITES_ROOT),
        "sites_cache_available": cache["available"],
        "sites_cache_age_seconds": cache["cache_age_seconds"],
        "running": nginx_running(),
        "installed": True,
    }


@app.get("/health")
async def health():
    """Health check endpoint"""
    return {
        "status": "ok" if nginx_running() else "degraded",
        "nginx": "ok" if nginx_running() else "down",
    }


@app.get("/health/{domain}")
async def check_site_health(domain: str):
    """Check health of a specific site by probing HTTP/HTTPS"""
    import httpx

    result = {
        "domain": domain,
        "http": None,
        "https": None,
        "waf": None,
        "error": None
    }

    try:
        # Check HTTPS (primary)
        async with httpx.AsyncClient(verify=False, timeout=5.0, follow_redirects=True) as client:
            try:
                resp = await client.get(f"https://{domain}/", headers={"Host": domain})
                result["https"] = resp.status_code
                result["waf"] = resp.headers.get("X-SecuBox-WAF", "unknown")
            except Exception as e:
                result["https"] = 0
                result["error"] = str(e)

            # Check HTTP (secondary)
            try:
                resp = await client.get(f"http://{domain}/", headers={"Host": domain})
                result["http"] = resp.status_code
            except Exception:
                result["http"] = 0

    except Exception as e:
        result["error"] = str(e)

    return result


# =============================================================================
# ACCESS - Sites list and URLs
# =============================================================================

@app.get("/access")
async def get_access():
    """Get all sites with their access URLs (public)"""
    sites = load_sites()
    return {
        "sites": [
            {
                "name": s["name"],
                "domain": s["domain"],
                "url": f"http://{s['domain']}",
                "published": s["published"],
            }
            for s in sites
        ],
        "count": len(sites),
    }


@app.get("/access/detailed")
def get_access_detailed():
    """Get all published sites with certificate info and sizes"""
    import subprocess
    from datetime import datetime

    sites = load_sites()
    detailed = []

    for s in sites:
        if not s.get("published"):
            continue

        domain = s["domain"]
        name = s["name"]
        site_dir = SITES_ROOT / name

        # Get size
        size = "-"
        if site_dir.exists():
            try:
                result = subprocess.run(
                    ["du", "-sh", str(site_dir)],
                    capture_output=True, text=True, timeout=5
                )
                if result.returncode == 0:
                    size = result.stdout.split()[0]
            except:
                pass

        # Check certificate
        cert_info = {"exists": False}
        cert_paths = [
            Path(f"/etc/letsencrypt/live/{domain}/fullchain.pem"),
            Path(f"/etc/haproxy/certs/{domain}.pem"),
        ]

        for cert_path in cert_paths:
            if cert_path.exists():
                cert_info["exists"] = True
                try:
                    result = subprocess.run(
                        ["openssl", "x509", "-in", str(cert_path), "-noout", "-enddate"],
                        capture_output=True, text=True, timeout=5
                    )
                    if result.returncode == 0:
                        expiry_str = result.stdout.strip().replace("notAfter=", "")
                        expiry = datetime.strptime(expiry_str, "%b %d %H:%M:%S %Y %Z")
                        cert_info["expiry"] = expiry.strftime("%Y-%m-%d")
                        cert_info["expired"] = expiry < datetime.now()
                except:
                    pass
                break

        detailed.append({
            "name": name,
            "domain": domain,
            "url": f"https://{domain}",
            "size": size,
            "certificate": cert_info,
        })

    return {"sites": detailed, "count": len(detailed)}


# =============================================================================
# SCREENSHOTS — Mosaic tab thumbnails (#956)
# =============================================================================

@app.get("/site/{name}/screenshot")
async def get_site_screenshot(name: str):
    """Serve the conserved thumbnail for the Mosaic tab.

    PUBLIC — no auth: the wall isn't expected to authenticate just to show an
    image, same call already made (and settled) for the equivalent Streamlit
    endpoint. This route only ever READS a file already produced by
    `metablog-shots.timer` (api/shots.py) — it never triggers a capture, so a
    burst of requests never spends chromium time.

    In production this route is a fallback, never actually hit: nginx serves
    the same file directly from the cache directory via `alias` (see
    `nginx/metablogizer.conf`, #977) before the request ever reaches this
    module's socket — 172 tiles is 172 static-file reads, which nginx does
    without waking this event loop once. This handler stays for local dev
    (`uvicorn --reload`, no nginx in front) and as documentation of the
    contract nginx's static rule must match (404 when absent, never a
    capture).

    `Cache-Control: no-cache` forces the browser to revalidate on every load
    instead of trusting a stale local copy blindly; FastAPI's `FileResponse`
    still attaches `Last-Modified`/`ETag` from the file's own stat, so a
    revalidation that finds nothing changed comes back as a cheap 304 rather
    than re-downloading the PNG. `X-Captured-At` mirrors the same timestamp
    in a form the frontend can read directly. nginx's copy of this route
    trades the revalidation for a long `immutable` Cache-Control instead,
    made safe by the `?v=<captured_at>` the frontend appends to the URL
    (see GET /sites: `screenshot_captured_at`) — a recapture changes the
    URL, so a stale browser cache can never outlive it.
    """
    try:
        p = _screenshots.png_path(SHOTS_CACHE_DIR, name)
    except ValueError:
        raise HTTPException(404, "unknown site")
    if not p.exists():
        raise HTTPException(404, "no screenshot yet")
    meta = _screenshots.read_meta(SHOTS_CACHE_DIR, name)
    return FileResponse(p, media_type="image/png", headers={
        "Cache-Control": "no-cache",
        "X-Captured-At": str(meta.get("captured_at", "")),
    })


# =============================================================================
# SITES MANAGEMENT
# =============================================================================

class SiteCreate(BaseModel):
    name: str
    domain: Optional[str] = None
    template: str = "default"


class SiteUpdate(BaseModel):
    domain: Optional[str] = None
    enabled: Optional[bool] = None


@app.get("/sites", dependencies=[Depends(require_jwt)])
async def list_sites():
    """List all sites — feeds the Mosaic tab and the Sites tab (#974).

    Served from the cache written out-of-band by metablog-audit.timer
    (`sites_scan.py`: git x2 + du per site, ~14.6s for 172 sites measured
    on the board under load, 77% of it forking git). This handler is a
    file read ONLY — it must NEVER fall back to `load_sites()` /
    `sites_scan.scan_sites()` on a cache miss, that would silently
    reintroduce the exact multi-request pileup (single uvicorn worker,
    fully blocking event loop) that made the Mosaic tab time out past 60s.

    `available=False` (cache never written yet, or unreadable) is reported
    explicitly rather than folded into `sites: []` — the frontend must be
    able to tell "no cache yet" apart from "genuinely zero sites".
    """
    cache = sites_scan.read_cache(SITES_CACHE_PATH)
    return {
        "sites": cache["sites"],
        "count": cache["count"],
        "available": cache["available"],
        "reason": cache["reason"],
        "cache_age_seconds": cache["cache_age_seconds"],
        "generated_at": cache["generated_at"],
    }


@app.post("/sites/refresh", dependencies=[Depends(require_jwt)])
async def refresh_sites_cache():
    """Trigger an out-of-band refresh of the GET /sites cache, without
    waiting for the next metablog-audit.timer tick (#974).

    Thin wrapper around `_trigger_sites_cache_refresh()` — the same
    fire-and-forget trigger every write path (create/publish/delete/…)
    already fires via `_invalidate_sites_cache()`. Exposed as its own
    endpoint for the Mosaic tab's manual "🔄 Rafraîchir" button, for when
    nothing changed on this module but the operator still wants a rescan
    (e.g. after fixing a site.json by hand outside the API). Deliberately
    NEVER calls `sites_scan.scan_sites()`/`main()` inline: doing the scan
    here would just move the blocking recompute from GET /sites to this
    endpoint, defeating the point of the cache.
    """
    error = _trigger_sites_cache_refresh()
    if error is None:
        return {"triggered": True}
    return {"triggered": False, "error": error}


@app.get("/site/{name}", dependencies=[Depends(require_jwt)])
async def get_site(name: str):
    """Get site details"""
    site_dir = SITES_ROOT / name
    if not site_dir.exists():
        raise HTTPException(404, "Site not found")

    # Calcul PARTAGE avec le chemin d'affichage (#1012). L'ancien defaut
    # `f"{name}.local"` produisait un `server_name` que nginx ne pouvait
    # associer a aucune requete : le site servait alors le contenu du premier
    # bloc venu, en 200, sans que rien ne le signale.
    domain = sites_scan.domaine_du_site(site_dir)

    # List files
    files = []
    public_dir = site_dir / "public"
    scan_dir = public_dir if public_dir.exists() else site_dir
    for f in scan_dir.rglob("*"):
        if f.is_file():
            files.append(str(f.relative_to(scan_dir)))

    published = (NGINX_ENABLED_DIR / f"{name}.conf").exists()

    return {
        "name": name,
        "domain": domain,
        "directory": str(site_dir),
        "files": files[:100],
        "published": published,
    }


@app.post("/site", dependencies=[Depends(require_jwt)])
async def create_site(site: SiteCreate):
    """Create a new site"""
    SITES_ROOT.mkdir(parents=True, exist_ok=True)
    site_dir = SITES_ROOT / site.name

    if site_dir.exists():
        raise HTTPException(400, "Site already exists")

    # A LA CREATION, un domaine non fourni ne doit pas graver `.local` dans le
    # site.json : c'est cette valeur que la publication relisait ensuite pour
    # ecrire un `server_name` que nginx n'associait a rien (#1012).
    domain = site.domain or f"{site.name}{DEFAULT_DOMAIN_SUFFIX}"

    # Create site
    public_dir = site_dir / "public"
    public_dir.mkdir(parents=True)

    # Create default index
    (public_dir / "index.html").write_text(f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{site.name}</title>
    <style>
        body {{ font-family: -apple-system, sans-serif; background: #0d1117; color: #c9d1d9; display: flex; align-items: center; justify-content: center; min-height: 100vh; margin: 0; }}
        .container {{ text-align: center; }}
        h1 {{ color: #58a6ff; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>{site.name}</h1>
        <p>Your static site is ready!</p>
    </div>
</body>
</html>
""")

    # Save config
    (site_dir / "site.json").write_text(json.dumps({
        "name": site.name,
        "domain": domain,
        "template": site.template,
    }, indent=2))

    _invalidate_sites_cache()
    return {"success": True, "name": site.name, "domain": domain}


@app.delete("/site/{name}", dependencies=[Depends(require_jwt)])
async def delete_site(name: str):
    """Delete a site"""
    site_dir = SITES_ROOT / name
    if not site_dir.exists():
        raise HTTPException(404, "Site not found")

    # Unpublish first
    (NGINX_ENABLED_DIR / f"{name}.conf").unlink(missing_ok=True)
    (NGINX_VHOST_DIR / f"{name}.conf").unlink(missing_ok=True)

    # Sites cloned from Gitea (sub-B of #49) carry a .git subtree whose pack
    # files are 0444 and whose directories may be 0500 — shutil.rmtree then
    # trips on os.open(..., O_RDONLY, dir_fd=topfd). _rmtree_force chmods
    # restricted entries to 0700 and retries.
    _rmtree_force(site_dir)

    _invalidate_sites_cache()
    return {"success": True, "name": name}


# =============================================================================
# PUBLISHING
# =============================================================================

@app.post("/site/{name}/publish", dependencies=[Depends(require_jwt)])
async def publish_site(name: str):
    """Publish a site (create nginx vhost)"""
    site_dir = SITES_ROOT / name
    if not site_dir.exists():
        raise HTTPException(404, "Site not found")

    # Calcul PARTAGE avec le chemin d'affichage (#1012). L'ancien defaut
    # `f"{name}.local"` produisait un `server_name` que nginx ne pouvait
    # associer a aucune requete : le site servait alors le contenu du premier
    # bloc venu, en 200, sans que rien ne le signale.
    domain = sites_scan.domaine_du_site(site_dir)
    # LE VHOST PAR-SITE PORTE LES MEMES ALIAS QUE LE BLOC UNIFIE (#1023).
    # Deux generateurs ecrivent des blocs nginx pour un meme site ; si un seul
    # connaissait les alias, `gk2.net` repondrait ou non selon celui des deux
    # qui a ecrit en dernier — un comportement qu'aucune lecture du site.json
    # ne permettrait de prevoir.
    noms = " ".join([domain] + alias_du_site(_load_site_json(site_dir)))

    public_dir = site_dir / "public"
    root_dir = str(public_dir) if public_dir.exists() else str(site_dir)
    root_dir, _ = racine_servable(Path(root_dir))

    # Generate nginx config
    #
    # LE PORT N'EST PAS 80, ET CE N'EST PAS UN DETAIL (#1012). Sur une board
    # SecuBox, HAProxy detient `0.0.0.0:80` : un vhost qui le reclame empeche
    # nginx de demarrer — `bind() to 0.0.0.0:80 failed (98: Address already in
    # use)`, et TOUS les vhosts de l'hote tombent avec lui.
    #
    # Le defaut restait invisible tant que nginx n'etait que RECHARGE : un
    # rechargement ne rebind pas, le master conservait donc un port pris avant
    # HAProxy. Il n'a eclate qu'au premier redemarrage franc — longtemps apres
    # la publication fautive, ce qui rendait le lien de cause a effet
    # indechiffrable.
    #
    # BASE_PORT est le port sur lequel la chaine HAProxy -> sbxwaf achemine
    # deja ces sites, et celui qu'emploie la configuration unifiee.
    nginx_conf = f"""# MetaBlogizer site: {name}
# Generated by SecuBox MetaBlogizer

server {{
    listen {BASE_PORT};
    server_name {noms};
    root {root_dir};
    index index.html index.htm;

    location / {{
        try_files $uri $uri/ =404;
    }}

    location ~* \\.(js|css|png|jpg|jpeg|gif|ico|svg|woff|woff2)$ {{
        expires 1y;
        add_header Cache-Control "public, immutable";
    }}

    access_log /var/log/nginx/{name}_access.log;
    error_log /var/log/nginx/{name}_error.log;
}}
"""

    NGINX_VHOST_DIR.mkdir(parents=True, exist_ok=True)
    (NGINX_VHOST_DIR / f"{name}.conf").write_text(nginx_conf)

    # Enable
    link = NGINX_ENABLED_DIR / f"{name}.conf"
    if not link.exists():
        link.symlink_to(NGINX_VHOST_DIR / f"{name}.conf")

    # Reload nginx
    run_cmd(["nginx", "-t"])
    run_cmd(["systemctl", "reload", "nginx"])

    _invalidate_sites_cache()
    return {"success": True, "name": name, "domain": domain, "url": f"http://{domain}"}


@app.post("/site/{name}/unpublish", dependencies=[Depends(require_jwt)])
async def unpublish_site(name: str):
    """Unpublish a site"""
    (NGINX_ENABLED_DIR / f"{name}.conf").unlink(missing_ok=True)
    run_cmd(["systemctl", "reload", "nginx"])

    _invalidate_sites_cache()
    return {"success": True, "name": name}


@app.post("/site/{name}/deploy", dependencies=[Depends(require_jwt)])
async def deploy_site(name: str):
    """Manually pull a site's latest content from its git repo and redeploy.

    Same operation as the Gitea push webhook, but triggered on demand from the
    dashboard's per-site update icon. Serialized against webhook deploys via the
    shared per-site lock.
    """
    import asyncio
    import time

    site_dir = SITES_ROOT / name
    if not site_dir.exists():
        raise HTTPException(404, "Site not found")
    if not (site_dir / ".git").exists():
        raise HTTPException(400, "Site has no git repo — nothing to update")

    # Pull whatever branch the working tree is on (webhook uses default_branch;
    # for a manual refresh the currently checked-out branch is the right target).
    try:
        branch = subprocess.run(
            ["git", "-c", f"safe.directory={site_dir}", "-C", str(site_dir),
             "rev-parse", "--abbrev-ref", "HEAD"],
            capture_output=True, text=True, timeout=15, check=True,
        ).stdout.strip() or "main"
    except subprocess.CalledProcessError:
        raise HTTPException(500, "cannot determine git branch")

    lock = await site_lock(name)
    loop = asyncio.get_running_loop()
    t0 = time.monotonic()
    try:
        async with lock:
            old_domain = _read_domain(site_dir)
            old, new = await loop.run_in_executor(None, git_pull, site_dir, branch)
            new_domain = _read_domain(site_dir)
            _invalidate_sites_cache()
            domain_changed = old_domain != new_domain
            if domain_changed:
                await loop.run_in_executor(None, regenerate_nginx_config)
        duration_ms = int((time.monotonic() - t0) * 1000)
        _record_deploy({
            "site": name, "from": old, "to": new,
            "duration_ms": duration_ms, "timestamp": time.time(),
            "domain_changed": domain_changed, "source": "manual",
        })
        logger.info(
            f"manual deploy site={name} from={old[:8]} to={new[:8]} "
            f"duration_ms={duration_ms} domain_changed={domain_changed}"
        )
        return {"success": True, "deployed": name, "from": old, "to": new,
                "updated": old != new, "duration_ms": duration_ms,
                "domain_changed": domain_changed}
    except subprocess.TimeoutExpired:
        raise HTTPException(504, "git-timeout")
    except subprocess.CalledProcessError as e:
        logger.error(f"manual deploy git failed site={name}: {e.stderr}")
        raise HTTPException(500, "git-failed")


@app.post("/republish-all", dependencies=[Depends(require_jwt)])
async def republish_all():
    """Republish all sites by regenerating nginx config"""
    success, count, message = regenerate_nginx_config()
    _invalidate_sites_cache()
    return {
        "success": success,
        "sites_published": count,
        "message": message
    }


# =============================================================================
# DEPLOY WEBHOOK (Gitea push → site update)
# =============================================================================

@app.post("/webhook")
async def webhook(request: Request):
    """Gitea push webhook. HMAC-verified; deploys metablog-* default-branch pushes."""
    import asyncio
    import time
    from fastapi import HTTPException

    body = await request.body()
    sig = request.headers.get("X-Gitea-Signature", "")

    try:
        secret = load_secret()
    except (FileNotFoundError, ValueError) as e:
        logger.error(f"webhook secret unavailable: {e}")
        raise HTTPException(503, "webhook secret not configured")

    if not verify_signature(secret, body, sig):
        raise HTTPException(401)

    try:
        payload = json.loads(body)
    except json.JSONDecodeError:
        raise HTTPException(400, "invalid-json")

    decision, info = classify_payload(payload)
    if decision == "malformed":
        raise HTTPException(400, info.get("reason", "malformed"))
    if decision == "skip":
        logger.info(f"webhook skip {info}")
        return {"skip": info["reason"], **{k: v for k, v in info.items() if k != "reason"}}

    site_name = info["site"]
    branch = info["branch"]
    site_dir = SITES_ROOT / site_name

    if not site_dir.exists():
        logger.info(f"webhook unknown-site {site_name}")
        return {"skip": "unknown-site", "site": site_name}
    if not (site_dir / ".git").exists():
        logger.info(f"webhook no-git-dir {site_name}")
        return {"skip": "no-git-dir", "site": site_name}

    lock = await site_lock(site_name)
    loop = asyncio.get_running_loop()
    t0 = time.monotonic()

    try:
        async with lock:
            old_domain = _read_domain(site_dir)
            old, new = await loop.run_in_executor(None, git_pull, site_dir, branch)
            new_domain = _read_domain(site_dir)

            _invalidate_sites_cache()

            domain_changed = old_domain != new_domain
            if domain_changed:
                await loop.run_in_executor(None, regenerate_nginx_config)

        duration_ms = int((time.monotonic() - t0) * 1000)
        entry = {
            "site": site_name,
            "from": old,
            "to": new,
            "duration_ms": duration_ms,
            "timestamp": time.time(),
            "domain_changed": domain_changed,
            "source": "webhook",
        }
        _record_deploy(entry)
        logger.info(
            f"deploy site={site_name} from={old[:8]} to={new[:8]} "
            f"duration_ms={duration_ms} domain_changed={domain_changed}"
        )
        return {"deployed": site_name, "from": old, "to": new,
                "duration_ms": duration_ms, "domain_changed": domain_changed}

    except subprocess.TimeoutExpired as e:
        logger.error(f"webhook git timeout site={site_name}: {e}")
        raise HTTPException(504, "git-timeout")
    except subprocess.CalledProcessError as e:
        logger.error(f"webhook git failed site={site_name}: {e.stderr}")
        raise HTTPException(500, "git-failed")


@app.get("/deploys", dependencies=[Depends(require_jwt)])
async def deploys():
    """Last 50 deploy records (newest first)."""
    return _list_deploys()


def _read_domain(site_dir: Path) -> str:
    """Best-effort read of site.json:domain. Returns '' on any error."""
    try:
        return (_load_site_json(site_dir) or {}).get("domain", "") or ""
    except Exception:
        return ""


@app.post("/site/{name}/upload", dependencies=[Depends(require_jwt)])
async def upload_content(name: str, file: UploadFile = File(...)):
    """Upload content to a site (.zip / .tar.gz archive, or a single .html).

    Content is written to the directory nginx actually serves for the site.
    The served-root convention (matching regenerate_nginx_config / publish) is
    `<site>/public` when that dir already exists, else the site dir root — so we
    must NOT create public/ here, or we'd silently move the served root out from
    under an already-published site and the upload wouldn't show up.
    """
    import asyncio

    site_dir = SITES_ROOT / name
    if not site_dir.exists():
        site_dir.mkdir(parents=True)

    public_dir = site_dir / "public"
    target_dir = public_dir if public_dir.exists() else site_dir

    fname = (file.filename or "").lower()

    # A bare HTML page becomes the site's index — no temp file / extraction.
    if fname.endswith((".html", ".htm")):
        content = await file.read()
        (target_dir / "index.html").write_bytes(content)
        _invalidate_sites_cache()
        version = await _version_upload(name, site_dir, file.filename or "index.html")
        return {"success": True, "name": name, "kind": "html", "target": str(target_dir), "gitea": version}

    content = await file.read()
    temp_file = site_dir / f"_upload_{file.filename}"
    temp_file.write_bytes(content)

    try:
        if fname.endswith(".zip"):
            import zipfile
            with zipfile.ZipFile(temp_file, 'r') as zf:
                zf.extractall(target_dir)
        elif fname.endswith((".tar.gz", ".tgz")):
            import tarfile
            with tarfile.open(temp_file, 'r:gz') as tf:
                tf.extractall(target_dir)
        else:
            temp_file.unlink(missing_ok=True)
            raise HTTPException(400, "Unsupported format. Use .zip, .tar.gz or .html")

        temp_file.unlink()
    except HTTPException:
        raise
    except Exception as e:
        temp_file.unlink(missing_ok=True)
        raise HTTPException(400, f"Failed to extract: {e}")

    _invalidate_sites_cache()
    version = await _version_upload(name, site_dir, file.filename or "archive")
    return {"success": True, "name": name, "kind": "archive", "target": str(target_dir), "gitea": version}


async def _version_upload(name: str, site_dir: Path, filename: str) -> dict:
    """Commit + push this upload into the site's Gitea repo as a new version.

    Runs under the shared per-site lock so it serializes against webhook/manual
    deploy pulls, and off the event loop (git blocks). Best-effort: a Gitea
    failure is reported in the response but never fails the upload itself.
    """
    import time
    lock = await site_lock(name)
    loop = asyncio.get_running_loop()
    # A monotonic stamp keeps commit messages unique/ordered without needing
    # wall-clock parsing; the operator sees "upload: <file>" + a counter.
    message = f"upload: {filename}"
    try:
        async with lock:
            return await loop.run_in_executor(None, git_commit_push, site_dir, message)
    except Exception as e:  # never let versioning break the upload response
        logger.warning(f"gitea version wrapper failed site={name}: {e}")
        return {"pushed": False, "committed": False, "commit": None, "reason": "error"}


# =============================================================================
# MIGRATION
# =============================================================================

class MigrateRequest(BaseModel):
    source: str = "192.168.255.1"


@app.post("/migrate", dependencies=[Depends(require_jwt)])
async def migrate(req: MigrateRequest, background_tasks: BackgroundTasks):
    """Migrate MetaBlogizer data from OpenWrt source"""
    def do_migrate():
        subprocess.run(["/usr/sbin/metablogizerctl", "migrate", req.source],
                      stdout=open("/var/log/metablogizer-migrate.log", "w"),
                      stderr=subprocess.STDOUT)

    background_tasks.add_task(do_migrate)
    return {"success": True, "message": f"Migration from {req.source} started"}


# =============================================================================
# LOGS & QR
# =============================================================================

@app.get("/logs/{name}", dependencies=[Depends(require_jwt)])
async def get_logs(name: str, lines: int = 100):
    """Get access logs for a site"""
    log_file = Path(f"/var/log/nginx/{name}_access.log")
    logs = []

    if log_file.exists():
        success, out, _ = run_cmd(["tail", f"-n{lines}", str(log_file)])
        if success:
            logs = out.split("\n")

    return {"name": name, "logs": logs}


@app.get("/site/{name}/qrcode", dependencies=[Depends(require_jwt)])
async def get_qrcode(name: str):
    """Generate QR code for site URL"""
    site_dir = SITES_ROOT / name
    if not site_dir.exists():
        raise HTTPException(404, "Site not found")

    # Calcul PARTAGE avec le chemin d'affichage (#1012). L'ancien defaut
    # `f"{name}.local"` produisait un `server_name` que nginx ne pouvait
    # associer a aucune requete : le site servait alors le contenu du premier
    # bloc venu, en 200, sans que rien ne le signale.
    domain = sites_scan.domaine_du_site(site_dir)

    url = f"http://{domain}"

    try:
        import qrcode
        import base64
        from io import BytesIO

        qr = qrcode.make(url)
        buffer = BytesIO()
        qr.save(buffer, format="PNG")
        b64 = base64.b64encode(buffer.getvalue()).decode()

        return {"qrcode": f"data:image/png;base64,{b64}", "url": url}
    except ImportError:
        return {"url": url, "error": "qrcode module not installed"}


@app.get("/site/{name}/export", dependencies=[Depends(require_jwt)])
async def export_site(name: str):
    """Export complete site package as ZIP archive

    Includes:
    - Site content (public/)
    - site.json config
    - nginx.conf (generated)
    - haproxy.cfg (snippet for HAProxy vhost)
    - certificate.pem (if available)
    - README.md (republishing instructions)
    """
    from fastapi.responses import FileResponse
    import zipfile
    import tempfile
    from datetime import datetime

    site_dir = SITES_ROOT / name
    if not site_dir.exists():
        raise HTTPException(404, "Site not found")

    # Read site config
    domain = f"{name}.gk2.secubox.in"
    config_file = site_dir / "site.json"
    site_config = {"name": name, "domain": domain}
    if config_file.exists():
        try:
            site_config = json.loads(config_file.read_text())
            domain = site_config.get("domain", domain)
        except:
            pass

    # Create temporary ZIP file
    with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as tmp:
        with zipfile.ZipFile(tmp.name, 'w', zipfile.ZIP_DEFLATED) as zf:
            # 1. Site content
            for file_path in site_dir.rglob("*"):
                if file_path.is_file():
                    arcname = f"content/{file_path.relative_to(site_dir)}"
                    zf.write(file_path, arcname)

            # 2. Site config
            zf.writestr("config/site.json", json.dumps(site_config, indent=2))

            # 3. Nginx config
            public_dir = site_dir / "public"
            root_dir = str(public_dir) if public_dir.exists() else str(site_dir)
            nginx_conf = f"""# Nginx config for {name}
# Generated by SecuBox MetaBlogizer
# Import: cp nginx.conf /etc/nginx/sites-available/{name}.conf

server {{
    listen 80;
    listen 443 ssl http2;
    server_name {domain};

    # SSL (adjust paths if using custom certs)
    ssl_certificate /etc/letsencrypt/live/{domain}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/{domain}/privkey.pem;

    root {root_dir};
    index index.html index.htm;

    location / {{
        try_files $uri $uri/ /index.html =404;
    }}

    # Cache static assets
    location ~* \\.(js|css|png|jpg|jpeg|gif|ico|svg|woff|woff2)$ {{
        expires 1y;
        add_header Cache-Control "public, immutable";
    }}

    access_log /var/log/nginx/{name}_access.log;
    error_log /var/log/nginx/{name}_error.log;
}}
"""
            zf.writestr("config/nginx.conf", nginx_conf)

            # 4. HAProxy config snippet
            haproxy_conf = f"""# HAProxy vhost snippet for {name}
# Add ACL and use_backend rules to your haproxy.cfg frontend

# ACL (add to frontend section)
acl host_{name.replace('.', '_').replace('-', '_')} hdr(host) -i {domain}

# Backend routing (add after ACLs)
use_backend mitmproxy_inspector if host_{name.replace('.', '_').replace('-', '_')}

# Note: Requires mitmproxy route configuration
# Add to /srv/mitmproxy/haproxy-routes.json:
# "{domain}": ["10.100.0.1", 8900]
"""
            zf.writestr("config/haproxy.cfg", haproxy_conf)

            # 5. Certificate (if available)
            cert_paths = [
                Path(f"/etc/letsencrypt/live/{domain}/fullchain.pem"),
                Path(f"/etc/haproxy/certs/{domain}.pem"),
            ]
            cert_found = False
            for cert_path in cert_paths:
                if cert_path.exists():
                    try:
                        zf.write(cert_path, "certs/certificate.pem")
                        # Also try to get private key
                        key_path = cert_path.parent / "privkey.pem"
                        if key_path.exists():
                            zf.write(key_path, "certs/privkey.pem")
                        cert_found = True
                    except:
                        pass
                    break

            # 6. README with republishing instructions
            readme = f"""# {name} - Site Export Package

**Domain:** {domain}
**Exported:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
**Generator:** SecuBox MetaBlogizer

## Contents

```
{name}-export.zip/
├── content/           # Site files (HTML, CSS, JS, images)
│   ├── public/        # Public web root
│   └── site.json      # Site configuration
├── config/
│   ├── site.json      # Site configuration
│   ├── nginx.conf     # Nginx vhost config
│   └── haproxy.cfg    # HAProxy routing snippet
├── certs/             # SSL certificates (if available)
│   ├── certificate.pem
│   └── privkey.pem
└── README.md          # This file
```

## Quick Republish (SecuBox)

1. Upload ZIP to target SecuBox:
   ```bash
   scp {name}-export.zip root@secubox:/tmp/
   ```

2. Extract and deploy:
   ```bash
   cd /srv/metablogizer/sites
   unzip /tmp/{name}-export.zip -d {name}/
   mv {name}/content/* {name}/
   rm -rf {name}/content
   systemctl restart secubox-metablogizer
   ```

## Manual Republish (Any Server)

### Nginx

1. Copy content:
   ```bash
   mkdir -p /var/www/{name}
   cp -r content/public/* /var/www/{name}/
   ```

2. Install nginx config:
   ```bash
   cp config/nginx.conf /etc/nginx/sites-available/{name}.conf
   ln -s /etc/nginx/sites-available/{name}.conf /etc/nginx/sites-enabled/
   nginx -t && systemctl reload nginx
   ```

3. SSL certificate (if included):
   ```bash
   mkdir -p /etc/ssl/{name}
   cp certs/*.pem /etc/ssl/{name}/
   ```
   Update nginx.conf paths accordingly.

### HAProxy (with SecuBox WAF)

1. Add ACL to haproxy.cfg:
   ```
   acl host_{name.replace('.', '_').replace('-', '_')} hdr(host) -i {domain}
   use_backend mitmproxy_inspector if host_{name.replace('.', '_').replace('-', '_')}
   ```

2. Add mitmproxy route:
   ```json
   "{domain}": ["10.100.0.1", 8900]
   ```

3. Reload:
   ```bash
   haproxy -c -f /etc/haproxy/haproxy.cfg && systemctl reload haproxy
   systemctl restart mitmproxy
   ```

## DNS Configuration

Point `{domain}` to your server IP:
```
{domain}. IN A <your-server-ip>
```

Or use wildcard if using subdomain:
```
*.gk2.secubox.in. IN A <your-server-ip>
```

## Certificate Status

{'✅ Certificate included in export' if cert_found else '⚠️ No certificate found - use certbot to generate:'}
{'' if cert_found else f'certbot certonly --webroot -w /var/www/{name} -d {domain}'}

---
Generated by SecuBox MetaBlogizer
https://secubox.in | CyberMind
"""
            zf.writestr("README.md", readme)

        return FileResponse(
            tmp.name,
            media_type="application/zip",
            filename=f"{name}-export.zip",
            headers={"Content-Disposition": f'attachment; filename="{name}-export.zip"'}
        )


@app.get("/site/{name}/cert", dependencies=[Depends(require_jwt)])
async def get_site_cert(name: str):
    """Get SSL certificate for site"""
    from fastapi.responses import FileResponse

    site_dir = SITES_ROOT / name
    if not site_dir.exists():
        raise HTTPException(404, "Site not found")

    # Read site config to get domain
    domain = f"{name}.gk2.secubox.in"
    config_file = site_dir / "site.json"
    if config_file.exists():
        try:
            cfg = json.loads(config_file.read_text())
            domain = cfg.get("domain", domain)
        except:
            pass

    # Check certbot cert locations
    cert_paths = [
        Path(f"/etc/letsencrypt/live/{domain}/fullchain.pem"),
        Path(f"/etc/letsencrypt/live/{domain}/cert.pem"),
        Path(f"/etc/haproxy/certs/{domain}.pem"),
        Path(f"/etc/ssl/certs/{domain}.pem"),
    ]

    for cert_path in cert_paths:
        if cert_path.exists():
            return FileResponse(
                str(cert_path),
                media_type="application/x-pem-file",
                filename=f"{domain}.pem",
                headers={"Content-Disposition": f'attachment; filename="{domain}.pem"'}
            )

    raise HTTPException(404, f"No certificate found for {domain}")


@app.get("/site/{name}/certificate", dependencies=[Depends(require_jwt)])
def get_certificate_info(name: str):
    """Get certificate information for a site"""
    import subprocess
    from datetime import datetime

    site_dir = SITES_ROOT / name
    if not site_dir.exists():
        raise HTTPException(404, "Site not found")

    # Read site config to get domain
    domain = f"{name}.gk2.secubox.in"
    config_file = site_dir / "site.json"
    if config_file.exists():
        try:
            cfg = json.loads(config_file.read_text())
            domain = cfg.get("domain", domain)
        except:
            pass

    # Check certbot cert
    cert_path = Path(f"/etc/letsencrypt/live/{domain}/fullchain.pem")
    if not cert_path.exists():
        cert_path = Path(f"/etc/haproxy/certs/{domain}.pem")

    if not cert_path.exists():
        return {"exists": False, "domain": domain}

    # Get cert expiry
    try:
        result = subprocess.run(
            ["openssl", "x509", "-in", str(cert_path), "-noout", "-enddate"],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            # Parse expiry: notAfter=May 10 12:00:00 2026 GMT
            expiry_str = result.stdout.strip().replace("notAfter=", "")
            expiry = datetime.strptime(expiry_str, "%b %d %H:%M:%S %Y %Z")
            expired = expiry < datetime.now()
            return {
                "exists": True,
                "domain": domain,
                "expiry": expiry.strftime("%Y-%m-%d"),
                "expired": expired,
                "path": str(cert_path)
            }
    except Exception as e:
        return {"exists": True, "domain": domain, "error": str(e)}

    return {"exists": True, "domain": domain, "path": str(cert_path)}
