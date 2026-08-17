#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: metablogizer.sites_scan — cache double-tampon de la liste des
sites, hors-ligne (#974)

`GET /sites` (`api/main.py`) recalculait tout à chaque appel : pour chacun
des sites du parc (172 en production), `load_sites()` lançait en
SYNCHRONE, dans le gestionnaire de requête FastAPI lui-même :

  - 2 sous-processus `git` (`describe --tags`, `log -1 --format=%cI`) via
    `site_schema.enrich()`
  - 1 sous-processus `du -sh`
  - 1 relecture du fichier de config nginx

Mesuré sur la board (172 sites, charge ~160-170, 4 coeurs) : ~14.6s par
passage, dont 11.2s (77%) rien que pour les 344 forks `git`. Comme ces
appels bloquent l'unique boucle d'événements du worker uvicorn du module
(pas de `run_in_executor`), chaque requête monopolise tout le service
pendant ce temps — les requêtes concurrentes (mosaïque + onglet Sites +
sondes santé + webhook) se mettent en file, et le délai cumulé dépasse
largement 60s. Un `curl` direct sur le socket Unix du module est resté sans
réponse après 90s.

Ce module sépare les deux moitiés du motif double-tampon de `CLAUDE.md`
(section « Performance Patterns ») :

  - `scan_sites()` : la moitié coûteuse, IDENTIQUE à l'ancien corps de
    `load_sites()` — jamais appelée depuis un gestionnaire de requête.
    Seuls `main()` (rappelé par `metablog-audit.timer`, cf.
    `sbin/metablog-audit`) et les chemins d'écriture internes de
    `api/main.py` (création/publication de site, régénération nginx —
    qui ont besoin d'une vérité à jour, pas d'un cache) l'appellent.
  - `read_cache()` : la moitié lue par `GET /sites` — une lecture de
    fichier, jamais un recalcul. Un cache absent ou corrompu est signalé
    explicitement (`available: False` + `reason`), jamais confondu avec un
    parc réellement vide (`available: True`, `sites: []`) — voir la
    docstring de `read_cache`.

Écriture atomique (`write_cache_atomic`) : fichier temporaire créé dans LE
MÊME RÉPERTOIRE que la cible puis `os.replace` — jamais le tempdir système
par défaut. Un `mktemp` dans `/tmp` suivi d'un `mv` transporterait les
permissions de `/tmp` vers la cible (déjà vu sur ce projet : un fichier
devenu `0600 root:root`, illisible par le service qui tourne en
`secubox` — panne de 15h). `os.replace` sur un même filesystem est un
rename POSIX atomique : un lecteur concurrent voit soit l'ancien fichier
complet, soit le nouveau, jamais un état intermédiaire.
"""
from __future__ import annotations

import json
import logging
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

# Self-bootstrap so `from site_schema import …` resolves whether this module
# is imported as `api.sites_scan` (tests, PYTHONPATH=api) or loaded directly
# by sbin/metablog-audit (which only puts THIS file's directory on the path).
sys.path.insert(0, str(Path(__file__).resolve().parent))
from site_schema import enrich as _schema_enrich, validate as _schema_validate  # noqa: E402
from secubox_core import screenshots as _screenshots  # noqa: E402

logger = logging.getLogger("metablogizer.sites_scan")

DEFAULT_SITES_ROOT = "/srv/metablogizer/sites"
DEFAULT_CACHE_PATH = "/var/cache/secubox/metablogizer/sites.json"
DEFAULT_NGINX_CONF = "/etc/nginx/sites-enabled/metablogizer"
DEFAULT_DOMAIN_SUFFIX = ".gk2.secubox.in"
DEFAULT_BASE_PORT = 8900
# Mosaic wall thumbnails (#956/#977): produced out-of-band by
# metablog-shots.timer, never by this process. Only read here to expose
# `screenshot_captured_at` — the cache-busting key the frontend appends to
# the (now nginx-served, never proxied) screenshot URL.
DEFAULT_SHOTS_CACHE_DIR = "/var/cache/secubox/metablogizer/shots"


# ─────────────────────────────────────────────────────────────────────────
# Helpers réutilisés par api/main.py (mêmes règles que l'ancien load_sites)
# ─────────────────────────────────────────────────────────────────────────

def run_cmd(cmd: list, timeout: int = 30) -> tuple:
    """Run command and return (success, stdout, stderr)."""
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return result.returncode == 0, result.stdout.strip(), result.stderr.strip()
    except subprocess.TimeoutExpired:
        return False, "", "Command timed out"
    except Exception as e:  # noqa: BLE001 — never let a scan error crash the loop
        return False, "", str(e)


def read_site_config(site_dir: Path) -> dict:
    """Read site.json (if any), enrich from git, validate (warn-only).

    Always returns a dict containing at least `name`. Missing/malformed
    files are tolerated. Moved out of api/main.py verbatim (#974) so it can
    be called both from the request-time write paths (create/publish) and
    from the out-of-band scan, without importing FastAPI.
    """
    name = site_dir.name
    config_file = site_dir / "site.json"
    doc: dict = {}
    if config_file.exists():
        try:
            doc = json.loads(config_file.read_text())
        except json.JSONDecodeError as e:
            logger.warning("site.json malformed for %s: %s", name, e)
            doc = {}
    doc["name"] = name
    doc = _schema_enrich(doc, site_dir)
    ok, errs = _schema_validate(doc)
    if not ok:
        logger.warning("site.json schema violations for %s: %s", name, errs)
    return doc


# ─────────────────────────────────────────────────────────────────────────
# scan_sites — la moitié coûteuse. NE JAMAIS appeler depuis un gestionnaire
# de requête HTTP — voir la docstring du module.
# ─────────────────────────────────────────────────────────────────────────

def domaine_est_declare(site_dir: Path) -> bool:
    """Le domaine vient-il d'un CHOIX, ou du nom du repertoire ? (#1016)

    La distinction tranche les egalites. `zemialos` declare
    `zem.gk2.secubox.in` dans son `site.json` ET porte un `index.html` ;
    `zem` ne fait qu'heriter du nom de son repertoire et n'a pas d'index.
    Les deux reclamaient le meme domaine, nginx gardait le premier — donc
    `zem`, qui repondait 403.

    Un domaine ECRIT est une intention ; un domaine HERITE n'est qu'un defaut.
    A egalite, l'intention l'emporte.
    """
    try:
        return bool((read_site_config(site_dir).get("domain", "") or "").strip())
    except Exception:
        return False


def domaine_du_site(site_dir: Path, domain_suffix: str = DEFAULT_DOMAIN_SUFFIX) -> str:
    """Le domaine d'un site — UN SEUL calcul, partagé par tous les chemins.

    POURQUOI CETTE FONCTION EXISTE (#1012). Le domaine était calculé à quatre
    endroits, et un seul était juste. Le chemin d'AFFICHAGE (le scan ci-dessous)
    appliquait le suffixe réel ; les chemins de DÉTAIL, de CRÉATION et surtout
    de PUBLICATION — celui qui écrit le vhost nginx — retombaient sur
    ``f"{nom}.local"``.

    Le décalage rendait le défaut invisible : le panneau affirmait
    ``aletheia.gk2.secubox.in`` pendant que nginx portait
    ``server_name aletheia.local``. Aucun ``server_name`` ne correspondant au
    Host demandé, nginx servait le premier bloc venu — un 200 sur le contenu
    d'un site sans rapport, PAS une erreur. Rien ne signalait quoi que ce soit,
    ni dans les journaux ni dans l'interface.

    Trois règles, dans cet ordre :

    1. un domaine explicite dans ``site.json`` fait foi — c'est un choix
       d'opérateur, y compris quand il pointe hors du board : une soixantaine
       de sites servent sous ``maegia.tv`` ou ``ganimed.fr`` ;
    2. un ``.local`` hérité est réécrit vers le suffixe réel — ces valeurs ont
       été gravées par l'ancien chemin de création, et les ignorer ferait
       perdre le sous-domaine choisi (``want`` sert sous ``wanted.``) ;
    3. sans rien, le nom du répertoire porte le suffixe par défaut.
    """
    saved = ""
    try:
        saved = (read_site_config(site_dir).get("domain", "") or "").strip()
    except Exception:
        # Un site.json illisible ne doit pas empêcher la publication : on
        # retombe sur le nom du site, jamais sur `.local`.
        saved = ""

    if not saved:
        return f"{site_dir.name}{domain_suffix}"
    if saved.endswith(".local"):
        # `removesuffix` et non `replace` : un site dont le domaine contient
        # `.local` ailleurs qu'en fin verrait sinon cette occurrence réécrite.
        return saved.removesuffix(".local") + domain_suffix
    return saved


def scan_sites(
    sites_root: Path,
    nginx_conf: Path,
    domain_suffix: str = DEFAULT_DOMAIN_SUFFIX,
    base_port: int = DEFAULT_BASE_PORT,
    shots_cache_dir: Optional[Path] = None,
) -> List[dict]:
    """Full synchronous scan of `sites_root` — same shape/rules as the
    former `api/main.py:load_sites()` body (domain rewriting, published
    detection, size, schema-overlay fields). One deliberate difference:
    directories are visited in sorted() order before the final sort-by-port,
    so same-port entries tie-break alphabetically instead of arbitrary
    filesystem iteration order — a stricter, deterministic superset of the
    old behaviour, not a functional regression. ~14.6s for 172 sites on a
    loaded board (measured); only ever called out of band (metablog-audit)
    or from write paths that need a live, authoritative view.

    `shots_cache_dir` (default `DEFAULT_SHOTS_CACHE_DIR`) adds one more
    field per site, `screenshot_captured_at` (#977) — a single JSON stat+
    read from `secubox_core.screenshots`, nothing like the git/du forks
    above. Present only when a screenshot was ever captured successfully;
    the frontend uses it to cache-bust the (nginx-served) thumbnail URL, so
    it must never be set on a capture that failed (the old PNG, if any, is
    still being served, not a new one — see screenshots.is_stale)."""
    sites: List[dict] = []
    if not sites_root.exists():
        return sites

    shots_dir = Path(shots_cache_dir) if shots_cache_dir is not None \
        else Path(DEFAULT_SHOTS_CACHE_DIR)

    nginx_content = ""
    if nginx_conf.exists():
        try:
            nginx_content = nginx_conf.read_text()
        except OSError as e:
            logger.warning("cannot read %s: %s", nginx_conf, e)

    for site_dir in sorted(sites_root.iterdir()):
        if not site_dir.is_dir() or site_dir.name.startswith("."):
            continue

        name = site_dir.name
        cfg = read_site_config(site_dir)
        # Passe par le calcul PARTAGE (#1012) : c'est ce chemin d'affichage qui
        # etait juste pendant que la publication ecrivait `.local`, et les faire
        # diverger de nouveau reproduirait exactement le defaut.
        domain = domaine_du_site(site_dir, domain_suffix)
        port = cfg.get("port", base_port)

        published = (
            f"root {site_dir}" in nginx_content
            or f"root {site_dir}/public" in nginx_content
        )

        size = "0"
        success, out, _ = run_cmd(["du", "-sh", str(site_dir)])
        if success:
            size = out.split()[0]

        entry = {
            "name": name,
            "domain": domain,
            "port": port,
            "published": published,
            "directory": str(site_dir),
            "size": size,
        }
        for key in ("version", "title", "description", "category",
                    "streamlit_app", "tags", "last_updated",
                    # UNE CLE ABSENTE DE CETTE LISTE N'EXISTE PAS POUR LE
                    # GENERATEUR (#1023). Les alias etaient bien ecrits dans le
                    # site.json et bien valides — mais le scan ne les recopiait
                    # pas dans l'entree, alors `server_name` n'en portait aucun.
                    # Rien n'echouait : le bloc etait juste incomplet.
                    # Le meme piege s'est referme sur `api` (#1032) : la route
                    # etait declaree, validee, et le vhost n'en portait rien.
                    "aliases", "api"):
            if key in cfg and cfg[key] is not None:
                entry[key] = cfg[key]

        try:
            shot_meta = _screenshots.read_meta(shots_dir, name)
        except ValueError:
            shot_meta = {}
        if shot_meta.get("ok"):
            entry["screenshot_captured_at"] = shot_meta.get("captured_at", "")

        sites.append(entry)

    return sorted(sites, key=lambda x: x.get("port", base_port))


# ─────────────────────────────────────────────────────────────────────────
# Écriture atomique — même répertoire, jamais /tmp
# ─────────────────────────────────────────────────────────────────────────

def write_cache_atomic(cache_path: Path, sites: List[dict]) -> None:
    """Write the scan result to `cache_path` atomically.

    The temp file is created with `tempfile.mkstemp(dir=cache_path.parent)`
    — explicitly IN the destination directory, never the platform tempdir —
    so `os.replace()` is a same-filesystem rename: atomic, and it can never
    drag in foreign ownership/permissions the way a cross-filesystem
    `mktemp in /tmp` + `mv` would. Explicitly chmod'd 0644 so the cache
    stays readable regardless of the writing process's umask.
    """
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "sites": sites,
        "count": len(sites),
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
    }
    fd, tmp_name = tempfile.mkstemp(
        dir=str(cache_path.parent), prefix=".sites.", suffix=".tmp"
    )
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(payload, f)
        os.chmod(tmp_name, 0o644)
        os.replace(tmp_name, cache_path)
    except BaseException:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise


# ─────────────────────────────────────────────────────────────────────────
# read_cache — la SEULE chose qu'un gestionnaire de requête a le droit
# d'appeler pour la liste des sites en lecture.
# ─────────────────────────────────────────────────────────────────────────

def read_cache(cache_path: Path) -> Dict[str, Any]:
    """Read the pre-computed cache. Never raises, never recomputes.

    `available=False` distinguishes explicitly between "no cache written
    yet" / "cache unreadable" and a genuinely empty fleet
    (`available=True, sites=[]`) — an empty array alone must never be read
    as "no sites" (#974).
    """
    try:
        raw = json.loads(cache_path.read_text())
        if not isinstance(raw, dict) or not isinstance(raw.get("sites"), list):
            raise ValueError("cache content is not a sites payload")
    except FileNotFoundError:
        return {
            "available": False,
            "reason": "cache not written yet",
            "sites": [],
            "count": 0,
            "cache_age_seconds": None,
            "generated_at": None,
        }
    except (OSError, ValueError) as exc:
        logger.warning("sites cache unreadable: %s", exc)
        return {
            "available": False,
            "reason": "cache unreadable",
            "sites": [],
            "count": 0,
            "cache_age_seconds": None,
            "generated_at": None,
        }

    age: Optional[int] = None
    try:
        age = int(time.time() - cache_path.stat().st_mtime)
    except OSError:
        pass

    sites = raw.get("sites", [])
    return {
        "available": True,
        "reason": None,
        "sites": sites,
        "count": len(sites),
        "cache_age_seconds": age,
        "generated_at": raw.get("generated_at"),
    }


# ─────────────────────────────────────────────────────────────────────────
# CLI — rappelé par metablog-audit.timer (via sbin/metablog-audit)
# ─────────────────────────────────────────────────────────────────────────

def main(argv: Optional[list] = None) -> int:
    """Entry point for `metablog-audit`. Scans once, writes the cache once,
    exits. Cadence (5 minutes, see debian/metablog-audit.timer) is the
    timer's job, not this script's — mirrors `metablog-shots.timer` /
    `streamlit-audit.timer`.

    Paths overridable by environment (tests, dev):
      METABLOG_SITES_ROOT   default /srv/metablogizer/sites
      METABLOG_SITES_CACHE  default /var/cache/secubox/metablogizer/sites.json
      METABLOG_NGINX_CONF   default /etc/nginx/sites-enabled/metablogizer
      METABLOG_SHOTS_CACHE  default /var/cache/secubox/metablogizer/shots
    """
    sites_root = Path(os.environ.get("METABLOG_SITES_ROOT", DEFAULT_SITES_ROOT))
    cache_path = Path(os.environ.get("METABLOG_SITES_CACHE", DEFAULT_CACHE_PATH))
    nginx_conf = Path(os.environ.get("METABLOG_NGINX_CONF", DEFAULT_NGINX_CONF))
    shots_cache_dir = Path(os.environ.get("METABLOG_SHOTS_CACHE", DEFAULT_SHOTS_CACHE_DIR))

    sites = scan_sites(sites_root, nginx_conf, shots_cache_dir=shots_cache_dir)
    write_cache_atomic(cache_path, sites)
    print(json.dumps({"sites": len(sites), "cache": str(cache_path)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
