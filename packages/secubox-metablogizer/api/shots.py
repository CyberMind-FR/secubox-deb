# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: metablogizer.shots — file d'attente de capture des vignettes

Sert `metablog-shotter` (sbin), rappelé toutes les 2 minutes par
`metablog-shots.timer` (#956). Capture UN site par exécution, jamais une
boucle sur les 172 : c'est le timer qui étale la charge dans le temps, pas ce
module (voir docstring de `main()`). Toute la mécanique de capture elle-même
(chromium piloté par CDP, stratégie d'attente branchable) vit dans
`secubox_core.shotter` ; le cycle de vie des images (fraîcheur, écriture
atomique, un échec qui préserve l'ancienne vignette) vit dans
`secubox_core.screenshots`. Ce module ne fait que : choisir LEQUEL des 172
sites capturer, vérifier la charge de la board avant de s'y risquer, et
empêcher deux exécutions concurrentes.

Mesures qui gouvernent ce design (voir la docstring de `shotter.py`) : une
capture de site statique a produit un PNG de 120 800 octets en 54 s sur une
board à 87 de charge — un passage complet sur 172 sites représente donc
plusieurs heures de chromium. Le chemin de requête HTTP qui sert la vignette
(`api/main.py:get_site_screenshot`) ne fait JAMAIS de capture — il ne fait
que lire un fichier déjà produit par ce module.

Choix du prochain site (`pick_next`) : parmi les sites dont la vignette est
absente ou périmée (`screenshots.is_stale`, comparée à `site_fingerprint` —
la date de publication du site), celui dont la dernière tentative de capture
(`captured_at`, absent = jamais tentée) est la plus ancienne. Une capture
ratée écrit quand même `captured_at` (règle de `screenshots.record`) : le
site tenté-et-raté retombe donc mécaniquement en fin de file au tour
suivant, sans code dédié — c'est ce qui empêche un site cassé de geler la
file (règle #956 : « un échec ne bloque pas la file »).
"""
from __future__ import annotations

import fcntl
import json
import os
import subprocess
from pathlib import Path
from typing import Optional

DEFAULT_SITES_ROOT = "/srv/metablogizer/sites"
DEFAULT_CACHE_DIR = "/var/cache/secubox/metablogizer/shots"
# SEUIL DE CHARGE. 40 sur une board a QUATRE coeurs laissait capturer alors que
# la machine etait deja dix fois saturee — et la capture, qui lance un
# navigateur complet, aggravait ce qu'elle etait censee eviter. Constate le
# 2026-08-12 : charge a 77, chromium relance toutes les deux minutes.
#
# 4 = un coeur par coeur, soit une machine occupee mais pas engorgee. Au-dela,
# la capture attend : elle n'est jamais urgente.
DEFAULT_LOAD_THRESHOLD = 4.0
LOCK_NAME = ".lock"
DEFAULT_DOMAIN_SUFFIX = ".gk2.secubox.in"


# ─────────────────────────────────────────────────────────────────────────
# Empreinte de fraîcheur — la date de publication du site
# ─────────────────────────────────────────────────────────────────────────

def site_fingerprint(site_dir: Path) -> str:
    """Empreinte de fraîcheur d'un site : sa date de publication.

    Les sites sont pour la plupart poussés via Gitea (webhook ou déploiement
    manuel, voir `api/webhook.py`) : la date du dernier commit EST la date de
    publication — exactement la même notion que `site_schema.enrich()`
    calcule déjà pour l'API (son champ `last_updated`), mais celle-ci évite
    l'enrichissement complet (validation de schéma + `du -sh`, ~5-10 s pour
    166 sites d'après `main.py`) : un simple `git log -1`, consulté pour 172
    sites à chaque tour, doit rester bon marché.

    Un site sans dépôt git (créé via `POST /site`, jamais republié depuis)
    n'a pas de date de commit : on retombe sur le mtime du répertoire, stable
    tant que le site n'est pas retouché — jamais recapturé (règle #956 : un
    site déjà capturé et non republié n'est jamais recapturé).
    """
    git_dir = site_dir / ".git"
    if git_dir.is_dir():
        try:
            out = subprocess.run(
                ["git", "-c", f"safe.directory={site_dir}", "-C", str(site_dir),
                 "log", "-1", "--format=%cI"],
                capture_output=True, text=True, timeout=5,
            )
            if out.returncode == 0 and out.stdout.strip():
                return out.stdout.strip()
        except (OSError, subprocess.TimeoutExpired):
            pass
    try:
        return str(int(site_dir.stat().st_mtime))
    except OSError:
        return ""


def site_domain(site_dir: Path, name: str) -> str:
    """Domaine public d'un site — même règle que `main.py:load_sites()` :
    `site.json:domain` s'il est renseigné (le suffixe `.local` est réécrit
    vers `.gk2.secubox.in`), sinon `<name>.gk2.secubox.in`."""
    domain = f"{name}{DEFAULT_DOMAIN_SUFFIX}"
    site_json = site_dir / "site.json"
    if site_json.exists():
        try:
            cfg = json.loads(site_json.read_text())
        except (OSError, ValueError):
            cfg = {}
        saved = (cfg.get("domain") or "").strip()
        if saved.endswith(".local"):
            domain = saved.replace(".local", DEFAULT_DOMAIN_SUFFIX)
        elif saved:
            domain = saved
    return domain


# ─────────────────────────────────────────────────────────────────────────
# Sélection du prochain site
# ─────────────────────────────────────────────────────────────────────────

def _site_dirs(sites_root: Path):
    if not sites_root.is_dir():
        return
    for entry in sorted(sites_root.iterdir()):
        if entry.is_dir() and not entry.name.startswith("."):
            yield entry


def pick_next(sites_root: Path, cache_dir: Path) -> Optional[str]:
    """Nom du site à capturer ce tour-ci, ou `None` si rien n'est dû.

    Une vignette n'est JAMAIS reprise parce que le temps a passe : seulement
    si elle manque, si la tentative precedente a echoue, ou si le site lui-meme
    a change (empreinte differente). Une capture est donc unique par etat du
    site, et le passage periodique ne sert qu'a rattraper ce qui manque.

    Parmi ces sites, celui dont la
    dernière tentative (`captured_at`) est la plus ancienne gagne — une
    chaîne vide (jamais tentée) trie avant toute date ISO 8601, donc un site
    jamais capturé passe toujours devant un site déjà tenté au moins une
    fois."""
    from secubox_core import screenshots

    candidates = []
    for site_dir in _site_dirs(sites_root):
        name = site_dir.name
        fingerprint = site_fingerprint(site_dir)
        if not screenshots.is_stale(cache_dir, name, fingerprint):
            continue
        meta = screenshots.read_meta(cache_dir, name)
        candidates.append((meta.get("captured_at") or "", name))

    if not candidates:
        return None
    candidates.sort()
    return candidates[0][1]


# ─────────────────────────────────────────────────────────────────────────
# Garde de charge
# ─────────────────────────────────────────────────────────────────────────

def load_ok(threshold: float) -> bool:
    """True si la charge à une minute est sous (ou égale à) `threshold` —
    condition nécessaire avant toute capture. La board passe ses journées
    au-dessus de 60 ; sans ce garde-fou, une capture (chromium, plusieurs
    minutes sous charge d'après `shotter.py`) aggraverait une machine déjà
    saturée."""
    try:
        return os.getloadavg()[0] <= threshold
    except OSError:
        # Pas de getloadavg() sur cette plateforme (jamais rencontré sur
        # Linux) : fail-open plutôt que de geler la file indéfiniment.
        return True


# ─────────────────────────────────────────────────────────────────────────
# Verrou d'exclusion
# ─────────────────────────────────────────────────────────────────────────

class _Lock:
    """Verrou tenu, à libérer via `release()` (ou un bloc `with`)."""

    def __init__(self, fh) -> None:
        self._fh = fh

    def release(self) -> None:
        try:
            fcntl.flock(self._fh, fcntl.LOCK_UN)
        finally:
            self._fh.close()

    def __enter__(self) -> "_Lock":
        return self

    def __exit__(self, *exc) -> None:
        self.release()


def acquire_lock(lock_path: Path) -> Optional[_Lock]:
    """Verrou non bloquant : renvoie un `_Lock` si acquis, `None` sinon (une
    autre exécution est déjà en cours — le timer a débordé sur le tir
    suivant).

    Le verrou `flock` est tenu par le descripteur de fichier : il disparaît
    avec le process qui le détient, y compris en cas de crash — jamais de
    verrou orphelin à nettoyer à la main, contrairement à un fichier PID."""
    lock_path.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    fh = open(lock_path, "w")
    try:
        fcntl.flock(fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        fh.close()
        return None
    return _Lock(fh)


# ─────────────────────────────────────────────────────────────────────────
# Capture d'un site
# ─────────────────────────────────────────────────────────────────────────

async def capture_site(sites_root: Path, cache_dir: Path, name: str, *, wait=None) -> dict:
    """Capture UN site déjà choisi par `pick_next`.

    Ne lève jamais : un échec est enregistré (`screenshots.record(ok=False)`
    conserve la vignette précédente si elle existe) et renvoyé dans le
    résultat, jamais propagé — c'est ce qui permet à l'appelant de passer au
    site suivant au prochain tour sans traitement d'erreur particulier
    (règle #956 : un échec ne bloque pas la file)."""
    from secubox_core import shotter, screenshots

    site_dir = sites_root / name
    fingerprint = site_fingerprint(site_dir)
    domain = site_domain(site_dir, name)
    url = f"https://{domain}/"
    strategy = wait or shotter.wait_static_ready

    try:
        png = await shotter.capture(url, wait=strategy)
    except shotter.ShotError as exc:
        screenshots.record(cache_dir, name, None, fingerprint, ok=False)
        return {"ok": False, "name": name, "url": url, "error": str(exc)}

    meta = screenshots.record(cache_dir, name, png, fingerprint, ok=True)
    return {"ok": True, "name": name, "url": url, "bytes": len(png), **meta}


# ─────────────────────────────────────────────────────────────────────────
# CLI — un seul site par exécution, rappelé par metablog-shots.timer
# ─────────────────────────────────────────────────────────────────────────

def main(argv=None) -> int:
    """Point d'entrée de `metablog-shotter`. Ne capture JAMAIS plus d'un
    site : c'est le timer (toutes les 2 minutes) qui étale la charge sur les
    172 sites, jamais une boucle interne — voir la docstring du module.

    Chemins et seuil surchargeables par l'environnement (tests, dev) :
      METABLOG_SITES_ROOT          défaut /srv/metablogizer/sites
      METABLOG_SHOTS_CACHE         défaut /var/cache/secubox/metablogizer/shots
      METABLOG_SHOTS_LOAD_THRESHOLD  défaut 40

    Code de sortie : 0 si rien à faire, sauté (charge, verrou) ou capture
    réussie ; 1 si une capture a été tentée et a échoué — un échec n'est
    JAMAIS traité comme une erreur bloquante par le timer (`OnUnitActiveSec`
    rappelle ce script au tour suivant quel que soit le code de sortie), ce
    code sert uniquement à rendre l'échec visible dans le journal.
    """
    import asyncio

    sites_root = Path(os.environ.get("METABLOG_SITES_ROOT", DEFAULT_SITES_ROOT))
    cache_dir = Path(os.environ.get("METABLOG_SHOTS_CACHE", DEFAULT_CACHE_DIR))
    threshold = float(os.environ.get("METABLOG_SHOTS_LOAD_THRESHOLD", DEFAULT_LOAD_THRESHOLD))

    if not load_ok(threshold):
        print(json.dumps({"skipped": "load-guard", "threshold": threshold}))
        return 0

    lock = acquire_lock(cache_dir / LOCK_NAME)
    if lock is None:
        print(json.dumps({"skipped": "locked"}))
        return 0

    try:
        name = pick_next(sites_root, cache_dir)
        if name is None:
            print(json.dumps({"skipped": "nothing-to-capture"}))
            return 0

        result = asyncio.run(capture_site(sites_root, cache_dir, name))
        print(json.dumps(result))
        return 0 if result.get("ok") else 1
    finally:
        lock.release()


if __name__ == "__main__":
    raise SystemExit(main())
