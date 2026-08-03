# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: streamlit.shots — capture d'UNE vignette, sur événement

Sert `streamlit-shotter` (sbin), lancé en tâche DÉTACHÉE par `api/main.py`
sur exactement deux déclencheurs (#958, spec §3.1) : un réveil qui vient de
réussir, ou un clic explicite sur « recapturer ». JAMAIS un timer — voir
`api/tests/test_no_timer_triggers_capture.py`, qui échoue si une unité
systemd du paquet en vient un jour à invoquer ce module.

C'est la différence structurelle avec `secubox-metablogizer` (qui capture
des sites toujours actifs, par minuterie de 2 minutes, #956) : une appli
Streamlit endormie DOIT LE RESTER — ce module ne réveille jamais rien lui-
même, il ne capture QUE des applis dont l'appelant a déjà établi qu'elles
sont en ligne (`streamlitctl app shot-target`, invoqué ci-dessous, renvoie
explicitement "not running" pour une appli endormie plutôt que de la
démarrer).

Toute la mécanique de capture (chromium piloté par CDP, stratégie
d'attente branchable) vit dans `secubox_core.shotter` ; le cycle de vie
des images (fraîcheur, écriture atomique, un échec qui préserve
l'ancienne vignette) vit dans `secubox_core.screenshots`. Ce module ne
fait que : résoudre la cible d'UNE appli nommée via `streamlitctl`, décider
si une capture est due, et empêcher deux captures concurrentes (#957 §3.4 :
~2 Go de RAM disponibles sur la board ne tiennent pas deux chromium).

Le stockage vit sous un répertoire de cache DÉDIÉ
(`/var/cache/secubox/streamlit/shots/<app>/`), jamais dans le répertoire de
l'appli elle-même : la moitié du parc est constituée de scripts `.py` à
plat sous `APPS_PATH` (#959) — il n'y a alors aucun répertoire où poser
"une image à côté de l'appli", et pour les applis-répertoire, y écrire
polluerait potentiellement un dépôt git source. `streamlitctl app audit`
lit ce même répertoire (lecture seule, jamais d'écriture) pour exposer
`screenshot_available`/`screenshot_stale` au panneau.
"""
from __future__ import annotations

import fcntl
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Optional

DEFAULT_SHOTS_CACHE_DIR = "/var/cache/secubox/streamlit/shots"
DEFAULT_CTL = "/usr/sbin/streamlitctl"
LOCK_NAME = ".lock"


# ─────────────────────────────────────────────────────────────────────────
# Empreinte de fraîcheur — mtime + taille du fichier source
# ─────────────────────────────────────────────────────────────────────────

def source_fingerprint(source: Path) -> str:
    """Empreinte de fraîcheur d'une appli Streamlit : mtime + taille de son
    script source, format "<mtime>:<taille>".

    DOIT rester identique au calcul fait côté bash dans
    `streamlitctl:cmd_app_audit` (`stat -c '%Y:%s' "$src"`) — c'est cette
    même empreinte que le panneau compare pour marquer une vignette comme
    périmée, indépendamment de ce module. Une chaîne vide si le fichier a
    disparu (jamais d'exception : un appelant qui vient de résoudre la
    cible ne doit pas se faire surprendre par une course avec un
    `app remove`)."""
    try:
        st = source.stat()
    except OSError:
        return ""
    return f"{int(st.st_mtime)}:{st.st_size}"


# ─────────────────────────────────────────────────────────────────────────
# Résolution de la cible — délègue entièrement à streamlitctl
# ─────────────────────────────────────────────────────────────────────────

def resolve_target(name: str, *, ctl: str = DEFAULT_CTL) -> dict:
    """Résout l'URL directe et le fichier source d'une appli EN LIGNE via
    `streamlitctl app shot-target` (#958). Ne redérive JAMAIS
    entrypoint/port/IP ici : ce serait recréer la classe de divergence que
    #959 a dû corriger entre `app start`/`app wake`/`app audit`, avec
    cette fois un quatrième point de vue à faire diverger.

    Renvoie toujours un dict avec `ok`; jamais d'exception — même un
    `streamlitctl` absent ou un timeout redescend en `{"ok": False, ...}`.
    """
    try:
        result = subprocess.run(
            ["sudo", "-n", ctl, "app", "shot-target", name],
            capture_output=True, text=True, timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"ok": False, "error": f"streamlitctl unreachable: {exc}"}

    out = result.stdout.strip()
    if not out.startswith("{"):
        return {"ok": False, "error": result.stderr.strip() or "no output from streamlitctl"}
    try:
        data = json.loads(out)
    except ValueError:
        return {"ok": False, "error": "malformed shot-target output"}
    return data if isinstance(data, dict) else {"ok": False, "error": "unexpected shot-target output"}


# ─────────────────────────────────────────────────────────────────────────
# Verrou d'exclusion — une capture à la fois (#957 §3.4)
# ─────────────────────────────────────────────────────────────────────────

class _Lock:
    """Verrou tenu, à libérer via `release()` (ou un bloc `with`). Détenu
    par le descripteur de fichier : disparaît avec le process qui le
    détient, y compris en cas de crash — jamais de verrou orphelin à
    nettoyer à la main."""

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


def acquire_lock(lock_path: Path) -> Optional["_Lock"]:
    """Verrou non bloquant : renvoie un `_Lock` si acquis, `None` sinon —
    une autre capture est déjà en cours. Jamais d'attente : un déclencheur
    qui trouve le verrou pris abandonne simplement (la prochaine occasion
    de capturer — prochain réveil, prochain clic — retentera)."""
    lock_path.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    fh = open(lock_path, "w")
    try:
        fcntl.flock(fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        fh.close()
        return None
    return _Lock(fh)


# ─────────────────────────────────────────────────────────────────────────
# Capture d'une appli déjà ciblée
# ─────────────────────────────────────────────────────────────────────────

async def capture_app(cache_dir: Path, name: str, url: str, source: Path, *, wait=None) -> dict:
    """Capture UNE appli dont la cible est déjà résolue.

    Ne lève jamais : un échec est enregistré (`screenshots.record(ok=False)`
    conserve la vignette précédente si elle existe, spec §3.6) et renvoyé
    dans le résultat, jamais propagé."""
    from secubox_core import shotter, screenshots

    fingerprint = source_fingerprint(source)
    strategy = wait or shotter.wait_streamlit_ready

    try:
        png = await shotter.capture(url, wait=strategy)
    except shotter.ShotError as exc:
        screenshots.record(cache_dir, name, None, fingerprint, ok=False)
        return {"ok": False, "name": name, "url": url, "error": str(exc)}

    meta = screenshots.record(cache_dir, name, png, fingerprint, ok=True)
    return {"ok": True, "name": name, "url": url, "bytes": len(png), **meta}


# ─────────────────────────────────────────────────────────────────────────
# CLI — capture UNE appli nommée, jamais rappelé par un timer
# ─────────────────────────────────────────────────────────────────────────

def main(argv=None) -> int:
    """Point d'entrée de `streamlit-shotter <name> [--force]`.

    Sans `--force` : capture SEULEMENT si la vignette est périmée
    (`screenshots.is_stale`) — couvre les déclencheurs "première
    inscription" et "mise à jour" (#957 §3.1), invoqué après un réveil qui
    vient de réussir. Un échec de résolution de cible (appli endormie,
    disparue, port/IP indisponible) est un simple `skipped`, jamais une
    erreur : appelé après un wake qui a déjà réussi, une appli qui
    s'avérerait finalement endormie ne doit jamais faire remonter d'échec
    bruyant dans les journaux.

    Avec `--force` : capture INCONDITIONNELLEMENT si l'appli est
    résolvable et en ligne — le bouton "recapturer" (déclencheur manuel,
    #957 §3.1), qui doit ignorer la fraîcheur enregistrée.

    Chemins/binaire surchargeables par l'environnement (tests, dev) :
      SECUBOX_STREAMLIT_SHOTS_CACHE   défaut /var/cache/secubox/streamlit/shots
      SECUBOX_STREAMLIT_CTL           défaut /usr/sbin/streamlitctl

    Code de sortie : 0 si rien à faire (skip) ou capture réussie ; 1 si une
    capture a été tentée et a échoué — jamais lu par un timer (il n'y en a
    pas), seulement visible dans le journal d'un lancement manuel.
    """
    import asyncio

    argv = sys.argv[1:] if argv is None else argv
    force = "--force" in argv
    positional = [a for a in argv if a != "--force"]
    if len(positional) != 1:
        print(json.dumps({"ok": False, "error": "usage: streamlit-shotter <name> [--force]"}))
        return 2
    name = positional[0]

    cache_dir = Path(os.environ.get("SECUBOX_STREAMLIT_SHOTS_CACHE", DEFAULT_SHOTS_CACHE_DIR))
    ctl = os.environ.get("SECUBOX_STREAMLIT_CTL", DEFAULT_CTL)

    lock = acquire_lock(cache_dir / LOCK_NAME)
    if lock is None:
        print(json.dumps({"skipped": "locked", "name": name}))
        return 0

    try:
        target = resolve_target(name, ctl=ctl)
        if not target.get("ok"):
            print(json.dumps({"skipped": "target-unavailable", "name": name,
                               "reason": target.get("error")}))
            return 0

        url = target["url"]
        source = Path(target["source"])

        if not force:
            from secubox_core import screenshots
            fingerprint = source_fingerprint(source)
            if not screenshots.is_stale(cache_dir, name, fingerprint):
                print(json.dumps({"skipped": "fresh", "name": name}))
                return 0

        result = asyncio.run(capture_app(cache_dir, name, url, source))
        print(json.dumps(result))
        return 0 if result.get("ok") else 1
    finally:
        lock.release()


if __name__ == "__main__":
    raise SystemExit(main())
