# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox-Deb :: WebOS — vignettes des modules pour la mosaïque du Hall (#2996).

Même discipline que le mur metablogizer (#956) : `webos-vignettes` est rappelé par une minuterie,
capture UN module par exécution, s'abstient si la charge dépasse le seuil, tient un verrou, et le
chemin HTTP qui sert la vignette ne capture jamais (nginx lit le PNG). La capture elle-même vit dans
`secubox_core.shotter`, le cycle de vie des images dans `secubox_core.screenshots`.

Ce qui est capturé : la page publique du vhost du module (`https://<domaine>/?theme=dark&embed=1`),
jamais une console d'administration. Empreinte de fraîcheur : le domaine et la semaine ISO — une
vignette est reprise au plus une fois par semaine, ou dès qu'elle manque ou que la tentative a échoué.
"""
from __future__ import annotations

import fcntl
import json
import os
import re
import ssl
import urllib.error
import urllib.request
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Iterable, Optional

CACHE_DIR = Path("/var/cache/secubox/webos/shots")
MENU = "/var/cache/secubox/menu.json"
CA = "/usr/share/secubox/egress-ca.pem"
# 8 sur quatre cœurs : la box vit entre 6 et 15 de charge, un seuil de 4 (celui du mur metablogizer) ne laisserait
# presque jamais capturer ; l'unité borne déjà Chromium (CPUQuota 20 %, Nice 19, E/S idle).
LOAD_THRESHOLD = 8.0
LOCK_NAME = ".lock"
SANS_PAGE = "sans-page.json"


def sonde(url: str, timeout: float = 10.0, ca: Optional[str] = CA) -> tuple[bool, str]:
    """Avant Chromium : la page existe-t-elle vraiment ? Un vhost non exposé répond 421 (le WAF), une page de
    connexion ou d'erreur n'est pas une vignette. Lecture bornée (64 Ko), jamais de capture ici."""
    ctx = ssl.create_default_context()
    if ca and Path(ca).is_file():
        try:
            ctx.load_verify_locations(ca)
        except ssl.SSLError:
            pass
    req = urllib.request.Request(url, headers={"User-Agent": "secubox-webos-vignettes", "Accept": "text/html"})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            if r.status != 200:
                return False, f"http {r.status}"
            corps = r.read(65536).decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return False, f"http {exc.code}"
    except (urllib.error.URLError, OSError, ValueError) as exc:
        return False, f"injoignable : {exc}"[:120]
    m = re.search(r"<title>([^<]*)", corps, re.I)
    titre = (m.group(1) if m else "").strip()
    if re.search(r"\b421\b|\b50\d\b|connexion|login|introuvable|not found", titre, re.I) or 'id="login' in corps:
        return False, f"page de connexion ou d'erreur : {titre[:60]}"
    return True, titre


def marque_sans_page(cache_dir: Path, sid: str, fp: str, raison: str) -> None:
    d = cache_dir / sid
    d.mkdir(mode=0o755, parents=True, exist_ok=True)
    (d / SANS_PAGE).write_text(json.dumps({"fingerprint": fp, "raison": raison,
                                           "captured_at": datetime.now(timezone.utc).isoformat()}))


def sans_page_frais(cache_dir: Path, sid: str, fp: str) -> bool:
    try:
        return json.loads((cache_dir / sid / SANS_PAGE).read_text()).get("fingerprint") == fp
    except (OSError, ValueError):
        return False


def fingerprint(domaine: str, jour: Optional[date] = None) -> str:
    j = jour or date.today()
    annee, semaine, _ = j.isocalendar()
    return f"{domaine}@{annee}-W{semaine:02d}"


def candidats(services: Iterable[dict]) -> list[tuple[str, str]]:
    """(id, domaine) des modules capturables : un vhost public joignable, pas une page d'un autre module."""
    out = []
    for s in services:
        urls = s.get("urls") or {}
        lan = urls.get("lan") or ""
        if not lan.startswith("https://") or not (s.get("routing") or {}).get("available", True):
            continue
        if (s.get("health") or {}).get("state") == "offline":
            continue
        out.append((s["id"], lan[len("https://"):].split("/")[0]))
    return out


def pick_next(services: Iterable[dict], cache_dir: Path = CACHE_DIR, jour: Optional[date] = None) -> Optional[tuple[str, str]]:
    """Le module à capturer ce tour-ci : vignette manquante, périmée ou tentative ratée ; le plus ancien d'abord."""
    from secubox_core import screenshots
    a_faire = []
    for sid, dom in candidats(services):
        fp = fingerprint(dom, jour)
        if not screenshots.is_stale(cache_dir, sid, fp) or sans_page_frais(cache_dir, sid, fp):
            continue
        meta = screenshots.read_meta(cache_dir, sid)
        a_faire.append((meta.get("captured_at") or "", sid, dom))
    if not a_faire:
        return None
    a_faire.sort()
    return a_faire[0][1], a_faire[0][2]


def load_ok(threshold: float = LOAD_THRESHOLD) -> bool:
    try:
        return os.getloadavg()[0] <= threshold
    except OSError:
        return True


def acquire_lock(lock_path: Path):
    lock_path.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    fh = open(lock_path, "w")
    try:
        fcntl.flock(fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        fh.close()
        return None
    return fh


async def capture_module(sid: str, domaine: str, cache_dir: Path = CACHE_DIR, *, ca: Optional[str] = CA, _capture=None, _sonde=None,
                         _routes=None) -> dict:
    """Capture UN module ; un échec est enregistré (l'ancienne vignette est conservée) et renvoyé, jamais propagé.
    Sans page réelle (421, erreur, connexion), on note « sans page » pour la semaine et Chromium ne démarre pas.
    Un domaine absent de la table de routes du WAF n'est même pas sondé (#3174) : il répondrait 421, et la sonde laissait
    une anomalie dans le journal des menaces du WAF."""
    from secubox_core import screenshots, shotter

    from api import hotes
    url = f"https://{domaine}/?theme=dark&embed=1"
    servis = (_routes or hotes.noms_routes)()
    if servis is not None and domaine.lower() not in servis:
        marque_sans_page(cache_dir, sid, fingerprint(domaine), "non routé par le WAF")
        return {"ok": False, "id": sid, "url": url, "sans_page": True, "error": "non routé par le WAF"}
    ok, raison = (_sonde or sonde)(url)
    if not ok:
        marque_sans_page(cache_dir, sid, fingerprint(domaine), raison)
        return {"ok": False, "id": sid, "url": url, "sans_page": True, "error": raison}
    capture = _capture or (lambda u: shotter.capture(u, wait=shotter.wait_static_ready, ca=ca if ca and Path(ca).is_file() else None))
    try:
        png = await capture(url)
    except shotter.ShotError as exc:
        screenshots.record(cache_dir, sid, None, fingerprint(domaine), ok=False)
        return {"ok": False, "id": sid, "url": url, "error": str(exc)}
    meta = screenshots.record(cache_dir, sid, png, fingerprint(domaine), ok=True)
    return {"ok": True, "id": sid, "url": url, "bytes": len(png), **meta}


def vignettes_presentes(ids: Iterable[str], cache_dir: Path = CACHE_DIR) -> set[str]:
    from secubox_core import screenshots
    return {i for i in ids if screenshots.png_path(cache_dir, i).exists()}


def services_du_registre(menu_path: str = MENU) -> list[dict]:
    """Le registre normalisé recalculé depuis le menu du hub (hors API : la minuterie tourne sans le service)."""
    from api import registry
    menu = registry.load_menu_cache(menu_path)
    return [s.model_dump() for s in registry.normalize_services(menu, {}, registry.load_exposure_cache())]


def main(argv=None) -> int:
    import asyncio
    cache_dir = Path(os.environ.get("WEBOS_SHOTS_CACHE", str(CACHE_DIR)))
    threshold = float(os.environ.get("WEBOS_SHOTS_LOAD_THRESHOLD", LOAD_THRESHOLD))
    if not load_ok(threshold):
        print(json.dumps({"skipped": "load-guard", "threshold": threshold}))
        return 0
    lock = acquire_lock(cache_dir / LOCK_NAME)
    if lock is None:
        print(json.dumps({"skipped": "locked"}))
        return 0
    try:
        choix = pick_next(services_du_registre(os.environ.get("WEBOS_MENU", MENU)), cache_dir)
        if choix is None:
            print(json.dumps({"skipped": "nothing-to-capture"}))
            return 0
        res = asyncio.run(capture_module(choix[0], choix[1], cache_dir))
        print(json.dumps(res))
        return 0 if res.get("ok") or res.get("sans_page") else 1
    finally:
        fcntl.flock(lock, fcntl.LOCK_UN)
        lock.close()
