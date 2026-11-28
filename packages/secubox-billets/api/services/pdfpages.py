# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""
SecuBox-Deb :: billets — pages d'un PDF joint en images (#4049)
CyberMind — https://cybermind.fr

Un PDF joint à un billet est rendu CÔTÉ SERVEUR, page par page, en JPEG, pour le
diaporama des cartes et de la vue. Aucune bibliothèque chargée chez le lecteur
(pas de PDF.js) : la box sert des images, le navigateur n'interprète jamais le PDF.

Bornes : `MAX_PAGES` pages au plus, côté long ramené à `COTE` pixels, chaque page
au plus `MAX_PAGE_BYTES` (une page plus lourde arrête le rendu là), délai total
`DELAI` secondes, priorité basse (`nice -n 19`), sans shell, argument `--` avant
le chemin. Le cache vit sous `pages_dir()/<id du média>/p-NNN.jpg` : le nom dérive
de l'identifiant du média, jamais du nom envoyé. Un échec laisse un marqueur
`.echec` (pas de rendu en boucle) ; la carte garde alors une diapositive
« document ».

Le dossier n'est PAS sous /media/ (servi en direct par nginx) : les pages passent
par la route gardée `/b/<slug>/diapo/<media>/<n>`, même visibilité que le billet.
"""
from __future__ import annotations

import asyncio
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

MAX_PAGES = 30
COTE = 1280                       # côté long, en pixels
MAX_PAGE_BYTES = 2 * 1024 * 1024  # 2 Mio par page
DELAI = 120                       # secondes, pour tout le document

_ID = re.compile(r"^[0-9A-Za-z]{10,40}$")
_PAGE = re.compile(r"^p-(\d{3})\.jpg$")


def pages_dir() -> Path:
    return Path(os.environ.get("BILLETS_PDFPAGES_DIR", "/var/lib/secubox/billets/pdfpages"))


def _dossier(media_id: str, racine: Path | None = None) -> Path | None:
    if not _ID.match(media_id or ""):
        return None
    return (racine or pages_dir()) / media_id


def pages(media_id: str, racine: Path | None = None) -> int:
    """Nombre de pages en cache (0 si rien encore, ou échec)."""
    d = _dossier(media_id, racine)
    if d is None or not (d / ".ok").exists():
        return 0
    return sum(1 for f in d.iterdir() if _PAGE.match(f.name))


def echoue(media_id: str, racine: Path | None = None) -> bool:
    d = _dossier(media_id, racine)
    return d is None or (d / ".echec").exists()


def page(media_id: str, n: int, racine: Path | None = None) -> Path | None:
    """Chemin de la page `n` (1-indexée) si elle est en cache."""
    d = _dossier(media_id, racine)
    if d is None or not (1 <= n <= MAX_PAGES):
        return None
    f = d / f"p-{n:03d}.jpg"
    return f if (d / ".ok").exists() and f.is_file() else None


def supprimer(media_id: str, racine: Path | None = None) -> None:
    """Efface le cache des pages (média supprimé). Sans effet si absent."""
    d = _dossier(media_id, racine)
    if d is not None and d.exists():
        shutil.rmtree(d, ignore_errors=True)


def _marquer_echec(d: Path) -> None:
    try:
        d.mkdir(parents=True, exist_ok=True)
        (d / ".echec").write_text("")
    except OSError:
        pass


def rendre(media_id: str, pdf: Path, racine: Path | None = None) -> int:
    """Rend le PDF en pages JPEG (synchrone, à lancer hors boucle). Rend le nombre
    de pages produites ; 0 sur tout échec (jamais d'exception)."""
    d = _dossier(media_id, racine)
    if d is None:
        return 0
    if (d / ".ok").exists():
        return pages(media_id, racine)
    if (d / ".echec").exists():
        return 0
    outil = shutil.which("pdftoppm")
    try:
        if not outil or not pdf.is_file() or pdf.read_bytes()[:5] != b"%PDF-":
            _marquer_echec(d)
            return 0
    except OSError:
        _marquer_echec(d)
        return 0
    cmd = [outil, "-jpeg", "-jpegopt", "quality=80", "-scale-to", str(COTE),
           "-f", "1", "-l", str(MAX_PAGES), "--", str(pdf)]
    nice = shutil.which("nice")
    if nice:
        cmd = [nice, "-n", "19"] + cmd
    d.parent.mkdir(parents=True, exist_ok=True)
    try:
        with tempfile.TemporaryDirectory(prefix=f".{media_id}-", dir=str(d.parent)) as tmp:
            r = subprocess.run(cmd + [str(Path(tmp) / "p")], capture_output=True,
                               timeout=DELAI, check=False, stdin=subprocess.DEVNULL)
            # pdftoppm nomme p-1.jpg, p-01.jpg ou p-001.jpg selon le nombre de pages
            produits = sorted(((int(m.group(1)), f) for f in Path(tmp).iterdir()
                               if (m := re.match(r"^p-(\d+)\.jpg$", f.name))))
            if r.returncode != 0 and not produits:
                _marquer_echec(d)
                return 0
            final = Path(tmp) / "final"
            final.mkdir()
            n = 0
            for num, f in produits[:MAX_PAGES]:
                if f.stat().st_size > MAX_PAGE_BYTES:
                    break
                n += 1
                f.rename(final / f"p-{n:03d}.jpg")
            if n == 0:
                _marquer_echec(d)
                return 0
            (final / ".ok").write_text(str(n))
            if d.exists():
                shutil.rmtree(d, ignore_errors=True)
            final.rename(d)       # bascule atomique : jamais de cache à moitié écrit
            return n
    except (subprocess.TimeoutExpired, OSError):
        _marquer_echec(d)
        return 0


# ── Planification en tâche de fond (une seule à la fois) ─────────────────────
_en_cours: set[str] = set()
_taches: set[asyncio.Task] = set()
_verrous: dict = {}   # un sémaphore par boucle (les tests en ouvrent plusieurs)


def planifier(media_id: str, pdf: Path, racine: Path | None = None) -> bool:
    """Lance le rendu en fond si besoin (ni en cache, ni en échec, ni en cours).
    Rend True si une tâche a été lancée. Sans boucle asyncio active : rien."""
    if media_id in _en_cours or pages(media_id, racine) or echoue(media_id, racine):
        return False
    try:
        boucle = asyncio.get_running_loop()
    except RuntimeError:
        return False
    verrou = _verrous.setdefault(id(boucle), asyncio.Semaphore(1))
    _en_cours.add(media_id)

    async def _job():
        try:
            async with verrou:
                await asyncio.to_thread(rendre, media_id, pdf, racine)
        finally:
            _en_cours.discard(media_id)

    t = boucle.create_task(_job())
    _taches.add(t)
    t.add_done_callback(_taches.discard)
    return True
