# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3338 — droit d'installer une app sous l'abonnement de la box. RÈGLE UNIQUE, lue par l'API (catalogue, refus 403) et
par secubox-appstorectl (root, frontière réelle) ; le ctl du pilotage applique la même règle de son côté.

FAIL-CLOSED. Sans /etc/secubox/abonnement.json, rien ne s'installe, SAUF signal POSITIF (voir _libre) : maître du
parc (secubox-fonction-maitre), box du propriétaire (drapeau de pilotage « proprietaire » valide), ou marqueur
/etc/secubox/abonnement-libre posé par l'opérateur.
Présent mais illisible, ou statut ≠ actif : rien. Sinon, seule une app du PROFIL de la formule s'installe ; le profil
est désigné par le NOM DE SON FICHIER (/etc/secubox/profiles/<profil>.toml), clé unique partout.

Exécutable : `python3 -I abonnement.py <module>` → code 0 permis, 3 refusé (motif sur stderr)."""
import json
import os
import re
import stat
import sys
import time
import tomllib

RE_PROFIL = re.compile(r"[a-z0-9][a-z0-9_-]{0,40}")
TAILLE_MAX = 1 << 20


def _racine() -> str:
    return os.environ.get("APPSTORE_RACINE", "").rstrip("/")


def _fichier_root(chemin: str, r: str):
    """Contenu d'un petit fichier ordinaire, sans lien, à root (sauf racine de test) et sans écriture groupe/autres."""
    try:
        fd = os.open(chemin, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError:
        return None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_mode & 0o022 or (st.st_uid != 0 and not r):
            return None
        return os.read(fd, 64)
    finally:
        os.close(fd)


def _libre(r: str) -> bool:
    """« Libre » seulement sur signal POSITIF (jamais déduit d'une absence) :
    (a) secubox-fonction-maitre installé — le maître du parc ;
    (b) drapeau de pilotage /etc/secubox-pilotage/proprietaire valide (root, échéance epoch future) — box du
        propriétaire, canal wg-mesh vérifié ; une box cliente (wg-autoload) ne l'a jamais ;
    (c) marqueur /etc/secubox/abonnement-libre posé explicitement par l'opérateur."""
    if os.path.isfile(f"{r}/var/lib/dpkg/info/secubox-fonction-maitre.list"):
        return True
    brut = _fichier_root(f"{r}/etc/secubox-pilotage/proprietaire", r)
    if brut is not None:
        try:
            if int(brut.decode("ascii").strip()) > time.time():
                return True
        except (UnicodeDecodeError, ValueError):
            pass
    return _fichier_root(f"{r}/etc/secubox/abonnement-libre", r) is not None


def modules_du_profil(profil: str, r: str = None):
    """Modules (`secubox-<id>`) du profil `<profil>.toml`, ou None si le nom ou le fichier ne vaut rien."""
    r = _racine() if r is None else r
    if not isinstance(profil, str) or not RE_PROFIL.fullmatch(profil):
        return None
    try:
        with open(f"{r}/etc/secubox/profiles/{profil}.toml", "rb") as f:
            on = tomllib.load(f).get("on") or []
    except (OSError, tomllib.TOMLDecodeError):
        return None
    if not isinstance(on, list):
        return None
    return {m if m.startswith("secubox-") else f"secubox-{m}" for m in on if isinstance(m, str)}


def droit(name: str, r: str = None):
    """(permis, formule_requise, motif)."""
    r = _racine() if r is None else r
    if _libre(r):
        return True, None, None
    try:
        with open(f"{r}/etc/secubox/abonnement.json", "rb") as f:
            ab = json.loads(f.read(TAILLE_MAX))
    except FileNotFoundError:
        return False, None, "aucun abonnement sur cette box"
    except (OSError, ValueError):
        return False, None, "abonnement illisible"
    if not isinstance(ab, dict):
        return False, None, "abonnement illisible"
    if ab.get("statut") != "actif":
        return False, None, f"abonnement {ab.get('statut') or 'inconnu'} : aucune installation"
    mods = modules_du_profil(ab.get("profil"), r)
    if mods is None:
        return False, None, "abonnement illisible"
    if name in mods:
        return True, None, None
    for fo in ab.get("formules") or []:
        if isinstance(fo, dict) and name in (modules_du_profil(fo.get("profil"), r) or set()):
            nom = str(fo.get("nom") or fo.get("profil"))
            return False, nom, f"Disponible avec la formule {nom}"
    return False, None, "hors de la formule de cette box"


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("usage : abonnement.py <module>", file=sys.stderr)
        sys.exit(2)
    ok, _req, motif = droit(sys.argv[1])
    if not ok:
        print(motif, file=sys.stderr)
    sys.exit(0 if ok else 3)
