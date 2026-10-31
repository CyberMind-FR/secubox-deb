# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3338 — droit d'installer une app sous l'abonnement de la box. RÈGLE UNIQUE, lue par l'API (catalogue, refus 403) et
par secubox-appstorectl (root, frontière réelle) ; le ctl du pilotage applique la même règle de son côté.

FAIL-CLOSED. Sans /etc/secubox/abonnement.json, rien ne s'installe, SAUF si le marqueur root
/etc/secubox/abonnement-libre existe (box du maître ou de l'atelier, posé par le provisionnement ou par le maître).
Présent mais illisible, ou statut ≠ actif : rien. Sinon, seule une app du PROFIL de la formule s'installe ; le profil
est désigné par le NOM DE SON FICHIER (/etc/secubox/profiles/<profil>.toml), clé unique partout.

Exécutable : `python3 -I abonnement.py <module>` → code 0 permis, 3 refusé (motif sur stderr)."""
import json
import os
import re
import stat
import sys
import tomllib

RE_PROFIL = re.compile(r"[a-z0-9][a-z0-9_-]{0,40}")
TAILLE_MAX = 1 << 20


def _racine() -> str:
    return os.environ.get("APPSTORE_RACINE", "").rstrip("/")


def _libre(r: str) -> bool:
    try:
        st = os.lstat(f"{r}/etc/secubox/abonnement-libre")
    except OSError:
        return False
    return stat.S_ISREG(st.st_mode) and (st.st_uid == 0 or bool(r))


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


def poser_libre(r: str = None) -> str:
    """Producteur du marqueur (postinst) : posé sur le maître et les box d'atelier du propriétaire, c'est-à-dire quand la
    box N'EST PAS une box cliente provisionnée par Auto-Load (ni secubox-autoload-agent, ni abonnement.json). Jamais
    posé si abonnement.json existe ; jamais retiré (le provisionnement Auto-Load s'en charge). Par descripteur du
    dossier, sans suivre de lien, root 0644."""
    r = _racine() if r is None else r
    if os.path.lexists(f"{r}/etc/secubox/abonnement.json"):
        return "box sous abonnement : marqueur non posé"
    if os.path.exists(f"{r}/var/lib/dpkg/info/secubox-autoload-agent.list"):
        return "box cliente Auto-Load : marqueur non posé"
    try:
        d = os.open(f"{r}/etc/secubox", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except OSError:
        return "/etc/secubox absent : marqueur non posé"
    try:
        try:
            st = os.stat("abonnement-libre", dir_fd=d, follow_symlinks=False)
            return "marqueur déjà présent" if stat.S_ISREG(st.st_mode) else "abonnement-libre n'est pas un fichier : laissé"
        except FileNotFoundError:
            pass
        fd = os.open("abonnement-libre", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644, dir_fd=d)
        os.fchmod(fd, 0o644)
        os.close(fd)
        return "marqueur abonnement-libre posé (maître ou atelier)"
    finally:
        os.close(d)


if __name__ == "__main__":
    if sys.argv[1:] == ["--poser-libre"]:
        print(poser_libre())
        sys.exit(0)
    if len(sys.argv) != 2:
        print("usage : abonnement.py <module>", file=sys.stderr)
        sys.exit(2)
    ok, _req, motif = droit(sys.argv[1])
    if not ok:
        print(motif, file=sys.stderr)
    sys.exit(0 if ok else 3)
