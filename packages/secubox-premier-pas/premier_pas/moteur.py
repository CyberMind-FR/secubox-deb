# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: Premier Pas — le MOTEUR (#1522)
CyberMind — https://cybermind.fr

Le moteur n'invente rien : chaque étape pilote un outil qui existe déjà dans
secubox-deb (relevé par l'audit du 2026-09-27, tableau de la maquette) :

    nom       hostnamectl                    (comme POST /system/settings)
    horloge   timedatectl + timesyncd        (#1497)
    admin     moteur de secubox-users        (empreinte argon2 seulement)
    reseau    secubox-net-detect apply ; domaine → secubox.conf
    services  secubox-profilectl apply --yes (R1..R4)
    maillage  sbx-mesh-join                  (rend la box visible, #1530)
    majs      minuterie secubox-majauto      (ce paquet)

Trois règles :
  1. un profil incomplet N'EST PAS appliqué : on rend l'étape où reprendre ;
  2. les étapes s'exécutent dans l'ordre et s'ARRÊTENT à la première erreur ;
  3. le marqueur `.premier-pas-fait` n'est écrit qu'à la toute fin.

Les commandes passent par un exécuteur injectable : les tests ne touchent à
rien, et `plan` montre exactement ce qui serait fait.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from . import profil as P

MARQUEUR = Path("/var/lib/secubox/.premier-pas-fait")
ETAT = Path("/run/secubox-premier-pas/etat.json")
JOURNAL = Path("/var/log/secubox/premier-pas.log")
SECUBOX_CONF = Path("/etc/secubox/secubox.conf")
USERS_FILE = Path("/etc/secubox/users.json")
MAJAUTO_DROPIN = Path("/etc/systemd/system/secubox-majauto.timer.d/heure.conf")

# Où chercher un profil prêt, dans l'ordre (maquette : trois sources).
SOURCES = (
    Path("/boot/secubox/profil.toml"),
    Path("/boot/firmware/secubox/profil.toml"),   # Raspberry Pi
    Path("/run/secubox-premier-pas/usb/profil.toml"),  # LABEL=SBXPROFIL monté ici
)


@dataclass
class Action:
    etape: str
    quoi: str                        # en clair, pour les faces et le journal
    argv: Optional[List[str]] = None  # commande, ou None pour une action Python
    fn: Optional[Callable[[], None]] = None


Executeur = Callable[[List[str]], Tuple[int, str]]


def execute_reel(argv: List[str]) -> Tuple[int, str]:
    try:
        r = subprocess.run(argv, capture_output=True, text=True, timeout=1800)
        return r.returncode, (r.stdout + r.stderr)[-4000:]
    except (OSError, subprocess.TimeoutExpired) as e:
        return 127, str(e)


# ── Sources ────────────────────────────────────────────────────────────────

def cherche_profil(cmdline: Optional[str] = None) -> Optional[Path]:
    """Le profil prêt : `secubox.profil=<chemin>` sur la ligne noyau d'abord,
    puis les emplacements connus. (URL signée : face « panneau maître ».)"""
    if cmdline is None:
        try:
            cmdline = Path("/proc/cmdline").read_text()
        except OSError:
            cmdline = ""
    m = re.search(r"(?:^|\s)secubox\.profil=(\S+)", cmdline)
    if m and m.group(1).startswith("/"):
        return Path(m.group(1)) if Path(m.group(1)).is_file() else None
    for s in SOURCES:
        if s.is_file():
            return s
    return None


# ── Plan ───────────────────────────────────────────────────────────────────

def _ecrit_conf(domaine: Optional[str]) -> None:
    """Domaine dans secubox.conf : [global] domain et [api] sso_cookie_domain.

    Édition LIGNE À LIGNE plutôt que réécriture du TOML : le fichier porte des
    commentaires et des sections qu'aucun autre outil ne doit perdre."""
    texte = SECUBOX_CONF.read_text() if SECUBOX_CONF.exists() else ""
    lignes = texte.splitlines()

    def pose(section: str, cle: str, valeur: Optional[str]):
        nonlocal lignes
        entete = f"[{section}]"
        if entete not in lignes:
            if valeur is None:
                return
            lignes += ["", entete]
        i = lignes.index(entete)
        j = i + 1
        while j < len(lignes) and not lignes[j].startswith("["):
            if re.match(rf"^\s*{cle}\s*=", lignes[j]):
                if valeur is None:
                    del lignes[j]
                else:
                    lignes[j] = f'{cle} = "{valeur}"'
                return
            j += 1
        if valeur is not None:
            lignes.insert(j if j < len(lignes) else len(lignes), f'{cle} = "{valeur}"')

    pose("global", "domain", domaine)
    pose("api", "sso_cookie_domain", f".{domaine}" if domaine else None)
    tmp = SECUBOX_CONF.with_suffix(".premier-pas.tmp")
    tmp.write_text("\n".join(lignes) + "\n")
    if SECUBOX_CONF.exists():
        st = SECUBOX_CONF.stat()
        os.chown(tmp, st.st_uid, st.st_gid)
        os.chmod(tmp, st.st_mode & 0o7777)
    os.replace(tmp, SECUBOX_CONF)


def _pose_empreinte_admin(empreinte: str) -> None:
    """Empreinte argon2 déjà calculée ailleurs (le clair ne transite jamais).
    Passe par le moteur de secubox-users : même écriture atomique, même
    propriétaire préservé, même journal d'audit que l'API."""
    sys.path.insert(0, "/usr/lib/secubox/users")
    from api import engine  # noqa: PLC0415
    e = engine.Engine(users_path=USERS_FILE)
    doc = e._load()
    u = e._find(doc, "admin")
    if not u:
        raise RuntimeError("compte admin absent de users.json")
    u["password_hash"] = empreinte
    u["must_change_password"] = False
    e._save(doc)
    try:
        e._audit("password_set", "admin", {"par": "premier-pas"})
    except Exception:
        pass


def _majauto(auto: bool, heure: str) -> None:
    if auto:
        MAJAUTO_DROPIN.parent.mkdir(parents=True, exist_ok=True)
        MAJAUTO_DROPIN.write_text(f"[Timer]\nOnCalendar=\nOnCalendar=*-*-* {heure}:00\n")
    elif MAJAUTO_DROPIN.exists():
        MAJAUTO_DROPIN.unlink()


def plan(profil: Dict[str, Any]) -> List[Action]:
    """Les actions exactes, dans l'ordre. Suppose un profil complet."""
    box, reseau = profil.get("box") or {}, profil.get("reseau") or {}
    admin, m, apt = profil.get("admin") or {}, profil.get("maillage") or {}, profil.get("apt") or {}
    nom = str(box["nom"]).strip().lower()
    out: List[Action] = [
        Action("nom", f"nommer la box « {nom} »", ["hostnamectl", "set-hostname", nom]),
        Action("horloge", f"fuseau {box['fuseau']}", ["timedatectl", "set-timezone", str(box["fuseau"])]),
        Action("horloge", "synchronisation NTP", ["timedatectl", "set-ntp", "true"]),
    ]
    mdp = admin.get("mot_de_passe")
    if mdp and mdp != "demander":
        out.append(Action("admin", "mot de passe admin (empreinte argon2)", fn=lambda: _pose_empreinte_admin(mdp)))
    out.append(Action("admin", "TOTP : enrôlé à la première connexion (écran de la box)"))
    mode = reseau["mode"]
    dom = None if mode == "lan" else str(reseau["domaine"]).strip().lower()
    out.append(Action("reseau", f"mode réseau {mode}", ["secubox-net-detect", "apply", P.MODES_RESEAU[mode]]))
    out.append(Action("reseau", f"domaine {dom}" if dom else "LAN seul, sans domaine", fn=lambda: _ecrit_conf(dom)))
    sp = profil["services"]["profil"]
    out.append(Action("services", f"profil de services « {sp} »",
                      ["secubox-profilectl", "apply", "--profile", sp, "--yes"]))
    if m["mode"] == "rejoindre":
        out.append(Action("maillage", f"rejoindre {m['rejoindre']}",
                          ["sbx-mesh-join", str(m["rejoindre"]), str(m["jeton"])]))
    else:
        out.append(Action("maillage", "première box" if m["mode"] == "premiere" else "maillage plus tard"))
    heure = str(apt.get("heure", "03:00"))
    out.append(Action("majs", f"mises à jour automatiques à {heure}" if apt["auto"] else "mises à jour sur validation",
                      fn=lambda: _majauto(bool(apt["auto"]), heure)))
    out.append(Action("majs", "minuterie des mises à jour",
                      ["systemctl", "enable" if apt["auto"] else "disable", "--now", "secubox-majauto.timer"]))
    return out


# ── Jeton de démarrage (couche 2) ──────────────────────────────────────────

JETON = Path("/run/secubox-premier-pas/jeton")
# Le jeton LOCAL : seuls le kiosque et la console le connaissent. Jamais
# affiché, jamais transmis à la box maîtresse — c'est lui qui prouve que
# « Accepter » vient de la personne devant la box (#1522, validation).
JETON_LOCAL = Path("/run/secubox-premier-pas/jeton-local")


def _dossier_prive(d: Path) -> None:
    """HORS de /run/secubox (#1540) : des services y portent RuntimeDirectory=
    secubox, et systemd ré-approprie alors TOUT le dossier au dernier service
    démarré — l'API (secubox) perdait la lecture de ses jetons. Ici : root:secubox
    0750, posé explicitement, sans dépendre de l'umask."""
    import grp
    d.mkdir(parents=True, exist_ok=True)
    try:
        os.chown(d, 0, grp.getgrnam("secubox").gr_gid)
        os.chmod(d, 0o750)
    except (KeyError, PermissionError):
        pass


def _pose(chemin: Path) -> str:
    import grp
    import secrets
    _dossier_prive(chemin.parent)
    if chemin.exists() and chemin.read_text().strip():
        return chemin.read_text().strip()
    jeton = secrets.token_urlsafe(24)
    tmp = chemin.with_suffix(".tmp")
    tmp.write_text(jeton + "\n")
    try:
        os.chown(tmp, 0, grp.getgrnam("secubox").gr_gid)
    except (KeyError, PermissionError):
        pass
    os.chmod(tmp, 0o640)
    os.replace(tmp, chemin)
    return jeton


def pose_jeton() -> str:
    """Pose les deux jetons ; rend le jeton d'appairage (le « code »)."""
    _pose(JETON_LOCAL)
    return _pose(JETON)


# ── État partagé par les faces ─────────────────────────────────────────────

def ecrit_etat(**etat: Any) -> None:
    etat["a"] = int(time.time())
    try:
        ETAT.parent.mkdir(parents=True, exist_ok=True)
        tmp = ETAT.with_suffix(".tmp")
        tmp.write_text(json.dumps(etat, ensure_ascii=False, indent=1))
        os.replace(tmp, ETAT)
    except OSError:
        pass


def journal(ligne: str) -> None:
    try:
        JOURNAL.parent.mkdir(parents=True, exist_ok=True)
        with JOURNAL.open("a") as f:
            f.write(time.strftime("%Y-%m-%dT%H:%M:%S ") + ligne + "\n")
    except OSError:
        pass


# ── Appliquer ──────────────────────────────────────────────────────────────

@dataclass
class Resultat:
    ok: bool
    faites: List[str] = field(default_factory=list)
    echec: Optional[str] = None
    detail: str = ""
    reprendre: Optional[str] = None


def appliquer(profil: Dict[str, Any], executeur: Executeur = execute_reel,
              profils_connus: Optional[List[str]] = None, marqueur: Path = MARQUEUR) -> Resultat:
    ex = P.examine(profil, profils_connus)
    if not ex.complet:
        ecrit_etat(phase="assistant", reprendre=ex.premiere_etape,
                   manquantes=ex.manquantes, erreurs=ex.erreurs)
        journal(f"profil incomplet : reprendre à « {ex.premiere_etape} »")
        return Resultat(ok=False, reprendre=ex.premiere_etape,
                        detail="; ".join(f"{k} : {v}" for k, v in ex.erreurs.items()) or
                               "à compléter : " + ", ".join(ex.manquantes))
    actions = plan(profil)
    faites: List[str] = []
    for i, a in enumerate(actions, 1):
        ecrit_etat(phase="application", etape=a.etape, action=a.quoi, n=i, total=len(actions))
        journal(f"[{a.etape}] {a.quoi}")
        try:
            if a.argv:
                code, sortie = executeur(a.argv)
                if code != 0:
                    raise RuntimeError(f"{' '.join(a.argv)} → code {code} : {sortie.strip()[-300:]}")
            elif a.fn:
                a.fn()
        except Exception as e:  # noqa: BLE001 — on s'arrête, on dit où
            journal(f"ÉCHEC [{a.etape}] {e}")
            ecrit_etat(phase="echec", etape=a.etape, action=a.quoi, erreur=str(e), reprendre=a.etape)
            return Resultat(ok=False, faites=faites, echec=a.etape, detail=str(e), reprendre=a.etape)
        faites.append(a.quoi)
    marqueur.parent.mkdir(parents=True, exist_ok=True)
    marqueur.write_text(time.strftime("%Y-%m-%dT%H:%M:%S\n"))
    ecrit_etat(phase="fait", total=len(actions))
    journal("premier pas terminé")
    return Resultat(ok=True, faites=faites)
