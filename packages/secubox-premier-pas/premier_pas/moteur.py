# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: Premier Pas — le MOTEUR (#1522)
CyberMind — https://cybermind.fr

Le moteur n'invente rien : chaque étape pilote un outil qui existe déjà dans
secubox-deb (relevé par l'audit du 2026-09-27, tableau de la maquette) :

    nom       secubox-renommer               (comme POST /system/settings, #3242)
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

from . import ancre_p2p
from . import profil as P

MARQUEUR = Path("/var/lib/secubox/.premier-pas-fait")
ETAT = Path("/run/secubox-premier-pas/etat.json")
JOURNAL = Path("/var/log/secubox/premier-pas.log")
SECUBOX_CONF = Path("/etc/secubox/secubox.conf")
NET_DETECT = Path("/usr/sbin/secubox-net-detect")
HAPROXYCTL = Path("/usr/sbin/haproxyctl")
DEFAULTS_ALIGNER = Path("/usr/sbin/secubox-defaults-aligner")
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
    essais: int = 1                   # tentatives (réseau qui revient, #1544)
    pause: float = 5.0
    souple: bool = False              # un échec est DIT mais n'arrête pas l'assistant (#2495) : ce qui ne doit pas bloquer une première installation
    codes_souples: Tuple[int, ...] = ()  # codes de retour traités comme `souple` pour cette seule action (#3428)


Executeur = Callable[[List[str]], Tuple[int, str]]

#: `secubox-profilectl apply` : paquets du profil non installables (réseau, dépôt) — rien changé (api/montee.py, #3428).
PROFILCTL_DIFFERE = 4

_CAUSE = re.compile(r"❌|✗|\bfail|échec|erreur|error|refus|masked|→ rc=", re.I)


def cause(sortie: str, n: int = 300) -> str:
    """Ce qu'une personne doit lire d'une commande en échec : les lignes qui
    disent la cause, pas la fin de la sortie. Sur gk3 la fin était la liste
    des rollbacks, et la cause (unité masquée) était perdue (#1544)."""
    lignes = [l.strip() for l in sortie.strip().splitlines() if l.strip()]
    utiles = [l for l in lignes if _CAUSE.search(l)]
    texte = " · ".join(utiles[:3]) if utiles else " · ".join(lignes[-3:])
    return texte[:n]


#: Unité transitoire de la montée de niveau (#3428). profilectl y lance apt-get, qui n'a JAMAIS de délai : un délai ici
#: tuerait profilectl et laisserait apt orphelin, verrou dpkg pris. Dans une unité systemd, apt vit et meurt avec elle.
UNITE_MONTEE = "secubox-montee-profil"


def argv_montee(argv: List[str]) -> List[str]:
    return ["systemd-run", "--wait", "--pipe", "--collect", "--quiet", "--unit", UNITE_MONTEE, *argv]


def execute_reel(argv: List[str]) -> Tuple[int, str]:
    if argv and argv[0] == "secubox-profilectl":
        # Sans délai : peut installer un méta-paquet par apt (api/montee.py de secubox-profiles).
        try:
            r = subprocess.run(argv_montee(argv), capture_output=True, text=True)
            return r.returncode, (r.stdout + r.stderr)[-4000:]
        except OSError as e:
            return 127, str(e)
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

# Renommage (#3126 D3, #3242) : un seul outil, celui de secubox-core — ligne 127.0.1.1 de /etc/hosts, [global] hostname
# de secubox.conf, hostnamectl, relance d'Avahi (#1544, #1556), audit box_renommee, état précédent rétabli à tout échec.
RENOMMER = "/usr/sbin/secubox-renommer"


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


def _garde_mot_de_passe_defaut() -> None:
    """« Plus tard » (#3401) : l'empreinte reste celle du premier démarrage, le compte reste « à changer ». Rien d'autre
    n'est persisté : à chaque connexion, le changement est redemandé, et l'écran de changement offre à nouveau
    « Plus tard » (admin, LAN/kiosque/maillage, audité). Les gardes lisent `secubox_core.mot_de_passe_defaut`."""
    sys.path.insert(0, "/usr/lib/secubox/users")
    try:
        from api import engine  # noqa: PLC0415
    except ImportError as e:
        raise RuntimeError(f"moteur des comptes introuvable (paquet secubox-auth absent ?) : {e}") from None
    from secubox_core import mot_de_passe_defaut  # noqa: PLC0415
    e = engine.Engine(users_path=USERS_FILE)
    doc = e._load()
    u = e._find(doc, "admin")
    if not u:
        raise RuntimeError("compte admin absent de users.json")
    u["must_change_password"] = True
    e._save(doc)
    mot_de_passe_defaut.audit("premier_pas_plus_tard", {"compte": "admin"})


def _majauto(auto: bool, heure: str) -> None:
    if auto:
        MAJAUTO_DROPIN.parent.mkdir(parents=True, exist_ok=True)
        MAJAUTO_DROPIN.write_text(f"[Timer]\nOnCalendar=\nOnCalendar=*-*-* {heure}:00\n")
    elif MAJAUTO_DROPIN.exists():
        MAJAUTO_DROPIN.unlink()


def _reseau_existant_conserve(sortie_route: Optional[str] = None) -> None:
    """Mode « lan » sans `secubox-net-detect` (#2306) : une seule carte, rien à reconfigurer. On CONSERVE le réseau en place, à condition qu'il ait une route par défaut :
    sans elle l'étape suivante (apt, tunnel) n'ira nulle part, et on le dit ici plutôt que plus loin."""
    if sortie_route is None:
        try:
            sortie_route = subprocess.run(["ip", "route", "show", "default"], capture_output=True, text=True, timeout=10).stdout
        except (OSError, subprocess.TimeoutExpired) as e:
            raise RuntimeError(f"réseau existant : route par défaut illisible ({e})") from None
    if "default" not in (sortie_route or ""):
        raise RuntimeError("réseau existant : aucune route par défaut — branchez la box ou corrigez la configuration réseau, puis reprenez")


def plan(profil: Dict[str, Any]) -> List[Action]:
    """Les actions exactes, dans l'ordre. Suppose un profil complet."""
    box, reseau = profil.get("box") or {}, profil.get("reseau") or {}
    admin, m, apt = profil.get("admin") or {}, profil.get("maillage") or {}, profil.get("apt") or {}
    nom = str(box["nom"]).strip().lower()
    out: List[Action] = [
        # Un seul pas : hosts, secubox.conf, hostnamectl, Avahi et audit, défaits ensemble si l'un échoue (#3242).
        Action("nom", f"nommer la box « {nom} »", [RENOMMER, nom]),
        Action("horloge", f"fuseau {box['fuseau']}", ["timedatectl", "set-timezone", str(box["fuseau"])]),
        # Souple (#2495) : sans systemd-timesyncd (« NTP not supported ») l'assistant s'arrêtait ICI et la box restait inutilisable. Le défaut est dit à l'écran et au journal,
        # l'installation continue ; l'horloge se règle ensuite (Tor et TLS en dépendent) dès qu'un client NTP est présent.
        Action("horloge", "synchronisation NTP", ["timedatectl", "set-ntp", "true"], souple=True),
    ]
    mdp = admin.get("mot_de_passe")
    if mdp == P.PLUS_TARD:
        out.append(Action("admin", "mot de passe par défaut conservé — redemandé à chaque connexion (LAN ou maillage seuls, ni SSH par mot de passe "
                                   "ni exposition externe tant qu'il est actif)", fn=_garde_mot_de_passe_defaut))
    elif mdp and mdp != "demander":
        out.append(Action("admin", "mot de passe admin (empreinte argon2)", fn=lambda: _pose_empreinte_admin(mdp)))
    out.append(Action("admin", "TOTP : enrôlé à la première connexion (écran de la box)"))
    mode = reseau["mode"]
    dom = None if mode == "lan" else str(reseau["domaine"]).strip().lower()
    if mode == "lan" and not os.access(NET_DETECT, os.X_OK):
        # L'outil n'est livré par aucune image (#2306). Une seule carte : le réseau en place (DHCP ou statique) EST la configuration. Routeur et pont, eux, ne peuvent pas
        # s'appliquer sans l'outil : ils gardent la commande, qui échoue en le disant.
        out.append(Action("reseau", "mode réseau lan : réseau existant conservé (secubox-net-detect absent de cette image)", fn=_reseau_existant_conserve))
    else:
        out.append(Action("reseau", f"mode réseau {mode}", ["secubox-net-detect", "apply", P.MODES_RESEAU[mode]]))
    out.append(Action("reseau", f"domaine {dom}" if dom else "LAN seul, sans domaine", fn=lambda: _ecrit_conf(dom)))
    sp = profil["services"]["profil"]
    if sp == P.GARDER:
        out.append(Action("services", "modules actuels gardés"))
    else:
        # MONTÉE DE NIVEAU (#3428) : sur une image lite, profilectl installe d'abord secubox-<profil> par apt. Sans réseau
        # il rend PROFILCTL_DIFFERE sans rien changer : avertissement, l'assistant continue avec le profil d'amorçage.
        # ESSAIS (#3442) : l'étape réseau vient de basculer les interfaces (mode routeur) ; l'`apt-get update` qui suit rend 0 sans avoir rien lu
        # du dépôt (vu sur gk8 : « Unable to locate package secubox-isp », dépôt joignable une minute plus tard). PROFILCTL_DIFFERE ne change
        # rien au système : on le rejoue, puis on garde l'avertissement.
        out.append(Action("services", f"profil de services « {sp} »",
                          ["secubox-profilectl", "apply", "--profile", sp, "--yes"],
                          essais=6, pause=20.0, codes_souples=(PROFILCTL_DIFFERE,)))
    if dom and os.access(HAPROXYCTL, os.X_OK):
        # FRONTAL APRÈS LE DOMAINE (#3442) : firstboot tente `haproxyctl frontal` avant que le domaine existe et renonce ; nginx autonome
        # gardait 443 et la racine menait au Hall, plus à l'administration. Idempotent (rend 0 si déjà actif) ; souple : un refus laisse
        # nginx autonome, l'état d'avant, et se relance à la main.
        # /etc/default/secubox porte encore le nom de la machine de build (vu sur gk8 : runnervm…) : frontal refuse tant qu'il diffère du domaine.
        if os.access(DEFAULTS_ALIGNER, os.X_OK):
            out.append(Action("services", "nom de la box dans /etc/default/secubox", [str(DEFAULTS_ALIGNER)], souple=True))
        out.append(Action("services", "frontal HAProxy + sbxwaf", [str(HAPROXYCTL), "frontal"], souple=True))
    if m["mode"] == "rejoindre":
        if m.get("ancre_cle"):
            # L'ancre AVANT la jonction (#3100) : la box retient le maître qui l'a flashée ; un autre maître déjà ancré arrête l'étape.
            out.append(Action("maillage", f"ancre du maître {m.get('ancre_nom') or m['rejoindre']}", fn=lambda: _pose_ancre(m)))
        # L'étape réseau vient de reconfigurer les interfaces : le maître n'est
        # pas joignable dans la seconde (vu deux fois sur gk3, #1544).
        out.append(Action("maillage", f"rejoindre {m['rejoindre']}",
                          ["sbx-mesh-join", str(m["rejoindre"]), str(m["jeton"])], essais=12))
    elif m["mode"] == "automesh":
        # La jonction elle-même est faite par secubox-automesh (code déposé par la préparation) : ici on prépare le terrain — annuaire (inscription chez le
        # maître) et assistance — et on rend la main. Souple : une première installation ne doit pas échouer pour un maillage qui arrive plus tard.
        # #3467 : sans code déposé, rien n'est joint ; le journal et la page ne doivent pas dire le contraire.
        quoi = ("maillage automatique : jonction, annuaire et assistance activés" if CODE_AUTOMESH.exists()
                else "maillage automatique : aucun code de maître, box autonome pour l'instant")
        out.append(Action("maillage", quoi, fn=_activer_maillage, souple=True))
        if m.get("aide") == "demander":
            nom = str((profil.get("box") or {}).get("nom") or "")
            out.append(Action("maillage", "demande d'aide « première installation » publiée au maillage", fn=lambda: _demander_aide(nom), souple=True))
    else:
        out.append(Action("maillage", "première box" if m["mode"] == "premiere" else "maillage plus tard"))
    heure = str(apt.get("heure", "03:00"))
    out.append(Action("majs", f"mises à jour automatiques à {heure}" if apt["auto"] else "mises à jour sur validation",
                      fn=lambda: _majauto(bool(apt["auto"]), heure)))
    out.append(Action("majs", "minuterie des mises à jour",
                      ["systemctl", "enable" if apt["auto"] else "disable", "--now", "secubox-majauto.timer"]))
    return out


# ── Maillage automatique (#2544) ────────────────────────────────────────────

CLE_ANNUAIRE = Path("/etc/secubox/secrets/annuaire/node.key")
MARQUEUR_AIDE = Path("/var/lib/secubox/premier-pas/aide-demandee")
UNITES_MAILLAGE = ("secubox-automesh.timer", "secubox-annuaire.service", "secubox-assist.service")


ANCRE_CHEMIN = Path("/etc/secubox/p2p/ancre-maitre.json")
AUDIT_CHEMIN = Path("/var/log/secubox/audit.log")
CODE_AUTOMESH = Path("/var/lib/secubox/p2p/automesh.code")


def _charge_ancre():
    return ancre_p2p.charge()


def _pose_ancre(m: Dict[str, Any]) -> None:
    """Écrit l'ancre du maître sans jamais écraser (#3100). Une ancre déjà posée pour une AUTRE clé : la box appartient à un autre maître, on ne rejoint pas."""
    ancre = _charge_ancre()
    cle = str(m["ancre_cle"])
    adresse = str(m.get("ancre_adresse") or m["rejoindre"])
    nom = str(m.get("ancre_nom") or "")
    emp = str(m.get("ancre_empreinte") or ancre.empreinte(cle))
    existante = ancre.lire(str(ANCRE_CHEMIN))

    def audit(evenement: str, **plus) -> None:
        # Une décision de sécurité, une ligne (jamais de code ni de jeton). Journal illisible (pas root) : l'étape ne s'arrête pas pour autant.
        try:
            ancre.audit(evenement, chemin=str(AUDIT_CHEMIN), maitre=nom, adresse=adresse, empreinte=emp, **plus)
        except OSError:
            pass

    if existante is not None and not ancre.accepte(existante, cle):
        audit("ancre_refusee", empreinte_existante=str(existante.get("empreinte") or ancre.empreinte(str(existante.get("cle_publique") or ""))))
        raise RuntimeError(f"cette box est déjà ancrée à un autre maître ({existante.get('nom') or existante.get('empreinte') or '?'}) : jonction refusée")
    if existante is not None:
        audit("ancre_conservee")
        return
    if not ancre.ecrire(cle, adresse, nom, emp, chemin=str(ANCRE_CHEMIN), ecraser=False):
        raise RuntimeError("ancre du maître non écrite")
    audit("ancre_ecrite")


def _activer_maillage() -> None:
    """Active, une par une, la jonction automatique (minuterie), l'annuaire (inscription chez le maître) et l'assistance. Une unité absente de cette image
    est dite dans le journal et n'arrête rien ; seule l'absence de TOUTES les unités est une erreur."""
    ratees = []
    for unite in UNITES_MAILLAGE:
        r = subprocess.run(["systemctl", "enable", "--now", unite], capture_output=True, text=True, timeout=60)
        if r.returncode != 0:
            ratees.append(unite)
    if len(ratees) == len(UNITES_MAILLAGE):
        raise RuntimeError("aucune unité du maillage n'a pu être activée : " + ", ".join(ratees))


def _demander_aide(nom: str) -> None:
    """Publie UNE demande d'aide ouverte « première installation » (journal signé de l'annuaire, en tant que `secubox`, comme le fait l'API de l'assistance).

    Une seule fois (marqueur) : une réapplication du profil ne multiplie pas les demandes. Le maître la voit dans « En cours » et y répond ; le demandeur
    accepte l'aide proposée : aucune session sans son consentement. Sans identité d'annuaire (annuairectl init), on le dit et l'étape est remise (souple)."""
    if MARQUEUR_AIDE.exists():
        return
    if not CLE_ANNUAIRE.exists():
        raise RuntimeError("identité d'annuaire absente : la demande d'aide sera publiée quand la box aura son identité (annuairectl init)")
    r = subprocess.run(["runuser", "-u", "secubox", "--", "/usr/sbin/secubox-assistctl", "request-open", "--tags", "premiere-installation",
                        "--ttl", "86400", "--reason", f"première installation de {nom or 'cette box'}"], capture_output=True, text=True, timeout=60)
    if r.returncode != 0:
        raise RuntimeError("demande d'aide non publiée : " + cause(r.stderr or r.stdout))
    MARQUEUR_AIDE.parent.mkdir(parents=True, exist_ok=True)
    MARQUEUR_AIDE.write_text(time.strftime("%Y-%m-%dT%H:%M:%S%z") + "\n")


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
    avertissements: List[str] = field(default_factory=list)


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
    avertissements: List[str] = []
    for i, a in enumerate(actions, 1):
        ecrit_etat(phase="application", etape=a.etape, action=a.quoi, n=i, total=len(actions))
        journal(f"[{a.etape}] {a.quoi}")
        try:
            if a.argv:
                for essai in range(1, max(1, a.essais) + 1):
                    code, sortie = executeur(a.argv)
                    if code == 0 or essai == a.essais:
                        break
                    journal(f"[{a.etape}] essai {essai}/{a.essais} : {cause(sortie, 120)} — nouvel essai")
                    time.sleep(a.pause)
                if code != 0:
                    msg = f"{' '.join(a.argv)} → code {code} : {cause(sortie)}"
                    if a.souple or code in a.codes_souples:
                        journal(f"AVERTISSEMENT [{a.etape}] {msg} — l'assistant continue")
                        avertissements.append(f"{a.etape} : {a.quoi} — {cause(sortie, 160)}")
                        ecrit_etat(phase="application", etape=a.etape, action=a.quoi, n=i, total=len(actions), avertissements=avertissements)
                        continue
                    raise RuntimeError(msg)
            elif a.fn:
                a.fn()
        except Exception as e:  # noqa: BLE001 — on s'arrête, on dit où
            journal(f"ÉCHEC [{a.etape}] {e}")
            ecrit_etat(phase="echec", etape=a.etape, action=a.quoi, erreur=str(e), reprendre=a.etape)
            return Resultat(ok=False, faites=faites, echec=a.etape, detail=str(e), reprendre=a.etape)
        faites.append(a.quoi)
    marqueur.parent.mkdir(parents=True, exist_ok=True)
    marqueur.write_text(time.strftime("%Y-%m-%dT%H:%M:%S\n"))
    ecrit_etat(phase="fait", total=len(actions), avertissements=avertissements)
    journal("premier pas terminé" + (f" ({len(avertissements)} avertissement(s))" if avertissements else ""))
    return Resultat(ok=True, faites=faites, avertissements=avertissements)
