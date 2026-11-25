# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox-Deb :: comptes administrateur sans mot de passe (#3708)

Un compte semé et jamais configuré restait revendicable pour toujours : la première configuration (#1707) remet un jeton
« set-password » à qui donne son nom avec un mot de passe vide depuis la zone de confiance (LAN, maillage). Ce module est
la RÈGLE UNIQUE que lisent la connexion (secubox-auth), le postinst et le renommage (moteur des comptes) et la santé :

- un administrateur CONFIGURÉ est un compte humain actif, de rôle `admin`, dont l'empreinte argon2 se lit, n'est PAS le
  mot de passe du premier démarrage et n'est pas « à changer ». Le défaut public, une empreinte illisible (SHA-256 v1 : personne ne peut entrer
  avec) et les comptes de service ne comptent pas : sur une box où il n'y a rien d'autre, le premier accès reste ouvert ;
- dès qu'il existe un administrateur configuré, plus aucun AUTRE compte sans mot de passe (ou admin au mot de passe du
  premier démarrage) ne s'ouvre, et ceux des admins qui n'ont JAMAIS SERVI sont désactivés (jamais supprimés) par le
  postinst. Un compte qui sert (second facteur, Google, service, connexion, appareil rattaché, session) n'est jamais
  désactivé : le refus à la connexion suffit. Une trace illisible compte comme un usage.

Bibliothèque stdlib (argon2 par `mot_de_passe_defaut`, chargé à la demande) : se charge aussi par son chemin, sans le
paquet secubox_core qui tire FastAPI (moteur des comptes sous root, sonde de santé chaque minute).
Aucun nom de compte ne sort de `resume()` : elle est servie à des appelants sans session.
"""
from __future__ import annotations

import fcntl
import importlib.util
import json
import os
import pwd
import shutil
import sqlite3
import stat
import tempfile
import threading
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, FrozenSet, Iterator, List, Optional, Set

try:
    import tomllib
except ImportError:  # pragma: no cover
    tomllib = None  # type: ignore[assignment]

#: Comptes de service : jamais comptés comme administrateur, jamais désactivés ni renommés ici. La console du kiosque
#: (#1695) porte un mot de passe aléatoire jeté ; les autres noms sont réservés aux services (IA, webhooks).
COMPTES_SYSTEME = frozenset({"console", "kiosk", "kiosque", "secubox-kiosk", "ai", "ai-ban", "ai-filtres", "webhook",
                             "webhooks"})


def _users_path() -> Path:
    return Path(os.environ.get("SECUBOX_USERS_JSON") or os.environ.get("USERS_FILE") or "/etc/secubox/users.json")


def _audit_path() -> Path:
    return Path(os.environ.get("SECUBOX_AUDIT_LOG", "/var/log/secubox/audit.log"))


def _conf_path() -> Path:
    return Path(os.environ.get("SECUBOX_CONF", "/etc/secubox/secubox.conf"))


def _delegues_path() -> Path:
    return Path(os.environ.get("SECUBOX_AUTH_DELEGUES", "/var/lib/secubox/auth/delegues.json"))


#: Marque d'une fermeture faite ici : seul ce motif se rouvre de lui-même (premier-pas).
MOTIF_FERMETURE = "sans-mot-de-passe-3708"
#: Marque d'un compte créé par un service (console, délégation) : il garde un mot de passe jeté, même s'il ne sert plus.
ORIGINE_SERVICE = "service"


# ── Écriture : UN verrou pour tous les écrivains de users.json ─────────────────────────────────────────────────────────

class VerrouOccupe(OSError):
    pass


_verrous: Dict[str, threading.RLock] = {}
_tenus: Dict[str, int] = {}
_verrous_garde = threading.Lock()


@contextmanager
def verrou(users: Path, delai: float = 10.0) -> Iterator[None]:
    """Lecture-modification-écriture exclusive de users.json, entre fils (RLock, réentrant) et entre processus (flock
    sur un fichier voisin). Attente bornée. Le fichier suit le propriétaire du dossier : root et secubox l'ouvrent."""
    cle = str(Path(users))
    with _verrous_garde:
        r = _verrous.setdefault(cle, threading.RLock())
    if not r.acquire(timeout=delai):
        raise VerrouOccupe("users.json occupé")
    fd = None
    try:
        if not _tenus.get(cle):
            fichier = Path(users).with_name("." + Path(users).name + ".verrou")
            drapeaux = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
            fichier.parent.mkdir(parents=True, exist_ok=True)
            try:
                fd = os.open(fichier, drapeaux)
            except FileNotFoundError:
                try:
                    fd = os.open(fichier, drapeaux | os.O_CREAT | os.O_EXCL, 0o640)
                    if os.geteuid() == 0:
                        d = os.stat(fichier.parent)
                        os.fchown(fd, d.st_uid, d.st_gid)
                except FileExistsError:
                    fd = os.open(fichier, drapeaux)
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise VerrouOccupe("verrou de users.json anormal")
            fin = time.monotonic() + delai
            while True:
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    if time.monotonic() >= fin:
                        raise VerrouOccupe("users.json occupé") from None
                    time.sleep(0.02)
        _tenus[cle] = _tenus.get(cle, 0) + 1
        try:
            yield
        finally:
            _tenus[cle] -= 1
    finally:
        if fd is not None:
            os.close(fd)
        r.release()


_mod_defaut: Any = None


def _defaut():
    """`mot_de_passe_defaut` (gardé : il tient le cache des verdicts), sans passer par le paquet si on n'y est pas."""
    global _mod_defaut
    if _mod_defaut is None:
        if __package__:
            from . import mot_de_passe_defaut as mod
        else:
            spec = importlib.util.spec_from_file_location("_sbx_mot_de_passe_defaut",
                                                          Path(__file__).with_name("mot_de_passe_defaut.py"))
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
        _mod_defaut = mod
    return _mod_defaut


# ── Lecture ────────────────────────────────────────────────────────────────────────────────────────────────────────────

def lire(chemin: Optional[Path] = None) -> Optional[Dict[str, Any]]:
    """Le registre v2, ou None s'il est absent, illisible ou d'une autre forme."""
    try:
        doc = json.loads(Path(chemin or _users_path()).read_text())
    except (OSError, ValueError):
        return None
    return doc if isinstance(doc, dict) and isinstance(doc.get("users"), list) else None


def comptes(doc: Any) -> List[Dict[str, Any]]:
    liste = doc.get("users") if isinstance(doc, dict) else None
    return [u for u in (liste if isinstance(liste, list) else [])
            if isinstance(u, dict) and isinstance(u.get("username"), str) and u["username"]]


def comptes_systeme() -> FrozenSet[str]:
    """Noms réservés, plus le compte de la console choisi dans secubox.conf et les comptes délégués ouverts (#1720)."""
    noms = set(COMPTES_SYSTEME)
    try:
        if tomllib is not None:
            section = tomllib.loads(_conf_path().read_text()).get("console")
            nom = section.get("compte") if isinstance(section, dict) else None
            if isinstance(nom, str) and nom.strip():
                noms.add(nom.strip())
    except (OSError, ValueError):
        pass                                   # config absente ou illisible : les noms par défaut
    try:
        reg = json.loads(_delegues_path().read_text())
        if isinstance(reg, dict):
            noms.update(str(k) for k in reg)
    except (OSError, ValueError):
        pass                                   # aucun compte délégué connu
    return frozenset(noms)


def sans_mot_de_passe(u: Dict[str, Any]) -> bool:
    return not u.get("password_hash")


def est_admin_actif(u: Dict[str, Any]) -> bool:
    return u.get("role") == "admin" and bool(u.get("enabled"))


def _anciens_services() -> FrozenSet[str]:
    """Comptes qu'un service a créés (journal d'authentification) : une console renommée ou un délégué fermé garde un
    mot de passe jeté que personne ne connaît."""
    noms: Set[str] = set()
    dossier = Path(os.environ.get("SECUBOX_AUTH_DATA_DIR", "/var/lib/secubox/auth"))
    journal = Path(os.environ.get("SECUBOX_AUTH_AUDIT", str(dossier / "audit.log")))
    try:
        with journal.open("rb") as f:
            f.seek(max(0, os.fstat(f.fileno()).st_size - (8 << 20)))
            for ligne in f:
                if b"console_compte_cree" in ligne or b"delegation_compte_cree" in ligne:
                    try:
                        noms.add(str(json.loads(ligne).get("user")))
                    except (ValueError, AttributeError):
                        continue
    except OSError:
        pass                                   # journal absent : restent la marque et la forme du nom
    return frozenset(noms)


def _humain(u: Dict[str, Any], systeme: FrozenSet[str]) -> bool:
    """Un compte délégué FERMÉ a quitté le registre, mais garde son mot de passe jeté : `<compte>.<nœud>`, jamais
    connecté par mot de passe. Il ne prouve pas qu'un administrateur est configuré."""
    nom = u["username"]
    return (nom not in systeme and u.get("origine") != ORIGINE_SERVICE
            and not ("." in nom and not u.get("last_login")))


def _verdict(u: Dict[str, Any]) -> str:
    h = u.get("password_hash")
    if not isinstance(h, str) or not h:
        return "inconnu"
    try:
        return _defaut()._verdict_empreinte(h)
    except Exception:  # noqa: BLE001 — argon2 absent, empreinte bizarre : rien n'est prouvé, donc rien n'est fermé
        return "inconnu"


def au_mot_de_passe_defaut(u: Dict[str, Any]) -> bool:
    return _verdict(u) == "actif"


def admin_avec_mot_de_passe(doc: Any) -> bool:
    """Un administrateur humain actif peut-il entrer par mot de passe, fût-ce celui du premier démarrage ?"""
    s = comptes_systeme() | _anciens_services()
    return any(est_admin_actif(u) and _humain(u, s) and _verdict(u) in ("actif", "inactif") for u in comptes(doc))


def admin_configure(doc: Any, sauf: Optional[str] = None) -> bool:
    """Y a-t-il un administrateur humain actif, autre que `sauf`, au mot de passe choisi (pas le défaut) ?"""
    s = comptes_systeme() | _anciens_services()
    return any(est_admin_actif(u) and _humain(u, s) and u["username"] != sauf
               and not u.get("must_change_password") and _verdict(u) == "inactif"
               for u in comptes(doc))


def admins_sans_mot_de_passe(doc: Any) -> List[str]:
    """Administrateurs actifs sans mot de passe, comptes de service exclus."""
    s = comptes_systeme()
    return [u["username"] for u in comptes(doc)
            if est_admin_actif(u) and sans_mot_de_passe(u) and u["username"] not in s]


def traces_d_usage() -> Optional[FrozenSet[str]]:
    """Comptes à session, ou auxquels un appareil est rattaché (/acces, sbxid). None si une trace existe sans se lire :
    on ne sait pas, donc on ne désactive personne."""
    noms: Set[str] = set()
    chemin = Path(os.environ.get("SECUBOX_AUTH_SESSIONS", "/var/lib/secubox/auth/sessions.json"))
    demandes = Path(os.environ.get("SECUBOX_ACCES_DEMANDES", "/var/lib/secubox/acces/demandes.json"))
    for fichier, cle_liste, cle in ((chemin, "sessions", "username"), (demandes, "demandes", "compte")):
        try:
            doc = json.loads(fichier.read_text())
        except FileNotFoundError:
            continue
        except (OSError, ValueError):
            return None
        lignes = doc.get(cle_liste) if isinstance(doc, dict) else doc
        if not isinstance(lignes, list):
            return None
        for d in lignes:
            if isinstance(d, dict) and isinstance(d.get(cle), str) and d.get("etat") != "refusee":
                noms.add(d[cle].strip().lower())
    base = Path(os.environ.get("SBXID_DB", "/var/lib/secubox/sbxid/sbx.db"))
    if base.exists():
        # Une COPIE (base et journal WAL) : root qui ouvrirait la base du service y laisserait des fichiers à lui (#1806).
        try:
            with tempfile.TemporaryDirectory() as d:
                for suffixe in ("", "-wal"):
                    if Path(str(base) + suffixe).exists():
                        shutil.copyfile(str(base) + suffixe, os.path.join(d, "sbx.db" + suffixe))
                c = sqlite3.connect(os.path.join(d, "sbx.db"))
                try:
                    noms.update(str(r[0]).lower() for r in c.execute("SELECT app_id FROM sbx_app_links WHERE app='systeme'"))
                finally:
                    c.close()
        except (OSError, sqlite3.Error):
            return None
    return frozenset(noms)


def jamais_servi(u: Dict[str, Any], traces: Optional[FrozenSet[str]]) -> bool:
    return (traces is not None and u["username"].lower() not in traces
            and not any(u.get(c) for c in ("last_login", "totp", "google", "services")))


def a_refermer(doc: Any) -> Dict[str, str]:
    """Admins jamais servis à désactiver, et pourquoi : sans mot de passe, ou encore au mot de passe du premier
    démarrage. Vide tant qu'aucun administrateur n'est configuré."""
    if not admin_configure(doc):
        return {}
    s, traces = comptes_systeme() | _anciens_services(), traces_d_usage()
    out: Dict[str, str] = {}
    for u in comptes(doc):
        if not est_admin_actif(u) or u["username"] in s or u.get("origine") == ORIGINE_SERVICE \
                or not jamais_servi(u, traces):
            continue
        if sans_mot_de_passe(u):
            out[u["username"]] = "sans_mot_de_passe"
        elif au_mot_de_passe_defaut(u):
            out[u["username"]] = "mot_de_passe_defaut"
    return out


def premiere_configuration_permise(compte: str, doc: Any) -> bool:
    """La première configuration (#1707) reste-t-elle ouverte à ce compte ? Registre illisible : non."""
    return isinstance(doc, dict) and isinstance(doc.get("users"), list) and not admin_configure(doc, sauf=compte)


def resume(chemin: Optional[Path] = None) -> Dict[str, Any]:
    """Pour la santé : des NOMBRES, jamais un nom. Sans argon2 (appelée chaque minute)."""
    doc = lire(chemin)
    if doc is None:
        return {"lisible": False, "sans_mot_de_passe": None}
    return {"lisible": True, "sans_mot_de_passe": len(admins_sans_mot_de_passe(doc))}


# ── Audit ──────────────────────────────────────────────────────────────────────────────────────────────────────────────

def auditer(evenement: str, **champs: Any) -> None:
    """Une ligne JSON en ajout seul dans /var/log/secubox/audit.log. Lève OSError : à l'appelant de décider (une
    désactivation non auditée n'a pas lieu ; un refus, si)."""
    entree = {"ts": datetime.now(timezone.utc).isoformat(), "module": "comptes_admin", "evenement": evenement}
    entree.update({k: v for k, v in champs.items() if v is not None})
    donnees = (json.dumps(entree, ensure_ascii=True) + "\n").encode()
    chemin = _audit_path()
    base = os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW | os.O_CLOEXEC
    try:
        fd = os.open(chemin, base)
    except FileNotFoundError:
        fd = os.open(chemin, base | os.O_CREAT | os.O_EXCL, 0o640)
        if os.geteuid() == 0:
            try:
                p = pwd.getpwnam("secubox")
                os.fchown(fd, p.pw_uid, p.pw_gid)
            except (KeyError, OSError):
                pass                           # compte absent : le journal reste à root, la ligne est écrite
    try:
        os.write(fd, donnees)
    finally:
        os.close(fd)
