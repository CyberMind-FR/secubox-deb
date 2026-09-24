# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: Users — comptes dans les services modulaires (#1375)
CyberMind — https://cybermind.fr

Un utilisateur SecuBox a, ou n'a pas, un compte dans Nextcloud, le courriel (et
donc le webmail), Gitea, PeerTube. Ce module le DIT (état mesuré, pas supposé)
et le FAIT (créer, retirer, activer, désactiver, réinitialiser, réparer) en
déléguant au helper root `secubox-usersctl-services`, par `sudo -n` et une
ligne sudoers exacte ; la demande voyage en JSON sur stdin.

LE MOT DE PASSE D'UN SERVICE N'EST PAS CONSERVÉ. Créé ou réinitialisé, il est
rendu UNE fois à l'administrateur, et envoyé — si on le demande — à l'adresse
de récupération de l'utilisateur. SecuBox n'en garde aucune copie.
"""
from __future__ import annotations

import json
import secrets
import smtplib
import subprocess
import threading
import time
import tomllib
from concurrent.futures import ThreadPoolExecutor
from email.message import EmailMessage
from pathlib import Path
from typing import Optional

HELPER = "/usr/sbin/secubox-usersctl-services"
CONF = Path("/etc/secubox/users.toml")

# Les services dont un compte se GÈRE d'ici. Les autres (jellyfin, matrix,
# jabber) restent listés par /services, mais sans adaptateur : l'écran le dit.
GERES = ("email", "nextcloud", "peertube", "gitea")
LIBELLES = {"email": "Courriel + webmail", "nextcloud": "Nextcloud",
            "peertube": "PeerTube", "gitea": "Gitea"}
ACTIONS = ("creer", "retirer", "activer", "desactiver", "reinitialiser", "reparer")

_ALPHABET = "abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"


def conf() -> dict:
    c = {"services_par_defaut": ["email", "nextcloud", "peertube"],
         "smtp_hote": "", "smtp_port": 25, "expediteur": ""}
    try:
        c.update(tomllib.loads(CONF.read_text()).get("users", {}))
    except (OSError, ValueError):
        pass
    # Le relais est déjà réglé pour les rapports de métriques : on le reprend
    # plutôt que d'exiger un second réglage identique.
    if not c.get("expediteur") or not c.get("smtp_hote"):
        try:
            r = tomllib.loads(Path("/etc/secubox/metrics.toml").read_text()).get("rapport", {})
        except (OSError, ValueError):
            r = {}
        c["expediteur"] = c.get("expediteur") or r.get("expediteur", "")
        c["smtp_hote"] = c.get("smtp_hote") or r.get("smtp_hote", "10.100.0.10")
        c["smtp_port"] = c.get("smtp_port") or r.get("smtp_port", 25)
    c["services_par_defaut"] = [s for s in c.get("services_par_defaut", []) if s in GERES]
    return c


def mot_de_passe_provisoire() -> str:
    # 16 signes sans les ambigus (0/O, 1/l/I) : il se lit et se recopie.
    return "".join(secrets.choice(_ALPHABET) for _ in range(16))


def helper(demande: dict, delai: int = 150) -> tuple[int, dict]:
    try:
        p = subprocess.run(["sudo", "-n", HELPER], input=json.dumps(demande),
                           capture_output=True, text=True, timeout=delai)
    except subprocess.TimeoutExpired:
        return 1, {"ok": False, "erreur": "délai dépassé"}
    except OSError as e:
        return 1, {"ok": False, "erreur": f"helper indisponible ({e})"}
    try:
        return p.returncode, json.loads(p.stdout.strip().splitlines()[-1])
    except (ValueError, IndexError):
        return p.returncode or 1, {"ok": False, "erreur": (p.stderr or p.stdout).strip()[-300:]
                                   or "réponse illisible du helper"}


def _demande(user: dict, service: str, action: str, password: str = "") -> dict:
    d = {"service": service, "action": action, "user": user["username"],
         "email": user.get("email") or "", "nom": user.get("display_name") or user["username"]}
    if password:
        d["password"] = password
    return d


# ── État, mis en cache : chaque lecture entre dans quatre conteneurs ─────────

_cache: dict[str, tuple[float, dict]] = {}
_verrou = threading.Lock()
CACHE_S = 60


def etat(user: dict, force: bool = False) -> dict:
    cle = user["username"]
    with _verrou:
        c = _cache.get(cle)
        if c and not force and time.time() - c[0] < CACHE_S:
            return c[1]

    def un(svc):
        rc, r = helper(_demande(user, svc, "etat"), delai=90)
        e = {"libelle": LIBELLES[svc], "code": rc}
        if rc == 0:
            e.update(r.get("etat") or {})
            e["disponible"] = True
        else:
            e.update({"existe": None, "actif": None, "disponible": rc != 4,
                      "erreur": r.get("erreur", "")})
        return svc, e

    with ThreadPoolExecutor(max_workers=len(GERES)) as ex:
        out = dict(ex.map(un, GERES))
    with _verrou:
        _cache[cle] = (time.time(), out)
    return out


def oublie(username: str) -> None:
    with _verrou:
        _cache.pop(username, None)


# ── Action ──────────────────────────────────────────────────────────────────

class ActionRefusee(Exception):
    def __init__(self, code: int, detail: str):
        super().__init__(detail)
        self.code, self.detail = code, detail


def _fait(user, svc, action, password=""):
    rc, r = helper(_demande(user, svc, action, password))
    if rc != 0:
        raise ActionRefusee(rc, r.get("erreur") or f"échec ({rc})")


def agit(user: dict, svc: str, action: str, password: Optional[str] = None) -> dict:
    """Rend {"etapes": [...], "mot_de_passe": <si créé/réinitialisé>}."""
    if svc not in GERES:
        raise ActionRefusee(3, f"service non géré : {svc}")
    if action not in ACTIONS:
        raise ActionRefusee(2, f"action inconnue : {action}")
    out: dict = {"etapes": []}
    try:
        if action in ("creer", "reinitialiser"):
            pw = password or mot_de_passe_provisoire()
            _fait(user, svc, action, pw)
            out["etapes"].append(action)
            if not password:
                out["mot_de_passe"] = pw
        elif action == "reparer":
            # RÉPARER = rendre l'état attendu : le compte existe, et il est actif.
            e = etat(user, force=True)[svc]
            if not e.get("disponible"):
                raise ActionRefusee(4, e.get("erreur") or "service indisponible")
            if not e.get("existe"):
                pw = password or mot_de_passe_provisoire()
                _fait(user, svc, "creer", pw)
                out["etapes"].append("creer")
                if not password:
                    out["mot_de_passe"] = pw
            elif e.get("actif") is False:
                _fait(user, svc, "activer")
                out["etapes"].append("activer")
            if not out["etapes"]:
                out["etapes"].append("rien à réparer")
        else:
            _fait(user, svc, action)
            out["etapes"].append(action)
    finally:
        oublie(user["username"])
    return out


# ── Courriel de récupération ─────────────────────────────────────────────────

def envoie(destinataire: str, sujet: str, corps: str) -> tuple[bool, str]:
    """Par le relais du conteneur `mail` (l'hôte est dans ses mynetworks)."""
    c = conf()
    exp = c.get("expediteur") or ""
    if not exp:
        return False, "aucun expéditeur configuré ([users] expediteur)"
    m = EmailMessage()
    m["From"], m["To"], m["Subject"] = exp, destinataire, sujet
    m.set_content(corps)
    try:
        with smtplib.SMTP(c["smtp_hote"], int(c["smtp_port"]), timeout=20) as s:
            s.send_message(m)
        return True, ""
    except (OSError, smtplib.SMTPException) as e:
        return False, str(e)[:200]


def message_mot_de_passe(user: dict, quoi: str, pw: str) -> tuple[str, str]:
    sujet = f"SecuBox — nouveau mot de passe ({quoi})"
    corps = (f"Bonjour {user.get('display_name') or user['username']},\n\n"
             f"Un administrateur a (ré)initialisé votre accès : {quoi}.\n"
             f"Identifiant : {user['username']}\n"
             f"Mot de passe provisoire : {pw}\n\n"
             "Changez-le à la première connexion. Si vous n'attendiez pas ce message, "
             "prévenez l'administrateur de la box.\n")
    return sujet, corps
