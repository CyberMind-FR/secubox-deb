# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Niveau 0 du Coffre : secrets de démarrage (P3, #1367).

Certains secrets servent sans humain (mot de passe MQTT, secret du sysop…) :
ils ne peuvent pas attendre l'ouverture du Coffre. Ils passent par
`systemd-creds` : chiffrés sur disque (clé d'hôte, et puce TPM2 quand la box
en a une — gk3 oui, gk2 non), déchiffrés par systemd au démarrage de l'unité
qui les déclare (`LoadCredentialEncrypted=`), lus par le service dans
`$CREDENTIALS_DIRECTORY`.

CE QUE ÇA PROTÈGE, HONNÊTEMENT : une sauvegarde ou une copie de /etc ne
contient plus le secret en clair. Avec TPM, une copie du disque entier non
plus. Sans TPM, la clé d'hôte (/var/lib/systemd/credential.secret) est sur le
même disque. Root vivant les lit toujours — on ne prétend pas mieux.

LA BASCULE SE FAIT EN DEUX TEMPS. `migrer` chiffre et déclare, en laissant le
fichier en clair ; le service lit d'abord la crédence, sinon l'ancien chemin.
`retirer_clair` détruit le fichier seulement quand l'unité tourne AVEC la
crédence et que les deux valeurs concordent.
"""
import json
import os
import re
import subprocess
from pathlib import Path

CREDSTORE = Path(os.environ.get("SECUBOX_CREDSTORE", "/etc/secubox/credstore"))
SYSTEMD_ETC = Path(os.environ.get("SECUBOX_SYSTEMD_ETC", "/etc/systemd/system"))
CREDENTIALS_RUN = Path(os.environ.get("SECUBOX_CREDENTIALS_RUN", "/run/credentials"))
NOM_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
UNITE_RE = re.compile(r"^[a-zA-Z0-9@._-]+\.service$")


class ErreurNiveau0(RuntimeError):
    pass


def _index() -> dict:
    f = CREDSTORE / "index.json"
    try:
        return json.loads(f.read_text())
    except (OSError, ValueError):
        return {}


def _ecrit_index(idx: dict) -> None:
    CREDSTORE.mkdir(parents=True, exist_ok=True)
    os.chmod(CREDSTORE, 0o700)
    t = CREDSTORE / "index.json.tmp"
    t.write_text(json.dumps(idx, indent=2, sort_keys=True))
    os.chmod(t, 0o600)
    os.replace(t, CREDSTORE / "index.json")


def _verifie(nom: str, unite: str = None) -> None:
    if not NOM_RE.match(nom or ""):
        raise ErreurNiveau0("nom de crédence invalide")
    if unite is not None and not UNITE_RE.match(unite):
        raise ErreurNiveau0("unité invalide (…​.service)")


def chemin_cred(nom: str) -> Path:
    return CREDSTORE / f"{nom}.cred"


def dropin(nom: str, unite: str) -> Path:
    return SYSTEMD_ETC / f"{unite}.d" / f"coffre-niveau0-{nom}.conf"


def chiffrer(nom: str, valeur: bytes) -> Path:
    _verifie(nom)
    CREDSTORE.mkdir(parents=True, exist_ok=True)
    os.chmod(CREDSTORE, 0o700)
    dest = chemin_cred(nom)
    r = subprocess.run(["systemd-creds", "encrypt", f"--name={nom}", "-", str(dest)],
                       input=valeur, capture_output=True)
    if r.returncode != 0:
        raise ErreurNiveau0("systemd-creds encrypt a échoué : " + r.stderr.decode(errors="replace")[:200])
    os.chmod(dest, 0o600)
    return dest


def dechiffrer(nom: str) -> bytes:
    _verifie(nom)
    r = subprocess.run(["systemd-creds", "decrypt", f"--name={nom}", str(chemin_cred(nom)), "-"],
                       capture_output=True)
    if r.returncode != 0:
        raise ErreurNiveau0("systemd-creds decrypt a échoué")
    return r.stdout


def lier(nom: str, unite: str) -> Path:
    """Déclare la crédence à l'unité (drop-in), puis recharge systemd."""
    _verifie(nom, unite)
    d = dropin(nom, unite)
    d.parent.mkdir(parents=True, exist_ok=True)
    d.write_text("# Coffre, niveau 0 (#1367) — généré par coffrectl niveau0 migrer\n"
                 f"[Service]\nLoadCredentialEncrypted={nom}:{chemin_cred(nom)}\n")
    os.chmod(d, 0o644)
    subprocess.run(["systemctl", "daemon-reload"], capture_output=True)
    return d


def migrer(nom: str, chemin: str, unite: str) -> dict:
    _verifie(nom, unite)
    clair = Path(chemin)
    if not clair.is_file():
        raise ErreurNiveau0(f"{chemin} introuvable")
    valeur = clair.read_bytes()
    chiffrer(nom, valeur)
    if dechiffrer(nom) != valeur:
        chemin_cred(nom).unlink(missing_ok=True)
        raise ErreurNiveau0("la crédence ne redonne pas la valeur — rien n'a changé")
    lier(nom, unite)
    idx = _index()
    e = idx.setdefault(nom, {"chemin": str(clair), "unites": []})
    e["chemin"] = str(clair)
    if unite not in e["unites"]:
        e["unites"].append(unite)
    _ecrit_index(idx)
    return e


def _unite_porte(nom: str, unite: str) -> bool:
    """L'unité tourne ET systemd lui a remis la crédence.

    On regarde le répertoire de crédences de l'unité vivante plutôt que
    `systemctl show -p LoadCredentialEncrypted` : systemd 252 y affiche
    « [unprintable] » (la donnée est binaire), rien qu'on puisse reconnaître.
    """
    r = subprocess.run(["systemctl", "show", "-p", "ActiveState", unite], capture_output=True, text=True)
    return "ActiveState=active" in r.stdout and (CREDENTIALS_RUN / unite / nom).is_file()


def retirer_clair(nom: str) -> str:
    """Détruit le fichier en clair — seulement si chaque unité tourne avec la crédence."""
    _verifie(nom)
    e = _index().get(nom)
    if not e:
        raise ErreurNiveau0("crédence inconnue — migrer d'abord")
    for u in e["unites"]:
        if not _unite_porte(nom, u):
            raise ErreurNiveau0(f"{u} ne tourne pas avec la crédence — redémarrer l'unité d'abord")
    clair = Path(e["chemin"])
    if not clair.exists():
        return "déjà retiré"
    if clair.read_bytes() != dechiffrer(nom):
        raise ErreurNiveau0("le fichier en clair diffère de la crédence — on ne détruit rien")
    with open(clair, "r+b") as h:
        h.write(b"\0" * max(1, clair.stat().st_size))
        h.flush()
        os.fsync(h.fileno())
    clair.unlink()
    return str(clair)


def etat() -> list:
    sortie = []
    for nom, e in sorted(_index().items()):
        sortie.append({"nom": nom, "chemin_clair": e["chemin"], "clair_present": Path(e["chemin"]).exists(),
                       "unites": [{"unite": u, "porte": _unite_porte(nom, u)} for u in e["unites"]]})
    return sortie
