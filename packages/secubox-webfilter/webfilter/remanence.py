# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Adresses rémanentes des appareils et ré-application amortie (#3005).

Le contrôleur construisait la carte MAC → adresses avec la seule table de voisinage du moment (`ip -j neigh` à 04:00) : un appareil assigné
absent de la table à cette heure retombait dans le profil `defaut` toute la journée.

`remanence.json` (dossier d'état, écrit par le démon d'alimentation au compte du service, 0640, atomique) retient, PAR ADRESSE, le dernier MAC
qui l'a utilisée (vue dans le journal d'Unbound ET dans la table de voisinage) et la date. Clé = adresse : deux MAC pour une adresse est
impossible par construction ; le dernier vu gagne. Le contrôleur fusionne cet historique, borné par la durée de rétention, avec la table du moment
(qui compte pour « maintenant »). Le démon dépose `appliquer.demande` quand une adresse d'un appareil assigné manque à la carte appliquée (ou qu'une
adresse de la carte sert un autre MAC), au plus une fois par fenêtre d'amortissement, jamais pendant une application ou une compilation."""
import contextlib
import ipaddress
import json
import os
import re
import sys
import tempfile
import time
from pathlib import Path

from . import etat as _etat

FICHIER = "remanence.json"
MARQUEUR = "application.en-cours"                     # posé par le contrôleur root pendant une application
DEMANDE = "appliquer.demande"
DNS_ETAT = Path("/var/lib/secubox-dns-listes/etat.json")
MAX_OCTETS = 1024 * 1024
MAX_ADRESSES = 4096
MAX_PAR_MAC = 64                                      # adresses IPv6 temporaires : une par jour et par réseau, quatorze jours
EN_COURS_MAX_S = 30 * 60                              # au-delà, un marqueur ou un état « en-cours » est celui d'un processus tué
DEMANDE_PERIMEE_S = 600                               # comme l'API

_MAC = re.compile(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$")


def vide() -> dict:
    return {"demande": 0, "adresses": {}}


def _adresse(v):
    if not isinstance(v, str) or "%" in v or len(v) > 45:
        return None
    try:
        a = ipaddress.ip_address(v)
    except ValueError:
        return None
    if a.is_link_local or a.is_multicast or a.is_loopback or a.is_unspecified:
        return None
    return str(a)


def _entier(v) -> bool:
    return isinstance(v, int) and not isinstance(v, bool) and 0 <= v < 2 ** 40


def valider(obj) -> dict:
    """Historique relu comme une entrée hostile (le contrôleur root le lit) : toute entrée invalide est ignorée, jamais d'exception."""
    sortie = vide()
    if not isinstance(obj, dict):
        return sortie
    if _entier(obj.get("demande")):
        sortie["demande"] = obj["demande"]
    adresses = obj.get("adresses")
    if not isinstance(adresses, dict):
        return sortie
    for cle, e in adresses.items():
        a = _adresse(cle)
        if a is None or a != cle or not isinstance(e, dict):
            continue
        mac, vu = e.get("mac"), e.get("vu")
        if not isinstance(mac, str) or not _MAC.match(mac) or not _entier(vu):
            continue
        n = {"mac": mac, "vu": vu}
        if _entier(e.get("signale")):
            n["signale"] = e["signale"]
        sortie["adresses"][a] = n
        if len(sortie["adresses"]) >= MAX_ADRESSES:
            break
    return sortie


def lire_octets(brut) -> dict:
    if brut is None or len(brut) > MAX_OCTETS:
        return vide()
    try:
        return valider(json.loads(brut.decode("utf-8")))
    except (ValueError, RecursionError):
        return vide()


def lire_fichier(chemin) -> dict:
    """Lecture tolérante côté démon (son propre fichier) : absent, énorme ou illisible → historique vide."""
    try:
        with open(chemin, "rb") as f:
            brut = f.read(MAX_OCTETS + 1)
    except OSError:
        return vide()
    return lire_octets(brut)


def ecrire(chemin, hist: dict) -> None:
    """Écriture atomique 0640 (fichier temporaire du même dossier, puis renommage), comme `connus.json`."""
    chemin = Path(chemin)
    fd, tmp = tempfile.mkstemp(dir=chemin.parent, prefix=".remanence-")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(hist, f, sort_keys=True)
            f.flush()
            os.fchmod(f.fileno(), 0o640)
            os.fsync(f.fileno())
        os.replace(tmp, chemin)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise


def observer(hist: dict, voisins: dict, vus, maintenant: int) -> dict:
    """Ajoute les adresses VUES dans le journal (`vus`) que la table de voisinage rattache à un MAC. Une adresse reprise par un autre MAC change
    de propriétaire (le dernier vu gagne) et perd sa marque « signalée »."""
    h = valider(hist)
    t = int(maintenant)
    for mac in sorted(voisins):
        if not isinstance(mac, str) or not _MAC.match(mac):
            continue
        for brut in voisins[mac]:
            a = _adresse(brut)
            if a is None or a not in vus:
                continue
            avant = h["adresses"].get(a)
            n = {"mac": mac, "vu": t}
            if avant and avant["mac"] == mac and "signale" in avant:
                n["signale"] = avant["signale"]
            h["adresses"][a] = n
    return h


def purger(hist: dict, retention_s: int, maintenant: int) -> dict:
    """Retire ce qui est plus vieux que la rétention ; garde au plus MAX_PAR_MAC adresses par MAC et MAX_ADRESSES en tout, les plus récentes."""
    h = valider(hist)
    limite = int(maintenant) - int(retention_s)
    vivantes = sorted(((e["vu"], a, e) for a, e in h["adresses"].items() if e["vu"] >= limite), key=lambda x: (-x[0], x[1]))
    par_mac: dict = {}
    garde = {}
    for _, a, e in vivantes:
        if par_mac.get(e["mac"], 0) >= MAX_PAR_MAC:
            continue
        par_mac[e["mac"]] = par_mac.get(e["mac"], 0) + 1
        garde[a] = e
        if len(garde) >= MAX_ADRESSES:
            break
    h["adresses"] = garde
    return h


def _cle_ip(a: str):
    ip = ipaddress.ip_address(a)
    return (ip.version, ip)


def fusionner(voisins: dict, hist: dict, retention_s: int, maintenant: int) -> dict:
    """{mac: [adresses]} pour le contrôleur : table de voisinage du moment (datée « maintenant ») + historique non expiré. Chaque adresse va à UN
    seul MAC, le plus récemment vu."""
    h = purger(hist, retention_s, maintenant)
    proprio = {a: (e["vu"], e["mac"]) for a, e in h["adresses"].items()}
    t = int(maintenant)
    for mac in sorted(voisins):
        for brut in voisins[mac]:
            a = _adresse(brut)
            if a is not None:
                proprio[a] = (t, mac)
    sortie: dict = {}
    for a, (_, mac) in proprio.items():
        sortie.setdefault(mac, []).append(a)
    return {mac: sorted(v, key=_cle_ip) for mac, v in sorted(sortie.items())}


def a_signaler(hist: dict, assignes, carte: dict) -> list:
    """Adresses à faire appliquer : celles d'un appareil assigné que la carte n'attribue pas à ce MAC, et celles que la carte attribue à un AUTRE
    MAC que leur dernier utilisateur (bail réattribué). Une adresse déjà signalée ne l'est plus tant qu'elle ne change pas de MAC."""
    adresses = carte.get("adresses") if isinstance(carte, dict) else None
    adresses = adresses if isinstance(adresses, dict) else {}
    sortie = []
    for a, e in sorted(hist["adresses"].items()):
        if "signale" in e:
            continue
        lien = adresses.get(a)
        mac_carte = lien.get("mac") if isinstance(lien, dict) else None
        if (e["mac"] in assignes or mac_carte is not None) and mac_carte != e["mac"]:
            sortie.append(a)
    return sortie


def assignes(dossier) -> set:
    cfg = _etat.lire_json(Path(dossier) / "config.json")
    app = cfg.get("appareils") if isinstance(cfg, dict) else None
    return {m for m in app if isinstance(m, str) and _MAC.match(m)} if isinstance(app, dict) else set()


def en_cours(dossier, dns_etat, maintenant: float) -> bool:
    """Une application du contrôleur (marqueur récent) ou une compilation de secubox-dns-listes (« en-cours » récent) tourne."""
    try:
        if maintenant - os.stat(Path(dossier) / MARQUEUR).st_mtime < EN_COURS_MAX_S:
            return True
    except OSError:
        pass
    d = _etat.lire_json(dns_etat)
    return isinstance(d, dict) and d.get("etat") == "en-cours" and _entier(d.get("t")) and maintenant - d["t"] < EN_COURS_MAX_S


def passe(dossier, voisins: dict, vus, carte: dict, retention_s: int, amorti_s: int, dns_etat=DNS_ETAT, maintenant=None) -> bool:
    """Une passe du démon (toutes les 5 minutes) : met à jour l'historique et, si besoin, dépose `appliquer.demande`. True si une demande a été
    déposée. L'historique est écrit AVANT la demande : l'application qui la consomme le lit."""
    t = int(time.time() if maintenant is None else maintenant)
    dossier = Path(dossier)
    h = purger(observer(lire_fichier(dossier / FICHIER), voisins, vus, t), retention_s, t)
    nouvelles = a_signaler(h, assignes(dossier), carte)
    depose = False
    if nouvelles and t - h["demande"] >= amorti_s and not en_cours(dossier, dns_etat, t):
        for a in nouvelles:
            h["adresses"][a]["signale"] = t
        h["demande"] = t
        ecrire(dossier / FICHIER, h)
        depose = _etat.deposer(dossier, DEMANDE, DEMANDE_PERIMEE_S)
        print(f"secubox-webfilter : {len(nouvelles)} adresse(s) nouvelle(s) d'appareils assignés : "
              + ("application demandée" if depose else "une demande attend déjà"), file=sys.stderr)
        return depose
    ecrire(dossier / FICHIER, h)
    return depose
