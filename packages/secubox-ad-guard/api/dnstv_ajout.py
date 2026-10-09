# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox-Deb :: ad-guard :: ajout automatique des TV et streamers détectés, et suivi de leurs adresses (#1959).

Pur : aucune entrée/sortie sauf `charger_suivi`/`ecrire_suivi`. Garde-fous (tous testés) : désactivé par défaut (`etat["ajout_auto"]`), MAC valide non nulle
et non ignorée, jamais un appareil sans MAC, au plus `max_par_jour` ajouts par 24 h, un changement du périmètre au plus par `delai_s` (chaque changement coûte un
rechargement complet d'Unbound, ≈ 10 s sans DNS), 32 adresses au plus, jamais d'adresse de lien local ni de multicast. Une adresse d'un appareil ajouté
automatiquement non vue depuis `retrait_jours` est retirée, mais UNE adresse au moins reste. L'état produit est revalidé par `dnstv.valider_etat` avant d'être gardé.
"""
from __future__ import annotations

import copy
import ipaddress
import json
import os
import tempfile
from pathlib import Path
from typing import Dict, List, Optional, Tuple

try:
    from . import dnstv, dnstv_profil, dnstv_regles
except ImportError:                                  # lancé hors paquet
    from api import dnstv, dnstv_profil, dnstv_regles

FICHIER_SUIVI = "suivi-ajout.json"
SUIVI_VIERGE = {"ajouts": [], "dernier_changement": 0}
AJOUTS_MAX = 50
ADRESSES_MAX_PAR_APPAREIL = 4          # une TV a une IPv4 et quelques IPv6 ; au-delà ce sont des entrées mortes du noyau ou une forgerie (revue #1959)


def nom_appareil(mac: str, existants: set) -> str:
    """`TV` + 4 derniers hexadécimaux de la MAC ; unique par identifiant de vue (`existants` : identifiants déjà pris)."""
    base = "TV " + mac.replace(":", "")[-4:]
    nom, i = base, 2
    while dnstv._slug(nom) in existants:
        nom = f"{base}-{i}"
        i += 1
    return nom


def _entier(v) -> bool:
    return isinstance(v, int) and not isinstance(v, bool) and v >= 0


def charger_suivi(dossier: Optional[Path] = None) -> dict:
    f = (dossier or dnstv.DOSSIER_ETAT) / FICHIER_SUIVI
    try:
        fd = os.open(f, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd, "r", encoding="utf-8") as h:
            brut = json.loads(h.read(65536))
        if isinstance(brut, dict) and isinstance(brut.get("ajouts"), list) and all(_entier(x) for x in brut["ajouts"]) \
                and _entier(brut.get("dernier_changement")):
            return {"ajouts": brut["ajouts"][-AJOUTS_MAX:], "dernier_changement": brut["dernier_changement"]}
    except (OSError, ValueError):
        pass
    return copy.deepcopy(SUIVI_VIERGE)


def ecrire_suivi(suivi: dict, dossier: Optional[Path] = None) -> None:
    d = dossier or dnstv.DOSSIER_ETAT
    d.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=d, prefix=".suivi.")
    with os.fdopen(fd, "w", encoding="utf-8") as h:
        json.dump({"ajouts": [int(x) for x in suivi["ajouts"]][-AJOUTS_MAX:], "dernier_changement": int(suivi["dernier_changement"])}, h)
    os.chmod(tmp, 0o644)
    os.replace(tmp, d / FICHIER_SUIVI)


def _adresse_utilisable(brut) -> Optional[str]:
    """Une adresse de CLIENT du LAN : ni lien local, ni multicast, ni boucle, ni texte."""
    try:
        a = ipaddress.ip_address(str(brut))
    except ValueError:
        return None
    if a.is_link_local or a.is_multicast or a.is_loopback or a.is_unspecified:
        return None
    return str(a)


def appliquer(etat: dict, regles, detections: List, voisins: Dict[str, str], vues: Dict[str, int], profil: List[Tuple[str, str]],
              suivi: dict, reglage, maintenant: int, exclus=frozenset()) -> dict:
    """Modifie `etat`, `regles` et `suivi` EN PLACE et rend {"changements": [...], "etat_modifie": bool}. Rien si `ajout_auto` est faux."""
    rien = {"changements": [], "etat_modifie": False}
    if not etat.get("ajout_auto"):
        return rien
    clients = copy.deepcopy(etat["clients"])
    changements: List[dict] = []
    ips = {c["ip"] for c in clients}
    slugs = {dnstv._slug(c["nom"]) for c in clients}
    connues = {c["mac"] for c in clients if c.get("mac")}
    ignores = set(etat.get("ignores", []))
    nouveaux: List[Tuple[str, str]] = []                                       # (nom, motif) des appareils à équiper

    # 1. suivi des adresses des appareils AJOUTÉS AUTOMATIQUEMENT (les appareils déclarés par l'administrateur ne sont pas touchés)
    # Les appareils DÉCLARÉS À LA MAIN qui portent une MAC sont suivis aussi (#2011) : leur IPv6 « de confidentialité » change,
    # et sans suivi la TV sortait de sa vue au premier changement (replay sur sa roue). Les adresses qu'on leur ajoute sont
    # marquées « suivi » : seules celles-là expirent ; les adresses déclarées ne sont jamais retirées.
    auto = {}
    for c in clients:
        if c.get("mac") and c.get("origine", "admin") in ("auto", "admin"):
            auto.setdefault(c["mac"], c)
    fenetre = maintenant - reglage.retrait_jours * 86400
    candidates = []
    for ip, mac in voisins.items():
        modele = auto.get(mac)
        a = _adresse_utilisable(ip) if modele else None
        # Une adresse n'est rattachée que si le DNS de la box l'a VUE récemment : la table des voisins du noyau garde des entrées mortes (STALE) et
        # peut être alimentée par des paquets forgés. Jamais une adresse exclue (box, passerelle), jamais plus de ADRESSES_MAX_PAR_APPAREIL.
        if a and a not in ips and a not in exclus and vues.get(a, 0) >= fenetre:
            candidates.append((vues[a], a, mac))
    for _, a, mac in sorted(candidates, reverse=True):
        modele = auto[mac]
        if len(clients) >= 32:
            continue
        mes = [c for c in clients if c.get("mac") == mac]
        if len(mes) >= ADRESSES_MAX_PAR_APPAREIL:
            # PLAFOND ATTEINT : une IPv6 qui n'a plus ete vue depuis `retrait_jours` cede sa place (#2146). Sans cela, les IPv6 de confidentialite
            # declarees puis perimees occupaient les quatre places pour toujours et la TV sortait de sa vue au premier changement d'adresse
            # (replay sans fin sur gk2 : imasdk.googleapis.com bloque). Jamais l'IPv4, jamais une adresse encore vue, une seule place liberee.
            def derniere_vue(c):
                return max(vues.get(c["ip"], 0), c.get("ajoute", 0))
            perimees6 = [c for c in mes if ":" in c["ip"] and derniere_vue(c) < fenetre]
            if not perimees6:
                continue
            ancienne = min(perimees6, key=derniere_vue)
            clients.remove(ancienne)
            ips.discard(ancienne["ip"])
            changements.append({"type": "adresse-", "nom": ancienne["nom"], "detail": ancienne["ip"]})
        entree = {k: v for k, v in modele.items() if k not in ("ip", "ajoute", "preuve")}
        entree.update(ip=a, ajoute=maintenant)
        if modele.get("origine", "admin") == "admin":
            entree["origine"] = "suivi"
        clients.append(entree)
        ips.add(a)
        changements.append({"type": "adresse+", "nom": modele["nom"], "detail": a})
    for mac, modele in auto.items():
        adr = [c for c in clients if c.get("mac") == mac and c.get("origine") in ("auto", "suivi")]
        declarees = [c for c in clients if c.get("mac") == mac and c.get("origine", "admin") == "admin"]
        vue = {c["ip"]: max(vues.get(c["ip"], 0), c.get("ajoute", 0)) for c in adr}
        perimees = [c for c in adr if maintenant - vue[c["ip"]] > reglage.retrait_jours * 86400]
        if len(perimees) >= len(adr) and not declarees:                         # une adresse au moins reste : la plus récemment vue
            perimees = sorted(perimees, key=lambda c: vue[c["ip"]])[:-1]
        for c in perimees:
            clients.remove(c)
            changements.append({"type": "adresse-", "nom": c["nom"], "detail": c["ip"]})

    # 2. nouveaux appareils détectés
    ajouts_24h = len([t for t in suivi["ajouts"] if t > maintenant - 86400])
    for d in detections:
        mac = d.mac
        if not isinstance(mac, str) or not dnstv.MAC_RE.match(mac) or mac == "00:00:00:00:00:00" or mac in ignores or mac in connues:
            continue
        adresses = [a for a in (_adresse_utilisable(x) for x in d.adresses) if a and a not in ips and a not in exclus]
        adresses = sorted(adresses, key=lambda a: -vues.get(a, 0))[:ADRESSES_MAX_PAR_APPAREIL]
        if not adresses:
            continue
        if ajouts_24h >= reglage.max_par_jour:
            continue
        if len(clients) + len(adresses) > 32:
            changements.append({"type": "refus", "nom": mac, "detail": "plafond de 32 adresses atteint"})
            continue
        if etat.get("mode_defaut", "auto") == "auto" and len(regles.liste()) + len(profil) > dnstv_regles.REGLES_MAX:
            changements.append({"type": "refus", "nom": mac, "detail": "plafond de règles atteint : le profil de base n'entre pas"})
            continue
        nom = nom_appareil(mac, slugs)
        slugs.add(dnstv._slug(nom))
        connues.add(mac)
        for a in adresses:
            clients.append({"ip": a, "nom": nom, "mode": etat.get("mode_defaut", "auto"), "mac": mac, "origine": "auto", "ajoute": maintenant, "preuve": str(d.preuve)[:120]})
            ips.add(a)
        nouveaux.append((nom, d.preuve))
        ajouts_24h += 1
        changements.append({"type": "ajout", "nom": nom, "detail": ", ".join(adresses)})

    # 3. rien à écrire, ou trop tôt après le dernier changement (un rechargement du DNS par heure au plus)
    reel = [c for c in changements if c["type"] != "refus"]
    if not reel:
        return {"changements": changements, "etat_modifie": False}
    if maintenant - suivi["dernier_changement"] < reglage.delai_s:
        return rien
    try:
        valide = dnstv.valider_etat({**etat, "clients": clients})
    except dnstv.ErreurTV as e:
        return {"changements": [{"type": "refus", "nom": "", "detail": f"état refusé : {e}"[:120]}], "etat_modifie": False}
    etat["clients"] = valide["clients"]
    if etat.get("mode_defaut", "auto") == "auto":
        for nom, _ in nouveaux:
            dnstv_profil.equiper(regles, dnstv._slug(nom), profil, maintenant)
    suivi["ajouts"] = (suivi["ajouts"] + [maintenant] * len(nouveaux))[-AJOUTS_MAX:]
    suivi["dernier_changement"] = maintenant
    return {"changements": changements, "etat_modifie": True}
