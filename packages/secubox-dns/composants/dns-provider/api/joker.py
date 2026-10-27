# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Joker DNS d'un pair du maillage (#3206) : « *.<nœud> A <ip publique du relais> » dans une zone gérée par un
fournisseur configuré ici (Gandi sur gk2).

Appelé par secubox-relais-maillage (secubox-dns-joker, root) AVANT le certificat joker du pair : son défi DNS-01 crée
_acme-challenge.<nœud>, le nœud existe alors dans la zone et le joker parent (*.secubox.in) ne couvre plus ses noms
(vécu sur gk3, puis gk4 le 2026-10-27). Idempotent ; un enregistrement existant qui pointe ailleurs n'est jamais
écrasé ; la création est relue, jamais crue sur parole (l'adaptateur Gandi rendait « succès » sur un refus)."""
from __future__ import annotations

import ipaddress
import re
from typing import Any, Callable, Iterable

_NOM = re.compile(r"(?=.{4,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}")
_LIBELLE = re.compile(r"[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?")


class Refus(ValueError):
    """Demande hors du cadre (domaine, IP, zone non gérée, enregistrement étranger) : rien n'est créé."""


class Echec(RuntimeError):
    """Le fournisseur n'a pas fait ce qui était demandé."""


def _a(enregistrements: Iterable[dict], nom: str) -> set[str]:
    return {str(r.get("value")) for r in enregistrements if r.get("name") == nom and r.get("type") == "A"}


async def assurer(fournisseurs: list[tuple[str, Any]], domaine: str, ip: str,
                  fabrique: Callable[[str, str], Any], zones_autorisees: Iterable[str]) -> dict:
    """fournisseurs : [(id, adaptateur)] ; domaine : domaine du pair (<nœud>.<zone>) ; ip : IPv4 publique du relais ;
    fabrique(nom, ip) : l'enregistrement que l'adaptateur sait créer ; zones_autorisees : les seules zones où écrire
    (le relais passe sa zone parente). Rend {"etat": "cree"|"inchange", …}.

    Revue #3206 : le domaine vient du pair. Un pair qui annoncerait mail.<zone> ne doit pas faire créer *.mail (le relais
    publierait ses noms sous le nom d'un autre) : le libellé doit être libre dans la zone, à son joker et à son défi
    ACME près."""
    domaine = str(domaine or "").strip().rstrip(".")
    if not _NOM.fullmatch(domaine):
        raise Refus(f"domaine invalide : « {domaine} »")
    try:
        adresse = ipaddress.ip_address(str(ip).strip())
    except ValueError as exc:
        raise Refus(f"adresse invalide : « {ip} »") from exc
    if adresse.version != 4 or not adresse.is_global:
        raise Refus(f"{adresse} n'est pas une adresse IPv4 publique")
    ip = str(adresse)
    autorisees = {str(z).strip().lower().rstrip(".") for z in zones_autorisees if str(z).strip()}

    choix = None                                            # (id, zone, libellé, adaptateur) : zone la plus longue
    pannes = []
    for fid, adaptateur in fournisseurs:
        try:
            domaines = await adaptateur.list_domains()
        except Exception as exc:                            # un fournisseur en panne n'arrête pas les autres
            pannes.append(f"{fid} : {getattr(exc, 'detail', None) or exc}")
            continue
        for d in domaines:
            zone = str(d.get("name", "")).strip().lower().rstrip(".")
            if not zone or not domaine.endswith("." + zone):
                continue
            libelle = domaine[: -len(zone) - 1]
            if _LIBELLE.fullmatch(libelle) and (choix is None or len(zone) > len(choix[1])):
                choix = (fid, zone, libelle, adaptateur)
    if choix is None:
        if pannes:
            raise Echec("aucune zone lisible : " + " ; ".join(pannes))
        raise Refus(f"aucune zone gérée ici ne porte {domaine} sous la forme <nœud>.<zone>")
    fid, zone, libelle, adaptateur = choix
    if zone not in autorisees:
        raise Refus(f"zone {zone} non autorisée pour les jokers du maillage (autorisées : {', '.join(sorted(autorisees)) or 'aucune'})")
    nom = f"*.{libelle}"
    sortie = {"zone": zone, "nom": nom, "ip": ip, "fournisseur": fid}

    enregistrements = await adaptateur.list_records(zone)
    vus = _a(enregistrements, nom)
    if vus == {ip}:                                         # déjà juste (gk1 : « gk1 » et « *.gk1 ») : rien à faire
        return {"etat": "inchange", **sortie}
    if vus:
        raise Refus(f"{nom}.{zone} existe déjà vers {', '.join(sorted(vus))} : jamais écrasé")
    siens = {(nom, "A"), (f"_acme-challenge.{libelle}", "TXT")}       # son joker et son défi ACME, rien d'autre
    autres = sorted({f"{r.get('name')} {r.get('type')}" for r in enregistrements
                     if (r.get("name") == libelle or str(r.get("name", "")).endswith("." + libelle))
                     and (r.get("name"), r.get("type")) not in siens})
    if autres:
        raise Refus(f"le nom {libelle}.{zone} est déjà utilisé dans la zone ({', '.join(autres)}) : aucun joker")
    await adaptateur.create_record(zone, fabrique(nom, ip))
    if ip not in _a(await adaptateur.list_records(zone), nom):
        raise Echec(f"{nom}.{zone} absent de la zone après sa création")
    return {"etat": "cree", **sortie}
