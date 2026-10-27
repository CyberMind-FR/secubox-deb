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
                  fabrique: Callable[[str, str], Any]) -> dict:
    """fournisseurs : [(id, adaptateur)] ; domaine : domaine du pair (<nœud>.<zone gérée>) ; ip : IPv4 publique du relais ;
    fabrique(nom, ip) : l'enregistrement que l'adaptateur sait créer. Rend {"etat": "cree"|"inchange", …}."""
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

    choix = None                                            # (id, zone, libellé, adaptateur) : zone la plus longue
    for fid, adaptateur in fournisseurs:
        for d in await adaptateur.list_domains():
            zone = str(d.get("name", "")).strip().lower().rstrip(".")
            if not zone or not domaine.endswith("." + zone):
                continue
            libelle = domaine[: -len(zone) - 1]
            if _LIBELLE.fullmatch(libelle) and (choix is None or len(zone) > len(choix[1])):
                choix = (fid, zone, libelle, adaptateur)
    if choix is None:
        raise Refus(f"aucune zone gérée ici ne porte {domaine} sous la forme <nœud>.<zone>")
    fid, zone, libelle, adaptateur = choix
    nom = f"*.{libelle}"
    sortie = {"zone": zone, "nom": nom, "ip": ip, "fournisseur": fid}

    vus = _a(await adaptateur.list_records(zone), nom)
    if vus == {ip}:
        return {"etat": "inchange", **sortie}
    if vus:
        raise Refus(f"{nom}.{zone} existe déjà vers {', '.join(sorted(vus))} : jamais écrasé")
    await adaptateur.create_record(zone, fabrique(nom, ip))
    if ip not in _a(await adaptateur.list_records(zone), nom):
        raise Echec(f"{nom}.{zone} absent de la zone après sa création")
    return {"etat": "cree", **sortie}
