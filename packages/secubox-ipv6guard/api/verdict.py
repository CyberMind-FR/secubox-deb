# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""
SecuBox-Deb :: ipv6guard :: verdict en langage courant
CyberMind — https://cybermind.fr

LE VERDICT DIT LA VÉRITÉ. Qu'un appareil soit joignable depuis Internet dépend du pare-feu IPv6 de la Freebox, que la box ne voit
pas : sans l'avoir lu (`freebox=None`), on ne dit JAMAIS « protégé » — on dit « à vérifier » et pourquoi. Aucun jargon dans les
textes : la carte s'adresse à quelqu'un qui n'est pas technicien.

`freebox` (phase 2) : {"pare_feu_actif": bool, "exceptions": [{"appareil": str, "port": int}, …]} ou None.
"""


def _publics(appareils):
    return [a for a in appareils if a.get("adresses_publiques")]


def _sensibles(appareils):
    return sum(1 for a in _publics(appareils) for s in a.get("services", []) if s.get("sensible"))


def verdict(appareils, freebox):
    publics = _publics(appareils)
    sens = _sensibles(appareils)
    base = {"sensibles": sens}
    if not publics:
        return {**base, "niveau": "sans_ipv6", "titre": "Rien n'est visible depuis Internet",
                "explication": "Aucun appareil du réseau n'a d'adresse publique IPv6 : rien n'est joignable de l'extérieur par ce chemin."}
    n = len(publics)
    # accord : « 1 appareil a … il pourrait » / « 3 appareils ont … ils pourraient »
    sujet = f"{n} appareil a" if n == 1 else f"{n} appareils ont"
    ils = "il pourrait être joignable" if n == 1 else "ils pourraient être joignables"
    ont = "il a" if n == 1 else "ils ont"
    if freebox is None:
        return {**base, "niveau": "a_verifier", "titre": "À vérifier",
                "explication": (f"{sujet} une adresse publique : {ils} depuis Internet. "
                                "Cela dépend du pare-feu de la Freebox, que SecuBox ne lit pas encore. "
                                "Connectez la Freebox pour savoir ce qui est réellement bloqué.")}
    if not freebox.get("pare_feu_actif"):
        return {**base, "niveau": "expose", "titre": "Attention : réseau exposé",
                "explication": (f"Le pare-feu IPv6 de la Freebox est désactivé et {sujet} une adresse publique : "
                                "tout ce que " + ("cet appareil propose" if n == 1 else "ces appareils proposent") + " peut être atteint depuis Internet.")}
    exc = freebox.get("exceptions") or []
    if not exc and freebox.get("exceptions_lues") is False:
        # pare-feu actif mais liste des exceptions illisible : on ne peut pas affirmer « protégé »
        return {**base, "niveau": "a_verifier", "titre": "À vérifier",
                "explication": "Le pare-feu de la Freebox est actif, mais la liste de ses exceptions n'a pas pu être lue : "
                               "impossible d'affirmer que rien n'est ouvert vers Internet."}
    if exc:
        k = len(exc)
        return {**base, "niveau": "ouvert_partiellement", "titre": f"{k} ouverture{'s' if k > 1 else ''} volontaire{'s' if k > 1 else ''}",
                "explication": ("Le pare-feu bloque tout, sauf ce que vous avez autorisé : "
                                f"{k} exception{'s' if k > 1 else ''} laisse{'nt' if k > 1 else ''} entrer des connexions d'Internet.")}
    return {**base, "niveau": "protege", "titre": "Votre réseau est protégé",
            "explication": "Le pare-feu de la Freebox bloque toutes les connexions qui arrivent d'Internet vers vos appareils."}


def etapes(appareils, freebox):
    publics = _publics(appareils)
    services_publics = [s for a in publics for s in a.get("services", [])]
    lu = freebox is not None
    exc = (freebox or {}).get("exceptions") or []
    return [
        {"id": "appareils", "titre": "Appareils joignables en IPv6", "valeur": len(publics), "etat": "ok",
         "detail": f"{len(appareils)} appareil{'s' if len(appareils) > 1 else ''} vu{'s' if len(appareils) > 1 else ''} sur le réseau, dont {len(publics)} avec une adresse publique."},
        {"id": "services", "titre": "Services visibles", "valeur": len(services_publics), "etat": "ok",
         "detail": "Ce que ces appareils annoncent sur le réseau (imprimante, partage de fichiers, accès à distance…)."},
        {"id": "bloquees", "titre": "Connexions entrantes bloquées", "valeur": None,
         "etat": "ok" if lu and freebox.get("pare_feu_actif") else ("alerte" if lu else "non_lu"),
         "detail": ("Le pare-feu de la Freebox bloque tout ce qui arrive d'Internet, sauf les exceptions."
                    if lu and freebox.get("pare_feu_actif") else
                    ("Le pare-feu de la Freebox est désactivé : rien n'est bloqué." if lu else "À connecter : lire le pare-feu de la Freebox."))},
        {"id": "exceptions", "titre": "Exceptions autorisées", "valeur": (len(exc) if lu else None), "etat": "ok" if lu else "non_lu",
         "liste": exc if lu else [],
         "detail": ("Ce que vous avez volontairement ouvert vers Internet." if lu else "À connecter : lire le pare-feu de la Freebox.")},
    ]
