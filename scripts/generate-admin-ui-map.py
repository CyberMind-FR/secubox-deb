#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Écrit docs/SBXOS_ADMIN_UI_MAP.md : la matrice de migration de l'administration vers les six espaces (#2212).

Source : packages/*/menu.d (les pages), packages/secubox-hub/espaces.json (espace et objet), et les notes ci-dessous (risque, réécriture).

    scripts/generate-admin-ui-map.py          # écrit
    scripts/generate-admin-ui-map.py --check  # code 1 si la matrice a dérivé
"""
import json
import sys
from pathlib import Path

RACINE = Path(__file__).resolve().parents[1]
SORTIE = RACINE / "docs" / "SBXOS_ADMIN_UI_MAP.md"

# (réécriture nécessaire ?, risque, remarque) — tout ce qui n'est pas listé : « non », « faible ».
NOTES = {
    "hub": ("non (page conservée) ; la VUE D'ENSEMBLE est une page nouvelle qui agrège ses caches", "moyen", "tableau de bord lourd : ne pas en faire une seconde page de configuration"),
    "health": ("non", "faible", "source de la santé des services"),
    "nac": ("API d'agrégation à ajouter (fiche appareil), page conservée", "moyen", "source canonique des appareils (MAC) ; jointure DNS (ad-guard) et trafic (dpi, clients WireGuard seulement)"),
    "ad-guard": ("non", "faible", "porte déjà une vue par appareil (DNS) : à relier à la fiche appareil"),
    "dpi": ("non", "faible", "ne voit que les clients WireGuard : pas de jointure avec ad-guard"),
    "actor": ("non", "moyen", "relais réservé à l'administrateur (_SOCKETS_ADMIN) : garder la garde"),
    "waf": ("non", "moyen", "cinq pages (waf, tableau, micro, racine, actor) : regrouper par navigation seulement"),
    "auth": ("non", "élevé", "login, TOTP et portail captif sous un seul nom : ne rien toucher à la logique"),
    "users": ("non", "élevé", "comptes SecuBox ; la séparation comptes Linux / identités SBXOS (capacites.py) est inviolable"),
    "sbxid": ("non", "moyen", "le menu redirige vers /identite/ : garder la redirection"),
    "vault": ("non", "moyen", "trois pages (/vault/, /coffre/, /pgp/) dont deux hors menu : raccorder sans les modifier ; ne jamais re-sceller"),
    "portal": ("non", "élevé", "page de connexion : hors périmètre de la façade"),
    "certs": ("non", "faible", "certificats de service ; les certificats système restent aussi sous Système"),
    "system": ("non", "moyen", "trois racines « système » (system, admin, hub) avec reboot et mises à jour en double : dédoublonner plus tard"),
    "admin": ("non", "moyen", "composant de system : mêmes actions que system et hub"),
    "backup": ("non", "moyen", "avec cloner et system : restauration à ne pas faire diverger"),
    "repo": ("non", "faible", "dépôt APT local : mises à jour"),
    "autoload": ("non", "faible", "nouveau (#2190) ; lien depuis Identité & accès pour les abonnements"),
    "console": ("non (TUI sans page web)", "faible", "sans chemin : le hub l'écarte déjà"),
    "mediaflow": ("non", "faible", "rangé en « boot » dans le menu actuel : reclassé en Surveillance"),
    "avatar": ("non", "faible", "« Identity Manager » dans le menu mesh : entrée à renommer plus tard"),
    "reality": ("non", "faible", "entrée de menu sans page : écartée par le hub"),
    "socialrelay": ("non", "faible", "entrée de menu sans page à son nom : écartée par le hub"),
    "metanews": ("non", "faible", "entrée de menu sans page à son nom : écartée par le hub"),
    "sbxos-audio-mood": ("non", "faible", "entrée de menu sans page à son nom : écartée par le hub"),
    "dns": ("non", "faible", "zones DNS ; le filtrage DNS est sous Protection (dns-guard, ad-guard, webfilter)"),
    "wireguard": ("non", "faible", "quatre modules gèrent WireGuard (wireguard, p2p, toolbox, netmodes) : un seul rattachement visible, les autres par lien"),
}
ESPACES_ORDRE = ["apercu", "protection", "surveillance", "services", "identite", "systeme"]


def entrees():
    out = {}
    for motif in ("packages/*/menu.d/*.json", "packages/*/composants/*/menu.d/*.json"):
        for f in sorted(RACINE.glob(motif)):
            if "/debian/" in str(f):
                continue
            d = json.loads(f.read_text(encoding="utf-8"))
            out[d["id"]] = {"nom": d.get("name", d["id"]), "path": d.get("path", ""), "categorie": d.get("category", ""), "theme": d.get("theme", ""),
                            "paquet": f.relative_to(RACINE).parts[1]}
    return out


def rendre() -> str:
    table = json.loads((RACINE / "packages/secubox-hub/espaces.json").read_text(encoding="utf-8"))
    meta = {e["id"]: e for e in table["espaces"]}
    ent = entrees()
    L = ["<!-- SPDX-License-Identifier: LicenseRef-CMSD-1.0 -->", "<!-- Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr> -->",
         "<!-- GÉNÉRÉ par scripts/generate-admin-ui-map.py — ne pas éditer à la main ; la source est packages/secubox-hub/espaces.json -->",
         "# SBXOS Admin — matrice de migration vers les six espaces (#2212)", "",
         f"{len(ent)} entrées de menu, rattachées chacune à un espace et à un objet central. **Aucune route n'est supprimée ni déplacée** : toutes les pages gardent leur chemin ; "
         "seule la navigation les regroupe. Colonnes : ancienne page · nouvelle section · objet · route conservée · composant réutilisé · réécriture nécessaire ? · risque.", ""]
    for eid in ESPACES_ORDRE:
        e = meta[eid]
        ids = sorted((i for i, m in table["modules"].items() if m["espace"] == eid), key=lambda i: (ent[i]["theme"], ent[i]["nom"].lower()))
        L += [f"## {e['icone']} {e['ordre']} — {e['nom']} ({len(ids)})", "",
              "| Ancienne page | Chemin conservé | Objet | Composant réutilisé | Réécriture ? | Risque | Remarque |", "|---|---|---|---|---|---|---|"]
        for i in ids:
            n = NOTES.get(i, ("non", "faible", ""))
            comp = f"`packages/{ent[i]['paquet']}/www` + sidebar.js" if ent[i]["path"] else "—"
            L.append(f"| {ent[i]['nom']} (`{i}`) | `{ent[i]['path'] or '(sans page web)'}` oui | {table['modules'][i]['objet'] or '—'} | {comp} | {n[0]} | {n[1]} | {n[2]} |")
        L.append("")
    L += ["## Ce qui est réellement nouveau (aucune page existante à réutiliser)", "",
          "| Élément | Pourquoi | S'appuie sur |", "|---|---|---|",
          "| Page « Vue d'ensemble » | aucune page ne synthétise l'état de la box | caches de `/hub/dashboard`, `/security-posture/overview`, `/metrics/overview`, `/backup/status`, `/repo/summary`, `/health/summary` |",
          "| Recherche globale | aucune recherche côté admin | index des menus (`espaces`), puis objets |",
          "| Panneau de notifications | l'API existe, aucun écran | `GET /api/v1/hub/notifications` (`require_jwt`) |",
          "| Fiche appareil | huit « appareils » avec huit clés, aucune fiche commune | `nac` (source), `ad-guard` (DNS), `dpi` (clients WireGuard) |",
          "| Fiche service | l'état est dispersé entre appstore, profiles et les pages | `appstore`, `health`, `/services/{s}/logs` de metrics |", ""]
    return "\n".join(L) + "\n"


def main() -> int:
    texte = rendre()
    if "--check" in sys.argv:
        if not SORTIE.exists() or SORTIE.read_text(encoding="utf-8") != texte:
            print("docs/SBXOS_ADMIN_UI_MAP.md a dérivé : relancer scripts/generate-admin-ui-map.py", file=sys.stderr)
            return 1
        return 0
    SORTIE.write_text(texte, encoding="utf-8")
    print(f"{SORTIE.relative_to(RACINE)} écrit")
    return 0


if __name__ == "__main__":
    sys.exit(main())
