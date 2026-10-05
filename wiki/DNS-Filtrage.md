<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Filtrage DNS : ad-guard, webfilter, dns-lan

Trois modules agissent sur le DNS de la box (Unbound), chacun avec son rôle.

## ad-guard — publicités et traceurs

Retire les publicités et les traceurs au niveau DNS, **par appareil** (téléviseurs, streamers, tablettes). Chaque appareil géré a sa propre vue Unbound et ses propres règles ; les domaines utiles à un service peuvent être autorisés explicitement. La réponse par défaut est NXDOMAIN, ce qui évite les roues de chargement bloquantes observées avec d'autres réponses.

## webfilter — contrôle parental et sites dangereux

Classe les requêtes DNS par catégorie : **adulte**, **jeux d'argent**, **phishing et malware**. Les listes sont téléchargées à l'exécution, jamais livrées dans le paquet.

- **Observation par défaut** : rien n'est bloqué tant que l'administrateur ne l'a pas décidé.
- **Profils** : par catégorie, `observe` ou `block`, plus une liste d'autorisations.
- **Appareils** : rattachés à un profil par adresse MAC, avec exceptions. Les appareils gérés par ad-guard sont exclus en v1.
- **Application** : la configuration est écrite par l'API, puis appliquée par un contrôleur root déclenché par fichier (jamais par sudo). Unbound est rechargé, ce qui coupe le DNS une dizaine de secondes ; un retour arrière automatique rétablit l'ancien fichier octet pour octet si le contrôle échoue. Les changements de listes sont rechargés une fois par nuit vers 4 h.
- Panneau : `/webfilter/` (onglets Observation, Profils, Appareils, Appliquer).

## dns-lan — noms du réseau local

Fournit à Unbound les noms et zones du réseau local à partir d'un fichier de configuration `/etc/secubox/dns-lan.toml`.

## DNS Guard

Tableau de bord des compteurs DNS (requêtes bloquées, principales cibles, état du puits), alimenté par ad-guard. Panneau : `/dns-guard/`.

Voir aussi : [[Profils]], [[WAF]].
