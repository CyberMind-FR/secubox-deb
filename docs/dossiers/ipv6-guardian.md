<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
-->
# IPv6 Guardian — conception

**But.** Rendre lisible, pour quelqu'un qui n'est pas technicien, un sujet très technique : *« mon réseau est-il exposé
à Internet en IPv6 ? »* Une carte du Hall raconte la chaîne en quatre temps, avec un verdict d'un coup d'œil :

1. **Appareils joignables en IPv6** — ce que la box voit sur le réseau local ;
2. **Services visibles** — ce que ces appareils annoncent (imprimante, partage de fichiers, accès à distance…) ;
3. **Connexions entrantes bloquées** — ce que le pare-feu empêche de venir d'Internet ;
4. **Exceptions autorisées** — ce qui a été volontairement ouvert.

## Pourquoi l'IPv6 change la donne
En IPv4 les appareils sont cachés derrière la traduction d'adresses de la Freebox. En IPv6 chaque appareil reçoit une adresse
**publique** (`2a01:e0a:…`) : c'est le **pare-feu IPv6 de la Freebox** qui décide ce qui entre. SecuBox est, sur ce réseau, un
voisin comme les autres : il ne voit passer ni le trafic des autres appareils ni leur pare-feu. D'où deux sources de vérité.

## Décisions du propriétaire (2026-10-08)
| Question | Choix |
|---|---|
| Périmètre | **tout le réseau local** (pas seulement la box) |
| Sondage | **passif seulement** : on n'envoie rien aux appareils (pas de scan de ports) |
| Pare-feu | **la box + l'API de la Freebox** |

## Architecture
- Module `secubox-ipv6guard` : API FastAPI sur socket Unix `/run/secubox/ipv6guard.sock`, **sans privilège** (utilisateur dédié
  `secubox-ipv6guard`, durcissement complet), **lecture seule**.
- **Sources passives** : table des voisins (`ip -6 neigh`, `ip -4 neigh`) → appareils, regroupés par adresse MAC ; annonces mDNS
  (`avahi-browse`) → noms et services. L'annonce mDNS est mesurée en arrière-plan (quelques secondes) et mise en cache 5 min.
- **Verdict** (honnête) : sans lecture du pare-feu de la Freebox, la box **ne peut pas affirmer** que le réseau est protégé : le
  verdict est « à vérifier ». Il ne devient « protégé » ou « ouvert » qu'avec la phase 2.
- **Carte du Hall** `ipv6guard.html` : bandeau verdict, quatre étapes, détail repliable. Route Hall authentifiée
  (`auth_request`), GET seulement ; carte dynamique (`si_present`).

## Phases
- **Phase 1 (livrée avec ce dossier)** : appareils, services annoncés, verdict « à vérifier », étapes 3 et 4 marquées « à
  connecter ».
- **Phase 2** : API de la Freebox (Freebox OS, API v16) : autorisation unique (le propriétaire valide **sur la Freebox**), lecture
  de l'état du pare-feu IPv6 et des redirections/ouvertures par appareil ; remplit les étapes 3 et 4 et le verdict
  protégé / ouvert. Le jeton reste côté box (`/var/lib/secubox/ipv6guard/`, 0600, utilisateur du module), jamais dans le code.
- **Phase 3 (si utile)** : pare-feu de la box elle-même (compteurs nft IPv6) par un assistant sudo étroit ; alertes.

## Hors périmètre (volontairement)
Aucun scan actif ; aucune modification du pare-feu de la Freebox ni de celui de la box ; aucune donnée envoyée hors de la box.
