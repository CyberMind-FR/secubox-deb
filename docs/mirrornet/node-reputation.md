<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Node Reputation — fiabilité explicable et réversible (#3429, phase B)

CONCEPTION, non implémentée. Composant N7, **Alpha 22**. En A21, seuls les signaux existants sont affichés (vue Flotte),
sans score. Marquage : EXISTANT / À ÉTENDRE / NOUVEAU.

Arbitrages : réputation **locale à chaque box** ; résumé **anonyme** sur `live.secubox.in` ; **indisponibilité ≠
malveillance**.

## 1. Deux axes séparés (NOUVEAU)

| Axe | Mesure | Effet | Ne fait jamais |
|---|---|---|---|
| **Disponibilité** D ∈ [0,1] | vivacité wg (`secubox-p2p/api/mesh.py:244,377`), santé des services (`federation.py:17-40`), sondes mirrornet, relevés pilotage | pondère le choix de cible (A22) ; sous un seuil, le nœud n'est plus cible | toucher la fiabilité ou le niveau de confiance |
| **Fiabilité** F ∈ [0,1], neutre 0,5 | faits **vérifiables localement** (§ 2) | au-dessous d'un seuil : **proposition** de révocation (vote ou administrateur), bans de ce pair ignorés | sanctionner seule |

## 2. Faits qui comptent pour la fiabilité

| Fait | Preuve locale | Poids (proposé) |
|---|---|---|
| entrée de journal à signature invalide émise par le pair | échec `verify` (`annuaire/log.py:112-140`) | −0,10 |
| équivocation (deux racines Merkle signées divergentes) | co-signée par un témoin (`model.py:393-420`, `WitnessAttest`) | −0,30 |
| version de site annoncée dont l'objet ne correspond pas à l'empreinte | BLAKE2b local | −0,10 |
| annonce de nom antidatée au-delà de `marge_horloge` (`distributed-hosting.md` § 6.2) | date de réception locale | −0,05 |
| ban fédéré contredit (IP en plage protégée, IP admin, ban sans TTL) | règles d'exclusion locales | −0,05 |
| ban fédéré levé par l'éditeur après annulation opérateur | journal | −0,02 |
| ban fédéré confirmé par une preuve locale (même acteur vu par ActorD local) | ActorD | +0,02 |
| service rendu sans erreur sur 24 h (réplique à jour) | sondes | +0,01 |

Ce qu'un pair **dit** d'un autre ne compte pas (aucune note de pair à pair).

## 3. Propriétés

- **Explicable** : chaque variation écrite dans `/var/lib/secubox/mirrornet/reputation.jsonl` (append-only, borné) avec
  fait, preuve (empreinte d'entrée), poids, valeur avant/après ; vue Flotte « pourquoi ».
- **Réversible** : décroissance exponentielle vers 0,5 (demi-vie proposée 7 jours) ; un administrateur peut annuler un
  fait (comme `POST /feedback/{id}` d'ActorD, `ddos-defense-audit.md` § 1.1), audité.
- **Bornée** : un fait de même type et de même preuve compte une fois ; plafond de variation par jour (−0,3).
- **Versionnée** : version du barème dans chaque ligne (principe de `secubox-toolbox-ng/internal/actor/score/score.go`).
- **Calcul** : sur les box disposant de `/data` et ≥ 2 Go ; les petites box ne calculent rien (vérifient des signatures,
  publient leurs relevés).

## 4. Publication anonyme sur live (À ÉTENDRE)

`secubox-live` (EXISTANT, `secubox-live/README.md`) ajoute une carte : nombre de nœuds par tranche de fiabilité et de
disponibilité, sans nom, sans adresse, sans `did`, agrégés à partir de 3 nœuds (sinon rien n'est publié).

## 5. Tests (A22)

gk4 hors ligne 1 h → D baisse, F inchangée, niveau inchangé ; signature invalide injectée → F baisse, explication
lisible, retour vers 0,5 par décroissance ; annulation opérateur → F restaurée ; tentative de dénigrement (pair A
déclare B malveillant) → aucun effet.
