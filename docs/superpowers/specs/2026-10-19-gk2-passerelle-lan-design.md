<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# gk2 passerelle du LAN plat — conception (ref #2940)

Statut : **approuvé par le propriétaire le 2026-10-19.** Les points marqués **(mon choix)** sont des décisions de l'auteur.
Décidé en échange le 2026-10-19 : gk2 devient la passerelle DHCP de tout le LAN, réseau **plat**
(`192.168.1.0/24`, même sous-réseau que la Freebox) ; limite acceptée : filtrage à l'aller seulement.

## Intention

Rendre effectif ce qui ne l'est pas aujourd'hui : bloquer l'accès Internet d'un appareil ou d'une zone. Le NAC
pose déjà des ensembles de zones (invités, objets connectés, quarantaine), mais ils ne bloquent **rien** de
l'accès Internet d'un appareil qui sort directement par la Freebox — ils n'agissent que sur ce qui touche gk2
(DNS, ses propres services). Devenir la passerelle ferme cette brèche : un paquet bloqué par gk2 ne repart jamais,
retour ou pas.

## Ce que la topologie permet et ne permet pas (vérifié techniquement, 2026-10-19)

Réseau **plat** : gk2, la Freebox et tous les appareils sur `192.168.1.0/24`. Avec gk2 comme passerelle DHCP :

- **Aller** (appareil → Internet) : passe par gk2, qui le transmet à la Freebox (`192.168.1.254`), sa propre
  passerelle. **Fonctionne.**
- **Retour** (Internet → appareil) : la Freebox reçoit la réponse, voit que l'appareil est sur son réseau
  **directement connecté**, et la lui envoie en direct — **sans repasser par gk2**. C'est le fonctionnement normal
  du routage IP, pas un défaut réparable côté gk2.

Conséquence acceptée par le propriétaire : pas d'inspection à état des flux, pas de DPI fiable, pas de WAF sur ce
trafic (le WAF protège ce que gk2 héberge depuis l'extérieur, sujet distinct). Ce qui reste pleinement fiable :
**le blocage** (un paquet dropé à l'aller ne part jamais, qu'il y ait un retour ou non), et la **visibilité sur la
demande** (destination, nom de domaine vu en clair dans la requête — SNI TLS, hôte HTTP).

## Objectifs

1. Un appareil ou une zone banni par le NAC/la quarantaine perd réellement l'accès Internet, pas seulement l'accès
   à gk2.
2. Journal de ce que chaque appareil a tenté de joindre (destination, domaine), honnête sur ses limites (pas un flux
   complet, pas de contenu).
3. Retour à l'état actuel (Freebox passerelle directe) en une commande, et **automatiquement** si gk2 cesse de
   répondre.

## Non-objectifs

DPI ou WAF sur ce trafic, comptage de débit fiable par flux, remplacer le NAC existant (il reste le gardien de
l'entrée et des services de gk2), un second sous-réseau derrière gk2 (matériel supplémentaire, hors de cette
livraison — noté comme évolution possible si le besoin d'inspection complète se confirme).

## Anti-objectifs

Couper Internet à tout le foyer sans retour automatique ; une page d'administration qui prétend voir des flux
complets ou faire du DPI alors qu'elle n'en voit que la moitié ; un changement appliqué directement sur gk2 sans
sonde de secours déjà en place et testée.

## Conception

### 1. Sonde de secours (dead-man switch) — livrée et testée AVANT tout changement de passerelle

**(mon choix)** Une minuterie système (`systemd-run --on-active`), comme celle utilisée pour l'essai IPv6 du même
jour, mais **permanente et auto-renouvelée** tant que le mode passerelle est actif :

- Toutes les 60 secondes, un service vérifie que gk2 transfère réellement (`ip_forward` actif, une règle `forward`
  présente, une sonde locale `ping` à travers lui-même vers `1.1.1.1` réussit).
- Si trois vérifications consécutives échouent (3 minutes), **ou** si le service de supervision lui-même s'arrête,
  un minuteur **déjà armé en parallèle** (indépendant du service de vérification, pour ne pas dépendre de ce qu'il
  surveille) remet `gateway = 192.168.1.254` dans `dhcp/config/` de la Freebox.
- Le minuteur de retour se réarme à chaque passage réussi de la sonde (`systemctl restart` du minuteur transitoire) :
  il ne se déclenche que si gk2 reste silencieux assez longtemps.
- Toute bascule (activation ou retour) écrit une ligne dans `/var/log/secubox/audit.log`.

### 2. Transfert IP et pare-feu sur gk2

- `net.ipv4.ip_forward = 1` posé par le module (pas à la main), avec le pendant IPv6 à `0` (le mesh et le forward
  IPv6 restent un sujet séparé, #2938 phase 3).
- Chaîne `forward` de `secubox-hardening` : politique `DEFAULT DROP`, comme `input`. Chaque zone (reprise des
  ensembles du NAC : `lan_allowed`, `guest_zone`, `iot_zone`, `quarantine_zone`, plus `blocked`) a sa règle
  `ether saddr @zone … accept` ou `drop`. Un appareil hors de tout ensemble connu suit la politique par défaut
  **décidé par le propriétaire : bloqué tant qu'il n'est pas classé.** Un appareil neuf (invité, objet connecté
  qu'on vient de brancher) n'a donc **aucun accès Internet** avant d'être rangé dans une zone : à dire clairement
  dans l'interface (« nouvel appareil détecté, sans accès tant qu'il n'est pas classé »), sinon ça ressemble à une
  panne. C'est plus strict que l'état actuel, où un appareil neuf a Internet par défaut.
- Aucune règle `ct state established` sur ce trafic précis (elle ne matcherait jamais, le retour ne passe pas par
  gk2) : les règles sont par paquet, sur l'adresse source et la destination/port.

### 3. Freebox : bascule du DHCP

- `POST /pare-feu-dhcp/passerelle` **(nouvelle route, mon choix de nom)** : écrit `gateway` dans `dhcp/config/` de la
  Freebox via le connecteur `secubox-freebox` existant (même mécanique que `_regler`, lu avant/après, journalisé).
- Jamais appliqué sans que la sonde de secours (section 1) soit déjà active et vérifiée.
- `GET` du même endpoint : état actuel (Freebox passerelle ou gk2), et pour chaque appareil connu de la Freebox,
  sa passerelle **actuellement utilisée** si disponible (sinon « inconnu, pas encore renouvelé son bail »).

### 4. Journal et interface

- Page du panneau réseau : état (« gk2 passerelle » / « Freebox passerelle »), bouton de bascule avec confirmation
  intégrée à la page, état de la sonde de secours, dernière bascule automatique s'il y en a eu une.
- Journal « qui a tenté de joindre quoi » : table tournante (comme les autres journaux SecuBox), destination et nom
  de domaine si vu, zone de l'appareil, accepté ou bloqué. Étiqueté clairement « vu à l'aller seulement », jamais
  présenté comme un flux complet.

## Tests

- Transfert : une règle qui bloque une zone dans la chaîne `forward` bloque bien un paquet de test (pytest +
  harnais nftables comme les tests existants de `secubox-hardening`).
- Sonde de secours : simulation d'un service qui ne répond plus, vérifier le déclenchement du retour sous le délai
  prévu ; vérifier qu'une vérification réussie réarme bien le minuteur (pas de retour intempestif).
- Freebox : écriture de la passerelle avec le droit `settings`, relecture, journal (mêmes motifs que
  `test_pare_feu_ecriture.py`).
- Essai réel sur gk2 **hors heures d'usage du foyer** ; bascule générale dès ce premier essai (décision du
  propriétaire), la sonde de secours testée en 1. est la seule garde.

## Décisions du propriétaire (2026-10-19)

1. Appareil inconnu de toute zone : **bloqué** tant qu'il n'est pas classé.
2. Délai de la sonde de secours avant retour automatique : **3 minutes**.
3. Portée de l'essai : **bascule générale** dès le premier essai, pas d'appareil de test isolé.

## Laissé au constructeur

Nom exact des routes API, format du journal, détail du harnais de test nftables, endroit précis où loger la
sonde de secours dans le dépôt (nouveau petit paquet, ou composante de `secubox-netmodes` / `secubox-hardening`).
