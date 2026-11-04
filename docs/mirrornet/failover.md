<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Failover — basculement, réintégration, anti split-brain (#3429, phase B)

CONCEPTION, non implémentée. Composants N5 (bascule en lecture, A21), N8 (écrivain + quorum, A22), N11 (keepalived,
A22 optionnel). Marquage : EXISTANT / À ÉTENDRE / NOUVEAU.

Arbitrage du 2026-11-03 (décision 1, `architecture.md` § 0) : le mode de basculement (`auto` | `manuel`) et la
sonde de santé sont **déclarés par le module** dans `mirrornet.d` ; `secubox-mirrornet` applique la politique
(éligibilité, routes sbxwaf, promotion) mais ne redémarre ni ne modifie jamais un service : il le demande à
l'adaptateur (`activer`).

Vision du 2026-11-03 : les copies sont placées **d'office** (`distributed-hosting.md` § 7) ; le nœud source n'est pas
forcément gk2 (gk6, gk9…). La disparition du nœud source est traitée au § 3 et dans `distributed-hosting.md` § 6.5.

## 1. Principes (arbitrages)

- Basculement **automatique en lecture** ; promotion d'un écrivain (CMS, dynamique) **manuelle** ; un module peut
  déclarer `basculement = "manuel"` même en lecture (plus strict, jamais plus laxiste que le type).
- **Pas d'élection** du maître du maillage : masterlink reste désactivé (`secubox-p2p/api/main.py:3384-3414`, EXISTANT,
  désactivé si `[masterlink]` manque) ; quorum de site en A22.
- keepalived seulement pour l'IP virtuelle d'un **site** sur un même LAN, **jamais** la passerelle.
- Indisponibilité ≠ malveillance : un nœud absent perd son rôle de cible, jamais sa confiance.

## 2. Scénario de référence : gk6 nœud source, copies d'office sur gk2 et gk4 (gk3 intouchable)

```
            Internet
               │
        ┌──────▼──────┐  HAProxy + sbxwaf (seul exposé)
        │ gk2 10.10.0.1│  entrée unique ; copie de « blog » (metablogizer) 127.0.0.1:8472, ou relais wg-mesh
        └──┬────────┬─┘
   wg-mesh │        │ wg-mesh
   ┌───────▼──┐  ┌──▼───────┐
   │ gk6      │  │ gk4      │  gk6 nœud source, gk4 copie (:8472 sur IP wg-mesh)
   └──────────┘  └──────────┘
```

Adresses maillées réelles de gk6 et gk4 : **NON VÉRIFIÉ** (à relever au banc ; 10.10.0.6 / 10.10.0.4 sont illustratives).

## 3. Matrice des pannes (statique, A21)

| Panne | Détection | Effet attendu | Délai visé |
|---|---|---|---|
| gk6 (nœud source) éteint | sonde 3 × 10 s ; repli passif immédiat sur erreur de connexion | trafic sur gk2 + gk4, aucun 5xx visible (GET rejoué) ; nom court conservé, pas de nouvelle version | 0 s (passif), 30 s (actif) |
| gk6 révoqué | `RevocationNotice` | nom court suspendu, routes retirées ; `blog.gk6…` retiré ; arbitrage pour réattribuer | < 60 s |
| vhost de réplique metablogizer de gk2 arrêté (WAF actif) | idem | trafic sur gk6/gk4 via wg-mesh | idem |
| gk6 et gk4 éteints | idem | gk2 seul | — |
| les trois copies indisponibles | — | 503 du WAF, page d'erreur | — |
| **gk2 éteint** | — | **site injoignable** (entrée unique) ; les équivalences aussi | non couvert avant la bêta (N12) |
| sondeur de mirrornet mort | `sante.json` périmé > 60 s | toutes les cibles réputées saines, journal | — |
| lien wg-mesh gk2–gk4 coupé | sonde | gk4 écarté ; gk4 continue de servir son LAN par `blog.gk4…` si un DNS local le pointe (hors périmètre) | 30 s |

## 4. Réintégration

1. La cible revient : 2 sondes saines → candidate.
2. Elle doit servir l'empreinte attendue ; sinon elle rattrape (`replication.md` § 5) avant d'être éligible.
3. Nœud source revenu : il reprend sa chaîne ; ses nouvelles versions avancent les copies (fast-forward). Une
   publication faite ailleurs pendant son absence n'est pas une branche de sa chaîne : même contenu → copie de plus ;
   contenu différent → règle de conflit (`distributed-hosting.md` § 6).
4. Chaque changement d'éligibilité est audité (`site`, `noeud`, ancien/nouvel état, cause).

## 5. Anti split-brain

### Alpha 21 (statique)

Aucun état écrit n'est répliqué et seul le nœud titulaire prolonge sa chaîne : une partition ne peut pas créer deux
versions concurrentes d'un même site. Elle peut créer deux **revendications** du même nom court (publications des deux
côtés) : au retour, le registre des noms les compare (`distributed-hosting.md` § 6.2) → `refuse`, `bloque` ou
`conteste`, jamais deux titulaires ; un nom contesté reste servi par son titulaire jusqu'à l'arbitrage administrateur.
Aucun nœud n'élit personne : le calcul est le même partout depuis le journal.

Garde-fou de régression : un test vérifie que `secubox-mirrornet` ne lit ni n'active `[masterlink]`.

### Alpha 22 (microblog, CMS, dynamique) — NOUVEAU (N8)

```
Bail d'écriture (signé par l'écrivain, publié au journal) :
  { site, terme (entier monotone), ecrivain (did), expire_le (≤ 60 s), quorum_signe_par [did…] }
```

- Quorum = **majorité stricte** de `[copies].noeuds`. Un écrivain n'accepte une écriture que s'il détient un bail
  non expiré co-signé par une majorité. Sans majorité : **lecture seule** (la partition minoritaire sert, refuse
  d'écrire, l'affiche).
- **Fencing** : chaque écriture répliquée porte `terme` ; une réplique refuse toute écriture de terme inférieur au plus
  grand terme vu (réutilise l'idée de `TermStore` de `secubox-p2p/api/masterlink.py`, EXISTANT, sans son élection
  sans quorum). Heartbeat non signé : refusé (correction de l'acceptation actuelle, audit § 4).
- Microblog : chaque événement est signé par son auteur ; en minorité, l'écriture peut aller en **file locale signée**,
  fusionnée au retour (déterministe) — seule exception à « pas d'écriture sans quorum », à confirmer en A22.
- CMS : un seul écrivain ; promotion = geste administrateur sur `admin.secubox.in`, relayé par le pilotage, exécuté par
  le ctl de la box promue, qui exige que l'ancien écrivain soit injoignable **et** que son bail ait expiré (terme + 1).
- Dynamique : actif-passif, même bail, promotion manuelle.

## 6. keepalived (A22, optionnel) — NOUVEAU (N11)

- Paquet séparé `secubox-mirrornet-vip`, désactivé par défaut. VRRP seulement sur l'interface LAN déclarée, adresse
  virtuelle d'un **site** (servie par le point de service local du module), jamais la route par défaut, jamais le WAN
  (mvpp2 : aucune action d'interface WAN, consigne d'exploitation).
- nft : VRRP (proto 112) accepté seulement sur l'interface LAN choisie, depuis les pairs déclarés.
- Le refus de configurer une VIP égale à la passerelle ou sur le WAN est **testé**.

## 7. Risques

gk2 reste le point unique d'entrée (accepté jusqu'à la bêta, à afficher dans la vue Flotte). Un rejeu GET sur une cible
lente double la latence perçue (borné à 2 s). Bail A22 : horloges ; l'expiration se mesure en durée locale monotone, pas
en heure murale.
