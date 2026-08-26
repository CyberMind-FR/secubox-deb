<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# POC Surf — relayer un site externe à travers la box

*Le morceau du §0bis : anti-censure, « SaaS inversé », blocage des pisteurs,
faux témoins rejoués. Ce document est la **mesure** qui décide si le proxy vaut
la peine d'être construit — pas le proxy lui-même.*

Cible du brief : `attraper Facebook dans le Hall`. Facebook est le **pire cas
possible** — un SaaS moderne hostile au proxy — et c'est pour ça qu'il est le
bon banc d'essai. On mesure d'abord, on construit ensuite, ou pas.

---

## 1. Ce qui est déjà écrit

Un cœur de relais isolé, `packages/secubox-surf/`, qui ne touche **pas** la
chaîne d'inspection de production (sbxwaf, workers Go). Trois fichiers :

| | |
|---|---|
| `surf/relais.py` | réécriture des URL réécrivables + **recensement** de ce qui ne l'est pas |
| `surf/egress.py` | l'égress commutable — **direct**, **Tor** (`.onion` et anti-censure) |
| `surf/mesure.py` | le harnais : va chercher une page, applique le relais, rend un verdict |

Aucune origine publique montée, aucun service lancé. La mesure tourne depuis la
box, qui a déjà la sortie internet et Tor.

```bash
python3 -m surf.mesure https://www.facebook.com/
python3 -m surf.mesure --egress tor https://check.torproject.org/
python3 -m surf.mesure <adresse>.onion          # Tor implicite
SECUBOX_TOR_SOCKS=192.168.1.200:9050 python3 -m surf.mesure --egress tor …
```

---

## 2. Les mesures — gk2, 2026-08-26

| Cible | Égress | Statut | URL réécrites | Verdict |
|---|---|---|---|---|
| **www.facebook.com** | direct | **400** | 4 | ⛔ **MUR** — coquille JS de 1542 o |
| **mbasic.facebook.com** | direct | 200 | 13 | ✅ **PASSABLE** — rendu serveur |
| example.com (statique) | direct | 200 | 1 | ✅ PASSABLE |
| check.torproject.org | **Tor** | 200 | 12 | ✅ PASSABLE |
| DuckDuckGo `.onion` | **Tor** | 200 | 112 | ⛔ MUR — un `fetch('/atb.js')` en dur |

### Ce que ça dit, sans détour

**Facebook « normal » est un mur — mais pas là où on l'attendait.** Le TLS
n'est pas le problème : la box joint `www.facebook.com` en 0,8 s. Le problème
est que la page est une **coquille de 1542 octets** qui monte toute
l'application en JavaScript, avec ses origines **écrites en dur** dans le code
et une CSP à `nonce`. Il n'y a littéralement **rien à réécrire statiquement** :
tout se joue à l'exécution, hors de portée d'un relais qui transforme du texte.
Facebook a de surcroît rendu **400** à notre requête — il éconduit avant même
de servir.

**Le même Facebook, en version `mbasic`, est relayable.** `mbasic.facebook.com`
est rendu **côté serveur** : 200, 13 URL réécrites proprement, aucune casse
bloquante. C'est **l'enseignement actionnable** du POC : contre un SaaS
hostile, on ne vise pas son application monopage, on vise son **point d'entrée
sobre** — mobile-legacy, `basic`, `m.`, AMP, flux RSS. Ils existent presque
toujours, ils sont faits pour les navigateurs pauvres, et un relais est
exactement un navigateur pauvre.

**L'égress Tor fonctionne, `.onion` compris.** `check.torproject.org` passe par
le tunnel (le site distant voit un nœud de sortie, pas la box), et un `.onion`
réel se résout **dans** le tunnel et se relaie — 112 URL réécrites sur la page
DuckDuckGo. Le verdict « MUR » y tient à **un seul** `fetch('/atb.js')` en dur :
la sévérité est voulue, un appel non détournable suffit à casser l'usage, et
elle montre où porterait le travail suivant.

---

## 3. Les murs, nommés une fois pour toutes

Ce que la réécriture statique **ne peut pas** atteindre, et que le harnais
compte :

- **`fetch()` / XHR en dur** vers l'origine réelle. Et `fetch(url)` où `url` est
  *calculée* échappe même au comptage — c'est le cas dominant des SPA.
- **Imports dynamiques** (`import('…')`) résolus à l'exécution.
- **Service workers** : ils s'installent sur **notre** origine et interceptent
  ensuite **tout** le réseau. À neutraliser explicitement, jamais à laisser
  passer.
- **WebSockets** : le temps réel ouvre vers l'origine réelle ; il faut un proxy
  WS dédié, origine par origine.
- **Sous-ressources à intégrité vérifiée** (`integrity=`) : réécrire le corps
  invalide leur hash, le navigateur les refuse. On retire l'attribut — donc on
  **renonce à la garantie** qu'il portait.
- **CSP à `nonce`** : liée à l'origine, elle bloque tout sous la nôtre. La
  retirer marche pour un POC ; la réécrire proprement, origine par origine, est
  un chantier.

Et le **piège structurant**, non négociable : une origine unique est un
contexte de sécurité unique. Une page arbitraire relayée sous l'origine du Hall
lirait le stockage de Nextcloud. D'où **une origine par site** —
`origine_de()` l'impose, aplatie en un label sous le wildcard `*.gk2.secubox.in`
(`www.facebook.com` → `surf-www-facebook-com.gk2.secubox.in`). C'est aussi ce
qui **sépare** ce POC de la corrélation de nos propres services (#1216) : là on
veut une origine commune, ici l'inverse. Les deux ne partagent aucun code.

---

## 4. Bloquer n'est pas cloisonner

La liste des pisteurs (`relais.PISTEURS`) est **coupée à la source** : une
requête qui n'existe que pour suivre est supprimée, pas isolée. C'est différent
du cloisonnement, qui garde un témoin **nécessaire** dans son contexte. Sur les
pages mesurées, aucun pisteur de la liste n'était encore chargé au premier
octet (ils viennent après, par le JS) — ce qui confirme au passage que sans
exécuter le JS, on ne voit pas non plus **tout** le traçage.

Les **faux témoins rejoués** (faire croire au service distant que sa publicité
est affichée) se brancheraient au même endroit que le rejeu de session — le
point `set-cookie` de `reecris_entetes`. Non implémenté : il suppose de savoir
ce que le service attend, service par service.

---

## 5. Encapsulation torrent — note de conception

Le torrent **n'est pas du HTTP** : c'est BitTorrent (µTP/TCP), qu'on **encapsule**
et non qu'on réécrit. La brique existe (`secubox-torrent`) ; l'encapsuler, c'est
lui imposer le **même égress** que ci-dessus :

- **trackers et pairs par le SOCKS de Tor** — anti-censure, l'IP de la box ne
  fuite pas dans la *swarm* ;
- ou par un **tunnel WireGuard** de sortie, quand la latence de Tor est
  rédhibitoire pour du volume.

Point de branchement : la configuration de `secubox-torrent` (proxy des
annonces + des connexions de pairs). À mesurer à part — débit et taux de
connexion aux pairs sous Tor sont l'inconnue, et Tor décourage explicitement le
torrent sur son réseau. Ce serait donc plutôt le tunnel WireGuard pour le
volume, Tor réservé aux annonces sensibles.

---

## 6. Décision proposée

1. **Ne pas** viser les SPA modernes de front. Le coût (réécrire du JS, proxy WS,
   neutraliser les service workers, rejouer une CSP à nonce) dépasse de loin le
   bénéfice, et le résultat reste fragile à chaque déploiement du site.
2. **Viser les points d'entrée sobres** — `mbasic`, `m.`, AMP, RSS, `.onion`
   quand il existe. Le POC montre qu'ils passent aujourd'hui, tels quels.
3. **Monter une origine de démonstration** (`surf-*.gk2.secubox.in`) servant
   `mbasic.facebook.com` en lecture, tracker-strippée, pour éprouver le rendu
   réel dans un cadre du Hall — la mesure suivante, celle qui manque encore.
4. **Garder ce POC hors de la chaîne d'inspection** tant qu'il relaie du surf
   arbitraire : une page hostile ne doit jamais toucher l'origine de nos
   services.

---

## 7. Où c'est écrit

| | |
|---|---|
| Cœur du relais | `packages/secubox-surf/surf/relais.py` |
| Égress direct / Tor | `packages/secubox-surf/surf/egress.py` |
| Harnais de mesure | `packages/secubox-surf/surf/mesure.py` |
| Corrélation de NOS services (l'inverse) | #1216, `docs/WEBOS-DESIGN.md` §4bis |
| Roadmap d'origine | `.claude/WIP.md` §0bis |
