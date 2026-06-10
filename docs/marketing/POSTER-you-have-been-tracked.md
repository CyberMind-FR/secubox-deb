<!--
SPDX-License-Identifier: LicenseRef-CMSD-1.0
Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
-->

# Poster — « YOU HAVE BEEN TRACKED » · Cartographie sociale kbin

> Affiche grand public pour la fonction **Cartographie sociale** de la
> cabine VILLAGE3B (kbin / analyseur R3 — Phase 11, ref #502).
> Pendant choc du poster sobre [POSTER-grand-public-village3b](POSTER-grand-public-village3b.md) :
> celui-ci est l'accroche « réveil » qui montre l'ampleur du pistage
> révélé après quelques heures de navigation à travers la cabine.

Asset : `docs/assets/poster/kbin-you-have-been-tracked.png`
URL produit : `https://kbin.gk2.secubox.in/social/me` (🕸️ « Ma carto » sur le splash)

---

## 0. Concept

Style comic / pulp années 50 — un utilisateur paniqué happé par une toile
de connexions (cookies tiers + IP de trackers). Le message : **le même
navigateur est reconnu de site en site**, et il suffit de quelques heures
de browsing pour révéler un réseau massif de pistage commercial.

C'est la traduction visuelle de ce que la Phase 11 mesure réellement :
corrélation cross-cookie + reconnaissance de fingerprint (JA4) par device,
en R3 consenti, à travers la cabine.

## 1. Accroche (copie FR — faisant foi)

- **Titre** : `YOU HAVE BEEN TRACKED !`
- **Sous-titre** : `Alerte globale — cartographie cookie / social / tracking`
- **Bulles** :
  - `TES VISITES LAISSENT DES TRACES !`
  - `LE MÊME NAVIGATEUR RECONNU DE SITE EN SITE`
  - `RECIBLAGE · COOKIES TIERS · CORRÉLATION INTER-SITES`
  - `CARTOGRAPHIE SOCIALE EN TEMPS RÉEL !`
- **Bandeau pied** : `QUELQUES HEURES DE BROWSING ONT SUFFI POUR RÉVÉLER UN RÉSEAU MASSIF DE PISTAGE.`
- **Signature** : `ANALYSEUR R3 · kbin.gk2.secubox.in`

## 2. Métriques live (exemple capturé sur gk2)

Les chiffres du poster sont des **vraies mesures** issues de l'agrégat
`/admin/social-aggregate` + des compteurs WAF/DPI — pas des placeholders :

| Métrique | Valeur exemple | Source |
|---|---|---|
| Traqueurs distincts | **218** | `social_nodes` |
| Sites visités | **142** | `social_nodes.sites` |
| Sessions uniques (7j) | **44** | `clients` |
| Connexions analysées | **83 693** | DPI events |
| Hôtes uniques (top) | **15** | mitm metrics |
| Cookies trackés | **43 613** | `social_edges` |
| Sessions 24h | **7** | `clients` |
| Fingerprints JA4 | **234** | `ja4` events |
| Events 7j | **127 541** | `events` |

Trackers nommés visibles sur le visuel (échantillon réel) :
`outbrain.com`, `smilewanted.com`, `smartadserver.com`, `rubiconproject.com`,
`omnitagjs.com`, `ultimedia.com`, `weborama.fr` + un nuage d'IP de relais
ad-tech (`35.x`, `185.89.210.x`, `34.x`, `172.217.x`…).

## 3. Doctrine d'usage (garde-fous)

- **R3 consenti uniquement** — la carto n'est calculée que pour les pairs
  qui ont installé le profil WireGuard + CA (le tunnel EST l'opt-in).
- **Anonyme** — `client_mac_hash` à sel rotatif 24h ; le graphe est
  inatteignable après rotation. Aucune valeur de cookie brute persistée
  (seulement `sha256(domain‖name‖value)[:16]`).
- **Droit à l'effacement** — bouton RGPD art. 17 dans la vue per-client.
- **Aucune donnée externe** — tout est calculé localement sur la cabine.
- **Pas d'alarmisme dans le produit** — le poster est l'accroche choc ;
  l'UI elle-même reste factuelle (cf. design lock #502).

## 4. Déclinaisons

- **A2 mur** — version pleine résolution, accroche événementielle.
- **A4 flyer** — recto poster, verso QR vers `kbin.gk2.secubox.in/social/me`.
- **Slide presse** — pour le press kit France.gouv (cf.
  [PROMPT-claude-presse-gouv](PROMPT-claude-presse-gouv.md)).

---

*CyberMind — Gérald Kerma. LicenseRef-CMSD-1.0. Phase 11 (#502).*
