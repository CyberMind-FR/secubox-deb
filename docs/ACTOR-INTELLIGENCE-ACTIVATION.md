<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Actor Intelligence 2.0 — politique de scoring et activation

Référence d'exploitation de #2240. Ce document dit ce que le **code** fait ; `tests/test_doc_actor_intelligence.py` (paquet `secubox-waf-ng`) échoue si un seuil,
un facteur ou un drapeau change sans que cette page suive. Le plan et les décisions de conception sont dans `docs/design/actor-intelligence-2-0.md`.

## 1. Vue d'ensemble

```
capteurs ──► sbx-actord (ingestion, corrélation, scénario, risque / confiance, décision proposée)
  waf · pare-feu · dns · dpi            │
  authwatch · sentinel                  ▼
                              sbxwaf (applique, si le mode l'autorise) ──► nft waf_ban{,6} ──► réévaluation à l'échéance
```

- **actord** observe, corrèle et PROPOSE. Il n'applique rien lui-même.
- **sbxwaf** applique, selon son mode, par `nft` (table `inet secubox`, ensembles `waf_ban` / `waf_ban6`, chaîne `waf_drop`).
- Le **Hall** montre le résultat (carte « Radar des acteurs » ; « Renseignement » pour le détail), l'**administration** (`/actor/`, `/waf/`) donne les décisions et les preuves.

## 2. Capteurs

| Capteur | Ce qu'il émet | Réglage |
|---|---|---|
| `waf` | requêtes bloquées, sondes, leurres touchés, campagnes | toujours actif dans sbxwaf |
| `firewall` | balayages de ports (paquets rejetés, ensemble `sbx_scan_seen4/6`) | `--scan-sensor`, `--scan-seuil` (défaut 8 ports distincts en 10 min) |
| `dns` | domaines malveillants ou anormaux, dérive d'un domaine connu, détournement (réponse vers une adresse ou un ASN inattendu) | `secubox-adguard-dnssensor` (minuteries ad-guard) ; détournement : apprentissage de 3 jours avant la première alerte |
| `dpi` | risques nDPI hostiles cumulés par adresse publique | `DPI_ACTOR_SOCK` dans `/etc/secubox/dpi.env` |
| `authwatch`, `sentinel` | échecs d'authentification, alertes de la sentinelle | modules respectifs |

Un capteur qui se tait **abaisse la confiance**, jamais le risque.

## 3. Politique de scoring `v2`

Le score est la **somme de facteurs traçables** ; chaque facteur garde ses références de preuve. Risque (ce que l'acteur FAIT) et confiance (ce que les preuves
permettent d'AFFIRMER) sont deux mesures séparées, bornées à 0–100. La version de la politique est figée avec chaque évaluation : changer les poids ne falsifie
jamais une évaluation passée. Version courante : **v2**.

### Risque

| Facteur | Points | Condition |
|---|---|---|
| balayage de ports | +20 | au moins un événement du capteur pare-feu |
| répétition | +15 | 10 événements ou plus |
| service sensible ou leurre visé | +20 | événement étiqueté `high_value_probe`, `honeypot` ou `leurre:*` |
| tentative d'exploitation | +20 | au moins un événement classé « exploitation » (injection, traversée, exécution…) |
| charges d'attaque répétées | +15 | 5 charges ou plus |
| corrélation multi-capteurs | +15 | au moins 2 capteurs distincts |
| comportement automatisé | +10 | automatisation du vecteur ≥ 60 |
| historique sur plusieurs jours | +7 | le scénario contient l'étape « persistance » |
| anomalie DNS (canal caché possible) | +10 | événement classé « canal caché » (capteur DNS) |
| gravité maximale ≥ 80 | +10 | |
| gravité maximale ≥ 60 | +5 | seulement si la ligne précédente ne s'applique pas |

### Confiance

| Facteur | Points | Condition |
|---|---|---|
| événements observés | +25 | au moins un événement |
| capteurs indépendants (≥ 2) | +20 | |
| capteurs indépendants (≥ 3) | +10 | en plus du précédent |
| volume d'événements (≥ 5) | +15 | |
| volume d'événements (≥ 20) | +10 | en plus du précédent |
| scénario structuré (≥ 3 étapes) | +10 | reconnaissance → sondage → exploitation → canal caché → persistance |
| continuité du graphe d'acteurs | +0 à +10 | confiance du rattachement à l'acteur ÷ 10 |
| un seul événement | -15 | |
| gravité faible partout | -10 | gravité maximale < 30 |
| capteur(s) muet(s) | -10 par capteur | capteur qui émettait et s'est tu |

### Décision

| Constante | Valeur | Rôle |
|---|---|---|
| `SeuilMitigate` | 42 | risque minimal pour MITIGATE |
| `SeuilConfianceMitige` | 50 | confiance minimale pour MITIGATE |
| `SeuilBlockRisque` | 75 | risque minimal pour BLOCK |
| `SeuilBlockConfiance` | 80 | confiance minimale pour BLOCK |
| `MinCapteursBlock` | 2 | capteurs distincts requis pour BLOCK |

- **BLOCK** : risque ≥ 75 **et** confiance ≥ 80 **et** au moins 2 capteurs distincts.
- **MITIGATE** (délai, défi, ralentissement, limitation — réversible) : risque ≥ 42 et confiance ≥ 50.
- **OBSERVE** sinon.
- Un niveau refusé écrit sa **raison** (`BLOCK refusé : un seul capteur (2 requis)`, `BLOCK refusé : confiance 70 < 80`, `MITIGATE refusé : confiance …`). Une décision de
  BLOCK sur un seul capteur est refusée par construction. Les trois facteurs les plus lourds sont donnés comme raisons.

## 3 bis. Échelle de réponse (#2274)

La décision `v2` dit QUOI penser d'un acteur ; l'échelle de réponse dit QUE FAIRE, à chaque cran, et c'est elle qui transforme la détection en action. actord choisit
le cran de chaque acteur (`internal/actor/mesure`), publie les mesures actives (`/run/secubox/actord-mesures.json`, toutes les 30 s) et **sbxwaf les applique**.
Tout cran est temporaire, réversible, et porte sa raison.

| Cran | Déclencheur (risque, confiance) | Effet | Durée | Appliqué par |
|---|---|---|---|---|
| OBSERVE | confiance < 50 ou risque < 42 | journal seulement | 0 | actord |
| DELAY | risque 42–54 | la requête attend 1,5 s avant d'être servie | 5 min | sbxwaf |
| CHALLENGE | risque 55–64 | page de vérification par preuve de travail (JavaScript, aucun service tiers) puis laissez-passer lié à l'adresse ; les requêtes d'API sont seulement ralenties | 15 min | sbxwaf |
| TARPIT | risque 65–74, ou risque ≥ 75 sans deux capteurs | la connexion est retenue et nourrie au compte-gouttes (60 s au plus, 64 connexions retenues au plus, au-delà : simple délai) | 30 min | sbxwaf |
| DENY | risque ≥ 75, confiance ≥ 80, deux capteurs distincts | ban nft de durée graduée 1 h, 24 h, 7 j | 1 h | sbxwaf |
| QUARANTINE | idem DENY, pour un appareil du LAN (toutes ses adresses privées) | isolement dans la zone de quarantaine du NAC | 6 h | NAC |

**Escalade sur insistance** : un acteur qui produit encore `SeuilInsistance` événements hostiles NOUVEAUX (gravité ≥ 40) sous sa mesure monte d'un cran à la fois
(DELAY → CHALLENGE → TARPIT → DENY). C'est ainsi qu'un acteur vu par le seul WAF, qui n'atteindra jamais « deux capteurs », finit banni sans que le moteur ait
jamais bloqué sur une incertitude : la confiance doit rester ≥ 50. Une mesure en cours ne descend pas avant son échéance.

| Constante | Valeur | Rôle |
|---|---|---|
| `SeuilDelay` | 42 | risque minimal pour DELAY |
| `SeuilChallenge` | 55 | risque minimal pour CHALLENGE |
| `SeuilTarpit` | 65 | risque minimal pour TARPIT |
| `SeuilBlock` | 75 | risque minimal pour DENY / QUARANTINE |
| `SeuilConfiance` | 50 | confiance minimale pour toute mesure |
| `SeuilConfBlock` | 80 | confiance minimale pour DENY / QUARANTINE |
| `MinCapteurs` | 2 | capteurs distincts pour DENY / QUARANTINE |
| `SeuilInsistance` | 10 | événements hostiles nouveaux pour monter d'un cran |

**Quarantaine d'un appareil du LAN** : c'est le **NAC** qui lit les mesures d'actord (socket locale, vue complète) et isole l'appareil dans sa zone de quarantaine
existante — la même que pour un appareil inconnu : DNS et le reste comme aujourd'hui. Il y reste jusqu'à ce qu'un administrateur le reconnaisse et le **valide** ; il
n'y a pas de libération automatique, et une même mesure n'isole qu'une fois (un appareil libéré n'est pas ré-isolé par elle). Réglage : `[nac] quarantaine_auto` =
`auto` (défaut) | `propose` | `off` dans `/etc/secubox/secubox.conf` ; `quarantaine_protegees = ["aa:bb:…"]` pour des adresses MAC jamais isolées. Jamais la box, un routeur,
un équipement OpenWrt ou SecuBox, ni un appareil absent depuis plus de 3 h. Candidats visibles : `GET /api/v1/nac/quarantaine/auto`. sbxwaf n'applique jamais ce cran :
exposé à internet, il ne détient ni le secret de flotte ni de raison de toucher au LAN.

**Côté HTTP, jamais** : une adresse privée, une plage `--actor-ban-protegees`, un moteur de recherche vérifié, ni `/.well-known/acme-challenge/` ni `/robots.txt`. Un fichier de
mesures périmé (plus de 3 min) ne laisse aucune mesure. Chaque première application est une ligne de `/var/lib/secubox/waf/mesures.jsonl` ; l'état courant est dans
`mesures-etat.json`. La page « Renseignement » du Hall montre, pour chaque cran, le nombre d'acteurs réellement dessous ; le « Radar des acteurs » montre la mesure en cours.

## 4. Modes et drapeaux de sbxwaf

Vocabulaire commun (`GET /api/v1/waf/enforcement/mode`) :

| Mode | Drapeau | Effet |
|---|---|---|
| `PASSIVE_ONLY` | `off` | observation seule, aucun état de ban publié |
| `SIMULATION` | `propose` | les candidats sont écrits (décision `WOULD_BLOCK`), **rien n'est appliqué** |
| `ACTIVE` | `auto` | les bans sont posés (décision `BLOCKED`) |

| Drapeau | Défaut du code | Rôle |
|---|---|---|
| `--actor-ban off\|propose\|auto` | off | ban des acteurs suivis |
| `--actor-ban-min` | 2 | sanctions locales requises avant un ban automatique |
| `--actor-ban-max-heure` | 20 | coupe-circuit : bans d'acteurs par heure glissante |
| `--campagne-ban off\|propose\|auto` | off | ban des campagnes à sondes de haute valeur (4 h, 24 h, 7 j) |
| `--campagne-ban-max-heure` | 30 | coupe-circuit : bans de campagne par heure |
| `--leurre-ban` (avec `--honeypot`) | faux | ban dès le premier contact avec un leurre (1 h, 24 h, 7 j) |
| `--mesures off\|propose\|auto` | off | échelle de réponse d'actord appliquée par sbxwaf (délai, défi, tarpit, ban) |
| `--mesures-fichier` | `/run/secubox/actord-mesures.json` | mesures publiées par actord (`--mesures` d'actord) |
| `--mesures-max-bans-heure` | 20 | coupe-circuit : bans de l'échelle de réponse par heure glissante |
| `--reevaluation off\|propose\|auto` | off | kill switch logique : réévaluation à l'échéance |
| `--reeval-seuil` | 10 | paquets reçus pendant le ban au-delà desquels l'adresse « insiste » |
| `--scan-sensor` | faux | capteur pare-feu |
| `--scan-seuil` | 8 | ports distincts en 10 min pour parler de balayage |
| `--actor-ban-protegees CIDR,…` | vide | adresses et plages jamais bannies (en plus du privé et du local) |

Sur gk2, l'unité livre `auto` pour les acteurs, les campagnes, la réévaluation et l'échelle de réponse, et le dropin du leurre ajoute `--honeypot --leurre-ban` (décision du propriétaire,
#2238). Le dropin `/etc/systemd/system/secubox-waf-ng.service.d/10-honeypot.conf` est une **copie** de `/usr/share/secubox/waf/honeypot.conf` : la recopier après
une mise à jour qui la change. Appliquer un changement : `systemctl restart secubox-waf-ng` (jamais SIGHUP, qui tue sbxwaf).

## 5. Garde-fous

- **Jamais** une adresse privée, locale, de lien local, ni une plage de `--actor-ban-protegees` (la box, la Freebox, le maillage).
- **Jamais un moteur de recherche** : les robots d'indexation vérifiés par DNS inverse confirmé par le DNS direct (Google, Bing, Apple, Baidu, Yandex) ne sont pas
  bannis ; les bans déjà posés sur eux sont levés au démarrage. Un usurpateur (inverse écrit par lui, direct non) reste banni.
- **Plafonds horaires** par source, durées **graduées** à la récidive, et **jamais de ban permanent** : une chaîne de bans ininterrompue de 30 jours est libérée.
- **Réévaluation à l'échéance** : dans les 90 s avant l'expiration, les compteurs nft de l'adresse disent si elle a continué d'envoyer des paquets.
  `RELEASE` (elle s'est tue, ou aucun compteur : jamais de prolongation à l'aveugle) ou `EXTEND` (durée graduée suivante, plafonnée à 7 j et au reste des 30 j).
  Un ban posé à la main n'est jamais touché.
- **Preuves** : chaque transition est une ligne de `/var/lib/secubox/waf/reevaluations.jsonl` (append-only) et de `/var/log/secubox/waf/audit.log`.

## 6. Procédure d'activation `PASSIVE_ONLY → SIMULATION → ACTIVE`

1. **`PASSIVE_ONLY`** — déploiement sans drapeau : `--actor-ban off --campagne-ban off --reevaluation off --mesures off`. actord observe, score, affiche. Vérifier que les capteurs
   émettent : `curl --unix-socket /run/secubox/actor.sock http://x/api/v1/actor/stats` (nombre d'acteurs, de campagnes, événements et blocages sur 24 h) et la carte « Radar des acteurs ».
2. **`SIMULATION`** — copier `/usr/share/secubox/waf/actor-intelligence-simulation.conf.example` en `/etc/systemd/system/secubox-waf-ng.service.d/20-actor-simulation.conf`, recharger (`systemctl daemon-reload && systemctl restart secubox-waf-ng`).
   Les candidats s'écrivent dans `/var/lib/secubox/waf/actor-ban-etat.json` et `campagne-ban-etat.json`, la réévaluation dans `reevaluations.jsonl` avec
   `"applique": false`. Relire pendant **au moins une semaine** :
   `GET /api/v1/waf/decisions` (`WOULD_BLOCK`), `GET /api/v1/waf/reevaluations`, `GET /api/v1/waf/enforcement/mode` (doit répondre `SIMULATION`).
   Mesurer les faux positifs : adresses partagées (CGNAT), robots légitimes, clients de la maison. Ajouter les plages à `--actor-ban-protegees` avant de continuer.
3. **`ACTIVE` par étapes**, du plus réversible au plus dur, une étape par semaine, en surveillant `GET /api/v1/waf/enforcement` (bans, échéances, rollback) :
   a. `--reevaluation auto` (ne fait que prolonger ou laisser expirer des bans existants), puis `--mesures auto` (d'abord DELAY et CHALLENGE, qui ne coupent personne) ;
   b. `--campagne-ban auto` ;
   c. `--actor-ban auto` ;
   d. `--honeypot --leurre-ban` en dernier : un leurre touché par un robot légitime bannit l'adresse (c'est la raison de l'exemption des moteurs de recherche).
4. Après chaque étape : `nft list set inet secubox waf_ban` (les éléments portent un `counter`), `journalctl -u secubox-waf-ng` (lignes `nft BAN`, `réévaluation`),
   et le taux de bans par heure comparé aux plafonds.

## 7. Retour arrière

- **Un ban** : `POST /api/v1/waf/enforcement/{id}/rollback` (ou `POST /api/v1/waf/unban/{ip}`) ; le journal reçoit un `unban`.
- **Une fonction** : remplacer `auto` par `propose` (rien n'est plus appliqué, les candidats restent écrits) ou par `off`, puis `systemctl restart secubox-waf-ng`.
  Les bans déjà posés expirent d'eux-mêmes (timeout nft) ; pour les retirer tout de suite : `nft flush set inet secubox waf_ban` et `waf_ban6`
  (le journal `bans.jsonl` les ré-injecterait au redémarrage : ajouter des `unban` par l'API plutôt que de vider seulement l'ensemble).
- **Retour à l'état d'avant #2240** : retirer les drapeaux ci-dessus ; aucune migration de données à défaire (les ensembles nft migrent d'eux-mêmes).

## 8. Limites connues

- La plupart des acteurs ne sont vus que par le WAF : sans second capteur, la confiance reste sous 80 et la décision plafonne à MITIGATE. C'est voulu.
- Le détournement DNS n'alerte qu'après 3 jours d'apprentissage ; les empreintes JA4 sont encore à 0 dans la page nDPId.
- Une adresse partagée (CGNAT, bureau, mobile) qui héberge un attaquant ralentit aussi ses voisins pendant la mesure : c'est la raison des durées courtes et du défi plutôt que du refus aux crans bas.
- L'audit des décisions de sbxwaf va dans `/var/log/secubox/waf/audit.log` : le journal central `/var/log/secubox/audit.log` (`secubox:secubox 0640`) est fermé à `secubox-waf`.
- Le journal de bans `bans.jsonl` ne garde que le dernier état par adresse : ne jamais y ajouter de ligne qui ne soit ni `ban` ni `unban`.
