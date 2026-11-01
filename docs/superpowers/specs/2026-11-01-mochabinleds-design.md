<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->
# mochabinleds — indicateur lumineux de supervision (conception)

Date : 2026-11-01. Paquet : `secubox-led-heartbeat` (moteur `secubox-led-pulse`, #3290).
Référence visuelle : la planche « mochabinleds » du propriétaire (3 LED RGB, 8 séquences rotatives).

## 1. Intention

Les 3 LED RGB du MOCHAbin (puce IS31FL3199) doivent dire, d'un coup d'œil et sans écran,
comment va la box : santé, réseau, filtrage, WAF, Actor, Ad-Guard, services, SOC. Sur gk2, la
seule box exposée à Internet, le moteur actuel « pulse sympa » ; la planche étend ce langage à
toute la supervision.

**Décision du propriétaire (2026-11-01) : les seuils sont RELATIFS à l'activité habituelle de
chaque box.** Une box calme (gk1) doit réagir à une hausse inhabituelle chez elle ; gk2 ne doit
pas rester orange en permanence parce qu'elle est toujours attaquée.

## 2. Objectifs, non-objectifs, anti-objectifs

Objectifs
- 8 séquences de 3 LED : SYSTÈME, RÉSEAU, FIREWALL, WAF, ACTOR, AD-GUARD, SERVICES, SOC
  (contenu de chaque LED : tableau §4).
- Grammaire commune à toutes les séquences : 6 couleurs (vert normal, cyan activité, jaune
  attention, orange dégradation, rouge critique, violet information) et 5 rythmes (fixe,
  respiration, pulsation, éclats, rotation).
- Rotation ~8 s par séquence ; rotation adaptative (une séquence en activité anormale reste
  affichée plus longtemps) ; priorité alerte (incident critique = interruption du cycle).
- Niveaux calculés contre une référence propre à la box (§5).

Non-objectifs
- Pas d'écran, pas de webui nouvelle dans ce lot (la page de réglage viendra après).
- Pas de nouvelles métriques côté modules : on lit ce qu'ils publient déjà.

Anti-objectifs (échec même si « ça marche »)
- Une charge mesurable sur gk2 (#3355) : le collecteur doit rester sous 1 % d'un cœur.
- Élargir les droits du démon LED (aujourd'hui : aucune capacité, `PrivateNetwork=yes`,
  AppArmor enforce).
- Un rouge qui ne veut rien dire : le rouge reste réservé aux faits absolus (§5.3).

## 3. Architecture

Deux processus, séparés par un fichier :

1. **`secubox-led-flux`** (nouveau, démon long, pas un minuteur) : relève toutes les 10 s les
   compteurs bruts dans l'espace réseau de l'hôte et écrit atomiquement
   `/run/secubox-leds/flux.json` (`{"genere_le": epoch, "metriques": {"waf.requetes": n, ...}}`).
   Compte dédié `secubox-leds`, `Nice=19`, `CPUWeight=10`, AppArmor enforce, lecture seule
   partout sauf `/run/secubox-leds/`. Seule capacité envisagée : `CAP_NET_ADMIN` pour lire les
   compteurs nftables — à éviter si `vortex-firewall` publie déjà ces compteurs (voir §7).
2. **`secubox-led-pulse`** (existant) : nouveau type de source `flux` qui lit une clé de
   `flux.json`, calcule un débit, le compare à la référence et rend un niveau 0..3. Le démon
   garde `PrivateNetwork=yes` et aucune capacité.

Pourquoi un collecteur séparé : le démon LED ne voit ni `/proc/net/dev` de l'hôte ni nftables
(espace réseau privé), et le confinement actuel doit rester tel quel.

## 4. Sources par séquence (lues par le collecteur)

| Séquence | LED 1 | LED 2 | LED 3 | Origine |
|---|---|---|---|---|
| SYSTÈME | CPU | RAM | E/S | `/proc` (déjà en place) |
| RÉSEAU | octets entrants WAN | octets sortants WAN | connexions suivies | `/proc/net/dev`, `nf_conntrack_count` |
| FIREWALL | paquets entrants | sortants | bloqués | compteurs nftables ou vortex-firewall |
| WAF | requêtes | blocages | attaques | `metrics-cache.json` (`waf.*`) |
| ACTOR | événements | suspects | critiques | `/run/secubox/actord-mesures.json` |
| AD-GUARD | requêtes DNS | trackers bloqués | appareils | `ad-guard.db` (lecture seule) |
| SERVICES | actifs | dégradés | arrêtés | `health-doctor.json` |
| SOC | infos | alertes | incidents | `soc` (fichier publié, à confirmer) |

Une source absente ou périmée vaut « inconnu » (comportement actuel du moteur), jamais rouge.

## 5. Seuils relatifs

### 5.1 Référence
**Métriques évolutives (propriétaire, 2026-11-01) : la référence est tirée des statistiques
temps réel elles-mêmes et suit leur évolution en continu.** Aucun seuil saisi à la main :
chaque relevé du collecteur (toutes les 10 s) met à jour la référence de sa tranche, et une
hausse durable devient progressivement la nouvelle normale de la box.

Pour chaque métrique de débit : moyenne et dispersion par **tranche horaire de la semaine**
(168 tranches), mises à jour à chaque relevé en moyenne mobile exponentielle (demi-vie ~7 jours), plus une tendance courte (demi-vie ~1 h) qui suit la journée en cours ; le niveau se calcule contre la plus haute des deux références, pour qu une montée rapide reste visible sans laisser une attaque durable devenir « normale » en quelques minutes. Persistée
dans `/var/lib/secubox-leds/reference.json` (écriture atomique toutes les 15 min, compte
`secubox-leds`). Une box qui démarre sans référence apprend pendant 24 h : niveaux plafonnés à
« activité » (cyan) tant que la tranche n'a pas assez d'échantillons.

### 5.2 Niveau
Écart réduit `z = (valeur − moyenne) / max(dispersion, plancher)` :
`z < 1` → normal ; `1 ≤ z < 2` → activité ; `2 ≤ z < 3` → attention ; `z ≥ 3` → dégradation.
Le **plancher** par métrique évite qu'une box à zéro attaque passe orange sur 2 requêtes.

### 5.3 Ce qui reste absolu
Rouge (critique) n'est jamais relatif : service arrêté, incident SOC ouvert, CPU ou RAM au-delà
des seuils absolus actuels, alerte Actor « critique ». C'est aussi ce qui déclenche la priorité
alerte.

## 6. Ordonnancement

- Cycle standard : les séquences actives défilent ~8 s chacune.
- Adaptatif : durée × (1 + niveau max de la séquence), plafonnée à 24 s.
- Priorité alerte : un rouge interrompt le cycle ; la séquence en cause s'affiche en éclats
  jusqu'à retour sous critique, avec un rappel toutes les 30 s si plusieurs séquences sont
  rouges.
- Tout se règle dans `leds.toml` (séquences activées, ordre, durées, planchers).

## 7. Points laissés au constructeur

- Lecture des compteurs FIREWALL : préférer une publication de `vortex-firewall` ; sinon
  `CAP_NET_ADMIN` au seul collecteur, avec justification dans le profil AppArmor.
- Source SOC exacte (fichier publié par `secubox-soc` ; `alerts.json` est absent sur gk2/gk1).
- Couleur exacte de chaque niveau dans chaque séquence : palette validée le 2026-10-30.

## 8. Validation

- Tests unitaires : référence (apprentissage, demi-vie, plancher), niveaux, ordonnanceur
  (adaptatif, priorité alerte), collecteur sur racine simulée.
- Banc : gk6 puis gk2 ; mesure CPU du collecteur sur 10 min (< 1 % d'un cœur).
- Œil du propriétaire sur gk2 et gk1 (box calme qui doit réagir à une hausse).
