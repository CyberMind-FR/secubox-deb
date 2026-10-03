<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# ad-guard TV — mode automatique avec essai, confirmation et retour arrière (#1954)

Suite du POC #1943, validé sur une TV réelle (une seule, une application, peu de coupures observées : `docs/poc-dns-adblock-tv-results.md`).

## 1. Objectif

Un administrateur déclare un appareil en mode **auto**. La box apprend ce qu'il demande, propose des domaines publicitaires, les applique **à l'essai**,
demande confirmation pour les garder, et retire seule une règle si des signes de casse apparaissent. Tout est daté, audité, annulable.

Décision de l'administrateur (2026-10-03) : option A — essai 24 h + confirmation + retrait automatique. Pas d'application définitive sans son accord.

## 2. Hors périmètre (volontairement)

- Aucune inspection HTTPS, aucun mitmproxy, aucun contournement de DRM (inchangé).
- Pas de panneau usager en v1. Les usagers ne voient que ce que la box expose déjà ; les confirmations sont **administrateur** (`require_jwt`).
- Pas de détection de « comportements » généraux (anomalies, nouveaux appareils) : chantier distinct, à ouvrir si utile.
- Pas de DoH/DoT/IPv6 hors box : toujours invisibles (limite du POC).

## 3. Cycle de vie d'une règle

`candidat → essai → confirmé`, avec sorties `rejeté` (par l'admin) et `retiré` (retour arrière automatique ou manuel).

| État | Effet DNS pour l'appareil | Sortie |
|---|---|---|
| candidat | aucun (proposé dans le panneau) | l'admin l'essaie, le rejette ; ou expiration 14 j |
| essai | NXDOMAIN, 24 h | confirmé (admin), retiré (signaux de casse ou admin), expiré → retiré (silence = pas de confirmation) |
| confirmé | NXDOMAIN permanent | retiré (admin ou signaux de casse persistants) |
| rejeté | aucun, jamais reproposé | l'admin le rouvre |

Une règle appartient à **un appareil** (périmètre par adresse MAC, adresses IPv4/IPv6 regroupées comme dans `regrouper_sources`).
**L'expiration d'un essai sans confirmation retire la règle** : l'automatisme ne se fixe jamais tout seul.

## 4. Détection des candidats

- **Base saine** par appareil : domaines vus hors coupure sur les 7 derniers jours (depuis `dnstv_recents` et les cumuls journaliers).
- **Déclencheur de coupure** : requête vers un domaine d'insertion publicitaire déjà classé (catégorie `advertising` de `lists/`, p. ex. `fwmrm.net`).
  C'est une heuristique propre au cas mesuré ; elle n'est pas validée hors France TV.
- **Candidat** : domaine absent de la base saine, vu dans les 60 s qui suivent un déclencheur, sur au moins 2 coupures distinctes.
  Un score (nombre de coupures, présence en base saine, catégorie des listes) ordonne la liste ; un nom d'infrastructure partagé est signalé « risque de casse ».
- **Motifs** : les noms à partie variable (`r1---sn-xxx.c.2mdn.net`) sont proposés comme zone parente seulement si ≥ 3 variantes ont été vues.
  Jamais de domaine parent générique (liste noire de sécurité : `googleapis.com`, `gstatic.com`, `apple.com`, `amazonaws.com`, domaines de l'appareil lui-même…).

## 5. Signaux de casse et retour arrière

Le DNS ne voit pas l'écran. Les signaux sont donc **indirects** et seront mesurés avant d'être crus :

1. **Rafale** : refus très supérieurs à l'étalon mesuré. Mesuré le 2026-10-03, en lecture NORMALE, la TV redemande un domaine refusé ~10 fois par minute (20 à 24 en 2,5 min) : ce n'est PAS un signe de casse. Seuil initial : > 60 refus/min pendant 5 min consécutives (à calibrer).
2. **Disparition du contenu** : après l'ajout de la règle, un domaine de la base saine (cible vidéo) n'est plus demandé alors que l'appareil reste actif.
3. **Retour manuel** : un bouton « ça ne marche plus » (administrateur) retire d'un coup **toutes les règles en essai** de l'appareil.

Un signal retire la règle concernée (ou toutes les règles en essai pour le signal 2, qui ne sait pas laquelle est en cause), écrit l'audit et notifie dans le panneau.
Seuils initiaux prudents et configurables ; ils seront ajustés après quelques jours réels. **Aucun chiffre n'est présenté comme validé tant qu'il n'a pas été mesuré.**

## 6. Application sans coupure de DNS

Un rechargement Unbound avec ~658 000 zones coupe le DNS environ 10 s (constaté). Chaque règle auto ne doit pas provoquer cela.
Piste : ajouter/retirer les zones de la vue de l'appareil à chaud (`unbound-control view_local_zone` / `view_local_zone_remove`), tout en persistant le drop-in
pour le prochain démarrage. **À vérifier par un essai sur Unbound 1.22 de gk2 avant de bâtir dessus** ; sinon, regroupement des changements en une fenêtre de rechargement
quotidienne.

## 7. Composants

- `api/dnstv_auto.py` : machine à états des règles, détection des candidats, évaluation des signaux (pur, testable sans Unbound).
- Table SQLite `dnstv_regles` (appareil, domaine, état, dates, origine, score, motif du retrait) dans la base existante.
- `sbin/secubox-adguard-tv` : seule porte privilégiée, accepte `regle-ajouter|regle-retirer` avec arguments validés (domaine, MAC), jamais de texte libre.
- Routes API (`require_jwt` en écriture, `require_lecture` en lecture) : `GET /auto/regles`, `POST /auto/regles/{id}/essayer|confirmer|rejeter|retirer`,
  `POST /auto/appareils/{mac}/ca-ne-marche-plus`, `GET /auto/journal`.
- Tâche de fond (déjà un pattern du module) : évaluation toutes les minutes ; jamais dans une route.
- Panneau d'administration (onglet existant étendu) : liste des appareils et de leur mode (observe / block / **auto**), file de candidats (domaine, appareil, score, risque),
  règles en essai avec compte à rebours, boutons Essayer / Confirmer / Rejeter / Retirer, bouton « ça ne marche plus », journal, statistiques (déjà présentes).
  Rendu par `textContent` seul, comme le panneau actuel.

## 8. Sécurité et audit

Chaque transition d'état écrit une ligne dans `/var/log/secubox/audit.log` (append-only) avec appareil, domaine, origine (auto/admin), motif.
L'API tourne sous `secubox` ; le contrôleur root revalide tout champ, refuse les liens symboliques et vérifie la configuration (`unbound-checkconf`) avant d'appliquer,
avec retour de la version précédente en cas d'échec (comportement du POC conservé). Modes par appareil : l'auto est **désactivé par défaut** et ne s'active que par action admin.

## 9. Tests

- Machine à états : transitions autorisées/refusées, expiration d'essai = retrait, rejeté jamais reproposé.
- Détection : jeux d'événements rejoués issus des phases E/P/C réelles (domaines, ordre, coupures) → candidats attendus ; liste noire de sécurité jamais proposée.
- Signaux : rafale, disparition du contenu, retour manuel ; absence de faux déclenchement sur un appareil inactif (la TV éteinte ne doit rien retirer).
- Contrôleur : argument invalide refusé, lien symbolique refusé, `unbound-checkconf` en échec → ancienne version rétablie.
- Application à chaud : sur un vrai Unbound (comme `test_dnstv_banc_unbound.py`).
- UI : rendu défensif, aucune injection par un nom de domaine hostile.

## 10. Livraison

`secubox-ad-guard` 1.4.0 (fonctionnalité), documenté dans HISTORY/WIP, README du paquet (API, TOML), déployé sur gk2 par paquet, dépôt apt à jour.
Mode auto d'abord **sur la TV 192.168.1.95 seule**. L'issue #1954 ne se ferme qu'une fois déployée et validée.

## 11. Risques et limites assumés

- Les heuristiques (déclencheur, fenêtre de 60 s, seuils) viennent d'**un** cas réel ; elles peuvent ne pas généraliser. Le mode essai + confirmation les encadre.
- Un nom partagé entre pub et contenu reste inséparable par DNS : l'outil le signale « risque de casse » mais ne peut pas le résoudre.
- Silence côté retour : si l'admin ne dit rien, l'essai expire et la règle est retirée ; c'est volontaire.
