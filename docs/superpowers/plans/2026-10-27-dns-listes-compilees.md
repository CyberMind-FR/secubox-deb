<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Listes DNS compilées par étiquettes — plan (#3205)

**But** : Unbound charge une seule fois chaque domaine bloqué ; les exemptions par client passent par les étiquettes
natives au lieu de recopier les listes. Validé au banc sur gk1 avec la configuration réelle de gk2 : 743 → 387 Mo,
20 → 13 s, 145 530 décisions comparées sur 27 classes de clients, aucune différence (commentaire de #3205).

**Décisions** (GO du propriétaire, 2026-10-27) :
1. Les trois générateurs gardent EXACTEMENT leur rendu actuel, mais le déposent comme **source** dans
   `/var/lib/secubox/dns-listes/sources/` (`93-secubox-webfilter.conf`, `95-secubox-adblock.conf`,
   `96-secubox-adult.conf`) au lieu de `unbound.conf.d`. Leurs droits se réduisent à ce dépôt.
2. Un **seul** service root, `secubox-dns-listes.service` (secubox-core, profil AppArmor propre), déclenché par
   `secubox-dns-listes.path` (sources modifiées, ou ancien fichier réapparu dans `unbound.conf.d`), compile et pose
   `92-secubox-listes.conf`, retire les anciens fichiers, vérifie et recharge en UNE transaction (retour arrière complet).
3. Compilation **asynchrone** : un clic dans webfilter n'attend pas la compilation ; état dans
   `/var/lib/secubox/dns-listes/etat.json` (`secubox-dns-listes etat`).
4. Interrupteur `/etc/secubox/dns-listes.toml` : `mode = "compile"` (défaut) ou `"direct"` (sources recopiées telles
   quelles sous leur ancien nom, sans 92) — retour en arrière sans rétrograder de paquet.
5. Migration : à la première passe, un ancien fichier présent dans `unbound.conf.d` sans source est **adopté** comme
   source puis retiré. Les vues TV (94), dns-lan et les autres fichiers ne sont pas touchés ; ils servent de contexte.
6. La journalisation des requêtes reste (POC DNS AdBlock TV).

**Sémantique** (mesurée au banc, à préserver) : vue prioritaire ; dans une vue `view-first`, une zone `transparent` ne
tranche pas et Unbound continue vers les zones globales ; dérogations `local-zone-override` sur les zones globales ;
zone la plus spécifique. Le compilateur calcule, pour chaque domaine, l'ensemble des classes de clients (blocs
d'adresses de `access-control`, `access-control-view`, dérogations) qui le voient bloqué, regroupe par ensemble
(étiquettes), traite les exceptions sous un parent bloqué par `access-control-tag-action … always_transparent`, et
n'élague un sous-domaine que si son parent donne la même réponse à toutes les classes.

## Tâches

1. **Compilateur** (`common/secubox_unbound/listes.py`, pur, stdlib) : lecture en flux, classes regroupées en profils
   (même vue, mêmes blocs de dérogation) pour tenir le temps de calcul, rendu ; tests sur configurations synthétiques
   avec un simulateur des deux sémantiques (ancienne et étiquetée) qui compare toutes les décisions.
2. **Transaction et service** : `poser_vues()` (plusieurs fichiers, une vérification, un rechargement, retour arrière
   complet), `deposer_source()`/`retirer_source()`, `appliquer()` (verrou, adoption, mode, état), CLI
   `/usr/sbin/secubox-dns-listes`, unités `.service`/`.path`, profil AppArmor, paquet secubox-core 1.8.0.
3. **Générateurs** : adblock-sync et adult-sync (secubox-ad-guard 1.16.0), webfilter-ctl (secubox-webfilter 0.5.0,
   profil AppArmor réduit au dépôt de sa source) ; `Depends: secubox-core (>= 1.8.0)`.
4. **Banc et déploiement** : banc de gk1 rejoué avec le compilateur de production ; gk1, puis gk2 (mesure de la
   mémoire d'Unbound avant/après) ; README, HISTORY.

## Points d'attention

- Temps et mémoire du compilateur sur gk2 (chargé) : Nice, IOSchedulingClass=idle ; mesurés avant déploiement.
- Une source refusée par `unbound-checkconf` ne doit jamais laisser Unbound sans listes : retour arrière complet.
- Aucune boucle de déclenchement : l'unité `.path` ne surveille pas le fichier qu'écrit le service.
