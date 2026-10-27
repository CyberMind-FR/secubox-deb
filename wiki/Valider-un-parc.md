<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Valider un parc

🔵 **MESH** · 🟢 **ROOT** — comparer l'état réel des box d'un même maillage.

Quand plusieurs SecuBox partagent un maillage (une MOCHAbin maître, un PC, un Raspberry Pi…), la question n'est pas
« que contient le profil ? » mais « qu'est-ce qui tourne vraiment sur chaque box ? ». La page
**Comparatif des profils** répond aux deux, dans deux onglets séparés :

| Onglet | Ce qu'il montre | D'où ça vient |
|---|---|---|
| **Profils déclarés** | le contenu de chaque profil (`minimal`, `lite`, `isp`, `full`) | les méta-paquets, à la construction |
| **Validation du parc** | l'état réel de chaque paquet sur chaque box | un relevé signé par chaque box |

Adresse : `https://admin.<votre-box>/profiles/comparatif.html#parc`, depuis **n'importe quelle box** du maillage.
Lecture seule : la page ne démarre ni n'installe rien.

## Les quatre niveaux

Pour chaque paquet SecuBox et chaque box :

1. **Attendu** — le paquet est-il demandé par le profil installé sur *cette* box ? (fermeture des dépendances du
   méta-paquet de profil le plus haut). Un paquet installé sans être demandé est marqué **hors profil**.
2. **Paquet** — la version installée, ou son absence ; un paquet dont la configuration n'a pas abouti est une erreur.
3. **Services** — les unités systemd livrées par le paquet, et les modules servis par l'agrégateur.
4. **Ressources** — la mémoire réellement occupée par les services actifs, et le CPU depuis le relevé précédent.

## Lire une cellule

| État | Signification |
|---|---|
| 🟢 fonctionnel | installé, services actifs (ou servi par l'agrégateur) |
| 🟣 en veille | module à la demande, endormi : c'est normal |
| 🟠 arrêté | installé, un service qui devrait tourner ne tourne pas |
| 🔴 en erreur | service en échec, paquet mal configuré, ou module que l'agrégateur n'a pas pu charger |
| 🔴 manquant | demandé par le profil de la box, pas installé |
| 🟡 inconnu | la box n'a pas pu observer ce paquet (sonde en échec) |
| ⚪ absent | ni installé ni demandé sur cette box |
| — | la box n'a pas de relevé lisible (la raison est dans l'en-tête de sa colonne) |

Ne sont **jamais** comptés comme « arrêtés » : un service lancé par un minuteur, un service dont la condition de
démarrage n'est pas remplie (matériel absent, premier démarrage déjà fait), une tâche ponctuelle terminée avec succès.

Une version en **jaune** signale que les box n'ont pas la même version du paquet.

## Filtres

- **Écarts** (par défaut) : versions différentes, ou au moins une box en erreur, arrêtée, manquante ou inconnue. Un
  paquet absent d'une box dont le profil ne le demande pas n'est pas un écart : les profils diffèrent, c'est voulu.
- **Erreurs** : au moins une box en erreur ou un paquet manquant.
- **Tous les paquets**.

Sous la matrice, la liste **Erreurs et relevés incomplets** donne le détail par box (unité en échec, paquet manquant,
box injoignable, relevé partiel).

## Comment ça marche

```
chaque box                                         la box qui affiche la page
──────────                                         ──────────────────────────
secubox-profilectl releve   (toutes les 5 min)
   ↓ /var/lib/secubox/profiles/validation/releve.json
sbx-fleetctl publish-modules   (signature Ed25519 de la box)
   ↓ /api/v1/annuaire/fleet/modules/self   ←── maillage WireGuard, port 8799 ──  /api/v1/annuaire/fleet/modules
```

- Chaque box relève **elle-même** son état, sans privilège, et le signe avec sa clé.
- La box qui affiche la page lit les relevés de ses pairs par le maillage, **vérifie la signature et la forme**, et
  n'en déduit rien : elle affiche ce que chaque box a signé.
- Une box injoignable, trop ancienne (version sans relevé) ou dont la signature ne se vérifie pas apparaît avec sa
  raison, jamais comme une box vide.

## Dépannage

| Symptôme | Piste |
|---|---|
| « relevé indisponible : version trop ancienne » | mettre à jour `secubox-profiles` (≥ 0.24.0) et `secubox-annuaire` (≥ 0.16.0) sur cette box |
| « relevé non publié » | attendre 5 minutes après l'installation, ou lancer `secubox-profilectl releve` puis `sbx-fleetctl publish-modules` |
| « injoignable » | la box est hors du maillage : voir la page p2p et `wg show wg-mesh` |
| colonne marquée « périmé » | le relevé a plus de 15 minutes : `systemctl status secubox-profiles-releve.timer` |
| colonne marquée « partiel » | une sonde a échoué (survol du badge pour le détail) : agrégateur, systemd ou dpkg |

Voir aussi : [[Profils]] · [[Trixie]]
