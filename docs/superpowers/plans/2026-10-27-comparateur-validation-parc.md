<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Comparateur des profils : validation du parc — plan (#3212)

**But** : `/profiles/comparatif.html` montre, pour chaque paquet SecuBox et chaque box du maillage, quatre niveaux
réels (attendu par le profil, paquet installé + version, services, ressources) sans confondre les métadonnées des
profils avec l'état des machines.

**Conception approuvée** (GO du propriétaire, 2026-10-27, issue #3212) :
1. Relevé par box, sans privilège (utilisateur `secubox`), toutes les 5 min : `secubox-profilectl releve` écrit
   `/var/lib/secubox/profiles/validation.json` (écriture atomique).
2. Signature et diffusion par annuaire : `sbx-fleetctl publish-modules` (à la suite de `publish`, même unité) signe le
   relevé avec la clé de la box (Ed25519) → `/var/lib/secubox/annuaire/fleet/modules.json` ; servi sur l'écoute du
   maillage 8799 (`/api/v1/annuaire/fleet/modules/self`) ; `GET /fleet/modules` (JWT) tire les pairs de `wg_mesh.json`.
3. Page : onglet « Validation du parc » (matrice paquet × box), onglet existant renommé « Profils déclarés ».
4. Lecture seule ; depuis n'importe quelle box ; README + wiki « Valider un parc ».

## Contraintes

- Nouveau modèle `ModulesSnapshot` séparé de `MetricSnapshot` (`extra="forbid"` : un champ ajouté casserait les pairs).
- Bornes : ≤ 400 paquets, ≤ 16 unités par paquet, ≤ 5 erreurs de ≤ 200 caractères ; noms `^(secubox|sbxos)-[a-z0-9.+-]+$`.
- Un pair injoignable, trop ancien (404) ou mal signé apparaît « relevé indisponible » avec sa raison ; jamais de zéro.
- `/fleet/modules` ne lève jamais (500 évité), lectures des pairs en parallèle (agrégateur partagé).

## Règles d'état (profiles, fonction pure, testée)

Par unité (`systemctl show` : ActiveState, SubState, UnitFileState, Result, TriggeredBy, MemoryCurrent, CPUUsageNSec) :
`failed` → erreur ; `active`/`reloading` → actif ; inactive + `TriggeredBy` non vide → déclenché (normal) ;
inactive + UnitFileState hors `enabled` → non requis (normal) ; inactive + enabled + module `on-demand` → veille ;
inactive + enabled → arrêté. Unités du paquet : services et timers listés dans `/var/lib/dpkg/info/<paquet>.list`
(sans gabarits `@`).

Par paquet : non installé → `manquant` si attendu, sinon `absent` ; statut dpkg ≠ `ii` → `erreur` (configuration
inachevée) ; une unité en erreur → `erreur` ; une unité arrêtée → `arrete` ; sinon, aucune active et au moins une en
veille → `veille` ; sinon `fonctionnel`. Drapeaux : `attendu` (fermeture des `Depends` du méta-paquet installé le plus
haut), `recommande` (ses `Recommends`), `hors_profil` (installé, ni attendu ni recommandé, pas un méta-paquet).
Ressources : somme de `MemoryCurrent` des unités actives (octets) ; CPU en % d'un cœur par différence de
`CPUUsageNSec` avec le relevé précédent.

## Tâches

1. **profiles — relevé** : `api/validation.py` (analyse dpkg-query, .list, systemctl show, règles, collecte, écriture),
   `secubox-profilectl releve`, unités `secubox-profiles-releve.service/.timer`, `GET /api/v1/profiles/validation`
   (`require_lecture`), tests `tests/test_validation_3212.py`. Paquet 0.24.0.
2. **annuaire — signature et diffusion** : `ModulesSnapshot` (+ `PaquetEtat`, `UniteEtat`), `fleet.sign_modules`,
   vérification avec validation du modèle, `fleet_store` (chemin modules), `sbx-fleetctl publish-modules` (saute si le
   relevé n'a pas changé), `ExecStart=-…publish-modules`, routes `/fleet/modules/self` (`lecture_ou_pair`) et
   `/fleet/modules` (JWT), emplacement nginx 8799, tests `tests/test_fleet_modules_3212.py`. Paquet 0.16.0.
3. **profiles — page** : onglets, matrice (colonnes triées par nom, écarts de version, filtres Tous/Écarts/Erreurs,
   légende, en-têtes : profil actif, âge du relevé, périmé), section erreurs, `?demo=1`. Pas de logique d'état en JS :
   la page affiche ce que les box ont signé.
4. **Documentation** : README de profiles et d'annuaire, README racine, wiki `Valider-un-parc.md` + accueil + barre.
5. **Déploiement et vérification** : gk1, gk2, gk3, gk4 ; relevé signé lu depuis chaque box ; page sur gk2 et gk4.

## Points d'attention pour la relecture

- Un pair ne doit pas pouvoir se faire passer pour un autre (chaîne DID de `verify_snapshot`) ni gonfler la réponse
  (modèle borné validé à la lecture).
- Unités `oneshot` déclenchées par un timer, modules à la demande endormis : jamais « arrêté » à tort.
- Box sans profil installé, `dpkg` illisible, `systemctl` en échec : relevé partiel annoncé, pas de faux « absent ».
