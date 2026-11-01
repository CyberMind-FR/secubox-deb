<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# SBX TV PRIVACY — lot 5b « assistant de détection en direct » (#3374)

Demande du propriétaire (2026-11-01) : « un dynamique mis à jour lors de la détection en cours, comme un passive wizard
interactivable, avec actions différées pour le smart et l'apprentissage ou la confirmation ; au moins en mode apprentissage
optionnel ». Aucun nouveau mécanisme DNS : l'assistant réutilise les exceptions du lot 3 et la garde du lot 2.

## 1. Vue « En direct » (onglet de `/tv-privacy/`, administrateur réel)

- Source : `GET /protection/direct?depuis=<id>&limite=` (`require_jwt`), qui lit l'interface du lot 4
  (`dpi-appareils.db`, découvertes à identifiant croissant) et y ajoute, pour chaque découverte : nom de l'appareil (jamais une
  IP quand la MAC est connue ; sinon « appareil inconnu »), catégorie (taxonomie unique si la découverte n'en porte pas), état
  de l'assistant (`en-attente`, `applique`, `refuse`), et les candidats du moteur en attente de validation (apprentissage guidé).
- Rafraîchissement par interrogation légère : toutes les 15 s, curseur `depuis` (on n'ajoute que les nouvelles), plafond de
  200 lignes affichées, seulement si la page est visible et l'onglet ouvert, et **jamais pendant une confirmation ouverte**
  (`etat.ouvert`, défaut subi dans la Flotte : la saisie était effacée).

## 2. Assistant passif

Chaque découverte qui porte un nom de domaine propose trois choix, aucun n'est imposé : **confirmer le blocage**, **c'est
légitime** (exception `autoriser`), **plus tard**. Les constats sans nom (`sans-dns`, `dns-chiffre`, `contournement` :
adresse:port) n'ont que « plus tard ». La confirmation se fait dans la page (`confirmer()`), jamais par `confirm()`.

## 3. Actions différées : `assistant.json` (`DOSSIER_ETAT`, 0640)

```json
{"version": 1, "guides": ["aa:bb:cc:dd:ee:ff"],
 "file": [{"id": "9f3c…", "mac": "…", "appareil": "TV salon", "domaine": "x.example", "choix": "bloquer|legitime|plus-tard",
           "force": false, "decouverte": 12, "acteur": "admin", "cree": 1793548800, "etat": "en-attente|applique|refuse",
           "applique": null, "raison": ""}]}
```

- Écrite sous `dnstv_regles.verrou`, atomique (`mkstemp` + `os.replace`), lue en `O_NOFOLLOW` et revalidée champ par champ.
- Bornée : 100 actions en attente, 300 entrées en tout ; les entrées appliquées ou refusées partent après 24 h.
- Sans doublon : une seule action en attente par couple (MAC, domaine) ; une seconde est refusée (409).
- Chaque ajout, annulation et changement d'apprentissage guidé passe AVANT écriture par le verbe root `audit-protection`,
  étendu de façon bornée : gestes `assistant`, `assistant-annule` (type `bloquer|legitime|plus-tard`, domaine obligatoire) et
  `guide` (type `active|desactive`, sans domaine). Audit impossible : geste refusé (502).
- Consommation par `secubox-adguard-auto` à son passage (chaque minute), sous le même verrou, AVANT `tick` :
  `bloquer` → `poser_exception(type="bloquer")`, `legitime` → `poser_exception(type="autoriser")` (origine `admin`), `plus-tard` →
  rien sur le DNS. La découverte passe à `confirmee`, `legitime` ou `plus-tard`. L'application DNS est faite et auditée par
  `regles-appliquer`, comme toute transition.
- Affichage : « en attente » puis « appliqué à HH:MM » ; « Annuler » tant que l'action est en attente
  (`POST /protection/assistant/annuler`).

## 4. Apprentissage guidé (option par appareil, désactivée par défaut)

`guides` (MAC) dans `assistant.json`, `POST /protection/assistant/guide {mac, actif}`. Pour un appareil guidé, `tick` ne fait
plus passer aucun candidat en essai automatique (détecteur, repli publicitaire, « confirmé ailleurs ») : ils attendent une
validation dans l'assistant. Sans appareil guidé, AUTO reste strictement identique (utilisateur lambda : aucun changement).

## 5. Gardes

- La garde du lot 2 est inchangée : catégories protégées et INCONNU jamais bloquées automatiquement.
- Une confirmation dans l'assistant est une décision **manuelle** : règle `confirme` d'origine `admin` (lève la garde comme au
  lot 2) ; bloquer une catégorie protégée autre qu'INCONNU exige `force` (409 sinon), comme au lot 3. Le moteur revérifie au
  passage : sans `force`, une catégorie devenue protégée entre-temps est refusée (`refuse`, raison écrite).
- `imasdk.googleapis.com` (STREAMING, référence) n'est jamais bloquable sans `force`.
- Toutes les routes nouvelles en `require_jwt` (déclarées dans `routes-ouvertes.d` pour la page relayée), sauf le compteur du
  kiosque.

## 6. Kiosque (préparé seulement)

`GET /protection/usager/appris` (`require_personne`) : `{"nouveaux_pisteurs": N, "jours": 7}`, nombre de domaines distincts
passés en essai ou confirmés sur 7 jours, sans détail par appareil ni domaine. La page du kiosque n'est pas modifiée.

## 7. Défauts de la page corrigés

- « Domaines par catégorie » : panneaux de la vue générale alignés en haut (`align-items:start`), sans étirement.
- Événements : une adresse brute (IPv6 d'un PC non déclaré) devient « appareil inconnu (IPv6) », l'adresse en infobulle pour
  l'administrateur.
- Couverture : `dns+dpi` ne compte que des flux vers un **tiers**. Les flux vers une adresse de gk2 (son DNS 53/853 compris,
  que conntrack voit) sont écartés au passage DPI (`dnstv_dpi.flux_tiers`).

## 8. Version

`secubox-ad-guard` 1.22.0-1~trixie1.

## Passe 2 (relectures du 2026-11-01)

- **B1** : à l'ouverture (`depuis=0`, F5), `/protection/direct` rend les `limite` découvertes les PLUS RÉCENTES (remises dans l'ordre) ;
  ensuite le curseur croissant. `etats` donne l'état courant des 200 plus récentes, pour mettre à jour les lignes déjà affichées (m3).
- **I1** : API et moteur classent par la même fonction `dnstv_assistant.taxonomie()` (listes, référence, services, profil, corrections
  manuelles, règles). Un domaine reclassé à la main en catégorie protégée exige `force` dès la route. Côté API, la taxonomie reste en cache
  dans le processus et n'est rechargée que si la date ou la taille d'un fichier source change (m4).
- **I2** : une découverte sans nom de domaine (`sans-dns`, `dns-chiffre`, `contournement`, adresse:port) propose « Vu / plus tard »
  (`POST /protection/assistant/vu {mac, decouverte}`, audit `assistant` type `vu` sans domaine). Le moteur la marque `plus-tard`, sans
  effet DNS. **Reporté** : « bloquer » et « légitime » par adresse, qui demandent un mécanisme nftables par appareil (autre lot).
- **Arbitrage du pilotage délégué** : `^/adblock-tv/protection/assistant/(choix|annuler|guide)$` reste dans `routes-ouvertes.d`. Ce sont des
  gestes d'administrateur relayés par le maître, cohérents avec le lot 3. Le compteur du kiosque n'y figure pas.
- m1 : purge des entrées traitées avant de compter les plafonds ; un message distinct pour les actions en attente et pour les choix traités en 24 h.
- m2 : rejeu après un arrêt du moteur entre exceptions et file. Une exception déjà présente dans le même sens est marquée `applique`, sans
  être reposée ni journalisée deux fois.
- `marquer_id` vérifie la MAC (et le domaine quand il est donné) ; un audit d'intention suivi d'un échec d'écriture de la file ajoute une
  entrée `annule`.
- m5 : le panneau « Candidats en attente de validation » ne montre que les appareils en apprentissage guidé.
- m7 : « appareil inconnu (IPv6) » s'applique aussi au tableau des erreurs DNS du diagnostic.
