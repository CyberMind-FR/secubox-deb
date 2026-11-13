<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Console de pilotage du maître — actions, macros, journal en direct — conception

**Date :** 2026-11-13 · **Issue :** #3702 (suite de #3288, #3126) · **Statut :** maquette validée par le propriétaire
(« go », 2026-11-13) ; conception à relire.
**Maquette :** https://claude.ai/artifact/Bie8keZPrYfQrvHx2gR5K2 (Console, Éditeur de macro, Lancer sur plusieurs box).

## 1. Intention

Le pilotage TR-369 sait déjà, depuis gk2 maître, voir une box (inventaire, relevé, événements, flux) et agir sur elle par
une **liste fermée** d'actions (`pilotage/operations.py` : `CATALOGUE`). Chaque geste se fait aujourd'hui box par box,
depuis la page Flotte. Le propriétaire veut une **console** : choisir plusieurs box, lancer une action ou une **macro**
(une suite d'actions du catalogue, avec quelques contrôles faits par le maître), et suivre le déroulement dans un
**journal en direct** façon terminal — « super smart », sans jamais ouvrir de commande libre.

## 2. Buts, non-buts, anti-buts

**Buts**
- Une page Aurora `/pilotage/console/` sur le maître : barre de commande (Ctrl K) qui cherche actions, macros et box ;
  flotte cochable avec groupes ; boutons des actions du catalogue ; liste des macros ; journal en direct ; état en direct
  de la box sélectionnée (mémoire, CPU, disque, services en échec).
- Des **macros** enregistrées sur le maître : étapes = actions du catalogue + contrôles du maître ; lancées sur une ou
  plusieurs box, **une box après l'autre**, avec **arrêt de toute la série au premier écart**.
- Des macros **livrées** (lecture seule, copiables) : Diagnostic complet, Mise à jour sûre, Remise en route, Retour en local.
- **Simulation** d'une macro sur une box : le plan, sans rien envoyer.
- Lancement **programmé** (chaque nuit à une heure donnée) pour les macros sans geste à risque.

**Non-buts (v1)**
- Pas de commande libre, pas de shell, pas de script : rien hors du `CATALOGUE` et des contrôles listés au § 4.
- Pas de macro sur une box cliente sans session de support ouverte (règle existante), donc pas de programmation sur une
  box cliente.
- Pas de groupes édités à la main : groupes calculés depuis l'inventaire (§ 4.4).
- Pas de console sur une box légère : la console vit sur le maître seulement.

**Anti-buts (échec même si « ça marche »)**
- Un geste à risque (`forte=True` au catalogue) lancé sans que l'administrateur ait retapé le nom exact de CHAQUE box.
- Une macro qui contourne les gardes existantes (validation des paramètres, support, audit) en parlant à l'agent par un
  autre chemin que celui des opérations.
- Une deuxième box touchée alors que la première n'est pas revenue saine.
- Un langage de conditions ouvert (expressions, `eval`) : les conditions sont des prédicats nommés à seuil.

## 3. Ce qui existe et sert tel quel

- `CATALOGUE` et `arguments()` (validation des paramètres) ; confirmation forte = nom exact de la box ; `support` exigé
  sur une box cliente ; audit `pilotage_action` ; `Suivi.apres_fin` (fin d'opération).
- Relevé `POST/GET /boxes/{x}/releve` (10..300 s), inventaire `GET /boxes/{x}`, événements, opérations, flux SSE
  `/boxes/{x}/flux` (4 flux par administrateur).
- Gardes : `require_jwt` + `session_toujours_admin` ; tout est servi par `/run/secubox/pilotage.sock` via l'agrégateur.

## 4. Ce qui est décidé

### 4.1 Modèle d'une macro (stockée dans `pilotage.db`)

`macros(id, nom, etapes_json, cibles_json, programmation_json, livree, cree_le, maj_le, auteur)`.
Une étape est un objet d'un de ces types, et de rien d'autre (refus 400 à l'enregistrement comme au lancement) :

| type | champs | effet |
|---|---|---|
| `action` | `action` (clé du `CATALOGUE`), `args` (validés par `arguments()`), `delai_s` (60..3600, 900 par défaut) | une opération, par le même chemin que `POST /boxes/{x}/actions/{action}` |
| `releve` | `duree_s` (10..300), `nom` (`avant`, `apres` ou libre `[a-z0-9-]{1,20}`) | un relevé, mémorisé sous ce nom pour la suite |
| `condition` | `mesure` ∈ {`memoire_dispo_mo`, `cpu_pct`, `swap_utilise_pct`, `services_en_echec`}, `releve` (nom), `op` ∈ {`>`, `<`}, `seuil` (nombre), `alors` ∈ {`arreter`, `passer`} | arrêt de la macro sur cette box (ou saut de l'étape suivante) si le prédicat est vrai ; mesure absente (agent ancien) = condition fausse, notée dans le journal |
| `comparer` | `avant`, `apres` (noms de relevés), `regle` ∈ {`nouveau_service_en_echec`, `memoire_dispo_baisse_mo`}, `seuil` | **écart** si la règle est vraie : arrêt de la série, proposition affichée (relancer le service nouveau en échec) |
| `attendre` | `delai_s` (30..900) | attendre que la box revienne en ligne (nouveau `boot_id` après un `reboot`, sinon simple présence) |

Bornes : 20 étapes au plus par macro ; nom de macro `^[\w àâçéèêëîïôûùüÿœ'-]{1,60}$`.

### 4.2 Lancement et déroulement

- `POST /macros/{id}/lancer {cibles: [box…], confirmations: {box: nom_retapé}, support: {box: sid}}` → 202 et un id
  d'exécution. Refus 400 si la macro contient une étape `forte` et qu'une box cible n'a pas sa confirmation exacte ;
  409 si une box cliente n'a pas de session de support ouverte ; 409 si une box cible est hors ligne.
- **Série** : les box dans l'ordre donné ; une box commence quand la précédente a fini **sans écart**. Écart, échec
  d'une étape, délai dépassé ou box qui ne revient pas → l'exécution s'arrête, les box suivantes ne sont pas touchées
  (état `non_lancee`).
- Une seule exécution à la fois par box (409 sinon) ; `POST /executions/{id}/arreter` arrête après l'étape en cours
  (jamais au milieu d'une opération déjà envoyée).
- Tables `executions(id, macro_id, macro_nom, cibles_json, etat, acteur, debut, fin, raison)` et
  `execution_etapes(execution_id, box, rang, type, etat, resultat_json, debut, fin)` ; `GET /executions`,
  `GET /executions/{id}`.
- Journal en direct : chaque début/fin d'étape est publié dans la diffusion existante (événement `macro`) ; la console
  s'abonne aux flux des box cibles (règle des 4 flux respectée : un flux par box sélectionnée, 4 au plus affichées) et à
  `GET /executions/{id}/flux` (SSE, nouveau, mêmes gardes).
- Audit : `pilotage_macro` (lancement, fin, arrêt, écart) en plus de l'audit `pilotage_action` de chaque action.
- Le maître redémarre pendant une exécution : au démarrage, toute exécution `en_cours` passe `interrompue` (aucune
  reprise automatique d'une série à moitié faite).

### 4.3 Simulation et programmation

- `POST /macros/{id}/simuler {box}` : rend le plan (étapes, paramètres validés, confirmation forte requise, durée
  estimée par étape) sans rien envoyer ni écrire hors du journal applicatif.
- `programmation = {"quotidien": "HH:MM"}` ou rien. **Refusée (400) si la macro contient une étape `forte`** (personne
  pour retaper les noms la nuit) ou si une cible est une box cliente. Un planificateur interne au service (tic de 60 s,
  dernière exécution mémorisée) lance la macro ; une exécution manquée pendant un arrêt du maître n'est pas rattrapée.

### 4.4 Groupes de la flotte

Calculés à chaque lecture depuis l'inventaire : par **matériel** (MOCHAbin, RPi, ESPRESSObin, autre), par **interface**
(légères = interface distante), par **état** (en ligne, muettes). Une box muette n'est jamais cochable.

### 4.5 Page

- `secubox-pilotage` livre `www/pilotage/console/index.html` (profil Aurora, `.claude/AURORA-REFERENCE.md`, autonome,
  sans bibliothèque, `?embed=1`, textContent seulement), entrée de menu (catégorie de la Flotte) et place dans le profil
  `full` (le maître).
- Barre de commande : recherche côté client sur les clés et libellés du catalogue, les noms de macros et de box ;
  Entrée lance la première suggestion **après** l'écran de confirmation quand il y a lieu.
- Boutons : une action du catalogue par bouton (paramètre demandé dans une petite fenêtre : unité, paquet, nom) ; couleur
  orange/rouge pour `forte`.
- Écran de lancement : plan par box et par étape, coupure prévue, rappel du déroulement en série, un champ par box pour
  retaper son nom ; « Lancer » inactif tant qu'un nom manque.
- Éditeur : catalogue à gauche, étapes au centre (ajout par clic et par glisser, ordre modifiable), cibles, programmation,
  « Simuler sur… », « Enregistrer ».

## 4 bis. Réponses à la relecture « constructeur » (2026-11-13) — choix de Claude, à contester

- **Mesures** : v1 sans changer l'agent Go. Les conditions lisent les mesures que le maître a déjà (`stockage.resumes()` :
  `memoire_dispo_mo`, `cpu_pct`, `swap_utilise_pct`, `services_en_echec`) ; pas de disque en v1 (piste v2 : mesure du
  disque racine dans l'agent).
- **Relevé nommé** : l'étape `releve` lance le relevé de l'agent (durée donnée), puis, à sa fin, prend un **instantané**
  des mesures de la box (`resumes()` + la liste des services en échec de l'inventaire) et le range sous son nom, pour
  CETTE exécution (table `execution_releves`). Un relevé manuel déjà en cours : attendre 60 s au plus, sinon échec de
  l'étape. Liste des services tronquée : la règle `nouveau_service_en_echec` compare aussi le compteur ; un compteur en
  hausse sans nom identifiable est un écart.
- **Action interne** : `executer_action` est extraite de la fermeture de `creer_app_admin` en une fonction du module
  (mêmes contrôles, mêmes exceptions), appelée par la route HTTP ET par le moteur. Fin d'une étape `action` : le moteur
  sonde l'opération (`stockage`, 1 s) jusqu'à un état terminal ou `delai_s`. Réponse `consentement` d'une box : échec de
  l'étape (une macro n'attend pas un accord humain).
- **Attendre** : après un `reboot`, la fin de l'opération (close par `vu()` au nouveau `boot_id`) fait foi ; ailleurs,
  « présente » = vue depuis moins de `HORS_LIGNE_S` (90 s).
- **Groupes** : matériel lu dans `Device.DeviceInfo.ModelName` de l'inventaire, sous-chaîne sans casse (« mochabin »,
  « raspberry », « espressobin »), sinon « autre » (inventaire absent compris) ; muette = `en_ligne` faux.
- **Diffusion** : `diffusion.NOMS` gagne `macro` ; la console ne s'abonne qu'au flux de l'exécution
  (`/executions/{id}/flux`, clé `exec:<id>`), qui relaie les événements `operation` des box concernées : une seule
  place sur les 4 flux d'un administrateur.
- **Box cliente** : alignée sur le code — sur une box cliente, la session de support (accord du détenteur) remplace la
  saisie du nom ; la console ne demande le nom retapé que sur les box du maillage du propriétaire.
- **Programmation** : heure locale du maître ; acteur `planificateur` (forme `RE_ACTEUR`) ; une box cible hors ligne à
  l'heure dite = box sautée et notée, la série continue avec les suivantes (aucun geste n'a été tenté sur elle).
- **Stockage** : tables nouvelles par `CREATE TABLE IF NOT EXISTS` dans `pilotage.db` (montée de version du paquet
  seulement). Macros livrées : insérées au démarrage par leur identifiant fixe (`livree:<nom>`), réécrites à chaque
  version, non modifiables ; « Copier » en fait une macro ordinaire, indépendante ensuite.
- **Étapes des macros livrées** :
  - Diagnostic complet : `releve 300 s` (nom `diag`).
  - Mise à jour sûre : `releve 60 s avant` → `condition services_en_echec > 0 alors arreter` → `action maj-paquets` →
    `releve 60 s apres` → `comparer avant/apres nouveau_service_en_echec`.
  - Remise en route : `releve 60 s avant` puis, côté console, une action `service-redemarrer` proposée pour chaque
    service en échec relevé (lancée par l'administrateur, pas par la macro : les unités ne sont connues qu'au relevé).
  - Retour en local : `action interface-locale` (forte : jamais programmable).

## 5. Laissé au constructeur

Découpage du moteur (module `pilotage/macros.py` conseillé), forme exacte des événements de diffusion, estimation des
durées de la simulation, détails de l'éditeur (glisser-déposer au clavier aussi), tests (unitaires du moteur avec une
fausse file d'opérations, API, page en Playwright à 1440 et 420 px).

## 6. Essais

Banc : gk6 et gk7 depuis gk2 (box du propriétaire). Vérifier : Diagnostic complet sur 2 box ; Mise à jour sûre avec un
écart provoqué (service arrêté entre les deux relevés) → arrêt avant la 2e box ; refus d'un `reboot` sans nom retapé ;
refus d'une programmation contenant `reboot` ; maître relancé pendant une exécution → `interrompue` ; une box muette non
cochable.
