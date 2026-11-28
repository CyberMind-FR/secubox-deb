<!--
SPDX-License-Identifier: LicenseRef-CMSD-1.0
Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
See LICENCE-CMSD-1.0.md for terms.
-->
# Atelier des émissions — conception (#4058)

Validée avec le propriétaire le 28/11/2026. Maquette approuvée : https://claude.ai/artifact/THsH33U7dQixiQp31o7Axj

## Intention

Transformer les analyses de menaces de gk2 en **émissions de décryptage à deux voix**, comme « Internet sous
surveillance » du 28/11 : écrites à partir des faits, relues par le code, dites par des voix de synthèse, illustrées
par des graphiques synchronisés, puis publiées sur les billets. Le propriétaire veut pouvoir les lancer à la demande et
recevoir chaque semaine un brouillon sur **ce qui a changé**. La source des émissions, ce sont des **lectures
évolutives** des campagnes et des acteurs : chaque nouvelle lecture repart des interprétations déjà validées et ne
garde que les évolutions (nouvelle vague, extinction, nouveaux opérateurs, retours d'acteurs).

## Objectifs

1. **Lectures évolutives** par campagne et par acteur : un historique des interprétations validées (phrases retenues
   par le vérificateur de #4006/#4030/#4042), comparé au dossier courant ; sortie = « ce qui a changé » + une analyse
   finale qui enchaîne les évolutions. Les retours possibles d'un acteur (récurrences, extinction depuis N jours) sont
   un fait de première classe.
2. **Chaîne de production** en sept étapes visibles : faits → évolutions → consigne → dialogue → vérification →
   voix → montage.
3. **Dialogue vérifié** : chaque réplique passe par le vérificateur de gk2 (même code `verif_rapport`), marquée
   ✓ vérifiée / ⚠ lecture IA seule / ✗ retirée ; une réplique retirée n'est jamais dite.
4. **Voix** sur le GPU de gk0 via le worker Voice Studio (#4057) : voix 1 = nova, voix 2 = onyx par défaut ;
   le LLM du relais (Gemma, llama-server) est **suspendu pendant la synthèse et relancé à la fin**, même en cas d'échec.
5. **Diaporama synchronisé** : graphiques générés depuis les dossiers (sans adresse IP), zoomés sur le chiffre cité ;
   chaque diapositive est liée à la réplique qui la cite et s'affiche au moment où elle est dite.
6. **Sorties** : MP3 + diaporama synchronisé publiés dans un billet ; **vidéo MP4 en option**, générée d'un clic.
7. **Validation humaine obligatoire** : rien n'est publié sans le clic « Publier » du propriétaire. Modifier une
   réplique ne refait que sa voix.
8. **Déclenchement** : à la demande (choix d'une ou plusieurs sources) **et** chaque lundi matin. L'hebdomadaire produit
   **les deux formats** : une émission de **synthèse** couvrant tous les sujets qui ont changé dans la semaine, puis des
   émissions **par sujet** pour les sujets aux évolutions marquantes (seuil réglable). Une production à la fois, en file,
   la synthèse d'abord ; chaque brouillon attend la validation.
10. **Capture d'admin d'un clic** (dans cette tranche) : capture d'une page d'admin choisie, zoomée sur une zone ;
   masquage automatique des zones à risque (sélecteurs connus : tableaux d'adresses, journaux, noms d'hôtes), puis
   **contrôle automatique bloquant** (OCR de l'image : aucune adresse IPv4/IPv6, aucun nom d'hôte interne, aucun
   jeton) et **validation visuelle du propriétaire** avant usage. Une capture qui échoue au contrôle ne peut pas être
   publiée.
9. **Panneau** : onglet « Émissions » du relais IA de gk0, conforme à la maquette (sources / brouillon / validation).

## Non-objectifs (cette tranche)

- Publication automatique sans validation. Jamais.
- Module SecuBox sur gk3 (voie B) : tranche ultérieure, une fois la qualité réglée.
- ~~Capture d'admin~~ : **dans le périmètre** (décision du 28/11, voir objectif 10).
- Dictée temps réel : existe déjà dans Voice Studio ; hors de la chaîne.
- Musique d'habillage : pas de source libre fournie ; emplacement prévu (intro/outro) mais vide.
- Exposer le LLM ou le GPU de gk0 au maillage.

## Anti-objectifs (échecs même si « ça marche »)

- Une adresse IP, un nom de site interne ou un détail de configuration dans un contenu publié.
- Une phrase non adossée au dossier dite à voix haute.
- Attribuer une activité à un hébergeur, ou prétendre à une opération d'État, un financement ou une coordination.
- Confondre bannissements, attaques réussies et incidents.
- Laisser le relais IA hors service après une production (Gemma non relancé).
- Un ton publicitaire pour SecuBox.

## Contraintes

- **Publication publique sur Internet** (décision du 28/11) : prudence éditoriale maximale ; garde finale avant
  publication = balayage automatique de TOUT le contenu (texte, chronologie, images par OCR) pour adresses, noms
  internes et jetons ; un seul résultat → publication refusée.
- **Stockage sur gk2** (disque racine presque plein) : médias des émissions sur le volume de données des billets, pas sur
  `/` ; MP3 128k mono (~1 Mo/min), images PNG compressées, MP4 seulement à la demande ; garde d'espace avant envoi ;
  rétention réglable (MP4 purgés après N jours, MP3 et diapos gardés).

- gk0 = poste du propriétaire : GPU RTX 3050 4 Go partagé avec Gemma (2,7 Go), RAM tendue, disque ~17 Go libres.
  **Une production à la fois**, GPU tour à tour (LLM pour écrire, puis voix).
- Relais : `packages/secubox-ai-agents` (branchement `agents_relais.brancher`, routes **locales seulement**,
  service utilisateur sur socket Unix, jeton 0600 posé par le relais). L'atelier suit ce patron : nouveau service
  utilisateur `secubox-ai-emissions` + page `emissions.html` + routes `/api/v1/ai/emissions/*`.
- gk2 en **lecture seule** pour les dossiers (API WAF `/rapports`, `/rapports/{genre}/{id}` ; lecture par le tunnel
  existant ou un jeton de lecture dédié). Publication par l'API des billets avec un **compte d'auteur dédié**.
- Vérification : réutiliser `verif_rapport.py` tel quel (copie versionnée ou dépendance), même dossier de faits.
- Voix : Voice Studio de gk3 via le worker GPU de gk0 (tunnel SSH sortant `127.0.0.1:7443`), ou moteur local si le
  worker l'expose ; délai et reprise par réplique (fichiers par réplique, reprise idempotente).
- Règles projet : français, SPDX, tests, pas de secret en clair, pas de CDN dans les pages servies.

## Approches considérées

- **A. Tout sur gk0, onglet du relais IA** : rapide, aucun port exposé, LLM local ; dépend de gk0 allumé.
- **B. Module SecuBox sur gk3, gk0 en fournisseur de calcul** : toujours en ligne, conforme aux modules ; exige
  d'exposer LLM et GPU de gk0 au maillage, beaucoup plus de travail.
- **C. A puis B** — **retenue** par le propriétaire : régler la qualité vite et sans exposition réseau, puis
  porter en module.

## Décisions du propriétaire

Validation à chaque émission · à la demande + hebdo · audio + diaporama synchronisé, MP4 en option · graphiques
générés, capture d'admin ajoutable d'un clic (avec floutage validé) · lectures évolutives campagnes **et acteurs**
comme source · voie C · GPU : Gemma suspendu le temps d'une production.

## Esquisse technique (pour le plan)

- **Lectures évolutives** : magasin SQLite par sujet (`interpretations` : sujet, date, phrase, statut, empreinte du
  dossier) alimenté par chaque rédaction validée ; `evolutions(sujet)` = diff entre le dossier courant et le dernier
  dossier validé (vagues, phases, opérateurs, récurrences, chiffres) → liste de faits nouveaux.
- **Consigne** : générée depuis le plan en 7 parties (gabarit éditable) + faits nouveaux + règles impératives.
- **Dialogue** : LLM local, sortie « V1:/V2: » ; chaque réplique vérifiée ; diapositive associée par les chiffres
  et termes qu'elle cite (correspondance avec les graphiques disponibles).
- **Graphiques** : rendu serveur (SVG → PNG) depuis le dossier ; palette SecuBox ; zoom = fenêtre de dates ou barre
  mise en avant ; aucune donnée d'adresse.
- **Montage** : ffmpeg (pauses 0,45 s, loudnorm −16 LUFS, MP3 128k) ; chronologie JSON (réplique → début/fin →
  diapo) publiée avec le billet ; MP4 = images + audio selon la chronologie.
- **Publication** : billet (titre, chapeau, MP3, diapositives, chronologie) ; nécessite que le diaporama des billets
  (#4049) sache suivre une chronologie audio (petit ajout côté billets).
- **Hebdomadaire** : minuterie utilisateur lundi 06:00 ; produit un brouillon, notifie, ne publie pas.

## Choix pris pendant la conception (corrigeables)

- Premier passage : l'historique des interprétations est **amorcé** avec les rapports déjà validés sur gk2.
- Brouillons conservés sur gk0 jusqu'au clic « Publier » ; rien n'est envoyé aux billets avant.
- Statuts : ⚠ (lecture IA seule) est dite mais signalée ; ✗ n'est jamais dite ; transitions et questions sans chiffre
  sont admises (règle d'ancrage assouplie pour les répliques sans affirmation factuelle).
- Gemma suspendu **pendant la seule synthèse vocale** ; le relais répond « voix en cours » (503 explicite) pendant ce
  temps ; verrou d'exclusion tenu par le service d'émissions, relance garantie (trap, et vérification au démarrage).
- Le worker GPU Voice Studio (#4057) est un **préalable** : sans lui, la chaîne s'arrête avant l'étape voix.
- Compte d'auteur dédié aux émissions à créer dans les billets.

## Ce qui reste au constructeur

Découpage des tâches, schéma exact du magasin, format de la chronologie, choix du moteur de rendu des graphiques,
gestion fine des reprises, et l'ajout « chronologie audio » dans le diaporama des billets.
