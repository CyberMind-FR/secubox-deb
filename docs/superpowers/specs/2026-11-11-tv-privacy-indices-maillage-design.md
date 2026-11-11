<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# TV Privacy × MirrorNet — indices de détection partagés entre box

Issue #3666 · premier vrai jeu de données MirrorNet (phase 4, #3649) · conception du 2026-11-11.

## 1. Intention

Chaque box SecuBox apprend, avec TV Privacy (`secubox-ad-guard`, module dnstv), quels domaines servent la publicité,
le pistage ou la télémétrie de ses TV. Aujourd'hui, cet apprentissage reste enfermé dans la box : une autre maison doit
tout réapprendre. Le propriétaire veut que **chaque box améliore sa propre détection grâce à ce que les autres ont
appris**, et réciproquement (« les autres aussi pour améliorer gk2… bien évidemment »).

Succès vu par le propriétaire : sur une deuxième box en mode auto, un domaine de pub Netflix déjà confirmé sur gk2 est
mis à l'essai dès la première coupure pub où la TV le demande, sans action de son propriétaire ; et gk2 profite de
même des domaines confirmés ailleurs.

## 2. Ce que le propriétaire a décidé

- Le partage sert à **améliorer la détection de la box qui reçoit**, pas à lui imposer une liste.
- **Mode auto, poids de détection maximal** : un domaine que la box voit elle-même pendant une coupure pub et qu'une autre
  box a confirmé comme pub/pistage/télémétrie passe **seul à l'essai**, sans attendre le propriétaire.
- **Réciproque** : chaque box publie et chaque box reçoit.
- Un domaine marqué **légitime** par une autre box **freine** l'essai automatique : il reste seulement proposé.

## 3. Objectifs, non-objectifs, anti-objectifs

Objectifs
- Publication automatique, par chaque box, de ses domaines confirmés (pub, pistage, télémétrie) et de ses domaines
  déclarés légitimes ; mise à jour à chaque changement significatif.
- Réception automatique des publications de toutes les box de confiance du maillage ; fusion en indices locaux.
- Utilisation des indices par le moteur auto de TV Privacy, avec le poids maximal, sur les seuls domaines vus localement.
- Visibilité dans la page TV Privacy : « suggéré par gk2, gk6 », « légitime chez gk1 », nombre d'indices reçus.

Non-objectifs (cette version)
- Partager la classification brute, les compteurs, `dnstv.db`, ou le tri Netflix (`dnstv_tri.py`, mécanisme à part).
- Partager entre box hors du maillage, ou vers Internet.
- Crédits, réciprocité comptable (phase 5).

Anti-objectifs — échec même si « ça marche »
- Un blocage déclenché chez une box par un domaine qu'**elle n'a jamais vu** passer.
- Un blocage automatique d'une catégorie protégée (streaming, CDN, DRM, authentification, mise à jour) parce
  qu'une autre box la classe pub. INCONNU fait exception : un indice le lève (voir § 5.3 bis, décision du propriétaire
  « auto tout ») ; les cinq autres catégories protégées ne sont jamais levées.
- Une publication qui révèle un appareil, un horaire, un volume, une MAC, un nom de TV, ou l'existence d'un domaine que
  le propriétaire n'a pas confirmé.
- Une erreur d'une box recopiée de box en box jusqu'à passer pour une certitude collective (écho).
- Un blocage impossible à défaire : l'essai doit rester réversible exactement comme aujourd'hui.
- Toute IA dans la décision (consigne #3509 : contrôle par des règles, jamais par un modèle).

## 4. Contraintes

- MirrorNet transporte des objets **opaques** (versions signées, BLAKE2b, maillage seulement) : `secubox-mirrornet` ne
  lit jamais le contenu ; seul le module consommateur l'interprète, sous son compte et dans son arbre.
- Jeu de données de classe `communaute` (membres du maillage), `donnees_personnelles = non` ; jamais `public` (les
  domaines confirmés trahissent les services et marques de TV de la maison).
- Seules les box au niveau de confiance ≥ LIMITED (`config.reglages()["confiance_min"]`) sont écoutées.
- Publication et abonnement **sans jeton d'administrateur** : ils tournent en tâche de fond. Le mécanisme ne doit pas
  élargir ce qu'un composant local peut faire signer à `node.key` : seulement des versions du jeu « indices TV » de
  cette box, et l'abonnement aux jeux « indices TV » des autres. Précédent existant : `secubox-annuaire-offres`
  (`annuaire/offres.py`, #3021) fait signer par l'annuaire des offres à partir d'un fichier de faits déposé localement.
- Règles du dépôt : RULES-CODE (gardes, comptes dédiés, AppArmor enforce, pas de secret), audit des décisions de
  sécurité, versions de paquets montées, tests ; relecture `relecteur-securite` avant la PR.
- Box modestes (ESPRESSObin 1 Go, RPi) : fusion et lecture des indices bornées (taille, nombre de domaines, mémoire).

## 5. Comment ça marche (décidé)

### 5.1 Publication (chaque box)

- Contenu publié, généré par `secubox-ad-guard` sous son compte, déterministe (même contenu → même empreinte → pas de
  nouvelle version) :
  - `indices` : domaines dont une règle est **confirmée localement** (`regles.json`, état confirmé, origine auto ou
    admin) ou une exception `bloquer` posée par l'admin, avec leur catégorie parmi PUBLICITE, TRACKING, TELEMETRIE ;
  - `legitimes` : domaines débloqués par l'admin (exception `autoriser`) ou dont une règle a été rejetée / retirée par
    l'admin.
  - *Relecture finale (vie privée)* : seuls les domaines dont la catégorie LOCALE est PUBLICITE, TRACKING ou TELEMETRIE
    (étiquette = cette catégorie), ou INCONNU avec une règle confirmée par l'administrateur (étiquette PUBLICITE), sont
    publiés ; une exception `bloquer` sur un domaine d'une autre catégorie (contrôle parental, streaming…) ne l'est
    jamais. `legitimes` : seulement les domaines de catégorie pub / pistage / télémétrie ou INCONNU.
  - Rien d'autre : ni appareil, ni slug, ni MAC, ni date par domaine, ni compteur.
- **Pas d'écho** : un domaine connu seulement par un indice reçu n'est jamais republié. Il l'est seulement après une
  confirmation **locale** (règle confirmée sur cette box).
- Une offre `kind=dataset` « Indices TV Privacy — <box> » est créée automatiquement au premier besoin ; une version est
  publiée quand le contenu change, au plus une fois par heure (débit du journal maîtrisé). *Décision assumée (relecture
  finale) : l'heure d'une version révèle qu'une règle a changé sur la box dans l'heure précédente ; la vitesse de
  détection prime sur ce signal (une publication quotidienne a été écartée).*

### 5.2 Réception (chaque box)

- La box s'abonne automatiquement aux offres « Indices TV Privacy » des autres box de confiance (abonnement d'un clic
  remplacé par un abonnement de fond ; résiliable par le propriétaire).
- MirrorNet reçoit et vérifie les versions (mécanisme existant 4a/4c : empreinte, taille, répartition entre sources).
  Il les **livre** au module : le module lit la dernière version vérifiée de chaque producteur, jamais en écriture,
  jamais un objet non vérifié.
- `secubox-ad-guard` valide chaque contenu (syntaxe de domaine, catégories admises, plafonds) et fusionne en un index
  local : domaine → {catégorie, box qui le confirment, box qui le déclarent légitime}.

### 5.3 Utilisation par la détection (mode auto)

- L'indice **n'est jamais un déclencheur** de coupure pub et n'agit **que sur un domaine vu localement** pendant une
  coupure pub (candidat de `dnstv_detect`).
- Domaine candidat localement + au moins une box le confirme + aucune box ne le déclare légitime + catégorie locale non
  protégée → **poids maximal**, et passage **seul à l'essai** (24 h, mêmes retraits automatiques qu'aujourd'hui), motif
  « suggéré par <box…> ».
- Si au moins une box le déclare légitime → pas d'essai automatique ; il reste candidat, motif « légitime chez <box> »,
  décision au propriétaire.
- Les catégories protégées gardent leur garde actuelle (`refus_auto`) : un indice ne la lève jamais.
- Appareil en apprentissage guidé : rien ne passe seul à l'essai (règle actuelle conservée).

### 5.3 ter Décisions du propriétaire sur l'automatisme (« auto tout », 2026-11-11)

- L'indice met à l'essai **même si le réglage `auto_essai` de la box est désactivé** (valeur par défaut), dès lors que
  l'appareil est en mode auto : c'est un chemin automatique propre aux indices du maillage, activé par défaut, que le
  propriétaire peut couper avec l'interrupteur « Recevoir les indices des autres box ».
- Un domaine **vu aussi hors des coupures** (risque « partage ») part **aussi** à l'essai automatique quand un indice le
  confirme ; la protection reste le retrait automatique de l'essai (rafale de refus, disparition du contenu habituel).
- Une coupure pub locale suffit (pas de seuil de deux coupures pour un domaine porteur d'un indice).

### 5.3 bis Précisions (relecture du 2026-11-11 — décisions de conception, à valider)

- **INCONNU** : un indice reçu reclasse un domaine localement INCONNU dans la catégorie de l'émetteur (PUBLICITE,
  TRACKING, TELEMETRIE) — sinon le poids maximal ne servirait jamais, un domaine de pub d'une autre maison étant presque
  toujours inconnu localement. Les autres catégories protégées (streaming, CDN, DRM, authentification, mise à jour)
  restent protégées. *(Décision de conception, déduite de « poids maximisé ».)*
- **Écho et confirmation automatique** : la règle garde sa provenance « née d'un indice ». Elle n'est republiée que
  confirmée par l'administrateur local, ou détectée localement sans indice ; une confirmation automatique d'un essai né
  d'un indice ne suffit pas. *(Décision de conception, conséquence de l'anti-objectif « écho ».)*
- **Retrait** : si la box émettrice retire le domaine, le déclare légitime, passe sous le seuil de confiance ou se
  désabonne, les essais en cours nés de ses seuls indices sont retirés ; les règles confirmées par l'administrateur
  restent, celles confirmées par le moteur à partir d'un indice suivent l'indice. *(Décision de conception.)*
  *Relecture finale* : seule une lecture LOCALE ratée (index ou fichier du producteur absent, illisible, tronqué, trop
  gros sur disque) protège un essai né d'indice ; un contenu signé mais invalide vaut « aucun indice ». Les
  prolongations d'un tel essai sont plafonnées à 3 consécutives, puis l'expiration ordinaire joue.
- **Portée** : domaine exact seulement, jamais un suffixe ni un parent ; un « légitime » ne porte aussi que sur le
  domaine exact. *(Décision de conception : borne le pouvoir d'une box distante.)*

### 5.4 Interface

- Page TV Privacy : sur une règle ou un candidat, la provenance (« suggéré par gk2, gk6 », « légitime chez gk1 ») ; un
  encart « Indices du maillage » (nombre de domaines reçus, nombre de box, dernière mise à jour) ; deux interrupteurs :
  « Publier mes indices » et « Recevoir les indices des autres box », actifs par défaut.

## 6. Laissé au constructeur

- Le format exact du contenu publié (JSON, champs, version de format), tant qu'il respecte 5.1.
- Le mécanisme local de publication et d'abonnement sans jeton, dans les limites de la contrainte 4 (dépôt d'un fichier
  de faits lu par l'annuaire, comme #3021, est le chemin attendu).
- Le mécanisme de livraison MirrorNet → module (dossier de livraison lisible par le groupe, ou route locale), tant
  qu'il ne livre que des objets vérifiés et ne donne aucun droit d'écriture.
- La valeur exacte du « poids maximal » et son intégration dans le score de `dnstv_detect` / `dnstv_auto`.
- Les plafonds (domaines par producteur, nombre de producteurs, taille d'objet) adaptés aux box modestes.
- Le nom des réglages et leur emplacement (TOML d'ad-guard ou état dnstv).
