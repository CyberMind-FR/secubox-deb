<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Aurora (SBX OS) : état, objectif, prompts, faisabilité et évolutions

> 2026-10-06. Sources : `docs/sbxos/MIGRATION-AURORA.md` (plan #1604, épopée #1598), `docs/sbxos/HALL-SBXOS-AUDIT.md`,
> `packages/secubox-sbxos/` (README, changelog), état des issues #1611 à #1624, paquet installé sur gk2.
> Les jugements de faisabilité (§5) sont une analyse à valider, pas des mesures.

## 1. Ce qu'est Aurora

Aurora est la **nouvelle interface « SBX OS »** de la box : une application React/Vite servie par le paquet `secubox-sbxos`
(`/sbxos/aurora/` pour l'aperçu), qui doit à terme **remplacer l'interface jouable du Hall** à l'URL `/sbxos/`. Elle ne porte
aucune logique métier : elle présente, sur les API réelles de la box, des « Espaces » (Hall, Atelier, Sécurité, Média, Maison),
des cartes, un rail de navigation, une palette Ctrl K branchée sur ZIA (le cerveau), Lexie (le visage et la voix), des quêtes
et une communauté de 32 personnages (les Zanimalos). Le Hall « vanille » (`secubox-webos`) reste inchangé.

Décisions de départ (2026-09-28/29) : le Hall vanille ne bouge pas ; SBXOS devient l'interface jouable, livrée à côté, sur les
mêmes API ; deux rendus (Complet pour le navigateur, Léger pour le kiosque, la TV et les clients faibles) ; **canon graphique =
planches raster**, jamais d'icône dessinée à la main ; la logique reste dans secubox-deb, le SDK n'est que présentation.

## 2. État réel

| Élément | État |
|---|---|
| Version | `0.6.0~aurora14` (pré-alpha) installée **sur gk2 seulement**. Aucun build ni image ne la contient (décision du 2026-10-06 : les versions `~aurora*` sont exclues). |
| Livré | P7 traceur React à `/sbxos/aurora/` ; P9 couche données et protocole sbx ; P10 Espace Hall sur données réelles ; P11 Lexie et palette Ctrl K sur ZIA (issues #1613 à #1615 fermées) ; voix réactive (#1656) avec reconnaissance sur la box. |
| Ouvert | P8 art canon (#1612) ; P12 carte légère, profils de rendu mesurés, accessibilité, mobile (#1616) ; **P13 bascule 0.7.0 (#1617)** ; P14 temps réel (#1618) ; P15 Média et Sécurité (#1619) ; P16 Atelier et Maison (#1620) ; P17 communauté, démarrage, quêtes (#1621) ; P18 kiosque Léger et nettoyage (#1622) ; noms `gk2` écrits en dur (#1623). |
| Art | **100 % provisoire** : 41 découpes webp sans alpha, fond marine incrusté, floues dès qu'on agrandit. Manquent ~106 des 120 icônes, tous les masters alpha, les animations (Lexie : 8 animations), l'environnement « Maison ». |
| Audio | Reporté après la 1.0 : aucune source. |
| Thème | Sombre seulement tant que l'arbitrage A7 n'est pas rendu. |
| Poids | Paquet de 18 Mo dans le dépôt (dont le SDK 17 Mo) ; budget visé : Léger ≤ 1 Mo au premier chargement, Complet ≤ 5 Mo. |
| Estimation d'origine | ~17 semaines pour 0.7.x ; le plan date du 2026-09-28, la bascule était visée semaines 10-11. |

Ce que je n'ai pas vérifié : le rendu réel sur gk2 (je n'ai pas ouvert l'aperçu), les budgets de poids mesurés, l'état des
tests du paquet, et si l'aperçu tourne encore tel que décrit par le changelog.

## 3. Objectif

**Une interface unique, jouable, qui montre ce que la box sait faire sans exiger de savoir ce qu'est un module.** Concrètement :

1. **Remplacer l'interface actuelle de `/sbxos/`** après une porte de parité (chaque fonction abandonnée est décidée et motivée),
   avec retour arrière possible sur le Hall classique.
2. **Deux rendus** : Complet (animé, art plein) et Léger (kiosque, TV, clients faibles : pas de canvas ni de WebGL, 256 px).
3. **Honnêteté des données** : un badge par carte (live, vide, démo, refusé, LAN, erreur) ; masquer plutôt que simuler. Sur une
   appliance de sécurité, un faux état est un défaut d'intégrité.
4. **ZIA seul cerveau, Lexie visage et voix** ; seules les actions de classe « média » s'exécutent sans clic ; la garde serveur
   s'applique toujours.
5. **Extensibilité** : un module nouveau apparaît sans modifier l'interface. C'est le même but que la simplification des modules
   (`simplification-modules-beta.md`) : la clé `theme` des `menu.d` (vague 1) servira aussi à regrouper les cartes d'Aurora.

## 4. Prompts pour ChatGPT

Aurora a un canon **raster** produit par ChatGPT à partir des planches existantes (SDK Characters, Icons, UI Components,
1536×1024). Deux prompts : le premier commande de l'art, le second demande une revue de conception.

### 4.1 Commande d'art (à répéter par lot, planche jointe)

```text
Tu es illustrateur d'interface. Je te joins une planche canon (personnages / icônes / composants) de SBX OS, l'interface
d'une box de sécurité et de services personnels. Produis des images DANS LE MÊME STYLE que la planche : mêmes proportions,
même épaisseur de trait, même palette, même éclairage.

Contraintes :
- Palette : fond marine #07111F, panneau #0B2036, cyan #38BDF8, vert #22C55E, violet #A855F7, ambre #F59E0B.
- Sortie : PNG, FOND TRANSPARENT (canal alpha réel, pas de fond marine incrusté), 1024×1024 pour une icône ou un
  personnage, 1536×1024 pour un décor. Un sujet centré, marge de 8 %, rien ne touche le bord.
- Aucun texte, aucun logo, aucune marque existante, aucun visage de personne réelle.
- Raster uniquement : pas de SVG, pas de dessin vectoriel.
- Une image par demande ; nomme-la <id>-<état>.png.

Lot demandé : <LISTE : ex. icônes « pare-feu, DNS, VPN, courrier, photos, radio » ; états idle, alert, success>.
Pour chaque image, réponds par une ligne : id, état, ce que tu as dessiné, et ce qui t'a manqué dans la planche.
Si un point du style n'est pas clair sur la planche, pose UNE question avant de produire.
```

Priorité des commandes (porte d'art avant la bascule) : hero et décor du Hall, Lexie, les 5 icônes du rail, les 4 cartes de
pièce, les icônes des cartes live, les icônes de l'application installable (192, 512, maskable).

### 4.2 Revue de conception (à coller avec la section 1 à 3 de ce document)

```text
Contexte : SBX OS « Aurora » est l'interface d'une box personnelle de sécurité et de services (pare-feu, DNS, courrier, radio,
photos, domotique). Elle présente des « Espaces » (Hall, Atelier, Sécurité, Média, Maison), des cartes vivantes, une palette
Ctrl K branchée sur un assistant (ZIA), une mascotte (Lexie) et 32 personnages. Deux rendus : Complet (navigateur) et Léger
(kiosque, TV, clients faibles). Les utilisateurs : un administrateur et des proches non techniques sur le réseau local.
Contraintes dures : aucune donnée simulée présentée comme réelle ; aucune action sensible sans clic ; accessibilité (contraste
4,5:1, clavier, mouvement réduit) ; 400 px de large au minimum ; thème sombre d'abord ; poids du premier chargement ≤ 1 Mo en Léger.

Travail demandé :
1. Critique l'organisation en cinq Espaces : qu'est-ce qui sera dur à trouver pour un proche non technicien ?
2. Propose le parcours de premier démarrage (≤ 5 écrans) et ce qu'il doit faire choisir, sans jargon.
3. Pour une carte qui n'a pas de source de données, compare « masquer », « grisée avec explication » et « démonstration
   étiquetée » : avantages, risques d'induire en erreur, recommandation.
4. Liste les 10 principaux risques d'usage (confusion entre jeu et sécurité réelle, fatigue des notifications, etc.) et une parade chacun.
5. Propose 3 évolutions qui augmentent l'utilité sans augmenter le poids ni la surface d'attaque.
Réponds en français, par sections numérotées, avec une recommandation nette à la fin de chaque section. Signale ce que tu supposes.
```

## 5. Faisabilité et évolutions (analyse à valider)

### 5.1 Ce qui est faisable à court terme (poids faible, risque faible)

- **Aller jusqu'à la porte d'art puis à la bascule 0.7.0** : l'architecture (trois couches, données, protocole, ZIA) est livrée
  jusqu'à P11. Le facteur limitant n'est pas le code : c'est **l'art** (100 % provisoire) et les arbitrages ouverts (A1 à A22).
- **Carte légère sans React (15 Ko gzip)** : réaliste, car c'est un module TypeScript simple ; à mesurer (P12) avant tout engagement.
- **Regroupement des cartes par thème** grâce à la clé `theme` des `menu.d` : déjà dérivée de `arbre.yaml` (vague 1 de la
  simplification), disponible sans changer les frontends portés.

### 5.2 Faisable avec réserves

| Sujet | Réserve |
|---|---|
| Art par ChatGPT | Cohérence de style d'un lot à l'autre et vrai canal alpha ne sont pas garantis : prévoir un contrôle (alpha exigé pour « définitif », déjà prévu en CI) et une relecture humaine. Licence et provenance à consigner dans `manifest.json`. |
| Temps réel (P14) | SSE recommandé plutôt que WebSocket : HAProxy coupe à 30 s d'inactivité, sbxwaf à 10 s sans en-têtes, un seul worker. Test de plus de 10 minutes obligatoire. |
| Un seul worker uvicorn / agrégateur | Une carte qui sonde trop ou un appel bloquant peut geler le Hall (risque déjà vécu sur la box). Sondage seulement onglet et carte visibles ; budgets en CI. |
| Voix de Lexie | Reconnaissance sur la box (Vosk dans le navigateur écarté : `unsafe-eval`). Dépend de la charge de gk3/gk2 ; l'arbitrage A4 (ouvrir ASR/TTS aux personnes avec limite de débit) est à rendre. |
| Kiosque Léger (P18) | Dépend du matériel (une ESPRESSObin n'a pas de sortie vidéo, A8) et du risque de saturation déjà observé sur gk3 (Chromium en kiosque coûteux). |
| Une seule origine | Aurora doit rester sur `hall.<box>` (clé d'appareil par origine) ; PeerTube y est un cas à part (A19). |

### 5.3 Risques à ne pas sous-estimer

1. **Service worker collant** : seule erreur qu'une rétrogradation apt ne répare pas. Le pont 0.5.2 et le `kill.json` existent ;
   à retester avant chaque bascule.
2. **Aperçu poussé à tout le parc** : garde-fous `~auroraN` (trois filtres + test CI). Ils viennent d'être complétés par
   l'exclusion des builds (2026-10-06).
3. **Jeu et sécurité confondus** : un état « démo » pris pour réel est un défaut d'intégrité ; d'où le badge par carte et
   « masquer plutôt que simuler ».
4. **Vide perçu** : beaucoup de cartes sans backend. SBXOS 1.0 paraîtra plus pauvre que la maquette.
5. **Dérive du protocole** entre l'hôte et l'enfant (deux copies) : test de contrat prévu.
6. **Poids dans git** : ~40 Mo de masters sans LFS (A22) ; à trancher avant d'ajouter l'art.
7. **Calendrier** : le plan visait ~17 semaines ; l'art est un chemin critique indépendant du code.

### 5.4 Évolutions possibles (hors plan actuel, à instruire)

- **Hall composé par les manifestes** : le manifeste de composant de la simplification fournirait Espace, thème, icône et
  capacités ; Aurora n'aurait plus de liste curée à tenir (`curation.json` généré, test de dérive).
- **Profils** : afficher « installé / recommandé / non installé » selon lite, isp, full, et proposer l'activation par
  `profilectl apply` (dry-run d'abord) plutôt qu'un réglage à la main.
- **Aide et recherche globale** : une recherche unique (services, cartes, objets ZIA), un résultat par source.
- **Audio** (après la 1.0) : sons d'interface optionnels, désactivés en Léger et par défaut sur kiosque.
- **Thème clair** (A7) : demande des jetons clairs et de masters alpha ; coût d'art, pas de code.
- **Convergence avec `secubox-sbxui`** (A18) : à acter pour éviter deux bibliothèques d'interface.

## 6. Décisions que seul le propriétaire peut prendre

1. Garder l'ordre « art d'abord, puis bascule 0.7.0 », ou basculer avec l'art provisoire ?
2. Arbitrages bloquants les plus proches : A7 (thème), A8/A9 (kiosque), A22 (art dans git), A4 (voix pour les personnes).
3. Qui produit l'art (ChatGPT sous contrôle, illustrateur) et qui valide le style ?
4. Le calendrier de 17 semaines tient-il toujours, ou Aurora est-elle suspendue derrière la simplification des modules ?
