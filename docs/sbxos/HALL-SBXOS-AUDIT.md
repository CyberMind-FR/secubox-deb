<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# SBXOS Hall — audit, design system, plan d'intégration

*État au 2026-09-29 (#1676). Réponse aux phases A, B et C du prompt « SBXOS Hall — implementation prompt ». Règle : on étend l'existant, on ne construit pas une seconde architecture.*

Le Hall réel porte déjà l'essentiel de ce que le prompt demande, sous d'autres noms. Ce document fait le relevé, nomme les écarts et ordonne le travail restant.

---

## A. Architecture existante

| Axe | Réalité dans le dépôt |
|---|---|
| **Framework** | Aucun. JavaScript natif, sans étape de construction. `packages/secubox-webos/www/hall/index.html` fait 5 545 lignes : 1 bloc de style et 2 scripts en ligne. Scripts partagés à côté : `domaine.js`, `aide.js`, `slicebar.js`, `lexie.js`, `sonde.js`. |
| **Point d'entrée** | Vhost nginx `hall.<domaine>` (`nginx/hall.vhost.conf`) : `/` sert `index.html`, `/cardlets/*.html` sert les cartes en cadre, `/api/v1/*` passe par une liste de relais vérifiée en CI (`scripts/verifie-relais-hall.py`). Le kiosque passe par `hall.localhost:9080` (#1668). |
| **Routage** | Vues internes (`showView('accueil'\|'embed'\|'systeme'\|'aide')`) et service embarqué (`data-nav`). Pas de routeur d'URL. |
| **État** | Variables de module et `localStorage` par profil (`cleProfil()`) : favoris, ordre des cartes, thème, historique du viewer. Rien côté serveur pour la disposition. |
| **Composants** | Carte du Hall = `fcard`, en trois variantes : vivante (`iframe` de `/cardlets/*.html` ou `micro` du service), aperçu, et compacte (`compactHTML`). Cardlets en cadre : 16 dans `www/hall/cardlets/` et les pages `micro` des services (radio, BBS, MetaNews, podcaster, billets, mood, ZIA, accès). Objets partagés : `SBXSliceBar` (tranches), `SBXAide` (aide reverse-design) et `SBX_DOMAINE` (hôtes). |
| **Styles** | 10 jetons sur `:root` dans le Hall (`--ink --paper --panel --line --cyan --mint --amber --coral --violet --sky …`), redéfinis en sombre. Skin des cartes : `spicy.css` et `slicebar.css` (dupliqués dans `secubox-sbxui`). Aurora a ses propres jetons (`sbx-sdk/tokens/tokens.css`, `--sbx-*`). Il y a donc deux jeux de jetons. |
| **API** | Toutes réelles, aucune maquette. webos publie `/public/services`, `/public/aide/cartes[/{id}]`, `/public/aide/trouver`, `/public/hotes.js`, `/public/broadcast(s)`, `/public/cardlets/{radio,waf,podcaster}`, `/public/actions/{module}/{action}`, `/public/menu/bbs`, `/public/sbxos/manifeste`. Chaque module sert en plus sa propre API (`/api/v1/<module>/…`). |
| **Temps réel** | Pas d'EventSource ni de WebSocket dans le Hall. Il interroge le serveur à intervalles (8 `setInterval`) et chaque carte en cadre a son propre rythme. Le SSE décidé en P5 n'est pas branché sur le Hall. |
| **Auth** | Session SecuBox (cookie `secubox_session` du domaine de la box), vérifiée par `/api/v1/auth/auth/verify`. Entrée sans mot de passe par appareil admis (`/acces`, #1562). `require_personne`, `require_session` et `require_jwt` (vrais admins, #1581) côté serveur. Un appareil n'est jamais admin. |
| **Modules** | Registre `/public/services`, fusion de `menu.d` et de la santé (112 modules sur gk2). Cartes mises en avant : tableau `FEATURED` (33 entrées) dans `index.html`. Aide de chaque carte : `api/aide_cartes.json` (#1664). |
| **ZIA** | Déjà dans le Hall : carte `/zia/micro.html`, page pleine, Ctrl K. Couche d'actions en place : ZIA propose une action (`media.volume`…), `api/capabilities.py` la valide contre les manifestes `capabilities.d/*.json` (hall, radio, podcaster, voice), et le Hall l'exécute par `sbxExecuteAction` (message `{sbx:'cmd'}` à la carte). ZIA décrit aussi les cartes (#1664). |
| **Voix** | Lexie : `secubox-voice` (synthèse piper locale, reconnaissance Vosk pour les commandes, VoiceStudio sur gk3 sinon whisper). `voix.js` côté ZIA. |
| **Aurora** | `secubox-sbxos`, React/Vite, `/sbxos/`. SDK `sbx-sdk` (jetons, icônes raster, protocole hôte/enfant, voix, FluxHall). Décision du 2026-09-28 : « le Hall reste tel quel, SBXOS est la nouvelle interface à côté ». |

## B. Cartographie : prompt → existant

| Brique du prompt | Existe sous le nom | Écart |
|---|---|---|
| HallShell / TopBar | `header` du Hall : logo SbX, Services, Système, recherche/surf, radio, diffusion, thème, profil, Lexie | La recherche ne couvre que services et surf ; pas de sources multiples. |
| HallStatusBar | `footer.statusbar` : fil d'Ariane, nœud, en ligne, modules, hôte | — |
| HallNavigation (mobile) | Aurora `carte.ts` : Hall / Favoris / Réglages | Le Hall lui-même n'a pas de barre basse mobile. |
| Cardlet | `fcard` + page de carte + `FEATURED` | Pas de modèle unique : taille (`h:`), accès (`auth`, `lan`) et contenu sont éparpillés entre `FEATURED`, `aide_cartes.json` et `menu.d`. |
| États de carte | favori ★, `cl-phare` (sélection d'aide), « en veille », hors ligne, DIRECT/LIVE | Pas de jeu d'états nommé et commun. |
| CardHelp générique | Bulle ❓ unique : source `aide_cartes.json`, chiffres vivants, zones colorées, clic/survol/visite (#1664, #1674) | **Fait.** Reste : actions de la carte dans la bulle. |
| Layout engine | Grille CSS + ordre glisser-déposer + favoris en tête, persistés en `localStorage` | Pas de tailles nommées (S/M/L/W/T/F), pas de redimensionnement, disposition non portable d'un appareil à l'autre. |
| ModuleRegistry | `FEATURED` + `/public/services` + `aide_cartes.json` + `capabilities.d` | Quatre sources à fusionner en une déclaration par module. |
| ActionRegistry | `capabilities.d/*.json` + `capabilities.py` (liste blanche, types, bornes, rôle minimal) + `sbxExecuteAction` | **Existe.** Manque : actions `card.*`, `hall.*`, `*.latest`, et la confirmation des actions sensibles côté UI. |
| ZIA Intent / Resolver | `runtime.respond` : commandes, recherche dans le bus, délégation, aide de carte | Types non formalisés (ZIAIntent/ZIAResult) ; pas de contexte « état du Hall ». |
| VoiceProvider | `voix.js` (ZIA), `lexie.js` (Hall), API `secubox-voice` | Deux clients ; pas d'interface unique `listen / stop / transcribe / speak`. |
| RealtimeProvider | Minuteurs par carte | À créer : un seul abonnement par source, partagé. |
| Design tokens | Jetons du Hall + `spicy.css` + `--sbx-*` d'Aurora | Trois jeux à réconcilier. |

## C. Design system déduit des captures

Les 14 captures montrent un seul système. Ce qui suit est la grammaire commune, pas le pixel d'une capture.

**Ton.** Console système sombre et dense. Fond bleu nuit presque noir, panneaux à peine plus clairs, une ligne fine pour délimiter. Pas de dégradé de marque ni de verre dépoli.

**Couleurs (rôles).**

| Rôle | Usage vu dans les captures |
|---|---|
| fond / panneau / relief | page, carte, champ ou tuile interne |
| trait | bordure 1 px des cartes et champs |
| cyan (action) | liens, onglet actif, anneau de sélection, bouton primaire « Suivant », ❓ |
| violet (accent) | lecteur radio (lecture, curseur), ZIA, chiffres ACTEURS |
| vert (OK / vivant) | puce de tranche active, DIRECT, « en ligne », « ouvert d'office » |
| ambre / orange | « Demander un accès », avertissements Zigbee, filet de titre |
| rouge (alerte) | LIVE, RISQUES, bannis, badge de diffusion |
| encre / doux / pâle | texte, secondaire, métadonnées mono |

**Géométrie de la carte.** Rayon ~16 px, bordure 1 px. Padding 12–14 px, en-tête ~40 px. Pied de 28 px avec puces de tranches et pastille d'hôte. Un **filet dégradé** de 2 px sous le titre (couleur du service). Ne s'allument que le focus, l'aide ouverte (anneau cyan double) et les états vivants.

**Anatomie d'une carte.** Pas de cartes géantes : chaque zone est une information réelle.
1. Titre : icône raster, nom, compteur mono à droite (« 60 SUJETS », « 8 FILS », « 54 ITEMS ») ou pastille d'état (DIRECT, LIVE, SHADOW · OBSERVE, en veille).
2. Rangée de chiffres optionnelle : nombre en grand et en couleur, libellé en petites capitales.
3. Corps : liste dense, média à la une ou tuiles.
4. Pied : puces de tranches, dont une puce verte allongée pour l'active, libellé de tranche en capitales, pastille d'hôte (`bbs.gk2.secubox.in`).

**Typographie.** Sans serif compacte pour le contenu (13–15 px). Mono pour hôtes, compteurs et barre d'état. Petites capitales espacées (0,1 em) pour les libellés de section (« EN ROTATION », « AIDE DE CARTE »). Chiffres tabulaires.

**Trois niveaux d'objet, à ne jamais confondre.**
1. **Cardlet** : l'aperçu vivant dans la grille.
2. **Vue détaillée** : le service embarqué dans le Hall, à sa vraie adresse.
3. **Aide de carte** : bulle flottante à côté de la carte, jamais par-dessus. Elle contient :
   - le titre à serif ;
   - « AIDE DE CARTE » en mono ;
   - la description ;
   - des tuiles de chiffres ;
   - une liste à chevrons (accès, gestes, favori) ;
   - la navigation (compteur, Passer, Suivant/Terminer).

   La carte visée porte un anneau cyan double, et ses zones sont annotées en couleur.

**Barres.**
- Barre haute sur une ligne : logo SbX, menus Services et Système, recherche mono « chercher un service, ou surfer une adresse… ». À droite : radio, diffusion, thème, pastille profil (avatar, nom, « Connecté » en vert), bouton Lexie.
- Barre d'état basse en mono : fil d'Ariane à gauche, « nœud gk2 · 87 en ligne · 112 modules » au centre, hôte et devise à droite.

**ZIA dans le Hall.** C'est une carte comme les autres, pas une page à part.
- En-tête : 🦊, badge « GGUF local », pastille MODÈLE.
- Corps : bulle d'accueil, puces de suggestion (« la dernière vidéo sur le WAF »…), champ « demande à ZIA… », boutons micro, haut-parleur et envoyer.
- Mention en pied : « 100 % local · le bus reste la source de vérité ».

**Mobile (« Votre Hall »).**
- Tuiles carrées sur 4 colonnes : icône raster, libellé, étoile de favori en coin.
- Barre basse Hall / Favoris / Réglages.
- Rien ne dépend du survol.

**Mouvement.** Durées courtes. Rien de permanent, sauf la puce de tranche qui avance et le pouls d'un état vivant. `prefers-reduced-motion` respecté.

## D. Décision et plan d'intégration

**Décision de Gandalf (2026-09-29) : Aurora devient SBXOS.**
- Le Hall classique reste figé : maintenance et correctifs seulement, et retour arrière à la bascule.
- Les cartes, la disposition, l'aide de carte, ZIA en couche et le mobile se construisent dans Aurora (`packages/secubox-sbxos`, React/Vite, `sbx-sdk`), sur les API réelles déjà servies.
- Ce que le Hall a gagné devient des couches partagées qu'Aurora consomme : la source d'aide, les chiffres vivants, la reconnaissance de carte pour ZIA, `capabilities.d`, la voix.
- Les phases ci-dessous s'insèrent dans le plan `MIGRATION-AURORA.md` (P13 à P18).

| # | Phase | Où | Fait en étendant | Livrable vérifiable |
|---|---|---|---|---|
| 1 | **Jetons SBXOS** | `sbx-sdk/tokens` | `tokens.css` reçoit les rôles déduits en C (panneau, relief, trait, filet, états, petites capitales, durées) ; le Hall garde les siens | Tests de contraste vitest étendus aux nouveaux rôles |
| 2 | **Déclaration de module unique** | webos + SDK | `aide_cartes.json` devient `modules/*.json` : id, titre, icône, catégorie, taille, accès, capacités, métriques, aide. Servi par `/public/sbxos/manifeste` (P6), lu par Aurora ; `FEATURED` du Hall en reste une vue | Test : aucune carte sans déclaration ; manifeste et aide cohérents |
| 3 | **`<Cardlet>`** | `sbx-sdk/ui` | Anatomie de C : titre et compteur, chiffres, corps, pied à tranches et pastille d'hôte. États nommés `default / hover / focus / selected / live / sleeping / offline / locked / favorite / loading / error` | Vitrine (`npm run vitrine`) + axe + contraste pour chaque état |
| 4 | **Layout engine** | `sbx-sdk/ui` | Tailles S/M/L/W/T/F, grille dense, ordre, masquage et favoris. Disposition persistée par personne (sbxid), `localStorage` en repli | Même disposition sur deux appareils ; test de réordonnancement |
| 5 | **`<CardHelp>`** | `sbx-sdk/ui` | Une seule bulle générique (description, chiffres, liste, actions, Passer/Suivant) sur `/public/aide/cartes/{id}` ; zones colorées par le protocole `aide` existant (`aide.js`) | Visite et clic testés ; aucune fenêtre propre à un module |
| 6 | **Registre d'actions** | zia + SDK | `capabilities.d` étendu (`card.*`, `hall.*`, `*.latest`) ; `sbxExecuteAction` côté hôte (`protocol/hote.ts`, P9) ; confirmation dans l'UI pour tout effet `ecriture` ou `physique` | Tests `capabilities.py` + contrat hôte/enfant vitest |
| 7 | **ZIA couche** | Aurora + zia | Panneau compact (Ctrl K, P11) ; contexte envoyé = cartes visibles, sélection, rôle ; types `ZIAIntent/ZIAResult` explicites dans `runtime` | « montre les dernières vidéos » met la carte PeerTube au premier plan |
| 8 | **VoiceProvider** | `sbx-sdk/voix` | `listen / stop / transcribe / speak` sur l'API `secubox-voice` (piper, Vosk, VoiceStudio) | Même micro dans Aurora et la carte ZIA |
| 9 | **Temps réel** | webos + SDK | Flux SSE serveur de P14 (`/api/v1/webos/flux/stream`) ; `LiveChannel` s'abonne par source ; aucun sondage global | Requêtes mesurées sur gk2 avant et après |
| 10 | **Mobile** | Aurora | Grammaire « Votre Hall » (`carte.ts`) : tuiles, barre Hall/Favoris/Réglages, rien au survol | Rendu 400 px + axe |
| 11 | **Recherche globale** | Aurora | Services, cartes (`/aide/trouver`), objets du bus ZIA, surf | Un résultat par source, origine affichée |
| 12 | **Tests et bascule** | tout | Parcours Playwright : ouvrir, sélectionner, aide, favori, recherche, action ZIA, action média, temps réel, changement de session, mobile ; puis bascule 0.7.0 (P13) avec la matrice de parité | Build CI + parcours verts sur gk2 |

**Invariants.**
- Pas de seconde architecture : Aurora est déjà l'application SBXOS construite, et le Hall classique n'est pas réécrit.
- Pas de maquette de données.
- Les permissions restent décidées côté serveur (`require_*`, `capabilities.py`, liste des relais) : un bouton affiché n'accorde jamais un droit.
- Art : planches raster uniquement, jamais de SVG dessiné.
