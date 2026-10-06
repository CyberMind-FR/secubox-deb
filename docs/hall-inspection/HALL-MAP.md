<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# HALL-MAP — cartographie fonctionnelle du Hall (visiteur invité)

Hall : https://hall.gk2.secubox.in/ · inspecté le 2026-10-02 · navigateur : **Chromium headless 145** (Playwright, locale fr-FR, 1440×900), JavaScript exécuté, **aucune écriture** (toute requête POST/PUT/DELETE est bloquée avant d'atteindre le serveur : rien n'a été modifié).

## Méthode et conditions de test
Tout ce qui suit vient de ce que le navigateur a chargé et affiché. Rien n'est tiré du code source ni de la documentation.

| Condition | Définition | Pourquoi |
|---|---|---|
| **A — LAN** | Chromium lancé depuis cette machine ; la box le voit comme un client du réseau local (retour par la passerelle). | C'est ce que la demande décrit (« depuis la machine »). Inclut des contenus réservés au LAN. |
| **B — externe simulé** | Même Chromium, avec `X-Forwarded-For: 203.0.113.50` (adresse de documentation, non routable) : nginx et sbxwaf la lisent comme l'adresse du client. | Montre ce que voit un visiteur de l'Internet. |
| **C — contrôle externe réel** | Un navigateur indépendant (Chrome 154 de Jina, IP Google Cloud 34.34.225.81) a rendu l'accueil : 37 requêtes, toutes en 200 sauf deux API privées en 401. | Confirme qu'un vrai client externe obtient la page et ses ressources. |

Étiquettes : `[TESTÉ DANS CHROMIUM]` · `[AFFICHE MAIS NON FONCTIONNEL]` · `[EXISTE MAIS NON ACCESSIBLE INVITÉ]`.

## 1. Entrée
- Une **fenêtre de bienvenue** (« Le Hall vous accueille ») couvre l'écran à la première visite ; un seul bouton, « Entrer dans le Hall → ». Elle explique quatre gestes (ranger, épingler, voir & écouter, surfer) et la barre d'adresse « navigateur souverain ». `[TESTÉ DANS CHROMIUM]`
- Le texte de la page existe dans le HTML derrière la fenêtre ; un lecteur qui n'exécute pas le JavaScript voit surtout la structure et quelques cartes (« Cloud — nc.gk2.secubox.in — inconnu »), pas le contenu vivant.
- Statut de session affiché en permanence : **« Invité — ○ Non connecté »**. Aucun cookie n'est posé.

## 2. Ossature de l'écran
```
┌ barre du haut ────────────────────────────────────────────────────────────┐
│ SbX (halo, pastille Diffusions) · Services ▾ · [recherche / surf] · 📻 🔊 📡 ◐ · Invité · Lexie │
├ mosaïque de cartes vivantes (4 colonnes) ─────────────────────────────────┤
│  Radio / MetaNews / Podcaster / PeerTube / Contenu / Forums …            │
├ barre « Volume général » + lecteurs flottants (radio, viewer) ───────────┤
└ fil d'Ariane · nœud · 81 en ligne · 113 modules · devise ─────────────────┘
```
- Pied d'écran : « nœud **secubox-mochabin** · ◆ **81** en ligne · ● **113** modules · hall.gk2.secubox.in — mon bureau numérique souverain : mes services et mes données, hébergés chez moi sur ma SecuBox, sous mon contrôle. » `[TESTÉ DANS CHROMIUM]`
- Animations vues : halo du logo, pulsation de la pastille et des boutons flottants, cycle des médaillons, pistes qui avancent ; les cartes se rafraîchissent seules.
- Thème papier/nuit ◐, ordre des cartes à la main (poignée ⠿), favoris ★ : tous gardés dans le navigateur. `[TESTÉ DANS CHROMIUM]`
- Mobile (390×844) : une colonne, menu en panneau latéral, même contenu. `[TESTÉ DANS CHROMIUM]`

## 3. Barre du haut
| Contrôle | Ce qu'il fait pour un invité | Étiquette |
|---|---|---|
| Logo SbX + pastille « 1 » | Diffusions du parc : un flux proposé (« Wyclef Jean - 911 »), rejoignable | `[TESTÉ DANS CHROMIUM]` |
| **Services ▾** | 31 services (point d'état, ⚙️ console, ⧉ nouvel onglet) + « Tableau d'accueil » + « Tout le parc… » | `[TESTÉ DANS CHROMIUM]` |
| **Recherche / surf** | Texte → filtre la vue « Système » ; adresse → Surf relayé par la box (pisteurs coupés) | `[TESTÉ DANS CHROMIUM]` |
| 📻 🔊 📡 | Agrandir la radio, ouvrir le lecteur, rejoindre la diffusion en direct | `[TESTÉ DANS CHROMIUM]` |
| ◐ | Bascule papier/nuit | `[TESTÉ DANS CHROMIUM]` |
| **Invité** (profil) | Demander un accès, Connexion SecuBox, réinitialiser l'affichage, revoir l'accueil, aide du Hall | `[TESTÉ DANS CHROMIUM]` |
| **Lexie** | Commande vocale locale : « Service vocal injoignable (HTTP 401) » | `[AFFICHE MAIS NON FONCTIONNEL]` |

## 4. La mosaïque : cartes et ce qu'elles montrent à l'invité
Les cartes sont des cadres de même origine que le Hall, qui se mettent à jour seuls. Chaque carte a ★ (favori) et ? (aide). 25 cartes existent ; l'invité en voit **17 depuis le LAN** et **16 depuis l'extérieur**.

| Carte | Contenu visible par l'invité | LAN | EXT | Étiquette |
|---|---|---|---|---|
| **Radio** | piste en cours (2TH — 7ème Ciel), ⏮ ❚❚ ⏭, volume, auditeurs, antenne (chat), playlist en rotation | ✔ | ✔ | `[TESTÉ DANS CHROMIUM]` |
| **MetaNews** | actualité par sujets (60 sujets), « À LA UNE », sources, tags | ✔ | ✔ | `[TESTÉ DANS CHROMIUM]` |
| **Podcaster** | épisodes du « Bureau des Complots », lecteur audio, téléchargement | ✔ | ✔ | `[TESTÉ DANS CHROMIUM]` |
| **PeerTube** | vidéo à la une (156 vidéos), bande des suivantes ; au repos « PeerTube en veille » | ✔ | ✔ | `[TESTÉ DANS CHROMIUM]` |
| **Contenu** (YTSaS + Dépôt) | 180 vidéos rapatriées, 430 Go libres, champ « URL de la vidéo / Capturer » ; Dépôt vide | ✔ | ✔ | `[TESTÉ DANS CHROMIUM]` |
| **Forums** (BBS + Billets) | fils en rotation, 8 fils, 238 billets publiés | ✔ | ✔ | `[TESTÉ DANS CHROMIUM]` |
| **Activité** | 19 gestes récents, tous « public » | ✔ | ✔ | `[TESTÉ DANS CHROMIUM]` |
| **Lyrion** | télécommande Squeezebox, « Disorder — Joy Division », pas de platine | ✔ | cachée | `[AFFICHE MAIS NON FONCTIONNEL]` (les appels JSON-RPC échouent) |
| **Freebox TV** | grille de 177 chaînes | ✔ | « Aucune chaîne. » | `[TESTÉ DANS CHROMIUM]` LAN · `[EXISTE MAIS NON ACCESSIBLE INVITÉ]` externe |
| **SBX OS** | « Votre Hall — GUEST », pastilles Radio, PeerTube, MetaNews, Billets, dock Hall/Favoris/Réglages | ✔ | ✔ | `[TESTÉ DANS CHROMIUM]` |
| **Mood** | humeur de la pièce par la voix : « en veille », « Indéterminé — personne n'est écouté » | ✔ | ✔ | `[AFFICHE MAIS NON FONCTIONNEL]` (micro non accordé) |
| **Messagerie** | mur public de 80 messages, onglet « Privés », écriture avec pseudo | ✔ | ✔ | `[TESTÉ DANS CHROMIUM]` |
| **DevWatch** | pouls du dépôt GitHub : 5 858 commits, 5 contributeurs, 11 releases, 238 issues | ✔ | API 401 | `[TESTÉ DANS CHROMIUM]` LAN |
| **ZIA** | assistante locale : message d'accueil, suggestions, micro, « 100 % local » | ✔ | ✔ | `[TESTÉ DANS CHROMIUM]` (question non posée) |
| **Accès** | formulaire « Demander un accès » avec appareil détecté | ✔ | ✔ | `[TESTÉ DANS CHROMIUM]` |
| **Surf & Viewer** | champ « coller un lien à voir / surfer », favoris (vide) | ✔ | ✔ | `[TESTÉ DANS CHROMIUM]` |
| **Cloud** (Nextcloud) | tuile « Cloud — nc.gk2.secubox.in — inconnu », bouton « Ouvrir » vers `/sbx/entrer` | ✔ | ✔ | `[EXISTE MAIS NON ACCESSIBLE INVITÉ]` (mène au formulaire de connexion) |
| Sécurité · Renseignement · Coffre · Mon coffre · Mes comptes · DPI · Zigbee · Mes sites | **cachées** pour l'invité (le Hall les charge puis abandonne leur cadre) | cachées | cachées | `[EXISTE MAIS NON ACCESSIBLE INVITÉ]` |

## 5. Menu Services et vue « Tout le parc »
- **31 services** dans le menu : Accès, Activité, BBS, Billets, Cloud, Coffre, Dépôt, DevWatch, DPI · Trafic, Freebox TV, Lyrion, Mail, Mes comptes, Mes sites, Messagerie, MetaNews, Mon coffre, Mood, PeerTube, Photos, Podcaster, Radio, Renseignement, SBX OS, Sécurité, SocialRelay, Surf & Viewer, Torrent, YTSaS, ZIA, Zigbee. Chacun a été ouvert : voir HALL-SCREENS.md §5.
- **113 modules** dans « Tout le parc » : 🛡️ Muraille 19, 🧠 Esprit 20, 🕸️ Maillage 46, 🔑 Accès 6, ⚙️ Racine 15, ⚡ Amorce 7 ; 31 sont grisés (hors ligne). `[TESTÉ DANS CHROMIUM]`

## 6. Surf (navigateur souverain)
Taper `example.com` dans la barre ouvre `cardlets/surf.html`, qui charge la page via un sous-domaine dédié `surf-example-com.gk2.secubox.in` ; bandeau « example.com — relayé, pisteurs coupés ». La page distante s'affiche (ici dans sa version arabe). `[TESTÉ DANS CHROMIUM]`
Constat annexe : depuis « Mes sites », un lien vers un site de la box est refusé par ce relais (« Cette adresse mène à la box ou à son réseau local ») ; corrigé par un lien direct le 2026-10-02.

## 7. Accès et identité d'un invité
| Parcours | Résultat | Étiquette |
|---|---|---|
| « Demander un accès… » | écran Accès `/i/acces/` : nom, adresse facultative, appareil, mot ; envoi non fait | `[TESTÉ DANS CHROMIUM]` |
| « Connexion SecuBox… » | fenêtre `admin.gk2.secubox.in/login.html` (« SecuBox — Login ») | `[TESTÉ DANS CHROMIUM]` |
| Nextcloud, Mail, PeerTube (compte) | redirigés vers leur formulaire de connexion | `[EXISTE MAIS NON ACCESSIBLE INVITÉ]` |
| Coffre, Mon coffre, Mes comptes, Sécurité, Renseignement | textes affichés, données refusées (401) | `[EXISTE MAIS NON ACCESSIBLE INVITÉ]` |

## 8. Fonctionnalités par condition
| Fonctionnalité | A — LAN | B — externe | Étiquette |
|---|---|---|---|
| Page d'accueil, assets, mosaïque | ✔ | ✔ | `[TESTÉ DANS CHROMIUM]` |
| Radio / Podcaster / MetaNews / BBS / Billets / Messagerie lecture | ✔ | ✔ | `[TESTÉ DANS CHROMIUM]` |
| Diffusion en direct, viewer, favoris, thème | ✔ | ✔ | `[TESTÉ DANS CHROMIUM]` |
| Surf relayé | ✔ | non rejoué | `[TESTÉ DANS CHROMIUM]` (LAN) |
| DPI, Freebox TV, Zigbee, Lyrion, DevWatch, profils de cycle de vie | ✔ | 401/403 | `[EXISTE MAIS NON ACCESSIBLE INVITÉ]` externe |
| Lexie (voix) | 401 | 401 | `[AFFICHE MAIS NON FONCTIONNEL]` |
| PhotoPrism | 504 | — | `[AFFICHE MAIS NON FONCTIONNEL]` |
| Torrent | 401 | 401 | `[EXISTE MAIS NON ACCESSIBLE INVITÉ]` |
| Mes comptes, Mon coffre, Coffre | 401 | 401 | `[EXISTE MAIS NON ACCESSIBLE INVITÉ]` |
