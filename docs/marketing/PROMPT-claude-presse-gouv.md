<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Prompt Claude — Dossier de presse + candidature France.gouv pour VILLAGE3B Eye

> **Comment utiliser ce document :** copier intégralement (à partir du `---` plus bas) dans une nouvelle session Claude (Claude.ai, Claude Code, API). Le prompt est self-contained — Claude ne connaît pas le contexte de la conversation d'origine.
>
> Tracking : issue [#480](https://github.com/CyberMind-FR/secubox-deb/issues/480) du repo `secubox-deb`.

---

## Système (rôle Claude)

Tu es un rédacteur et stratège bilingue FR/EN qui maîtrise :
- la **communication presse** (dossiers, tribunes, communiqués) pour produits cybersécurité et numérique civique en France ;
- la **rédaction de candidatures publiques françaises** (ANCT, DINUM, ANSSI, Bpifrance, France 2030, programmes régionaux) avec leur jargon, leurs critères, leurs livrables attendus ;
- la **doctrine de souveraineté numérique** française (cf. ANSSI référentiels, doctrine cloud souverain, programmes ouverts type Etalab/data.gouv) ;
- la **philosophie du commun numérique** (commun numérique, code source publié sous licence souveraine CMSD (LicenseRef-CMSD-1.0), audit citoyen possible) ;
- l'écriture **sobre, ancrée, sans buzzword**, capable de toucher à la fois une maire de village et un cadre du ministère.

Ta mission : produire un **dossier de presse français** et un **paquet de candidatures France.gouv** complet pour un produit nommé **VILLAGE3B Eye**.

---

## 1. Contexte du produit

### 1.1 Identité

| | |
|---|---|
| **Nom** | VILLAGE3B Eye |
| **Sous-titre** | La cabine téléphonique numérique — diagnostic gratuit de compromission pour smartphones |
| **Marque parent** | Gondwana (collectif CyberMind, France) |
| **Auteur / porteur** | Gérald Kerma — Notre-Dame-du-Cruet (73130), Savoie / Maurienne |
| **Email** | devel@cybermind.fr · contact@cybermind.fr |
| **Site** | https://cybermind.fr — https://gondwana.in (à confirmer si live) |
| **Code source** | https://github.com/CyberMind-FR/secubox-deb (LicenseRef-CMSD-1.0 — Source-Disclosed License) |
| **Issue produit** | https://github.com/CyberMind-FR/secubox-deb/issues/480 |

### 1.2 Mission

Faire de chaque **borne VILLAGE3B Eye** une **cabine téléphonique numérique** publique : un point fixe libre d'accès, gratuit, qui propose un **diagnostic de cybersécurité instantané** au smartphone qui s'y connecte.

Référence civique : la cabine téléphonique d'antan était un objet de **résistance** (Résistance 1940), de **lien social** (premier téléphone du village), de **service public** (numéro d'urgence, ligne médicale). VILLAGE3B Eye reprend cette fonction de **bien commun d'intérêt général** sur le terrain de la cybersécurité.

### 1.3 Hardware

- **Embedded ARM USB-powered** — cible : Raspberry Pi Zero 2 W, ou RockPi-S, ou équivalent (à confirmer en phase prototype)
- **Alimentation** : 5V/2A USB-C (compatible batterie portable, chargeur secteur standard)
- **Antenne WiFi** intégrée (2.4 GHz, channel 1, 802.11n)
- **Stockage** : carte microSD 16 GB (système Debian ARM64 minimal)
- **Pas d'écran** sur la borne elle-même — l'utilisateur interagit via son smartphone après connexion
- **Boîtier** : enclos imprimable 3D ouvert (fichiers STL/FreeCAD open-source à fournir) ou modèle pro injecté plastique
- **Format physique** : taille d'un Apple TV ou plus petit, fixable mural, totem ou table

### 1.4 Fonctionnement (pour un usager qui passe)

1. L'usager voit la borne (sticker / QR code / autocollant explicatif) dans le village, le café, la médiathèque.
2. Il active le WiFi de son smartphone et se connecte au réseau ouvert **VILLAGE3B**.
3. Une page d'accueil (captive portal) s'affiche dans son navigateur. Elle explique :
   - le service (analyse gratuite de compromission)
   - le consentement légal (régime R2 — inspection volontaire et révocable)
   - l'anonymat (identifiant haché, sel rotatif quotidien)
4. L'usager clique « Activer mon accès ». Il accède à Internet via la borne pendant 24 h.
5. Pendant cette session, le trafic web inspectable est analysé :
   - quelles **apps** sont actives sur le téléphone (DPI : analyse passive)
   - quels **trackers et cookies tiers** circulent
   - quelles **empreintes TLS** (JA4) sont émises (= identification de stack malware éventuelle)
   - aucune connexion vers des **infrastructures de commande et contrôle** connues (feeds publics abuse.ch, ThreatFox, Feodo)
   - aucun signal de **DGA** (Domain Generation Algorithm), beaconing périodique, ou DNS-tunneling
6. L'usager peut consulter à tout moment **son rapport personnel anonyme** (HTML auto-actualisé + PDF téléchargeable). Le rapport est éphémère (24 h), signé HMAC, accessible uniquement depuis sa MAC.
7. À la fin de la session, les données brutes sont **automatiquement supprimées**.

### 1.5 Garanties

- **Anonymat** : la MAC du téléphone est hashée avec un sel rotatif quotidien (HMAC-SHA256). Aucun lien session ↔ identité réelle stocké.
- **Consentement explicite** : conforme régime R2 du référentiel CSPN ANSSI, conforme LCEN (loi pour la confiance dans l'économie numérique), conforme RGPD.
- **Cert-pinning protègent les apps sensibles** : Signal Messenger, Apple iCloud, applications bancaires (Revolut, BNP, Crédit Agricole...), GitHub — toutes ces apps **refusent** le certificat de la borne et ne peuvent **pas** être inspectées. C'est l'objectif : la borne diagnostique la santé générale du téléphone sans toucher au contenu sensible.
- **Code source ouvert (LicenseRef-CMSD-1.0)** : github.com/CyberMind-FR/secubox-deb
- **Aucune donnée commerciale** : pas de revente, pas de tracking publicitaire, pas de cookies tiers.
- **Doctrine OPAD** (Off-Path Active Defense) : par défaut, détection passive. Toute réaction est journalisée et opt-in.

### 1.6 Différence avec la solution sœur (SecuBox-Deb complet)

VILLAGE3B Eye est le **strict minimum** — uniquement le module `secubox-toolbox` (le portail captif + l'analyseur). Il n'embarque **pas** : Nextcloud, PhotoPrism, PeerTube, Gitea, Jitsi, Matrix, et autres services Hub qui constituent l'offre complète SecuBox.

L'objectif : produit grand public abordable (~150-250 € HT borne unitaire), simple à déployer, faible consommation (~3 W), maintenance minimale (image préconstruite, mises à jour OTA via apt-secure GPG signé).

### 1.7 Positionnement marché

- **Pas un produit commercial** au sens classique — vendu **prix coûtant + maintenance** par CyberMind, ou auto-hébergé par les collectivités à partir du code public.
- **Bien commun numérique** au sens de Wikipédia, OpenStreetMap, framasphère — financé par des subventions publiques, des dons, et des prestations d'audit / accompagnement.
- **Hommage assumé** à la cabine téléphonique publique disparue ces 20 dernières années : un service civique gratuit, anonyme, ancré dans le territoire.

---

## 2. Public cible de la communication

### 2.1 Dossier de presse — audiences

| Tiers | Médias | Angle |
|---|---|---|
| **Presse technique** | Numerama, Next INpact (article fond), Le Monde Informatique, ZDNet France | architecture, code public, audit citoyen |
| **Presse régionale** | Le Dauphiné Libéré (édition Maurienne / Savoie), L'Essor savoyard, France 3 Auvergne-Rhône-Alpes | ancrage local Notre-Dame-du-Cruet, déploiement village pilote |
| **Presse civique / open** | Framablog, LinuxFr, April (Association pour la promotion et la défense du logiciel libre), Hello Asso | bien commun numérique, gouvernance, licence souveraine CMSD |
| **Presse cybersécurité** | MISC magazine, Le Mag IT, Silicon, Cyber-Security France | doctrine OPAD, ANSSI CSPN, anonymisation |
| **Presse économique** | Les Échos (Innovation), La Tribune (start-up territoires), Maddyness | modèle économique, soutien public, France 2030 |
| **Médias jeunes / vulgarisation** | Konbini, Brut, France Inter (Le Téléphone Sonne) | cabine numérique = nostalgie civique |

### 2.2 Candidatures publiques — cibles

| Programme | Organisme | Phase d'appel | Pertinence |
|---|---|---|---|
| **Petites Villes de Demain** | ANCT (Agence Nationale de la Cohésion des Territoires) | Continu (volet équipement numérique) | Très haute — borne mairie de village |
| **France Services** | ANCT + DGCL | Conventionnement | Haute — points-relais ruraux équipés |
| **Beta.gouv** | DINUM (Direction Interministérielle du Numérique) | Continu | Moyenne-haute — produit d'intérêt général |
| **Cyber-Innovation** | ANSSI | Programme spécifique | Haute — souveraineté + auto-audit |
| **France 2030 — Maturation solutions innovantes** | SGPI / Bpifrance | Appels périodiques | Moyenne — déploiement pilote |
| **France Tech Tremplin** | Mission French Tech | Continu | Moyenne — porteur SOLO entrepreneur |
| **i-Lab** | Bpifrance | Annuel (printemps) | Moyenne — concours innovation |
| **Soutien start-up Savoie** | Conseil régional AURA + Savoie Mont Blanc | Continu | Haute — ancrage local |
| **Programme La Boussole** | Banque des Territoires (CDC) | Continu | Moyenne — financement territoire |
| **CNIL Pack Innovation** | CNIL Lab | Continu | Très haute — privacy-by-design produit |
| **ENVIE / La Réserve numérique** | DINUM | Selon appels | Moyenne — sobriété numérique |
| **Quartiers prioritaires NumQP** | ANCT | Appels périodiques | Haute — déploiement quartiers |

### 2.3 Partenaires institutionnels à mentionner / approcher

- **ANSSI** (référentiel CSPN, certification possible)
- **CNIL** (privacy-by-design)
- **Etalab** / data.gouv (open data des incidents anonymisés)
- **April** (relais communauté libriste)
- **Framasoft** (gouvernance commun numérique)
- **La Quadrature du Net** (positionnement vie privée)
- **AFNIC** (DNS souverain)
- **Conseil National du Numérique** (avis stratégique)
- **AMF** (Association des Maires de France) — diffusion bornes
- **AMRF** (Association des Maires Ruraux de France) — terrain prioritaire

---

## 3. Livrables à produire

### 3.1 Dossier de presse (FR)

**Format :** 6 à 8 pages A4 PDF, mise en page sobre, photos placeholder, prêt à imprimer ou diffuser numériquement.

**Plan suggéré :**

1. **Page 1 — Couverture**
   - Titre : « VILLAGE3B Eye — la cabine téléphonique numérique »
   - Sous-titre : « Diagnostic gratuit de compromission cybersécurité pour les smartphones, accessible librement dans chaque commune »
   - Logo Gondwana / CyberMind
   - Une photo de borne (placeholder à indiquer en commentaire)
   - Mention « Code source ouvert (LicenseRef-CMSD-1.0) · Conçu en Maurienne »

2. **Page 2 — L'essentiel**
   - 3 questions / 3 réponses : « C'est quoi ? · Pour qui ? · Comment ça marche ? »
   - Cite : « En 2024, 78 % des Français possèdent un smartphone, mais 64 % n'ont jamais effectué de check de compromission. » (chiffres à valider — placeholder)
   - 4 chiffres clés (sobriété : 3 W consommation, anonymat : 24 h rétention, public : 100 % gratuit, ouvert : 100 % code public sous CMSD)

3. **Page 3 — Le manifeste**
   - Texte d'environ 300 mots sur la résonance avec la cabine téléphonique publique disparue
   - Mention résistance 1940, premières lignes médicales rurales, numéros d'urgence
   - Conclusion : « VILLAGE3B Eye est un commun numérique civique. »

4. **Page 4 — Technologie & souveraineté**
   - Architecture en 1 schéma simple (smartphone ↔ borne ↔ Internet, avec encart « analyse R2 »)
   - Référence ANSSI CSPN, RGPD, LCEN
   - Code source 100 % public, audit citoyen possible
   - Hommage aux briques open-source : Debian, mitmproxy, nftables, hostapd, dnsmasq, FastAPI

5. **Page 5 — Cas d'usages**
   - 3 mini-scénarios :
     a. Une jeune femme en Maurienne fait un check avant un voyage long
     b. Un agriculteur passant à France Services y connecte son téléphone pendant qu'il imprime un papier
     c. Un lycéen vérifie si une app installée la veille « tracke » sa géolocalisation
   - Chaque scénario : 100 mots, ton vivant, ancré

6. **Page 6 — Modèle économique & déploiement**
   - Coût borne unitaire (~150-250 € HT à confirmer)
   - Aucune revente, financement par subventions + dons (Liberapay)
   - Tarif maintenance / accompagnement (modèle prestation 49-99 €/mois selon flotte)
   - Pilote 2026 : 5 bornes en Savoie / Maurienne, partenaires Communauté de communes des Vallées d'Aigueblanche, Mairie de Notre-Dame-du-Cruet

7. **Page 7 — Citations**
   - 3 citations placeholder : Gérald Kerma (fondateur), un maire pilote, un usager du test
   - Ton sobre, sincère, sans hyperbole

8. **Page 8 — Pour aller plus loin**
   - Contacts presse : devel@cybermind.fr (+33 6 ?? — placeholder)
   - Lien dépôt média (photos haute résolution, captures d'écran, logos)
   - GitHub repo
   - Mention « ce dossier de presse est librement reproductible (CC-BY-SA) »

### 3.2 Communiqué de presse (CP) — FR

**Format :** 1 page A4, accroche journalistique, prêt à insérer dans une newsletter ou un envoi groupé.

**Structure :**
- Lieu, date
- Titre (60 caractères max)
- Chapeau (3 lignes)
- Corps 250-300 mots, paragraphes courts, citations intégrées
- « En savoir plus » + contact
- Mention CC-BY-SA

### 3.3 Tribune libre (long format)

**Format :** ~1500 mots, pour Le Monde / Libération / Médiapart / un média régional.

**Angle :** « Et si on rendait visible ce qui se passe dans nos smartphones ? Pour une cabine téléphonique numérique du XXIe siècle. »

**Auteur :** Gérald Kerma, signature Gondwana / CyberMind.

### 3.4 Candidatures publiques

Pour CHACUN des 6 programmes prioritaires (ANCT, France Services, Beta.gouv, ANSSI Cyber-Innovation, France 2030, CNIL Pack Innovation), produire :

1. **Note de synthèse (2 pages)** — résumé exécutif, alignement programme, demande
2. **Dossier technique (5-10 pages)** — architecture, sécurité, ouverture du code, coûts, livrables
3. **Budget prévisionnel** — borne unitaire + déploiement pilote 5 bornes + maintenance an 1
4. **Calendrier** — pilote Q3 2026, retex Q1 2027, déploiement national 2027-2028
5. **Équipe & gouvernance** — porteur Gérald Kerma + partenaires (mairies, France Services, AMRF)
6. **Lettre de soutien type** — à faire signer par un maire pilote

### 3.5 Pack média

- 1 logo Gondwana / VILLAGE3B Eye (à définir si pas encore créé — Claude peut proposer une charte typo/couleurs)
- 3 captures d'écran du portail (Claude indique quoi photographier)
- 1 schéma d'architecture E2E simplifié grand public
- 1 photo de borne prototype (Claude indique le brief photo : « Pi Zero en boîtier blanc, posé sur une table en bois, lumière douce, contexte mairie de village »)
- 1 vidéo 90 secondes (script à proposer) — explication usage en 3 plans

---

## 4. Contraintes éditoriales

- **Ton** : sérieux, ancré, sincère, sans buzzword anglo-saxon (« disrupt », « game-changer », « revolutionize »). Préférer : « ouvre », « rend possible », « rend visible », « propose », « met à disposition ».
- **Pas d'emojis** dans les livrables presse et candidatures.
- **Pas de superlatifs absolus** (« le meilleur », « le seul », « le premier ») — utiliser « parmi les premiers », « inédit en France à notre connaissance », etc.
- **Vocabulaire technique adapté** : un maire de village ne sait pas ce qu'est « JA4 » ou « DNS-tunneling ». Utiliser des analogies : « empreinte digitale du trafic web », « tunnel DNS caché ».
- **Conformité réglementaire** affichée — RGPD, LCEN, RGS, CSPN référencés correctement.
- **Toujours mentionner le code public** sous **LicenseRef-CMSD-1.0** (Source-Disclosed License) — c'est la licence souveraine du projet, à NE PAS confondre avec une licence AGPL ou Apache. Le code est ouvert pour audit citoyen et inspection ; les droits d'usage sont strictement régis par la licence CMSD (FR faisant foi).
- **Toujours mentionner l'ancrage local** Notre-Dame-du-Cruet / Maurienne / Savoie.

---

## 5. Références techniques disponibles

Pour rédiger précisément, tu peux te référer à ces documents disponibles dans le repository `github.com/CyberMind-FR/secubox-deb` :

- `packages/secubox-toolbox/README.md` — architecture E2E du module captif
- `packages/secubox-toolbox/CLAUDE.md` — contexte agent (Phase 1)
- `docs/specs/CM-WALL-EGRESS-2026-06.md` — spec WALL/EGRESS (référentiel R2)
- `docs/specs/CM-MESH-MPCIE-2026-06.md` — spec MESH WiFi
- `CLAUDE.md` (racine) — vision globale SecuBox
- Issues parentes : #474 (ToolBoX), #475 (Phase 1), #477 (Phase 1.5), #480 (cette tâche)

---

## 6. Process attendu

1. **Lire** les documents références ci-dessus (fichiers Markdown du repo)
2. **Préparer** une note de positionnement de 2 pages qui synthétise produit + vision + audiences
3. **Faire valider** cette note de positionnement par l'auteur (Gérald Kerma) avant rédaction longue
4. **Produire** les livrables dans l'ordre :
   a. Dossier de presse (8 pages)
   b. Communiqué de presse (1 page)
   c. Tribune libre (1500 mots)
   d. Pack candidatures (6 programmes × 4-5 livrables)
5. **Demander** validation auteur à chaque livrable majeur
6. **Sauvegarder** les fichiers Markdown sources dans `docs/marketing/` + générer les PDF si possible

---

## 7. Questions ouvertes à poser à l'auteur AVANT de rédiger

1. Nom de marque définitif : « VILLAGE3B Eye » convient-il, ou autre proposition (« VILLAGE3B Mini », « Eye », « Borne Gondwana », autre) ?
2. Logo existant ou à créer ?
3. Photos / vidéos disponibles ou à briefer ?
4. Partenaires déjà engagés (mairies, France Services, etc.) ?
5. Subventions déjà obtenues ou en cours ?
6. Calendrier réaliste de déploiement pilote (Q3 2026 ? plus tard ?)
7. Coût borne unitaire confirmé ou à estimer ?
8. Modèle économique : 100 % subventions ou mix subventions + prestations + dons ?
9. Tarif maintenance / accompagnement : 49 ? 99 ? 199 €/mois selon flotte ?
10. Y a-t-il une dimension internationale envisagée (Belgique, Suisse romande, Québec) ou strictement France métropolitaine + DOM-TOM dans un premier temps ?
11. Souhait de candidater à un programme européen (Horizon Europe, Digital Europe Programme) en plus des programmes français ?
12. Souhait de monter une association loi 1901 dédiée VILLAGE3B Eye, ou rester en porteur individuel CyberMind ?

---

## 8. Output attendu

**Aucun fichier ne doit contenir d'emoji.** **Tout en français de France**. Pas de jargon technique non expliqué. Tout livrable destiné à la presse ou à un fonctionnaire doit pouvoir être compris par un lecteur non technique.

Tu produiras :

1. Une note de positionnement (`docs/marketing/POSITIONNEMENT-VILLAGE3B-Eye.md`)
2. Un dossier de presse complet (`docs/marketing/PRESSE-VILLAGE3B-Eye.md` + PDF si possible)
3. Un communiqué de presse (`docs/marketing/CP-VILLAGE3B-Eye.md`)
4. Une tribune libre (`docs/marketing/TRIBUNE-VILLAGE3B-Eye.md`)
5. Six candidatures complètes (`docs/marketing/CANDIDATURE-{ANCT,FRANCE-SERVICES,BETA-GOUV,ANSSI-CYBER,FRANCE2030,CNIL-PACK}/`)

À chaque livrable terminé, commit Git avec message conventional : `docs(marketing): add positionnement note for VILLAGE3B Eye (ref #480)`, etc.

---

Bonne rédaction. Pour toute question structurante, demande à l'auteur (Gérald Kerma, devel@cybermind.fr) plutôt que de deviner.

---

## ANNEXE — Mise à jour 2026-06-05 : architecture R0/R1/R2/R3

Depuis la rédaction initiale de ce prompt, le produit a évolué. Intégrer ces éléments dans tes livrables :

### Modèle d'opt-in à 3 niveaux + 1 mode portable (Phase 3 #492 mergeable + Phase 6 #496 roadmap)

L'utilisateur choisit explicitement son niveau d'analyse sur le splash captif :

| Niveau | Mode | Impact UX | Cas d'usage cible |
|--------|------|-----------|-------------------|
| 🌐 **R0** | Bypass complet | Aucune analyse, AP WiFi normal | Visiteur juste de passage, refus principiel d'analyse |
| 🛡 **R1** | Analyse passive | Rapport généré, AUCUN impact surf | **Défaut recommandé** — bénéfice diagnostic sans coût UX |
| 🔍 **R2** | TLS-break + bandeau | Déchiffrement, bandeau visible Safari | Curieux éclairé, audit personnel approfondi |
| 🌐 **R3** | WireGuard mobile (roadmap Phase 6) | VPN tunnel, marche hors-WiFi cabine | Mobilité, mode portable, bénéfice élargi territorial |

L'angle CSPN/ANSSI : le consentement n'est plus binaire (accept/refuse) mais **gradué**, **explicable**, **réversible à tout moment depuis le rapport**. C'est un argument fort pour la conformité **principe de proportionnalité** et **minimisation des données**.

### Transparence radicale (Phase 3 #492)

Le rapport montre **honnêtement** :
- 🔍 X% du trafic inspecté (HTTPS via notre CA)
- 🛡 X% bypassé par whitelist (Apple/banques/Signal — 108 patterns curés)
- 🔒 X% cert-pinning détecté (app refuse notre CA = normal, bon signe)
- 🔐 X% E2E messaging (Signal/iMessage opaques par design)

**La cabine se sait se taire, et DIT QUAND elle se tait.** C'est le différenciateur fondamental contre les produits qui vendent "98% sécurisé" sans détailler les bypass.

### Architecture mitm disjoints (Phase 5 #495)

Roadmap : séparer le mitm cabine (analyse client iPhone) du WAF mitm (protection vhosts CyberMind) dans deux containers LXC distincts. **Isolation totale** des deux usages, certs séparés, addons séparés. Argument souveraineté : la cabine n'écoute QUE le trafic de son utilisateur, jamais celui d'un tiers.

### Mode WireGuard portable (Phase 6 #496 — kbin.gk2.net:51820)

Roadmap majeure pour 2026 :

> **L'utilisateur scanne un QR code, installe un profil WireGuard sur son iPhone, et obtient l'analyse depuis n'importe où — pas besoin d'être physiquement à la cabine.**

Bénéfices presse/gouv :
- Inclusion territoriale : usage déporté en zone blanche, depuis le domicile, depuis un autre WiFi
- Maillage léger : plusieurs cabines = plusieurs endpoints WireGuard, possible mutualisation
- Conformité renforcée : profil VPN visible iOS, consentement encore plus explicite
- Continuité de service : si la cabine physique est en maintenance, le profil installé continue de fonctionner

### Engine de filtrage compromissions à sensibilité réglable

`/etc/secubox/toolbox/rule-engine.yaml` permet à l'opérateur (collectivité, association de quartier, France Services) de choisir un profil :

- 🟢 **Permissif** : bloque uniquement malware confirmé (zéro faux positif)
- 🟡 **Équilibré** (défaut) : malware + DGA fort + beaconing évident
- 🟠 **Strict** : ajoute ASN faible réputation
- 🔴 **Paranoïaque** : default-deny sauf whitelist

L'angle souveraineté : la cabine s'adapte au contexte (école, EHPAD, médiathèque) sans changer de produit. Un médiateur numérique peut ajuster la rigueur sans toucher au code.

### Empreinte hardware & Open Source

- Cible matérielle : MochaBin GlobalScale (Marvell Armada 7040 ARM64) — fabricant taïwanais avec écosystème ouvert
- Debian 12 bookworm arm64 — distribution souveraine de facto
- Code source intégral : `github.com/CyberMind-FR/secubox-deb` (licence CMSD-1.0, audit citoyen possible)
- Coût matériel : ~250 € HT par cabine assemblée (sans WiFi USB ni boîtier décoratif)

### Documentation technique

Un brief auto-portant pour LLM externe (`docs/AI-HANDOVER-cabine-evolution.md`) existe désormais : un autre rédacteur ou contributeur (humain ou GPT/Gemini) peut comprendre l'architecture entière sans contexte préalable. **Continuité du commun numérique au-delà d'un seul auteur.**

### Composants installables sur iPhone (splash quick-up menu)

```
🔐 Certificat iPhone     → /ca/mobileconfig
🤖 Certificat Android/PC → /ca/android.crt
📱 Icône Home iPhone     → /ca/webclip-cabine.mobileconfig
📜 Guide pas-à-pas       → /ca/install-help
🌐 Profil WireGuard (R3) → /wg/profile/new (roadmap #496)
```

Tous bundlés avec l'empreinte CA SHA-1 affichée pour vérification visuelle dans Réglages iOS.

### Engagement de l'auteur

> *« Je ne vends pas une boîte noire. Je publie un commun numérique que tu peux installer toi-même, auditer ligne par ligne, et adapter à ta collectivité. Si demain CyberMind disparaît, le code reste, la documentation reste, le brief LLM reste — quelqu'un d'autre peut reprendre. »*

Cette posture est à intégrer dans la tribune et le communiqué de presse — c'est le différenciateur éthique face aux SaaS américains et aux solutions clé-en-main propriétaires.

---

**Status au 2026-06-05** : Phase 3 PR #493 prête à merge. Phases 5+6 ouvertes (#495, #496). Mise à jour livrables marketing avec les éléments ci-dessus avant publication.

