<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# secubox-ai — la suite IA du POC gk0 en module Debian, pour gk3 (#3583)

## Intention

Le propriétaire a validé le POC `~/poc-secubox-ai` de gk0 (« c'est parfait ») et demande de le mettre sur **gk3**,
**tel quel**, dans un module SecuBox empaqueté. Le POC reste en service sur gk0 pendant tout le portage.

Le POC, au 2026-11-13 : un relais FastAPI d'un seul fichier (`relais/relais.py`, 3 845 lignes) et une page
(`relais/index.html`, 1 015 lignes ; `dialogue.html`, 188 lignes, pour le public). Onglets : Essai (dialogue en flux),
Menaces, Code, Générateur, Documents, Agents, Mémoire, Historique, Modèles, Préférences, OBLITERATUS, Médias, Journal.

« Tel quel » veut dire : **mêmes fonctions, même comportement, même aspect**, mais aux règles SecuBox (AGENTS.md,
`.claude/RULES-CODE.md`, `.claude/MODULE-COMPLIANCE.md`).

## Décisions du propriétaire (2026-11-13)

1. **Moteurs hybrides.** Un petit modèle de texte **local** sur gk3 (CPU, ~3 milliards de paramètres), toujours
   disponible. Quand gk0 est allumé, le module utilise ses **moteurs distants** : DeepSeek 9B (texte), sd-server
   (images, animation), par le LAN, avec une clé.
2. **Le dialogue public `ai.gk2` reste servi par le POC de gk0** pour l'instant ; la bascule vers gk3 est une étape
   ultérieure, sur accord.
3. **Livraison par étapes déployables**, chacune installée et vérifiée sur gk3 :
   - **Étape 1 — socle** : API et page ; Essai (dialogue), Mémoire, Historique, Menaces, Code, Documents ; travaux en
     cours et reprise après rechargement ; Tout arrêter ; contexte automatique ; moteur local + moteur distant texte.
   - **Étape 2** : Générateur (images, animation, par le moteur distant de gk0), Agents, voix.
   - **Étape 3** : dialogue public (route WAF déclarée, quotas, filtre de contenu), sur accord.

## Contraintes (non négociables, AGENTS.md)

- Paquet `packages/secubox-ai/` (`api/`, `www/`, `debian/`), version `X.Y.Z-N~trixie1`, `debian/compat` 13,
  `Standards-Version: 4.6.2`, en-tête SPDX CMSD-1.0 partout.
- API FastAPI sur **socket Unix** `/run/secubox/ai.sock`, jamais un port TCP ; routes `GET|POST /api/v1/ai/<méthode>`.
- **Toute route porte une garde** : `require_jwt` (administrateur réel) pour tout ce qui existe en étapes 1 et 2.
  Le contrôle par nom d'hôte du POC (`HOTES`, `HOTE_PUBLIC`) disparaît : la session SecuBox le remplace.
- Utilisateur dédié `secubox-ai`, **AppArmor enforce**, jamais root. Actions root (unité du moteur local, fichiers de
  modèles) par un contrôleur `secubox-aictl` (sudoers exact, audit), comme les modules dédiés existants.
- Configuration `/etc/secubox/ai.toml` (double tampon : ombre → validation → bascule, rollback) ; secrets
  `/etc/secubox/secrets/ai/` (clé du moteur distant) ; jamais de secret dans le code ni le TOML versionné.
- Données `/var/lib/secubox/ai/` : `memoire.db` (SQLite, FTS5 — mémoire **et** historique), médias générés,
  `instantanes-menaces.json`. Chaque décision de sécurité tracée dans `/var/log/secubox/audit.log`.
- Journal du module : **ni question, ni réponse, ni titre de document, ni adresse lue** (vie privée, comme le POC).
- Cycle de vie `on-demand` (manifeste `modules.d`) : le moteur local s'arrête après inactivité (réglage existant).
- **Ne pas gêner VoiceStudio sur gk3** : budget mémoire du moteur local plafonné (MemoryMax), contexte automatique
  calculé sur la mémoire **réellement disponible** moins une réserve.
- Pas de Docker, pas de LXC pour ce module (llama-server est un binaire, comme dans le POC).

## Ce qui se porte (le comportement fait foi : le code du POC est la référence)

Chaque point ci-dessous existe et a été vérifié sur gk0 ; le porter, c'est garder ce comportement.

- **Dialogue en flux NDJSON** (`/essai/flux`) : lucidité, recherche avec sources, budget de sources en vrais jetons
  plafonné (`outils.sources_max_jetons`, 8 000), contrôle des adresses non vérifiées, image jointe, **lecture du
  contexte avec avancement** (`return_progress`), **Continuer** pour une réponse coupée (contexte gardé 30 min en
  mémoire, jamais sur disque), fil d'événements gardé 30 min pour la **reprise après rechargement**.
- **Contexte automatique** (`moteur.contexte = 0`) : coût du cache par jeton lu dans l'en-tête GGUF (modèles hybrides
  compris), mémoire disponible moins réserve, entre 4 096 et 32 768.
- **Tâches de fond** (documents, agents, code, menaces) : étapes, progression colorée (lecture, écriture, attente),
  avancement global et temps restant, Arrêter, Tout arrêter, résultat partiel gardé en cas d'arrêt ou de dépassement.
- **Documents** : PDF/HTML/texte jusqu'à 100 Mo, envoi brut écrit sur disque, `pdftotext`, lien public seulement
  (garde SSRF : hôte public, ports 80/443, redirections revérifiées), texte plafonné, morceaux taillés sur le contexte
  réel, résumé / points clés / questions-réponses / liens / traduction.
- **Mémoire** : notes, documents gardés, réponses approuvées, corrections prioritaires ; recherche FTS5 ; « Rappelle-toi… » ;
  👍 / 👎 sous les réponses ; export / import ; tout oublier (confirmation écrite).
- **Historique** sur disque : chaque réponse, analyse et résultat d'agent ; Mémoriser / Oublier.
- **Menaces** (lecture seule de gk2 par les routes `require_lecture`, sans jeton) : relevé agrégé sans IA (cache 15 s),
  relevés de fond toutes les 2 min gardés sur disque (tendances), **Faits** écrits par le relais, **Lecture** par l'IA
  en **double tampon** (brouillon jamais montré → relecture contre les faits → contrôles mécaniques → bascule),
  contrôles (chiffres absents, tendance non mesurée, pays absents, arrondi toléré), **propositions** limitées au
  catalogue fermé et à des cibles présentes dans le relevé, jamais les adresses de la box ni une adresse non publique ;
  rapport audio qui ne lit que la lecture de l'IA ; résumé automatique seulement si le moteur tourne et est libre.
- **Code** : expliquer, relire (sévérités), tests, corriger, documenter ; règles de code de la mémoire jointes.
- **Médias**, **Modèles** (catalogue, téléchargement Hugging Face, activation), **Préférences**, **Journal** : tels quels.
- **Écouter / Mémoriser / Copier** sous chaque résultat.

## Ce qui ne se porte pas

- **OBLITERATUS** : licence AGPL-3.0 et besoin d'une carte graphique ; il reste sur gk0.
- Le contrôle par nom d'hôte et les routes « locales d'office » du POC (remplacés par `require_jwt`).
- Les sauvegardes `*.avant-*` du POC.

## Moteurs : local et distant

- **Local (gk3)** : `llama-server` CPU, unité systemd gérée par `secubox-aictl`, socket Unix, modèle par défaut
  ~3B Q4 (choix du constructeur, à mesurer sur gk3 : vitesse, mémoire), `enable_thinking: false`, signe de vie 5 s.
- **Distant (gk0)** : `llama-server` lancé avec `--api-key` et un service d'entrée **séparé du relais POC**, lié au LAN
  seulement, qui exige la clé et ne relaie que les routes du contrat (texte : `/v1/chat/completions`, `/props`,
  `/tokenize`, `/health` ; images : `/sdcpp/v1/*` utiles et `/sdapi/v1/txt2img`). Le relais POC reste sur 127.0.0.1 :
  son contrôle par nom d'hôte ne résisterait pas à une exposition sur le LAN.
- **Choix du moteur** : le module essaie le distant s'il est déclaré et répond (`/health`, délai court), sinon le local ;
  l'administrateur peut forcer l'un ou l'autre ; la page dit toujours lequel répond.
- Les médias joints (image d'une question) suivent la règle de `secubox-ai-gateway` : ils ne quittent jamais la box
  sauf choix explicite du moteur distant de confiance (gk0, LAN).

## Choix laissés au constructeur

- Découpage de `relais.py` en modules (`api/dialogue.py`, `api/memoire.py`, `api/menaces.py`…), à condition que chaque
  comportement listé ci-dessus garde son test.
- Le modèle local exact (Llama 3.2 3B, Qwen 2.5 3B…), d'après une mesure sur gk3.
- La forme du service d'entrée distant sur gk0 (petite application FastAPI, ou nginx à clé), à condition qu'il soit
  lié au LAN, exige la clé et ne relaie que le contrat.

## Décisions complémentaires (2026-11-13, après la relecture du constructeur)

Du propriétaire :

- **Moteur distant partagé** : gk3 utilise **le même** moteur de texte que le POC de gk0 (DeepSeek 9B, une seule carte
  de 4 Go) et **a le droit de le réveiller** (30 à 60 s). Il prend le modèle chargé ; le POC garde la main (veille,
  pause pour les images, changement de modèle). Le service d'entrée de gk0 réveille le moteur par le relais POC
  (`/moteur/demarrer` en local), jamais en pilotant l'unité lui-même.
- **Mémoire de gk3** : si la mémoire disponible moins la réserve ne suffit pas au moteur local, il **refuse de
  démarrer** ; la page le dit et propose le moteur distant. **VoiceStudio n'est jamais touché.** Mais « VoiceStudio
  moins urgent » (propriétaire, 2026-11-13) : secubox-ai passe avant lui sur gk3. Réserve : 512 Mo ;
  `MemoryMax` du moteur local = taille du modèle + cache du contexte automatique + 300 Mo.

Choix du constructeur (vérifiés le 2026-11-13) :

- **gk3 sort sur Internet en direct** (Wikipédia, Hugging Face répondent) : pas de relais ; la garde SSRF du POC
  s'applique telle quelle.
- **Binaire `llama-server`** : il n'existe pas de paquet `llama.cpp` en trixie. La recette statique de
  `secubox-zia-llm` (`build-arm64.sh`) est étendue à l'**amd64** (CPU, AVX2), version de llama.cpp **épinglée** et
  empreinte vérifiée, construite hors de la box (CI) ; `secubox-ai` en dépend.
- **Modèle local** : téléchargé par `secubox-aictl` (empreinte SHA-256 épinglée dans le paquet) au premier démarrage
  ou depuis l'onglet Modèles ; jamais embarqué dans le `.deb`.
- **Service d'entrée de gk0** : une petite application dans le dossier du POC (`~/poc-secubox-ai/distant/`), unité
  utilisateur comme les autres `poc-*`, liée à l'adresse LAN de gk0 seulement, clé exigée (Bearer), ne relayant que
  le contrat. gk0 n'est pas une box SecuBox : ce service n'est pas un paquet du dépôt. La clé est produite sur gk0 et
  posée sur gk3 par `secubox-aictl cle-distante` (lue sur l'entrée standard, 0600, jamais affichée).
- **Recherche web** : sources SecuBox (ZIA `/objets` de gk2) et Wikipédia en direct dès l'étape 1 ; SearXNG de gk0 par
  le service d'entrée quand gk0 répond.
- **Voix** (« Écouter », rapport audio des Menaces) : par l'API de `secubox-voice` déjà installé sur gk3 (Piper ou
  VoiceStudio selon son réglage) ; le bouton est masqué si le module ne répond pas. **Étape 2** (VoiceStudio moins
  urgent).
- **Périmètre de l'étape 1** : Essai, Menaces, Code, Documents, Mémoire, Historique, Modèles, Préférences, Médias,
  Journal, bandeau « En cours », Mémoriser / Copier. Étape 2 : Générateur, Agents, Écouter et rapport audio.
- **Aspect** : la page du POC est reprise telle quelle (mêmes couleurs, même structure), servie sous `/ai/` dans la
  coque SecuBox (entrée `menu.d`, carte du Hall), jeton `sbx_token` comme les autres pages.
- **Entrée ZIA** (modèle servi au ZIA du Hall de gk2) : reste sur gk0, comme le dialogue public.
- **Mémoire et historique du POC** : pas de migration automatique ; Exporter sur gk0 puis Importer sur gk3.
- **Code** : moteur de texte général (local ou distant). Le contrat distant admet plusieurs moteurs nommés dans
  `ai.toml` pour qu'un moteur de code s'ajoute plus tard sans changer le code.

## Questions ouvertes (à trancher avant l'étape 2)

- **Recherche web sans gk0** pour les Agents : installer SearXNG sur gk3 (composant de `secubox-metanews`) ou s'en
  passer quand gk0 dort ?
- **Licence SD-Turbo** (non commerciale) pour un usage autre que personnel.

## Critères de réussite (étape 1)

- `apt install secubox-ai` sur gk3 : service actif, socket, AppArmor enforce, page `/ai/` derrière la session SecuBox.
- Une question au dialogue répond avec le moteur local, puis avec le moteur distant quand gk0 est allumé, et la page
  dit lequel.
- Les tests portés du POC passent (propositions, contrôles du résumé, découpage, contexte automatique, garde SSRF,
  mémoire, historique) ; `relecteur-securite` ne relève aucun constat bloquant.
- VoiceStudio continue de répondre pendant une génération longue sur gk3.
