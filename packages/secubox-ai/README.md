<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# secubox-ai — assistant IA de la box

Module IA de SecuBox (#3583), porté du POC de gk0. Une page d'administration `/ai/` et une API FastAPI sur le socket
Unix `/run/secubox/ai.sock`, publiée sous `/api/v1/ai` (nginx retire le préfixe). Le modèle répond soit sur la box
(moteur **local** : llama-server de `secubox-zia-llm`), soit sur un moteur **distant** compatible OpenAI (gk0).

## Fonctionnalités

- Dialogue en flux (NDJSON), curseur de lucidité, image jointe pour un modèle multimodal, reprise d'une réponse coupée.
- Recherche de sources avant de répondre : SecuBox (objets du Hall de gk2), SearXNG (local, sinon celui de gk0),
  Wikipédia. Le contenu des sources est cité, jamais suivi comme une instruction.
- Documents : PDF, HTML ou texte, déposés ou tirés d'un lien (garde SSRF) ; résumé, points clés, question, liens,
  traduction, en tâche de fond (2 h au plus, arrêt possible).
- Menaces : relevé WAF et posture de gk2, résumé et questions ; aucun résumé sur un relevé incomplet.
- Code : expliquer, relire, tests, corriger, documenter.
- Mémoire (SQLite, FTS5) : notes, réponses approuvées, corrections, documents gardés ; export et import.
- Modèles : catalogue, téléchargement depuis Hugging Face, activation, dépôts suivis ; médias générés et entrées.
- Moteur local démarré et arrêté à la demande par le contrôleur root `secubox-aictl` : contexte calculé sur la mémoire
  réellement disponible (4 096 – 32 768), réserve de 512 Mo, refus de démarrer plutôt que d'arrêter un autre service.

## Architecture

```
navigateur ─▶ nginx (admin) ─▶ /run/secubox/ai.sock ─▶ API secubox-ai (compte secubox-ai, AppArmor enforce)
                                                      │  ├─▶ moteur distant (gk0, HTTP + clé)
                                                      │  └─▶ /run/secubox-ai/moteur.sock ─▶ llama-server
                                                      │                                    (compte secubox-ai-moteur)
                                                      └─ dépose <action>.demande ─▶ secubox-ai-demandes.path
                                                                                   ─▶ secubox-aictl demandes (root)
```

| Unité | Rôle |
|---|---|
| `secubox-ai.service` | API (uvicorn), `User=secubox-ai`, sans capacité, filtrage IP (R13), profil `secubox-ai-api` |
| `secubox-ai-moteur.service` | llama-server, `User=secubox-ai-moteur`, sans réseau IP, profil `secubox-ai-moteur` ; sans `[Install]` |
| `secubox-ai-preparer.service` | oneshot root à l'amorçage : `/run/secubox-ai`, drop-in des adresses LAN de l'API |
| `secubox-ai-demandes.path` / `.service` | demandes de l'API (démarrer, arrêter, redémarrer) traitées par le contrôleur root |

Aucun sudo, aucun `systemd-run` : l'API ne lance rien en root.

## Socket et ports

- `/run/secubox/ai.sock` : API (0660, groupe `secubox`, servie à nginx). Aucun port TCP.
- `/run/secubox-ai/moteur.sock` : moteur local (0770, groupe `secubox-ai`).
- Aucune exposition publique : ni vhost, ni nom, ni route WAF. La page est servie par la racine statique du vhost
  d'administration (`/usr/share/secubox/www/ai/`).

## Configuration

| Fichier | Propriétaire | Rôle |
|---|---|---|
| `/etc/secubox/ai.toml` | root 0644 | configuration fixe, copiée de `/usr/share/secubox/ai/ai.toml.example` au premier passage seulement |
| `/etc/secubox/secrets/ai/distant.key` | root:secubox-ai 0640 | clé du moteur distant, posée par `secubox-aictl cle-distante` (lue sur l'entrée standard) |
| `/var/lib/secubox/ai/preferences.toml` | secubox-ai | préférences modifiables depuis la page (écriture atomique, double tampon) |
| `/var/lib/secubox/ai/` | secubox-ai 0750 | `memoire.db`, `journal.jsonl`, `documents/`, `medias/`, `modeles/` (0750, modèles 0640), `tmp/` (0700, temporaires de SQLite) |

`ai.toml` (sections) :

```toml
[distant]
url = ""                      # moteur distant compatible OpenAI ; vide = non configuré

[gk2]
menaces_url = "https://admin.gk2.secubox.in/api/v1"
sources_url = "https://hall.gk2.secubox.in/api/v1/zia/objets"

[searxng]
# url = "http://10.100.0.85:8888"   # SearXNG local de la box, essayé avant celui de gk0

[moteur_local]
modele = "Llama-3.2-3B-Instruct-Q4_K_M.gguf"
```

Un changement d'adresse dans `ai.toml` (ou de DNS) demande `secubox-aictl preparer` puis
`systemctl restart secubox-ai` : les adresses LAN rouvertes à l'API sont résolues à ce moment-là. Les résolveurs
privés de `/etc/resolv.conf` (gk3 résout par gk2, 192.168.1.200) sont rouverts de la même façon ; 127.0.0.1
(Unbound de la box) l'est déjà par l'unité.

**La clé du moteur distant circule en clair sur le LAN** : l'appel à gk0 se fait en HTTP (`Authorization: Bearer`).
Elle ne protège que d'un appel par erreur ; quiconque écoute le LAN peut la lire. Ne pas réutiliser cette clé ailleurs.

**Clés de préférences inertes** (arbitrage R15) : gardées pour que la page du POC ne reçoive pas de 422, mais sans
aucun effet dans ce paquet — `moteur.backend`, `moteur.threads`, `moteur.paralleles`, `moteur.couches_gpu`,
`moteur.nice`, `outils.recherche_web`, `outils.heure`, `outils.appels_max`. Pour
`outils.mode`, seule la valeur `jamais` agit (aucune recherche). L'appel de fonctions et la recherche web du POC sont
restés sur gk0.

**Arrêt du moteur local après inactivité** (`moteur.arret_inactivite_min`, 30 par défaut, 0 = jamais) : toutes les
30 s, l'API dépose `arreter` au contrôleur si le moteur local répond, que rien n'est en cours et qu'aucune demande de
l'administrateur n'a eu lieu depuis ce délai (compté aussi depuis le démarrage de l'API et le dernier « prêt » du
contrôleur). Le résumé automatique des menaces et les sondes du moteur ne comptent pas comme une activité.

## API — `/api/v1/ai/`

Toute route porte `require_jwt` (administrateur réel), sauf `GET /health` (test `test_toute_route_est_gardee`).

| Route | Rôle |
|---|---|
| `GET /health` | vivacité `{"status": "ok", "module": "ai"}` (sans garde) |
| `GET /status` | version, état des moteurs, préférences invalides signalées |
| `GET /preferences` | préférences courantes |
| `PUT /preferences` | modifie les préférences (validées, bornées) |
| `GET /moteur` | état des moteurs local et distant |
| `POST /moteur/{choix}` | `local`, `distant` ou `auto` |
| `POST /essai/flux` | dialogue, flux NDJSON (étapes, texte, bilan) |
| `GET /travaux` | dialogues et tâches en cours ou récents |
| `GET /travaux/{ident}` | événements d'un dialogue (reprise après rechargement) |
| `POST /travaux/{ident}/arreter` | arrête un dialogue |
| `GET /taches/{t}` | avancement d'une tâche (document, menaces, code) |
| `POST /taches/{t}/arreter` | arrête une tâche |
| `POST /tout-arreter` | arrête tout ce que l'administration a lancé |
| `GET /historique` | historique des échanges |
| `GET /historique/{ident}` | un échange |
| `DELETE /historique/{ident}` | supprime un échange |
| `POST /historique/{ident}/memoriser` | garde un échange en mémoire |
| `GET /memoire` | souvenirs |
| `GET /memoire/chercher` | recherche plein texte |
| `GET /memoire/{ident}` | un souvenir |
| `POST /memoire/notes` | ajoute une note |
| `POST /memoire/reponses` | ajoute une réponse approuvée |
| `POST /memoire/corrections` | ajoute une correction |
| `PUT /memoire/{ident}` | modifie un souvenir |
| `DELETE /memoire/{ident}` | supprime un souvenir |
| `POST /memoire/tout-oublier` | vide la mémoire |
| `GET /memoire-export` | export JSON |
| `POST /memoire-import` | import JSON (5 000 souvenirs, 20 M caractères au plus) |
| `PUT /memoire-reglage` | active ou suspend la mémoire |
| `POST /documents` | lit un document depuis un lien (garde SSRF, 20 Mo) |
| `POST /documents/fichier` | dépôt en corps brut (100 Mo), en-tête `X-Nom` |
| `POST /documents/{ident}/analyser` | `resume`, `points`, `question`, `liens`, `traduire` (tâche) |
| `POST /memoire/documents/{doc}` | garde un document lu en mémoire |
| `GET /menaces/releve` | relevé des menaces de gk2 |
| `POST /menaces/resumer` | résumé IA du relevé (tâche) |
| `POST /menaces/demander` | question sur le relevé (tâche) |
| `POST /code/{action}` | `expliquer`, `relire`, `tests`, `corriger`, `documenter` (tâche) |
| `GET /modeles/catalogue` | modèles proposés |
| `GET /modeles` | modèles présents et actif |
| `GET /modeles/depot` | fichiers d'un dépôt Hugging Face |
| `POST /modeles` | télécharge un modèle : un à la fois (409 sinon), reprise Range et 3 reprises automatiques ; 422 pour Q4_0_4_4, Q4_0_4_8, Q4_0_8_8 (retirés de llama.cpp) |
| `POST /modeles/{nom}/activer` | active un modèle (redémarre le moteur local s'il tourne) |
| `DELETE /modeles/{nom}` | supprime un modèle |
| `GET /medias/gguf` | fichiers GGUF présents (actif, métadonnées), partiels compris |
| `DELETE /medias/gguf/{nom}` | supprime un GGUF |
| `DELETE /medias/gguf-part/{nom}` | supprime un téléchargement partiel |
| `GET /depots` | dépôts suivis |
| `POST /depots` | suit un dépôt |
| `DELETE /depots/{editeur}/{nom}` | ne suit plus un dépôt |
| `GET /medias/{dossier}` | `generes` ou `entree` |
| `GET /medias/{dossier}/{ident}/fichier` | un fichier média |
| `DELETE /medias/{dossier}/{ident}` | supprime un média |
| `POST /medias/entree` | dépôt d'un média en corps brut (50 Mo, quota 2 Go) |
| `GET /journal` | fin du journal du module |

nginx : flux du dialogue sans tampon (lecture jusqu'à 2 h), corps de 100 Mo pour les deux seuls dépôts de fichier,
8 Mo pour le dialogue (image jointe), 64 Mo pour l'import de mémoire, 2 Mo ailleurs ; 900 s pour les lectures de
document (lien ou dépôt : pdftotext dans la requête).

## Journal

`/var/lib/secubox/ai/journal.jsonl` : une ligne JSON par événement, **ni question, ni réponse, ni titre de document,
ni adresse lue, ni clé** (règle du POC). Rotation par `/etc/logrotate.d/secubox-ai` : hebdomadaire ou dès 5 Mo,
8 archives, par renommage (l'API rouvre le fichier à chaque événement). Les décisions du contrôleur root (démarrages,
refus, adresses permises) vont dans `/var/log/secubox/audit.log`.

## Dépendances

- Debian : `secubox-core (>= 1.8.30~)`, `secubox-zia-llm (>= 0.3.0~)` (llama-server statique,
  `/usr/lib/secubox/zia-llm/llama-server`), `python3 (>= 3.11)`, `python3-fastapi`, `python3-httpx`, `uvicorn`,
  `poppler-utils` (`pdfinfo`, `pdftotext`), `sqlite3`, `adduser` ; recommandés : `apparmor`, `logrotate`.
- Python : FastAPI, httpx, uvicorn, bibliothèque standard (`sqlite3` avec FTS5, `tomllib`).
- À savoir : `secubox-zia-llm` dépend lui-même de `secubox-zia` (le Hall ZIA) ; installer secubox-ai tire donc
  secubox-zia. Gardé tel quel à l'étape 1 (gk3 l'a déjà) ; à revoir si le moteur doit vivre sans le Hall.

## Installation

```bash
apt-get install secubox-ai            # depuis apt.secubox.in
secubox-aictl cle-distante < cle.txt  # facultatif : clé du moteur distant, jamais affichée
```

Le postinst crée les comptes `secubox-ai` et `secubox-ai-moteur`, `/var/lib/secubox/ai` et `modeles/` (0750, par
descripteur), copie `ai.toml` s'il manque, charge les profils AppArmor (API en enforce, moteur en complain jusqu'à la
mesure sur gk3), active `secubox-ai-preparer.service`, `secubox-ai-demandes.path` et `secubox-ai.service`, lance
`secubox-aictl preparer` puis relance l'API. Préférences, mémoire, journal et modèles survivent aux mises à jour ; la
purge retire `ai.toml` mais garde les données et la clé (retrait à la main).

## Exemples

```bash
secubox-aictl etat --json             # état du moteur local (groupe secubox-ai)
secubox-aictl demarrer                # démarre le moteur local si la mémoire le permet (root)
curl -s --unix-socket /run/secubox/ai.sock http://ai/health
curl -s -H "Authorization: Bearer $JETON" https://admin.<box>/api/v1/ai/moteur
```

## Tests

`python -m pytest packages/secubox-ai/tests -q` depuis la racine du dépôt, ce paquet seul (collision des paquets
`api`).
