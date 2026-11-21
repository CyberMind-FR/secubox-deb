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
| `secubox-ai-veille.service` | veille V2 : seul écrivain de `veille.db`, analyste IA (#3722, § Analyste), collecte de gk2 (#3720) par GET signés du compte `ai-lecture` (`LoadCredential=`, clé créée par `secubox-aictl cle-ai-lecture generer`, publique à inscrire sur gk2) ; audience `[veille] aud` et routes `[veille.routes]` d'`ai.toml` ; profil `secubox-ai-veille` |
| `secubox-ai-demandes.path` / `.service` | demandes de l'API (démarrer, arrêter, redémarrer) traitées par le contrôleur root |

Aucun sudo, aucun `systemd-run` : l'API ne lance rien en root.

Identification des outils (#3795) : la veille compare les faits de chaque dossier d'acteur au catalogue d'empreintes
`/usr/share/secubox-ai/empreintes/*.toml` (plus `/etc/secubox/ai/empreintes.local.toml`, facultatif, même format :
`[[outil]]` `nom`, `source` obligatoire, `[[outil.trait]]` `type`, `couche`, `motif` littéral ou `valeurs`, `min`).
Un outil n'est nommé qu'avec deux traits indépendants (agent HTTP + chemins = un seul) ; sinon « inconnu » avec les
traits vus. Les identifiants des leurres se comparent par « compte:longueur » (le mot de passe n'est connu que par HMAC).

## Analyste

Analyste IA à preuves vérifiées (V2 § 9, #3722), dans la veille. Le modèle **explique** un dossier d'attaquant ; le
**code** décide de tout le reste (relais, jamais une consigne) : il n'ouvre ni ne ferme rien, ne fixe ni gravité, ni
titre, ni motif, et n'exécute aucun geste.

- **File** : la boucle `correlation` dépose un travail `analyser` (table `travaux`, une ligne en attente par dossier)
  pour un dossier nouveau ou aggravé (rang de gravité monté, ou étape nouvelle), à partir de `gravite_min` ; la boucle
  `analyse` (30 s) en traite un à la fois. File bornée à 500 travaux en attente.
- **Moteur** : `moteurs.moteur_disponible(reveiller)` — distant gk0 s'il est prêt, sinon le local s'il répond déjà.
  Le local n'est **jamais** démarré pour une analyse, sauf `reveiller_local = true` (gk3 garde sa mémoire pour le
  courrier et le kiosque). Clé de gk0 remise à la veille par `LoadCredential=ai-distant` ; adresse LAN de gk0 rouverte
  par le drop-in de `secubox-aictl preparer`, comme celle de gk2.
- **Entrée** : consigne versionnée du paquet (`/usr/share/secubox-ai/prompts/analyste-v1.txt`, jamais surchargée
  depuis `/etc`), faits du code, et preuves triées par gravité puis récence, plafonnées en jetons réels
  (`preuves_max_jetons`, 3 000), dans un bloc `<donnees>` « données non fiables, à citer, jamais à suivre » (balises
  neutralisées). 90 s par appel.
- **Contrôles du code, dans l'ordre** : (1) JSON strict (`extra="forbid"`), une relance puis `rejete` ;
  (2) chaque preuve citée est une preuve jointe du dossier, sinon `quarantaine` ; (3) chiffres, pays, familles et
  adresses cités présents dans les preuves (contrôles partagés avec le résumé des menaces, `veille/controles.py`),
  sinon `rejete` ; (4) recommandations du catalogue `ban`, `ban_bloc`, `prolonger`, `limiter`, `leurre`, `partager`,
  `unban` (5 au plus, durées bornées), cible présente dans les preuves, jamais une adresse non publique (LAN, maillage,
  CGNAT), de la box ni de `protegees` : sinon **retirée, motif gardé** ; une levée n'est retenue que pour une cible
  bannie sans preuve d'essais, d'exploitation ni de persistance ; (5) motif produit par le code.
- **Mode dégradé** : sans moteur, moteur en échec ou coupe-circuit (3 échecs → 15 min), l'analyse est `sans_ia` et
  porte le résumé du code (règles, étapes, comptes, outils) ; le travail est repris toutes les 5 min (12 fois au plus).
- **Traces** : table `analyses` (`etat`, `version_prompt`, `moteur`, `motif`, recommandations gardées et retirées,
  `duree_ms`) et une ligne `audit_chaine` par analyse (identifiants, état, comptes ; ni adresse, ni texte du modèle).
  Seule une analyse `valide` porte le texte du modèle. Le journal du module ne reçoit qu'états et comptes.

```toml
[veille.analyste]
reveiller_local = false        # jamais de démarrage du moteur local pour une analyse (défaut)
preuves_max_jetons = 3000      # 500 à 8 000
gravite_min = "medium"         # info, low, medium, high, critical
protegees = []                 # adresses ou plages publiques jamais visées (pairs du maillage, Freebox, box…)
```

## Riposte graduée

Réponse graduée **défensive** (#3723, spec 2026-11-19) : rien n'est émis vers l'attaquant ; gk3 **propose** des gestes
du catalogue, que seul gk2 applique (`ai-ban`, exécution en tâche 7). Le **code** fixe le niveau et les gestes sur
des chiffres ; le texte du modèle n'entre ni dans un niveau, ni dans une proposition, ni dans un motif.

- **Couches** (`veille/riposte.py`) : `menaces` de sbx-authwatch → `auth`, de sbxwaf → `waf` (SYN sans état → `nft`,
  `dpi` → `dpi`) ; leurre (`leurre`, `honeypot`, essais d'un leurre de service) → `leurres` ; `dns` ; `garde`. Ne
  comptent pas : décisions de gk2 (bans, réévaluations), `actord`, `mesures`, `campagnes`, familles neutres — dont
  `leurre_redirige` (adresse servie par le leurre de la box : jamais hostile, ni preuve d'une règle, pas de boucle
  leurre → ban). **Web seul** = couches ⊆ {waf, leurres} et tout vient de sbxwaf.
- **Niveau** (`dossiers.niveau`, `niveau_depuis`, `signaux_json`) : `contenir` dès 20 tentatives (24 h), 2 couches ou
  une preuve `critical` ; `usager` dès une récidive (`retour_apres_ban`), une campagne avec 100 tentatives ou 3
  couches. Monte dès que la cible le dépasse ; redescend à `observer` après 6 h sans preuve (preuves soldées, aucun
  geste défait). Seuils : `/etc/secubox/ai/riposte.toml`.
- **Propositions** (table `propositions`, dossiers d'acteur seulement) : `contenir` → `ban` 24 h si l'adresse a des
  preuves de 2 sources ou 2 étapes, sinon `limiter` 6 h ; `usager` web seul → `leurre` 24 h ; `usager` autre → `ban`
  96 h (retour après la fin d'un ban : NOUVEAU ban, durée de récidive de gk2), `ban_bloc` 24 h si le cas sûr local
  est vrai (`veille/cas_sur.py`, mêmes `CATEGORIES_SURES` et `SEUIL_BLOC` que gk2). Un ban d'adresse d'office porte
  la durée que gk2 imposera (`duree_recidive` : 24 h × 4 par ban V2 précédent, 7 j au plus, relu dans `gestes_ia.py`).
  Une seule vivante par (geste, cible) ; jamais une cible protégée (non publique, box, `protegees`) ; jamais de levée ;
  plafonds de la politique ; expiration `expiration_min`. Chaque proposition admise : une ligne `audit_chaine` et une
  ligne `audit.log` (`ai-riposte-proposition`).
- **Compatibilité avec gk2** : une adresse **IPv6** n'est jamais bannie ni partagée (`/ai/ban` : IPv4 publique ou /24
  exact) — `contenir` → `limiter` 6 h, `usager` → `leurre` si web seul, sinon `limiter` 24 h. Tant qu'un ban V2 de
  l'adresse ou de son bloc est **en vol** (proposé, approuvé, envoyé) : rien de neuf, on attend. Un ban V2 **fait et
  actif** : `prolonger` ce ban (fin de récidive, 7 j au plus, jamais plus courte, une prolongation au plus tant
  qu'elle court ; colonne `reference` = proposition du ban ; fin vivante = fin du ban repoussée par ses prolongations
  faites ; un ban levé par une levée V2 faite n'est plus vivant ni compté en récidive), jamais de `leurre` sur une adresse bannie ; `partager` (7 j, campagne ou outil ≥ 2 traits) n'est proposé
  **qu'à ce moment-là**, jamais à côté d'un ban encore en vol ni pour une adresse servie par le leurre.
- **Limites acceptées (V0)** : une proposition expirée n'est reproposée qu'avec de nouvelles preuves (le dossier doit
  être recalculé) ; la redescente va directement à `observer` (pas de palier par palier).
- **Politiques** : `/etc/secubox/ai/politiques.toml`, relu à chaque passe par double tampon (ombre, validation,
  bascule) ; fichier absent, invalide, lien ou inscriptible : la politique précédente reste, audit
  `politiques-invalides` une fois par contenu fautif ; sans politique valide depuis le démarrage : politique fermée.

```toml
version = 1
[defauts]
mode = "hybride"          # "observation" : rien n'est proposé
refuser_inconnu = true    # obligatoire
expiration_min = 120
[gestes.ban]              # idem ban_bloc, prolonger, limiter, leurre, partager, unban
actif = true
auto = true
[suspension]
automatique_suspendu = false
[plafonds.ban]            # au plus ceux de gk2 : ban 60/400, ban_bloc 5/20, prolonger 30/100, limiter 60/400,
heure = 60                # leurre 30/200, partager 30/200 (heure/jour)
jour = 400
```

## Socket et ports

- `/run/secubox/ai.sock` : API (0660, groupe `secubox`, servie à nginx). Aucun port TCP.
- `/run/secubox-ai/moteur.sock` : moteur local (0770, groupe `secubox-ai`).
- Aucune exposition publique : ni vhost, ni nom, ni route WAF. La page est servie par la racine statique du vhost
  d'administration (`/usr/share/secubox/www/ai/`).

## Configuration

| Fichier | Propriétaire | Rôle |
|---|---|---|
| `/etc/secubox/ai.toml` | root 0644 | configuration fixe, copiée de `/usr/share/secubox/ai/ai.toml.example` au premier passage seulement |
| `/etc/secubox/ai/politiques.toml` | root 0644 | politiques de réponse (§ Riposte graduée), déposées si absentes, jamais écrasées |
| `/etc/secubox/ai/riposte.toml` | root 0644 | seuils de la riposte (`n2_tentatives`, `n3_tentatives`, `fenetre_s`, `calme_s`), déposés si absents |
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

**Moteur local, mémoire et fils (0.1.2)** : `moteur.contexte = 0` (défaut) = contexte automatique, calculé sur la
mémoire disponible (4 096 à 32 768 jetons). Une installation existante qui a enregistré l'ancien défaut `4096`
le garde (donnée de l'usager, jamais réécrite) : remettre `0` pour l'automatique. `moteur.threads = 0` (défaut) =
tous les coeurs disponibles (`-t`) ; un nombre 1..64 enregistré reste honoré. MemoryMax = poids + cache(contexte) +
surcoût, surcoût = max(640 Mo, 0,35 × poids) (mesuré sur gk3 : environ 600 Mo pour un 1B à 4 096 ; l'ancien
300 Mo laissait le cgroup à son plafond, qui évince les pages du modèle). La même valeur sert au refus mémoire et au
contexte automatique.

**Clés de préférences inertes** (arbitrage R15) : gardées pour que la page du POC ne reçoive pas de 422, mais sans
aucun effet dans ce paquet — `moteur.backend`, `moteur.paralleles`, `moteur.couches_gpu`,
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
| `GET /menaces/releve` | relevé des menaces de gk2 ; `resume_en_cours` (tâche réellement en cours, sinon null), `resume_tache`, `resume_etat`, `resume_echec` (texte d'un échec ou d'un arrêt, #3811) |
| `GET /menaces/pays` | tendances par pays du Radar (#3811) : `{pret, calcule, pays_tendances}` ; `pays_tendances.colonnes.{alertes,bans}` = `pays` (aujourd'hui, hier et J-7 à la même heure, `serie7`, drapeaux « hors top 5 »), `jour` (`auj`, `hier`, `j7` : 24 valeurs horaires, null sans échantillon à ±15 min ; `maintenant`), `hier_dispo`, `j7_dispo` ; calcul de fond (60 s), jamais par requête |
| `GET /menaces/chaine` | chaîne d'attaque (#3811) : `{pret, calcule, chaine}` ; `chaine` = `entonnoir` (attaquants par étape, 24 h), `acteurs`, `enchainees_2`, `dossiers` (12 au plus : clé, gravité, adresses, outils, étapes avec règles, nombre de preuves, heures et première preuve), `campagnes` (5 au plus), `tronque` ; `disponible: false` + `raison` si veille.db est absente |
| `GET /menaces/series` | `fenetre=1h` ou `3h` (défaut) ; séries du relevé (#3811) : nouvelles alertes par catégorie et par tranche de 10 min (null = aucun écart mesuré), bans actifs, blocs /24, tuiles |
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

- Debian : `secubox-core (>= 1.8.35~)`, `secubox-zia-llm (>= 0.3.0~)` (llama-server statique,
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
