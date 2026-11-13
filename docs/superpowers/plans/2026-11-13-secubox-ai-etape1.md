<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# secubox-ai — étape 1 (socle) : plan d'implémentation

> **Pour les agents :** sous-compétence REQUISE : superpowers:subagent-driven-development (recommandée) ou
> superpowers:executing-plans, tâche par tâche. Les étapes utilisent des cases `- [ ]`.

**But :** livrer sur gk3 le paquet `secubox-ai` (socle de la suite IA du POC gk0) : dialogue, Mémoire, Historique,
Menaces, Code, Documents, Modèles, Préférences, Médias, Journal, moteur local CPU + moteur distant gk0.

**Architecture :** une API FastAPI découpée par domaine (`api/*.py`), servie sur `/run/secubox/ai.sock` sous
l'utilisateur `secubox-ai` (AppArmor enforce) ; un moteur local `llama-server` (unité `secubox-ai-moteur`, utilisateur
`secubox-ai-moteur`) piloté par le contrôleur root `secubox-aictl` via fichiers de demande (patron SearXNG #3581) ; un
moteur distant = service d'entrée à clé sur gk0. La page du POC est reprise sous `/ai/`.

**Pile :** Python 3.13 (trixie), FastAPI, httpx, uvicorn, SQLite FTS5, poppler-utils (`pdftotext`), llama.cpp statique.

**Spec :** `docs/superpowers/specs/2026-11-13-secubox-ai-module-design.md` (décisions du 2026-11-13 comprises).
**Référence de comportement :** `~/poc-secubox-ai/relais/relais.py` et `relais/index.html` (gk0). « Porter X » veut
dire reprendre la fonction nommée du POC **avec son comportement**, en n'adaptant que ce que la tâche dit.

## Contraintes globales

- Paquet `packages/secubox-ai/`, version `0.1.0-1~trixie1`, `debhelper-compat (= 13)`, `Standards-Version: 4.6.2`,
  `Architecture: all` ; en-tête SPDX CMSD-1.0 sur **tout** fichier (`scripts/license-headers.py`).
- Socket `/run/secubox/ai.sock` ; préfixe d'API `/api/v1/ai` (identique au POC : la page n'a pas à changer ses URL).
- **Toute route** : `require_jwt` (`from secubox_core.auth import require_jwt`), sauf `GET /health`.
- Utilisateurs dédiés `secubox-ai` (API) et `secubox-ai-moteur` (llama-server) ; jamais root.
- Données `/var/lib/secubox/ai/` (0750 secubox-ai) ; préférences modifiables `/var/lib/secubox/ai/preferences.toml`
  (écriture atomique, double tampon) ; configuration fixe `/etc/secubox/ai.toml` (root, lue seulement) ; clé distante
  `/etc/secubox/secrets/ai/distant.key` (0640 root:secubox-ai).
- Journal du module : ni question, ni réponse, ni titre de document, ni adresse lue (règle du POC).
- Moteur local : réserve mémoire **512 Mo** ; refuse de démarrer si `MemAvailable − 512 Mo` < poids + cache du
  contexte minimal (4 096) ; n'arrête jamais un autre service ; `MemoryMax` = poids + cache du contexte + 300 Mo.
- Contexte automatique : bornes **4 096 – 32 768**.
- Tests : `pytest` depuis la racine du dépôt (`.venv`), un fichier `tests/test_<domaine>_3583.py` par tâche.
- Commits : `type(ai): message (ref #3583)` + `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.

## Points de relecture (non couverts par la spec, les plus probables)

1. Moteur distant qui répond à `/health` puis coupe au milieu d'un flux → l'événement `erreur` arrive, le travail
   passe à fini, aucune tâche ne reste « en cours » (test : Tâche 8).
2. Préférences invalides écrites à la main dans `preferences.toml` → le module démarre avec les défauts et le dit
   dans `/status`, sans planter (test : Tâche 2).
3. gk2 injoignable pour les Menaces → relevé avec `erreurs` non vide, aucun résumé IA lancé sur un relevé vide (test :
   Tâche 10).
4. Deux onglets qui lancent la même analyse → deux tâches distinctes, aucune ne corrompt l'autre (test : Tâche 5).
5. Clé distante absente ou illisible → moteur distant « non configuré », jamais d'appel sans clé (test : Tâche 4).

---

### Tâche 1 : squelette du paquet et garde des routes

**Fichiers :** créer `packages/secubox-ai/{README.md,api/__init__.py,api/main.py,menu.d/130-ai.json,debian/control,
debian/rules,debian/changelog,debian/source/format,tests/test_socle_3583.py}`.

**Interfaces — produit :** `api.main.app` (FastAPI) ; `api.main.ROUTEUR = APIRouter(prefix="")` incluant les routeurs
des tâches suivantes par `app.include_router(<module>.routeur)`.

- [ ] Écrire `test_toute_route_est_gardee` : pour chaque route de `app.routes` sauf `/health`, une dépendance
  `require_jwt` est présente (`assert dep.call is require_jwt`) ; et `test_health` : `GET /health` →
  `{"status": "ok", "module": "ai"}`.
- [ ] Le lancer : échec (module absent).
- [ ] Écrire `api/main.py` (app, `/health`, `/status` gardé renvoyant `{"module": "ai", "version": …, "moteur": …}`),
  `debian/control` (Depends : `secubox-core (>= 1.8.30~)`, `python3-fastapi`, `python3-httpx`, `uvicorn`,
  `poppler-utils`, `sqlite3`, `secubox-zia-llm (>= 0.3.0~)`), `menu.d/130-ai.json` (`id "ai"`, `path "/ai/"`,
  `category "apps"`, icône 🧠).
- [ ] Tests verts ; commit `feat(ai): squelette du paquet secubox-ai (ref #3583)`.

### Tâche 2 : préférences (double tampon) et configuration fixe

**Fichiers :** créer `api/reglages.py`, `conf/ai.toml.example`, `tests/test_reglages_3583.py`.

**Interfaces — produit :** `ETAT: Path` (variable `SECUBOX_AI_ETAT`, défaut `/var/lib/secubox/ai` : toutes les tâches
y rangent leurs données) ; `DEFAUTS: dict`, `BORNES`, `CHOIX` (repris du POC, plus `memoire`, `menaces`,
`outils.sources_max_jetons`) ; `lire_prefs() -> dict` ; `valider(entree: dict) -> dict` (HTTPException 422) ;
`ecrire_prefs(prefs: dict) -> None` ; `config() -> dict` (lit `/etc/secubox/ai.toml` : `[distant] url`,
`[gk2] menaces_url = "https://admin.gk2.secubox.in/api/v1"`, `sources_url`, `[moteur_local] modele`) ;
routes `GET /preferences`, `PUT /preferences`. Chemins pris de `SECUBOX_AI_ETAT` (défaut `/var/lib/secubox/ai`) pour
les tests.

- [ ] Tests : `moteur.contexte = 0` accepté ; `65536` refusé (422) ; clé inconnue 422 ; écriture atomique (pas de
  fichier partiel si `tomllib.loads` échoue) ; **fichier corrompu → `lire_prefs()` rend les défauts et
  `etat_prefs()["erreur"]` le dit** (point de relecture 2).
- [ ] Porter `DEFAUTS`, `BORNES`, `CHOIX`, `lire_prefs`, `_toml`, `ecrire_prefs`, `valider` (relais.py) vers le
  nouveau chemin ; `ecrire_prefs` via fichier `.tmp` + `os.replace`.
- [ ] Tests verts ; commit.

### Tâche 3 : contexte automatique (en-tête GGUF sans dépendance)

**Fichiers :** créer `api/contexte_auto.py`, `tests/test_contexte_auto_3583.py`.

**Interfaces — produit :** `lire_meta_gguf(chemin: Path, cles: set[str]) -> dict` (lecteur GGUF v3 minimal : en-tête,
paires clé/valeur, types scalaires, chaînes et tableaux ; s'arrête avant les tenseurs) ; `kv_par_jeton(chemin) ->
tuple[int | None, int | None]` ; `contexte_auto(chemin, dispo_mo: int, memoire_max_mo: int, reserve_mo=512) -> int`.

- [ ] Tests (fichiers GGUF synthétiques écrits par le test) : métadonnées qwen35 (`block_count 33`, `head_count_kv 4`,
  `key_length 256`, `value_length 256`, `full_attention_interval 4`) → **32 768 octets/jeton** ; llama 3B
  (`28`, `8`, `128`, `128`, sans intervalle) → **114 688** ; `contexte_auto` borné à 4 096 et 32 768 ; en-tête illisible
  → 4 096.
- [ ] Porter `kv_par_jeton` / `contexte_auto` du POC en remplaçant `gguf.GGUFReader` par `lire_meta_gguf`.
- [ ] Tests verts ; commit.

### Tâche 4 : moteurs local et distant

**Fichiers :** créer `api/moteurs.py`, `tests/test_moteurs_3583.py`.

**Interfaces — consomme :** `config()`, `lire_prefs()`. **Produit :** `class Moteur` (`nom: "local"|"distant"`,
`client(delai) -> httpx.AsyncClient`) ; `async choisir(force: str | None = None) -> Moteur` ; `async assurer_moteur()
-> Moteur` (local : dépose la demande `demarrer` et attend `/health` ≤ 180 s ; distant : `POST {url}/moteur/demarrer`
puis attend) ; `async contexte_reel() -> int` ; `async compter_tokens(texte) -> int` ; `async etat() -> dict` (dit
quel moteur répond) ; route `GET /moteur`, `POST /moteur/{local|distant|auto}` (forçage dans les préférences).
Local = `httpx.AsyncHTTPTransport(uds="/run/secubox-ai/moteur.sock")` ; distant = `base_url=config["distant"]["url"]`,
en-tête `Authorization: Bearer <clé>` lue dans `distant.key`.

- [ ] Tests (`httpx.MockTransport`) : distant déclaré et `/health` 200 → distant ; distant muet (délai 2 s) → local ;
  forçage respecté ; **clé absente → distant « non configuré », aucun appel émis** (point 5) ; la clé n'apparaît dans
  aucun journal (`caplog`).
- [ ] Porter `client_moteur`, `attendre_moteur`, `assurer_moteur`, `contexte_reel`, `compter_tokens` en les
  paramétrant par le `Moteur` choisi.
- [ ] Tests verts ; commit.

### Tâche 5 : tâches de fond, travaux en cours, Tout arrêter

**Fichiers :** créer `api/taches.py`, `tests/test_taches_3583.py`.

**Interfaces — consomme :** `assurer_moteur`, `Moteur.client`. **Produit :** `TACHES`, `TRAVAUX`, `class FilSuivi`,
`nouvelle_tache(genre, titre) -> str`, `etape(t, texte)`, `finir(t, etat, resultat)`, `lancer_tache(t, coro, delai)`,
`async demander_modele(systeme, utilisateur, max_tokens=400, t=None) -> str` (flux, `return_progress`, progression
`lecture/ecriture/attente`) ; routes `/taches/{t}`, `/taches/{t}/arreter`, `/travaux`, `/travaux/{id}`,
`/travaux/{id}/arreter`, `/tout-arreter`.

- [ ] Tests : arrêt → `etat "arrete"` et résultat partiel gardé + mention ; dépassement → `"echec"`, partiel gardé ;
  « Voici le résumé : » retiré en tête ; `/tout-arreter` annule tâches et travaux ; **deux tâches simultanées gardent
  chacune leurs étapes** (point 4) ; `demander_modele` remplit `progression` depuis `prompt_progress` puis les jetons.
- [ ] Porter `nouvelle_tache`, `etape`, `finir`, `lancer_tache`, `FilSuivi`, `purger_travaux`, `travaux_liste`,
  `travail_lire`, `travail_arreter`, `tout_arreter`, `tache_lire`, `tache_arreter`, `demander_modele`. Sans génération
  d'image à l'étape 1 : `tout_arreter` ignore `ENCOURS`.
- [ ] Tests verts ; commit.

### Tâche 6 : recherche et lecture de pages (garde SSRF)

**Fichiers :** créer `api/recherche.py`, `tests/test_recherche_3583.py`.

**Interfaces — produit :** `async telecharger(url) -> str` ; `async lire_page(url) -> str` ; `termes(q) -> list[str]` ;
`passages(texte, mots) -> str` ; `controler_reponse(texte, bloc) -> tuple[str, list, list]` ;
`async recherche_fiable(question, prefs, sources, suivi) -> tuple[str, str]` ; outils `outil_secubox` (URL
`config()["gk2"]["sources_url"]`), `outil_wikipedia`, `outil_searxng` (par le moteur distant `/search`, absent si
distant indisponible), `outil_heure`.

- [ ] Tests : `telecharger` refuse `http://127.0.0.1/`, `http://10.0.0.1/`, `http://x:8080/`, et une redirection vers
  une adresse privée ; `controler_reponse` retire une adresse absente des sources ; le budget respecte
  `outils.sources_max_jetons`.
- [ ] Porter les fonctions nommées (et `MOTS_VIDES`, `_plat`, `pertinent`, `consigne_sources`, `regler_lucidite`).
- [ ] Tests verts ; commit.

### Tâche 7 : Mémoire et Historique

**Fichiers :** créer `api/memoire.py`, `tests/test_memoire_3583.py`.

**Interfaces — produit :** `memoire_ajouter(...)`, `memoire_chercher(question, budget_car=7000, compter=False)`,
`bloc_memoire(passages)`, `CONSIGNE_MEMOIRE`, `DECLENCHEUR_MEMOIRE`, `historique_ajouter(genre, titre, texte, sources)` ;
toutes les routes `/memoire*`, `/memoire-export`, `/memoire-import`, `/memoire-reglage`, `/historique*`.

- [ ] Tests : FTS sans accents (« essai » trouve « d’essai ») ; correction prioritaire en tête ; `tout-oublier` exige
  `OUBLIER` ; export puis import restitue le même nombre ; historique : ajout, liste, `memoriser` crée une réponse,
  `oublier` efface ; **import d'un fichier du POC gk0** (format `secubox-ai-memoire/1`) accepté.
- [ ] Porter le bloc « Mémoire » et le bloc « Historique » du POC (base `ETAT/memoire.db`).
- [ ] Tests verts ; commit.

### Tâche 8 : dialogue en flux (Essai), Continuer, reprise

**Fichiers :** créer `api/dialogue.py`, `tests/test_dialogue_3583.py`.

**Interfaces — consomme :** tâches 4, 5, 6, 7 (`memoire_chercher`, `bloc_memoire`, `historique_ajouter`).
**Produit :** route `POST /essai/flux` (NDJSON) ; `SUITES`, `suite_demandee(corps) -> tuple[dict|None, str]`.

- [ ] Tests (moteur simulé) : ordre `travail → lucidite → memoire → … → generation → lecture → texte → bilan` ;
  `fin "length"` → `bilan.suite` non nul ; `{"suite": id}` reprend avec le contexte gardé et le texte complet au
  contrôle ; suite expirée → 404 ; **le moteur coupe en plein flux → événement `erreur`, travail fini** (point 1) ;
  la réponse est ajoutée à l'historique ; le journal ne contient pas la question.
- [ ] Porter `essai_flux` (et `travail`, `mener`, `flux`) : retirer `public`, `HOTE_PUBLIC`, `ROUTES_ZIA`, les quotas
  publics ; `travail_id` toujours créé ; `return_progress` et `sources_max_jetons` conservés.
- [ ] Tests verts ; commit.

### Tâche 9 : Documents

**Fichiers :** créer `api/documents.py`, `tests/test_documents_3583.py`.

**Interfaces — consomme :** tâches 4, 5, 6, 7. **Produit :** routes `POST /documents`, `POST /documents/fichier`,
`POST /documents/{id}/analyser` ; `extraire_document(chemin, ctype)`, `decouper(pages, taille)`,
`taille_morceau(ctx)`.

- [ ] Tests : corps > 100 Mo → 413 et fichier temporaire effacé ; PDF sans titre → nom du fichier ; HTML : texte
  d'`<article>` ; `taille_morceau(4096) == 5990`, `taille_morceau(32768) == 74800` ; texte plafonné à 3 000 000
  caractères avec `tronque: true`.
- [ ] Porter le bloc « Documents » (`DOC_TMP = ETAT/documents`, 0700).
- [ ] Tests verts ; commit.

### Tâche 10 : Menaces (gk2 en lecture seule, double tampon)

**Fichiers :** créer `api/menaces.py`, `tests/test_menaces_3583.py`.

**Interfaces — consomme :** tâches 4, 5, 7. **Produit :** routes `/menaces/releve`, `/menaces/resumer`,
`/menaces/demander` ; `releve_menaces`, `faits_menaces`, `controler_resume`, `filtrer_propositions`,
`relire_contre_faits`, veille de fond (relevé 120 s, résumé auto si moteur actif et libre).

- [ ] Tests (repris des essais du 2026-11-13) : « 950 bans » signalé, « 92 » toléré pour 91,9 ; « Chine » signalée si
  `CN` absent ; « en hausse » signalé sans évolution ; propositions : bloc absent retiré, adresse de la box
  (`82.67.100.75` vue comme vhost) retirée, `authwatch` → sa signature, outil ambigu retiré ; **gk2 injoignable →
  `erreurs` non vide et `/menaces/resumer` répond 503 sans lancer le modèle** (point 3) ; instantanés relus au
  redémarrage.
- [ ] Porter le bloc « Menaces » (instantanés `ETAT/instantanes-menaces.json`).
- [ ] Tests verts ; commit.

### Tâche 11 : Code

**Fichiers :** créer `api/code.py`, `tests/test_code_3583.py`.

- [ ] Tests : action inconnue 404 ; code > 200 000 caractères 413 ; `langue` assainie (`"py;rm"` → `"pyrm"`) ; règles
  de la mémoire jointes quand la mémoire est active.
- [ ] Porter `CONSIGNES_CODE`, `travail_code`, `code_lancer`. Tests verts ; commit.

### Tâche 12 : Modèles, Médias, Journal

**Fichiers :** créer `api/modeles.py`, `api/medias.py`, `api/journal.py`, `tests/test_modeles_medias_3583.py`.

**Interfaces — produit :** catalogue, liste des installés (`ETAT/modeles/*.gguf`, liens symboliques refusés),
téléchargement Hugging Face avec empreinte, activation (préférences + demande `redemarrer` au contrôleur) ;
médias (`ETAT/medias/{generes,entree}`) ; `journal(action, **champs)` dans `ETAT/journal.jsonl`.

- [ ] Tests : nom de modèle avec `/` ou `..` refusé ; empreinte fausse → fichier `.faux` et 409 ; `journal` refuse les
  champs `question`, `texte`, `titre`, `url` (ValueError).
- [ ] Porter les blocs « Modèles », « Médias », `journal`. Tests verts ; commit.

### Tâche 13 : contrôleur root et unités

**Fichiers :** créer `sbin/secubox-aictl`, `systemd/secubox-ai.service`, `systemd/secubox-ai-moteur.service`,
`systemd/secubox-ai-demandes.{path,service}`, `tests/test_aictl_3583.py`.

**Interfaces — produit :** `secubox-aictl preparer | demarrer | arreter | redemarrer | etat --json | cle-distante |
demandes` ; codes : 0 fait, 2 refus d'usage, 4 **mémoire insuffisante** (message clair), 5 occupé. Demandes déposées
par l'API dans `/run/secubox-ai/demandes/` (patron `searxngctl reload --demandes`). `demarrer` calcule le contexte
(Tâche 3), écrit `/run/secubox-ai/moteur.env` (`MODELE`, `CTX`, `MEMMAX`) puis démarre `secubox-ai-moteur.service`
(`llama-server -m $MODELE -c $CTX -t 4 --jinja --no-webui --host /run/secubox-ai/moteur.sock`, `MemoryMax=$MEMMAX`,
`UMask=0007`, groupe `secubox-ai`).

- [ ] Tests (fonctions importées du script) : mémoire insuffisante → code 4 et aucune unité démarrée ; `cle-distante`
  lit l'entrée standard et écrit 0640 sans jamais l'afficher ; une demande au nom invalide est ignorée et tracée.
- [ ] Écrire le script et les unités (durcissement complet du patron SearXNG ; `secubox-ai.service` :
  `AppArmorProfile=secubox-ai-api`, `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6`).
- [ ] Tests verts ; `visudo` inutile (pas de sudo) ; commit.

### Tâche 14 : page `/ai/`

**Fichiers :** créer `www/ai/index.html` (port de `relais/index.html`), `tests/test_page_3583.py`.

- [ ] Tests : onglets exactement `essai, menaces, code, documents, memoire, historique, modeles, prefs, medias,
  journal` ; aucune référence à `/obliteratus`, `/image`, `/animation`, `/agents`, `/generateur`, `/voix` ; **aucun nom
  de fonction déclaré deux fois** (`function X(` unique) ; le script passe `node --check` ; la page inclut
  `/shared/sidebar.js` et `nav.sidebar` (Pattern 12) ; boutons « Écouter » absents.
- [ ] Porter la page : retirer OBLITERATUS, Générateur, Agents, Écouter et rapport audio (étape 2) ; tuile « Moteur »
  qui dit `local` ou `distant` (route `/moteur`) ; boutons `■ Local / ■ Distant / Auto`.
- [ ] Tests verts ; commit.

### Tâche 15 : empaquetage complet

**Fichiers :** `debian/{rules,postinst,prerm}`, `apparmor/secubox-ai-api`, `nginx/ai.conf`,
`tests/test_paquet_3583.py`, `README.md`, `wiki/MODULES-FR.md`, `wiki/MODULES-EN.md`.

- [ ] Tests : chaque fichier installé par `rules` existe ; `AppArmorProfile=` correspond au nom du profil ;
  `nginx/ai.conf` relaie `/api/v1/ai/` vers `unix:/run/secubox/ai.sock` (patron SearXNG) et sert `/ai/` ; le profil
  AppArmor n'autorise pas `/etc/secubox/**` en lecture (seulement les fichiers nommés et `secrets/ai/distant.key`) ;
  postinst crée `secubox-ai` et `secubox-ai-moteur`, `/var/lib/secubox/ai` 0750, charge le profil avant le démarrage.
- [ ] Écrire les fichiers ; README conforme à `MODULE-COMPLIANCE.md` (routes, socket, configuration, dépendances).
- [ ] Construire localement (`dpkg-buildpackage -us -uc -b` dans le worktree) : le `.deb` contient les chemins
  attendus (`dpkg -c`). Commit.

### Tâche 16 : llama-server statique amd64 (`secubox-zia-llm`)

**Fichiers :** `packages/secubox-zia-llm/{build-amd64.sh,build-arm64.sh,debian/control,debian/rules,debian/changelog}`.

- [ ] `build-amd64.sh` : clone **épinglé** (variable `LLAMA_TAG`, même étiquette pour les deux scripts), CPU,
  `-DGGML_NATIVE=OFF -DGGML_AVX2=ON`, statique ; sortie `bin/amd64/`. `control` : `Architecture: arm64 amd64` ;
  `rules` choisit `bin/$(DEB_HOST_ARCH)/`. Version `0.3.0-1~trixie1`.
- [ ] Construire sur gk0, `bin/amd64/llama-server --version` affiche l'étiquette ; `bash -n` sur les deux scripts.
  Commit.

### Tâche 17 : service d'entrée sur gk0 (hors dépôt)

**Fichiers (gk0, hors dépôt) :** `~/poc-secubox-ai/distant/entree.py`, unité utilisateur `poc-distant.service`,
`~/poc-secubox-ai/distant/test_entree.py`.

- [ ] Tests : sans clé → 401 ; adresse source hors liste (gk3 seulement) → 403 ; seules les routes du contrat passent
  (`/health`, `/props`, `/tokenize`, `/v1/chat/completions` en flux, `/moteur/demarrer`, `/search`) ; `/slots`,
  `/sdapi/*` → 404 à l'étape 1.
- [ ] Écrire l'entrée (FastAPI, liée à l'adresse LAN de gk0, port 8091) ; `/moteur/demarrer` appelle le relais POC
  `POST /api/v1/ai/moteur/demarrer` sur 127.0.0.1:8098 ; clé dans `~/.config/secubox-ai/distant.key` (0600).
- [ ] Tests verts ; unité active ; le relais POC reste sur 127.0.0.1.

### Tâche 18 : déploiement sur gk3

- [ ] CI : construire `secubox-ai` (all) ; publier `secubox-ai` et `secubox-zia-llm` amd64 sur apt.secubox.in.
- [ ] gk3 : `apt-get install secubox-ai` (apt seulement, sans délai) ; poser la clé (`secubox-aictl cle-distante`) ;
  télécharger le modèle local depuis l'onglet Modèles (Llama 3.2 3B Q4_K_M, empreinte relevée au téléchargement) et
  **mesurer** vitesse et mémoire ; garder ou changer le défaut d'après la mesure.
- [ ] Critères de la spec : service actif, socket, `aa-status` enforce, page `/ai/` derrière la session ; question
  répondue en local puis en distant, la page dit lequel ; `relecteur-securite` sans constat bloquant ; le conteneur
  `mail` et le kiosque répondent pendant une génération longue.
- [ ] `HISTORY.md`, `WIP.md` ; issue #3583 laissée ouverte (étapes 2 et 3).
