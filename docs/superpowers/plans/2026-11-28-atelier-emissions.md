<!--
SPDX-License-Identifier: LicenseRef-CMSD-1.0
Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
See LICENCE-CMSD-1.0.md for terms.
-->
# Atelier des émissions — plan d'implémentation

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or
> superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal :** produire sur gk0, à la demande et chaque lundi, des émissions à deux voix tirées des lectures évolutives des
campagnes et acteurs de gk2, vérifiées réplique par réplique, illustrées d'un diaporama synchronisé, publiées sur les
billets après le seul clic « Publier » du propriétaire.

**Architecture :** un service utilisateur `secubox-ai-emissions` (FastAPI sur socket Unix, aucun réseau hors sockets et
tunnel) dans `packages/secubox-ai-agents/emissions/`, branché au relais du POC par `emissions_relais.brancher(app, local)`
comme `agents_relais`. Une file mono-production enchaîne sept étapes (faits → évolutions → consigne → dialogue →
vérification → voix → montage) dont chacune écrit ses fichiers dans le brouillon (reprise idempotente). La publication
passe par l'API des billets (compte d'auteur dédié), après un balayage final bloquant.

**Tech Stack :** Python 3.13, FastAPI/Uvicorn (`--uds`), SQLite, httpx, ffmpeg, `rsvg-convert` (SVG → PNG),
`tesseract-ocr` (fra+eng), chromium headless par Playwright (capture), systemd utilisateur ; billets : Jinja + JS sans CDN.

**Spec :** `docs/superpowers/specs/2026-11-28-atelier-emissions-design.md`

## Global Constraints

- Validation humaine obligatoire : rien n'atteint les billets sans `POST /api/v1/ai/emissions/{id}/publier` déclenché
  par le clic « Publier » ; aucun chemin automatique (hebdo compris) n'appelle la publication.
- Publication publique : balayage final bloquant de TOUT le contenu (titre, chapeau, répliques dites, chronologie,
  diapositives et captures par OCR) ; une seule adresse IPv4/IPv6, un nom d'hôte interne ou un jeton → refus.
- Une réplique ✗ retirée n'est jamais dite ; ⚠ est dite et signalée ; une réplique modifiée ne refait que sa voix.
- Gemma (llama-server du relais) suspendu pendant la **seule** synthèse vocale, relance garantie (finally + contrôle
  au démarrage du service) ; pendant ce temps le relais répond 503 `{"detail": "voix en cours"}`.
- Une production à la fois (file FIFO, synthèse hebdo d'abord).
- Voix 1 = `nova`, voix 2 = `onyx` par défaut (réglables).
- Montage : pauses 0,45 s entre répliques, `loudnorm` I=−16 LUFS, MP3 128k mono 44,1 kHz.
- Médias sur le volume de données des billets (jamais `/`), garde d'espace avant envoi, PNG compressés ; MP4 seulement à
  la demande ; rétention réglable (MP4 purgés après N jours, défaut 14 ; MP3 et diapos gardés).
- Graphiques : aucune adresse IP ni nom interne ; dossiers gk2 lus en lecture seule (`/rapports`, `/rapports/{genre}/{id}`).
- Hebdo : minuterie utilisateur lundi 06:00 ; une émission de synthèse, puis une par sujet au-dessus du seuil
  (réglable, défaut 3 évolutions marquantes) ; brouillons seulement, notification, jamais de publication.
- Capture d'admin dans le périmètre : masquage des sélecteurs à risque, OCR bloquant, validation visuelle du
  propriétaire avant usage ; une capture en échec n'est pas publiable.
- Projet : français partout, en-tête SPDX CMSD-1.0 sur tout fichier créé, version `X.Y.Z-N~trixie1` montée à chaque
  paquet modifié, commits `type: message (ref #4058)` terminés par
  `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`, aucun CDN dans les pages servies, aucun secret en clair
  (jetons 0600 sous `~/.config/secubox-ai-jeton/` ou `/etc/secubox/secrets/`).

## Review Focus

1. **Échec de la synthèse vocale (worker coupé, exception, SIGTERM)** → Gemma relancé, verrou libéré, relais de nouveau
   à 200. Test : `test_gpu_relance_meme_en_echec` (Task 9).
2. **Réplique retirée par le vérificateur** → absente des fichiers voix, du MP3 et de la chronologie, présente marquée ✗
   dans le brouillon. Test : `test_retiree_jamais_dite` (Task 7, contrôle répété Task 11 `test_chronologie_sans_retiree`).
3. **Adresse ou jeton présent dans un texte ou incrusté dans une image** → publication refusée avec la liste des
   motifs, rien envoyé aux billets. Test : `test_balayage_bloque_ip_dans_png` (Task 12) et
   `test_publier_refuse_si_balayage` (Task 17).
4. **Hebdo** → produit des brouillons, n'appelle jamais `publier`. Test : `test_hebdo_ne_publie_jamais` (Task 16).
5. **Disque des billets presque plein ou MP4 non demandé** → envoi refusé (507) avant écriture, aucun MP4 produit sans
   demande. Test : `test_garde_espace_refuse` (Task 2) et `test_mp4_seulement_a_la_demande` (Task 11).

## Parallélisme

- **Vague 0 (en cours)** : Task 1 (agent parallèle, billets).
- **Vague 1, indépendantes entre elles** : Tasks 2 (après 1 seulement pour le champ chronologie), 3, 4, 8, 9, 12, 13.
- **Vague 2** : Task 5 (après 3, 4), Task 6 (après 3), Task 10 (après 9).
- **Vague 3** : Task 7 (après 3, 5, 6), Task 11 (après 8, 10, et format de Task 1).
- **Vague 4** : Task 14 (après 5–11), puis Tasks 15, 16, 17 en parallèle (17 après 2, 12, 14).
- Ordre critique : 3 → 4 → 5 → 7 → 14 → 17. Le worker GPU Voice Studio (#4057) est un préalable d'exécution de
  Task 10 en réel (les tests utilisent un faux worker sur socket).

Commande de test commune (venv local du dépôt) :
`.venv/bin/python -m pytest packages/secubox-ai-agents/tests/test_emissions_<x>.py -q`

---

### Task 1: billets-chronologie — diaporama synchronisé sur une chronologie audio — **en cours (agent parallèle)**

**Files :** `packages/secubox-billets/api/static/diaporama.js`, `packages/secubox-billets/api/templates/_diaporama.html`,
modèle et stockage du billet (`api/`), `debian/changelog` (0.15.0-1~trixie1), tests du paquet.

**Interfaces (fixées pour les autres tâches) :**
- Produces : champ de billet `chronologie` = liste JSON
  `[{"debut_s": float, "fin_s": float, "diapo": int, "replique": int}]` (`diapo` = rang du média image du billet,
  `replique` = rang de la réplique dite), triée par `debut_s`, sans chevauchement.
- Produces : à la création (`POST /admin/billets`), champ de formulaire `chronologie` (texte JSON) accepté et validé.
- Produces : quand le billet porte un `<audio>` et une chronologie, `diaporama.js` suit `timeupdate`/`seeked` de cet
  élément (défilement automatique coupé) ; sans chronologie, comportement #4049 inchangé.

- [ ] Suivi seulement : relire la PR de l'agent parallèle contre ce format avant d'engager Tasks 2 et 11.

### Task 2: Billets — compte d'auteur des émissions, garde d'espace, rétention MP4

**Files :** `packages/secubox-billets/api/routes/admin.py`, `packages/secubox-billets/api/media.py`,
`packages/secubox-billets/sbin/` (outil de création du compte), `packages/secubox-billets/tests/test_emissions_4058.py`,
`debian/changelog`, `README.md`.

**Interfaces :**
- Consumes : Task 1 (`chronologie`).
- Produces : `media.espace_suffisant(octets: int, marge: int = 512 * 1024**2) -> bool` (sur le volume de `media_dir()`).
- Produces : `media.purger_mp4(jours: int) -> int` (nombre purgé ; MP3 et images intouchés), lancé par la minuterie
  existante du paquet ; réglage `retention_mp4_jours = 14` dans `/etc/secubox/billets.toml`.
- Produces : `secubox-billets-auteur-emissions` crée l'auteur `emissions` et écrit son jeton dans
  `/etc/secubox/secrets/billets-emissions.jeton` (0600) ; `create` répond 507 si `espace_suffisant` est faux.

- [ ] Test : `test_garde_espace_refuse` — avec `espace_suffisant` forcé à faux, `POST /admin/billets` avec un MP3
  renvoie 507 et `list(media_dir().iterdir()) == []` ; `test_purge_mp4_garde_mp3` — après `purger_mp4(14)` sur un
  MP4 daté de 15 jours et un MP3 de 30 jours : `mp4 absent`, `mp3 présent`, retour `== 1`.
- [ ] Voir échouer : `.venv/bin/python -m pytest packages/secubox-billets/tests/test_emissions_4058.py -q`.
- [ ] Implémenter (`shutil.disk_usage`, tri par `st_mtime`).
- [ ] Vert, puis `scripts/avant-commit.sh`.
- [ ] Commit `feat(billets): auteur des émissions, garde d'espace, rétention MP4 (ref #4058)`.

### Task 3: Vérificateur — copie versionnée de `verif_rapport.py`

**Files :** `packages/secubox-ai-agents/emissions/__init__.py`, `packages/secubox-ai-agents/emissions/verif_rapport.py`
(copie à l'identique), `packages/secubox-ai-agents/tests/test_emissions_verif.py`.

**Interfaces :**
- Produces : `emissions.verif_rapport.verifier(texte: str, dossier: dict) -> dict` et `Contexte`, inchangés.

- [ ] Test : `test_copie_identique` — `sha256(copie) == sha256(packages/secubox-waf-ng/composants/waf/api/verif_rapport.py)` ;
  `test_verifier_repond` — sur un dossier minimal, `verifier(...)["taux_retenues_pct"]` est un `int`.
- [ ] Voir échouer, copier, vert (le test d'empreinte casse dès qu'une copie diverge : on recopie, on ne patche pas).
- [ ] Commit `feat(ai-emissions): vérificateur partagé avec gk2 (ref #4058)`.

### Task 4: Magasin des lectures évolutives (SQLite) et amorçage

**Files :** `packages/secubox-ai-agents/emissions/magasin.py`, `tests/test_emissions_magasin.py`.

**Interfaces :**
- Produces : `Magasin(chemin: Path)` ; tables
  `interpretations(id, sujet TEXT, quand INTEGER, phrase TEXT, statut TEXT, empreinte TEXT)` et
  `dossiers(sujet TEXT, empreinte TEXT, quand INTEGER, contenu TEXT, PRIMARY KEY(sujet, empreinte))` ;
  `sujet` = `"<genre>/<ident>"`, `statut ∈ {"verifiee","hypothese"}`.
- Produces : `retenir(sujet: str, dossier: dict, gardees: list[dict]) -> None`,
  `dernier_valide(sujet: str) -> dict | None`, `interpretations(sujet: str) -> list[dict]`,
  `amorcer(rapports: list[dict]) -> int` (rapports `etat == "ia"` déjà vérifiés sur gk2).

- [ ] Test : `test_retenir_puis_dernier` — après deux `retenir`, `dernier_valide(s)["genere_le"]` est celui du second ;
  `test_amorcer_idempotent` — `amorcer(x)` deux fois → second retour `== 0`.
- [ ] Voir échouer, implémenter (empreinte = `rapports.signature`-like : sha256 du JSON trié), vert.
- [ ] Commit `feat(ai-emissions): magasin des lectures évolutives (ref #4058)`.

### Task 5: Évolutions d'un sujet

**Files :** `packages/secubox-ai-agents/emissions/evolutions.py`, `tests/test_emissions_evolutions.py`.

**Interfaces :**
- Consumes : `Magasin.dernier_valide`.
- Produces : `evolutions(courant: dict, precedent: dict | None, maintenant: float) -> list[dict]`, chaque fait
  `{"genre": str, "texte": str, "marquant": bool}` avec `genre ∈ {"nouvelle_vague","extinction","operateur_nouveau",
  "retour_acteur","phase","chiffre"}` ; `precedent is None` → un seul fait `genre="premiere_lecture"`.
- Règles : `extinction` si aucun ban depuis ≥ 7 jours alors qu'il y en avait ; `retour_acteur` si réapparition après
  extinction ; `chiffre` marquant si écart ≥ 25 %. Aucun texte ne contient d'adresse (filtre `_sans_adresse`).

- [ ] Test : `test_retour_acteur_premiere_classe` (dossier éteint puis réactivé → un fait `retour_acteur`, `marquant`) ;
  `test_sans_changement_vide` (`evolutions(d, d, t) == []`).
- [ ] Voir échouer, implémenter, vert. Commit `feat(ai-emissions): évolutions par sujet (ref #4058)`.

### Task 6: Lecture des dossiers de gk2

**Files :** `packages/secubox-ai-agents/emissions/sources.py`, `tests/test_emissions_sources.py`.

**Interfaces :**
- Produces : `class Sources(base: str, jeton: Callable[[], str], client: httpx.AsyncClient | None = None)` ;
  `async lister() -> list[dict]` (`GET {base}/rapports`), `async dossier(genre: str, ident: str) -> dict`
  (`GET {base}/rapports/{genre}/{ident}`) ; `genre` refusé hors `("campagne","acteur")` ; **aucune méthode d'écriture**.
- Base : tunnel existant vers l'API WAF de gk2 ; jeton de lecture dédié `~/.config/secubox-ai-jeton/lecture-gk2` (0600).

- [ ] Test : `test_genre_inconnu_refuse` (`ValueError`) ; `test_get_seulement` (transport httpx factice : toutes les
  requêtes ont `method == "GET"`).
- [ ] Voir échouer, implémenter, vert. Commit `feat(ai-emissions): lecture seule des dossiers gk2 (ref #4058)`.

### Task 7: Consigne, dialogue et vérification par réplique

**Files :** `packages/secubox-ai-agents/emissions/consigne.py`, `emissions/gabarit-7-parties.txt`, `emissions/dialogue.py`,
`tests/test_emissions_dialogue.py`.

**Interfaces :**
- Consumes : `evolutions`, `verif_rapport.verifier`, socket du moteur (`SECUBOX_AI_AGENTS_MOTEUR`).
- Produces : `consigne(sujets: list[dict], faits: list[dict], gabarit: str) -> str` (règles impératives : pas
  d'attribution à un hébergeur, pas d'opération d'État, distinguer bans/attaques/incidents, pas de ton publicitaire).
- Produces : `decouper(sortie: str) -> list[dict]` → `[{"rang": int, "voix": 1|2, "texte": str}]` (lignes `V1:`/`V2:`).
- Produces : `verifier_repliques(repliques: list[dict], dossier: dict) -> list[dict]` ajoutant
  `statut ∈ {"verifiee","ia_seule","retiree"}` et `motifs` ; une réplique sans affirmation chiffrée (transition,
  question) est `verifiee` ; une phrase retirée dans la réplique → réplique `retiree`.
- Produces : `async ecrire(consigne: str) -> str` (appel au moteur local, délai 300 s).

- [ ] Test : `test_decouper_v1_v2` ; `test_retiree_jamais_dite` — une réplique citant un chiffre absent du dossier
  obtient `statut == "retiree"` et `dites(repliques)` (filtre exporté) ne la contient pas ; `test_question_admise`.
- [ ] Voir échouer, implémenter, vert. Commit `feat(ai-emissions): dialogue vérifié réplique par réplique (ref #4058)`.

### Task 8: Graphiques et association des diapositives

**Files :** `packages/secubox-ai-agents/emissions/graphiques.py`, `tests/test_emissions_graphiques.py`.

**Interfaces :**
- Produces : `graphiques(dossier: dict) -> list[dict]` → `[{"id": str, "svg": str, "chiffres": list[str],
  "termes": list[str]}]` (bans par jour, phases, opérateurs ; palette SecuBox ; zoom = fenêtre de dates ou barre
  mise en avant).
- Produces : `png(svg: str, sortie: Path) -> Path` (`rsvg-convert`, puis compression `-z` sans perte si disponible).
- Produces : `associer(repliques: list[dict], graphs: list[dict]) -> dict[int, str]` (rang → id ; par chiffres puis
  termes cités ; sinon diapo précédente).

- [ ] Test : `test_aucune_adresse_dans_svg` (regex IPv4/IPv6 sur chaque `svg` → aucune) ;
  `test_associer_par_chiffre` (réplique citant « 1 204 » → graphique dont `chiffres` contient `"1204"`).
- [ ] Voir échouer, implémenter, vert. Commit `feat(ai-emissions): graphiques des dossiers (ref #4058)`.

### Task 9: Verrou GPU — Gemma suspendu pendant la voix

**Files :** `packages/secubox-ai-agents/emissions/gpu.py`, `packages/secubox-ai-agents/relais/emissions_relais.py`
(garde 503 seulement à ce stade), `tests/test_emissions_gpu.py`.

**Interfaces :**
- Produces : `class VerrouGPU(fichier: Path, arreter: Callable[[], Awaitable[None]], relancer: Callable[[], Awaitable[None]])`,
  gestionnaire asynchrone `async with verrou.voix(): ...` : pose le fichier verrou, arrête l'unité transitoire
  `poc-llama`, et dans `finally` relance puis retire le verrou ; `async reparer() -> bool` au démarrage (verrou présent
  sans production vivante → relance).
- Produces : dans le relais, `voix_en_cours() -> bool` (présence du verrou) ; les routes LLM du relais répondent
  503 `{"detail": "voix en cours"}` tant qu'il est vrai.

- [ ] Test : `test_gpu_relance_meme_en_echec` — corps qui lève `RuntimeError` → `relancer` appelé une fois, verrou
  absent ; `test_reparer_au_demarrage` ; `test_relais_503_voix_en_cours`.
- [ ] Voir échouer, implémenter, vert. Commit `feat(ai-emissions): Gemma suspendu le temps de la voix (ref #4058)`.

### Task 10: Voix par réplique, reprise idempotente

**Files :** `packages/secubox-ai-agents/emissions/voix.py`, `tests/test_emissions_voix.py`.

**Interfaces :**
- Consumes : worker Voice Studio par le tunnel `127.0.0.1:7443` (API de `secubox-voicestudio/api/moteur.py` :
  `dire(texte, voix, format_="mp3") -> bytes`), `VerrouGPU`.
- Produces : `async dire_tout(brouillon: Path, repliques: list[dict], voix: dict[int, str] = {1: "nova", 2: "onyx"},
  delai_s: int = 120) -> list[Path]` ; fichier `voix/<rang>-<sha256(texte+voix)[:12]>.mp3` ; existant → non refait ;
  répliques `retiree` ignorées ; un seul passage sous `verrou.voix()`.

- [ ] Test : `test_reprise_idempotente` (second appel : zéro requête au faux worker) ;
  `test_modifier_ne_refait_que_sa_voix` (une réplique changée → exactement une requête).
- [ ] Voir échouer, implémenter, vert. Commit `feat(ai-emissions): voix par réplique (ref #4058)`.

### Task 11: Montage, chronologie, MP4 à la demande

**Files :** `packages/secubox-ai-agents/emissions/montage.py`, `tests/test_emissions_montage.py`.

**Interfaces :**
- Consumes : fichiers de Task 10, association de Task 8, format de Task 1.
- Produces : `monter(fichiers: list[Path], repliques: list[dict], diapos: dict[int, str], sortie: Path)
  -> tuple[Path, list[dict]]` : concaténation avec 0,45 s de silence, `loudnorm=I=-16`, `-b:a 128k -ac 1 -ar 44100` ;
  chronologie aux durées réelles (`ffprobe`), entrées `{debut_s, fin_s, diapo, replique}`.
- Produces : `video(mp3: Path, chronologie: list[dict], images: list[Path], sortie: Path) -> Path` appelé seulement par
  la route MP4 (Task 14).

- [ ] Test (sauté si ffmpeg absent, en le disant) : `test_chronologie_sans_retiree` ; `test_pauses_045`
  (`debut_s[n+1] - fin_s[n] ≈ 0.45 ± 0.02`) ; `test_mp3_format` (ffprobe : `mp3`, 1 canal, 44100) ;
  `test_mp4_seulement_a_la_demande` (`monter` ne crée aucun `.mp4`).
- [ ] Voir échouer, implémenter, vert. Commit `feat(ai-emissions): montage et chronologie (ref #4058)`.

### Task 12: Balayage final bloquant

**Files :** `packages/secubox-ai-agents/emissions/balayage.py`, `tests/test_emissions_balayage.py`.

**Interfaces :**
- Produces : `balayer(textes: list[str], images: list[Path], noms_internes: list[str]) -> list[dict]`
  (`[{"ou": str, "motif": "ipv4"|"ipv6"|"nom_interne"|"jeton"}]`, vide = publiable) ; OCR `tesseract -l fra+eng` sur
  chaque image ; jeton = suite base64/hex ≥ 32 caractères ou motifs `eyJ`, `sk-`, `ghp_` ; `noms_internes` lus de
  `~/.config/secubox-ai-emissions/noms-internes.txt` (gk0…gk7, domaines locaux). Le texte trouvé n'est jamais recopié
  dans le résultat.
- Image illisible par l'OCR → motif `"ocr_echec"` (bloquant).

- [ ] Test : `test_balayage_bloque_ip_dans_png` (PNG rendu avec « 192.0.2.7 » → un résultat `ipv4`) ;
  `test_texte_propre_vide` ; `test_ocr_echec_bloque`.
- [ ] Voir échouer, implémenter, vert. Commit `feat(ai-emissions): balayage final bloquant (ref #4058)`.

### Task 13: Capture d'admin masquée

**Files :** `packages/secubox-ai-agents/emissions/capture.py`, `emissions/masques.toml`, `tests/test_emissions_capture.py`.

**Interfaces :**
- Consumes : `balayer`.
- Produces : `async capturer(url: str, zone: str | None, sortie: Path) -> dict` →
  `{"png": Path, "masques": int, "controle": list[dict], "etat": "a_valider"|"refusee"}` ; masquage (CSS
  `filter: blur(12px)` puis aplat) des sélecteurs de `masques.toml` (tableaux d'adresses, journaux, noms d'hôtes) ;
  `url` limitée aux pages d'admin joignables par le tunnel (liste blanche d'hôtes) ; `controle` non vide → `refusee`.
- Produces : `valider_capture(brouillon, id, accord: bool)` (validation visuelle ; seule une capture `validee` entre au
  diaporama).

- [ ] Test : `test_capture_refusee_si_ocr` (page factice locale montrant une IPv4 non couverte par un sélecteur →
  `etat == "refusee"`) ; `test_url_hors_liste_refusee`.
- [ ] Voir échouer, implémenter, vert. Commit `feat(ai-emissions): capture d'admin masquée (ref #4058)`.

### Task 14: Service, file de production et routes

**Files :** `packages/secubox-ai-agents/emissions/app.py`, `emissions/production.py`,
`packages/secubox-ai-agents/relais/emissions_relais.py`, `packages/secubox-ai-agents/systemd/secubox-ai-emissions-gk0.service`,
`sbin/secubox-ai-agents-construire` (installation), `tests/test_emissions_service.py`, `README.md`.

**Interfaces :**
- Consumes : Tasks 4–13.
- Produces : brouillon `~/.local/state/secubox-ai-emissions/brouillons/<id>/etat.json`
  (`{"id", "sources", "etape": 1..7, "etapes": [{"nom","etat"}], "repliques", "diapos", "captures", "chronologie"}`).
- Produces : `class File` (une production à la fois, `asyncio.Lock`, FIFO, priorité « synthèse ») ;
  `async produire(id: str) -> None` reprend à la première étape non `faite`.
- Produces : routes locales `/api/v1/ai/emissions/` : `GET sources`, `POST produire` `{"sources": [str], "format":
  "synthese"|"sujet"}`, `GET brouillons`, `GET {id}`, `POST {id}/replique/{rang}` (texte → revérification + sa voix),
  `POST {id}/capture`, `POST {id}/capture/{cid}/valider`, `POST {id}/mp4`, `POST {id}/publier` (Task 17), `DELETE {id}` ;
  `emissions_relais.brancher(app, local)` relaie vers `%t/secubox-ai-emissions/emissions.sock` avec la garde jeton du
  relais (local seulement, `CORPS_MAX`).
- Unité : copie du socle de durcissement de `secubox-ai-agents-gk0.service`, `RestrictAddressFamilies=AF_UNIX AF_INET`
  limité à `IPAddressAllow=127.0.0.1` (tunnel), `MemoryMax=1G`, `ExecStartPre` = `reparer()` du verrou.

- [ ] Test : `test_une_production_a_la_fois` (deux `produire` → la seconde attend, `etape` intacte) ;
  `test_reprise_apres_coupure` ; `test_routes_locales_seulement` (client non local → 403).
- [ ] Voir échouer, implémenter, vert. Commit `feat(ai-emissions): service et file de production (ref #4058)`.

### Task 15: Page `emissions.html`

**Files :** `packages/secubox-ai-agents/relais/emissions.html`, `tests/test_emissions_page.py`.

**Interfaces :**
- Consumes : routes de Task 14 ; servie par `GET /emissions` dans `brancher`.
- Produces : trois colonnes selon la maquette : gauche = sources évolutives (campagnes/acteurs, pastille « évolutions »,
  sélection multiple) ; centre = chaîne 7 étapes, lecteur `<audio>` + diaporama synchronisé (même logique que Task 1),
  dialogue marqué ✓/⚠/✗ éditable ; droite = validation (résultat du balayage, captures à valider), actions (MP4,
  Publier désactivé tant que balayage non vide ou captures non validées), réglages hebdo (seuil, voix, rétention).

- [ ] Test : `test_page_sans_cdn` (aucun `http://`/`https://` dans `src=`/`href=`) ; `test_page_spdx` ;
  `test_publier_desactive_par_defaut` (bouton `id="publier"` porte `disabled`).
- [ ] Voir échouer, implémenter, vert. Commit `feat(ai-emissions): page de l'atelier (ref #4058)`.

### Task 16: Hebdomadaire du lundi

**Files :** `packages/secubox-ai-agents/emissions/hebdo.py`, `systemd/secubox-ai-emissions-hebdo-gk0.service`,
`systemd/secubox-ai-emissions-hebdo-gk0.timer`, `tests/test_emissions_hebdo.py`.

**Interfaces :**
- Produces : `planifier_semaine(sujets: dict[str, list[dict]], seuil: int = 3) -> list[dict]` → d'abord
  `{"format": "synthese", "sources": [tous les sujets changés]}`, puis un `{"format": "sujet"}` par sujet dont
  `sum(f["marquant"])` ≥ seuil ; met en file par `POST produire` et notifie (`notify-send` utilisateur).
- Minuterie : `OnCalendar=Mon *-*-* 06:00:00`, `Persistent=true`.

- [ ] Test : `test_synthese_d_abord` ; `test_seuil` ; `test_hebdo_ne_publie_jamais` (client factice : aucune requête
  vers `/publier`).
- [ ] Voir échouer, implémenter, vert. Commit `feat(ai-emissions): émissions hebdomadaires (ref #4058)`.

### Task 17: Publication sur les billets

**Files :** `packages/secubox-ai-agents/emissions/publication.py`, `tests/test_emissions_publication.py`.

**Interfaces :**
- Consumes : `balayer` (Task 12), API billets + auteur dédié (Task 2), chronologie (Task 1), `Magasin.retenir` (Task 4).
- Produces : `async publier(brouillon: Path, billets: str, jeton: Callable[[], str]) -> dict` : refuse si captures non
  validées ou `balayer(...)` non vide (409 avec motifs) ; envoie titre, chapeau, MP3, PNG des diapos, `chronologie` ;
  sur succès, `retenir` des répliques `verifiee`/`ia_seule` (alimente les lectures évolutives) et marque le brouillon
  `publie`. Le MP4 n'est envoyé que s'il a été produit.

- [ ] Test : `test_publier_refuse_si_balayage` (aucune requête vers les billets) ; `test_publier_alimente_magasin` ;
  `test_capture_non_validee_bloque`.
- [ ] Voir échouer, implémenter, vert. Commit `feat(ai-emissions): publication après validation (ref #4058)`.
- [ ] Suivi : `HISTORY.md`, `WIP.md`, README de `secubox-ai-agents` et de `secubox-billets`.

## Auto-revue

- Couverture : objectifs 1 (Tasks 4–5, 17), 2 (14), 3 (3, 7), 4 (9–10), 5 (8, 1), 6 (11, 17), 7 (15, 17, 10),
  8 (16, 14), 9 (15), 10 (13) ; contraintes stockage (2), lecture seule gk2 (6), balayage (12) ; amorçage (4).
- Signatures recoupées : `chronologie` (1 ↔ 11 ↔ 17), `statut` des répliques (7 ↔ 10 ↔ 11 ↔ 15), `VerrouGPU` (9 ↔ 10 ↔ 14).
- Review Focus : chaque entrée a son test dans sa tâche propriétaire.
- Points ouverts : Playwright et `tesseract-ocr` sur gk0 à confirmer (sinon chromium `--headless` + CDP) ; musique
  d'habillage hors tranche (emplacement intro/outro vide dans `monter`).
