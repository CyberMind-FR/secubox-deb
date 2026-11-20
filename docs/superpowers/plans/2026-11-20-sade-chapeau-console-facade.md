<!--
SPDX-License-Identifier: LicenseRef-CMSD-1.0
Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
Source-Disclosed License — All rights reserved except as expressly granted.
See LICENCE-CMSD-1.0.md for terms.
-->

# SADE « chapeau » — console Cyber Defense Live + façade (OBSERVE puis REACTIVE au banc) : plan d'implémentation

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or
> superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Livrer dans `secubox-soc` la vue « Cyber Defense Live » et une façade d'API `/defense/*` qui lisent le
substrat réel (actord, WAF, threatmesh), d'abord en lecture seule (OBSERVE), puis avec file d'approbation (REACTIVE)
sur le banc.

**Architecture:** Aucun détecteur, corrélateur ni score nouveau. Un routeur FastAPI `defense` monté dans l'API
existante de `secubox-soc` interroge les sockets Unix du substrat et projette le score acteur sur l'échelle SADE.
La page `defense.html` est une vue de même origine ajoutée aux onglets du SOC. L'état propre à SADE (mode,
décisions, liste blanche) vit dans une base SQLite du SOC ; toute application passe par les chemins audités
existants.

**Tech Stack:** Python 3 / FastAPI (API `secubox-soc`, socket `/run/secubox/soc.sock`), SQLite, HTML/CSS/JS sans
bibliothèque (Aurora), pytest.

**Spec:** `docs/superpowers/specs/2026-11-20-sade-active-defense-design.md` (prolonge
`2026-11-19-secubox-ai-v2-riposte-graduee-design.md`). Maquette validée le 20/11 :
https://claude.ai/artifact/DHMxG19De7sMYjHJDchzJT (source : à copier depuis l'artefact en tâche 5).

## Global Constraints

- Périmètre « chapeau d'abord » : modes `observe` et `reactive` seulement ; `active` et `aggressive` sont refusés
  (HTTP 409, `cause: "gestes_non_livres"`) tant que V2 phases 4-7 ne sont pas livrées.
- Zéro action offensive ; rien n'est émis vers un attaquant. Aucune règle nft/nginx/WAF écrite par ce code.
- Le code décide sur des chiffres ; aucun appel à un modèle de langue dans ce plan.
- Seul geste applicable : le ban/unban par le chemin WAF existant, sur validation d'un administrateur (`require_jwt`).
  Jamais une adresse privée, de maillage, de passerelle ou d'administration (liste blanche prioritaire).
- Toute route porte une garde : lecture `require_lecture`, action `require_jwt`. Socket Unix, pas de port TCP.
- Chaque décision (changement de mode, approbation, refus) écrit une ligne dans `/var/log/secubox/audit.log`.
- En-tête SPDX CMSD-1.0 sur tout fichier créé. Version `secubox-soc` `1.9.0-1~trixie1`.
- Banc d'abord : REACTIVE s'essaie sur gk6, jamais sur gk2 en premier. gk2 ne reçoit que l'OBSERVE.
- Suivi : issue GitHub + worktree (`scripts/agent-worktree.sh start --issue <N>`), commits `type: message (ref #N)`.
- Bandes de score (départ, réglables) : 0-19 observer, 20-59 reactive, 60-79 contenir, 80-94 usager, 95-100 incident.

## Review Focus

- Substrat muet (socket absent, délai, 5xx) : la façade rend l'état connu avec `sources.<nom>.ok = false`, jamais
  un 500, jamais un chiffre inventé à zéro présenté comme vrai. Test en tâche 3.
- Adresse de la liste blanche proposée au ban : l'approbation est refusée (403, `cause: "liste_blanche"`), y compris
  IPv6 et adresse privée absente de la liste. Test en tâche 6.
- Double clic ou deux administrateurs sur la même proposition : une seule application, la seconde rend 409. Test
  en tâche 6.
- Changement de mode pendant qu'une approbation est en cours : une approbation reçue en `observe` est refusée
  (409, `cause: "mode"`). Test en tâche 6.
- Score hors bornes ou absent dans la réponse d'actord : la bande vaut `inconnu`, la ligne reste affichée. Test en
  tâche 2.

---

### Task 1: Relevé du substrat et lecteur de sockets

**Files:**
- Create: `packages/secubox-soc/api/substrat.py`
- Create: `packages/secubox-soc/tests/donnees/substrat/{actord_actors,actord_proposals,waf_bans,waf_bans_history,threatmesh_status,threatmesh_decisions}.json`
- Create: `packages/secubox-soc/tests/donnees/substrat/RELEVE.md`
- Test: `packages/secubox-soc/tests/test_defense_substrat.py`

**Interfaces:**
- Produces: `lire(source: str, chemin: str, entetes: dict | None = None, delai: float = 3.0) -> Lecture` où
  `Lecture = {"ok": bool, "donnees": dict | list | None, "erreur": str | None}` ;
  `SOURCES = {"actord": "/run/secubox/actord.sock", "waf": "/run/secubox/waf.sock", "threatmesh": "/run/secubox/threatmesh.sock"}`.

- [ ] **Step 1: Relever les réponses réelles (lecture seule) sur gk6**

Routes à relever : actord `/actors`, `/proposals`, `/overview` (avec le préfixe servi par `sbx-actord`,
`cmd/sbx-actord/server.go:289`) ; WAF `/bans`, `/bans/history`, `/menaces/flux`
(`composants/waf/api/main.py:1707,1799,1948`) ; threatmesh `/status`, `/peers`, `/decisions`
(`secubox-threatmesh/api/main.py:136-157`). Enregistrer chaque réponse en fixture, adresses publiques remplacées
par des adresses de documentation (203.0.113.0/24, 198.51.100.0/24). Consigner dans `RELEVE.md` : préfixe exact,
garde exigée par chaque route, champ qui porte le score 0-100 et champs d'identité d'un acteur, et **la route
d'administration du WAF qui applique un ban** (chemin, garde, corps), utilisée en tâche 6.

Décision à vérifier ici : la façade **transmet les en-têtes d'authentification de l'appelant** (`Authorization`,
`Cookie`) aux sockets du substrat. Si une route du substrat refuse ce passage, le noter dans `RELEVE.md` et
arrêter le plan à cette tâche : c'est un choix de garde à arbitrer, pas à contourner.

- [ ] **Step 2: Écrire le test qui échoue**

```python
def test_socket_absent_rend_une_lecture_ko(tmp_path, monkeypatch):
    monkeypatch.setitem(substrat.SOURCES, "waf", str(tmp_path / "absent.sock"))
    r = substrat.lire("waf", "/bans")
    assert r == {"ok": False, "donnees": None, "erreur": "socket absent"}

def test_source_inconnue_refusee():
    with pytest.raises(KeyError):
        substrat.lire("ailleurs", "/x")

def test_reponse_200_json(serveur_unix):          # fixture : petit serveur HTTP sur socket Unix temporaire
    serveur_unix.repond("/bans", 200, {"bans": []})
    assert substrat.lire("waf", "/bans") == {"ok": True, "donnees": {"bans": []}, "erreur": None}

def test_reponse_503_et_delai(serveur_unix):
    serveur_unix.repond("/bans", 503, {})
    assert substrat.lire("waf", "/bans")["ok"] is False
    serveur_unix.dort("/lent", 2.0)
    assert substrat.lire("waf", "/lent", delai=0.2)["erreur"] == "délai"
```

- [ ] **Step 3: Run** `pytest packages/secubox-soc/tests/test_defense_substrat.py -v` — attendu : FAIL (module absent).
- [ ] **Step 4: Implémenter `lire`** sur `http.client` + socket Unix (même patron que `_fetch_p2p_api`,
  `api/main.py:637`), sans dépendance nouvelle ; corps borné à 4 Mio ; aucune exception ne sort.
- [ ] **Step 5: Run** le test — attendu : PASS. **Commit** `feat(soc): lecteur du substrat SADE (ref #N)`.

### Task 2: Échelle — projection du score sur bandes et phases

**Files:**
- Create: `packages/secubox-soc/api/echelle.py`
- Test: `packages/secubox-soc/tests/test_defense_echelle.py`

**Interfaces:**
- Produces: `BANDES_DEFAUT: tuple[tuple[int, str], ...]` ;
  `bande(score: object, bandes=BANDES_DEFAUT) -> str` (`observer|reactive|contenir|usager|incident|inconnu`) ;
  `phase(b: str) -> int` (1 pour observer, 2 pour reactive, 3 pour contenir et usager et incident, 0 pour inconnu) ;
  `exige_validation(b: str) -> bool` (vrai pour `incident`).

- [ ] **Step 1: Test qui échoue**

```python
@pytest.mark.parametrize("s,b", [(0,"observer"),(19,"observer"),(20,"reactive"),(59,"reactive"),
                                 (60,"contenir"),(79,"contenir"),(80,"usager"),(94,"usager"),
                                 (95,"incident"),(100,"incident")])
def test_bornes(s, b): assert echelle.bande(s) == b

@pytest.mark.parametrize("s", [None, "", "82", -1, 101, 3.5, True])
def test_score_invalide_est_inconnu(s): assert echelle.bande(s) == "inconnu"

def test_phase_et_validation():
    assert [echelle.phase(b) for b in ("observer","reactive","contenir","usager","incident","inconnu")] == [1,2,3,3,3,0]
    assert echelle.exige_validation("incident") and not echelle.exige_validation("usager")
```

- [ ] **Step 2: Run** — FAIL. **Step 3: Implémenter** (fonctions pures, entier strict, `bool` refusé).
- [ ] **Step 4: Run** — PASS. **Commit** `feat(soc): échelle SADE score → bande → phase (ref #N)`.

### Task 3: Façade en lecture seule (OBSERVE)

**Files:**
- Create: `packages/secubox-soc/api/defense.py`
- Modify: `packages/secubox-soc/api/main.py` (monter le routeur : `app.include_router(defense.router, prefix="/defense")`)
- Test: `packages/secubox-soc/tests/test_defense_facade.py`

**Interfaces:**
- Consumes: `substrat.lire`, `echelle.bande/phase/exige_validation`, fixtures de la tâche 1.
- Produces (toutes `require_lecture`, toutes avec `"sources": {"actord": {"ok": bool}, "waf": {...}, "threatmesh": {...}}`) :
  - `GET /defense/status` → `{"mode", "menaces_suivies", "evenements_24h", "blocages_actifs", "a_valider", "score_max", "bande_max", "sources"}`
  - `GET /defense/threats` → `{"menaces": [{"id", "source", "score", "bande", "phase", "couches", "tentatives", "vu"}], "sources"}` triées par score décroissant, 200 au plus
  - `GET /defense/threats/{id}` → la menace + `"chronologie": [{"ts", "capteur", "libelle"}]`
  - `GET /defense/actions` → `{"actions": [{"ts", "cible", "geste", "origine", "ttl_s", "etat"}], "sources"}` (bans actifs + historique WAF)
  - `GET /defense/mesh` → `{"noeuds": [{"nom", "soi", "emis", "recus", "etat"}], "sources"}`
  - `GET /defense/incidents?jours=7` → `{"incidents": [{"ts", "titre", "score", "bande", "issue"}], "sources"}`

- [ ] **Step 1: Tests qui échouent** — pour chaque route : réponse nominale construite depuis les fixtures (les
  valeurs attendues se calculent à la main depuis `tests/donnees/substrat/*.json` et s'écrivent en dur dans le
  test) ; sans jeton → 401 ; et :

```python
def test_substrat_muet_ne_rend_jamais_500(client, substrat_ko):     # les trois sockets absents
    r = client.get("/defense/status", headers=LECTURE)
    assert r.status_code == 200
    j = r.json()
    assert all(v["ok"] is False for v in j["sources"].values())
    assert j["menaces_suivies"] is None and j["score_max"] is None     # None, pas 0

def test_une_source_ko_les_autres_servies(client, waf_ko):
    j = client.get("/defense/actions", headers=LECTURE).json()
    assert j["sources"]["waf"]["ok"] is False and j["actions"] == []

def test_score_absent_reste_affiche(client, acteur_sans_score):
    m = client.get("/defense/threats", headers=LECTURE).json()["menaces"]
    assert m[0]["bande"] == "inconnu" and m[0]["phase"] == 0
```

- [ ] **Step 2: Run** — FAIL. **Step 3: Implémenter** le routeur. Les lectures du substrat se font dans
  `asyncio.to_thread` ; résultat mis en cache 15 s par route (patron `CacheTTL` déjà présent, `api/main.py:99`) ;
  un rafraîchissement dégradé n'écrase pas un relevé complet plus récent de moins de 120 s (double tampon #3011).
- [ ] **Step 4: Run** — PASS. **Commit** `feat(soc): façade SADE en lecture seule (ref #N)`.

### Task 4: Mode et politique

**Files:**
- Create: `packages/secubox-soc/api/defense_etat.py`
- Create: `packages/secubox-soc/api/migrations/0001-defense.sql`
- Modify: `packages/secubox-soc/api/defense.py`
- Test: `packages/secubox-soc/tests/test_defense_mode.py`

**Interfaces:**
- Produces: base `/var/lib/secubox/soc/defense.db` ; tables `mode(id=1, valeur, depuis, par)`,
  `seuils(cle, valeur)`, `liste_blanche(cidr, motif, par, ts)`, `decisions(id, menace_id, cible, geste, score,
  etat, demande_ts, tranche_ts, par, resultat)` avec `UNIQUE(menace_id, geste)` ;
  `mode_courant() -> str` (défaut `observe`) ; `changer_mode(valeur: str, par: str) -> None` ;
  `GET /defense/policies` (`require_lecture`) → `{"mode", "modes_ouverts": ["observe","reactive"], "bandes", "seuils", "liste_blanche"}` ;
  `POST /defense/mode` (`require_jwt`), corps `{"mode": str}`.

- [ ] **Step 1: Tests qui échouent**

```python
def test_mode_par_defaut_observe(client): assert client.get("/defense/policies", headers=LECTURE).json()["mode"] == "observe"

@pytest.mark.parametrize("m", ["active", "aggressive"])
def test_modes_differes_refuses(client, m):
    r = client.post("/defense/mode", json={"mode": m}, headers=ADMIN)
    assert r.status_code == 409 and r.json()["cause"] == "gestes_non_livres"

def test_mode_inconnu_400(client): assert client.post("/defense/mode", json={"mode": "x"}, headers=ADMIN).status_code == 400
def test_lecture_ne_change_pas_le_mode(client): assert client.post("/defense/mode", json={"mode": "reactive"}, headers=LECTURE).status_code in (401, 403)

def test_changement_audite_et_persistant(client, audit):
    assert client.post("/defense/mode", json={"mode": "reactive"}, headers=ADMIN).status_code == 200
    assert defense_etat.mode_courant() == "reactive"
    assert "sade-mode" in audit.derniere() and "reactive" in audit.derniere()
```

- [ ] **Step 2: Run** — FAIL. **Step 3: Implémenter.** Liste blanche amorcée à la création avec les réseaux
  privés, lien-local, CGNAT et boucle (IPv4 et IPv6) ; ces entrées ne se suppriment pas.
- [ ] **Step 4: Run** — PASS. **Commit** `feat(soc): mode et politique SADE (ref #N)`.

### Task 5: Vue « Cyber Defense Live »

**Files:**
- Create: `packages/secubox-soc/www/soc/defense.html`
- Modify: `packages/secubox-soc/www/soc/index.html` (un onglet `data-vue="defense.html?embed=1"`, en tête)
- Modify: `packages/secubox-soc/tests/test_vues_rassemblees_2358.py` (`len(urls) == len(VUES) + 2`)
- Test: `packages/secubox-soc/tests/test_defense_vue.py`

**Interfaces:**
- Consumes: les six routes de lecture et `GET /defense/policies`.

- [ ] **Step 1: Tests qui échouent** (statiques, sur le texte de la page) : en-tête SPDX ; aucune URL d'une autre
  origine ; les sept `fetch` visent `/api/v1/soc/defense/` ; le jeton se lit sous la clé `sbx_token` ; les sections
  `id="phases"`, `id="flux"`, `id="approbation"`, `id="incidents"`, `id="synthese"`, `id="maillage"`,
  `id="seuils"` existent ; les boutons de mode `active` et `aggressive` portent `disabled` ; aucun texte de la page
  ne contient les valeurs fictives de la maquette (`203.0.113.45`, `82`).
- [ ] **Step 2: Run** — FAIL.
- [ ] **Step 3: Écrire la page** en reprenant la disposition et les styles de la maquette validée, adaptés aux
  jetons Aurora du dépôt (`.claude/AURORA-REFERENCE.md`, cadre `.cadre > .app`). Chaque carte a trois états :
  chargement, données, **source indisponible** (texte « relevé indisponible », jamais un zéro). En `observe`, la
  carte d'approbation affiche les propositions sans bouton d'action. Rafraîchissement toutes les 15 s, suspendu
  quand l'onglet est caché.
- [ ] **Step 4: Run** — PASS, et `pytest packages/secubox-soc/tests` entier — PASS.
- [ ] **Step 5: Commit** `feat(soc): vue Cyber Defense Live (ref #N)`.

### Task 6: REACTIVE — file d'approbation

**Files:**
- Modify: `packages/secubox-soc/api/defense.py`, `packages/secubox-soc/api/defense_etat.py`
- Modify: `packages/secubox-soc/www/soc/defense.html`
- Test: `packages/secubox-soc/tests/test_defense_approbation.py`

**Interfaces:**
- Consumes: propositions d'actord (`/proposals`), route d'administration de ban du WAF relevée en tâche 1.
- Produces: `GET /defense/proposals` (`require_lecture`) → `{"propositions": [{"id", "menace_id", "cible", "geste",
  "score", "bande", "motif", "validation_humaine": bool, "etat"}]}` ;
  `POST /defense/approve` et `POST /defense/refuse` (`require_jwt`), corps `{"id": str, "simuler": bool}` →
  `{"etat": "applique|refuse|simule", "resultat": str}`.

- [ ] **Step 1: Tests qui échouent**

```python
def test_approbation_refusee_en_observe(client):
    r = client.post("/defense/approve", json={"id": P1}, headers=ADMIN)
    assert r.status_code == 409 and r.json()["cause"] == "mode"

@pytest.mark.parametrize("cible", ["192.168.1.20", "10.98.0.1", "fd00::1", "127.0.0.1", "100.64.0.9"])
def test_liste_blanche_prioritaire(client, reactive, proposition, cible):
    r = client.post("/defense/approve", json={"id": proposition(cible)}, headers=ADMIN)
    assert r.status_code == 403 and r.json()["cause"] == "liste_blanche"
    assert waf_factice.appels == []

def test_simulation_n_appelle_pas_le_waf(client, reactive):
    r = client.post("/defense/approve", json={"id": P1, "simuler": True}, headers=ADMIN)
    assert r.json()["etat"] == "simule" and waf_factice.appels == []

def test_une_seule_application(client, reactive):
    assert client.post("/defense/approve", json={"id": P1}, headers=ADMIN).status_code == 200
    assert client.post("/defense/approve", json={"id": P1}, headers=ADMIN).status_code == 409
    assert len(waf_factice.appels) == 1

def test_geste_hors_ban_refuse(client, reactive, proposition_bloc):      # ban_bloc n'est pas exécutable aujourd'hui
    r = client.post("/defense/approve", json={"id": proposition_bloc}, headers=ADMIN)
    assert r.status_code == 409 and r.json()["cause"] == "gestes_non_livres"

def test_echec_du_waf_ne_marque_pas_applique(client, reactive):
    waf_factice.echoue(502)
    r = client.post("/defense/approve", json={"id": P1}, headers=ADMIN)
    assert r.status_code == 502
    assert defense_etat.decision(P1)["etat"] == "en_attente"

def test_approbation_et_refus_audites(client, reactive, audit): ...     # « sade-approuve » / « sade-refuse », cible, score, opérateur
```

- [ ] **Step 2: Run** — FAIL.
- [ ] **Step 3: Implémenter.** La ligne `decisions` est posée en `en_cours` par une insertion sous contrainte
  d'unicité **avant** l'appel au WAF (c'est elle qui tranche le double clic) ; elle repasse `en_attente` si le WAF
  échoue. L'appel au WAF transmet les en-têtes de l'administrateur : c'est son geste, audité à son nom par le WAF.
  Dans la page, les boutons Approuver, Refuser et Simuler n'apparaissent qu'en `reactive`.
- [ ] **Step 4: Run** — PASS, suite entière — PASS. **Commit** `feat(soc): file d'approbation SADE en REACTIVE (ref #N)`.

### Task 7: Paquet, documentation, banc

**Files:**
- Modify: `packages/secubox-soc/debian/changelog` (`1.9.0-1~trixie1`), `packages/secubox-soc/README.md`
- Modify: `.claude/HISTORY.md`, `.claude/WIP.md`

- [ ] **Step 1:** README : routes `/defense/*`, gardes, modes ouverts et différés, base `defense.db`, liste blanche.
- [ ] **Step 2:** `dpkg-buildpackage -us -uc -b -d` ; relecture par le sous-agent `relecteur-securite` sur le diff
  de la branche ; corriger tout constat bloquant ou « à corriger ».
- [ ] **Step 3: Banc gk6** (publication apt puis `apt-get install`, jamais d'édition à chaud) : la vue s'ouvre par
  le chemin public de gk6 ; les sept cartes affichent des données réelles ou « relevé indisponible » ; passer en
  `reactive` ; approuver une proposition réelle en **simulation**, puis une réelle sur une adresse de test du
  banc ; vérifier la ligne d'audit et le ban dans le WAF ; lever le ban ; repasser en `observe`.
- [ ] **Step 4: gk2** : après accord du propriétaire, déploiement en `observe` seulement. `reactive` sur gk2 est une
  décision séparée, prise sur les mesures du banc.
- [ ] **Step 5:** Suivi (`HISTORY.md`, `WIP.md`), PR `ref #N`.
