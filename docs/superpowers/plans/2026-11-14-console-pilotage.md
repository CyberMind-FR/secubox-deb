<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Console de pilotage du maître — actions, macros, journal en direct : plan d'implémentation

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or
> superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal :** une page `/pilotage/console/` sur le maître gk2 qui lance, sur plusieurs box cochées, une action du
`CATALOGUE` ou une macro (étapes fermées + contrôles du maître), **une box après l'autre avec arrêt au premier écart**,
et suit le déroulement dans un journal en direct.

**Architecture :** `executer_action` et le relevé sortent de la fermeture de `creer_app_admin` vers `api/actions.py`
(un `Contexte` porte les dépendances). Un moteur pur `pilotage/moteur.py` déroule une exécution en appelant ces
fonctions par un adaptateur (`Executant`), range tout dans `pilotage.db` (tables nouvelles) et publie des événements
`macro` sur la clé de diffusion `exec:<id>`, qui relaie aussi les événements `operation` de la box en cours. Les
règles des étapes (validation, conditions, comparaisons, estimation) vivent dans `pilotage/macros.py`, sans E/S.
La page Aurora autonome lit `/api/v1/pilotage/…` et un seul flux SSE par exécution.

**Tech Stack :** Python 3.11+ / FastAPI / Pydantic v2, SQLite (`StockageSqlite`), asyncio, SSE lu par `fetch` +
`ReadableStream`, HTML/CSS/JS autonomes (profil Aurora), pytest + pytest-asyncio + httpx + Playwright (chromium).

**Spec :** `docs/superpowers/specs/2026-11-13-console-pilotage-design.md` (§ 4.1 à 4.5, § 4 bis, § 6). Maquette validée :
https://claude.ai/artifact/Bie8keZPrYfQrvHx2gR5K2, planches `Main`, `Macro`, `Confirmer`, `Panneau` (la planche `Zoom`,
interface d'une box agrandie, est **hors périmètre**).

## Global Constraints

- Tout se fait dans le worktree `/home/reepost/CyberMindStudio/secubox-deb-worktrees/3702-pilotage-console-du-maitre-actions-macro`,
  branche `feature/3702-pilotage-console-du-maitre-actions-macro`. Jamais `git stash`, jamais `git add` sous `.superpowers/`.
- Tests : `PYTEST="/home/reepost/CyberMindStudio/secubox-deb/secubox-deb/.venv/bin/python -m pytest"`, lancé depuis la
  racine du worktree : `$PYTEST packages/secubox-pilotage/tests -q` (référence avant travaux : 598 passés).
- Commits : `type(pilotage): message (ref #3702)`, ligne vide, `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`
  (deux `-m`). Jamais `closes #3702` avant le déploiement sur gk2.
- En-tête SPDX CMSD-1.0 sur tout fichier créé (copier celui de `pilotage/operations.py`, ou le bloc HTML du spec).
- **Liste fermée** : une étape est `action`, `releve`, `condition`, `comparer` ou `attendre`, rien d'autre ; refus **400**
  à l'enregistrement comme au lancement. Aucune commande libre, aucun `eval`, aucune expression.
- Bornes copiées du spec : **20 étapes** au plus ; nom de macro `^[\w àâçéèêëîïôûùüÿœ'-]{1,60}$` ; `action.delai_s`
  60..3600, **900** par défaut ; `releve.duree_s` 10..300 ; nom de relevé `avant`, `apres` ou `[a-z0-9-]{1,20}` ;
  `attendre.delai_s` 30..900 ; mesures `memoire_dispo_mo`, `cpu_pct`, `swap_utilise_pct`, `services_en_echec` ;
  `op` ∈ {`>`, `<`} ; `alors` ∈ {`arreter`, `passer`} ; règles `nouveau_service_en_echec`, `memoire_dispo_baisse_mo`.
- Une étape `action` passe **par `executer_action`** (même validation `arguments()`, même confirmation forte, même
  exigence de support, même audit `pilotage_action`) : aucun autre chemin vers l'agent.
- Série : une box commence quand la précédente a fini **sans écart** ; écart, échec, délai dépassé ou box qui ne
  revient pas → arrêt, box suivantes `non_lancee`. Une seule exécution par box (409). `arreter` agit **après l'étape en
  cours**. Au démarrage du service, toute exécution `en_cours` passe `interrompue`, sans reprise.
- Confirmation forte (`forte=True`) : nom **exact** retapé pour CHAQUE box du maillage ; box cliente : session de
  support ouverte (accord du détenteur) à la place du nom. Box cliente sans support : 409. Box hors ligne au lancement
  manuel : 409.
- Programmation `{"quotidien": "HH:MM"}`, heure locale du maître, acteur `planificateur` ; **refusée (400)** si une
  étape est `forte` ou si une cible est une box cliente ; tic de 60 s ; une heure manquée n'est jamais rattrapée.
- Audit : `pilotage_macro` (lancement, fin, arrêt, écart) en plus de `pilotage_action` ; « pas d'audit, pas de
  lancement » (503 si l'audit du lancement échoue).
- Toute route nouvelle : `require_jwt` ; un flux revérifie `session_toujours_admin` à chaque battement ; 4 flux au plus
  par administrateur (règle existante de `Diffusion`).
- v1 **sans changement de l'agent Go** ; pas de mesure disque (piste v2).
- Page : profil Aurora (`.claude/AURORA-REFERENCE.md`), un fichier autonome, CSS/JS en ligne, police système
  (`"IBM Plex Sans","Inter",system-ui,…` sans Google Fonts, contrairement à la maquette), `textContent`/`createElement`
  seulement pour toute valeur de l'API, jamais `confirm(`/`alert(`/`prompt(`, `?embed=1` (sans menu latéral),
  `?demo=1` (bandeau orange, aucun appel d'écriture), mesure absente = « — ». Menu latéral comme
  `packages/secubox-annuaire/www/fleet/index.html` (`/shared/sidebar.js`, `/shared/sidebar-light.css`).
- Versions : `secubox-pilotage` **0.7.0-1~trixie1** ; `secubox-hub` 1.12.57-1~trixie1 (seulement `espaces.json`).
  `debian/compat` 13, `Standards-Version: 4.6.2` inchangés.
- Déploiement : par paquet seulement (build → `scripts/apt-publier.sh` → `apt-get install` sur gk2), jamais
  d'édition à chaud ; jamais de `timeout` autour d'apt/dpkg.

## Review Focus

- **Relevé « après » pris sur un inventaire antérieur à l'action** (l'inventaire n'est relevé que toutes les 60 s) :
  `comparer` verrait « rien de nouveau » et la box suivante serait touchée. Attendu : l'instantané n'est pris que sur
  un inventaire relevé **après le début de l'étape** (90 s au plus), sinon échec de l'étape.
  Test : `test_releve_attend_un_inventaire_posterieur_au_debut` (Task 4).
- **Deux lancements simultanés sur la même box** (deux onglets, deux administrateurs) : la vérification « box
  occupée » et la réservation se font avant tout `await`. Attendu : une exécution, l'autre 409.
  Test : `test_deux_lancements_concurrents_une_seule_execution` (Task 4).
- **Session de support échue au milieu d'une macro sur une box cliente** (la route de relevé ne vérifie pas le support) :
  attendu : l'étape suivante échoue (« session de support échue ») et la série s'arrête.
  Test : `test_support_echu_en_cours_echec_et_serie_arretee` (Task 4).
- **Box renommée ou oubliée entre l'enregistrement d'une macro programmée et la nuit** (sa clé change) : attendu :
  cible sautée et notée, les autres déroulées, le planificateur vivant au tic suivant même après une exception.
  Test : `test_planificateur_cible_disparue_sautee_et_boucle_vivante` (Task 4).
- **Page rechargée pendant ou après une exécution** : le flux d'une exécution déjà finie rend son état final puis se
  ferme (pas de connexion pendue qui mange une des 4 places) ; la page reprend l'exécution en cours au chargement.
  Tests : `test_flux_d_une_execution_finie_rend_la_fin_et_se_ferme` (Task 6),
  `test_rechargement_reprend_l_execution_en_cours` (Task 7).

---

### Task 1 : extraire l'action et le relevé dans `api/actions.py`

Refactor sans changement de comportement : la route HTTP, le vhost d'une box légère et (Task 6) le moteur appellent
les mêmes fonctions.

**Files :**
- Create : `packages/secubox-pilotage/api/actions.py`
- Modify : `packages/secubox-pilotage/api/main.py` (fermetures `trouver`, `en_ligne`, `auditer_ou_503`, `auditer`,
  `operer`, `acteur_de`, `executer_action`, `releve`/`suivre_releve` ; constantes et modèles déplacés, ré-exportés)
- Modify : `packages/secubox-pilotage/pilotage/stockage.py` (`operation_lire`)
- Test : `packages/secubox-pilotage/tests/test_actions_module.py`

**Interfaces :**
- Produces (dans `api/actions.py`) :
  - constantes `DELAI_ACTION_S = 90.0`, `ETATS_REPONSE`, `IDENT_MAX = 128`, `ERREUR_MAX = 300` ; `def borne(v, n=ERREUR_MAX) -> str` ;
    modèles `ReleveIn`, `ActionIn` (déplacés tels quels).
  - `@dataclass class Contexte` : `stockage`, `files`, `audit`, `suivi`, `diffusion`, `horloge=time.time`,
    `noms_pris=set`, `delai_action_s=DELAI_ACTION_S`, `releves_en_cours: set` et `taches: set` (`field(default_factory=set)`).
  - `async def trouver(ctx, ident: str) -> dict` ; `def en_ligne(ctx, b: dict) -> bool` ;
    `async def auditer_ou_503(ctx, evenement: str, champs: dict) -> None` ; `async def auditer(ctx, evenement, champs) -> None` ;
    `async def operer(ctx, cle: str, corps: dict) -> Optional[dict]` ; `def acteur_de(jwt: dict) -> str`.
  - `async def executer_action(ctx, ident: str, action: str, corps: ActionIn, jwt: dict) -> dict` — corps actuel inchangé.
  - `async def lancer_releve(ctx, b: dict, duree_s: int, acteur: str) -> asyncio.Task` — 409 « un relevé est déjà en
    cours » (réservation avant tout `await`), audit `pilotage_releve_demande` (503), dépôt (429) ; la tâche rendue range
    le relevé (`releve_enregistrer`) et libère `releves_en_cours` ; elle est ajoutée à `ctx.taches`.
- Produces (stockage) : `StockageSqlite.operation_lire(ident: int) -> Optional[dict]` (même forme que `operations()`).
- `api/main.py` garde importables `DELAI_ACTION_S`, `DELAI_LECTURE_S`, `ActionIn`, `ReleveIn`, `creer_app_admin` ;
  `creer_app_admin` construit `ctx = Contexte(...)` et le pose sur `app.state.contexte`.

- [ ] **Step 1 : tests**

```python
async def test_executer_action_du_module_meme_audit_que_la_route(m):   # Monde de test_operations_api
    ctx = m.app.state.contexte
    t = asyncio.create_task(actions.executer_action(ctx, "gk5", "reboot", ActionIn(confirmation="gk5"), {"sub": "alice"}))
    await m.repondre(GK5, ACCEPTE)
    r = await t
    assert r["etat"] == "accepte" and [e for e, _ in m.lignes] == ["pilotage_action", "pilotage_action"]

async def test_lancer_releve_refuse_un_second_releve(m):
    ctx = m.app.state.contexte; b = await actions.trouver(ctx, "gk5")
    await actions.lancer_releve(ctx, b, 10, "alice")
    with pytest.raises(HTTPException) as e:
        await actions.lancer_releve(ctx, b, 10, "alice")
    assert e.value.status_code == 409

def test_operation_lire(tmp_path):   # None pour un id inconnu ; la ligne de operation_demander sinon
```

- [ ] **Step 2 :** `$PYTEST packages/secubox-pilotage/tests/test_actions_module.py -q` → FAIL (`api.actions` absent).
- [ ] **Step 3 :** créer `api/actions.py`, faire de chaque fermeture un appel du module (`functools.partial(actions.trouver, ctx)`
  etc.), garder les routes à l'identique ; la lambda `agir=` du vhost appelle `actions.executer_action(ctx, …)`.
- [ ] **Step 4 :** `$PYTEST packages/secubox-pilotage/tests -q` → tout vert (598 + nouveaux), en particulier
  `test_operations_api.py`, `test_flux.py`, `test_vhosts.py`.
- [ ] **Step 5 :** commit `refactor(pilotage): action et relevé extraits de creer_app_admin (ref #3702)`.

### Task 2 : règles des macros (`pilotage/macros.py`, sans E/S)

**Files :**
- Create : `packages/secubox-pilotage/pilotage/macros.py`
- Test : `packages/secubox-pilotage/tests/test_macros_regles.py`

**Interfaces :**
- Consumes : `CATALOGUE`, `arguments()` (`pilotage/operations.py`).
- Produces :
  - constantes du Global Constraints (`ETAPES_MAX = 20`, `RE_NOM_MACRO`, `RE_NOM_RELEVE`, `MESURES`, `REGLES`, bornes) ;
    `RE_HEURE = r"([01]\d|2[0-3]):[0-5]\d"`.
  - `class MacroInvalide(ValueError)` (message français lisible, rendu tel quel en 400).
  - `def valider_nom(nom) -> str` ; `def valider_etapes(etapes) -> list[dict]` (étapes normalisées, défauts posés :
    `delai_s` 900 pour `action`, 300 pour `attendre`, `seuil` 0 pour `comparer`, `args` `{}`) ;
    `def contient_forte(etapes: list[dict]) -> bool` ; `def valider_programmation(prog, etapes, cibles_clientes: bool) -> Optional[dict]`.
  - `LIVREES: tuple[dict, ...]` — `{"id", "nom", "etapes"}` :
    `livree:diagnostic-complet` « Diagnostic complet » = `releve 300 diag` ;
    `livree:mise-a-jour-sure` « Mise à jour sûre » = `releve 60 avant` → `condition services_en_echec (avant) > 0 alors arreter`
    → `action maj-paquets` → `releve 60 apres` → `comparer avant/apres nouveau_service_en_echec seuil 0` ;
    `livree:remise-en-route` « Remise en route » = `releve 60 avant` ; `livree:retour-en-local` « Retour en local » =
    `action interface-locale`.
  - `def services_en_echec(valeurs: dict) -> list[str]` — noms `Device.X_SECUBOX_Services.{i}.Name` dont `ActiveState ==
    "failed"`, i = 1..200, arrêt au premier `Name` absent, triés.
  - `def instantane(resume: dict, valeurs: dict) -> dict` — `{memoire_dispo_mo, cpu_pct, swap_utilise_pct,
    services_en_echec, services, inventaire_le}` (valeurs de `resumes()`, None si absentes).
  - `def evaluer_condition(etape: dict, instantanes: dict) -> dict` — `{"vrai": bool, "mesure_absente": bool, "valeur"}`.
  - `def comparer(etape: dict, instantanes: dict) -> dict` — `{"ecart": bool, "nouveaux": [...], "hausse": int|None,
    "baisse_mo": int|None, "mesure_absente": bool, "propositions": [{"action": "service-redemarrer", "args": {"unite": u}}]}`.
  - `def estimer_s(etape: dict) -> int` ; `def coupure(etape: dict) -> Optional[str]`.
- Règles fixées ici (décisions, spec § 5) :
  - champs exacts par type (clé en trop ou manquante → `MacroInvalide`) ; booléen refusé partout où un nombre est
    attendu ; `seuil` fini, |seuil| ≤ 1e6 ; 0 étape refusée.
  - un nom de relevé n'est produit qu'une fois par macro ; `condition.releve`, `comparer.avant`/`apres` doivent nommer
    un relevé produit par une étape **antérieure**.
  - `nouveau_service_en_echec` : écart si `len(nouveaux) > seuil` ou `hausse > seuil` (hausse du compteur
    `services_en_echec` : un compteur en hausse sans nom identifiable est un écart) ; `memoire_dispo_baisse_mo` : écart si
    `avant - apres > seuil`. Mesure absente d'un côté → pas d'écart, `mesure_absente` vrai (noté au journal, comme une
    condition).
  - estimation : `releve` = `duree_s + 10` ; `action` = `min(delai_s, ESTIMATION_S[action])` avec `reboot` 120,
    `maj-paquets` 300, `installer` 180, `service-*` 15, `renommer` 60, `renouveler` 30, `interface-*` 60 ;
    `attendre` = `delai_s` ; `condition`/`comparer` = 0. Coupure : `reboot` « redémarrage », `interface-*` « bascule
    d'interface », `renommer` « changement de nom », sinon None.

- [ ] **Step 1 : tests** (un `pytest.mark.parametrize` par famille de refus)

```python
def test_etapes_hors_liste_refusees():           # {"type": "shell"}, {"type": "action", "action": "rm"}, clé en trop, 21 étapes, []
def test_bornes_des_etapes():                    # delai_s 59/3601, duree_s 9/301, attendre 29/901, True comme seuil → MacroInvalide
def test_defauts_poses():
    (e,) = valider_etapes([{"type": "action", "action": "maj-paquets"}]); assert e["delai_s"] == 900 and e["args"] == {}
def test_args_valides_par_arguments():           # service-redemarrer sans unite, unite "ssh.service" → refus
def test_releve_reference_doit_preceder():       # condition sur « avant » avant le relevé « avant » → refus ; doublon de nom → refus
def test_nom_de_macro():                         # "Mise à jour sûre" ok ; "a(b)", "", 61 caractères, "x\n" → refus
def test_programmation_refusee_si_forte_ou_cliente():
    with pytest.raises(MacroInvalide): valider_programmation({"quotidien": "03:00"}, [REBOOT], cibles_clientes=False)
    with pytest.raises(MacroInvalide): valider_programmation({"quotidien": "03:00"}, [RELEVE], cibles_clientes=True)
    assert valider_programmation({"quotidien": "03:00"}, [RELEVE], False) == {"quotidien": "03:00"}
    # "24:00", "3:00", {"hebdo": …} → refus ; None → None
def test_livrees_valides_et_retour_en_local_forte():   # chaque LIVREES passe valider_etapes ; contient_forte vrai seulement pour retour-en-local
def test_services_en_echec_depuis_l_inventaire():      # 1.Name secubox-a.service failed, 2.Name nginx.service active → ["secubox-a.service"]
def test_condition_mesure_absente_fausse():
    assert evaluer_condition(COND_ECHECS_SUP_0, {"avant": {"services_en_echec": None}}) == {"vrai": False, "mesure_absente": True, "valeur": None}
def test_comparer_nouveau_service_et_compteur_sans_nom():
    r = comparer(CMP, {"avant": inst(services=[], n=0), "apres": inst(services=["secubox-portal.service"], n=1)})
    assert r["ecart"] and r["nouveaux"] == ["secubox-portal.service"] and r["propositions"][0]["args"] == {"unite": "secubox-portal.service"}
    assert comparer(CMP, {"avant": inst(services=["a"], n=1), "apres": inst(services=["a"], n=2)})["ecart"]   # hausse sans nom
def test_comparer_baisse_memoire():               # 900 → 700 Mo, seuil 150 → écart ; seuil 250 → pas d'écart
def test_estimation_et_coupure():                 # reboot 120 + « redémarrage » ; releve 60 → 70
```

- [ ] **Step 2 :** `$PYTEST packages/secubox-pilotage/tests/test_macros_regles.py -q` → FAIL (module absent).
- [ ] **Step 3 :** implémenter `pilotage/macros.py` (fonctions pures, aucune importation de FastAPI ni du stockage).
- [ ] **Step 4 :** même commande → PASS.
- [ ] **Step 5 :** commit `feat(pilotage): règles fermées des macros (ref #3702)`.

### Task 3 : stockage des macros et des exécutions

**Files :**
- Modify : `packages/secubox-pilotage/pilotage/stockage.py` (`_SCHEMA`, méthodes, `C_MODELE` dans `_RESUME`, champ `modele` de `resumes()`)
- Test : `packages/secubox-pilotage/tests/test_macros_stockage.py`

**Interfaces :**
- Tables (`CREATE TABLE IF NOT EXISTS`, dans `_SCHEMA`) :
  `macros(id TEXT PRIMARY KEY, nom, etapes_json, cibles_json DEFAULT '[]', programmation_json, livree INTEGER DEFAULT 0, cree_le, maj_le, auteur)` ;
  `executions(id INTEGER PRIMARY KEY AUTOINCREMENT, macro_id, macro_nom, cibles_json, etat, acteur, debut, fin, raison)` ;
  `execution_etapes(execution_id, box, rang, type, etat, resultat_json, debut, fin, PRIMARY KEY(execution_id, box, rang))` ;
  `execution_releves(execution_id, box, nom, instantane_json, pris_le, PRIMARY KEY(execution_id, box, nom))`.
  `box` = `Box.cle` (R15). `cibles_json` d'une exécution = `[{"cle", "nom"}]` (le nom survit à un oubli).
- Constantes : `MACROS_MAX = 200` (macros ordinaires), `EXECUTIONS_MAX = 500` (au-delà, les plus anciennes partent avec
  leurs étapes et relevés), `ETATS_EXECUTION = ("en_cours", "terminee", "ecart", "echec", "arretee", "interrompue")`,
  `ETATS_ETAPE = ("en_attente", "en_cours", "ok", "passee", "ecart", "echec", "non_lancee", "sautee", "interrompue")`.
- Méthodes (synchrones, appelées par `to_thread`) :
  - `macros_livrees_installer(livrees) -> None` (réécrit chaque livrée par son id, `livree=1`) ;
    `macro_creer(nom, etapes, cibles, programmation, auteur) -> str` (id `m-` + 12 hex ; `None` au-delà de `MACROS_MAX`) ;
    `macro_lire(ident) -> Optional[dict]` ; `macros() -> list[dict]` (livrées d'abord, puis par nom) ;
    `macro_maj(ident, nom, etapes, cibles, programmation) -> bool` (faux si absente **ou livrée**) ;
    `macro_supprimer(ident) -> bool` (faux si absente ou livrée) ; `macros_programmees() -> list[dict]`.
    Forme rendue : `{id, nom, etapes, cibles, programmation, livree: bool, cree_le, maj_le, auteur}`.
  - `execution_creer(macro_id, macro_nom, cibles: list[dict], etapes: list[dict], acteur) -> int` — crée l'exécution
    `en_cours` et toutes les lignes (box × rang) `en_attente`.
  - `etape_noter(ident, cle, rang, etat, resultat=None) -> None` (`debut` posé à `en_cours`, `fin` à un état terminal) ;
    `etapes_clore(ident, etat, cle=None) -> int` (toutes les lignes `en_attente`, d'une box ou de toutes, passent à `etat`) ;
    `execution_finir(ident, etat, raison=None) -> None` ; `execution(ident) -> Optional[dict]` (avec `etapes`, ordonnées
    par ordre des cibles puis rang) ; `executions(limite=50) -> list[dict]` (sans étapes, plus récentes d'abord) ;
    `executions_interrompre() -> list[dict]` (`en_cours` → `interrompue`, leurs lignes `en_cours`/`en_attente` aussi ;
    rend celles changées) ; `execution_programmee_depuis(macro_id, depuis: int) -> bool` (acteur `planificateur`).
  - `releve_ranger(ident, cle, nom, instantane: dict) -> None` ; `releves_execution(ident, cle) -> dict[str, dict]`.
  - `resumes()` gagne `"modele"` : `Device.DeviceInfo.ModelName` si chaîne, bornée à 120 caractères, sinon None.

- [ ] **Step 1 : tests**

```python
def test_tables_creees_sur_une_base_existante(tmp_path):   # base d'avant (schéma L2) rouverte → tables présentes, données gardées
def test_livrees_reecrites_et_non_modifiables(s):
    s.macros_livrees_installer(LIVREES); s.macros_livrees_installer(LIVREES)
    assert [m["id"] for m in s.macros()][:4] == [l["id"] for l in LIVREES]
    assert s.macro_maj("livree:diagnostic-complet", "x", [], [], None) is False and s.macro_supprimer("livree:retour-en-local") is False
def test_macro_creer_lire_maj_supprimer(s):
def test_plafond_des_macros(s):                  # MACROS_MAX + 1 → None
def test_execution_lignes_en_attente_puis_clore(s):
    i = s.execution_creer("m-1", "M", [{"cle": "maillage:gk7", "nom": "gk7"}, {"cle": "maillage:gk6", "nom": "gk6"}], [R, A], "alice")
    s.etape_noter(i, "maillage:gk7", 0, "en_cours"); s.etape_noter(i, "maillage:gk7", 0, "ecart", {"nouveaux": ["x"]})
    assert s.etapes_clore(i, "non_lancee") == 3
    e = s.execution(i); assert [x["etat"] for x in e["etapes"]] == ["ecart", "non_lancee", "non_lancee", "non_lancee"]
def test_interrompre_au_demarrage(s):            # en_cours → interrompue ; une terminee reste terminee
def test_executions_bornees(s):                  # EXECUTIONS_MAX + 1 → la plus ancienne et ses étapes ont disparu
def test_programmee_depuis(s):                   # acteur planificateur, debut ≥ depuis → vrai ; autre acteur → faux
def test_releves_par_execution_et_box(s):
def test_resumes_porte_le_modele(s):             # inventaire avec ModelName "Globalscale MOCHAbin" → resumes()[0]["modele"]
```

- [ ] **Step 2 :** `$PYTEST packages/secubox-pilotage/tests/test_macros_stockage.py -q` → FAIL.
- [ ] **Step 3 :** implémenter (transactions `_tx`, JSON par `_json`, aucune migration hors `CREATE … IF NOT EXISTS`).
- [ ] **Step 4 :** `$PYTEST packages/secubox-pilotage/tests -q` → tout vert (`test_stockage.py` compris).
- [ ] **Step 5 :** commit `feat(pilotage): tables des macros et des exécutions (ref #3702)`.

### Task 4 : moteur d'exécution, relais de diffusion, planificateur

**Files :**
- Create : `packages/secubox-pilotage/pilotage/moteur.py`
- Modify : `packages/secubox-pilotage/pilotage/diffusion.py` (`NOMS` + `macro`, relais)
- Test : `packages/secubox-pilotage/tests/test_moteur.py`

**Interfaces :**
- Consumes : Task 2 (`valider_etapes`, `contient_forte`, `instantane`, `evaluer_condition`, `comparer`), Task 3 (méthodes
  ci-dessus, `operation_lire`, `boite`, `resumes`, `inventaire`, `support_ouvert`).
- Produces (diffusion) : `NOMS = ("notify", "operation", "etat", "macro")` ; `Diffusion.relayer(cle_box: str, cle_flux: str)`,
  `Diffusion.cesser(cle_box: str, cle_flux: str)` — tant qu'un relais existe, chaque `publier(cle_box, "operation", d)`
  est aussi posé chez les abonnés de `cle_flux` ; les autres noms ne sont pas relayés.
- Produces (moteur) :
  - `def cle_flux(ident: int) -> str` → `f"exec:{ident}"`.
  - `class EchecEtape(Exception)` (raison lisible) ; `class RefusLancement(Exception)` avec `.statut: int` (400, 409, 503)
    et `.message: str`.
  - `class Executant(Protocol)` :
    `async def action(self, b: dict, action: str, args: dict, *, confirmation: Optional[str], support: Optional[str], acteur: str) -> dict`
    (rend au moins `{"operation": int, "etat": str}`, lève `EchecEtape`) ;
    `async def releve(self, b: dict, duree_s: int, acteur: str) -> str` (statut `ok`/`expire`/`erreur`, lève `EchecEtape`).
  - `class Moteur(stockage, executant, diffusion, audit, *, horloge=time.time, attente=asyncio.sleep, sonde_s=1.0,
    frais_s=90.0, resoudre: Callable[[str], Optional[dict]])` (`resoudre(cle)`, synchrone, appelé par `asyncio.to_thread`) :
    - `async def lancer(self, macro: dict, boxes: list[dict], confirmations: dict[str, str], support: dict[str, str], acteur: str, *, programme: bool = False) -> int`
      (`confirmations`/`support` indexés par `Box.cle`) ;
    - `def arreter(self, ident: int) -> bool` (faux si inconnue ou finie) ;
    - `def occupees(self) -> set[str]` ;
    - `async def interrompre_au_demarrage(self) -> list[int]` (stockage + audit `pilotage_macro` `fin`/`interrompue`) ;
    - `async def tic(self, maintenant: datetime) -> list[int]` (datetime local avec fuseau) ;
    - `async def planifier(self, maintenant_local: Callable[[], datetime], periode_s: float = 60.0) -> None` (boucle ;
      une exception d'un tic est journalisée, la boucle continue) ;
    - `async def fermer(self) -> None` (annule les déroulements ; leurs exécutions restent `en_cours` → `interrompue` au démarrage suivant).
  - Événement `macro` sur `cle_flux(id)` : `{"execution", "evenement": "lancement"|"box"|"etape"|"fin", "box", "cle",
    "rang", "type", "etat", "resultat", "raison"}` (champs sans objet à None).
- Comportement fixé :
  - `lancer` : revalide les étapes (`MacroInvalide` → 400) ; 1..32 box sans doublon (400) ; box occupée → 409 ;
    **réservation avant le premier `await`** ; box hors ligne → 409 (en `programme` : notée, sautée à son tour) ;
    box cliente sans `support[cle]` ouvert → 409 ; `forte` sur une box du maillage sans `confirmations[cle] == b["nom"]`
    → 400 ; audit `pilotage_macro` `lancement` (échec → 503, réservation rendue) ; `execution_creer` ; tâche de déroulement.
  - Audit `pilotage_macro` : champs `{"evenement", "execution", "macro", "nom", "cibles" (noms joints par « , »), "acteur",
    "etat", "raison"}` (`evenement` ∈ `lancement`, `fin`, `arret`, `ecart`, `enregistrement`, `suppression`, `refus_programme`).
  - Déroulement : box dans l'ordre ; à son tour, box hors ligne → échec de la série en manuel, `sautee` (et la série
    continue) en programmé ; `relayer(cle, cle_flux)` le temps de la box ; avant chaque étape : arrêt demandé →
    reste `non_lancee`, exécution `arretee`, audit `arret` ; box cliente → `support_ouvert(cle, sid)` sinon `EchecEtape`.
  - `action` : `executant.action(...)` ; `etat != "accepte"` → échec (`consentement` : « une macro n'attend pas l'accord
    du détenteur ») ; puis sonde `operation_lire` toutes les `sonde_s` jusqu'à `termine`/`inconnu`/`sans_reponse`/`refuse`
    ou `delai_s` ; `termine` + `resultat == "succes"` → `ok` (résultat `{operation, rc, resume}`), sinon échec.
  - `releve` : `t0 = horloge()` ; `executant.releve` ≠ `ok` → échec ; puis attente d'un inventaire avec
    `inventaire_le >= t0` (sonde, `frais_s` au plus, sinon échec « inventaire non rafraîchi ») ; `instantane(...)` rangé
    par `releve_ranger` et rendu comme résultat.
  - `condition` vraie + `arreter` → reste de CETTE box `passee`, la série continue ; vraie + `passer` → étape suivante
    `passee` ; mesure absente → fausse, notée dans le résultat.
  - `comparer` écart → étape `ecart`, reste `non_lancee`, exécution `ecart`, audit `ecart` (avec `nouveaux`).
  - `attendre` : sonde jusqu'à box vue depuis moins de `HORS_LIGNE_S` **et** toute opération `reboot` de cette box dans
    cette exécution terminée ; sinon `EchecEtape` « la box n'est pas revenue ».
  - Échec → étape `echec`, reste `non_lancee`, exécution `echec`. Fin normale → `terminee`. Audit `fin` toujours.
  - `tic` : pour chaque macro programmée, `t = maintenant` à `HH:MM:00` ; lance si `0 <= maintenant - t < 120 s` et pas
    `execution_programmee_depuis(id, t)` ; cibles par `resoudre(cle)` (None → sautée, notée dans l'audit) ; une macro
    devenue `forte` ou une cible devenue cliente → refus audité, rien lancé ; acteur `planificateur`.

- [ ] **Step 1 : tests** — monde : `StockageSqlite` réel, `Diffusion` réelle, audit en liste, `Horloge` de `outils.py`,
  `attente` qui avance l'horloge, `sonde_s=0.01`, et un faux exécutant :

```python
class FauxExecutant:
    """Range l'opération comme executer_action, puis la termine selon `fins[action]` (rc) ; `None` = jamais de fin."""
    def __init__(self, s, fins=None, etats=None): ...
    async def action(self, b, action, args, *, confirmation, support, acteur): ...   # appels.append((b["nom"], action))
    async def releve(self, b, duree_s, acteur): ...                                  # range un inventaire frais (releve_gk5)
```

  Tests (assertions clés) :
  - `test_serie_une_box_apres_l_autre` : `appels == [("gk7","releve"),("gk7","maj-paquets"),…,("gk6","releve"),…]`.
  - `test_ecart_arrete_la_serie_box_suivante_non_lancee` : service nouveau en échec sur gk7 → exécution `ecart`, aucune
    entrée gk6 dans `appels`, étapes gk6 toutes `non_lancee`, audit `pilotage_macro` `ecart`.
  - `test_echec_action_consentement` ; `test_delai_action_depasse` (`fins={"maj-paquets": None}`, `delai_s=60`).
  - `test_condition_arreter_saute_le_reste_de_la_box_et_continue` ; `test_condition_passer_saute_l_etape_suivante` ;
    `test_condition_mesure_absente_notee`.
  - `test_attendre_apres_reboot` (opération close « redémarrée » par `vu()` au nouveau `boot_id`) ;
    `test_box_qui_ne_revient_pas_arrete_la_serie`.
  - `test_arreter_apres_l_etape_en_cours` (arrêt demandé pendant l'action : l'action va à son terme, la suite `non_lancee`).
  - `test_refus_au_lancement` : forte sans nom 400 ; nom faux (`"GK7"`, `"gk7 "`) 400 ; cliente sans support 409 ;
    hors ligne 409 ; box occupée 409 ; audit en panne 503 ; dans tous les cas rien dans `appels`.
  - `test_programme_box_hors_ligne_sautee_la_serie_continue`.
  - `test_interrompre_au_demarrage_audite`.
  - `test_planificateur_une_fois_par_nuit_sans_rattrapage` : tics à 03:00:10 et 03:01:10 → une exécution ; tic à 05:00 →
    aucune (heure manquée).
  - `test_relais_operation_vers_le_flux_d_execution` : abonné `exec:<id>` reçoit `operation` de gk7 pendant son tour,
    plus après ; `notify` jamais relayé.
  - Review Focus : `test_releve_attend_un_inventaire_posterieur_au_debut`,
    `test_deux_lancements_concurrents_une_seule_execution` (`asyncio.gather` de deux `lancer` → un id et un 409),
    `test_support_echu_en_cours_echec_et_serie_arretee`, `test_planificateur_cible_disparue_sautee_et_boucle_vivante`
    (`resoudre` rend None pour une cible, lève pour le tic suivant : la boucle `planifier` vit encore au tic d'après).
- [ ] **Step 2 :** `$PYTEST packages/secubox-pilotage/tests/test_moteur.py -q` → FAIL.
- [ ] **Step 3 :** implémenter `diffusion.py` (relais borné : dict `cle_box -> set(cle_flux)`), puis `pilotage/moteur.py`
  (stockage appelé par `asyncio.to_thread`, jamais d'E/S bloquante dans la boucle, RULES-CODE § 6).
- [ ] **Step 4 :** `$PYTEST packages/secubox-pilotage/tests -q` → tout vert (`test_flux.py` compris).
- [ ] **Step 5 :** commit `feat(pilotage): moteur des macros, série et arrêt au premier écart (ref #3702)`.

### Task 5 : API — catalogue, flotte, macros, simulation

**Files :**
- Create : `packages/secubox-pilotage/pilotage/flotte.py`
- Modify : `packages/secubox-pilotage/api/main.py` (routes ; `GET /boxes/{x}` gagne `services_en_echec_noms`)
- Test : `packages/secubox-pilotage/tests/test_macros_api.py`

**Interfaces :**
- Produces (`pilotage/flotte.py`) : `def materiel(modele: Optional[str]) -> str` (sous-chaîne sans casse : « mochabin » →
  `MOCHAbin`, « raspberry » → `RPi`, « espressobin » → `ESPRESSObin`, sinon `autre`) ;
  `def groupes(resumes: list[dict]) -> dict` → `{"materiel": {nom: [cle…]}, "interface": {"legeres": […], "locales": […]},
  "etat": {"en_ligne": […], "muettes": […]}}` (légère = `interface == "distante"`, muette = `en_ligne` faux).
- Routes (toutes `require_jwt`) :
  - `GET /catalogue` → `[{"cle", "parametres": [...], "forte": bool}]` trié par clé.
  - `GET /flotte` → `{"boxes": [resume + "materiel" + "cochable" (= en_ligne)], "groupes": groupes(...)}`.
  - `GET /macros` ; `GET /macros/{id}` (404).
  - `POST /macros` (201 `{"id"}`) corps `MacroIn{nom: str, etapes: list, cibles: list[str] = [], programmation: Optional[dict] = None}`
    (`extra="forbid"`, `cibles` ≤ 32) : `MacroInvalide` → **400** ; cibles résolues par `actions.trouver` (404/409 tels
    quels) et rangées par **clé** ; programmation validée avec `cibles_clientes = any(reseau != "maillage")` ; plafond →
    409 ; audit `pilotage_macro` `enregistrement` (`auditer_ou_503`).
  - `PUT /macros/{id}` (même corps ; livrée → **403** « macro livrée : copiez-la pour la modifier ») ;
    `DELETE /macros/{id}` (livrée → 403 ; audit `suppression`).
  - `POST /macros/{id}/copier` (201) : nom `"<nom> copie"` tronqué à 60, programmation retirée, `livree` faux.
  - `POST /macros/{id}/simuler {box}` → `{"box", "cle", "en_ligne", "cliente", "forte_requise", "support_requis",
    "etapes": [{"rang", "type", "resume", "forte", "coupure", "duree_estimee_s"}], "duree_totale_s"}` ; rien d'envoyé, rien
    d'écrit (ni base, ni audit). `resume` en français (« relevé 60 s « avant » », « maj-paquets », « si services en
    échec (avant) > 0 alors arrêter »…).
  - `GET /boxes/{x}` : champ ajouté `services_en_echec_noms = macros.services_en_echec(inventaire)`.

- [ ] **Step 1 : tests** (monde de `test_operations_api.py`)

```python
def test_toutes_les_routes_console_exigent_un_jwt(tmp_path):   # 401 sans jeton ; dépendance require_jwt sur /catalogue, /flotte, /macros*, /executions*
def test_catalogue_liste_fermee(m):    # clés == sorted(CATALOGUE) ; reboot forte ; service-redemarrer parametres == ["unite"]
def test_flotte_groupes(m):            # gk5 MOCHAbin en ligne, gk4 RPi muette (non cochable), gk6 interface distante → legeres
def test_enregistrer_macro_400_hors_liste(m):     # étape {"type": "shell"} → 400 ; nom "a(b)" → 400 ; rien en base, rien audité
def test_enregistrer_programmation_refusee(m):    # reboot + quotidien → 400 ; cible cliente + quotidien → 400
def test_enregistrer_puis_lire_cibles_par_cle(m): # cibles ["gk5"] → macro["cibles"] == ["maillage:gk5"] ; audit enregistrement
def test_livree_403_et_copie(m):                  # PUT/DELETE livree:… → 403 ; copier → 201, "Mise à jour sûre copie", livree False
def test_simuler_sans_rien_envoyer(m):
    r = c.post(f"/macros/{mid}/simuler", json={"box": "gk5"}).json()
    assert r["forte_requise"] is True and r["etapes"][2]["coupure"] == "redémarrage"
    assert m.f.en_attente(GK5.cle) == 0 and m.lignes == []
def test_box_porte_les_noms_des_services_en_echec(m):
```

- [ ] **Step 2 :** `$PYTEST packages/secubox-pilotage/tests/test_macros_api.py -q` → FAIL.
- [ ] **Step 3 :** implémenter `pilotage/flotte.py` et les routes (stockage par `asyncio.to_thread`).
- [ ] **Step 4 :** `$PYTEST packages/secubox-pilotage/tests -q` → tout vert.
- [ ] **Step 5 :** commit `feat(pilotage): API des macros, catalogue, flotte et simulation (ref #3702)`.

### Task 6 : API — lancement, exécutions, flux, cycle de vie

**Files :**
- Modify : `packages/secubox-pilotage/api/actions.py` (adaptateur `ExecutantApi`)
- Modify : `packages/secubox-pilotage/api/main.py` (routes, `vie`, paramètres de `creer_app_admin`)
- Test : `packages/secubox-pilotage/tests/test_executions_api.py`

**Interfaces :**
- Consumes : `Moteur`, `Executant`, `EchecEtape`, `RefusLancement`, `cle_flux` (Task 4) ; `executer_action`, `lancer_releve`,
  `Contexte` (Task 1).
- Produces :
  - `class ExecutantApi(ctx: Contexte)` qui satisfait `Executant` : `action` appelle `executer_action(ctx, b["cle"], action,
    ActionIn(args=args, confirmation=confirmation, support=support), {"sub": acteur})` et change toute `HTTPException` en
    `EchecEtape(detail)` ; `releve` attend jusqu'à **60 s** qu'un relevé manuel en cours finisse (sinon `EchecEtape`), puis
    `await lancer_releve(...)` et rend `releve_lire(cle)["statut"]`.
  - `creer_app_admin(..., moteur: Optional[Moteur] = None, planificateur: bool = True,
    maintenant_local: Callable[[], datetime] = lambda: datetime.now().astimezone(), sonde_s: float = 1.0)` ; le moteur par
    défaut est `Moteur(stockage, ExecutantApi(ctx), diffusion, audit, horloge=horloge, sonde_s=sonde_s, resoudre=stockage.boite)`,
    posé sur `app.state.moteur`.
  - `vie` : `macros_livrees_installer(LIVREES)`, `await moteur.interrompre_au_demarrage()`, tâche `moteur.planifier(...)` si
    `planificateur` ; à l'arrêt : annuler le planificateur, `await moteur.fermer()`.
  - Routes (toutes `require_jwt`) :
    - `POST /macros/{id}/lancer` corps `LancerIn{cibles: list[str] (1..32), confirmations: dict[str, str] = {}, support: dict[str, str] = {}}`
      (clés = identifiants tels qu'écrits dans `cibles`, traduits en `Box.cle` après `trouver`) → **202** `{"execution": id}` ;
      `RefusLancement` → son statut.
    - `POST /executions/action` corps `ActionLancerIn{action, args = {}, cibles, confirmations, support}` → 202 : exécution
      d'**une** étape `action` (`macro_id` None, `macro_nom` = clé de l'action), même moteur, mêmes refus.
    - `GET /executions?limite=` (1..200, 50) ; `GET /executions/{id}` (404).
    - `POST /executions/{id}/arreter` → 202 `{"arret": "demande"}` ; 404 inconnue ; 409 déjà finie.
    - `GET /executions/{id}/flux` : `diffusion.abonner(acteur, cle_flux(id))` (429 au plafond global) ; premier événement
      `etat {"execution", "connecte": true, "etat"}` ; puis `macro` et `operation` relayés ; battement `: battement` toutes
      les `battement_s` avec `session_toujours_admin` (coupure `etat {"session": "expiree"}`) ; **fermeture après l'événement
      `macro` `fin`** ; exécution déjà finie → un `macro` `fin` (état final) puis fermeture. Réutilise `ReponseFlux` et `formater`.

- [ ] **Step 1 : tests**

```python
async def test_lancer_202_puis_lire_l_execution(m):        # Diagnostic complet sur gk5 → 202 ; GET /executions/{id} etat terminee
def test_lancer_refus(m):                                  # reboot sans nom 400 ; cliente sans support 409 ; hors ligne 409 ; inconnue 404
async def test_action_seule_passe_par_executer_action(m):  # POST /executions/action service-redemarrer → audit pilotage_action + pilotage_macro
async def test_arreter(m):                                 # 202 puis etat arretee ; 409 sur une exécution finie
async def test_flux_relaie_macro_et_operation(m):          # événements dans l'ordre : etat, macro lancement, …, macro fin ; flux clos
async def test_flux_d_une_execution_finie_rend_la_fin_et_se_ferme(m):   # Review Focus
async def test_flux_cinquieme_ferme_le_plus_ancien(m):     # règle des 4 flux par login
def test_demarrage_interrompt_et_installe_les_livrees(tmp_path):   # exécution en_cours en base → interrompue après lifespan ; 4 livrées
async def test_releve_manuel_en_cours_attendu_puis_echec(m):       # relevé manuel tenu > 60 s → étape echec « relevé déjà en cours »
```

- [ ] **Step 2 :** `$PYTEST packages/secubox-pilotage/tests/test_executions_api.py -q` → FAIL.
- [ ] **Step 3 :** implémenter l'adaptateur, les routes et le cycle de vie ; `api/asgi.py` n'a rien à changer (le moteur
  naît dans `creer_app_admin`) — le vérifier par `test_lanceur.py`.
- [ ] **Step 4 :** `$PYTEST packages/secubox-pilotage/tests -q` → tout vert.
- [ ] **Step 5 :** relecture de sécurité : sous-agent `relecteur-securite` sur `git diff origin/master -- packages/secubox-pilotage/api packages/secubox-pilotage/pilotage` ;
  corriger les constats bloquants.
- [ ] **Step 6 :** commit `feat(pilotage): lancement des macros, exécutions et flux en direct (ref #3702)`.

### Task 7 : page de la console — flotte, barre de commande, actions, journal, box, zoom

**Files :**
- Create : `packages/secubox-pilotage/www/pilotage/console/index.html`
- Test : `packages/secubox-pilotage/tests/test_console_page.py` (statique), `packages/secubox-pilotage/tests/test_console_navigateur.py`
  (Playwright, `pytest.importorskip("playwright.sync_api")`, API simulée par `page.route` comme
  `packages/secubox-annuaire/tests/test_fleet_page_aurora_2487.py`)

**Interfaces :**
- Consumes : `GET /api/v1/pilotage/flotte`, `/catalogue`, `/macros`, `/boxes/{x}`, `/boxes/{x}/support`, `/executions?limite=20`,
  `/executions/{id}`, `/executions/{id}/flux` ; `POST /api/v1/pilotage/executions/action`, `/macros/{id}/lancer`,
  `/executions/{id}/arreter`, `/boxes/{x}/support`.
- Produces : la page ; `parent.postMessage({sbxVue, onglet: "pilotage-console"}, location.origin)` (AURORA § 7) ;
  fonctions JS réutilisées par la Task 8 : `ouvrirLancement(plan)` (écran de lancement, Task 8 le remplit),
  `suivreExecution(id)`, `api(chemin, options)`.
- Mise en page (maquette `Main`, `Panneau`) :
  - tête : « Pilotage », « TR-369 · MAÎTRE <nom> », barre de commande (`aria-label` « Chercher une action, une macro ou
    une box », Ctrl K), pastille « N box en ligne » ;
  - **Flotte** : filtres Toutes + groupes de `/flotte`, cases à cocher ; box muette `disabled` avec « muette N j » ;
  - **centre** : suggestions de la barre (clés et libellés du catalogue, noms de macros et de box ; Entrée = première
    suggestion), un bouton par action du catalogue (regroupés comme la maquette : Relevé, Mettre à jour, Service…,
    Installer…, Interface…, Support, Secrets / Renommer, Redémarrer) ; `forte` en orange/rouge ; paramètre demandé dans
    une petite fenêtre intégrée (unité, paquet, nom) ;
  - **Journal en direct** : une ligne par événement (heure, box ou « macro », libellé, état coloré), Pause ; liens
    « relancer <unité> sur <box> ? » tirés de `propositions` (comparer) et des `services` d'un relevé ;
  - **Macros** : liste (livrées, programmées « chaque nuit HH:MM », en cours), Lancer, Nouvelle (Task 8) ;
  - **<box> · maintenant** : mémoire dispo (Mo), CPU %, swap %, services en échec avec « Relancer » ; **pas de ligne
    disque** (mesure absente en v1) ; le lien « Zoom sur l'interface » de la maquette n'est pas repris.
  - Lancement direct d'une action non `forte` sur une seule box ; sinon écran de lancement (Task 8). Box cliente : la
    session de support ouverte (`GET /boxes/{x}/support`) est envoyée dans `support`, sinon le lancement est refusé dans
    la page avec le message de l'API.
  - **Zoom** (spec § 4.5) : bouton « Agrandir » par panneau (`aria-label` « Agrandir le panneau Flotte », etc.) ; agrandi,
    le panneau garde ses commandes et son flux ; le journal agrandi gagne filtres box et niveau (« tout », « écarts et
    échecs ») et une recherche, côté client ; barre `nav aria-label="Panneaux de la console"` entre panneaux agrandis ;
    « Réduire » et Échap (écouteur sur le `document` de la page seulement ; Échap ferme d'abord une fenêtre ouverte)
    rendent la console entière ; choix gardé dans `sessionStorage` (essais enveloppés de `try/catch`) ; sous 720 px, un
    panneau ouvert est agrandi d'office. Le zoom ne fait **aucun** appel réseau.
  - Au chargement : la dernière exécution `en_cours` de `GET /executions?limite=20` est relue puis suivie.
  - Flux : `fetch` + `ReadableStream` avec `Authorization` (modèle : `pbOuvrirFlux` de `www/fleet/index.html`), tampon borné,
    reprise après coupure seulement si l'exécution est encore `en_cours`. Actualisation 15–60 s si `!document.hidden`,
    jamais pendant une saisie ou une fenêtre ouverte.

- [ ] **Step 1 : tests statiques** (`test_console_page.py`) : en-tête SPDX ; `sbxVue` + `onglet` ; `?embed=1` et
  `?demo=1` ; aucun `<script src=` hors `/shared/sidebar.js` ; aucun `fonts.googleapis` ; ni `confirm(`, `alert(`,
  `prompt(`, ni `innerHTML` ; routes citées ci-dessus présentes ; aucun `eval(`/`new Function`.
- [ ] **Step 2 : tests navigateur** (`test_console_navigateur.py`) :
  - `test_console_1440_sans_debordement` et `test_console_420_un_panneau_agrandi` (`scrollWidth <= innerWidth`, aucune
    `pageerror`, aucun dialogue natif) ;
  - `test_box_muette_non_cochable` ;
  - `test_zoom_echap_garde_le_flux` (agrandir le journal, Échap → console entière, le flux simulé n'a pas été rouvert) ;
  - `test_zoom_chaque_panneau_puis_reduire` ;
  - `test_journal_texte_brut` (unité `<img src=x onerror=…>` dans un événement → aucun `img` créé) ;
  - `test_demo_aucun_appel_d_ecriture` (`?demo=1` : aucune requête autre que GET) ;
  - `test_rechargement_reprend_l_execution_en_cours` (Review Focus).
- [ ] **Step 3 :** `$PYTEST packages/secubox-pilotage/tests/test_console_page.py packages/secubox-pilotage/tests/test_console_navigateur.py -q` → FAIL.
- [ ] **Step 4 :** écrire la page (jetons de couleur de AURORA § 2, container queries, `.cadre` sans `min-height`).
- [ ] **Step 5 :** même commande → PASS ; prendre les captures 1440×900 et 420 px (`file://…?demo=1`) et **les lire** :
  pas de texte coupé, pas de débordement.
- [ ] **Step 6 :** commit `feat(pilotage): page de la console, journal en direct et zoom des panneaux (ref #3702)`.

### Task 8 : éditeur de macro, écran de lancement, simulation

**Files :**
- Modify : `packages/secubox-pilotage/www/pilotage/console/index.html`
- Test : `packages/secubox-pilotage/tests/test_console_page.py`, `packages/secubox-pilotage/tests/test_console_navigateur.py`

**Interfaces :**
- Consumes : `POST/PUT/DELETE /api/v1/pilotage/macros…`, `/macros/{id}/copier`, `/macros/{id}/simuler`, `/macros/{id}/lancer` ;
  `ouvrirLancement`, `suivreExecution`, `api` (Task 7).
- Éditeur (maquette `Macro`) : nom (`aria-label` « Nom de la macro ») ; à gauche le catalogue (actions de `/catalogue`,
  `forte` en orange/rouge) et les contrôles du maître (relevé, condition, comparer, attendre) ; au centre les étapes
  numérotées avec leurs champs (bornes du Global Constraints, mêmes listes fermées en `<select>`), ajout par clic et par
  glisser, ordre modifiable **au clavier aussi** (boutons Monter/Descendre), suppression ; cibles (box cochées ou
  groupe) ; « Quand » : à la demande ou chaque nuit HH:MM (option désactivée, avec la raison, si une étape est `forte`
  ou une cible cliente) ; « Simuler sur… », « Enregistrer », « Enregistrer et lancer ». Le message 400 de l'API est affiché
  tel quel dans la page. Macro livrée : lecture seule + « Copier ».
- Écran de lancement (maquette `Confirmer`, `role="dialog"`) : plan par box et par étape tiré de `simuler` (durée,
  coupure prévue en rouge), rappel « Une box après l'autre : <b2> ne commence qu'une fois <b1> revenue et son relevé sain »,
  un champ par box **du maillage** quand une étape est `forte` ; « Lancer » `disabled` tant qu'un nom ne correspond pas
  exactement, libellé « Lancer (k noms sur n) » ; Annuler et Échap ferment ; envoi `confirmations` et `support`.

- [ ] **Step 1 : tests** : statiques (routes d'écriture des macros présentes, `role="dialog"`) ; navigateur :
  `test_lancer_inactif_tant_qu_un_nom_manque` (gk7 tapé, gk6 vide → `disabled` ; « gk6 » → actif ; « GK6 » → inactif) ;
  `test_programmation_desactivee_si_reboot` ; `test_editeur_ordre_au_clavier` ; `test_echap_ferme_d_abord_le_dialogue` ;
  `test_erreur_400_affichee` ; `test_editeur_420_sans_debordement`.
- [ ] **Step 2 :** lancer les deux fichiers de test → FAIL sur les nouveaux tests.
- [ ] **Step 3 :** compléter la page.
- [ ] **Step 4 :** mêmes tests → PASS ; captures 1440 et 420 px de l'éditeur et de l'écran de lancement, lues.
- [ ] **Step 5 :** commit `feat(pilotage): éditeur de macro et écran de lancement (ref #3702)`.

### Task 9 : paquet, menu, documentation

**Files :**
- Create : `packages/secubox-pilotage/menu.d/596-pilotage-console.json`
- Modify : `packages/secubox-pilotage/debian/rules` (installer `www/pilotage/console/index.html` dans
  `/usr/share/secubox/www/pilotage/console/` et le menu dans `/usr/share/secubox/menu.d/`)
- Modify : `packages/secubox-pilotage/tests/test_paquet.py` (`test_pas_d_entree_de_menu_et_hors_arbre` : R29 levée pour
  cette seule entrée ; assertions sur `arbre.yaml` inchangées)
- Modify : `packages/secubox-hub/espaces.json` (`"pilotage-console": {"espace": "systeme", "objet": "BOX"}`)
- Modify : `packages/secubox-pilotage/debian/changelog` (0.7.0-1~trixie1), `packages/secubox-hub/debian/changelog`
  (1.12.57-1~trixie1), `packages/secubox-pilotage/README.md` (section « Console (#3702) »)

**Interfaces :**
- Menu : `{"id": "pilotage-console", "name": "Console de pilotage", "icon": "🎛", "path": "/pilotage/console/",
  "category": "mesh", "order": 596, "description": "Actions, macros et journal en direct sur plusieurs box du parc",
  "requires": ["secubox-pilotage"], "theme": "mesh", "www": "pilotage", "unite": "pilotage"}` — catégorie de la Flotte ;
  `www`/`unite` font juger l'entrée par `/usr/share/secubox/www/pilotage` et `/run/secubox/pilotage.sock`.
- Profil `full` : rien à changer dans `secubox-profiles` (l'entrée n'y est pas masquée ; le paquet n'est installé que
  par la fonction « Maître du parc »). Le test le fige.

- [ ] **Step 1 : tests** — dans `test_paquet.py` : `test_console_installee_et_au_menu` (rules installe la page et le
  menu ; seul fichier de `menu.d/` = `596-pilotage-console.json`, `requires == ["secubox-pilotage"]`, catégorie `mesh`) et
  `test_console_visible_au_profil_full` (`"pilotage-console"` absent de `menu_off` de
  `packages/secubox-profiles/profiles/full.toml`, `"pilotage"` absent de `on`) ; version du changelog `0.7.0-1~trixie1`.
- [ ] **Step 2 :** `$PYTEST packages/secubox-pilotage/tests/test_paquet.py packages/secubox-hub/tests/test_espaces_2212.py -q` → FAIL.
- [ ] **Step 3 :** fichiers, rules, `espaces.json`, changelogs (dire ce qui change **et ce qui n'est pas repris** : pas de
  disque, pas de zoom sur l'interface d'une box, agent inchangé), README (routes, tables, macros livrées, planificateur,
  états).
- [ ] **Step 4 :** `$PYTEST packages/secubox-pilotage/tests -q` et `$PYTEST packages/secubox-hub/tests -q` → verts ;
  `python3 scripts/license-headers.py --check packages/secubox-pilotage packages/secubox-hub/espaces.json` sans écart ;
  `cd packages/secubox-pilotage && dpkg-buildpackage -us -uc -b` puis `dpkg-deb -c ../secubox-pilotage_0.7.0-1~trixie1_all.deb | grep -E 'pilotage/console/index.html|596-pilotage-console.json'`
  → deux lignes.
- [ ] **Step 5 :** commit `feat(pilotage): console au menu du maître, version 0.7.0 (ref #3702)`.

### Task 10 : déploiement sur gk2 et banc (exécutée par le CONTRÔLEUR, jamais par un sous-agent)

- [ ] **Step 1 :** branche à jour : `git fetch origin && git rebase origin/master` ; suites vertes
  (`$PYTEST packages/secubox-pilotage/tests -q`, `$PYTEST packages/secubox-hub/tests -q`) ; versions déployées sur gk2
  (`ssh root@192.168.1.200 "dpkg-query -W secubox-pilotage secubox-hub"`) inférieures à 0.7.0-1~trixie1 et
  1.12.57-1~trixie1, et aucune couche non fusionnée sur gk2 (sinon fusionner d'abord).
- [ ] **Step 2 :** construire les deux paquets (`dpkg-buildpackage -us -uc -b` dans chaque dossier), publier :
  `scripts/apt-publier.sh packages/secubox-pilotage_0.7.0-1~trixie1_all.deb packages/secubox-hub_1.12.57-1~trixie1_all.deb`.
- [ ] **Step 3 :** sur gk2 : `df -h /` d'abord (racine chargée) ; `apt-get update && apt-get install -y secubox-pilotage secubox-hub`
  **sans timeout** ; `dpkg-query -W` montre les deux versions ; `systemctl is-active secubox-pilotage` ; journal du service
  sans trace d'erreur.
- [ ] **Step 4 : agrégateur.** Aucun redémarrage de `secubox-aggregator` n'est attendu (pilotage a sa propre unité,
  `espaces.json` est relu à chaque appel). S'il en fallait un (menu absent), il est **groupé** avec les autres
  déploiements en attente et **demande le « go » du propriétaire** (4 à 8 min de Hall coupé) ; vérification par
  `curl --unix-socket /run/secubox/aggregator.sock http://x/health` = 200, pas `is-active`.
- [ ] **Step 5 : chemin public** (celui du navigateur) : `curl -sk https://127.0.0.1/pilotage/console/ -H "Host: admin.gk2.secubox.in"`
  → 200 ; `…/api/v1/pilotage/macros` sans session → 401, avec la session administrateur → les 4 livrées ; menu du Hub :
  entrée « Console de pilotage » ; coup d'œil humain sur la page avec les vraies box.
- [ ] **Step 6 : banc (spec § 6)**, depuis gk2, sur gk6 et gk7 (lien TR-369 gk2 → gk7 vérifié le 2026-11-14) :
  Diagnostic complet sur 2 box ; Mise à jour sûre avec un écart provoqué (pendant `maj-paquets` sur la première box :
  `systemd-run --unit=secubox-banc-echec /bin/false`, puis `systemctl reset-failed secubox-banc-echec.service` après)
  → arrêt avant la 2e box ; refus d'un `reboot` sans nom retapé (400, « Lancer » inactif) ; refus d'une programmation
  contenant `reboot` (400) ; zoom de chaque panneau puis Échap (console entière, journal non coupé) ;
  `systemctl restart secubox-pilotage` sur gk2 pendant une exécution (annoncé au propriétaire) → `interrompue` ; une box
  muette non cochable. Noter chaque résultat.
- [ ] **Step 7 :** suivi : entrée datée dans `.claude/HISTORY.md` (avec `closes #3702` une fois le banc tenu),
  `.claude/WIP.md`, README déjà à jour ; PR (`scripts/agent-worktree.sh finish` ou `gh pr create`), fusion ; après un
  squash avec `--delete-branch`, ne pas relancer `finish` (nettoyer à la main) ; `scripts/sync-issues.sh`.
