<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# TV Privacy — indices partagés entre box : plan d'implémentation

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal :** chaque box publie par MirrorNet ses domaines pub/pistage/télémétrie confirmés et ses légitimes, reçoit ceux des
autres box de confiance, et son moteur auto met à l'essai, avec le poids maximal, un domaine vu localement en coupure pub
et confirmé ailleurs.

**Architecture :** trois composants, chacun sous son compte, reliés par des fichiers. `secubox-ad-guard` (compte
`secubox`) écrit sa publication et lit les livraisons. `secubox-mirrornet` (compte `secubox-mirrornet`) transforme la
publication en objet vérifié, écrit une demande pour l'annuaire et livre les versions reçues. `secubox-annuaire`
(`secubox`, seul détenteur de `node.key`) signe l'offre, les versions et les abonnements « tv-indices », sans jeton
d'administrateur (même principe que `annuaire/offres.py`, #3021).

**Tech stack :** Python 3 (FastAPI, SQLite), systemd, AppArmor, pytest.

**Spec :** `docs/superpowers/specs/2026-11-11-tv-privacy-indices-maillage-design.md`

## Global Constraints

- Contenu publié : rien d'autre que domaine → catégorie (PUBLICITE, TRACKING, TELEMETRIE) et liste de domaines légitimes ;
  ni appareil, ni slug, ni MAC, ni date par domaine, ni compteur.
- Jeu de classe `communaute`, `donnees_personnelles = "non"`, format `application/json`, licence `CC0-1.0`, provenance
  `secubox-ad-guard:tv-indices`, offre `kind=dataset`, `approval_mode=auto`, `scope = {"usage": "tv-indices"}`, nom
  `Indices TV Privacy — <boxname>`.
- Une version au plus par heure ; aucune nouvelle version si le contenu (octets canoniques) ne change pas.
- Producteurs écoutés : niveau ≥ `confiance_min` de MirrorNet (LIMITED par défaut).
- L'indice n'est jamais un déclencheur de coupure, n'agit que sur un domaine vu localement pendant une coupure, sur le
  domaine EXACT (jamais un parent ni un suffixe).
- Poids maximal : `SCORE_INDICE = 100` ; une coupure suffit ; essai automatique même si `auto_essai` est désactivé et même
  en risque `partage`, si l'appareil est en mode auto et non guidé ; un légitime d'une autre box l'empêche.
- Catégories protégées (`dnstv_taxonomie.PROTEGEES`) : un indice ne lève que INCONNU ; STREAMING, CDN, DRM,
  AUTHENTIFICATION, MISE_A_JOUR restent refusées.
- Pas d'écho : une règle née d'un indice n'est publiée que confirmée par l'administrateur local.
- Retrait : un essai né d'indices est retiré quand plus aucun producteur ne le confirme ou qu'un producteur le déclare
  légitime ; une règle confirmée par l'administrateur reste ; une règle confirmée par le moteur à partir d'un indice
  suit l'indice (oubliée quand il disparaît ou qu'un producteur la déclare légitime).
- Plafonds de lecture : fichier livré ≤ 2 Mio, ≤ 20 000 indices et ≤ 5 000 légitimes par producteur, ≤ 64 producteurs.
- Interrupteurs `indices_publier` et `indices_recevoir`, vrais par défaut.
- Règles du dépôt : SPDX CMSD-1.0, versions de paquets montées, comptes dédiés, AppArmor enforce, audit des gestes signés
  (`par = "fond"`), aucun secret, `relecteur-securite` avant la PR.

## Review Focus

1. Fichier livré malformé, tronqué ou géant (producteur hostile) → ignoré entier, les autres producteurs comptent encore.
2. Domaine reçu avec majuscules, point final, caractères interdits ou nom de 300 caractères → rejeté par `dnstv.valider_domaine`, jamais proposé.
3. Box sans aucune TV en mode auto, ou TV en apprentissage guidé → aucun essai né d'un indice.
4. `indices_recevoir` coupé alors que des essais nés d'indices sont en cours → ces essais sont retirés au passage suivant.
5. Annuaire sans `node.key`, ou export MirrorNet absent → rien n'est signé, aucune exception ne remonte dans la boucle de synchronisation.

Chaque ligne a son test dans la tâche qui possède le code (marqué « Review Focus n »).

---

### Task 1 : ad-guard — contenu publié et lecture des livraisons (module pur)

**Files :**
- Create : `packages/secubox-ad-guard/api/dnstv_indices.py`
- Test : `packages/secubox-ad-guard/tests/test_indices_3666.py`

**Interfaces :**
- Produces :
  - `PUBLICATION = Path("/var/lib/secubox/ad-guard/dnstv/indices-publication.json")`
  - `LIVRAISONS = Path("/var/lib/secubox-mirrornet-partage/livraisons/tv-indices")`
  - `CATEGORIES_INDICE = ("PUBLICITE", "TRACKING", "TELEMETRIE")`
  - `contenu(regles: dnstv_regles.Regles, exceptions: list, taxo: dnstv_taxonomie.Taxonomie) -> dict` →
    `{"format": 1, "jeu": "tv-indices", "indices": {domaine: categorie}, "legitimes": [domaines triés]}`
  - `octets(c: dict) -> bytes` : `json.dumps(c, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()`
  - `ecrire_publication(publier: bool, recevoir: bool, c: dict, chemin: Path = PUBLICATION) -> bool` : écrit
    `{"format": 1, "publier", "recevoir", "contenu": c}` en atomique, 0640, seulement si changé ; rend True si écrit.
  - `@dataclass Index` : `confirmes: Dict[str, Dict[str, str]]` (domaine → {nom_box: categorie}),
    `legitimes: Dict[str, Set[str]]` (domaine → noms) ; méthodes `confirmateurs(d) -> List[str]` (triés),
    `legitime_chez(d) -> List[str]`, `categorie(d) -> Optional[str]` (la plus fréquente, puis ordre alphabétique).
  - `charger(dossier: Path = LIVRAISONS) -> Index` : lit `index.json` ({did: {"nom", "empreinte"}}) et `<did>.json`.

Règles de `contenu` : indices = domaines d'une règle `confirme` (sauf si `r.get("indice")` non vide et que la dernière
transition n'est pas `origine == "admin"`), plus exceptions `type == "bloquer"` ; catégorie = `taxo.classer(d)["categorie"]`
si elle est dans `CATEGORIES_INDICE`, sinon `PUBLICITE`. Légitimes = exceptions `type == "autoriser"` + règles `rejete` ou
`retire` dont la dernière transition a `origine == "admin"`. Un domaine à la fois indice et légitime : légitime l'emporte.

- [ ] **Step 1 : tests**
  - `test_contenu_sans_appareil_ni_date` : deux règles confirmées (`tv-salon`, `tv-chambre`) sur `ads.ex.com` → `contenu["indices"] == {"ads.ex.com": "PUBLICITE"}` et `"tv-" not in octets(contenu)` et aucune clé autre que `format, jeu, indices, legitimes`.
  - `test_pas_d_echo` : règle confirmée par `auto` avec `indice=["gk6"]` → absente ; même règle dont la dernière transition est `origine="admin"` → présente.
  - `test_legitime_l_emporte` : exception `autoriser` et règle confirmée sur le même domaine → seulement dans `legitimes`.
  - `test_octets_deterministes` : deux appels sur des entrées permutées → mêmes octets.
  - `test_ecrire_publication_atomique_0640_et_si_change` : premier appel True et mode 0o640, second identique False.
  - `test_charger_valide_et_plafonne` (Review Focus 1, 2) : un producteur valide, un fichier de 3 Mio, un JSON tronqué, un domaine `"ADS.Ex.com."`, une catégorie `"STREAMING"` → seul le valide compte, le domaine en majuscules est normalisé ou rejeté selon `dnstv.valider_domaine`, la catégorie interdite est ignorée.
  - `test_index_confirmateurs_et_legitimes` : gk2 et gk6 confirment `a.com`, gk1 le déclare légitime → `confirmateurs("a.com") == ["gk2", "gk6"]`, `legitime_chez("a.com") == ["gk1"]`.
- [ ] **Step 2 :** `cd packages/secubox-ad-guard && ../../.venv/bin/python -m pytest -q tests/test_indices_3666.py` → FAIL (module absent).
- [ ] **Step 3 :** implémenter `api/dnstv_indices.py` (lecture `O_NOFOLLOW`, taille vérifiée avant `json.loads`).
- [ ] **Step 4 :** relancer → PASS.
- [ ] **Step 5 :** commit `feat(ad-guard): indices TV Privacy — contenu publié et livraisons (ref #3666)`.

### Task 2 : ad-guard — l'indice dans la détection et le moteur auto

**Files :**
- Modify : `packages/secubox-ad-guard/api/dnstv_regles.py` (`valider_regle`, `proposer`)
- Modify : `packages/secubox-ad-guard/api/dnstv_detect.py` (`detecter`)
- Modify : `packages/secubox-ad-guard/api/dnstv_taxonomie.py` (nouvelle `refus_indice`)
- Modify : `packages/secubox-ad-guard/api/dnstv_auto.py` (`tick`)
- Test : `packages/secubox-ad-guard/tests/test_indices_moteur_3666.py`

**Interfaces :**
- Consumes : `dnstv_indices.Index` (Task 1).
- Produces :
  - règle : champ facultatif `indice: List[str]` (noms de box, ≤ 8, chacun `^[a-z0-9-]{1,32}$`), conservé par
    `valider_regle` ; `Regles.proposer(..., indice: Optional[List[str]] = None)`.
  - `dnstv_detect.SCORE_INDICE = 100` ; `detecter(..., indices: Set[str] = frozenset())` : un domaine de `indices` vu dans
    ≥ 1 coupure devient candidat (`score = SCORE_INDICE`, risque `partage` s'il est vu hors coupure, sinon `faible`), même
    INCONNU, et n'est jamais regroupé sous un parent.
  - `dnstv_taxonomie.refus_indice(taxo, domaine, macs=(), confirmes_admin=frozenset()) -> Optional[str]` : comme
    `refus_auto`, mais INCONNU est permis.
  - `dnstv_auto.tick(..., indices: Optional[Index] = None)` : pour un candidat dont le domaine a ≥ 1 confirmateur et aucun
    légitime, `proposer(..., indice=confirmateurs, motif="suggéré par " + ", ".join(confirmateurs))` puis transition
    `essai` (`"essai automatique (indice du maillage)"`) si appareil non guidé et `refus_indice(...)` est None, quel que
    soit `reglage.auto_essai` et le risque `faible`/`partage`. Domaine légitime ailleurs : candidat seulement, motif
    `"légitime chez " + noms`. Retrait : chaque règle en `essai` avec `indice` non vide dont le domaine n'a plus aucun
    confirmateur, ou a un légitime → `retire`, motif `"indice retiré"`.

- [ ] **Step 1 : tests**
  - `test_une_coupure_suffit_et_inconnu_leve` : un domaine INCONNU vu dans une seule coupure, indice gk2 → candidat score 100 puis `essai` avec `auto_essai=False`.
  - `test_partage_part_aussi_en_essai` : domaine vu aussi hors coupure → `essai`.
  - `test_jamais_sans_vue_locale` : indice sur un domaine jamais vu par l'appareil → aucune règle.
  - `test_protegee_reste_protegee` : domaine classé STREAMING localement + indice → candidat, jamais `essai`.
  - `test_legitime_ailleurs_freine` : indice gk2 + légitime gk1 → candidat, motif `"légitime chez gk1"`.
  - `test_appareil_guide_jamais_seul` (Review Focus 3) : appareil dans `guides` → candidat seulement.
  - `test_aucun_appareil_auto` (Review Focus 3) : état sans client en mode auto → aucun changement.
  - `test_retrait_quand_l_indice_disparait` (Review Focus 4) : essai né d'un indice, second passage avec `indices=Index()` vide → `retire`, motif `"indice retiré"` ; une règle `confirme` reste.
  - `test_domaine_exact_jamais_parent` : trois variantes `a1.x.ex.com`, `a2…`, `a3…` dont une porte un indice → le domaine porteur reste exact, pas de candidat `x.ex.com` né de lui.
  - `test_valider_regle_indice_borne` : `indice` de 9 noms ou un nom `"GK 2"` → `ErreurRegle`.
- [ ] **Step 2 :** lancer → FAIL.
- [ ] **Step 3 :** implémenter (les tests existants de `tick` doivent rester verts : `indices=None` ne change rien).
- [ ] **Step 4 :** `../../.venv/bin/python -m pytest -q tests/` (suite ad-guard entière) → mêmes échecs qu'avant la tâche, aucun nouveau.
- [ ] **Step 5 :** commit `feat(ad-guard): indices du maillage dans la détection auto (ref #3666)`.

### Task 3 : ad-guard — branchement du moteur, interrupteurs, routes et page

**Files :**
- Modify : `packages/secubox-ad-guard/sbin/secubox-adguard-auto` (`main`)
- Modify : `packages/secubox-ad-guard/api/dnstv.py` (`ETAT_DEFAUT`, `valider_etat`)
- Modify : `packages/secubox-ad-guard/api/main.py` (routes)
- Modify : `packages/secubox-ad-guard/www/tv-privacy/index.html`
- Modify : `packages/secubox-ad-guard/debian/secubox-ad-guard-auto.service` (`ReadOnlyPaths=-/var/lib/secubox-mirrornet-partage`)
- Test : `packages/secubox-ad-guard/tests/test_indices_routes_3666.py`

**Interfaces :**
- Consumes : Tasks 1 et 2.
- Produces :
  - état : `indices_publier: bool`, `indices_recevoir: bool`, défaut True, validés par `valider_etat`.
  - `main()` : à chaque passage, `indices = dnstv_indices.charger() if etat["indices_recevoir"] else Index()` passé à
    `tick` ; puis `ecrire_publication(etat["indices_publier"], etat["indices_recevoir"], contenu(...))`.
  - `GET /adblock-tv/indices` (`require_jwt`) → `{"publier", "recevoir", "recus": int, "producteurs": [{"nom", "indices", "legitimes"}], "publies": int}`.
  - `POST /adblock-tv/indices` (`require_jwt`) corps `{"publier": bool, "recevoir": bool}` → sous `dnstv_regles.verrou()`, état écrit, audit `tv_indices_reglage`.
- [ ] **Step 1 : tests** — GET sans jeton 401 ; POST bascule et persiste ; GET compte les producteurs depuis un dossier de livraisons de test ; `main()` avec `indices_recevoir=False` passe un `Index` vide (Review Focus 4).
- [ ] **Step 2 :** lancer → FAIL. **Step 3 :** implémenter ; page : encart « Indices du maillage » (reçus, producteurs, dernière mise à jour), deux interrupteurs, et le motif des règles déjà affiché. **Step 4 :** PASS. **Step 5 :** commit `feat(ad-guard): interrupteurs et encart des indices du maillage (ref #3666)`.

### Task 4 : MirrorNet — publication locale et livraison

**Files :**
- Create : `packages/secubox-mirrornet/secubox_mirrornet/locaux.py`
- Modify : `packages/secubox-mirrornet/secubox_mirrornet/schema.py` (v6 : `ALTER TABLE offer ADD COLUMN usage TEXT NOT NULL DEFAULT ''`)
- Modify : `packages/secubox-mirrornet/secubox_mirrornet/catalogue.py` (`offre_normalisee` lit `scope.usage`, texte ≤ 32 `^[a-z0-9-]*$`, sinon `''` ; insert/upsert de `usage`)
- Modify : `packages/secubox-mirrornet/api/main.py` (`tirer_maintenant` appelle `locaux.passe`)
- Modify : `packages/secubox-mirrornet/debian/postinst`, `debian/secubox-mirrornet.service`, `apparmor/secubox-mirrornet`
- Test : `packages/secubox-mirrornet/tests/test_locaux_3666.py` (+ mise à jour du numéro de schéma dans `test_api_3645.py`, `test_modele_3645.py`)

**Interfaces :**
- Produces :
  - `PARTAGE = Path("/var/lib/secubox-mirrornet-partage")` (root crée en postinst, `secubox-mirrornet:secubox` 0750) ;
    `PUBLICATIONS = PARTAGE / "publications.json"` ; `LIVRAISON = PARTAGE / "livraisons" / "tv-indices"`.
  - `SOURCE_TV = Path("/var/lib/secubox/ad-guard/dnstv/indices-publication.json")`
  - `deposer(cx, reglages, source: Path = SOURCE_TV) -> Optional[dict]` : lit la publication d'ad-guard (≤ 2 Mio,
    `O_NOFOLLOW`), écrit l'objet `octets(contenu)` par `objets.ecrire`, `objets.noter(..., soi)`, puis écrit
    `PUBLICATIONS` = `{"format": 1, "jeux": {"tv-indices": {"publier", "recevoir", "empreinte", "taille"}}}` (0640,
    atomique, seulement si changé). Rend le dict écrit ou None.
  - `livrer(cx, dossier: Path = LIVRAISON) -> int` : pour chaque abonnement `role='abonne'` Actif à une offre
    `usage='tv-indices'` dont le fournisseur est au niveau ≥ `confiance_min` (un fournisseur déclassé n'est plus livré :
    ses indices disparaissent et les essais qui en sont nés sont retirés, Task 2), copie (atomique, 0640) la dernière version non retirée PRÉSENTE dans `objet` vers
    `<did-hex32>.json`, écrit `index.json` `{did: {"nom", "empreinte"}}`, supprime les fichiers d'abonnements clos. Rend le
    nombre de fichiers livrés.
  - `passe(cx, reglages) -> dict` : `deposer` puis `livrer`, sans jamais lever (journalise).
- [ ] **Step 1 : tests** — dépôt crée l'objet et la demande ; fournisseur passé OBSERVER → plus livré ; contenu identique → pas de nouvelle demande ; livraison seulement des abonnements Actif à `usage='tv-indices'` (une offre `usage=''` n'est jamais livrée) ; abonnement résilié → fichier supprimé ; source absente ou de 3 Mio → None sans exception ; lien symbolique refusé.
- [ ] **Step 2–4 :** FAIL puis implémenter puis PASS (suite MirrorNet entière verte).
- [ ] **Step 5 :** commit `feat(mirrornet): publication locale et livraison des indices TV (ref #3666)`.

### Task 5 : annuaire — signer offre, versions et abonnements « tv-indices » en tâche de fond

**Files :**
- Create : `packages/secubox-annuaire/annuaire/mirrornet_locaux.py`
- Modify : `packages/secubox-annuaire/api/main.py` (`_dir_sync_loop` appelle le traitement après `_cycle_sync`)
- Modify : `packages/secubox-annuaire/debian/*.service` / AppArmor si présent (lecture de `/var/lib/secubox-mirrornet-partage/publications.json`)
- Test : `packages/secubox-annuaire/tests/test_mirrornet_locaux_3666.py`

**Interfaces :**
- Consumes : `PUBLICATIONS` (Task 4) ; verbes `offer_service`, `publish_dataset_version`, `subscribe`,
  `cancel_subscription`, `revoke_offer`, `_get_offers`, `dataset_versions`, `confiance.niveau`.
- Produces : `traiter(journal, priv: Optional[bytes], did: Optional[str], boxname: str, demandes: Optional[dict], maintenant: datetime) -> dict`
  (`{"offre": "creee"|"existante"|"retiree"|None, "version": empreinte|None, "abonnements": n, "resiliations": n}`),
  idempotent :
  - `publier` vrai : offre propre `scope.usage == "tv-indices"` créée si absente (constantes de Global Constraints) ;
    version publiée si `empreinte` ≠ dernière version et dernière version > 3600 s.
  - `publier` faux : offre propre `tv-indices` retirée (`revoke_offer`).
  - `recevoir` vrai : abonnement (`provider` lié) à chaque offre `tv-indices` d'un autre nœud de niveau ≥ LIMITED sans
    abonnement en cours ; `recevoir` faux : résiliation de ces abonnements.
  - Chaque geste signé audité `_auditer_mirrornet(..., par="fond")`.
- [ ] **Step 1 : tests** — création d'offre puis idempotence ; version limitée à une par heure ; abonnement auto à l'offre d'un autre membre LIMITED, jamais à un OBSERVER ni à une offre sans `usage` ; `recevoir=False` résilie ; `priv=None` ou `demandes=None` → aucun geste, aucune exception (Review Focus 5).
- [ ] **Step 2–4 :** FAIL, implémenter, PASS (suite annuaire : mêmes 16 échecs qu'avant, aucun nouveau).
- [ ] **Step 5 :** commit `feat(annuaire): offre, versions et abonnements tv-indices signés en tâche de fond (ref #3666)`.

### Task 6 : livraison

**Files :** `debian/changelog` des trois paquets (ad-guard, mirrornet, annuaire), README de chaque paquet, `.claude/HISTORY.md`, `.claude/WIP.md`.

- [ ] Monter les versions, changelogs, README (routes, fichiers échangés, interrupteurs).
- [ ] Relecture `relecteur-securite` du diff entier ; corriger ; ruff.
- [ ] PR, fusion, construction, `scripts/apt-publier.sh`.
- [ ] Banc gk6 ↔ gk2 (gk12 hors ligne) : installation par apt ; vérifier offres créées, abonnements croisés, livraisons dans `/var/lib/secubox-mirrornet-partage/livraisons/tv-indices/`, puis un domaine de test confirmé sur gk2 qui devient candidat-essai sur une TV auto de gk6 vue en coupure (ou, à défaut de TV sur gk6, la présence de l'indice dans `GET /adblock-tv/indices`).
- [ ] Les routes ad-guard sont servies DANS l'agrégateur : relance groupée de l'agrégateur sur gk2 (4–8 min de Hall hors ligne), à annoncer au propriétaire avant.
- [ ] Suivi HISTORY/WIP, `closes #3666` une fois déployé et vérifié.
