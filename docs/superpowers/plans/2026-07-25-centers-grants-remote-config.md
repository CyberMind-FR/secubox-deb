# Centres & Grants + Remote Config — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Une box fédère avec 0..N « centres » et reçoit de la config distante en calques (baseline+override+local), tout en restant souveraine — bâti sur le journal signé de `secubox-annuaire`.

**Architecture:** On étend le journal annuaire de deux ops signées (`GRANT_ISSUE`/`GRANT_REVOKE`) et le `ConfigBlob` d'un champ `layer`. Un `grants.py` résout la propriété par `(scope, layer)` depuis le journal ; un `config_compose.py` (pur) deep-merge les calques par précédence (baseline<override<local) ; `config_apply.py` compose puis applique via le 4R double-buffer existant. Toute écriture passe par un ctl délégué ; le calque `local` n'est jamais délégable.

**Tech Stack:** Python 3.11, pydantic (`ConfigDict(extra="forbid")`), `tomllib`/`tomli-w`, Ed25519 (`annuaire.crypto`), le 4R existant (`annuaire.config_apply`), FastAPI (aggregator-served), bash ctl, webui hybrid-dark.

## Global Constraints

- **Calques** : ordre fixe `LAYER_ORDER = ["baseline", "override", "local"]`. `local` = box-local, **jamais délégable** à un centre.
- **Scopes non délégables** : `NON_DELEGATABLE = {"auth", "secrets"}` — un `GRANT_ISSUE` visant ces scopes (ou le calque `local`) est **rejeté**.
- **Unicité** : au plus un grant actif par `(scope, layer)` non-local ; émettre sur un `(scope, layer)` déjà accordé est **rejeté** (révoquer d'abord).
- **Souveraineté** : le calque `local` est toujours composé **en dernier** (précédence maximale) ; un centre ne peut jamais l'écrire.
- **Deep-merge** : tables TOML = merge récursif ; valeurs scalaires et listes = **remplacées** par le calque de précédence supérieure.
- **4R fail-safe** : shadow → validate (BLAKE2b + parse TOML) → swap atomique `os.replace` → rollback gardé ; un blob composé invalide **garde le dernier-bon actif**.
- **Signatures** : toute op de journal signée Ed25519 sur `crypto.canonical_bytes(payload_sans_sig)` ; un `CONFIG_PUBLISH` d'un centre est vérifié (signature centre + grant actif) avant apply.
- **Audit** : le journal append-only EST la piste d'audit (qui a accordé/poussé/révoqué quoi, quand).
- **Zéro-centre = autonomie** : sans grant, seul `local` existe.
- **Aucune action root in-process** dans l'API : délégation au ctl `sbx-centersctl` (pattern [[feedback_webui_delegates_to_confined_ctl]]).
- Commits : `Co-Authored-By: Gerald KERMA <devel@cybermind.fr>`, aucune réf IA. Tests par-répertoire (`cd packages/secubox-annuaire && python3 -m pytest tests/...`).

## File Structure

- `annuaire/model.py` (modifié) — `Op.GRANT_ISSUE`/`GRANT_REVOKE`, modèle `Grant`, `ConfigBlob.layer`, constantes `LAYER_ORDER`/`NON_DELEGATABLE`.
- `annuaire/grants.py` (neuf) — résolution des grants depuis le journal.
- `annuaire/config_compose.py` (neuf) — deep-merge pur des calques.
- `annuaire/config_apply.py` (modifié) — `apply_composed()` : compose puis 4R.
- `annuaire/verbs.py` (modifié) — `grant_issue()`/`grant_revoke()`.
- `sbin/sbx-centersctl` (neuf) — CLI de gestion.
- `api/main.py` (modifié) — endpoints /centers.
- `www/centers/index.html` + `menu.d/…-centers.json` (neufs) — panneau + navbar.
- `debian/…` — packaging.

---

### Task 1: model — ops GRANT_ISSUE/GRANT_REVOKE + Grant + ConfigBlob.layer

**Files:** Modify `annuaire/model.py`; Test `tests/test_grant_model.py`

**Interfaces:**
- Produces: `Op.GRANT_ISSUE`, `Op.GRANT_REVOKE`; `class Grant(BaseModel)` fields `{grant_id:str, center_did:str, capability:str, scope:str, layer:str, issued_by:str, created_at:str, sig:Optional[str], signer_did:Optional[str]}`; `LAYER_ORDER=["baseline","override","local"]`; `NON_DELEGATABLE={"auth","secrets"}`; `ConfigBlob.layer:str` (default `"baseline"`).

- [ ] **Step 1: failing test**
```python
# tests/test_grant_model.py
import sys; from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]; sys.path.insert(0, str(ROOT))
from annuaire.model import Op, Grant, LAYER_ORDER, NON_DELEGATABLE, ConfigBlob

def test_grant_ops_exist():
    assert Op.GRANT_ISSUE == "grant_issue" and Op.GRANT_REVOKE == "grant_revoke"

def test_layer_order_and_non_delegatable():
    assert LAYER_ORDER == ["baseline", "override", "local"]
    assert "auth" in NON_DELEGATABLE and "secrets" in NON_DELEGATABLE

def test_grant_model_forbids_extra():
    g = Grant(grant_id="g1", center_did="did:plc:"+("a"*32), capability="config",
              scope="firewall", layer="baseline", issued_by="did:plc:"+("b"*32))
    assert g.layer == "baseline" and g.sig is None
    import pytest
    with pytest.raises(Exception):
        Grant(grant_id="g1", center_did="x", capability="config", scope="s",
              layer="baseline", issued_by="y", bogus=1)

def test_configblob_has_layer_default_baseline():
    b = ConfigBlob(config_id="cfg-firewall", publisher="did:plc:"+("a"*32),
                   scope="firewall", version=1, content_hash="deadbeef")
    assert b.layer == "baseline"
```
- [ ] **Step 2:** `cd packages/secubox-annuaire && python3 -m pytest tests/test_grant_model.py -q` → FAIL.
- [ ] **Step 3: implement** — in `annuaire/model.py`: add to `Op` enum `GRANT_ISSUE = "grant_issue"` and `GRANT_REVOKE = "grant_revoke"`. Add module constants `LAYER_ORDER = ["baseline", "override", "local"]` and `NON_DELEGATABLE = {"auth", "secrets"}`. Add `layer: str = Field(default="baseline", description="config layer; local is box-only")` to `ConfigBlob`. Add the `Grant` model mirroring `NodeRecord` style (`model_config = ConfigDict(extra="forbid")`, DID pattern on `center_did`/`issued_by`, `created_at: str = Field(default_factory=now_rfc3339)`, `sig`/`signer_did` optional).
- [ ] **Step 4:** run → PASS (4 tests). Run the FULL existing model suite `python3 -m pytest tests/test_directory.py -q` → PASS (no regression on ConfigBlob).
- [ ] **Step 5: commit** `feat(annuaire): GRANT_ISSUE/GRANT_REVOKE ops + Grant model + ConfigBlob.layer`.

---

### Task 2: grants — résolution depuis le journal

**Files:** Create `annuaire/grants.py`; Test `tests/test_grants.py`

**Interfaces:**
- Consumes: the journal as a list of entries `[{op, payload, author, ...}]` (same shape `verbs.py` reads — an entry has `entry["op"]` and `entry["payload"]`). Reuse `annuaire.log.Journal` iteration (see `verbs.py` `_get_member_dids` for how entries are walked).
- Produces: `active_grants(entries) -> dict[(scope,layer)->Grant-dict]` (a `GRANT_ISSUE` not later `GRANT_REVOKE`'d by same `grant_id`); `owner(entries, scope, layer) -> Optional[str]` (center_did or None); `can_push(entries, center_did, scope, layer) -> bool`; `validate_issue(entries, scope, layer) -> Optional[str]` (returns a rejection reason string, or None if OK: rejects `layer=="local"`, `scope in NON_DELEGATABLE`, or `(scope,layer)` already owned).

- [ ] **Step 1: failing test**
```python
# tests/test_grants.py
import sys; from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]; sys.path.insert(0, str(ROOT))
from annuaire import grants
A = "did:plc:" + ("a"*32); B = "did:plc:" + ("b"*32)

def _issue(gid, center, scope, layer):
    return {"op": "grant_issue", "payload": {"grant_id": gid, "center_did": center,
            "capability": "config", "scope": scope, "layer": layer, "issued_by": B}}
def _revoke(gid):
    return {"op": "grant_revoke", "payload": {"grant_id": gid, "issued_by": B}}

def test_active_grant_and_owner():
    e = [_issue("g1", A, "firewall", "baseline")]
    assert grants.owner(e, "firewall", "baseline") == A
    assert grants.can_push(e, A, "firewall", "baseline") is True
    assert grants.can_push(e, A, "firewall", "override") is False

def test_revoke_drops_owner():
    e = [_issue("g1", A, "firewall", "baseline"), _revoke("g1")]
    assert grants.owner(e, "firewall", "baseline") is None
    assert grants.can_push(e, A, "firewall", "baseline") is False

def test_validate_issue_rejects_local_and_secrets_and_dup():
    assert grants.validate_issue([], "firewall", "local") == "layer-local-not-delegatable"
    assert grants.validate_issue([], "auth", "baseline") == "scope-not-delegatable"
    e = [_issue("g1", A, "firewall", "baseline")]
    assert grants.validate_issue(e, "firewall", "baseline") == "already-owned"
    assert grants.validate_issue(e, "firewall", "override") is None

def test_zero_center_autonomous():
    assert grants.owner([], "firewall", "baseline") is None
```
- [ ] **Step 2:** run → FAIL. **Step 3: implement** `grants.py` (SPDX header per `model.py`): walk entries, build `{(scope,layer): grant}` from `GRANT_ISSUE` minus `GRANT_REVOKE` by `grant_id`; `owner`/`can_push` read that; `validate_issue` checks `layer=="local"` → `"layer-local-not-delegatable"`, `scope in NON_DELEGATABLE` → `"scope-not-delegatable"`, existing owner → `"already-owned"`, else None. Import `NON_DELEGATABLE` from `model`. **Step 4:** run → PASS (4 tests). **Step 5: commit** `feat(annuaire): grants resolution (owner/can_push/validate_issue, non-delegatable)`.

---

### Task 3: config_compose — deep-merge par calque (pur)

**Files:** Create `annuaire/config_compose.py`; Test `tests/test_config_compose.py`

**Interfaces:**
- Produces: `deep_merge(base: dict, over: dict) -> dict` (tables recursively merged, scalars/lists replaced by `over`); `compose(ordered_texts: list[str]) -> str` — parse each TOML text, deep-merge in order (index 0 lowest precedence), re-serialize to TOML. Uses `tomllib` (read) + `tomli_w` (write).

- [ ] **Step 1: failing test**
```python
# tests/test_config_compose.py
import sys; from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]; sys.path.insert(0, str(ROOT))
from annuaire.config_compose import deep_merge, compose
import tomllib

def test_deep_merge_tables_recursive_scalars_replaced():
    base = {"net": {"a": 1, "b": 2}, "x": 1, "lst": [1, 2]}
    over = {"net": {"b": 9, "c": 3}, "x": 5, "lst": [7]}
    assert deep_merge(base, over) == {"net": {"a": 1, "b": 9, "c": 3}, "x": 5, "lst": [7]}

def test_compose_precedence_local_top():
    baseline = 'x = 1\n[net]\na = 1\nb = 1\n'
    override = '[net]\nb = 2\n'
    local    = 'x = 9\n'
    out = tomllib.loads(compose([baseline, override, local]))
    assert out["x"] == 9              # local wins
    assert out["net"]["a"] == 1       # baseline survives
    assert out["net"]["b"] == 2       # override wins over baseline

def test_compose_empty_layers():
    assert compose([]).strip() == ""
```
- [ ] **Step 2:** run → FAIL. **Step 3: implement** — `deep_merge` recursive (both dict → recurse, else `over` wins); `compose` folds `tomllib.loads` over the list with `deep_merge`, then `tomli_w.dumps`. Empty list → `""`. Skip empty/blank texts. SPDX header. **Step 4:** run → PASS (3 tests). **Step 5: commit** `feat(annuaire): config_compose deep-merge (baseline<override<local)`.

---

### Task 4: config_apply — apply_composed (compose puis 4R)

**Files:** Modify `annuaire/config_apply.py`; Test `tests/test_apply_composed.py`

**Interfaces:**
- Consumes: `config_compose.compose` (Task 3); the existing 4R primitives in this file (`_blake2b_hex`, the shadow/rollback/`os.replace` block inside `apply_blob`).
- Produces: `apply_composed(scope: str, ordered_layer_texts: list[str], target_dir: str) -> dict` — `compose` the texts → composed TOML; write to `<target_dir>/<scope>.toml` via the SAME 4R (shadow → validate parse → atomic swap → rollback kept). Returns `{status: applied|skip|reject, scope, reason?}`. `skip` when the composed hash equals the current active file's hash (idempotent, avoids mesh_sync loops). Never raises.

- [ ] **Step 1: failing test**
```python
# tests/test_apply_composed.py
import sys, tomllib; from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]; sys.path.insert(0, str(ROOT))
from annuaire.config_apply import apply_composed

def test_apply_composed_writes_merged(tmp_path):
    r = apply_composed("firewall", ['x = 1\n[net]\nb = 1\n', '[net]\nb = 2\n', 'x = 9\n'], str(tmp_path))
    assert r["status"] == "applied"
    doc = tomllib.loads((tmp_path/"firewall.toml").read_text())
    assert doc["x"] == 9 and doc["net"]["b"] == 2

def test_apply_composed_idempotent_skip(tmp_path):
    layers = ['x = 1\n']
    assert apply_composed("s", layers, str(tmp_path))["status"] == "applied"
    assert apply_composed("s", layers, str(tmp_path))["status"] == "skip"

def test_apply_composed_bad_toml_keeps_lastgood(tmp_path):
    apply_composed("s", ['good = 1\n'], str(tmp_path))
    before = (tmp_path/"s.toml").read_text()
    r = apply_composed("s", ['this is = = not toml\n'], str(tmp_path))
    assert r["status"] == "reject"
    assert (tmp_path/"s.toml").read_text() == before   # last-good untouched
```
- [ ] **Step 2:** run → FAIL. **Step 3: implement** `apply_composed`: `text = compose(ordered_layer_texts)`; if the parse of `text` raises → `reject:unparseable-toml` (compose parses on the way in — guard by re-parsing the composed output); compute `_blake2b_hex(text)`; if `<scope>.toml` exists and its hash == composed hash → `skip`; else shadow-write + rollback-copy + `os.replace`. (Mirror the 4R block already in `apply_blob`.) **Step 4:** run → PASS (3 tests) + non-regression `python3 -m pytest tests/ -q` on the package. **Step 5: commit** `feat(annuaire): apply_composed (layer compose + 4R, idempotent skip)`.

---

### Task 5: verbs — grant_issue / grant_revoke (signés)

**Files:** Modify `annuaire/verbs.py`; Test `tests/test_grant_verbs.py`

**Interfaces:**
- Consumes: `annuaire.crypto.sign` + `canonical_bytes`; `grants.validate_issue` (Task 2); the `Journal` append pattern used by existing verbs (`invite`, `propose` — see how they build a signed entry and append).
- Produces: `grant_issue(journal, box_priv: bytes, box_did: str, center_did: str, scope: str, layer: str, capability: str = "config") -> dict` (validates via `validate_issue` against the journal; raises `ValueError(reason)` on rejection; else builds a `Grant`, signs `canonical_bytes`, appends a `GRANT_ISSUE` entry, returns the grant dict); `grant_revoke(journal, box_priv, box_did, grant_id) -> dict` (appends signed `GRANT_REVOKE`).

- [ ] **Step 1: failing test** — build a `Journal` (see `tests/conftest.py` for the fixture), a box keypair (`crypto.generate_keypair`); assert `grant_issue` appends a `GRANT_ISSUE` and `grants.owner` then sees it; `grant_issue` on `auth` raises `ValueError("scope-not-delegatable")`; on `local` layer raises; a second issue on the same `(scope,layer)` raises `already-owned`; `grant_revoke` appends and `owner` becomes None; the appended entry's `sig` verifies with `crypto.verify`.
- [ ] **Step 2:** run → FAIL. **Step 3: implement** following the exact append+sign idiom of `invite()`/`propose()` in `verbs.py` (read them first). **Step 4:** run → PASS + `python3 -m pytest tests/test_verbs.py -q` non-regression. **Step 5: commit** `feat(annuaire): grant_issue/grant_revoke signed verbs (validate + append)`.

---

### Task 6: push routing — vérifier signature centre + grant → apply / propose

**Files:** Create `annuaire/config_router.py`; Test `tests/test_config_router.py`

**Interfaces:**
- Consumes: `grants.can_push` (Task 2), `crypto.verify`, `apply_composed` (Task 4), the journal.
- Produces: `route_config(entries, target_dir, self_did, local_dir) -> dict` — for each scope that has ≥1 active grant OR a local layer: gather the ordered layer texts (baseline/override from the newest verified `CONFIG_PUBLISH` of a *granted* center for that `(scope,layer)`; local from `<local_dir>/<scope>.toml` if present), then `apply_composed`. A `CONFIG_PUBLISH` whose publisher lacks the grant for its `(scope,layer)`, or whose sig fails, is **dropped into a proposals list** (returned), never applied. Returns `{"applied": [...], "proposals": [...]}`.

- [ ] **Step 1: failing test** — journal with `GRANT_ISSUE(A, firewall, baseline)` + a signed `CONFIG_PUBLISH{A, firewall, baseline, payload.text}` → `route_config` applies it (composed), and `firewall.toml` written. An **ungranted** `CONFIG_PUBLISH{B, firewall, override}` → appears in `proposals`, not applied. A local `<local_dir>/firewall.toml` overrides. (Use inline payload `{"text": "..."}` + correct `content_hash` via `config_apply._blake2b_hex`.)
- [ ] **Step 2:** run → FAIL. **Step 3: implement** `config_router.py`. **Step 4:** run → PASS. **Step 5: commit** `feat(annuaire): config_router (verify sig+grant → apply, else proposals)`.

---

### Task 7: sbx-centersctl — CLI de gestion

**Files:** Create `sbin/sbx-centersctl`; Test `tests/test_centersctl.py`

**Interfaces:**
- Produces: `sbx-centersctl grant <center_did> <scope> <layer>` / `revoke <grant_id>` / `list` / `route` (runs `route_config` → applies) — thin CLI over the verbs + router, operating on the box journal + box key. Env-overridable paths for tests (`ANNUAIRE_JOURNAL`, `ANNUAIRE_KEY`, `CONFIG_TARGET_DIR`, `CONFIG_LOCAL_DIR`, `DRYRUN`). `grant`/`revoke` reject with rc≠0 on a `validate_issue` failure (JSON error to stderr). Every mutation is a signed journal append (audit).

- [ ] **Step 1: failing test** (pytest calling the CLI via subprocess with a temp journal+key): `grant A firewall baseline` → rc0, `list` shows it; `grant A auth baseline` → rc≠0 `scope-not-delegatable`; `revoke <gid>` → rc0, `list` no longer shows it.
- [ ] **Step 2-4:** implement (python3 CLI is simplest given the verbs are python — `#!/usr/bin/env python3`, `sys.path.insert(0, "/usr/lib/secubox/annuaire")`), tests PASS. **Step 5: commit** `feat(annuaire): sbx-centersctl (grant/revoke/list/route, signed audit)`.

---

### Task 8: API — endpoints /centers (délégation ctl)

**Files:** Modify `api/main.py`; Test `tests/test_centers_api.py`

**Interfaces:**
- Produces: `GET /centers` (enrolled centers + capabilities from the journal), `GET /centers/ownership` (matrix scope×layer→owner via `grants.active_grants`), `POST /centers/grant {center_did,scope,layer}` (delegates `sbx-centersctl grant`), `POST /centers/revoke {grant_id}`, `GET /centers/proposals` + `POST /centers/proposal/accept {...}` (via router/ctl), `GET /centers/effective/{scope}` (composed vs local diff). All writes delegate to `sbx-centersctl` (no in-process root). JWT-gated.

- [ ] **Step 1-5:** TDD with TestClient, monkeypatch the ctl call (mirror `secubox-proxypac` API `_ctl` pattern); assert grant delegates to `sbx-centersctl grant`; ownership matrix reflects the journal; non-delegatable scope → 400. Commit `feat(annuaire): API /centers (ownership + grant/revoke + proposals, ctl delegation)`.

---

### Task 9: Panel /centers + menu.d

**Files:** Create `www/centers/index.html`, `menu.d/570-centers.json`; Test `tests/test_centers_panel.py`

**Interfaces:** consumes the Task 8 API.

- [ ] **Step 1: failing test** — panel has sidebar (`class="sidebar"` + `/shared/sidebar.js`), `sbx_token`, calls `/api/v1/annuaire/centers/ownership` (adapt prefix to the annuaire mount), an ownership **matrix** table, grant/revoke controls, proposals section, effective-diff; **event delegation only** (guard: no `on\w+="..."` handler containing a variable — whitelist static handlers, strip comments — reuse the hardened guard from `secubox-toolbox/tests/test_rlevel_panel.py`); `menu.d` JSON valid (`path=="/centers/"`).
- [ ] **Step 2-5:** implement (hybrid-dark, model on `secubox-proxypac/www/proxypac/index.html`), tests PASS. Commit `feat(annuaire): panneau /centers (matrice propriété + diff + délégation événements)`.

---

### Task 10: Packaging + build

**Files:** Modify `debian/{rules,control,changelog}`; maybe `debian/secubox-annuaire.sudoers` (only if the annuaire daemon can't run the ctl directly).

- [ ] **Step 1:** `debian/rules` installs `sbin/sbx-centersctl` (0755), `www/centers/`, `menu.d/570-centers.json`; `config_compose.py`/`grants.py`/`config_router.py` ship with the module (under `usr/lib/secubox/annuaire/annuaire/`). Verify the annuaire daemon user can write the journal + `<target_dir>` + run the ctl (no shared-parent chown; sudoers only if needed, scoped like `secubox-proxypac`).
- [ ] **Step 2:** changelog bump; Depends sane (`tomli-w` if not already present). `#DEBHELPER#` seul sur sa ligne.
- [ ] **Step 3:** build `.deb`; `dpkg-deb -c` shows the new files; `bash -n`/`python3 -m py_compile` the ctl. Full package suite `python3 -m pytest tests/ -q` PASS. **Step 4: commit** `build(annuaire): package centres/grants (ctl, panel, compose/grants/router) + changelog`.

---

## Recette de vérification manuelle (board)

```bash
# 1. Grant baseline à un centre-peer, pousser une config, vérifier compose+apply.
sbx-centersctl grant did:plc:<A> firewall baseline
# (le centre A publie un CONFIG_PUBLISH{firewall,baseline} via l'annuaire)
sbx-centersctl route   # applique → /etc/secubox/firewall.toml = baseline(A) ⊕ local
# 2. Ajouter un override local (calque local) → vérifier qu'il gagne.
# 3. Revoke → recompose sans baseline. Vérifier l'audit dans le journal.
# 4. Panneau /centers : matrice, diff effectif, propositions d'un centre non-accordé.
# 5. Souveraineté : un GRANT_ISSUE sur 'auth' ou layer 'local' est rejeté.
```

## Hors périmètre
Sous-projets 2 (assistance, `capability="assist"`) et 3 (métriques meshed, `capability="metrics"`) — specs/plans séparés réutilisant le socle. Superposition >3 calques, quorum multi-centres, mode flotte autoritaire.
