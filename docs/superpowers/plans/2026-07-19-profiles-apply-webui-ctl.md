# Profils — API/panel apply+rollback (webui→ctl) — Plan d'implémentation

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Expose `apply`/`rollback` in the profiles API + panel via the webui→ctl pattern: the panel (unprivileged `secubox`) delegates to root `secubox-profilectl` over a scoped exact-command sudoers grant. Operator picks a profile, previews the plan, confirms, applies; can rollback.

**Architecture:** Add `--json` to the CLI apply/rollback; three new async web routes (`active`/`apply`/`rollback`) that run the root CLI via `asyncio.to_thread(sudo …)`; set `NoNewPrivileges=false` on the service (so sudo works) + ship the sudoers; a panel "Bascule" section.

**Tech Stack:** Python 3.11 stdlib + FastAPI, existing `secubox-profiles` modules, vanilla JS panel.

## Global Constraints

- Package `packages/secubox-profiles`. SPDX 4-line header on new `.py`; SPDX on the sudoers. Copyright `Gérald Kerma <devel@cybermind.fr>`.
- **The web routes NEVER actuate in-process.** They only `sudo -n /usr/sbin/secubox-profilectl <verb> --yes --json` (root does the privileged work + audits). Sudo command is FIXED (no variable args) so the sudoers stays exact-command (no wildcard). `--only` stays CLI-only.
- Blocking subprocess runs via `asyncio.to_thread` (the profiles service has its own loop; a multi-minute apply must not freeze status polling).
- Reuse: `_cli._paths`, `_cli._active_profile_name`, `_atomic_write`, `require_jwt`, `load_profile`, existing `/diff` route (the panel's preview).
- CLI apply/rollback exit-code semantics UNCHANGED (0 applied/planned, 1 non-root, 2 else, 3 protected refusal). `--json` only changes output format.
- Commit messages end `Co-Authored-By: Gerald KERMA <devel@cybermind.fr>`, NO Claude reference. Tests per-directory: `.venv/bin/python -m pytest packages/secubox-profiles/tests -q`.

---

### Task 1: CLI `--json` on `apply`/`rollback`

**Files:**
- Modify: `packages/secubox-profiles/api/cli.py`
- Test: `packages/secubox-profiles/tests/test_cli.py`

**Interfaces:**
- Produces: `secubox-profilectl apply --yes --json` / `rollback --yes --json` emit a JSON report `{"status","changed","failed","rolled_back","target"?}` on stdout; exit codes unchanged.

- [ ] **Step 1: Write the failing test** — add to `test_cli.py`:

```python
def test_apply_json_emits_report(tmp_path, monkeypatch, capsys):
    import json as _json
    import api.cli as cli
    import api.apply as ap
    from api.apply import ApplyReport
    monkeypatch.setattr(cli, "_running_as_root", lambda: True)
    root = tmp_path / "etc"
    (root / "modules.d").mkdir(parents=True)
    (root / "profiles").mkdir(parents=True)
    (root / "modules.d" / "x.toml").write_text(
        'id="x"\ncategory="infra"\nruntime="native"\nexposure="lan"\n'
        'units=["x.service"]\nprotected=false\n')
    from api.observe import Actual
    monkeypatch.setattr(cli, "_observe_all",
                        lambda mans, routes: {"x": Actual(enabled=True, active=True)})
    monkeypatch.setattr(ap, "apply_plan",
                        lambda *a, **k: ApplyReport(status="applied", changed=["x"]))
    rc = cli.main(["--root", str(root), "apply", "--yes", "--json"])
    out = _json.loads(capsys.readouterr().out)
    assert rc == 0
    assert out["status"] == "applied" and out["changed"] == ["x"]
```

- [ ] **Step 2: Run — must fail** (`--json` prints text, `json.loads` errors or missing keys).

Run: `.venv/bin/python -m pytest packages/secubox-profiles/tests/test_cli.py::test_apply_json_emits_report -q`

- [ ] **Step 3: Implement.** In `cli.py`, add `--json` to the `apply` and `rollback` subparsers (next to `--yes`). In `_cmd_apply`, after computing `report`, replace the final text print with a format branch:

```python
    if args.json:
        import json as _json
        print(_json.dumps({"status": report.status, "changed": report.changed,
                           "failed": report.failed, "rolled_back": report.rolled_back}))
    else:
        print(f"apply: {report.status} — changed={report.changed} "
              f"failed={report.failed} rolled_back={report.rolled_back}")
    return 0 if report.status == "applied" else 2
```

Note: dry-run (no `--yes`) with `--json` should still print the plan payload — emit
`{"status":"planned","changed":[c.id for c in plan]}` in the dry-run branch when `args.json`,
else the existing text. In `_cmd_rollback`, add the same `--json` branch with the report +
`"target": args.target`.

- [ ] **Step 4: Run — must pass.**

- [ ] **Step 5: Commit.**

```bash
git add packages/secubox-profiles/api/cli.py packages/secubox-profiles/tests/test_cli.py
git commit -m "feat(profiles): --json output for apply/rollback (panel consumes it)

Co-Authored-By: Gerald KERMA <devel@cybermind.fr>"
```

---

### Task 2: Web routes — active / apply / rollback (webui→ctl)

**Files:**
- Modify: `packages/secubox-profiles/api/web.py`
- Test: `packages/secubox-profiles/tests/test_web.py` (extend; if absent, create with the app fixture pattern already used)

**Interfaces:**
- Produces: `POST /api/v1/profiles/active {name}`, `POST /api/v1/profiles/apply`, `POST /api/v1/profiles/rollback`.

- [ ] **Step 1: Write failing tests.** Add to `test_web.py` (use the existing test client + `require_jwt` override the file already sets up; if new, mirror the pattern in web.py's tests). Inject the subprocess via a module-level indirection so no real sudo runs:

```python
def test_set_active_unknown_profile_404(client, tmp_root):
    r = client.post("/api/v1/profiles/active", json={"name": "nope"})
    assert r.status_code == 404


def test_set_active_writes_file(client, tmp_root):
    (tmp_root / "profiles" / "lite.toml").write_text('name="lite"\non=["core"]\n')
    r = client.post("/api/v1/profiles/active", json={"name": "lite"})
    assert r.status_code == 200 and r.json()["active"] == "lite"
    assert (tmp_root / "profiles" / "active").read_text().strip() == "lite"


def test_apply_route_delegates_to_ctl_and_returns_report(client, monkeypatch):
    import api.web as web
    def fake_run(argv, **kw):
        assert argv[:3] == ["sudo", "-n", "/usr/sbin/secubox-profilectl"]
        assert argv[3:] == ["apply", "--yes", "--json"]
        class P: returncode = 0; stdout = '{"status":"applied","changed":["x"],"failed":[],"rolled_back":[]}'; stderr = ""
        return P()
    monkeypatch.setattr(web, "_ctl_run", fake_run)
    r = client.post("/api/v1/profiles/apply", json={})
    assert r.status_code == 200 and r.json()["status"] == "applied"


def test_apply_route_protected_refusal_409(client, monkeypatch):
    import api.web as web
    def fake_run(argv, **kw):
        class P: returncode = 3; stdout = ""; stderr = "refusé: protégé"
        return P()
    monkeypatch.setattr(web, "_ctl_run", fake_run)
    r = client.post("/api/v1/profiles/apply", json={})
    assert r.status_code == 409
```

Note: if `test_web.py` has no `client`/`tmp_root` fixtures, add them (a `TestClient(create_app())` with `SECUBOX_ROOT`/`_root()` pointed at a tmp dir + the module dir; follow how web.py resolves `_root()`). The reviewer accepts an equivalent fixture that reaches the routes.

- [ ] **Step 2: Run — must fail.**

- [ ] **Step 3: Implement in `web.py`.** Add a module-level helper (indirection so tests monkeypatch it):

```python
def _ctl_run(argv, **kw):
    import subprocess
    return subprocess.run(argv, capture_output=True, text=True, timeout=1800, **kw)


async def _run_ctl_json(verb: str):
    """Délègue au helper root via sudo (webui→ctl). Fixe, exact-command
    (voir /etc/sudoers.d/secubox-profiles). Bloquant → to_thread pour ne pas
    figer la boucle du service pendant un apply long."""
    import asyncio as _a
    import json as _json
    argv = ["sudo", "-n", "/usr/sbin/secubox-profilectl", verb, "--yes", "--json"]
    proc = await _a.to_thread(_ctl_run, argv)
    if proc.returncode == 3:
        raise HTTPException(status_code=409, detail=(proc.stderr or proc.stdout).strip()[:300])
    if proc.returncode != 0:
        raise HTTPException(status_code=500,
                            detail=f"{verb} échoué: {(proc.stderr or proc.stdout).strip()[:300]}")
    try:
        return _json.loads(proc.stdout)
    except ValueError:
        raise HTTPException(status_code=500, detail=f"{verb}: sortie CLI malformée")
```

Add the routes inside `create_app()` (beside the existing ones):

```python
    @app.post("/api/v1/profiles/active")
    async def set_active(body: ActiveUpdate, _claims=Depends(require_jwt)):
        root = _root()
        _mod, prof_dir, _pins, active_file = _cli._paths(root)
        if not (Path(prof_dir) / f"{body.name}.toml").exists():
            raise HTTPException(status_code=404, detail=f"profil inconnu: {body.name}")
        _atomic_write(Path(active_file), body.name + "\n")
        return {"active": body.name}

    @app.post("/api/v1/profiles/apply")
    async def apply_active(_claims=Depends(require_jwt)):
        return await _run_ctl_json("apply")

    @app.post("/api/v1/profiles/rollback")
    async def rollback_active(_claims=Depends(require_jwt)):
        return await _run_ctl_json("rollback")
```

Define the `ActiveUpdate` pydantic model near the other body models: `class ActiveUpdate(BaseModel): name: str`.

- [ ] **Step 4: Run — must pass** (`.venv/bin/python -m pytest packages/secubox-profiles/tests/test_web.py -q`).

- [ ] **Step 5: Commit.**

```bash
git add packages/secubox-profiles/api/web.py packages/secubox-profiles/tests/test_web.py
git commit -m "feat(profiles): API active/apply/rollback — delegate to root profilectl via sudo

Co-Authored-By: Gerald KERMA <devel@cybermind.fr>"
```

---

### Task 3: Service `NoNewPrivileges=false` + sudoers + packaging

**Files:**
- Modify: `packages/secubox-profiles/debian/secubox-profiles.service`
- Create: `packages/secubox-profiles/sudoers.d/secubox-profiles`
- Modify: `packages/secubox-profiles/debian/rules` (install sudoers)
- Modify: `packages/secubox-profiles/debian/postinst` (NNP change takes effect on daemon-reload+restart, already done by postinst)

**Interfaces:** none (packaging).

- [ ] **Step 1: Set `NoNewPrivileges=false`** in `debian/secubox-profiles.service` (replace `NoNewPrivileges=true`). Add a comment: `# false (not true): the apply/rollback routes must sudo → secubox-profilectl (webui→ctl); NNP=true would neutralize sudo. The rest of the hardening (User=secubox, restricted ReadWritePaths) stays.`

- [ ] **Step 2: Create `packages/secubox-profiles/sudoers.d/secubox-profiles`:**

```
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# SecuBox Profiles — the /profiles/ panel (User=secubox) delegates apply/rollback
# to the root helper secubox-profilectl (webui→ctl pattern, see
# .claude/MODULE-COMPLIANCE.md → Privileged Operations). Exact-command grants
# (no wildcards): the panel always calls the FIXED `apply --yes --json` /
# `rollback --yes --json` (--only stays a root-CLI-only affordance).
secubox ALL=(root) NOPASSWD: /usr/sbin/secubox-profilectl apply --yes --json
secubox ALL=(root) NOPASSWD: /usr/sbin/secubox-profilectl rollback --yes --json
```

- [ ] **Step 3: Install the sudoers** in `debian/rules` (add to the install section, `0440`):

```
	install -d debian/secubox-profiles/etc/sudoers.d
	install -m 0440 sudoers.d/secubox-profiles debian/secubox-profiles/etc/sudoers.d/secubox-profiles
```

- [ ] **Step 4: Validate** `visudo -c -f sudoers.d/secubox-profiles` (must parse). Bump `debian/changelog` to the next minor (the current version after Phase 2 bump).

- [ ] **Step 5: Commit.**

```bash
git add packages/secubox-profiles/debian/secubox-profiles.service packages/secubox-profiles/sudoers.d/secubox-profiles packages/secubox-profiles/debian/rules packages/secubox-profiles/debian/changelog
git commit -m "feat(profiles): NNP=false + scoped sudoers so the panel can sudo→profilectl

Co-Authored-By: Gerald KERMA <devel@cybermind.fr>"
```

---

### Task 4: Panel "Bascule" section

**Files:**
- Modify: `packages/secubox-profiles/www/profiles/index.html`

**Interfaces:** consumes `GET /profiles/profiles`, `POST /profiles/active`, `GET /profiles/diff`, `POST /profiles/apply`, `POST /profiles/rollback`.

- [ ] **Step 1: Add the section.** In `www/profiles/index.html`, add a "Bascule" card: a `<select id="profileSelect">` populated from `GET /api/v1/profiles/profiles`; a "Prévisualiser" button that `POST`s `/active {name}` then renders `GET /diff` into the existing diff-list; an "Apply" button (hidden until a preview is shown) that `confirm()`s ("Ceci va démarrer/arrêter N modules sur la box. Continuer ?", N from the diff count) then `POST /apply`, showing the report; a "Rollback" button that `confirm()`s then `POST /rollback`. Reuse the file's existing helpers (`esc()`, token from `localStorage.getItem('sbx_token')`, the diff-row rendering, a persistent error toast on failure). A long apply shows a persistent progress indicator that resolves to a transient success or a persistent error.

- [ ] **Step 2: `node --check`** the extracted `<script>` (must parse).

- [ ] **Step 3: Confirm the module still loads** (`python3 -c "import ast; ast.parse(open('packages/secubox-profiles/api/web.py').read())"`) and the full suite is green: `.venv/bin/python -m pytest packages/secubox-profiles/tests -q`.

- [ ] **Step 4: Commit.**

```bash
git add packages/secubox-profiles/www/profiles/index.html
git commit -m "feat(profiles): panel Bascule — select/preview/apply/rollback (webui→ctl)

Co-Authored-By: Gerald KERMA <devel@cybermind.fr>"
```

---

## Auto-revue du plan

- **Couverture** : CLI --json (T1) ; routes active/apply/rollback via sudo (T2) ; NNP=false + sudoers + packaging (T3) ; panel (T4). ✓
- **webui→ctl** : les routes ne font QUE `sudo -n profilectl <verb> --yes --json` (fixe, exact-command) ; jamais d'actionnement in-process ; blocage en to_thread.
- **Sûreté** : sudoers exact-command (pas de wildcard) ; `--only` reste CLI ; rc 3→409, !=0→500 ; panel dry-run+confirm avant apply.
- **NNP=false** : assouplissement ciblé documenté, précédent wireguard/wgctl ; reste du durcissement conservé.
- **Types** : `_run_ctl_json(verb)` consommé par apply/rollback ; `ActiveUpdate{name}` ; `--json` payload cohérent CLI↔route.
- **Placeholders** : le fixture test_web (client/tmp_root) porte une note d'équivalence si absent ; panel décrit précisément (réutilise l'existant).
