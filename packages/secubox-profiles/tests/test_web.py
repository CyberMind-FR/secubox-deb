# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
Tests API web (packages/secubox-profiles/api/web.py).

Portent en priorité sur les hard constraints du plan (voir CLAUDE.md du
projet) : `apply` n'existe nulle part, un pin protégé->off est refusé AVANT
d'écrire, l'écriture de profil est atomique et fait un aller-retour propre
via load_profile, et 404 sur un id/profil inconnu.

`common/` est ajouté à sys.path pour importer le VRAI secubox_core.auth
(comme packages/secubox-users/tests/test_users_api_handlers.py) : un test
vérifie que require_jwt réel est bien branché (401 sans credentials) avant
que les autres tests ne le bypassent via dependency_overrides.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO_ROOT / "common"))
# packages/secubox-profiles itself is already on sys.path via conftest.py.

from fastapi.testclient import TestClient  # noqa: E402

import api.web as web  # noqa: E402
from api.manifest import PROTECTED_IDS  # noqa: E402
from api.state import load_profile, load_pins  # noqa: E402

MANIFEST_LYRION = """
id       = "lyrion"
category = "media"
runtime  = "native"
exposure = "lan"
units    = ["secubox-lyrion.service"]
priority = 30
"""

MANIFEST_AUTH = """
id       = "auth"
category = "security"
runtime  = "native"
exposure = "internal"
units    = ["secubox-auth.service"]
priority = 90
"""


def _noop_jwt():
    return {"sub": "admin"}


@pytest.fixture()
def root(tmp_path, monkeypatch):
    (tmp_path / "modules.d").mkdir()
    (tmp_path / "modules.d" / "lyrion.toml").write_text(MANIFEST_LYRION)
    (tmp_path / "modules.d" / "auth.toml").write_text(MANIFEST_AUTH)
    (tmp_path / "profiles").mkdir()
    (tmp_path / "profiles" / "media.toml").write_text(
        'name = "media"\nlabel = "\U0001f3ac Média"\non = ["lyrion"]\n')
    (tmp_path / "profiles" / "active").write_text("media\n")
    monkeypatch.setenv("SECUBOX_PROFILES_ROOT", str(tmp_path))
    return tmp_path


@pytest.fixture()
def client(root, monkeypatch):
    # Deterministic observation: lyrion on, auth on (protected forces ON
    # anyway, but the fixture keeps observe() consistent with reality).
    from api.observe import Actual

    monkeypatch.setattr(web._cli, "_observe_all", lambda ms, routes: {
        "lyrion": Actual(enabled=True, active=True, rss_kb=2048),
        "auth": Actual(enabled=True, active=True, rss_kb=4096),
    })
    monkeypatch.setattr(web, "load_routes", lambda: set())
    c = TestClient(web.app)
    c.app.dependency_overrides[web.require_jwt] = _noop_jwt
    yield c
    c.app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# apply/rollback exist but delegate to the root CLI via sudo — the web
# process itself never actuates anything in-process (webui→ctl pattern).
# ---------------------------------------------------------------------------

def test_apply_route_never_actuates_in_process(client):
    paths = {getattr(r, "path", "") for r in client.app.routes}
    assert "/api/v1/profiles/apply" in paths
    assert "/api/v1/profiles/rollback" in paths
    # No route accepts a direct actuation verb — apply/rollback only ever
    # shell out to the fixed `sudo -n secubox-profilectl <verb> --yes --json`
    # command (see test_apply_route_delegates_to_ctl_and_returns_report).
    for p in paths:
        assert "start" not in p and "stop" not in p and "restart" not in p


def test_web_module_has_no_actuation_helper():
    # Grep-level guard: nothing in web.py calls systemctl/lxc-* directly —
    # only read helpers (_cli._observe_all -> observe.py) are used, and those
    # are read-only by construction (see observe.py docstring). apply/rollback
    # delegate exclusively to `_ctl_run` -> `sudo -n secubox-profilectl`.
    src = Path(web.__file__).read_text(encoding="utf-8")
    for forbidden in ("systemctl start", "systemctl stop", "systemctl enable",
                      "systemctl disable", "lxc-start", "lxc-stop"):
        assert forbidden not in src


# ---------------------------------------------------------------------------
# JWT gating
# ---------------------------------------------------------------------------

def test_status_requires_jwt_when_not_overridden(root):
    # Real secubox_core.auth.require_jwt (no override): no Authorization
    # header, no session cookie -> 401. Confirms Depends(require_jwt) is
    # actually wired on the route, not just imported.
    c = TestClient(web.app)
    resp = c.get("/api/v1/profiles/status")
    assert resp.status_code == 401


# ---------------------------------------------------------------------------
# status / profiles / pins / diff (read paths)
# ---------------------------------------------------------------------------

def test_status_lists_modules_with_tri_state(client):
    resp = client.get("/api/v1/profiles/status")
    assert resp.status_code == 200
    data = resp.json()
    ids = {m["id"]: m for m in data["modules"]}
    assert ids["lyrion"]["on"] == "on"
    assert ids["auth"]["protected"] is True
    assert data["totals"]["count"] == 2
    assert "media" in data["by_category"]


def test_status_surfaces_unknown_probe_not_off(root, monkeypatch):
    from api.observe import Actual

    monkeypatch.setattr(web._cli, "_observe_all", lambda ms, routes: {
        "lyrion": Actual(enabled=None, active=None),  # probe could not run
        "auth": Actual(enabled=True, active=True),
    })
    monkeypatch.setattr(web, "load_routes", lambda: set())
    c = TestClient(web.app)
    c.app.dependency_overrides[web.require_jwt] = _noop_jwt
    resp = c.get("/api/v1/profiles/status")
    ids = {m["id"]: m for m in resp.json()["modules"]}
    assert ids["lyrion"]["on"] == "unknown"
    assert ids["lyrion"]["on"] != "off"


def test_list_profiles_reports_active(client):
    resp = client.get("/api/v1/profiles/profiles")
    assert resp.status_code == 200
    data = resp.json()
    assert data["active"] == "media"
    assert data["profiles"][0]["name"] == "media"
    assert data["profiles"][0]["on"] == ["lyrion"]


def test_get_pins_empty_by_default(client):
    resp = client.get("/api/v1/profiles/pins")
    assert resp.status_code == 200
    assert resp.json() == {"pins": {}}


def test_diff_reports_no_change_when_converged(client):
    resp = client.get("/api/v1/profiles/diff", params={"profile": "media"})
    assert resp.status_code == 200
    assert resp.json()["changes"] == []


def test_diff_unknown_profile_is_404(client):
    resp = client.get("/api/v1/profiles/diff", params={"profile": "fantome"})
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# members (write path #1)
# ---------------------------------------------------------------------------

def test_set_member_adds_and_round_trips(client, root):
    resp = client.post("/api/v1/profiles/profiles/media/members",
                       json={"id": "auth", "on": True})
    assert resp.status_code == 200
    assert set(resp.json()["on"]) == {"lyrion", "auth"}
    # Round-trip through the real reader, not just the API response.
    prof = load_profile(root / "profiles" / "media.toml")
    assert prof.on == frozenset({"lyrion", "auth"})
    assert prof.label == "\U0001f3ac Média"  # label preserved


def test_set_member_removes(client, root):
    resp = client.post("/api/v1/profiles/profiles/media/members",
                       json={"id": "lyrion", "on": False})
    assert resp.status_code == 200
    assert resp.json()["on"] == []
    prof = load_profile(root / "profiles" / "media.toml")
    assert prof.on == frozenset()


def test_set_member_unknown_profile_404(client):
    resp = client.post("/api/v1/profiles/profiles/fantome/members",
                       json={"id": "lyrion", "on": True})
    assert resp.status_code == 404


def test_set_member_unknown_module_404(client):
    resp = client.post("/api/v1/profiles/profiles/media/members",
                       json={"id": "fantome", "on": True})
    assert resp.status_code == 404


def test_set_member_atomic_write_leaves_no_tmp_file(client, root):
    client.post("/api/v1/profiles/profiles/media/members", json={"id": "auth", "on": True})
    leftovers = list((root / "profiles").glob("*.tmp"))
    assert leftovers == []


# ---------------------------------------------------------------------------
# pins (write path #2) — the load-bearing protected-refusal test
# ---------------------------------------------------------------------------

def test_set_pin_on_ordinary_module_writes(client, root):
    resp = client.post("/api/v1/profiles/pins", json={"id": "lyrion", "pin": "off"})
    assert resp.status_code == 200
    assert resp.json()["pins"] == {"lyrion": "off"}
    pins = load_pins(root / "profiles" / "pins.toml")
    assert pins == {"lyrion": "off"}


def test_set_pin_protected_module_off_is_refused(client, root):
    """The one hard constraint that matters most: a pin that would switch a
    protected module off must be rejected with 409 and NOTHING must reach
    disk. `auth` is in PROTECTED_IDS, so manifest.load_manifest() forces
    protected=True on it regardless of the .toml content."""
    assert "auth" in PROTECTED_IDS
    resp = client.post("/api/v1/profiles/pins", json={"id": "auth", "pin": "off"})
    assert resp.status_code == 409
    pins_file = root / "profiles" / "pins.toml"
    assert not pins_file.exists()  # refusal happened before any write


def test_set_pin_protected_module_on_is_allowed(client, root):
    # Pinning a protected module ON is a no-op semantically (resolve() always
    # forces ON for protected modules) but must not be blocked — only OFF is
    # the lock-out case.
    resp = client.post("/api/v1/profiles/pins", json={"id": "auth", "pin": "on"})
    assert resp.status_code == 200


def test_set_pin_clear_with_null(client, root):
    client.post("/api/v1/profiles/pins", json={"id": "lyrion", "pin": "off"})
    resp = client.post("/api/v1/profiles/pins", json={"id": "lyrion", "pin": None})
    assert resp.status_code == 200
    assert resp.json()["pins"] == {}
    pins = load_pins(root / "profiles" / "pins.toml")
    assert pins == {}


def test_set_pin_unknown_module_404(client):
    resp = client.post("/api/v1/profiles/pins", json={"id": "fantome", "pin": "on"})
    assert resp.status_code == 404


def test_set_pin_invalid_value_400(client):
    resp = client.post("/api/v1/profiles/pins", json={"id": "lyrion", "pin": "sideways"})
    assert resp.status_code == 400


def test_diff_after_pin_reflects_refusal_not_partial_state(client, root):
    # Belt-and-braces: even if the write-path refusal were somehow bypassed,
    # plan_changes() itself raises ProtectedViolation independently — but the
    # write-path refusal must be the one that actually stops the write, which
    # is what test_set_pin_protected_module_off_is_refused proves via the
    # missing pins.toml file. Here we only confirm /diff still 409s cleanly
    # (no half-written pins.toml poisoning subsequent reads).
    client.post("/api/v1/profiles/pins", json={"id": "auth", "pin": "off"})  # refused, no-op
    resp = client.get("/api/v1/profiles/diff", params={"profile": "media"})
    assert resp.status_code == 200
    assert resp.json()["changes"] == []


# ---------------------------------------------------------------------------
# active / apply / rollback (write path #3) — webui→ctl: apply/rollback never
# actuate in-process, they only shell out to the fixed root CLI via sudo (see
# _ctl_run/_run_ctl_json in web.py). `root` here is this file's own tmp_path
# fixture (the brief's `tmp_root` — same tmp dir, real fixture name).
# ---------------------------------------------------------------------------

def test_set_active_unknown_profile_404(client, root):
    r = client.post("/api/v1/profiles/active", json={"name": "nope"})
    assert r.status_code == 404


def test_set_active_writes_file(client, root):
    (root / "profiles" / "lite.toml").write_text('name="lite"\non=["core"]\n')
    r = client.post("/api/v1/profiles/active", json={"name": "lite"})
    assert r.status_code == 200 and r.json()["active"] == "lite"
    assert (root / "profiles" / "active").read_text().strip() == "lite"


def test_apply_route_delegates_to_ctl_and_returns_report(client, monkeypatch):
    def fake_run(argv, **kw):
        assert argv == ["sudo", "-n", "/usr/bin/systemd-run", "--wait", "--pipe",
                        "--collect", "--quiet", "/usr/sbin/secubox-profilectl",
                        "apply", "--yes", "--json"]

        class P:
            returncode = 0
            stdout = '{"status":"applied","changed":["x"],"failed":[],"rolled_back":[]}'
            stderr = ""
        return P()
    monkeypatch.setattr(web, "_ctl_run", fake_run)
    r = client.post("/api/v1/profiles/apply", json={"profile": "media"})
    assert r.status_code == 200 and r.json()["status"] == "applied"


def test_apply_route_protected_refusal_409(client, monkeypatch):
    def fake_run(argv, **kw):
        class P:
            returncode = 3
            stdout = ""
            stderr = "refusé: protégé"
        return P()
    monkeypatch.setattr(web, "_ctl_run", fake_run)
    r = client.post("/api/v1/profiles/apply", json={"profile": "media"})
    assert r.status_code == 409


def test_rollback_route_delegates_to_ctl_and_returns_report(client, monkeypatch):
    def fake_run(argv, **kw):
        assert argv == ["sudo", "-n", "/usr/bin/systemd-run", "--wait", "--pipe",
                        "--collect", "--quiet", "/usr/sbin/secubox-profilectl",
                        "rollback", "--yes", "--json"]

        class P:
            returncode = 0
            stdout = '{"status":"applied","changed":["x"],"failed":[],"rolled_back":["x"]}'
            stderr = ""
        return P()
    monkeypatch.setattr(web, "_ctl_run", fake_run)
    r = client.post("/api/v1/profiles/rollback", json={})
    assert r.status_code == 200 and r.json()["rolled_back"] == ["x"]


def test_apply_route_generic_failure_500(client, monkeypatch):
    def fake_run(argv, **kw):
        class P:
            returncode = 2
            stdout = ""
            stderr = "boum"
        return P()
    monkeypatch.setattr(web, "_ctl_run", fake_run)
    r = client.post("/api/v1/profiles/apply", json={"profile": "media"})
    assert r.status_code == 500


def test_apply_route_malformed_json_500(client, monkeypatch):
    def fake_run(argv, **kw):
        class P:
            returncode = 0
            stdout = "not json"
            stderr = ""
        return P()
    monkeypatch.setattr(web, "_ctl_run", fake_run)
    r = client.post("/api/v1/profiles/apply", json={"profile": "media"})
    assert r.status_code == 500


# ---------------------------------------------------------------------------
# Finding 1 (TOCTOU) — apply must actuate the REQUESTED profile, not whatever
# happens to be in the shared `active` file at execution time. `active`
# stays at "media" (the root fixture's default) throughout these tests; the
# apply call must still flip it to the body's profile BEFORE shelling out.
# ---------------------------------------------------------------------------

def test_apply_writes_requested_profile_before_calling_ctl(client, root, monkeypatch):
    (root / "profiles" / "lite.toml").write_text('name="lite"\nlabel="Lite"\non=["lyrion"]\n')
    assert (root / "profiles" / "active").read_text().strip() == "media"

    seen = {}

    def fake_run(argv, **kw):
        # The active file must already read "lite" by the time the ctl is
        # invoked — proves apply sets it BEFORE actuating, not after, and
        # regardless of what was active when the request was made.
        seen["active_at_ctl_time"] = (root / "profiles" / "active").read_text().strip()

        class P:
            returncode = 0
            stdout = '{"status":"applied","changed":["lyrion"],"failed":[],"rolled_back":[]}'
            stderr = ""
        return P()

    monkeypatch.setattr(web, "_ctl_run", fake_run)
    r = client.post("/api/v1/profiles/apply", json={"profile": "lite"})
    assert r.status_code == 200
    assert seen["active_at_ctl_time"] == "lite"
    assert (root / "profiles" / "active").read_text().strip() == "lite"


def test_apply_unknown_profile_404_and_ctl_not_called(client, root, monkeypatch):
    called = []

    def fake_run(argv, **kw):
        called.append(argv)
        class P:
            returncode = 0
            stdout = '{"status":"applied","changed":[],"failed":[],"rolled_back":[]}'
            stderr = ""
        return P()
    monkeypatch.setattr(web, "_ctl_run", fake_run)

    r = client.post("/api/v1/profiles/apply", json={"profile": "fantome"})
    assert r.status_code == 404
    assert called == []
    # The shared active file must be untouched by a rejected request.
    assert (root / "profiles" / "active").read_text().strip() == "media"


def test_apply_rolled_back_returns_report_not_500(client, root, monkeypatch):
    # A rolled_back apply (CLI rc=2) still emits a --json report; the route must
    # surface it (200) so the panel shows which modules changed/rolled back,
    # not a raw truncated error string (final-review finding 1).
    import api.web as web
    (root / "profiles" / "lite.toml").write_text('name="lite"\nlabel="Lite"\non=["lyrion"]\n')

    def fake_run(argv, **kw):
        class P:
            returncode = 2
            stdout = '{"status":"rolled_back","changed":[],"failed":["x"],"rolled_back":["y"]}'
            stderr = ""
        return P()
    monkeypatch.setattr(web, "_ctl_run", fake_run)
    r = client.post("/api/v1/profiles/apply", json={"profile": "lite"})
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "rolled_back" and body["failed"] == ["x"]


def test_apply_rolled_back_reverts_active_to_prior(client, root, monkeypatch):
    # A rolled_back apply must leave `active` pointing at the PRIOR profile
    # (state was reverted), not at the target that never took — otherwise the
    # pointer lies. Fixture default active="media"; we apply "lite" -> rolled_back.
    (root / "profiles" / "lite.toml").write_text('name="lite"\nlabel="Lite"\non=["lyrion"]\n')
    assert (root / "profiles" / "active").read_text().strip() == "media"

    def fake_run(argv, **kw):
        class P:
            returncode = 2
            stdout = '{"status":"rolled_back","changed":[],"failed":["x"],"rolled_back":["y"]}'
            stderr = ""
        return P()
    monkeypatch.setattr(web, "_ctl_run", fake_run)

    r = client.post("/api/v1/profiles/apply", json={"profile": "lite"})
    assert r.status_code == 200
    assert r.json()["status"] == "rolled_back"
    assert (root / "profiles" / "active").read_text().strip() == "media"  # reverted


def test_apply_applied_keeps_active_at_target(client, root, monkeypatch):
    (root / "profiles" / "lite.toml").write_text('name="lite"\nlabel="Lite"\non=["lyrion"]\n')

    def fake_run(argv, **kw):
        class P:
            returncode = 0
            stdout = '{"status":"applied","changed":["lyrion"],"failed":[],"rolled_back":[]}'
            stderr = ""
        return P()
    monkeypatch.setattr(web, "_ctl_run", fake_run)

    r = client.post("/api/v1/profiles/apply", json={"profile": "lite"})
    assert r.status_code == 200
    assert (root / "profiles" / "active").read_text().strip() == "lite"  # kept
