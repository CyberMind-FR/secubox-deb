# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""Cross-engine parity harness — Python side (#662 Phase 3).

Loads the SAME ``parity-fixtures.json`` and ``testdata/config`` snapshot the Go
core uses (``../secubox-toolbox-ng/testdata``), drives the production Python
decision logic — ``ad_ghost._allowed`` + ``_AD_HOST`` + the learned-trackers
check, composed with ``splice.should_splice`` — under the SAME precedence as
Go's ``Policy.Decide``, and asserts the action == the fixture's ``expect``.

Python is the source of truth: if Go and Python ever diverge on a fixture, Go
is fixed to match this. Both test files reading the identical inputs is what
makes the parity meaningful.
"""
from __future__ import annotations

import json
import os

import pytest

from mitmproxy_addons import ad_ghost
from secubox_toolbox import splice

_HERE = os.path.dirname(os.path.abspath(__file__))
# tests/ → packages/secubox-toolbox → packages → packages/secubox-toolbox-ng
_NG_TESTDATA = os.path.normpath(
    os.path.join(_HERE, "..", "..", "secubox-toolbox-ng", "testdata"))
_FIXTURES = os.path.join(_NG_TESTDATA, "parity-fixtures.json")


def _load_fixtures():
    with open(_FIXTURES, encoding="utf-8") as f:
        return json.load(f)


def _cfg_path(rel: str) -> str:
    return os.path.join(_NG_TESTDATA, rel.replace("/", os.sep))


def _decide(host: str, sni: str, *, seed, learned_splice, never,
            self_regs) -> str:
    """Mirror Go's Policy.Decide precedence EXACTLY.

      1. own-infra / allowlist (ad_ghost._allowed) → "allow"
      2. splice never-set check, then seed/learned (splice.should_splice) → "splice"
      3. _AD_HOST match OR registrable/host in learned-trackers → "block"
      4. otherwise → "mitm"
    """
    # 1. allowlist + own-infra ALWAYS win first.
    if ad_ghost._allowed(host):
        return "allow"
    # 2. splice (TLS layer runs first; never-set already excludes trackers).
    if splice.should_splice(sni or host, seed, learned_splice, never):
        return "splice"
    # 3. ad_ghost block decision (request layer).
    blocked = bool(ad_ghost._AD_HOST.search(host))
    if not blocked:
        reg = ad_ghost._registrable(host)
        ls = ad_ghost._learned_set()
        if (reg and reg in ls) or host.lower() in ls:
            blocked = True
    if blocked:
        return "block"
    # 4.
    return "mitm"


@pytest.fixture
def parity_env(monkeypatch):
    """Point the Python addon decision logic at the SAME testdata snapshot the
    Go core loads, and load the splice sets the same way the addon does."""
    data = _load_fixtures()
    cfg = data["config"]

    # ad_ghost: allowlist + learned-trackers paths, self-domains, fresh caches.
    monkeypatch.setattr(ad_ghost, "_ALLOW_PATH", _cfg_path(cfg["ad_allowlist"]))
    monkeypatch.setattr(ad_ghost, "_LEARNED_PATH", _cfg_path(cfg["learned_trackers"]))
    monkeypatch.setattr(ad_ghost, "_SELF_REGS",
                        {d.strip().lower() for d in cfg["self_domains"] if d.strip()})
    # reset module-level caches so the monkeypatched paths are (re)read.
    monkeypatch.setattr(ad_ghost, "_allow", set())
    monkeypatch.setattr(ad_ghost, "_allow_mtime", 0.0)
    monkeypatch.setattr(ad_ghost, "_learned", set())
    monkeypatch.setattr(ad_ghost, "_learned_mtime", 0.0)
    monkeypatch.setattr(ad_ghost, "_learned_check", 0.0)  # bypass the 60s cache

    # splice: load seed/learned the addon way; never = pure-trackers ∪ fortknox.
    seed = splice.load_splice_seed(_cfg_path(cfg["splice_seed"]))
    learned_splice = splice.load_learned_splice(_cfg_path(cfg["splice_learned"]))
    never = splice.load_learned_splice(_cfg_path(cfg["pure_trackers"]))
    for s in cfg.get("fortknox_sites", []) or []:
        never.add(str(s).lower().strip("."))

    return {
        "fixtures": data["fixtures"],
        "seed": seed,
        "learned_splice": learned_splice,
        "never": never,
        "self_regs": ad_ghost._SELF_REGS,
    }


def test_parity_decide(parity_env):
    seed = parity_env["seed"]
    learned_splice = parity_env["learned_splice"]
    never = parity_env["never"]
    self_regs = parity_env["self_regs"]

    failures = []
    for fx in parity_env["fixtures"]:
        host = fx["host"]
        got = _decide(host, host, seed=seed, learned_splice=learned_splice,
                      never=never, self_regs=self_regs)
        if got != fx["expect"]:
            failures.append(
                f"Decide({host!r})={got!r} want {fx['expect']!r}  ({fx.get('why')})")
    assert not failures, "Python↔fixture parity mismatches:\n" + "\n".join(failures)


def test_fixtures_present(parity_env):
    # Guard: the fixture set must cover every action class, else "parity" is
    # vacuously true for a missing branch.
    actions = {fx["expect"] for fx in parity_env["fixtures"]}
    assert actions == {"allow", "block", "splice", "mitm"}, actions
