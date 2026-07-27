# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""
SecuBox-Deb :: secubox-annuaire :: tests/test_fleet_packaging.py
Packaging coverage for fleet metrics (Task 5, feat/fleet-metrics):
the publisher systemd unit/timer, debian/rules install lines, and
debian/postinst (fleet data dir ownership + no shared-parent chown).
"""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


# ── publisher unit / timer ───────────────────────────────────────────────

def test_publisher_unit_non_root_oneshot():
    svc = (ROOT / "systemd" / "secubox-metrics-publish.service").read_text()
    assert "User=secubox" in svc
    assert "sbx-fleetctl publish" in svc
    assert "Type=oneshot" in svc


def test_publisher_timer_schedule():
    tmr = (ROOT / "systemd" / "secubox-metrics-publish.timer").read_text()
    assert "OnUnitActiveSec" in tmr
    assert "OnBootSec=90s" in tmr
    assert "OnUnitActiveSec=60s" in tmr
    assert "WantedBy=timers.target" in tmr


# ── debian/postinst ───────────────────────────────────────────────────────

def test_postinst_no_shared_parent_chown_and_fleetdir():
    p = (ROOT / "debian" / "postinst").read_text()
    for bad in (
        "chown -R secubox /run/secubox",
        "chown -R secubox /etc/secubox",
        "chown -R secubox /var/lib/secubox",
    ):
        assert bad not in p, f"forbidden shared-parent chown found: {bad!r}"
    assert "/var/lib/secubox/annuaire/fleet" in p
    assert "#DEBHELPER#" in p


def test_postinst_enables_metrics_publish_timer():
    p = (ROOT / "debian" / "postinst").read_text()
    assert "secubox-metrics-publish.timer" in p
    assert "daemon-reload" in p


def test_debhelper_token_alone_on_its_line():
    p = (ROOT / "debian" / "postinst").read_text()
    lines = [l.strip() for l in p.splitlines()]
    assert "#DEBHELPER#" in lines


# ── debian/rules install lines ───────────────────────────────────────────

def test_rules_installs_sbx_fleetctl_to_usr_sbin():
    rules = (ROOT / "debian" / "rules").read_text()
    assert "sbin/sbx-fleetctl" in rules
    assert "usr/sbin" in rules


def test_rules_installs_metrics_publish_units():
    rules = (ROOT / "debian" / "rules").read_text()
    assert "secubox-metrics-publish.service" in rules
    assert "secubox-metrics-publish.timer" in rules
    assert "lib/systemd/system" in rules


def test_rules_installs_www_fleet():
    rules = (ROOT / "debian" / "rules").read_text()
    assert "www/fleet" in rules


def test_rules_installs_menu_and_nginx():
    rules = (ROOT / "debian" / "rules").read_text()
    assert "595-fleet.json" in rules
    assert "fleet.conf" in rules


def test_annuaire_source_modules_exist_on_disk():
    """fleet.py/fleet_store.py/metrics_collect.py already ship via the
    existing `cp -r annuaire/*` glob in override_dh_auto_install — verify
    the source files are actually present so that glob has something to copy."""
    for mod in ("fleet.py", "fleet_store.py", "metrics_collect.py"):
        assert (ROOT / "annuaire" / mod).exists(), f"missing annuaire/{mod}"


# ── mesh listener (:8799) allow-list ─────────────────────────────────────

def test_mesh_listener_exposes_fleet_self():
    """BLOCKING fix: the :8799 Gondwana mesh listener must allow-list
    /api/v1/annuaire/fleet/self, or GET /fleet can never pull a peer's
    snapshot (_fetch_fleet_peer gets 403 from the exact-match template and
    no peer ever appears in the fleet-wide view — only `self` shows)."""
    tpl = (ROOT / "nginx" / "annuaire-mesh.conf.tpl").read_text()
    assert "location = /api/v1/annuaire/fleet/self" in tpl
    # sanity: the sibling we mirrored is still there, and the new block sits
    # before the terminal catch-all deny.
    assert "location = /api/v1/annuaire/log/export" in tpl
    deny_idx = tpl.index("location / { return 403; }")
    fleet_idx = tpl.index("location = /api/v1/annuaire/fleet/self")
    assert fleet_idx < deny_idx


def test_mesh_listener_fleet_self_mirrors_log_export():
    """The new block must be shaped exactly like /log/export: GET-only,
    same rewrite, same unix-socket proxy_pass, same include."""
    tpl = (ROOT / "nginx" / "annuaire-mesh.conf.tpl").read_text()

    def _block(path: str) -> str:
        start = tpl.index(f"location = {path} {{")
        # Walk braces to find the location block's own closing '}' — the
        # block contains a nested `limit_except GET { deny all; }`.
        depth = 0
        for i, ch in enumerate(tpl[start:], start=start):
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    return tpl[start:i]
        raise AssertionError(f"unterminated location block for {path!r}")

    log_export = _block("/api/v1/annuaire/log/export")
    fleet_self = _block("/api/v1/annuaire/fleet/self")
    for needle in (
        "limit_except GET { deny all; }",
        "rewrite ^/api/v1/annuaire/(.*)$ /$1 break;",
        "proxy_pass http://unix:/run/secubox/annuaire.sock;",
        "include /etc/nginx/snippets/secubox-proxy.conf;",
        "proxy_intercept_errors on;",
    ):
        assert needle in log_export
        assert needle in fleet_self


# ── changelog ─────────────────────────────────────────────────────────────

def test_changelog_bumped_for_fleet_metrics():
    head = (ROOT / "debian" / "changelog").read_text().splitlines()[0]
    assert "secubox-annuaire (" in head
    # version must be strictly newer than the pre-task-5 0.9.0
    import re
    m = re.search(r"\((\d+)\.(\d+)\.(\d+)-", head)
    assert m, f"unparseable changelog head: {head!r}"
    major, minor, patch = (int(x) for x in m.groups())
    assert (major, minor, patch) > (0, 9, 0)
