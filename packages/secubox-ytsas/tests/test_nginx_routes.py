# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: secubox-ytsas :: admin-panel nginx route (ref #979)

ytsas is LXC-native (the yt-dlp engine runs entirely inside its own
container), so /api/v1/ytsas/ was 404 from the admin vhost. These tests
check the shipped route snippet (nginx/ytsas-routes.conf), its packaging
(debian/rules + postinst + prerm), and — with a real, ephemeral nginx
binary — that dropping it into secubox-routes.d/ does not collide with
anything the companion PWA vhost already declares.
"""

import re
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
REPO_ROOT = ROOT.parent.parent

ROUTE_FILE = ROOT / "nginx" / "ytsas-routes.conf"
PROXY_SNIPPET = REPO_ROOT / "common" / "nginx" / "secubox-proxy.conf"
COMPANION_CONF = REPO_ROOT / "secubox-companion" / "deploy" / "nginx-companion.conf"

NGINX_BIN = shutil.which("nginx")


def _read(p):
    return p.read_text()


# ── Static content ──────────────────────────────────────────────────────

def test_route_file_targets_the_lxc_static_address():
    conf = _read(ROUTE_FILE)
    assert "location /api/v1/ytsas/" in conf
    assert "proxy_pass http://10.100.0.180:8091;" in conf
    assert "include /etc/nginx/snippets/secubox-proxy.conf;" in conf


def test_route_file_ip_matches_the_toml_source_of_truth():
    # The LXC's address is static (assigned to its veth by install-lxc.sh),
    # not resolved at request time. Guard against the route drifting from
    # the [lxc].ip declared in conf/ytsas.toml.
    toml = _read(ROOT / "conf" / "ytsas.toml")
    assert 'ip      = "10.100.0.180"' in toml
    assert "10.100.0.180" in _read(ROUTE_FILE)


def test_companion_vhost_has_no_conflicting_ytsas_location():
    # Unlike torrent, the companion PWA vhost does not (yet) special-case
    # /api/v1/ytsas/ — it falls through to the generic /api/v1/ catch-all
    # (proxied to the aggregator, which has no ytsas module either; a
    # separate, pre-existing gap outside this ticket's scope). Documented
    # here so a future companion route for ytsas is a deliberate change,
    # not a silent duplicate of this admin-vhost snippet.
    assert "/api/v1/ytsas/" not in _read(COMPANION_CONF)


# ── Packaging wiring ─────────────────────────────────────────────────────

def test_rules_installs_route_to_secubox_routes_d():
    rules = _read(ROOT / "debian" / "rules")
    assert "etc/nginx/secubox-routes.d" in rules
    assert "nginx/ytsas-routes.conf" in rules


def test_postinst_validates_before_reload():
    postinst = _read(ROOT / "debian" / "postinst")
    assert "nginx -t" in postinst
    assert "systemctl reload nginx" in postinst


def test_prerm_removes_route_only_on_remove_or_deconfigure_not_upgrade():
    prerm = _read(ROOT / "debian" / "prerm")
    idx = prerm.index("secubox-routes.d/ytsas-routes.conf")
    # The removal must sit in its own, innermost remove|deconfigure case
    # arm, never the outer remove|upgrade|deconfigure) one — dpkg's own
    # conffile handling already covers upgrades, and deleting it there
    # would just make postinst redo pointless work on every reinstall.
    # Find the *nearest* preceding case-arm line (e.g. "remove|deconfigure)")
    # not separated from the target by an intervening "esac" (which would
    # mean that arm's block had already closed).
    arm_lines = [
        (m.start(), m.group(1))
        for m in re.finditer(r"^\s*(\S+\))\s*$", prerm, re.MULTILINE)
        if m.start() < idx
    ]
    assert arm_lines, "could not find any case arm before the route removal"
    nearest_pos, nearest_arm = arm_lines[-1]
    assert "esac" not in prerm[nearest_pos:idx]
    assert nearest_arm == "remove|deconfigure)"


# ── Real nginx: no collision with the admin vhost's other locations ──────

pytestmark_nginx = pytest.mark.skipif(
    NGINX_BIN is None, reason="nginx binary not available in this environment"
)


def _run_nginx_t(tmp_path, http_server_blocks: str) -> subprocess.CompletedProcess:
    assert NGINX_BIN is not None  # guarded by pytestmark_nginx at call sites
    (tmp_path / "secubox-routes.d").mkdir()
    shutil.copy(ROUTE_FILE, tmp_path / "secubox-routes.d" / ROUTE_FILE.name)
    (tmp_path / "snippets").mkdir()
    shutil.copy(PROXY_SNIPPET, tmp_path / "snippets" / "secubox-proxy.conf")

    conf = tmp_path / "nginx.conf"
    conf.write_text(
        "worker_processes 1;\n"
        "error_log stderr;\n"
        f"pid {tmp_path}/nginx.pid;\n"
        "events { worker_connections 16; }\n"
        "http {\n"
        "    access_log off;\n"
        f"{http_server_blocks}\n"
        "}\n"
    )
    return subprocess.run(
        [NGINX_BIN, "-t", "-c", str(conf), "-p", str(tmp_path)],
        capture_output=True,
        text=True,
    )


@pytestmark_nginx
def test_admin_vhost_with_route_and_companion_vhost_coexist(tmp_path):
    # Mirrors production: the admin vhost (common/nginx/webui.conf) has no
    # server_name and blanket-includes secubox-routes.d/*.conf; the
    # companion vhost (secubox-companion/deploy/nginx-companion.conf) is a
    # separate server{} disambiguated by server_name, with its own generic
    # /api/v1/ catch-all. Different server{} blocks on the same listen port
    # never collide in nginx — this proves it against the real shipped
    # files rather than assuming it.
    blocks = f"""
    server {{
        listen 127.0.0.1:19082;
        location / {{ return 404; }}
        include {tmp_path}/secubox-routes.d/*.conf;
    }}
    server {{
        listen 127.0.0.1:19082;
        server_name companion.gk2.secubox.in;
        location /api/v1/ {{ proxy_pass http://unix:/run/secubox/aggregator.sock:/api/v1/; }}
        location / {{ return 404; }}
    }}
    """
    result = _run_nginx_t(tmp_path, blocks)
    assert result.returncode == 0, result.stderr
    assert "duplicate location" not in result.stderr


@pytestmark_nginx
def test_duplicate_location_in_the_same_server_would_be_caught(tmp_path):
    # Sanity check that the harness above is actually sensitive to a real
    # conflict, not just trivially passing. Deliberately reintroduces the
    # route's location directly alongside the include, inside ONE server{}.
    blocks = f"""
    server {{
        listen 127.0.0.1:19083;
        location /api/v1/ytsas/ {{ proxy_pass http://10.100.0.180:8091; }}
        include {tmp_path}/secubox-routes.d/*.conf;
    }}
    """
    result = _run_nginx_t(tmp_path, blocks)
    assert result.returncode != 0
    assert "duplicate location" in result.stderr
