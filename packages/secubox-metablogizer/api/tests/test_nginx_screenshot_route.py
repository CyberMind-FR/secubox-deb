# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""nginx/metablogizer.conf — mosaic wall thumbnails served without FastAPI (#977).

Every mosaic tile used to fetch its screenshot through
`GET /api/v1/metablogizer/site/<name>/screenshot`, proxied all the way to
this module's single-worker asyncio event loop just to read a static PNG
that changes at most every few hours — measured on the board at
140-470ms/request through Python, ~37s for a full 172-tile wall even at
browser-typical concurrency (6). The fix moves that route to nginx: a
regex `location` with `alias` reads the file directly with sendfile(), the
Python backend never sees the request.

Unlike the other tests in this package, this one exercises the SHIPPED
`nginx/metablogizer.conf` file itself, through a real (non-root, ephemeral)
nginx process — not a hand-written re-implementation of its regex that
could silently drift from what actually ships. Only the hardcoded cache
directory prefix is substituted (verified to occur exactly once) so the
test can point at a temp directory instead of the real
`/var/cache/secubox/metablogizer/shots` (root-owned, not writable in a test
sandbox); the regex, `alias`, and header directives under test are the
literal shipped bytes.

Skips cleanly (not a failure) when no `nginx` binary is on PATH — this
package's other ~120 tests must stay runnable without nginx installed.

Run from packages/secubox-metablogizer/ with secubox_core importable:
    PYTHONPATH=api:../../common ../../.venv/bin/pytest \
        api/tests/test_nginx_screenshot_route.py -v
"""
from __future__ import annotations

import re
import shutil
import socket
import subprocess
import time
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(
    shutil.which("nginx") is None, reason="nginx binary not on PATH"
)

CONF_PATH = Path(__file__).resolve().parents[2] / "nginx" / "metablogizer.conf"
SHOTS_LITERAL = "/var/cache/secubox/metablogizer/shots"


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _extract_screenshot_location(shots_dir: Path) -> str:
    """Pull the screenshot `location ~ ...` block out of the real shipped
    conf file, with only the hardcoded cache path swapped for `shots_dir`.
    Asserts the literal appears exactly once — a silent 0-or-2+ match would
    mean this test stopped exercising what's actually shipped."""
    content = CONF_PATH.read_text()
    assert content.count(SHOTS_LITERAL) == 1, (
        "expected the shots cache path literal exactly once in "
        f"{CONF_PATH} — test substitution would be unsound otherwise"
    )
    match = re.search(r"(location ~ .*?\n\})\n", content, re.S)
    assert match, f"no `location ~ ...` block found in {CONF_PATH}"
    return match.group(1).replace(SHOTS_LITERAL, str(shots_dir))


@pytest.fixture
def nginx_server(tmp_path):
    """Start a real, ephemeral, non-root nginx serving ONLY the shipped
    screenshot location block, pointed at a temp cache dir. Yields
    (base_url, shots_dir). Torn down at the end of the test — nothing
    lingers past this fixture, deliberately: an orphaned background nginx
    process is exactly the kind of thing that would corrupt an unrelated
    later test run."""
    shots_dir = tmp_path / "shots"
    shots_dir.mkdir()
    location_block = _extract_screenshot_location(shots_dir)

    run_dir = tmp_path / "run"
    run_dir.mkdir()
    port = _free_port()

    location_conf = tmp_path / "location.conf"
    location_conf.write_text(location_block)

    nginx_conf = tmp_path / "nginx.conf"
    nginx_conf.write_text(f"""
worker_processes 1;
daemon off;
error_log {tmp_path}/error.log warn;
pid {run_dir}/nginx.pid;
events {{ worker_connections 16; }}
http {{
    include /etc/nginx/mime.types;
    default_type application/octet-stream;
    access_log off;
    client_body_temp_path {tmp_path}/tmp_client;
    proxy_temp_path {tmp_path}/tmp_proxy;
    fastcgi_temp_path {tmp_path}/tmp_fastcgi;
    uwsgi_temp_path {tmp_path}/tmp_uwsgi;
    scgi_temp_path {tmp_path}/tmp_scgi;
    server {{
        listen 127.0.0.1:{port};
        server_name _;
        include {location_conf};
    }}
}}
""")

    proc = subprocess.Popen(
        ["nginx", "-c", str(nginx_conf)],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )
    try:
        deadline = time.monotonic() + 5.0
        last_err = None
        while time.monotonic() < deadline:
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                    break
            except OSError as e:
                last_err = e
                if proc.poll() is not None:
                    out = proc.stdout.read().decode(errors="replace")
                    pytest.fail(f"nginx exited early: {out}")
                time.sleep(0.05)
        else:
            pytest.fail(f"nginx never opened port {port}: {last_err}")

        yield f"http://127.0.0.1:{port}", shots_dir
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)


def _get(base_url, path):
    import urllib.request
    import urllib.error

    req = urllib.request.Request(base_url + path)
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.getcode(), dict(resp.headers), resp.read()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read()


# ─────────────────────────────────────────────────────────────────────────
# The happy path — this is the whole point of #977: nginx, not Python.
# ─────────────────────────────────────────────────────────────────────────

def test_existing_screenshot_served_with_correct_bytes(nginx_server):
    base_url, shots_dir = nginx_server
    (shots_dir / "demo").mkdir()
    png = b"\x89PNG" + b"fake" * 10
    (shots_dir / "demo" / "screenshot.png").write_bytes(png)

    code, headers, body = _get(base_url, "/api/v1/metablogizer/site/demo/screenshot")

    assert code == 200
    assert body == png


def test_content_type_is_image_png_despite_extensionless_url(nginx_server):
    """The URL has no `.png` suffix (same path FastAPI answers to) — nginx's
    mime.types lookup keys off the request URI's extension, not the aliased
    file's real name, so without an explicit `default_type` in the location
    this would silently regress to application/octet-stream."""
    base_url, shots_dir = nginx_server
    (shots_dir / "demo").mkdir()
    (shots_dir / "demo" / "screenshot.png").write_bytes(b"\x89PNG")

    _, headers, _ = _get(base_url, "/api/v1/metablogizer/site/demo/screenshot")

    assert headers.get("Content-Type") == "image/png"


def test_cache_control_is_long_and_immutable(nginx_server):
    """Safe only because the frontend cache-busts via `?v=<captured_at>`
    (api/sites_scan.py: screenshot_captured_at) — a recapture changes the
    URL, so this aggressive caching can never serve a stale vignette."""
    base_url, shots_dir = nginx_server
    (shots_dir / "demo").mkdir()
    (shots_dir / "demo" / "screenshot.png").write_bytes(b"\x89PNG")

    _, headers, _ = _get(base_url, "/api/v1/metablogizer/site/demo/screenshot")

    cache_control = headers.get("Cache-Control", "")
    assert "immutable" in cache_control
    assert "max-age=31536000" in cache_control


def test_query_string_cache_buster_does_not_affect_matching(nginx_server):
    """The frontend appends `?v=<captured_at>` — nginx location matching is
    path-only, so the same file must still resolve regardless of query
    string, cache-busting must not turn into a 404."""
    base_url, shots_dir = nginx_server
    (shots_dir / "demo").mkdir()
    png = b"\x89PNG-v2"
    (shots_dir / "demo" / "screenshot.png").write_bytes(png)

    code, _, body = _get(
        base_url, "/api/v1/metablogizer/site/demo/screenshot?v=2026-08-04T00%3A00%3A00Z"
    )

    assert code == 200
    assert body == png


# ─────────────────────────────────────────────────────────────────────────
# Absence — must 404 quietly, never break the frontend's onerror fallback.
# ─────────────────────────────────────────────────────────────────────────

def test_never_captured_site_is_404(nginx_server):
    base_url, _shots_dir = nginx_server
    code, _, _ = _get(base_url, "/api/v1/metablogizer/site/never-captured/screenshot")
    assert code == 404


def test_404_response_carries_no_long_lived_cache_header(nginx_server):
    """A 404 must never be cached the way a real vignette is — `add_header`
    without `always` only decorates successful responses, so a site that
    hasn't been captured YET doesn't get permanently stuck 404 in the
    browser cache once metablog-shots.timer does capture it."""
    base_url, _shots_dir = nginx_server
    _, headers, _ = _get(base_url, "/api/v1/metablogizer/site/never-captured/screenshot")
    assert "immutable" not in headers.get("Cache-Control", "")


# ─────────────────────────────────────────────────────────────────────────
# Traversal — the FastAPI route this bypasses guards `../` via `_safe_key()`
# (see test_site_screenshot_route.py::test_404_for_traversal_attempt); the
# nginx alias needs its own guard since it never reaches that code anymore.
# ─────────────────────────────────────────────────────────────────────────

def test_dotdot_segment_does_not_escape_the_cache_dir(nginx_server):
    base_url, shots_dir = nginx_server
    # A real secret the traversal would read if the guard failed.
    (shots_dir.parent / "sites.json").write_text('{"secret": true}')

    code, _, body = _get(
        base_url, "/api/v1/metablogizer/site/..%2f..%2fsites.json/screenshot"
    )

    assert code == 404
    assert b"secret" not in body


def test_dot_prefixed_name_rejected(nginx_server):
    """Matches `_site_dirs()`/`scan_sites()`, which skip dotfile-named
    directories when producing the fleet — the alias should reject the same
    shapes rather than trust an arbitrary caller-supplied name."""
    base_url, shots_dir = nginx_server
    hidden = shots_dir / ".secret"
    hidden.mkdir()
    (hidden / "screenshot.png").write_bytes(b"\x89PNG")

    code, _, _ = _get(base_url, "/api/v1/metablogizer/site/.secret/screenshot")

    assert code == 404
