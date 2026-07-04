# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox-Deb :: vhost.main — generate_vhost_config include wiring + seed-on-create (ref #793).

Strategy under test: seed the per-vhost exposure snippet BEFORE emitting the
nginx `include`, and only emit the include when seeding succeeded. This
guarantees nginx is never left referencing a missing include (hard 500 on
reload) — a freshly-created vhost either gates (seeded ok) or stays ungated
but loadable (seed failed), never broken.
"""
import sys
from pathlib import Path
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "common"))
sys.path.insert(0, str(ROOT / "packages" / "secubox-vhost"))

import api.main as m
from api.exposure_seed import ensure_snippet as _real_ensure_snippet


def test_generate_vhost_config_default_omits_include():
    conf = m.generate_vhost_config("z.example", "http://127.0.0.1:9000", "off", False, True)
    assert "include /etc/nginx/snippets/exposure/z.example.conf;" not in conf


def test_generate_vhost_config_with_include_true_emits_include_in_location_block():
    conf = m.generate_vhost_config(
        "z.example", "http://127.0.0.1:9000", "off", False, True, exposure_include=True)
    assert "include /etc/nginx/snippets/exposure/z.example.conf;" in conf

    # the include line must sit inside `location / { ... }`, before proxy_pass
    loc_start = conf.index("location / {")
    loc_body = conf[loc_start:]
    include_pos = loc_body.index("include /etc/nginx/snippets/exposure/z.example.conf;")
    proxy_pos = loc_body.index("proxy_pass")
    assert include_pos < proxy_pos


def test_generate_vhost_config_include_false_by_default_keeps_existing_tests_green():
    conf = m.generate_vhost_config("z.example", "http://127.0.0.1:9000", "off", False, True)
    assert "proxy_pass http://127.0.0.1:9000;" in conf


def _client(tmp_path, monkeypatch, seed_dir=None):
    (tmp_path / "enabled").mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(m, "NGINX_VHOST_DIR", tmp_path / "available")
    monkeypatch.setattr(m, "NGINX_ENABLED_DIR", tmp_path / "enabled")
    if seed_dir is not None:
        monkeypatch.setattr(m, "ensure_snippet",
                             lambda vhost: _real_ensure_snippet(vhost, snippet_dir=seed_dir))
    m.app.dependency_overrides[m.require_jwt] = lambda: {"sub": "admin"}
    return TestClient(m.app)


def test_create_vhost_seeds_snippet_and_includes_it(tmp_path, monkeypatch):
    seed_dir = tmp_path / "snip"
    c = _client(tmp_path, monkeypatch, seed_dir=seed_dir)
    r = c.post("/vhost", json={"domain": "new.example", "backend": "http://127.0.0.1:9100"})
    assert r.status_code == 200

    assert (seed_dir / "new.example.conf").exists()
    conf = (tmp_path / "available" / "new.example.conf").read_text()
    assert "include /etc/nginx/snippets/exposure/new.example.conf;" in conf


def test_create_vhost_stays_ungated_but_loadable_when_seed_fails(tmp_path, monkeypatch):
    (tmp_path / "enabled").mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(m, "NGINX_VHOST_DIR", tmp_path / "available")
    monkeypatch.setattr(m, "NGINX_ENABLED_DIR", tmp_path / "enabled")
    monkeypatch.setattr(m, "ensure_snippet", lambda vhost: False)
    m.app.dependency_overrides[m.require_jwt] = lambda: {"sub": "admin"}
    c = TestClient(m.app)

    r = c.post("/vhost", json={"domain": "broken.example", "backend": "http://127.0.0.1:9200"})
    assert r.status_code == 200

    conf = (tmp_path / "available" / "broken.example.conf").read_text()
    # no include emitted — nginx stays loadable even though the seed failed
    assert "include /etc/nginx/snippets/exposure/broken.example.conf;" not in conf
