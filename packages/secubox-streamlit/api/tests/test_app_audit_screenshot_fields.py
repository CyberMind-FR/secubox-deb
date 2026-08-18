# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Tests for the screenshot_* fields surfaced by `streamlitctl app audit`
(#958).

These fields let the wall mark a tile as having a vignette, périmée
(stale), or failed WITHOUT any extra HTTP round trip: the audit cache is
already refreshed every 5 minutes by streamlit-audit.timer and read by the
panel on every refresh, so folding screenshot freshness into the same
JSON avoids polling 56 separate `/screenshot` endpoints just to read a
timestamp header. This module ONLY READS what `streamlit-shotter` (api/
shots.py, via secubox_core.screenshots) already wrote — it never captures
anything itself, consistent with the "app audit never triggers anything"
rule already established by #956.
"""
import json
import subprocess
from pathlib import Path

CTL = Path(__file__).resolve().parents[2] / "sbin" / "streamlitctl"


def _audit_with_shots(tmp_path, apps_dir, shots_dir, conf_extra=""):
    conf = tmp_path / "streamlit.toml"; conf.write_text(conf_extra)
    ps_file = tmp_path / "ps.txt"; ps_file.touch()
    env = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
           "SECUBOX_STREAMLIT_APPS_PATH": str(apps_dir),
           "SECUBOX_STREAMLIT_CONF": str(conf),
           "SECUBOX_STREAMLIT_IDLE_DIR": str(tmp_path / "idle"),
           "SECUBOX_STREAMLIT_PS_SOURCE": str(ps_file),
           "SECUBOX_STREAMLIT_SHOTS_DIR": str(shots_dir)}
    r = subprocess.run(["bash", str(CTL), "app", "audit"],
                       capture_output=True, text=True, env=env, timeout=30)
    return json.loads(r.stdout)


def _write_meta(shots_dir, name, fingerprint, ok=True, captured_at="2026-08-03T10:00:00+00:00"):
    d = shots_dir / name
    d.mkdir(parents=True, exist_ok=True)
    (d / "screenshot.png").write_bytes(b"\x89PNG" + b"0" * 100)
    meta = {"captured_at": captured_at, "fingerprint": fingerprint, "ok": ok}
    (d / "screenshot.json").write_text(json.dumps(meta, indent=2))


def test_app_never_captured_reports_unavailable_never_stale_marker(tmp_path):
    """No screenshot.json/png at all -- must report available=false rather
    than crash or omit the fields (the wall must always find them)."""
    apps_dir = tmp_path / "apps"; apps_dir.mkdir()
    d = apps_dir / "jamais"; d.mkdir()
    (d / "app.py").write_text("import streamlit\n")

    out = _audit_with_shots(tmp_path, apps_dir, tmp_path / "shots")
    app = out["apps"][0]

    assert app["screenshot_available"] is False
    assert app["screenshot_ok"] is False
    assert app["screenshot_captured_at"] == ""


def test_fresh_screenshot_matching_fingerprint_is_not_stale(tmp_path):
    shots_dir = tmp_path / "shots"
    apps_dir = tmp_path / "apps"; apps_dir.mkdir()
    d = apps_dir / "demo"; d.mkdir()
    src_file = d / "app.py"
    src_file.write_text("import streamlit\n")

    st = src_file.stat()
    fingerprint = f"{int(st.st_mtime)}:{st.st_size}"
    _write_meta(shots_dir, "demo", fingerprint, ok=True)

    out = _audit_with_shots(tmp_path, apps_dir, shots_dir)
    app = out["apps"][0]

    assert app["screenshot_available"] is True
    assert app["screenshot_ok"] is True
    assert app["screenshot_stale"] is False
    assert app["screenshot_captured_at"] == "2026-08-03T10:00:00+00:00"


def test_screenshot_marked_stale_when_fingerprint_mismatches(tmp_path):
    """Design invariant (#957 §3.6): "image périmée -> affichée et
    marquée" -- once the source's mtime/size fingerprint no longer matches
    what was recorded, screenshot_stale must flip to true even though the
    PNG itself is still served."""
    shots_dir = tmp_path / "shots"
    apps_dir = tmp_path / "apps"; apps_dir.mkdir()
    d = apps_dir / "demo"; d.mkdir()
    (d / "app.py").write_text("import streamlit\n")
    _write_meta(shots_dir, "demo", fingerprint="1:1", ok=True)  # doesn't match real stat

    out = _audit_with_shots(tmp_path, apps_dir, shots_dir)
    app = out["apps"][0]

    assert app["screenshot_available"] is True
    assert app["screenshot_stale"] is True


def test_failed_capture_reported_as_not_ok_while_png_still_available(tmp_path):
    """Design invariant (#957 §3.6): "capture en échec -> l'image
    précédente survit et l'échec est signalé" -- the audit must expose
    both halves: the PNG is still there (available=true) AND the failure
    is visible (ok=false), so the wall can show the old image with a
    failure badge instead of silently pretending nothing happened."""
    shots_dir = tmp_path / "shots"
    apps_dir = tmp_path / "apps"; apps_dir.mkdir()
    d = apps_dir / "demo"; d.mkdir()
    (d / "app.py").write_text("import streamlit\n")
    _write_meta(shots_dir, "demo", fingerprint="whatever", ok=False)

    out = _audit_with_shots(tmp_path, apps_dir, shots_dir)
    app = out["apps"][0]

    assert app["screenshot_available"] is True
    assert app["screenshot_ok"] is False
    assert app["screenshot_stale"] is True


def test_flat_script_app_screenshot_fields_resolve_too(tmp_path):
    """The screenshot fields must be resolved for flat-script apps exactly
    like directory apps -- the exact class of app the pre-#959 code used
    to miss entirely."""
    shots_dir = tmp_path / "shots"
    apps_dir = tmp_path / "apps"; apps_dir.mkdir()
    script = apps_dir / "billets.py"
    script.write_text("import streamlit\n")

    st = script.stat()
    fingerprint = f"{int(st.st_mtime)}:{st.st_size}"
    _write_meta(shots_dir, "billets", fingerprint, ok=True)

    out = _audit_with_shots(tmp_path, apps_dir, shots_dir)
    app = out["apps"][0]

    assert app["screenshot_available"] is True
    assert app["screenshot_ok"] is True
    assert app["screenshot_stale"] is False
