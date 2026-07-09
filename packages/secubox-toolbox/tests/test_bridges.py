# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""obfs4 bridge emission (Task 8) + reapply-when-armed (Step 5c)."""
import subprocess
from pathlib import Path

CTL = Path(__file__).resolve().parents[1] / "sbin" / "secubox-toolbox-tor-reconcile"


def _emit(lines, tmp_path):
    f = tmp_path / "b.txt"
    f.write_text(lines)
    return subprocess.run(["bash", str(CTL), "__emit_bridges", str(f)],
                           capture_output=True, text=True).stdout


def test_valid_bridge_emits_usebridges(tmp_path):
    out = _emit("Bridge obfs4 192.0.2.3:80 ABCD cert=xyz iat-mode=0\n", tmp_path)
    assert "UseBridges 1" in out
    assert "ClientTransportPlugin obfs4 exec /usr/bin/obfs4proxy" in out
    assert "Bridge obfs4 192.0.2.3:80 ABCD cert=xyz iat-mode=0" in out


def test_empty_emits_nothing(tmp_path):
    assert _emit("\n", tmp_path).strip() == ""


def test_injection_line_skipped(tmp_path):
    # a line not starting with 'Bridge obfs4 ' (torrc-injection attempt) is dropped
    out = _emit("HiddenServiceDir /evil\nBridge obfs4 192.0.2.3:80 AB cert=x iat-mode=0\n", tmp_path)
    assert "HiddenServiceDir" not in out
    assert "192.0.2.3:80" in out


def test_missing_file_emits_nothing(tmp_path):
    out = _emit_missing = subprocess.run(
        ["bash", str(CTL), "__emit_bridges", str(tmp_path / "does-not-exist.txt")],
        capture_output=True, text=True)
    assert out.returncode == 0
    assert out.stdout.strip() == ""


def test_reapply_reruns_emit_and_populate_helpers(tmp_path, monkeypatch):
    """A second `reconcile` while already armed must NOT no-op: it must
    re-emit the country/bridge drop-ins and re-populate the nft sets so
    edits made while Tor is ON apply live (#683 Step 5c)."""
    filters = tmp_path / "filters.json"
    filters.write_text('{"tor_mode": true}\n')

    # Stub out everything reapply() touches so this test never calls real
    # nft/systemctl/tor. We wrap the script in a harness that overrides
    # table_present (pretend armed), nft, systemctl, and traces calls to
    # populate_vpn_clients/populate_exempt/_emit_exit_country/_emit_bridges
    # via a marker file each stub appends to.
    marker = tmp_path / "calls.log"
    harness = tmp_path / "harness.sh"
    # `source` the reconciler (its own trailing `main "$@"` is guarded to only
    # fire when executed directly, not sourced) so its real function
    # definitions load, THEN redefine the ones we want to stub — stubs must
    # come AFTER the source or the script's own defs would clobber them.
    harness.write_text(f"""#!/usr/bin/env bash
set -euo pipefail
MARKER="{marker}"
source "{CTL}"
table_present() {{ return 0; }}   # pretend armed
nft() {{ echo "nft $*" >> "$MARKER"; return 0; }}
systemctl() {{ echo "systemctl $*" >> "$MARKER"; return 0; }}
populate_vpn_clients() {{ echo "populate_vpn_clients" >> "$MARKER"; }}
populate_exempt() {{ echo "populate_exempt" >> "$MARKER"; }}
_emit_exit_country() {{ echo "_emit_exit_country" >> "$MARKER"; return 0; }}
_emit_bridges() {{ echo "_emit_bridges" >> "$MARKER"; return 0; }}
main reconcile
""")
    env = dict(**__import__("os").environ)
    env["SECUBOX_FILTERS_PATH"] = str(filters)
    result = subprocess.run(["bash", str(harness)],
                             capture_output=True, text=True, env=env)
    assert result.returncode == 0, result.stderr
    calls = marker.read_text() if marker.exists() else ""
    assert "populate_vpn_clients" in calls
    assert "populate_exempt" in calls
    assert "_emit_exit_country" in calls
    assert "_emit_bridges" in calls
    assert "systemctl reload tor" in calls or "systemctl restart tor" in calls
