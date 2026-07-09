# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""obfs4 bridge emission (Task 8) + reapply-when-armed (Step 5c):
ordering (torrc drop-ins BEFORE tor reload) and ATOMIC nft set swap
(flush+add in one `nft -f` txn — no clearnet fall-through window)."""
import os
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
    out = subprocess.run(
        ["bash", str(CTL), "__emit_bridges", str(tmp_path / "does-not-exist.txt")],
        capture_output=True, text=True)
    assert out.returncode == 0
    assert out.stdout.strip() == ""


def _run_harness(tmp_path, filters_json, harness_body):
    """Source the reconciler (its trailing `main "$@"` is guarded so sourcing
    does NOT auto-run), install stubs, then drive `main reconcile` in-process.
    Note: sourcing propagates the script's `set -euo pipefail` into the
    harness, so every stub is written to return 0."""
    filters = tmp_path / "filters.json"
    filters.write_text(filters_json)
    harness = tmp_path / "harness.sh"
    harness.write_text(f'#!/usr/bin/env bash\nsource "{CTL}"\n{harness_body}\nmain reconcile\n')
    env = dict(os.environ)
    env["SECUBOX_FILTERS_PATH"] = str(filters)
    return subprocess.run(["bash", str(harness)], capture_output=True, text=True,
                           env=env, stdin=subprocess.DEVNULL)


def test_reapply_writes_torrc_before_tor_reload(tmp_path):
    """A second `reconcile` while armed must (a) re-run the torrc-drop-in and
    set-apply helpers, and (b) write the torrc drop-ins BEFORE reloading tor
    (else tor reloads without bridges/exit-country → direct/unbridged)."""
    marker = tmp_path / "calls.log"
    body = f"""
MARKER="{marker}"
table_present() {{ return 0; }}                     # pretend armed
_write_torrc_dropins() {{ echo "write_torrc_dropins" >> "$MARKER"; }}
populate_vpn_clients() {{ echo "10.0.0.5"; }}         # stdout -> piped into _apply_set
populate_exempt() {{ echo "127.0.0.0/8"; }}
populate_exempt_dynamic_hosts() {{ echo "exempt_dynamic" >> "$MARKER"; }}
_apply_set() {{ cat >/dev/null || true; echo "apply_set $1" >> "$MARKER"; return 0; }}
nft() {{ return 0; }}
systemctl() {{ echo "systemctl $*" >> "$MARKER"; return 0; }}
"""
    r = _run_harness(tmp_path, '{"tor_mode": true}\n', body)
    assert r.returncode == 0, r.stderr
    lines = marker.read_text().splitlines()
    assert "write_torrc_dropins" in lines
    assert "apply_set tor_vpn_src" in lines
    assert "apply_set tor_exempt" in lines
    assert "exempt_dynamic" in lines
    reload_line = next(l for l in lines if l.startswith("systemctl reload tor"))
    # ordering: torrc drop-ins land before the tor reload
    assert lines.index("write_torrc_dropins") < lines.index(reload_line)


def test_reapply_uses_atomic_set_swap(tmp_path):
    """The tor_vpn_src repopulation must be ONE atomic `nft -f` batch
    (flush+add together), never a bare `flush` left standing that would open a
    clearnet fall-through window on a @tor_vpn_src-gated rule."""
    marker = tmp_path / "nft.log"
    vpn = tmp_path / "vpn.txt"
    vpn.write_text("ip:10.0.0.5\n")
    body = f"""
MARKER="{marker}"
VPN_CLIENTS_STATE="{vpn}"                            # real populate_vpn_clients reads this
table_present() {{ return 0; }}
_write_torrc_dropins() {{ :; }}
populate_exempt() {{ printf ''; }}                    # empty exempt (separate set)
populate_exempt_dynamic_hosts() {{ :; }}
systemctl() {{ return 0; }}
nft() {{
  echo "ARGS:$*" >> "$MARKER"
  if [ ! -t 0 ]; then
    local in=""; in="$(cat)" || true
    if [ -n "$in" ]; then printf 'STDIN:%s\\n' "$in" >> "$MARKER"; fi
  fi
  return 0
}}
"""
    r = _run_harness(tmp_path, '{"tor_mode": true}\n', body)
    assert r.returncode == 0, r.stderr
    content = marker.read_text()
    # atomic apply: nft invoked with `-f -`, carrying flush+add for the SAME set
    assert "ARGS:-f -" in content
    assert "flush set inet toolbox_tor tor_vpn_src" in content
    assert "add element inet toolbox_tor tor_vpn_src { 10.0.0.5 }" in content
    # and NOT the non-atomic bare-flush path for tor_vpn_src
    assert "ARGS:flush set inet toolbox_tor tor_vpn_src" not in content
