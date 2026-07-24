"""sbxmitm-policyctl (#rlevel-per-peer, task 4) — atomic peer-rlevel.json
write, nft off-bypass drop-in regeneration, and audit logging.

Runs the real bash script via subprocess with every path env-overridden into
a tmp_path sandbox (RLEVEL_FILE/WG_PEERS/NFT_D/AUDIT_FILE) and DRYRUN=1 so
`nft -f` is never actually invoked.
"""
import json
import subprocess
from pathlib import Path

import pytest

CTL = Path(__file__).resolve().parents[1] / "sbin" / "sbxmitm-policyctl"

PK1 = "PK1pubkeyBASE64aaaaaaaaaaaaaaaaaaaaaaaaaaaa="
PK2 = "PK2pubkeyBASE64bbbbbbbbbbbbbbbbbbbbbbbbbbbb="


@pytest.fixture
def sandbox(tmp_path):
    rlevel = tmp_path / "peer-rlevel.json"
    wg_peers = tmp_path / "wg-peers.json"
    nft_d = tmp_path / "nftables.d"
    nft_d.mkdir()
    audit = tmp_path / "audit.log"
    nft_out = tmp_path / "rlevel-off.elements"
    wg_peers.write_text(json.dumps({
        "peers": {
            PK1: {"ip": "10.99.1.5"},
            PK2: {"ip": "10.99.1.6"},
        }
    }))
    env = {
        "RLEVEL_FILE": str(rlevel),
        "WG_PEERS": str(wg_peers),
        "NFT_D": str(nft_d),
        "AUDIT_FILE": str(audit),
        "RLEVEL_NFT_OUT": str(nft_out),
        "DRYRUN": "1",
        "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
    }
    return {
        "rlevel": rlevel, "wg_peers": wg_peers, "nft_d": nft_d,
        "audit": audit, "nft_out": nft_out, "env": env,
    }


def run(sandbox, *args):
    return subprocess.run(
        ["bash", str(CTL), *args],
        capture_output=True, text=True, env=sandbox["env"],
    )


def rlevel_json(sandbox):
    return json.loads(sandbox["rlevel"].read_text())


def nft_text(sandbox):
    out = sandbox["nft_out"]
    return out.read_text() if out.exists() else ""


# ── mutation correctness ──────────────────────────────────────────────────

def test_set_floor_mutates_json(sandbox):
    r = run(sandbox, "set-floor", PK1, "active")
    assert r.returncode == 0, r.stderr
    doc = rlevel_json(sandbox)
    assert doc["peers"][PK1]["floor"] == "active"


def test_force_mutates_json(sandbox):
    r = run(sandbox, "force", PK2, "off")
    assert r.returncode == 0, r.stderr
    doc = rlevel_json(sandbox)
    assert doc["peers"][PK2]["forced"] == "off"


def test_force_none_clears(sandbox):
    run(sandbox, "force", PK2, "off")
    r = run(sandbox, "force", PK2, "none")
    assert r.returncode == 0, r.stderr
    doc = rlevel_json(sandbox)
    assert doc["peers"][PK2]["forced"] is None


def test_set_chosen_mutates_json(sandbox):
    r = run(sandbox, "set-chosen", PK1, "active")
    assert r.returncode == 0, r.stderr
    doc = rlevel_json(sandbox)
    assert doc["peers"][PK1]["chosen"] == "active"


def test_set_chosen_clamped_to_floor(sandbox):
    run(sandbox, "set-floor", PK1, "active")
    r = run(sandbox, "set-chosen", PK1, "off")
    assert r.returncode == 0, r.stderr
    doc = rlevel_json(sandbox)
    # chosen "off" clamped up to the peer's floor "active"
    assert doc["peers"][PK1]["chosen"] == "active"


def test_set_default_mutates_json(sandbox):
    r = run(sandbox, "set-default", "active", "passive")
    assert r.returncode == 0, r.stderr
    doc = rlevel_json(sandbox)
    assert doc["defaults"] == {"mode": "active", "floor": "passive"}


def test_list_prints_json(sandbox):
    run(sandbox, "set-floor", PK1, "active")
    r = run(sandbox, "list")
    assert r.returncode == 0, r.stderr
    doc = json.loads(r.stdout)
    assert doc["peers"][PK1]["floor"] == "active"


# ── atomicity + idempotence ───────────────────────────────────────────────

def test_no_shadow_file_left_behind(sandbox):
    run(sandbox, "set-floor", PK1, "active")
    assert not (sandbox["rlevel"].parent / "peer-rlevel.json.shadow").exists()


def test_idempotent_same_command_twice_same_content(sandbox):
    run(sandbox, "set-floor", PK1, "active")
    first = sandbox["rlevel"].read_text()
    run(sandbox, "set-floor", PK1, "active")
    second = sandbox["rlevel"].read_text()
    assert first == second


def test_idempotent_force_twice_same_content(sandbox):
    run(sandbox, "force", PK2, "off")
    first = sandbox["rlevel"].read_text()
    run(sandbox, "force", PK2, "off")
    second = sandbox["rlevel"].read_text()
    assert first == second


def test_ctl_writes_rlevel_json_via_shadow_then_rename():
    """Structural guard (task-4 review, Important finding): peer-rlevel.json
    must never be written in place — a crash mid-write must never leave a
    torn/partial file readable by the Go workers. Grep the real script for
    the shadow-write-then-atomic-rename pattern rather than relying only on
    the behavioral before/after tests above."""
    src = CTL.read_text()
    assert '$RLEVEL_FILE.shadow"' in src
    assert 'mv -f "$shadow" "$RLEVEL_FILE"' in src


def test_nft_dropins_place_off_bypass_in_same_chain_as_dnat():
    """Structural guard (task-4 review, CRITICAL finding): the off-bypass
    `return` must live in the SAME nat chain as the DNAT it is meant to
    short-circuit — a `return` from a separate nat table does not stop
    another table's dnat on the same hook/priority. Assert both shipped
    drop-ins declare the named set and reference it before any `dnat`."""
    nft_dir = Path(__file__).resolve().parents[1] / "nftables.d"
    for fname in ("secubox-toolbox-wg.nft", "secubox-toolbox-wg-fanout.nft"):
        raw = (nft_dir / fname).read_text()
        assert "set rlevel_off" in raw
        assert "type ipv4_addr" in raw
        # Strip full-line comments so header prose (which mentions the old
        # single-target `dnat ip to ...` for context) can't shadow the real
        # rule lines below when locating statement order.
        code = "\n".join(
            ln for ln in raw.splitlines() if not ln.strip().startswith("#")
        )
        return_idx = code.index("ip saddr @rlevel_off return")
        dnat_idx = code.index("dnat ip to")
        assert return_idx < dnat_idx, f"{fname}: off-bypass must precede dnat in the same chain"
        assert "table inet secubox-toolbox-rlevel" not in raw


# ── nft off-bypass named set ───────────────────────────────────────────────
#
# The fix for the task-4 CRITICAL finding: the off-bypass is no longer a
# separate `table inet secubox-toolbox-rlevel` (a `return` from a distinct
# nat table does not stop another table's dnat on the same hook — the
# wg-toolbox fanout DNAT'd "off" peers regardless). It is now a named set
# `@rlevel_off` inside `table inet wg-toolbox` itself — the SAME table+chain
# that performs the DNAT — updated via `nft flush set` / `add element`.
# Under DRYRUN those commands are written to RLEVEL_NFT_OUT so we can
# assert on their content without a live nft/kernel.

def test_force_off_updates_rlevel_off_set(sandbox):
    run(sandbox, "force", PK2, "off")
    text = nft_text(sandbox)
    assert "10.99.1.6" in text
    assert "10.99.1.5" not in text
    assert "inet wg-toolbox rlevel_off" in text
    assert "flush set inet wg-toolbox rlevel_off" in text
    assert "add element inet wg-toolbox rlevel_off" in text


def test_force_none_removes_ip_from_rlevel_off_set(sandbox):
    run(sandbox, "force", PK2, "off")
    assert "10.99.1.6" in nft_text(sandbox)
    run(sandbox, "force", PK2, "none")
    text = nft_text(sandbox)
    assert "10.99.1.6" not in text


def test_empty_off_set_yields_flush_only_no_add_element(sandbox):
    run(sandbox, "set-floor", PK1, "active")  # any non-off mutation
    text = nft_text(sandbox)
    assert "flush set inet wg-toolbox rlevel_off" in text
    assert "add element" not in text


# ── validation ─────────────────────────────────────────────────────────────

def test_invalid_mode_rc_nonzero_and_json_untouched(sandbox):
    before = sandbox["rlevel"].exists() and sandbox["rlevel"].read_text()
    r = run(sandbox, "set-floor", PK1, "bogus")
    assert r.returncode != 0
    after = sandbox["rlevel"].exists() and sandbox["rlevel"].read_text()
    assert before == after


def test_invalid_mode_after_prior_state_leaves_it_untouched(sandbox):
    run(sandbox, "set-floor", PK1, "active")
    before = sandbox["rlevel"].read_text()
    r = run(sandbox, "force", PK1, "bogus")
    assert r.returncode != 0
    assert sandbox["rlevel"].read_text() == before


def test_unknown_pubkey_rc_nonzero(sandbox):
    r = run(sandbox, "set-floor", "not-a-real-pubkey", "active")
    assert r.returncode != 0


def test_unknown_pubkey_force_rc_nonzero(sandbox):
    r = run(sandbox, "force", "not-a-real-pubkey", "active")
    assert r.returncode != 0


def test_set_default_does_not_require_pubkey(sandbox):
    r = run(sandbox, "set-default", "passive", "passive")
    assert r.returncode == 0, r.stderr


# ── audit ───────────────────────────────────────────────────────────────────

def test_audit_line_appended(sandbox):
    run(sandbox, "set-floor", PK1, "active")
    lines = sandbox["audit"].read_text().strip().splitlines()
    assert len(lines) == 1
    rec = json.loads(lines[0])
    assert rec["action"] == "set-floor"
    assert rec["pubkey"] == PK1
    assert rec["new"] == "active"
    assert rec["ts"].endswith("Z")


def test_audit_not_appended_on_validation_failure(sandbox):
    run(sandbox, "set-floor", PK1, "bogus")
    assert not sandbox["audit"].exists() or sandbox["audit"].read_text() == ""


def test_audit_accumulates_multiple_lines(sandbox):
    run(sandbox, "set-floor", PK1, "active")
    run(sandbox, "force", PK2, "off")
    lines = sandbox["audit"].read_text().strip().splitlines()
    assert len(lines) == 2
