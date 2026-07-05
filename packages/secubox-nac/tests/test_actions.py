# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: secubox-nac — tests for the allow/deny action endpoints
(#817 Task 5, mac-guard absorption) and the def-converted zone/action
handlers that finish #808 on the action path.

`nft` is never invoked for real: `_nft_add_element` / `_nft_delete_element`
/ `_nft_list_set` are monkeypatched onto an in-memory fake set-membership
dict, and the SQLite store is a fresh `tmp_path` instance per test.
"""


class _FakeCompletedProcess:
    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def _fake_nft(monkeypatch, main):
    """Replace the three nft-touching helpers with an in-memory
    set-membership dict so no test ever shells out to `nft`.

    `ban_client`/`unban_client` build their own raw `nft add/delete
    element ...` argv instead of going through `_nft_add_element` /
    `_nft_delete_element` — `main.subprocess.run` is also intercepted so
    those calls land in the same fake `sets` dict rather than the real
    `nft` binary.
    """
    sets: dict = {}

    def fake_add(set_name, element):
        sets.setdefault(set_name, set()).add(element)
        return True

    def fake_delete(set_name, element):
        sets.get(set_name, set()).discard(element)
        return True

    def fake_list(set_name):
        return sorted(sets.get(set_name, set()))

    def fake_subprocess_run(cmd, **kwargs):
        if isinstance(cmd, list) and cmd[:1] == ["nft"] and "element" in cmd:
            action = cmd[1]
            brace = cmd.index("{")
            set_name = cmd[brace - 1]
            element = cmd[brace + 1]
            if action == "add":
                fake_add(set_name, element)
            elif action == "delete":
                fake_delete(set_name, element)
        return _FakeCompletedProcess()

    monkeypatch.setattr(main, "_nft_add_element", fake_add)
    monkeypatch.setattr(main, "_nft_delete_element", fake_delete)
    monkeypatch.setattr(main, "_nft_list_set", fake_list)
    monkeypatch.setattr(main.subprocess, "run", fake_subprocess_run)
    return sets


def _setup(tmp_path, monkeypatch):
    """Fresh DeviceStore + JSON side files under tmp_path, fake nft."""
    from api.store import DeviceStore
    import api.main as main

    monkeypatch.setattr(main, "DATA_DIR", tmp_path)
    monkeypatch.setattr(main, "HISTORY_FILE", tmp_path / "history.json")
    monkeypatch.setattr(main, "CLIENTS_META_FILE", tmp_path / "clients.json")
    monkeypatch.setattr(main, "ZONE_ASSIGNMENTS_FILE", tmp_path / "zone_assignments.json")
    main.store = DeviceStore(str(tmp_path / "d.db"))
    sets = _fake_nft(monkeypatch, main)
    return main, sets


def test_deny_blocks_and_sets_allow_state(tmp_path, monkeypatch):
    main, sets = _setup(tmp_path, monkeypatch)
    user = {"sub": "tester"}

    result = main.deny("AA:BB:CC:00:00:40", user=user)

    assert result["success"] is True
    assert result["mac"] == "aa:bb:cc:00:00:40"
    assert result["allow_state"] == "deny"
    assert "aa:bb:cc:00:00:40" in sets.get("blocked", set())
    assert "aa:bb:cc:00:00:40" not in sets.get("lan_allowed", set())

    d = main.store.get("aa:bb:cc:00:00:40")
    assert d is not None
    assert d["allow_state"] == "deny"


def test_allow_reverses_deny(tmp_path, monkeypatch):
    main, sets = _setup(tmp_path, monkeypatch)
    user = {"sub": "tester"}

    main.deny("AA:BB:CC:00:00:41", user=user)
    result = main.allow("AA:BB:CC:00:00:41", user=user)

    assert result["success"] is True
    assert result["mac"] == "aa:bb:cc:00:00:41"
    assert result["allow_state"] == "allow"
    assert "aa:bb:cc:00:00:41" not in sets.get("blocked", set())
    assert "aa:bb:cc:00:00:41" in sets.get("lan_allowed", set())

    d = main.store.get("aa:bb:cc:00:00:41")
    assert d is not None
    assert d["allow_state"] == "allow"


def test_allow_then_deny_moves_between_sets(tmp_path, monkeypatch):
    """allow() then deny() on the same MAC must leave it in exactly one
    of the two sets, never both."""
    main, sets = _setup(tmp_path, monkeypatch)
    user = {"sub": "tester"}

    main.allow("AA:BB:CC:00:00:42", user=user)
    assert "aa:bb:cc:00:00:42" in sets.get("lan_allowed", set())

    main.deny("AA:BB:CC:00:00:42", user=user)
    assert "aa:bb:cc:00:00:42" in sets.get("blocked", set())
    assert "aa:bb:cc:00:00:42" not in sets.get("lan_allowed", set())

    d = main.store.get("aa:bb:cc:00:00:42")
    assert d["allow_state"] == "deny"


def test_zones_reads_fake_nft(tmp_path, monkeypatch):
    """`zones` (converted async def -> def, #808) must be callable as a
    plain function and reflect the fake nft set membership."""
    main, sets = _setup(tmp_path, monkeypatch)
    user = {"sub": "tester"}

    main.allow("AA:BB:CC:00:00:43", user=user)  # lands in lan_allowed
    result = main.zones(user=user)

    lan_zone = next(z for z in result["zones"] if z["nft_set"] == "lan_allowed")
    assert "aa:bb:cc:00:00:43" in lan_zone["members"]


def test_add_to_zone_and_approve_client_are_plain_def(tmp_path, monkeypatch):
    """`add_to_zone`/`approve_client` (converted async def -> def, #808)
    must be plain callables (no coroutine) and move the client's zone."""
    import asyncio
    main, sets = _setup(tmp_path, monkeypatch)
    user = {"sub": "tester"}

    result = main.approve_client("AA:BB:CC:00:00:44", zone="lan", user=user)
    assert not asyncio.iscoroutine(result)
    assert result["success"] is True
    assert result["zone"] == "lan"
    assert "aa:bb:cc:00:00:44" in sets.get("lan_allowed", set())


def test_zone_map_builds_from_nft_sets(tmp_path, monkeypatch):
    """#817 whole-branch fix (I3): `_zone_map` resolves each MAC's zone from
    the nft sets (listed once each), preserving `_get_client_zone` semantics
    (nft membership wins, first zone in ZONES order wins on a tie)."""
    main, sets = _setup(tmp_path, monkeypatch)

    main._nft_add_element("lan_allowed", "aa:bb:cc:00:08:01")
    main._nft_add_element("quarantine_zone", "aa:bb:cc:00:08:02")

    zmap = main._zone_map()
    assert zmap["aa:bb:cc:00:08:01"] == "lan"
    assert zmap["aa:bb:cc:00:08:02"] == "quarantine"
    # a MAC in no set is absent from the map (callers default to quarantine)
    assert "aa:bb:cc:00:08:99" not in zmap


def test_clients_uses_batched_zone_map(tmp_path, monkeypatch):
    """#817 whole-branch fix (I3): `/clients` must resolve zones via one
    batched `_zone_map()` — 4 `nft list set` calls (one per zone), NOT one
    per device. With N devices the old path was N×4 subprocesses."""
    main, sets = _setup(tmp_path, monkeypatch)
    user = {"sub": "tester"}

    calls = {"n": 0}
    inner = main._nft_list_set

    def counting(set_name):
        calls["n"] += 1
        return inner(set_name)

    monkeypatch.setattr(main, "_nft_list_set", counting)

    for i in range(6):
        main.store.upsert({
            "mac": f"aa:bb:cc:00:09:0{i}", "ip": f"10.0.0.{i}",
            "last_seen": 1, "source": "arp",
        })

    main.clients(user=user)
    # exactly one list per zone, independent of the 6 devices
    assert calls["n"] == len(main.ZONES)


def test_ban_client_and_unban_client_are_plain_def(tmp_path, monkeypatch):
    """`ban_client` (converted async def -> def, #808) fires the webhook
    via `_fire_webhook_sync` instead of `await`, and must not raise even
    with no main loop registered (module-level default is None)."""
    import asyncio
    main, sets = _setup(tmp_path, monkeypatch)
    monkeypatch.setattr(main, "_main_loop", None)
    user = {"sub": "tester"}

    result = main.ban_client("AA:BB:CC:00:00:45", user=user)
    assert not asyncio.iscoroutine(result)
    assert result["status"] == "banned"
    assert "aa:bb:cc:00:00:45" in sets.get("blocked", set())

    result2 = main.unban_client("AA:BB:CC:00:00:45", user=user)
    assert result2["status"] == "quarantine"
    assert "aa:bb:cc:00:00:45" not in sets.get("blocked", set())
