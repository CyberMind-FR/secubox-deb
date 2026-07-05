# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: secubox-nac — tests for `presence.alerts.evaluate`/
`load_config` and `presence.mailer.send_alert` (Project B, Task 6, #820).
"""

import json


def _wan_presence(store, ip, client_type, geo_cc=None, last_seen=1_000_000):
    store.upsert({
        "id": f"wan:{ip}",
        "plane": "wan",
        "identity": ip,
        "client_type": client_type,
        "geo_cc": geo_cc,
        "last_seen": last_seen,
    })


def _wg_presence(store, mac, risk_level, plane="wg", last_seen=1_000_000):
    store.upsert({
        "id": f"{plane}:{mac}",
        "plane": plane,
        "identity": mac,
        "device_mac": mac,
        "client_type": "peer",
        "last_seen": last_seen,
        "extra": json.dumps({"risk_level": risk_level}),
    })


class _RecordingMailer:
    def __init__(self, result=True):
        self.result = result
        self.calls = []

    def __call__(self, subject, body, *, to):
        self.calls.append((subject, body, to))
        return self.result


class _RaisingMailer:
    def __call__(self, subject, body, *, to):
        raise RuntimeError("sendmail exploded")


def test_no_config_no_alerts(tmp_path):
    from api.presence.store import PresenceStore
    from api.presence.alerts import evaluate

    store = PresenceStore(str(tmp_path / "devices.db"))
    _wan_presence(store, "1.2.3.4", "bot")
    mailer = _RecordingMailer()

    fired = evaluate(store, None, mailer, now=1_000_000, state={})

    assert fired == []
    assert mailer.calls == []
    assert store.alerts() == []


def test_bot_surge_warns_and_emails_once(tmp_path):
    from api.presence.store import PresenceStore
    from api.presence.alerts import evaluate

    store = PresenceStore(str(tmp_path / "devices.db"))
    for i in range(3):
        _wan_presence(store, f"10.0.0.{i}", "bot", last_seen=1_000_000)

    config = {
        "recipient": "admin@example.com",
        "window_seconds": 3600,
        "wan": {"bot_surge": 2},
    }
    mailer = _RecordingMailer()
    state: dict = {}

    fired = evaluate(store, config, mailer, now=1_000_000, state=state)

    assert len(fired) == 1
    assert fired[0]["tier"] == "warn"
    assert fired[0]["plane"] == "wan"
    assert len(mailer.calls) == 1
    assert mailer.calls[0][2] == "admin@example.com"

    recorded = store.alerts()
    assert len(recorded) == 1
    assert recorded[0]["tier"] == "warn"
    assert recorded[0]["plane"] == "wan"

    # Second evaluate, still within the same window -> alert recorded
    # again (reality still holds) but NOT re-emailed (dedup).
    fired2 = evaluate(store, config, mailer, now=1_000_100, state=state)

    assert len(fired2) == 1
    assert len(mailer.calls) == 1  # still just the one send
    assert len(store.alerts()) == 2  # recorded again


def test_bot_surge_reemails_after_window(tmp_path):
    from api.presence.store import PresenceStore
    from api.presence.alerts import evaluate

    store = PresenceStore(str(tmp_path / "devices.db"))
    for i in range(3):
        _wan_presence(store, f"10.0.1.{i}", "bot", last_seen=1_000_000)

    config = {
        "recipient": "admin@example.com",
        "window_seconds": 100,
        "wan": {"bot_surge": 2},
    }
    mailer = _RecordingMailer()
    state: dict = {}

    evaluate(store, config, mailer, now=1_000_000, state=state)
    assert len(mailer.calls) == 1

    # Bots are still being seen (fresh last_seen) at a time past the dedup
    # window -> the condition still fires AND emails again.
    for i in range(3):
        _wan_presence(store, f"10.0.1.{i}", "bot", last_seen=1_000_200)
    evaluate(store, config, mailer, now=1_000_200, state=state)
    assert len(mailer.calls) == 2


def test_new_country_notice(tmp_path):
    from api.presence.store import PresenceStore
    from api.presence.alerts import evaluate

    store = PresenceStore(str(tmp_path / "devices.db"))
    _wan_presence(store, "1.2.3.4", "browser", geo_cc="FR")

    config = {
        "recipient": "admin@example.com",
        "window_seconds": 3600,
        "wan": {"new_country": True},
    }
    mailer = _RecordingMailer()
    state: dict = {}

    fired = evaluate(store, config, mailer, now=1_000_000, state=state)

    assert len(fired) == 1
    assert fired[0]["tier"] == "notice"
    assert fired[0]["plane"] == "wan"
    assert len(mailer.calls) == 1

    # Same country again -> not re-alerted (seen_countries), even in a
    # later window.
    fired2 = evaluate(store, config, mailer, now=1_010_000, state=state)

    assert fired2 == []
    assert len(mailer.calls) == 1
    # Only the first pass's alert is on record.
    assert len(store.alerts()) == 1


def test_rogue_router_warn(tmp_path):
    from api.presence.store import PresenceStore
    from api.presence.alerts import evaluate

    store = PresenceStore(str(tmp_path / "devices.db"))
    _wg_presence(store, "aa:bb:cc:00:00:09", risk_level="high")
    _wg_presence(store, "aa:bb:cc:00:00:0a", risk_level="low")

    config = {
        "recipient": "admin@example.com",
        "window_seconds": 3600,
        "wg": {"rogue_router": True},
    }
    mailer = _RecordingMailer()

    fired = evaluate(store, config, mailer, now=1_000_000, state={})

    assert len(fired) == 1
    assert fired[0]["tier"] == "warn"
    assert fired[0]["plane"] == "wg"
    assert "aa:bb:cc:00:00:09" in fired[0]["detail"]
    assert len(mailer.calls) == 1


def test_mailer_failure_still_records(tmp_path):
    from api.presence.store import PresenceStore
    from api.presence.alerts import evaluate

    store = PresenceStore(str(tmp_path / "devices.db"))
    for i in range(3):
        _wan_presence(store, f"10.0.2.{i}", "bot", last_seen=1_000_000)

    config = {
        "recipient": "admin@example.com",
        "window_seconds": 3600,
        "wan": {"bot_surge": 2},
    }

    # A mailer that returns False.
    fired = evaluate(store, config, _RecordingMailer(result=False), now=1_000_000, state={})
    assert len(fired) == 1
    assert len(store.alerts()) == 1

    # A mailer that raises outright — evaluate() must not raise either.
    store2 = PresenceStore(str(tmp_path / "devices2.db"))
    for i in range(3):
        _wan_presence(store2, f"10.0.3.{i}", "bot", last_seen=1_000_000)
    fired2 = evaluate(store2, config, _RaisingMailer(), now=1_000_000, state={})
    assert len(fired2) == 1
    assert len(store2.alerts()) == 1


def test_no_recipient_records_but_does_not_email(tmp_path):
    from api.presence.store import PresenceStore
    from api.presence.alerts import evaluate

    store = PresenceStore(str(tmp_path / "devices.db"))
    for i in range(3):
        _wan_presence(store, f"10.0.4.{i}", "bot", last_seen=1_000_000)

    config = {"window_seconds": 3600, "wan": {"bot_surge": 2}}
    mailer = _RecordingMailer()

    fired = evaluate(store, config, mailer, now=1_000_000, state={})

    assert len(fired) == 1
    assert mailer.calls == []
    assert len(store.alerts()) == 1


def test_load_config_missing_file_returns_none(tmp_path):
    from api.presence.alerts import load_config

    assert load_config(str(tmp_path / "does-not-exist.toml")) is None


def test_load_config_malformed_returns_none(tmp_path):
    from api.presence.alerts import load_config

    bad = tmp_path / "presence-alerts.toml"
    bad.write_text("this is not [ valid toml")

    assert load_config(str(bad)) is None


def test_load_config_parses_shape(tmp_path):
    from api.presence.alerts import load_config

    cfg_path = tmp_path / "presence-alerts.toml"
    cfg_path.write_text(
        'recipient = "admin@example.com"\n'
        "window_seconds = 3600\n"
        "\n"
        "[wan]\n"
        "bot_surge = 50\n"
        "new_country = true\n"
        "\n"
        "[wg]\n"
        "rogue_router = true\n"
    )

    config = load_config(str(cfg_path))

    assert config["recipient"] == "admin@example.com"
    assert config["window_seconds"] == 3600
    assert config["wan"]["bot_surge"] == 50
    assert config["wan"]["new_country"] is True
    assert config["wg"]["rogue_router"] is True


# --- mailer ---------------------------------------------------------------


class _FakeCompletedProcess:
    def __init__(self, returncode):
        self.returncode = returncode


def test_send_alert_success():
    from api.presence.mailer import send_alert

    calls = []

    def fake_runner(cmd, *, input, capture_output, timeout):
        calls.append((cmd, input, timeout))
        return _FakeCompletedProcess(0)

    ok = send_alert(
        "subject", "body", to="admin@example.com", runner=fake_runner
    )

    assert ok is True
    assert len(calls) == 1
    cmd, input_bytes, timeout = calls[0]
    assert cmd == ["/usr/sbin/sendmail", "-t", "-oi"]
    assert b"To: admin@example.com" in input_bytes
    assert b"Subject: subject" in input_bytes
    assert timeout == 10


def test_send_alert_nonzero_rc_is_false():
    from api.presence.mailer import send_alert

    def fake_runner(cmd, *, input, capture_output, timeout):
        return _FakeCompletedProcess(1)

    ok = send_alert("s", "b", to="admin@example.com", runner=fake_runner)

    assert ok is False


def test_send_alert_raising_runner_is_false_not_raised():
    from api.presence.mailer import send_alert

    def raising_runner(cmd, *, input, capture_output, timeout):
        raise FileNotFoundError("no sendmail binary")

    ok = send_alert("s", "b", to="admin@example.com", runner=raising_runner)

    assert ok is False


def test_send_alert_no_recipient_is_false():
    from api.presence.mailer import send_alert

    ok = send_alert("s", "b", to="", runner=lambda *a, **k: _FakeCompletedProcess(0))

    assert ok is False
