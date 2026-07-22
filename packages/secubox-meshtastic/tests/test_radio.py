# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>


def test_mock_radio_dispatches_events():
    from api.radio import MockRadio
    r = MockRadio(); seen = []
    r.on("receive", lambda pkt: seen.append(pkt))
    r.emit("receive", {"from": 1})
    assert seen == [{"from": 1}]


def test_mock_radio_records_sent_text():
    from api.radio import MockRadio
    r = MockRadio(); r.send_text("hello", channel=2)
    assert r.sent == [("hello", 2)]


def test_open_serial_absent_device_returns_none(tmp_path):
    from api.radio import open_serial
    assert open_serial(str(tmp_path / "no-such-tty")) is None
