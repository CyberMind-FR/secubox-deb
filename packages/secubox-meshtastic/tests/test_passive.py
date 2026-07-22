# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""SecuBox-Deb :: meshtastic — tests for passive capture (packet log + census + stats)."""
import json
from api.model import Packet


def _p(fr="!00000001", ch=0, port="TEXT_MESSAGE_APP", dec=None):
    return Packet(fr, "!ffffffff", ch, port, dec, -90, 5.0, 3, 0.0)


def test_record_appends_metadata_line(tmp_path):
    from api.passive import PassiveCapture
    cap = PassiveCapture(tmp_path / "packets.jsonl")
    cap.record(_p(dec={"text": "secret"}), now=1.0, decrypted=False)
    line = json.loads((tmp_path / "packets.jsonl").read_text().strip())
    assert line["from"] == "!00000001" and line["portnum"] == "TEXT_MESSAGE_APP"
    assert "text" not in json.dumps(line)     # payload withheld when not decrypted


def test_record_includes_payload_when_decrypted(tmp_path):
    from api.passive import PassiveCapture
    cap = PassiveCapture(tmp_path / "packets.jsonl")
    cap.record(_p(dec={"text": "hi"}), now=1.0, decrypted=True)
    assert "hi" in (tmp_path / "packets.jsonl").read_text()


def test_census_tracks_all_heard_nodes(tmp_path):
    from api.passive import PassiveCapture
    cap = PassiveCapture(tmp_path / "p.jsonl")
    cap.record(_p(fr="!00000001"), now=1.0, decrypted=True)
    cap.record(_p(fr="!00000002"), now=2.0, decrypted=True)
    cap.record(_p(fr="!00000001"), now=3.0, decrypted=True)
    ids = {c["id"]: c for c in cap.census()}
    assert set(ids) == {"!00000001", "!00000002"}
    assert ids["!00000001"]["first_heard"] == 1.0 and ids["!00000001"]["last_heard"] == 3.0


def test_channel_stats_count_per_channel(tmp_path):
    from api.passive import PassiveCapture
    cap = PassiveCapture(tmp_path / "p.jsonl")
    cap.record(_p(ch=0), 1.0, True); cap.record(_p(ch=1), 2.0, True); cap.record(_p(ch=1), 3.0, True)
    assert cap.channel_stats()[1]["packets"] == 2
