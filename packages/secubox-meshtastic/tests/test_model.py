# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""SecuBox-Deb :: meshtastic — tests for mesh state model + packet parser."""


def _pkt(**kw):
    base = {"from": 0x11, "to": 0xffffffff, "channel": 0,
            "decoded": {"portnum": "TEXT_MESSAGE_APP", "text": "hi"},
            "rxRssi": -95, "rxSnr": 6.5, "hopLimit": 3}
    base.update(kw)
    return base


def test_parse_packet_fields():
    from api.model import parse_packet
    p = parse_packet(_pkt())
    assert p.from_id == "!00000011" and p.portnum == "TEXT_MESSAGE_APP"
    assert p.rssi == -95 and p.snr == 6.5 and p.decoded["text"] == "hi"


def test_meshstate_census_updates_last_heard():
    from api.model import MeshState, parse_packet
    st = MeshState()
    st.apply_packet(parse_packet(_pkt()), now=100.0)
    st.apply_packet(parse_packet(_pkt()), now=200.0)
    node = st.to_dict()["nodes"][0]
    assert node["id"] == "!00000011" and node["first_heard"] == 100.0 and node["last_heard"] == 200.0


def test_text_message_lands_in_channel_log():
    from api.model import MeshState, parse_packet
    st = MeshState()
    st.apply_packet(parse_packet(_pkt(channel=1)), now=1.0)
    assert st.to_dict()["messages_by_channel"]["1"][0]["text"] == "hi"


def test_nodeinfo_sets_names_and_role():
    from api.model import MeshState
    st = MeshState()
    st.apply_nodeinfo({"num": 0x22, "user": {"shortName": "AB", "longName": "Alpha", "role": "CLIENT_MUTE"}}, now=5.0)
    n = st.to_dict()["nodes"][0]
    assert n["id"] == "!00000022" and n["short"] == "AB" and n["role"] == "CLIENT_MUTE"
