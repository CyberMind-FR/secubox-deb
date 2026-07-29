# SPDX-License-Identifier: LicenseRef-CMSD-1.0
from api.config import Config, ChannelCfg, BrokerCfg
from api.cache import StateCache
from api.passive import PassiveCapture
from api.radio import MockRadio


class FakeMqtt:
    def __init__(self): self.pub=[]
    def connect(self,h,p): pass
    def publish(self,t,pl): self.pub.append((t,pl))
    def disconnect(self): pass

def _engine(tmp_path, grid=("off","shared"), mode="both"):
    from api.bridge import Bridge
    from api.daemon import Engine
    cfg = Config(mode=mode, region="EU_868", channels=[ChannelCfg("fam", grid, "fam-psk")],
                 shared_grid=BrokerCfg("10.10.0.1:1883"))
    made={}
    br = Bridge(cfg, lambda k: made.setdefault(k, FakeMqtt())); br.start()
    cap = PassiveCapture(tmp_path/"p.jsonl")
    eng = Engine(cfg, MockRadio(), StateCache(tmp_path/"s.json"), cap, br, clock=lambda:42.0)
    return eng, cap, made

def test_on_receive_updates_cache_and_bridges(tmp_path):
    eng, cap, made = _engine(tmp_path)
    eng.on_receive({"from":0x1,"to":0xffffffff,"channel":0,
                    "decoded":{"portnum":"TEXT_MESSAGE_APP","text":"hi"}})
    snap = eng.snapshot()
    assert snap["nodes"][0]["id"] == "!00000001"
    assert made["shared"].pub                       # bridged to private broker
    assert cap.census()                             # passive recorded (mode both)

def test_active_only_mode_skips_passive(tmp_path):
    eng, cap, made = _engine(tmp_path, mode="active-node")
    eng.on_receive({"from":0x1,"channel":0,"decoded":{"portnum":"NODEINFO_APP"}})
    assert cap.census() == []

def test_snapshot_reports_radio_present(tmp_path):
    eng,_,_ = _engine(tmp_path)
    assert eng.snapshot()["radio"] == "present"

def test_seed_from_radio_populates_local_node(tmp_path):
    from api.bridge import Bridge
    from api.daemon import Engine
    cfg = Config(mode="both", region="EU_868", channels=[ChannelCfg("fam", ("off",), "fam-psk")],
                 shared_grid=BrokerCfg("10.10.0.1:1883"))
    br = Bridge(cfg, lambda k: FakeMqtt()); br.start()
    cap = PassiveCapture(tmp_path/"p.jsonl")
    radio = MockRadio(node_db=[
        {"num": 0x11, "user": {"shortName": "ME", "longName": "My Node", "role": "CLIENT"}, "is_self": True},
        {"num": 0x22, "user": {"shortName": "PE", "longName": "Peer"},
         "position": {"latitude": 45.1, "longitude": 6.2}},
    ], my_num=0x11)
    eng = Engine(cfg, radio, StateCache(tmp_path/"s.json"), cap, br, clock=lambda: 42.0)
    eng.seed_from_radio(radio)
    ids = {n["id"]: n for n in eng.snapshot()["nodes"]}
    assert eng.my_num == 0x11
    assert ids["!00000011"]["is_self"] is True
    assert ids["!00000011"]["long"] == "My Node"
    assert tuple(ids["!00000022"]["pos"]) == (45.1, 6.2)

def test_record_sent_appears_in_messages(tmp_path):
    eng, _, _ = _engine(tmp_path)
    eng.my_num = 0x11
    eng.record_sent(0, "hello mesh")
    msgs = eng.snapshot()["messages_by_channel"]["0"]
    assert msgs[-1]["text"] == "hello mesh"
    assert msgs[-1]["outbound"] is True
    assert msgs[-1]["from"] == "!00000011"

def test_on_node_updates_live(tmp_path):
    eng, _, _ = _engine(tmp_path)
    eng.on_node({"num": 0x33, "user": {"shortName": "LV", "longName": "Live"}})
    assert "!00000033" in {n["id"] for n in eng.snapshot()["nodes"]}
