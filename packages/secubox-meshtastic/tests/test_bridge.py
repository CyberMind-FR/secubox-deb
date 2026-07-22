# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
from api.config import Config, ChannelCfg, BrokerCfg
from api.model import Packet

class FakeMqtt:
    def __init__(self): self.pub=[]; self.conn=None
    def connect(self, host, port): self.conn=(host,port)
    def publish(self, topic, payload): self.pub.append((topic, payload))
    def disconnect(self): pass

def _cfg(grid, on=False):
    return Config(region="EU_868", channels=[ChannelCfg("fam", tuple(grid), "psk")],
                  shared_grid=BrokerCfg("10.10.0.1:1883"),
                  on_grid=BrokerCfg("mqtt.x.org:8883", on))

def _p(): return Packet("!1","!ffffffff",0,"TEXT_MESSAGE_APP",{"text":"hi"},-90,5.0,3,1.0)

def test_shared_channel_publishes_to_private_broker_only():
    from api.bridge import Bridge
    made={}
    def fac(key): made[key]=FakeMqtt(); return made[key]
    b=Bridge(_cfg(["off","shared"]), fac); b.start(); b.publish("fam", _p())
    assert made["shared"].conn==("10.10.0.1",1883)
    assert "on" not in made and len(made["shared"].pub)==1
    topic,_=made["shared"].pub[0]; assert topic.startswith("msh/EU_868/2/e/fam/")

def test_offgrid_channel_publishes_nowhere():
    from api.bridge import Bridge
    made={}
    b=Bridge(_cfg(["off"]), lambda k: made.setdefault(k, FakeMqtt())); b.start(); b.publish("fam", _p())
    assert all(not m.pub for m in made.values())

def test_on_channel_publishes_only_when_enabled():
    from api.bridge import Bridge
    made={}
    b=Bridge(_cfg(["off","on"], on=True), lambda k: made.setdefault(k, FakeMqtt())); b.start(); b.publish("fam", _p())
    assert "on" in made and made["on"].conn==("mqtt.x.org",8883)


class RefusingMqtt(FakeMqtt):
    def connect(self, host, port):
        raise ConnectionRefusedError("broker down")


def test_start_tolerates_unreachable_broker():
    # A configured broker that is DOWN at startup must not crash Bridge.start()
    # (the daemon's #897 deploy bug: opt-in mosquitto not running).
    from api.bridge import Bridge
    b = Bridge(_cfg(["off", "shared"]), lambda k: RefusingMqtt())
    b.start()                          # must not raise
    b.publish("fam", _p())             # no client registered → no-op, no crash
