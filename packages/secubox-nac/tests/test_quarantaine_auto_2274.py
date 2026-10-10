# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2274 : quarantaine automatique d'un appareil du LAN dont actord publie une mesure QUARANTINE — par le NAC, dans sa zone de quarantaine existante."""
import json
import os
import socket
import threading

import pytest

from api.quarantaine_auto import QuarantaineAuto, choisir, lire_mesures

NOW = 1_800_000_000


def mesure(ip="192.168.1.50", niveau="QUARANTINE", depuis=NOW - 60, lan=True, actor="ACT-9", expire=None):
    return {"actor": actor, "ips": [ip], "niveau": niveau, "depuis": depuis, "expire": expire or NOW + 3600, "lan": lan, "raison": "niveau BLOCK sur un appareil du LAN",
            "risque": 82, "confiance": 85, "capteurs": ["dns", "dpi"]}


def appareil(mac="aa:bb:cc:00:00:50", ip="192.168.1.50", **kw):
    return {"mac": mac, "ip": ip, "hostname": "cam-salon", "last_seen": NOW - 30, "is_router": 0, "is_secubox": 0, "is_openwrt": 0, **kw}


def par_ip(*apps):
    return {a["ip"]: a for a in apps}


def test_un_appareil_du_lan_sous_mesure_quarantine_est_isole():
    r = choisir([mesure()], par_ip(appareil()), set(), NOW, lambda mac: "lan")
    assert [(x["mac"], x["actor"]) for x in r] == [("aa:bb:cc:00:00:50", "ACT-9")] and r[0]["cle"] == "aa:bb:cc:00:00:50|%d" % (NOW - 60)


@pytest.mark.parametrize("m", [mesure(niveau="TARPIT"), mesure(niveau="DENY"), mesure(lan=False), mesure(expire=NOW - 1), mesure(ip="203.0.113.5")])
def test_seule_une_mesure_quarantine_active_du_lan_isole(m):
    assert choisir([m], par_ip(appareil(), appareil(mac="aa:bb:cc:00:00:51", ip="203.0.113.5")), set(), NOW, lambda mac: "lan") == []


def test_un_appareil_inconnu_ou_absent_depuis_longtemps_n_est_pas_isole():
    assert choisir([mesure()], {}, set(), NOW, lambda mac: "lan") == []
    vieux = appareil(last_seen=NOW - 4 * 3600)
    assert choisir([mesure()], par_ip(vieux), set(), NOW, lambda mac: "lan") == []         # l'adresse a pu changer de main


@pytest.mark.parametrize("kw", [{"is_router": 1}, {"is_secubox": 1}, {"is_openwrt": 1}])
def test_jamais_la_box_un_routeur_ou_un_equipement_du_parc(kw):
    assert choisir([mesure()], par_ip(appareil(**kw)), set(), NOW, lambda mac: "lan") == []


def test_un_appareil_deja_en_quarantaine_est_laisse_tel_quel():
    assert choisir([mesure()], par_ip(appareil()), set(), NOW, lambda mac: "quarantine") == []


def test_les_macs_protegees_ne_sont_jamais_isolees():
    r = choisir([mesure()], par_ip(appareil()), set(), NOW, lambda mac: "lan", protegees={"aa:bb:cc:00:00:50"})
    assert r == []


def test_une_mesure_ne_reisole_pas_un_appareil_libere_par_l_administrateur():
    cle = "aa:bb:cc:00:00:50|%d" % (NOW - 60)
    assert choisir([mesure()], par_ip(appareil()), {cle}, NOW, lambda mac: "lan") == []
    # une NOUVELLE mesure (autre départ) peut isoler à nouveau
    assert len(choisir([mesure(depuis=NOW - 10)], par_ip(appareil()), {cle}, NOW, lambda mac: "lan")) == 1


class Banc:
    def __init__(self, mode="auto", mesures=None):
        self.isoles, self.mode, self.mesures = [], mode, mesures if mesures is not None else [mesure()]
        self.q = QuarantaineAuto(lambda: self.mode, lire=lambda: self.mesures, isoler=self._iso, zone_de=lambda mac: "lan", trouver=lambda: par_ip(appareil()), now=lambda: NOW)

    def _iso(self, mac, ip, actor, raison):
        self.isoles.append((mac, ip, actor))


def test_en_auto_l_appareil_est_isole_une_seule_fois():
    b = Banc()
    b.q.tick()
    b.q.tick()
    assert b.isoles == [("aa:bb:cc:00:00:50", "192.168.1.50", "ACT-9")]


def test_en_propose_ou_off_rien_n_est_isole_mais_le_candidat_est_visible():
    for mode in ("propose", "off"):
        b = Banc(mode)
        b.q.tick()
        assert b.isoles == []
    b = Banc("propose")
    b.q.tick()
    assert [c["mac"] for c in b.q.candidats] == ["aa:bb:cc:00:00:50"] and b.q.candidats[0]["decision"] == "a_isoler"


def test_une_panne_d_actord_n_isole_rien_et_ne_casse_pas():
    b = Banc()
    b.q.lire = lambda: (_ for _ in ()).throw(OSError("actord arrêté"))
    b.q.tick()
    assert b.isoles == []


def test_un_echec_d_isolement_reessaie_au_tour_suivant():
    b = Banc()
    essais = []

    def iso(mac, ip, actor, raison):
        essais.append(mac)
        if len(essais) == 1:
            raise RuntimeError("nft indisponible")
        b.isoles.append(mac)
    b.q.isoler = iso
    b.q.tick()
    b.q.tick()
    assert b.isoles == ["aa:bb:cc:00:00:50"] and len(essais) == 2


def test_lire_mesures_parle_a_la_socket_d_actord_en_vue_complete(tmp_path):
    chemin = str(tmp_path / "actor.sock")
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(chemin)
    srv.listen(1)
    vu = {}

    def servir():
        c, _ = srv.accept()
        vu["req"] = c.recv(4096).decode()
        corps = json.dumps({"mesures": [mesure()], "par_niveau": {}}).encode()
        c.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n" % len(corps) + corps)
        c.close()
    t = threading.Thread(target=servir)
    t.start()
    ms = lire_mesures(chemin)
    t.join(5)
    srv.close()
    assert len(ms) == 1 and ms[0]["niveau"] == "QUARANTINE"
    assert "GET /api/v1/actor/mesures" in vu["req"] and "X-Sbx-Vue: complete" in vu["req"]


def test_lire_mesures_sans_socket_rend_une_liste_vide(tmp_path):
    assert lire_mesures(str(tmp_path / "absente.sock")) == []


# ── Intégration : collecteur et API ──────────────────────────────────────────────────────────────────────────────────────────────────────────
def test_le_collecteur_appelle_la_quarantaine_a_chaque_cycle_et_survit_a_ses_pannes(tmp_path, monkeypatch):
    import api.collector as C
    from api.collector import Collector
    from api.store import DeviceStore
    appels = []

    class Q:
        def tick(self):
            appels.append(1)
            raise RuntimeError("panne")
    monkeypatch.setattr(C, "discover", lambda **k: [])
    col = Collector(DeviceStore(str(tmp_path / "d.db")), oui_map={}, interval=0, quarantaine_auto=Q())
    col.cycle_once()
    col.cycle_once()
    assert len(appels) == 2                        # un échec n'arrête ni le cycle ni les suivants


def test_l_isolement_automatique_utilise_la_zone_de_quarantaine_du_nac_et_laisse_une_trace(tmp_path, monkeypatch):
    from tests.test_endpoints import _setup
    main, sets = _setup(tmp_path, monkeypatch)
    main.store.upsert({"mac": "aa:bb:cc:00:00:50", "ip": "192.168.1.50", "hostname": "cam", "last_seen": 100, "source": "arp"})
    posees = []
    monkeypatch.setattr(main, "_set_client_zone", lambda mac, zone: posees.append((mac, zone)))
    main._isoler_auto("aa:bb:cc:00:00:50", "192.168.1.50", "ACT-9", "niveau BLOCK sur un appareil du LAN")
    assert posees == [("aa:bb:cc:00:00:50", "quarantine")]
    hist = main.store.history("aa:bb:cc:00:00:50", limit=5)
    assert any(h["event"] == "quarantine_auto" and "ACT-9" in h.get("detail", "") for h in hist)


def test_le_mode_vient_de_la_config_et_vaut_auto_par_defaut(tmp_path, monkeypatch):
    from tests.test_endpoints import _setup
    main, _ = _setup(tmp_path, monkeypatch)
    monkeypatch.setattr(main, "get_config", lambda *_a, **_k: {})
    assert main._mode_quarantaine_auto() == "auto"
    monkeypatch.setattr(main, "get_config", lambda *_a, **_k: {"quarantaine_auto": "off"})
    assert main._mode_quarantaine_auto() == "off"
    monkeypatch.setattr(main, "get_config", lambda *_a, **_k: {"quarantaine_auto": "n'importe quoi"})
    assert main._mode_quarantaine_auto() == "off"      # une valeur inconnue n'isole rien


def test_la_route_de_lecture_montre_le_mode_et_les_candidats(tmp_path, monkeypatch):
    from tests.test_endpoints import USER, _setup
    main, _ = _setup(tmp_path, monkeypatch)
    monkeypatch.setattr(main, "get_config", lambda *_a, **_k: {})
    r = main.quarantaine_auto_etat(user=USER)
    assert r["mode"] == "auto" and r["candidats"] == []
