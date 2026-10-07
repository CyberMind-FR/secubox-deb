# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""Autoconfiguration de la Freebox : comparer l'état à la cible, ne corriger que l'écart, DMZ à part et doublement confirmée."""
import json

import pytest
from fastapi.testclient import TestClient

from api import client as c
from api import main
from tests.test_pare_feu_ecriture import _pret, ok

IP = "192.168.1.200"


MAC = "F0:AD:4E:27:88:9B"
HOTES = [{"l2ident": {"id": MAC, "type": "mac_address"}, "l3connectivities": [{"addr": IP, "af": "ipv4"}, {"addr": "fe80::1", "af": "ipv6"}]},
         {"l2ident": {"id": "AA:BB:CC:DD:EE:FF", "type": "mac_address"}, "l3connectivities": [{"addr": "192.168.1.9", "af": "ipv4"}]}]


def _lectures(fw=True, dns=(IP, "", "", "", "", ""), dmz=(True, IP), bail=IP):
    # ordre des lectures : pare-feu, DNS, DMZ, hôtes (adresse MAC de la box), baux statiques
    baux = [{"mac": MAC, "ip": bail, "id": MAC}] if bail else []
    return [ok({"ipv6_firewall": fw}), ok({"dns": list(dns)}), ok({"enabled": dmz[0], "ip": dmz[1]}), ok(HOTES), ok(baux)]


def test_tout_conforme_ne_propose_rien(tmp_path):
    svc, f, _ = _pret(tmp_path, _lectures())
    r = svc.autoconfig(IP)
    assert [i["id"] for i in r["items"]] == ["pare_feu_ipv6", "dns", "ip_fixe", "dmz"]
    assert all(i["conforme"] for i in r["items"]) and r["ecarts"] == 0


def test_les_ecarts_sont_decrits_avec_actuel_et_cible(tmp_path):
    svc, f, _ = _pret(tmp_path, _lectures(fw=False, dns=("8.8.8.8", "", "", "", "", ""), dmz=(False, "")))
    r = svc.autoconfig(IP)
    par = {i["id"]: i for i in r["items"]}
    assert par["pare_feu_ipv6"]["actuel"] is False and par["pare_feu_ipv6"]["cible"] is True
    assert par["dns"]["actuel"] == ["8.8.8.8"] and par["dns"]["cible"] == [IP]
    assert par["dmz"]["cible"] == {"enabled": True, "ip": IP} and par["dmz"]["sensible"] is True
    assert r["ecarts"] == 3


def test_appliquer_ne_touche_que_les_elements_demandes_et_relit(tmp_path):
    avant = ok({"dns": ["8.8.8.8", "", "", "", "", ""]})
    apres = ok({"dns": [IP, "", "", "", "", ""]})
    svc, f, journal = _pret(tmp_path, [avant, ok({}), apres])      # relecture avant, écriture, relecture après
    r = svc.appliquer_autoconfig(["dns"], IP)
    puts = [a for a in f.appels if a[0] == "PUT"]
    assert len(puts) == 1 and puts[0][1].endswith("dhcp/config/") and json.loads(puts[0][3])["dns"][0] == IP
    assert r["appliques"] == ["dns"] and journal and journal[0]["action"] == "autoconfig_dns"


def test_un_element_deja_conforme_n_est_pas_reecrit(tmp_path):
    svc, f, journal = _pret(tmp_path, [ok({"dns": [IP, "", "", "", "", ""]})])
    r = svc.appliquer_autoconfig(["dns"], IP)
    assert r["appliques"] == [] and not [a for a in f.appels if a[0] == "PUT"]


def test_la_dmz_confirmee_s_ecrit_vers_la_box(tmp_path):
    svc, f, journal = _pret(tmp_path, [ok({"enabled": False, "ip": ""}), ok({}), ok({"enabled": True, "ip": IP})])
    r = svc.appliquer_autoconfig(["dmz"], IP, confirme_dmz=True)
    puts = [a for a in f.appels if a[0] == "PUT"]
    assert json.loads(puts[0][3]) == {"enabled": True, "ip": IP} and puts[0][1].endswith("fw/dmz/") and r["appliques"] == ["dmz"]


def test_une_relecture_qui_ne_confirme_pas_est_une_erreur(tmp_path):
    svc, f, _ = _pret(tmp_path, [ok({"dns": ["8.8.8.8", "", "", "", "", ""]}), ok({}), ok({"dns": ["8.8.8.8", "", "", "", "", ""]})])
    with pytest.raises(c.ErreurFreebox):
        svc.appliquer_autoconfig(["dns"], IP)


def test_la_dmz_exige_une_confirmation_dediee(tmp_path):
    svc, f, _ = _pret(tmp_path, [])
    with pytest.raises(ValueError):
        svc.appliquer_autoconfig(["dmz"], IP, confirme_dmz=False)
    assert not [a for a in f.appels if a[0] == "PUT"]


def test_sans_droit_settings_rien_n_est_ecrit(tmp_path):
    svc, f, _ = _pret(tmp_path, [], droits={"settings": False})
    with pytest.raises(c.DroitManquant):
        svc.appliquer_autoconfig(["pare_feu_ipv6"], IP)
    assert not [a for a in f.appels if a[0] == "PUT"]


def test_identifiant_inconnu_refuse(tmp_path):
    svc, f, _ = _pret(tmp_path, [])
    with pytest.raises(ValueError):
        svc.appliquer_autoconfig(["wifi"], IP)


def test_routes_garde_et_confirmation():
    t = TestClient(main.app)
    assert t.post("/autoconfig", json={"ids": ["dns"], "confirme": True}).status_code in (401, 403)
    from secubox_core import auth
    main.app.dependency_overrides[auth.require_jwt] = lambda: {"sub": "a"}
    try:
        assert t.post("/autoconfig", json={"ids": ["dns"]}).status_code == 400
        assert t.post("/autoconfig", json={"confirme": True}).status_code == 400
        assert t.post("/autoconfig", json={"ids": ["dmz"], "confirme": True}).status_code == 400   # DMZ : confirme_dmz requis
    finally:
        main.app.dependency_overrides.clear()


def test_le_panneau_a_l_onglet_autoconfig_avec_confirmation_dmz():
    from pathlib import Path
    html = (Path(__file__).resolve().parents[1] / "www" / "freebox" / "index.html").read_text()
    assert 'data-tab="autoconfig"' in html and 'id="t-autoconfig"' in html and "function appliqueAuto(" in html
    assert "confirme_dmz" in html and "TOUT le trafic entrant" in html


def test_ip_fixe_absente_est_un_ecart_avec_la_mac_de_la_box(tmp_path):
    svc, f, _ = _pret(tmp_path, _lectures(bail=""))
    par = {i["id"]: i for i in svc.autoconfig(IP)["items"]}
    assert par["ip_fixe"]["conforme"] is False and par["ip_fixe"]["cible"] == {"mac": MAC, "ip": IP}
    assert par["ip_fixe"]["actuel"] == {"mac": MAC, "ip": ""}


def test_ip_fixe_creee_par_post_quand_le_bail_manque(tmp_path):
    svc, f, journal = _pret(tmp_path, [ok(HOTES), ok([]), ok({}), ok(HOTES), ok([{"mac": MAC, "ip": IP, "id": MAC}])])
    r = svc.appliquer_autoconfig(["ip_fixe"], IP)
    posts = [a for a in f.appels if a[0] == "POST" and a[1].endswith("dhcp/static_lease/")]
    assert len(posts) == 1 and json.loads(posts[0][3])["mac"] == MAC and json.loads(posts[0][3])["ip"] == IP
    assert r["appliques"] == ["ip_fixe"] and journal[0]["action"] == "autoconfig_ip_fixe"


def test_ip_fixe_corrigee_par_put_quand_le_bail_pointe_ailleurs(tmp_path):
    svc, f, _ = _pret(tmp_path, [ok(HOTES), ok([{"mac": MAC, "ip": "192.168.1.77", "id": MAC}]), ok({}), ok(HOTES), ok([{"mac": MAC, "ip": IP, "id": MAC}])])
    svc.appliquer_autoconfig(["ip_fixe"], IP)
    puts = [a for a in f.appels if a[0] == "PUT"]
    assert len(puts) == 1 and puts[0][1].endswith("dhcp/static_lease/" + MAC)


def test_la_box_introuvable_dans_les_hotes_n_ecrit_rien(tmp_path):
    svc, f, _ = _pret(tmp_path, [ok([]), ok([])])
    with pytest.raises(c.ErreurFreebox):
        svc.appliquer_autoconfig(["ip_fixe"], IP)
    assert not [a for a in f.appels if a[0] in ("PUT", "POST") and "login" not in a[1]]


def test_pas_de_sequence_d_echappement_dans_le_html_visible():
    # « \\u2019 » écrit dans le HTML (hors script) s'affiche tel quel : l'apostrophe typographique doit être le caractère lui-même
    import re
    from pathlib import Path
    html = (Path(__file__).resolve().parents[1] / "www" / "freebox" / "index.html").read_text()
    visible = html[:html.index("<script>")]
    assert not re.search(r"\\u[0-9a-fA-F]{4}", visible), "séquence \\uXXXX visible dans le HTML"
