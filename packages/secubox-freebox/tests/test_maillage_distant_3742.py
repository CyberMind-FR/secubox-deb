# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""Maillage distant (#3742) : redirection UDP idempotente, exception IPv6 ciblée seulement si la Freebox l'expose, jamais le pare-feu
IPv6 global ; contrôle de l'IPv6 fixe du WAN contre l'AAAA publiée."""
import importlib.machinery
import importlib.util
import io
import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from api import client as c
from api import maillage as MA
from api import main
from tests.test_pare_feu_ecriture import _pret, ok

IP = "192.168.1.200"
V6 = "2a01:e0a:dec:c4e0::200"
NON = (200, {"success": False, "error_code": "invalid_request"})
VOULU = {"enabled": True, "comment": "SecuBox maillage distant (wg-mesh)", "lan_port": 51822, "wan_port_start": 51822,
         "wan_port_end": 51822, "lan_ip": IP, "ip_proto": "udp", "src_ip": "0.0.0.0"}
AUTRE = {"id": 1, "enabled": True, "ip_proto": "tcp", "wan_port_start": 443, "wan_port_end": 443, "lan_ip": IP, "lan_port": 443}


def _ecritures(f):
    return [a for a in f.appels if a[0] in ("POST", "PUT", "DELETE") and "login" not in a[1]]


# ── redirection IPv4 ─────────────────────────────────────────────────────────
def test_redirection_absente_est_creee_une_fois_puis_relue(tmp_path):
    svc, f, journal = _pret(tmp_path, [ok([AUTRE]), ok({"id": 7}), ok([AUTRE, {"id": 7, **VOULU}])])
    r = svc.appliquer_maillage_distant(IP, "", 51822)
    w = _ecritures(f)
    assert len(w) == 1 and w[0][0] == "POST" and w[0][1].endswith("fw/redir/") and json.loads(w[0][3]) == VOULU
    assert r == {"change": True, "redirection": "creee", "exception_ipv6": "sans_ipv6"}
    assert journal[0]["action"] == "maillage_redirection" and journal[0]["geste"] == "creee"


def test_redirection_deja_conforme_rien_n_est_ecrit(tmp_path):
    existante = {"id": 7, **VOULU}
    del existante["wan_port_end"]          # la Freebox omet la fin quand elle vaut le début
    svc, f, journal = _pret(tmp_path, [ok([AUTRE, existante])])
    r = svc.appliquer_maillage_distant(IP, "", 51822)
    assert not _ecritures(f) and r["change"] is False and r["redirection"] == "inchangee" and journal == []


def test_redirection_differente_est_corrigee_par_put_sans_doublon(tmp_path):
    vieille = {**VOULU, "id": 7, "lan_ip": "192.168.1.50"}
    svc, f, journal = _pret(tmp_path, [ok([vieille]), ok({}), ok([{**VOULU, "id": 7}])])
    r = svc.appliquer_maillage_distant(IP, "", 51822)
    w = _ecritures(f)
    assert len(w) == 1 and w[0][0] == "PUT" and w[0][1].endswith("fw/redir/7") and json.loads(w[0][3])["lan_ip"] == IP
    assert r["redirection"] == "corrigee"


def test_relecture_non_conforme_est_une_erreur(tmp_path):
    svc, f, _ = _pret(tmp_path, [ok([]), ok({"id": 7}), ok([])])
    with pytest.raises(c.ErreurFreebox):
        svc.appliquer_maillage_distant(IP, "", 51822)


def test_sans_droit_settings_rien_n_est_ecrit(tmp_path):
    svc, f, _ = _pret(tmp_path, [], droits={"settings": False})
    with pytest.raises(c.DroitManquant):
        svc.appliquer_maillage_distant(IP, V6, 51822)
    assert not _ecritures(f)


# ── IPv6 ─────────────────────────────────────────────────────────────────────
def test_sans_voie_d_exception_ipv6_le_pare_feu_global_n_est_jamais_touche(tmp_path):
    conforme = {"id": 7, **VOULU}
    svc, f, journal = _pret(tmp_path, [ok([conforme]), NON, NON, NON])
    r = svc.appliquer_maillage_distant(IP, V6, 51822)
    assert r["exception_ipv6"] == "indisponible" and not _ecritures(f)
    assert not [a for a in f.appels if "connection/ipv6/config" in a[1] and a[0] != "GET"]
    assert journal[-1]["geste"] == "indisponible"


def test_exception_ipv6_creee_quand_la_freebox_l_expose(tmp_path):
    conforme = {"id": 7, **VOULU}
    voulue6 = {"enabled": True, "comment": "SecuBox maillage distant (wg-mesh)", "ip_proto": "udp", "ip": V6, "port_start": 51822, "port_end": 51822}
    svc, f, journal = _pret(tmp_path, [ok([conforme]), ok([]), ok({"id": 3}), ok([{"id": 3, **voulue6}])])
    r = svc.appliquer_maillage_distant(IP, V6, 51822)
    w = _ecritures(f)
    assert len(w) == 1 and w[0][0] == "POST" and w[0][1].endswith("fw/ipv6/") and json.loads(w[0][3]) == voulue6
    assert r["exception_ipv6"] == "creee" and r["change"] is True


def test_exception_ipv6_deja_la_n_est_pas_reecrite(tmp_path):
    conforme = {"id": 7, **VOULU}
    e6 = {"id": 3, "enabled": True, "comment": "SecuBox maillage distant (wg-mesh)", "ip_proto": "udp", "ip": V6, "port_start": 51822, "port_end": 51822}
    svc, f, _ = _pret(tmp_path, [ok([conforme]), NON, ok([e6])])
    r = svc.appliquer_maillage_distant(IP, V6, 51822)
    assert not _ecritures(f) and r == {"change": False, "redirection": "inchangee", "exception_ipv6": "inchangee"}


def test_etat_lecture_seule_signale_l_absence_de_voie_ipv6(tmp_path):
    svc, f, _ = _pret(tmp_path, [ok([]), NON, NON, NON, ok({"ipv6_firewall": True})])
    e = svc.etat_maillage_distant(IP, V6, 51822)
    assert e["redirection"]["conforme"] is False and e["ipv6"]["etat"] == "indisponible"
    assert "PAS désactivé" in e["ipv6"]["message"] and not _ecritures(f)


def test_item_autoconfig_seulement_si_une_annonce_est_donnee(tmp_path):
    from tests.test_autoconfig import _lectures
    svc, f, _ = _pret(tmp_path, _lectures() + [ok([{"id": 7, **VOULU}]), NON, NON, NON, ok({"ipv6_firewall": True})])
    r = svc.autoconfig(IP, {"port": 51822, "ipv6": V6})
    par = {i["id"]: i for i in r["items"]}
    assert par["maillage_distant"]["conforme"] is True and r["ecarts"] == 0


def test_appliquer_autoconfig_maillage_exige_l_annonce(tmp_path):
    svc, f, _ = _pret(tmp_path, [])
    with pytest.raises(ValueError):
        svc.appliquer_autoconfig(["maillage_distant"], IP)


# ── routes ───────────────────────────────────────────────────────────────────
def test_routes_gardees():
    t = TestClient(main.app)
    assert t.post("/maillage-distant", json={"confirme": True}).status_code in (401, 403)
    from secubox_core import auth
    gardes = {next(iter(r.methods)): [d.call for d in r.dependant.dependencies] for r in main.app.routes
              if getattr(r, "path", "") == "/maillage-distant"}
    assert auth.require_lecture in gardes["GET"] and auth.require_jwt in gardes["POST"]
    main.app.dependency_overrides[auth.require_jwt] = lambda: {"sub": "a"}
    try:
        assert t.post("/maillage-distant", json={}).status_code == 400
    finally:
        main.app.dependency_overrides.clear()


# ── annonce et contrôle de l'IPv6 fixe ───────────────────────────────────────
def test_annonce_lue_dans_p2p_toml(tmp_path):
    p = tmp_path / "p2p.toml"
    p.write_text('[wireguard]\nlisten_port = 51822\npublic_endpoint = "gk2.secubox.in:51822"\n')
    assert MA.annonce(str(p)) == {"public_endpoint": "gk2.secubox.in:51822", "hote": "gk2.secubox.in", "port": 51822, "port_local": 51822}
    p.write_text('[wireguard]\nlisten_port = 51822\n')
    assert MA.annonce(str(p)) is None


IP_JSON = [
    {"ifname": "eth2", "addr_info": [
        {"family": "inet6", "scope": "global", "local": "2a01:e0a:dec:c4e0:1234:5678:9abc:def0", "dynamic": True, "mngtmpaddr": True, "valid_life_time": 86000},
        {"family": "inet6", "scope": "global", "local": V6, "valid_life_time": 4294967295}]},
    {"ifname": "wg-mesh", "addr_info": [{"family": "inet6", "scope": "global", "local": "2a01:e0a:dec:c4e0::9", "valid_life_time": 4294967295}]},
]


def test_seule_l_ipv6_statique_du_wan_est_retenue():
    assert MA.ipv6_fixes(IP_JSON) == [{"interface": "eth2", "adresse": V6}]


def test_controle_conforme_sans_aaaa_publiee():
    r = MA.controler(MA.ipv6_fixes(IP_JSON), [], V6, horloge=lambda: 5)
    assert r["conforme"] is True and r["aaaa_publiee"] is False and r["aaaa_conforme"] is None


def test_controle_alerte_si_l_aaaa_differe_ou_si_l_ipv6_disparait():
    r = MA.controler(MA.ipv6_fixes(IP_JSON), ["2a01:e0a:dec:c4e0::300"], V6)
    assert r["conforme"] is False and "AAAA" in r["alertes"][0]
    r = MA.controler([], [], V6)
    assert r["conforme"] is False and r["presente"] is False


def test_relever_resout_le_nom_annonce(tmp_path):
    p = tmp_path / "p2p.toml"
    p.write_text('[wireguard]\npublic_endpoint = "gk2.secubox.in:51822"\n')
    vus = []
    r = MA.relever(str(p), str(tmp_path / "absent.toml"), ip_json=lambda: IP_JSON, resoudre=lambda n: vus.append(n) or [V6])
    assert vus == ["gk2.secubox.in"] and r["conforme"] is True and r["aaaa_conforme"] is True


def _ctl():
    chemin = str(Path(__file__).resolve().parents[1] / "sbin" / "freeboxctl")
    spec = importlib.util.spec_from_loader("freeboxctl", importlib.machinery.SourceFileLoader("freeboxctl", chemin))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_controle_periodique_ecrit_l_etat_et_alerte_au_journal():
    ctl = _ctl()
    ecrit, err = [], io.StringIO()
    etat = ctl.controle_maillage(relever=lambda: MA.controler([], [], V6), ecrire=ecrit.append, sortie=err)
    assert ecrit == [etat] and err.getvalue().startswith("<4>maillage distant")
