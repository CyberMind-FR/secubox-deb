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
HOST = {"l2ident": {"id": "F0:AD:4E:27:88:9B", "type": "mac_address"}, "primary_name": "gk2"}


def _regle(id_, debut, fin, lan_port, proto="udp", lan_ip=IP, comment="", enabled=True):
    # Format exact de fw/redir/ relevé sur la Freebox de gk2 (#3742).
    return {"id": id_, "enabled": enabled, "ip_proto": proto, "wan_port_start": debut, "wan_port_end": fin, "lan_ip": lan_ip,
            "lan_port": lan_port, "src_ip": "0.0.0.0", "comment": comment, "host": HOST}


# Les quatre règles réelles de gk2 : aucune sur 51822.
REELLES = [_regle(1, 5060, 5060, 5060), _regle(2, 10000, 20000, 10000), _regle(3, 5080, 5080, 5080), _regle(4, 51830, 51830, 51830)]
DMZ_OFF = ok({"enabled": False, "ip": ""})
DMZ_BOX = ok({"enabled": True, "ip": IP})
NOTRE = {**_regle(7, 51822, 51822, 51822, comment=VOULU["comment"])}


def _ecritures(f):
    return [a for a in f.appels if a[0] in ("POST", "PUT", "DELETE") and "login" not in a[1]]


# ── redirection IPv4 ─────────────────────────────────────────────────────────
def test_redirection_absente_est_creee_une_fois_puis_relue(tmp_path):
    svc, f, journal = _pret(tmp_path, [ok(REELLES), DMZ_OFF, ok({"id": 7}), ok(REELLES + [NOTRE]), DMZ_OFF])
    r = svc.appliquer_maillage_distant(IP, "", 51822)
    w = _ecritures(f)
    assert len(w) == 1 and w[0][0] == "POST" and w[0][1].endswith("fw/redir/") and json.loads(w[0][3]) == VOULU
    assert r["change"] is True and r["redirection"] == "creee" and r["exception_ipv6"] == "sans_ipv6"
    assert journal[0]["action"] == "maillage_redirection" and journal[0]["geste"] == "creee"


def test_dmz_vers_la_box_couvre_l_ipv4_sans_rien_creer(tmp_path):
    svc, f, journal = _pret(tmp_path, [ok(REELLES), DMZ_BOX])
    e = svc.etat_maillage_distant(IP, "", 51822)
    assert e["redirection"]["etat"] == "couvert_par_dmz" and e["redirection"]["conforme"] is True
    svc, f, journal = _pret(tmp_path, [ok(REELLES), DMZ_BOX])
    r = svc.appliquer_maillage_distant(IP, "", 51822)
    assert not _ecritures(f) and r["redirection"] == "couvert_par_dmz" and r["change"] is False


def test_redirection_deja_conforme_rien_n_est_ecrit(tmp_path):
    existante = dict(NOTRE)
    del existante["wan_port_end"]          # la Freebox peut omettre la fin quand elle vaut le début
    svc, f, journal = _pret(tmp_path, [ok(REELLES + [existante]), DMZ_OFF])
    r = svc.appliquer_maillage_distant(IP, "", 51822)
    assert not _ecritures(f) and r["change"] is False and r["redirection"] == "inchangee" and journal == []


def test_regle_tierce_identique_vers_la_box_compte_comme_conforme(tmp_path):
    svc, f, _ = _pret(tmp_path, [ok(REELLES + [_regle(9, 51822, 51822, 51822, comment="à la main")]), DMZ_OFF])
    r = svc.appliquer_maillage_distant(IP, "", 51822)
    assert not _ecritures(f) and r["redirection"] == "inchangee"


@pytest.mark.parametrize("occupante", [
    _regle(9, 51822, 51822, 51822, lan_ip="192.168.1.50"),
    _regle(9, 51000, 52000, 51000, lan_ip="192.168.1.50"),           # plage
    _regle(9, 51822, 51822, 51822, proto="tcp_udp", lan_ip="192.168.1.50"),
    _regle(9, 51822, 51822, 4000),                                     # vers la box mais autre port local : pas à nous
])
def test_port_pris_par_une_autre_regle_refus_sans_reecriture(tmp_path, occupante):
    svc, f, journal = _pret(tmp_path, [ok(REELLES + [occupante, NOTRE]), DMZ_OFF])
    with pytest.raises(c.ErreurFreebox) as e:
        svc.appliquer_maillage_distant(IP, "", 51822)
    assert not _ecritures(f) and journal[0]["geste"] == "port_pris" and occupante["lan_ip"] in str(e.value)


def test_seule_la_regle_secubox_est_corrigee(tmp_path):
    vieille = {**NOTRE, "lan_port": 51000}
    svc, f, journal = _pret(tmp_path, [ok(REELLES + [vieille]), DMZ_OFF, ok({}), ok(REELLES + [NOTRE]), DMZ_OFF])
    r = svc.appliquer_maillage_distant(IP, "", 51822)
    w = _ecritures(f)
    assert len(w) == 1 and w[0][0] == "PUT" and w[0][1].endswith("fw/redir/7") and json.loads(w[0][3]) == VOULU
    assert r["redirection"] == "corrigee"


def test_doublons_secubox_signales_jamais_supprimes(tmp_path):
    doublon = {**NOTRE, "id": 12, "lan_port": 1}
    svc, f, _ = _pret(tmp_path, [ok(REELLES + [doublon, NOTRE]), DMZ_OFF])
    r = svc.appliquer_maillage_distant(IP, "", 51822)
    assert not _ecritures(f) and r["doublons"] == [12] and r["redirection"] == "inchangee"   # règle retenue : id 7


def test_relecture_non_conforme_est_une_erreur(tmp_path):
    svc, f, _ = _pret(tmp_path, [ok(REELLES), DMZ_OFF, ok({"id": 7}), ok(REELLES), DMZ_OFF])
    with pytest.raises(c.ErreurFreebox):
        svc.appliquer_maillage_distant(IP, "", 51822)


def test_sans_droit_settings_rien_n_est_ecrit(tmp_path):
    svc, f, _ = _pret(tmp_path, [], droits={"settings": False})
    with pytest.raises(c.DroitManquant):
        svc.appliquer_maillage_distant(IP, V6, 51822)
    assert not _ecritures(f)


# ── IPv6 ─────────────────────────────────────────────────────────────────────
def test_freebox_de_gk2_aucune_voie_ipv6_aucune_ecriture_ipv6(tmp_path):
    svc, f, journal = _pret(tmp_path, [ok(REELLES + [NOTRE]), DMZ_OFF, NON, NON, NON])
    r = svc.appliquer_maillage_distant(IP, V6, 51822)
    assert r["exception_ipv6"] == "indisponible" and not _ecritures(f)
    assert all(any(a[0] == "GET" and a[1].endswith(ch) for a in f.appels) for ch in ("fw/ipv6/", "fw/ipv6/redir/", "fw/pinhole/"))
    assert not [a for a in f.appels if "connection/ipv6/config" in a[1]]
    assert journal[-1]["geste"] == "indisponible"


def test_exception_ipv6_creee_quand_la_freebox_l_expose(tmp_path):
    voulue6 = {"enabled": True, "comment": VOULU["comment"], "ip_proto": "udp", "ip": V6, "port_start": 51822, "port_end": 51822}
    svc, f, journal = _pret(tmp_path, [ok(REELLES + [NOTRE]), DMZ_OFF, ok([]), ok({"id": 3}), ok([{"id": 3, **voulue6}])])
    r = svc.appliquer_maillage_distant(IP, V6, 51822)
    w = _ecritures(f)
    assert len(w) == 1 and w[0][0] == "POST" and w[0][1].endswith("fw/ipv6/") and json.loads(w[0][3]) == voulue6
    assert r["exception_ipv6"] == "creee" and r["change"] is True


def test_exception_ipv6_seule_la_regle_secubox_retenue(tmp_path):
    e6 = {"id": 3, "enabled": True, "comment": VOULU["comment"], "ip_proto": "udp", "ip": V6, "port_start": 51822, "port_end": 51822}
    double = {**e6, "id": 9, "port_start": 1, "port_end": 1}
    svc, f, _ = _pret(tmp_path, [ok(REELLES + [NOTRE]), DMZ_OFF, NON, ok([double, e6])])
    r = svc.appliquer_maillage_distant(IP, V6, 51822)
    assert not _ecritures(f) and r["exception_ipv6"] == "inchangee"


def test_etat_lecture_seule_signale_l_absence_de_voie_ipv6(tmp_path):
    svc, f, _ = _pret(tmp_path, [ok(REELLES), DMZ_OFF, NON, NON, NON, ok({"ipv6_firewall": True, "ipv6_prefix_firewall": True})])
    e = svc.etat_maillage_distant(IP, V6, 51822)
    assert e["redirection"]["etat"] == "absente" and e["ipv6"]["etat"] == "indisponible"
    assert "PAS désactivé" in e["ipv6"]["message"] and not _ecritures(f)


def test_item_autoconfig_seulement_si_une_annonce_est_donnee(tmp_path):
    from tests.test_autoconfig import _lectures
    svc, f, _ = _pret(tmp_path, _lectures() + [ok(REELLES), DMZ_BOX, NON, NON, NON, ok({"ipv6_firewall": True})])
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


ROUTES = [{"dst": "default", "gateway": "fe80::1", "dev": "eth2"}]


def test_seule_l_ipv6_statique_de_l_interface_de_la_route_par_defaut():
    assert MA.ipv6_fixes(IP_JSON, ROUTES) == [{"interface": "eth2", "adresse": V6}]
    autre = [{"ifname": "eth0", "addr_info": [{"family": "inet6", "scope": "global", "local": "2a01:e0a:1::5", "valid_life_time": 4294967295}]}]
    assert MA.ipv6_fixes(IP_JSON + autre, ROUTES) == [{"interface": "eth2", "adresse": V6}]


def test_sans_route_par_defaut_ni_ipv6_declaree_pas_d_ouverture_ipv6(tmp_path):
    assert MA.ipv6_fixes(IP_JSON, []) == []
    r = MA.relever(str(tmp_path / "p.toml"), str(tmp_path / "f.toml"), ip_json=lambda: IP_JSON, routes_json=lambda: [], resoudre=lambda n: [])
    assert r["ipv6_attendue"] == ""


def test_controle_conforme_sans_aaaa_publiee():
    r = MA.controler(MA.ipv6_fixes(IP_JSON, ROUTES), [], V6, horloge=lambda: 5)
    assert r["conforme"] is True and r["aaaa_publiee"] is False and r["aaaa_conforme"] is None


def test_controle_alerte_si_l_aaaa_differe_ou_si_l_ipv6_disparait():
    r = MA.controler(MA.ipv6_fixes(IP_JSON, ROUTES), ["2a01:e0a:dec:c4e0::300"], V6)
    assert r["conforme"] is False and "AAAA" in r["alertes"][0]
    r = MA.controler([], [], V6)
    assert r["conforme"] is False and r["presente"] is False


def test_relever_resout_le_nom_annonce(tmp_path):
    p = tmp_path / "p2p.toml"
    p.write_text('[wireguard]\npublic_endpoint = "gk2.secubox.in:51822"\n')
    vus = []
    r = MA.relever(str(p), str(tmp_path / "absent.toml"), ip_json=lambda: IP_JSON, routes_json=lambda: ROUTES, resoudre=lambda n: vus.append(n) or [V6])
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


RACINE = Path(__file__).resolve().parents[1]


def test_unite_du_controle_durcie():
    u = (RACINE / "systemd" / "secubox-freebox-maillage.service").read_text()
    for ligne in ("User=secubox-freebox", "ProtectProc=invisible", "ProcSubset=pid", "MemoryDenyWriteExecute=yes",
                  "NoNewPrivileges=yes", "ProtectSystem=strict", "ReadWritePaths=/var/lib/secubox/freebox", "UMask=0027"):
        assert ligne + "\n" in u


def test_profil_apparmor_enforce_installe_et_charge():
    prof = (RACINE / "apparmor" / "usr.sbin.freeboxctl").read_text()
    assert "profile secubox-freeboxctl /usr/sbin/freeboxctl flags=(enforce, attach_disconnected)" in prof
    ecritures = [x.strip() for x in prof.splitlines() if x.strip().endswith((" rw,", " w,")) and not x.strip().startswith("deny")]
    assert ecritures == ["/var/lib/secubox/freebox/** rw,"]
    assert "/usr/bin/ip mrix," in prof and "network netlink raw," in prof and "deny /etc/secubox/secrets/** rw," in prof
    assert "etc/apparmor.d/usr.sbin.freeboxctl" in (RACINE / "debian" / "rules").read_text()
    assert "apparmor_parser -r /etc/apparmor.d/usr.sbin.freeboxctl" in (RACINE / "debian" / "postinst").read_text()


def _regles_profil():
    prof = (RACINE / "apparmor" / "usr.sbin.freeboxctl").read_text()
    return {x.split("#")[0].strip() for x in prof.splitlines() if x.split("#")[0].strip()}


def test_profil_couvre_le_shebang_l_interpreteur_et_ip():
    r = _regles_profil()
    for regle in ("/usr/bin/env rix,", "/usr/bin/python3* mrix,", "/usr/lib/python3*/** mr,", "/usr/lib/python3/dist-packages/** mr,",
                  "/etc/python3*/** r,", "/usr/bin/ip mrix,", "/etc/iproute2/** r,", "/usr/share/iproute2/** r,",
                  "/usr/lib/secubox/freebox/** r,", "/var/lib/secubox/freebox/** rw,", "network inet stream,"):
        assert regle in r, regle
    assert (RACINE / "sbin" / "freeboxctl").read_text().startswith("#!/usr/bin/env python3\n")


def test_postrm_decharge_le_profil():
    s = (RACINE / "debian" / "postrm").read_text()
    assert "apparmor_parser -R /etc/apparmor.d/usr.sbin.freeboxctl" in s and "remove|purge" in s


def test_port_pris_l_emporte_sur_la_dmz(tmp_path):
    occupante = _regle(9, 51822, 51822, 51822, lan_ip="192.168.1.50")
    svc, f, journal = _pret(tmp_path, [ok(REELLES + [occupante]), DMZ_BOX])
    e = svc.etat_maillage_distant(IP, "", 51822)
    assert e["redirection"]["etat"] == "port_pris" and e["redirection"]["occupant"] == "192.168.1.50"
    svc, f, journal = _pret(tmp_path, [ok(REELLES + [occupante]), DMZ_BOX])
    with pytest.raises(c.ErreurFreebox):
        svc.appliquer_maillage_distant(IP, "", 51822)
    assert not _ecritures(f)


def test_regle_tierce_inactive_n_occupe_pas_le_port(tmp_path):
    inactive = _regle(9, 51822, 51822, 51822, lan_ip="192.168.1.50", enabled=False)
    svc, f, _ = _pret(tmp_path, [ok(REELLES + [inactive]), DMZ_BOX])
    assert svc.etat_maillage_distant(IP, "", 51822)["redirection"]["etat"] == "couvert_par_dmz"


def test_exception_ipv6_tierce_vers_une_autre_ipv6_signalee_sans_ecriture(tmp_path):
    e6 = {"id": 3, "enabled": True, "comment": VOULU["comment"], "ip_proto": "udp", "ip": V6, "port_start": 51822, "port_end": 51822}
    tierce = {"id": 5, "enabled": True, "comment": "", "ip_proto": "udp", "ip": "2a01:e0a:dec:c4e0::9", "port_start": 51800, "port_end": 51900}
    svc, f, _ = _pret(tmp_path, [ok(REELLES + [NOTRE]), DMZ_OFF, ok([tierce, e6])])
    e = svc.etat_maillage_distant(IP, V6, 51822)
    assert e["ipv6"]["etat"] == "conforme" and e["ipv6"]["occupants"] == [{"id": 5, "ip": "2a01:e0a:dec:c4e0::9"}]
    svc, f, journal = _pret(tmp_path, [ok(REELLES + [NOTRE]), DMZ_OFF, ok([tierce, e6])])
    r = svc.appliquer_maillage_distant(IP, V6, 51822)
    assert not _ecritures(f) and r["occupants_ipv6"] == [{"id": 5, "ip": "2a01:e0a:dec:c4e0::9"}]
    assert any(j.get("geste") == "occupant_signale" for j in journal)
