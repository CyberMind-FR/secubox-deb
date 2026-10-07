# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""Connecteur Freebox — service (états lisibles, cache court, droits) et routes (lecture gardée, administration en JWT, jamais de jeton)."""
import json

import pytest
from fastapi.testclient import TestClient

from api import client as c
from api import main, magasin as m
from api import service as s
from tests.test_client import VERSION, Faux


def _session(defi="D", droits=None):
    return [(200, {"success": True, "result": {"logged_in": False, "challenge": defi}}),
            (200, {"success": True, "result": {"session_token": "SESS", "permissions": droits if droits is not None else {"settings": False}}})]


def _svc(tmp_path, reponses, **mem):
    mag = m.Magasin(str(tmp_path / "app.json"))
    if mem:
        mag.ecrire(mem)
    f = Faux(reponses)
    cl = c.Client(f, mag, hote="http://x")
    return s.Freebox(cl, mag, horloge=lambda: 1000.0, nom_appareil="gk2"), f, mag


# ── états ────────────────────────────────────────────────────────────────────
def test_sans_jeton_l_etat_est_non_configure(tmp_path):
    svc, f, _ = _svc(tmp_path, [VERSION])
    r = svc.statut()
    assert r["etat"] == "non_configure" and r["freebox"]["modele"] == "Freebox v9 (r1)"


def test_demande_en_attente_dit_de_valider_sur_la_freebox(tmp_path):
    svc, f, _ = _svc(tmp_path, [VERSION, (200, {"success": True, "result": {"status": "pending"}})], app_token="T", track_id=7, autorise=False)
    r = svc.statut()
    assert r["etat"] == "attente_validation" and "Freebox" in r["message"] and "✓" in r["message"]


def test_refusee_ou_expiree_est_dite_clairement(tmp_path):
    for statut, mot in (("denied", "refus"), ("timeout", "expir")):
        svc, f, _ = _svc(tmp_path, [VERSION, (200, {"success": True, "result": {"status": statut}})], app_token="T", track_id=7, autorise=False)
        r = svc.statut()
        assert r["etat"] in ("refusee", "expiree") and mot in r["message"].lower()


def test_autorise_donne_les_droits_et_ceux_qui_manquent(tmp_path):
    svc, f, _ = _svc(tmp_path, [VERSION] + _session(droits={"settings": False, "parental": False, "player_control": True}), app_token="T", autorise=True)
    r = svc.statut()
    assert r["etat"] == "autorise" and r["droits"]["settings"] is False
    assert "settings" in r["droits_manquants"] and "redirections" in r["aide_droits"]["settings"].lower()


def test_freebox_injoignable_est_un_etat_pas_une_exception(tmp_path):
    def casse(methode, url, entetes, corps):
        raise OSError("down")
    mag = m.Magasin(str(tmp_path / "app.json"))
    svc = s.Freebox(c.Client(casse, mag, hote="http://x"), mag, horloge=lambda: 1.0, nom_appareil="gk2")
    r = svc.statut()
    assert r["etat"] == "injoignable" and "Freebox" in r["message"]


def test_le_statut_ne_contient_jamais_le_jeton(tmp_path):
    svc, f, _ = _svc(tmp_path, [VERSION] + _session(), app_token="SECRET-TOKEN", autorise=True)
    assert "SECRET-TOKEN" not in json.dumps(svc.statut())


# ── lectures ─────────────────────────────────────────────────────────────────
HOTES = [{"id": "e", "primary_name": "TV", "host_type": "tv", "active": True, "reachable": True, "l2ident": {"id": "AA:BB:CC:DD:EE:FF"},
          "l3connectivities": [{"addr": "192.168.1.9", "af": "ipv4"}]}]


def test_les_appareils_sont_lus_puis_servis_du_cache(tmp_path):
    svc, f, _ = _svc(tmp_path, [VERSION] + _session() + [(200, {"success": True, "result": HOTES})], app_token="T", autorise=True)
    a = svc.appareils()
    assert a[0]["nom"] == "TV"
    n = len(f.appels)
    assert svc.appareils() == a and len(f.appels) == n                   # aucun nouvel appel dans le délai


def test_le_pare_feu_dit_actif_et_si_les_exceptions_sont_lues(tmp_path):
    rep = [VERSION] + _session() + [(200, {"success": True, "result": {"ipv6_enabled": True, "ipv6_firewall": True, "delegations": []}}),
                                    (404, {"success": False, "error_code": "no_such_api"}), (404, {"success": False, "error_code": "no_such_api"}),
                                    (404, {"success": False, "error_code": "no_such_api"})]
    svc, f, _ = _svc(tmp_path, rep, app_token="T", autorise=True)
    r = svc.pare_feu()
    assert r["pare_feu_actif"] is True and r["exceptions"] == [] and r["exceptions_lues"] is False


def test_le_pare_feu_remplit_les_exceptions_quand_l_api_les_donne(tmp_path):
    rep = [VERSION] + _session() + [(200, {"success": True, "result": {"ipv6_enabled": True, "ipv6_firewall": True, "delegations": []}}),
                                    (200, {"success": True, "result": [{"id": "a", "enabled": True, "ip_proto": "tcp", "ip": "2a01::1", "port_start": 443, "port_end": 443}]})]
    svc, f, _ = _svc(tmp_path, rep, app_token="T", autorise=True)
    r = svc.pare_feu()
    assert r["exceptions_lues"] is True and r["exceptions"][0]["port_debut"] == 443


def test_les_redirections_signalent_un_droit_manquant(tmp_path):
    rep = [VERSION] + _session() + [(403, {"success": False, "error_code": "insufficient_rights"})]
    svc, f, _ = _svc(tmp_path, rep, app_token="T", autorise=True)
    with pytest.raises(c.DroitManquant):
        svc.redirections()


# ── routes ───────────────────────────────────────────────────────────────────
@pytest.fixture
def api(tmp_path, monkeypatch):
    svc, f, mag = _svc(tmp_path, [VERSION], )
    monkeypatch.setattr(main, "_service", svc)
    monkeypatch.setenv("SECUBOX_TABLEAU_DE_BORD", "0")
    return TestClient(main.app), svc, f, mag


def test_health_est_publique(api):
    cl, *_ = api
    assert cl.get("/health").json()["module"] == "freebox"


def test_la_lecture_est_gardee(api):
    cl, *_ = api
    for chemin in ("/status", "/appareils", "/connexion", "/pare-feu", "/redirections", "/autoriser/etat"):
        assert cl.get(chemin).status_code in (401, 403), chemin


def test_l_administration_exige_un_jeton_admin(api):
    cl, *_ = api
    assert cl.post("/autoriser", json={}).status_code in (401, 403)
    assert cl.post("/revoquer").status_code in (401, 403)
    assert cl.get("/explorer", params={"chemin": "connection/"}).status_code in (401, 403)


def _autoriser_api(monkeypatch):
    from secubox_core import auth
    main.app.dependency_overrides[auth.require_lecture] = lambda: {"sub": "t"}
    main.app.dependency_overrides[auth.require_jwt] = lambda: {"sub": "admin", "role": "admin"}


def test_autoriser_demarre_la_demande_et_ne_rend_pas_le_jeton(api, monkeypatch):
    cl, svc, f, mag = api
    f.reponses.extend([(200, {"success": True, "result": {"app_token": "SECRET-TOKEN", "track_id": 9}})])
    _autoriser_api(monkeypatch)
    try:
        r = cl.post("/autoriser", json={})
        assert r.status_code == 200 and "SECRET-TOKEN" not in r.text and r.json()["track_id"] == 9 and "✓" in r.json()["message"]
        assert mag.lire()["app_token"] == "SECRET-TOKEN"
    finally:
        main.app.dependency_overrides.clear()


def test_revoquer_oublie_le_jeton_localement(api, monkeypatch):
    cl, svc, f, mag = api
    mag.ecrire({"app_token": "T", "autorise": True})
    _autoriser_api(monkeypatch)
    try:
        r = cl.post("/revoquer")
        assert r.status_code == 200 and mag.lire() == {} and "Freebox" in r.json()["message"]
    finally:
        main.app.dependency_overrides.clear()


def test_les_erreurs_ont_le_bon_code_et_un_message_clair(api, monkeypatch):
    cl, svc, f, mag = api
    _autoriser_api(monkeypatch)
    try:
        r = cl.get("/appareils")                                    # pas autorisé
        assert r.status_code == 409 and "autorisé" in r.json()["erreur"]
    finally:
        main.app.dependency_overrides.clear()


def test_aucune_route_d_ecriture_n_est_publique_sans_jwt():
    ecritures = [r for r in main.app.routes if getattr(r, "methods", None) and (r.methods & {"POST", "PUT", "DELETE"})]
    assert ecritures
    for r in ecritures:
        deps = [d.call for d in r.dependant.dependencies]
        assert any(getattr(d, "__name__", "") == "require_jwt" for d in deps), r.path


def test_explorer_refuse_les_chemins_hors_liste(api, monkeypatch):
    cl, *_ = api
    _autoriser_api(monkeypatch)
    try:
        assert cl.get("/explorer", params={"chemin": "../x"}).status_code == 400
        assert cl.get("/explorer", params={"chemin": "login/session/"}).status_code == 400   # jamais le chemin de session
        assert cl.get("/explorer", params={"chemin": "system/reboot/"}).status_code == 400
    finally:
        main.app.dependency_overrides.clear()
