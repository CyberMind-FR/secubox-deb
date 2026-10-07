# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""Connecteur Freebox — client de l'API Freebox OS : autorisation, session HMAC, appels, erreurs. Transport injecté : aucun réseau."""
import hashlib
import hmac
import json

import pytest

from api import client as c
from api import magasin as m


class Faux:
    """Transport qui rejoue des réponses prévues et garde la trace des appels."""
    def __init__(self, reponses):
        self.reponses, self.appels = list(reponses), []

    def __call__(self, methode, url, entetes, corps):
        self.appels.append((methode, url, dict(entetes or {}), corps))
        statut, doc = self.reponses.pop(0)
        return statut, doc


def _magasin(tmp_path, **kw):
    mag = m.Magasin(str(tmp_path / "app.json"))
    if kw:
        mag.ecrire(kw)
    return mag


VERSION = (200, {"api_version": "16.0", "api_base_url": "/api/", "box_model_name": "Freebox v9 (r1)", "device_name": "Freebox Server"})


# ── adresse de l'API ─────────────────────────────────────────────────────────
def test_la_version_de_l_api_donne_l_adresse_de_base(tmp_path):
    f = Faux([VERSION])
    cl = c.Client(f, _magasin(tmp_path), hote="http://mafreebox.freebox.fr")
    info = cl.decouvrir()
    assert info["version"] == "16.0" and info["modele"] == "Freebox v9 (r1)"
    assert cl.base == "http://mafreebox.freebox.fr/api/v16/"
    assert f.appels[0][1] == "http://mafreebox.freebox.fr/api_version"


# ── autorisation ─────────────────────────────────────────────────────────────
def test_demande_d_autorisation_garde_le_jeton_et_rend_le_suivi(tmp_path):
    f = Faux([VERSION, (200, {"success": True, "result": {"app_token": "SECRET-TOKEN", "track_id": 7}})])
    mag = _magasin(tmp_path)
    cl = c.Client(f, mag, hote="http://x")
    r = cl.demander_autorisation(nom_appareil="gk2")
    assert r == {"track_id": 7}
    corps = json.loads(f.appels[1][3])
    assert corps["app_id"] == c.APP_ID and corps["device_name"] == "gk2" and f.appels[1][0] == "POST"
    assert mag.lire()["app_token"] == "SECRET-TOKEN" and mag.lire()["autorise"] is False and mag.lire()["track_id"] == 7


def test_le_jeton_n_est_jamais_rendu_par_le_client(tmp_path):
    f = Faux([VERSION, (200, {"success": True, "result": {"app_token": "SECRET-TOKEN", "track_id": 7}})])
    cl = c.Client(f, _magasin(tmp_path), hote="http://x")
    assert "SECRET-TOKEN" not in repr(cl.demander_autorisation(nom_appareil="gk2"))


@pytest.mark.parametrize("statut,attendu", [("pending", "attente"), ("granted", "accordee"), ("denied", "refusee"), ("timeout", "expiree"),
                                            ("unknown", "inconnue")])
def test_l_etat_de_l_autorisation_est_traduit(tmp_path, statut, attendu):
    f = Faux([VERSION, (200, {"success": True, "result": {"status": statut, "challenge": "abc"}})])
    mag = _magasin(tmp_path, app_token="T", track_id=7, autorise=False)
    cl = c.Client(f, mag, hote="http://x")
    assert cl.etat_autorisation()["etat"] == attendu
    assert mag.lire()["autorise"] is (statut == "granted")


def test_sans_demande_en_cours_pas_d_etat(tmp_path):
    cl = c.Client(Faux([VERSION]), _magasin(tmp_path), hote="http://x")
    assert cl.etat_autorisation()["etat"] == "aucune"


# ── session HMAC ─────────────────────────────────────────────────────────────
def test_la_session_signe_le_defi_avec_hmac_sha1(tmp_path):
    f = Faux([VERSION, (200, {"success": True, "result": {"logged_in": False, "challenge": "DEFI123"}}),
              (200, {"success": True, "result": {"session_token": "SESS", "permissions": {"settings": False, "parental": False}}})])
    cl = c.Client(f, _magasin(tmp_path, app_token="TOKEN", autorise=True), hote="http://x")
    cl.ouvrir_session()
    attendu = hmac.new(b"TOKEN", b"DEFI123", hashlib.sha1).hexdigest()
    corps = json.loads(f.appels[2][3])
    assert corps == {"app_id": c.APP_ID, "password": attendu}
    assert cl.session == "SESS" and cl.droits == {"settings": False, "parental": False}


def test_sans_autorisation_on_n_ouvre_pas_de_session(tmp_path):
    cl = c.Client(Faux([VERSION]), _magasin(tmp_path, app_token="T", autorise=False), hote="http://x")
    with pytest.raises(c.NonAutorise):
        cl.ouvrir_session()


def test_un_appel_porte_le_jeton_de_session_et_ouvre_la_session_si_besoin(tmp_path):
    f = Faux([VERSION, (200, {"success": True, "result": {"logged_in": False, "challenge": "D"}}),
              (200, {"success": True, "result": {"session_token": "SESS", "permissions": {}}}),
              (200, {"success": True, "result": [{"id": "ether-aa"}]})])
    cl = c.Client(f, _magasin(tmp_path, app_token="T", autorise=True), hote="http://x")
    assert cl.lire("lan/browser/pub/") == [{"id": "ether-aa"}]
    assert f.appels[3][2]["X-Fbx-App-Auth"] == "SESS" and f.appels[3][0] == "GET"


def test_une_session_expiree_est_rouverte_une_fois(tmp_path):
    f = Faux([VERSION, (200, {"success": True, "result": {"logged_in": False, "challenge": "D"}}),
              (200, {"success": True, "result": {"session_token": "S1", "permissions": {}}}),
              (403, {"success": False, "error_code": "auth_required", "msg": "x"}),
              (200, {"success": True, "result": {"logged_in": False, "challenge": "D2"}}),
              (200, {"success": True, "result": {"session_token": "S2", "permissions": {}}}),
              (200, {"success": True, "result": {"ok": 1}})])
    cl = c.Client(f, _magasin(tmp_path, app_token="T", autorise=True), hote="http://x")
    assert cl.lire("connection/") == {"ok": 1}
    assert f.appels[-1][2]["X-Fbx-App-Auth"] == "S2"


def test_un_droit_manquant_donne_un_message_clair(tmp_path):
    f = Faux([VERSION, (200, {"success": True, "result": {"logged_in": False, "challenge": "D"}}),
              (200, {"success": True, "result": {"session_token": "S", "permissions": {"settings": False}}}),
              (403, {"success": False, "error_code": "insufficient_rights", "msg": "Insufficient rights"})])
    cl = c.Client(f, _magasin(tmp_path, app_token="T", autorise=True), hote="http://x")
    with pytest.raises(c.DroitManquant) as e:
        cl.lire("fw/redir/")
    assert "droit" in str(e.value).lower()


def test_la_freebox_injoignable_donne_une_erreur_propre(tmp_path):
    def casse(methode, url, entetes, corps):
        raise OSError("Network is unreachable")
    cl = c.Client(casse, _magasin(tmp_path), hote="http://x")
    with pytest.raises(c.Injoignable) as e:
        cl.decouvrir()
    assert "Network is unreachable" not in str(e.value)


def test_un_chemin_d_ecriture_douteux_est_refuse_avant_tout_appel(tmp_path):
    f = Faux([])
    cl = c.Client(f, _magasin(tmp_path, app_token="T", autorise=True), hote="http://x")
    for mauvais in ("../etc/passwd", "http://evil/x", "fw/redir/;rm", "", "a b"):
        with pytest.raises(ValueError):
            cl.lire(mauvais)
    assert f.appels == []


# ── magasin du jeton ─────────────────────────────────────────────────────────
def test_le_magasin_est_ecrit_en_0600_et_atomiquement(tmp_path):
    mag = _magasin(tmp_path, app_token="T")
    p = tmp_path / "app.json"
    assert (p.stat().st_mode & 0o777) == 0o600
    mag.ecrire({"autorise": True})
    assert mag.lire() == {"app_token": "T", "autorise": True}
    assert not (tmp_path / "app.json.tmp").exists()


def test_le_magasin_oublie_le_jeton(tmp_path):
    mag = _magasin(tmp_path, app_token="T", autorise=True)
    mag.oublier()
    assert mag.lire() == {} and not (tmp_path / "app.json").exists()


def test_un_magasin_illisible_vaut_vide(tmp_path):
    (tmp_path / "app.json").write_text("{pas du json")
    assert m.Magasin(str(tmp_path / "app.json")).lire() == {}
