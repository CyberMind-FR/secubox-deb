# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3212 — relevé de validation des modules, signé par la box et lu par ses pairs du maillage.

Le relevé (secubox-profiles) est signé par sbx-fleetctl publish-modules avec la clé de la box, servi sur l'écoute du
maillage (:8799, /fleet/modules/self) et rassemblé par /fleet/modules (JWT) pour le comparateur des profils. Modèle
séparé de MetricSnapshot (extra="forbid" : un champ ajouté y casserait les pairs pas encore à jour)."""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
from pydantic import ValidationError

PKG_ROOT = Path(__file__).resolve().parents[1]
CLI = PKG_ROOT / "sbin" / "sbx-fleetctl"
sys.path.insert(0, str(PKG_ROOT))

from annuaire import fleet, fleet_store  # noqa: E402
from annuaire.crypto import did_from_pubkey, generate_keypair, public_from_private  # noqa: E402

PAQUET = {"paquet": "secubox-p2p", "version": "1.19.2-1~trixie1", "statut_dpkg": "ii", "installe": True,
          "attendu": True, "recommande": False, "meta": False, "hors_profil": False, "etat": "fonctionnel",
          "unites": [{"unite": "secubox-p2p.service", "etat": "actif", "memoire_o": 52428800}],
          "agregateur": [{"module": "p2p", "etat": "actif"}], "memoire_o": 52428800, "cpu_pct": 1.5, "erreurs": []}
RELEVE = {"version": 1, "hostname": "gk3", "releve_epoch": 1000.0, "releve_ts": "2026-10-27T10:00:00Z",
          "profil_actif": "lite", "profils_installes": ["lite"], "partiel": [],
          "paquets": [{**PAQUET, "cpu_ns": 9217830000},
                      {**PAQUET, "paquet": "secubox-gitea", "version": None, "statut_dpkg": "absent", "installe": False,
                       "etat": "manquant", "unites": [], "agregateur": [], "memoire_o": None, "cpu_pct": None,
                       "erreurs": ["attendu par le profil lite, non installé"], "cpu_ns": None}]}


def _acteur():
    priv, pub = generate_keypair()
    return priv, did_from_pubkey(pub)


def _champs(did, **sur):
    return {"node_did": did, "issued_by": did, "hostname": "gk3", "ts": "2026-10-27T10:00:30Z",
            "releve_ts": "2026-10-27T10:00:00Z", "profil_actif": "lite", "profils_installes": ["lite"], "partiel": [],
            "paquets": [PAQUET], **sur}


# ── modèle, signature, vérification ──────────────────────────────────────────

def test_signe_et_verifie():
    priv, did = _acteur()
    rec = fleet.sign_modules(priv, _champs(did))
    assert fleet.verify_modules(rec) and rec["paquets"][0]["etat"] == "fonctionnel"


def test_un_releve_altere_ne_se_verifie_plus():
    priv, did = _acteur()
    rec = fleet.sign_modules(priv, _champs(did))
    rec["paquets"][0]["etat"] = "erreur"
    assert not fleet.verify_modules(rec)


def test_un_pair_ne_se_fait_pas_passer_pour_un_autre():
    priv, did = _acteur()
    _autre_priv, autre = _acteur()
    rec = fleet.sign_modules(priv, _champs(did))
    rec.update(node_did=autre, issued_by=autre)
    assert not fleet.verify_modules(rec)


@pytest.mark.parametrize("sur", [
    {"paquets": [{**PAQUET, "paquet": "../etc/passwd"}]},
    {"paquets": [{**PAQUET, "etat": "excellent"}]},
    {"paquets": [{**PAQUET, "erreurs": ["x" * 201]}]},
    {"paquets": [{**PAQUET, "unites": [PAQUET["unites"][0]] * 17}]},
    {"paquets": [PAQUET] * 401},
    {"champ_inconnu": 1},
])
def test_modele_borne(sur):
    priv, did = _acteur()
    with pytest.raises(ValidationError):
        fleet.sign_modules(priv, _champs(did, **sur))


def test_un_releve_signe_hors_bornes_est_refuse_a_la_lecture():
    """Un pair malveillant signerait un relevé géant à la main : la lecture le refuse quand même."""
    from annuaire import crypto
    priv, did = _acteur()
    rec = fleet.sign_modules(priv, _champs(did))
    rec["paquets"] = [PAQUET] * 401
    charge = {k: v for k, v in rec.items() if k not in ("sig", "signer_did", "signer_pub")}
    rec["sig"] = crypto.sign(priv, crypto.canonical_bytes(charge))
    assert fleet.verify_snapshot(rec) and not fleet.verify_modules(rec)


# ── publication ───────────────────────────────────────────────────────────────

@pytest.fixture()
def env(tmp_path):
    priv, _pub = generate_keypair()
    (tmp_path / "box.key").write_text(priv.hex())
    (tmp_path / "releve.json").write_text(json.dumps(RELEVE))
    e = os.environ.copy()
    e.update(ANNUAIRE_LIB=str(PKG_ROOT), ANNUAIRE_KEY_PATH=str(tmp_path / "box.key"),
             FLEET_SELF_PATH=str(tmp_path / "self.json"), FLEET_MODULES_PATH=str(tmp_path / "modules.json"),
             SECUBOX_PROFILS_VALIDATION=str(tmp_path / "releve.json"), SECUBOX_CONF=str(tmp_path / "secubox.conf"))
    e.pop("DRYRUN", None)
    return e


def _publier(env):
    r = subprocess.run([sys.executable, str(CLI), "publish-modules"], env=env, capture_output=True, text=True,
                       timeout=20)
    return r.returncode, (json.loads(r.stdout) if r.stdout.strip() else {}), r.stderr


def test_publie_le_releve_signe(env):
    rc, out, err = _publier(env)
    assert rc == 0, err
    rec = json.loads(Path(env["FLEET_MODULES_PATH"]).read_text())
    priv = bytes.fromhex(Path(env["ANNUAIRE_KEY_PATH"]).read_text())
    assert fleet.verify_modules(rec) and rec["node_did"] == did_from_pubkey(public_from_private(priv))
    assert rec["hostname"] == "gk3" and rec["releve_ts"] == RELEVE["releve_ts"] and out["published"] == rec["node_did"]
    assert [p["paquet"] for p in rec["paquets"]] == ["secubox-p2p", "secubox-gitea"]
    assert "cpu_ns" not in rec["paquets"][0] and "releve_epoch" not in rec                # détails internes du relevé


def test_releve_inchange_rien_n_est_resigne(env):
    assert _publier(env)[0] == 0
    avant = Path(env["FLEET_MODULES_PATH"]).read_text()
    rc, out, _ = _publier(env)
    assert rc == 0 and out == {"skipped": "relevé inchangé"} and Path(env["FLEET_MODULES_PATH"]).read_text() == avant


def test_sans_releve_rien_a_publier(env):
    os.remove(env["SECUBOX_PROFILS_VALIDATION"])
    rc, out, _ = _publier(env)
    assert rc == 0 and "skipped" in out and not Path(env["FLEET_MODULES_PATH"]).exists()


def test_releve_corrompu_refuse_proprement(env):
    Path(env["SECUBOX_PROFILS_VALIDATION"]).write_text(json.dumps({**RELEVE, "paquets": [{"paquet": "../x"}]}))
    rc, _out, err = _publier(env)
    assert rc != 0 and "relevé" in err and not Path(env["FLEET_MODULES_PATH"]).exists()


def test_publication_coupee_par_la_config(env, tmp_path):
    (tmp_path / "secubox.conf").write_text("[metrics]\nfleet_publish = false\n")
    rc, out, _ = _publier(env)
    assert rc == 0 and "skipped" in out and not Path(env["FLEET_MODULES_PATH"]).exists()


# ── API ───────────────────────────────────────────────────────────────────────

@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("ANNUAIRE_DIR_SYNC", "0")
    monkeypatch.setenv("FLEET_MODULES_PATH", str(tmp_path / "modules.json"))
    import importlib
    from annuaire import fleet_store as mod
    importlib.reload(mod)
    from fastapi.testclient import TestClient
    from api import main as apimain
    apimain._journal = None
    apimain._DB_PATH = str(tmp_path / "journal.db")
    surcharges = apimain.app.dependency_overrides
    ancienne = surcharges.get(apimain._require_jwt)                # celles des autres tests restent en place
    surcharges[apimain._require_jwt] = lambda: {"sub": "admin"}
    try:
        yield TestClient(apimain.app), apimain
    finally:
        if ancienne is None:
            surcharges.pop(apimain._require_jwt, None)
        else:
            surcharges[apimain._require_jwt] = ancienne
        importlib.reload(mod)


def test_self_rend_le_releve_signe_ou_rien(client, tmp_path):
    tc, _ = client
    assert tc.get("/fleet/modules/self").json() == {}
    priv, did = _acteur()
    rec = fleet.sign_modules(priv, _champs(did))
    fleet_store.write(rec, path=str(tmp_path / "modules.json"))
    assert tc.get("/fleet/modules/self").json() == rec


def test_gardes_des_routes(client):
    tc, apimain = client
    deps = {r.path: [d.call for d in r.dependant.dependencies] for r in tc.app.routes if hasattr(r, "dependant")}
    assert apimain.lecture_ou_pair in deps["/fleet/modules/self"] and apimain._require_jwt not in deps["/fleet/modules/self"]
    assert apimain._require_jwt in deps["/fleet/modules"]


def test_rassemble_soi_et_les_pairs_et_nomme_les_indisponibles(client, tmp_path, monkeypatch):
    tc, apimain = client
    priv, did = _acteur()
    fleet_store.write(fleet.sign_modules(priv, _champs(did, hostname="gk2")), path=str(tmp_path / "modules.json"))
    p3, d3 = _acteur()
    p4, d4 = _acteur()
    gk4 = fleet.sign_modules(p4, _champs(d4, hostname="gk4"))
    gk4["paquets"][0]["etat"] = "erreur"                                              # altéré en route
    reponses = {"10.10.0.5": (fleet.sign_modules(p3, _champs(d3)), None), "10.10.0.9": (gk4, None),
                "10.10.0.8": (None, "version trop ancienne"), "10.10.0.7": (None, "injoignable"),
                "10.10.0.1": (fleet.sign_modules(priv, _champs(did, hostname="gk2")), None)}  # soi, vu comme pair
    monkeypatch.setattr(apimain.mesh_sync, "read_mesh_peers", lambda *a, **k: [
        {"mesh_ip": ip, "name": n} for ip, n in (("10.10.0.5", "secubox-live"), ("10.10.0.9", "gk4"),
                                                 ("10.10.0.8", "gk1"), ("10.10.0.7", "vieux"), ("10.10.0.1", "master"))])
    monkeypatch.setattr(apimain, "_fetch_modules_peer", lambda url, timeout=3: reponses[url.split("/")[2].split(":")[0]])
    d = tc.get("/fleet/modules").json()
    assert sorted(n["hostname"] for n in d["noeuds"]) == ["gk2", "gk3"]               # gk3 sous son vrai nom
    assert all("stale" in n for n in d["noeuds"])
    raisons = {i["nom"]: i["raison"] for i in d["indisponibles"]}
    assert raisons == {"gk4": "signature invalide", "gk1": "version trop ancienne", "vieux": "injoignable"}


def test_releve_pas_encore_publie_et_jamais_de_500(client, monkeypatch):
    tc, apimain = client
    monkeypatch.setattr(apimain.mesh_sync, "read_mesh_peers", lambda *a, **k: [{"mesh_ip": "10.10.0.5", "name": "gk3"}])
    monkeypatch.setattr(apimain, "_fetch_modules_peer", lambda url, timeout=3: ({}, None))
    d = tc.get("/fleet/modules").json()
    assert d["noeuds"] == [] and {i["nom"]: i["raison"] for i in d["indisponibles"]} == {
        "cette box": "relevé non publié", "gk3": "relevé non publié"}

    def panne(*a, **k):
        raise RuntimeError("boum")
    monkeypatch.setattr(apimain.mesh_sync, "read_mesh_peers", panne)
    r = tc.get("/fleet/modules")
    assert r.status_code == 200 and r.json()["erreur"] is True


def test_lecture_d_un_pair_distingue_les_raisons(monkeypatch):
    from api import main as apimain
    import urllib.error
    import urllib.request

    class Rep:
        def __init__(self, corps):
            self.corps = corps

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self, n=-1):
            return self.corps

    def ouvrir(effet):
        def f(req, timeout):
            if isinstance(effet, Exception):
                raise effet
            return Rep(effet)
        return f
    cas = [(urllib.error.HTTPError("u", 404, "nf", {}, None), (None, "version trop ancienne")),
           (urllib.error.URLError("refused"), (None, "injoignable")),
           (b"pas du json", (None, "réponse illisible")),
           (b"[1]", (None, "réponse illisible")),
           (b'{"a": 1}', ({"a": 1}, None))]
    for effet, attendu in cas:
        monkeypatch.setattr(urllib.request, "urlopen", ouvrir(effet))
        assert apimain._fetch_modules_peer("http://10.10.0.5:8799/x") == attendu
