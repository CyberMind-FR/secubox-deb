# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3305 : services du maillage rendus par le fournisseur selon les droits publiés par Auto-Load (abonnement actif + formule)."""
import json

import pytest

from annuaire import droits as D

T0 = 1_800_000_000
JOUR = 86400
TOUS = ["annuaire-offres", "bans-waf"]


@pytest.fixture
def fichiers(tmp_path):
    droits = tmp_path / "droits-maillage.json"
    pairs = tmp_path / "pairs-enroles.json"
    pairs.write_text(json.dumps({"version": 1, "pairs": [
        {"name": "gk5", "mesh_ip": "10.10.0.10", "fingerprint": "sbx-f0ad4e08ab71"},
        {"name": "lgm-ebin", "mesh_ip": "10.10.0.7", "fingerprint": "sb-f0ad4e08ab2a"},
        {"name": "gk4", "mesh_ip": "10.10.0.9", "fingerprint": "sbx-c81b0ece8285"}]}))

    def poser(pairs_droits, grace=T0 + 5 * JOUR):
        droits.write_text(json.dumps({"version": 1, "grace_jusqu_a": grace, "services": TOUS, "pairs": pairs_droits}))
    return droits, pairs, poser


def _dec(fichiers, ip, service, t=T0):
    droits, pairs, _ = fichiers
    return D.decider(ip, service, droits_chemin=droits, pairs_chemin=pairs, maintenant=t)


def test_sans_politique_tout_est_rendu(fichiers):
    assert _dec(fichiers, "10.10.0.10", "bans-waf") == (True, "sans-politique")


def test_pair_atelier_tout_rendu(fichiers):
    fichiers[2]([{"nom": "gk5", "empreinte": "sbx-f0ad4e08ab71", "statut": "actif", "services": TOUS}])
    assert _dec(fichiers, "10.10.0.10", "bans-waf", T0 + 30 * JOUR)[0]


def test_service_non_inclus_refuse(fichiers):
    fichiers[2]([{"nom": "lgm-ebin", "empreinte": None, "statut": "actif", "services": ["annuaire-offres"]}])
    assert _dec(fichiers, "10.10.0.7", "bans-waf", T0 + 30 * JOUR) == (False, "service non inclus")
    assert _dec(fichiers, "10.10.0.7", "annuaire-offres", T0 + 30 * JOUR)[0]


def test_suspendu_refuse_meme_pendant_la_grace(fichiers):
    fichiers[2]([{"nom": "gk4", "empreinte": None, "statut": "suspendu", "services": []}])
    assert _dec(fichiers, "10.10.0.9", "bans-waf") == (False, "abonnement suspendu")


def test_sans_abonnement_grace_puis_coupure(fichiers):
    fichiers[2]([])
    assert _dec(fichiers, "10.10.0.7", "bans-waf", T0 + 4 * JOUR) == (True, "grace")
    assert _dec(fichiers, "10.10.0.7", "bans-waf", T0 + 6 * JOUR) == (False, "sans abonnement")


def test_empreinte_differente_refusee(fichiers):
    fichiers[2]([{"nom": "gk5", "empreinte": "sbx-000000000000", "statut": "actif", "services": TOUS}])
    assert _dec(fichiers, "10.10.0.10", "bans-waf") == (False, "empreinte inattendue")


def test_adresse_inconnue_traitee_comme_sans_abonnement(fichiers):
    fichiers[2]([])
    assert _dec(fichiers, "10.10.0.99", "bans-waf", T0 + 6 * JOUR) == (False, "sans abonnement")


def test_politique_illisible_fermee(fichiers):
    fichiers[0].write_text("{pas du json")
    assert _dec(fichiers, "10.10.0.10", "bans-waf") == (False, "politique illisible")


def test_service_hors_liste_leve(fichiers):
    with pytest.raises(ValueError):
        _dec(fichiers, "10.10.0.10", "tout")
    with pytest.raises(ValueError):
        _dec(fichiers, "10.10.0.10", "openpgp")                                  # pas encore câblé


def test_droits_self(fichiers):
    fichiers[2]([{"nom": "lgm-ebin", "empreinte": None, "statut": "actif", "services": ["annuaire-offres"]}])
    d = D.droits_de(  "10.10.0.7", droits_chemin=fichiers[0], pairs_chemin=fichiers[1], maintenant=T0 + 30 * JOUR)
    assert d == {"politique": True, "services": ["annuaire-offres"]}
    assert D.droits_de("10.10.0.7", droits_chemin=fichiers[0].with_name("x"), pairs_chemin=fichiers[1])["politique"] is False


def test_operations_exclues(fichiers):
    fichiers[2]([{"nom": "lgm-ebin", "empreinte": None, "statut": "actif", "services": ["annuaire-offres"]}])
    ex = D.operations_exclues("10.10.0.7", droits_chemin=fichiers[0], pairs_chemin=fichiers[1], maintenant=T0 + 30 * JOUR)
    assert ex == ("ban_",)
    fichiers[2]([])
    ex = D.operations_exclues("10.10.0.7", droits_chemin=fichiers[0], pairs_chemin=fichiers[1], maintenant=T0 + 30 * JOUR)
    assert set(ex) == {"ban_", "service_"}


def test_filtre_export(fichiers):
    entrees = [{"op": "ban_publish"}, {"op": "service_offer"}, {"op": "node_publish"}, {"op": "config_publish"}]
    assert [e["op"] for e in D.filtrer(entrees, ("ban_", "service_"))] == ["node_publish", "config_publish"]


def test_bans_locaux_seulement_sans_droit(tmp_path):
    cache = tmp_path / "droits-self.json"
    bans = [{"ip": "1.1.1.1", "publisher": "did:plc:" + "a" * 32}, {"ip": "2.2.2.2", "publisher": "did:plc:" + "b" * 32}]
    moi = "did:plc:" + "a" * 32
    assert D.bans_a_appliquer(bans, moi, cache, maintenant=T0) == ["1.1.1.1", "2.2.2.2"]      # jamais de réponse : aucune politique connue
    D.noter_droits_self({"politique": True, "services": ["annuaire-offres"]}, cache, maintenant=T0)
    assert D.bans_a_appliquer(bans, moi, cache, maintenant=T0 + 3600) == ["1.1.1.1"]
    D.noter_droits_self({"politique": True, "services": TOUS}, cache, maintenant=T0)
    assert D.bans_a_appliquer(bans, moi, cache, maintenant=T0 + 3600) == ["1.1.1.1", "2.2.2.2"]
    # réponse trop vieille : le dernier droit connu reste (I2), audité
    audit = tmp_path / "audit.log"
    assert D.bans_a_appliquer(bans, moi, cache, maintenant=T0 + 49 * 3600, audit=audit) == ["1.1.1.1", "2.2.2.2"]
    assert "droits_self_perimes" in audit.read_text()


@pytest.fixture
def api(tmp_path, monkeypatch, fichiers):
    monkeypatch.setenv("ANNUAIRE_DIR_SYNC", "0")
    from fastapi.testclient import TestClient
    from api import main as apimain
    apimain._journal = None
    apimain._DB_PATH = str(tmp_path / "journal.db")
    monkeypatch.setattr(D, "DROITS_DEFAUT", fichiers[0])
    monkeypatch.setattr(D, "PAIRS_DEFAUT", fichiers[1])
    audit = tmp_path / "audit.log"
    monkeypatch.setattr(apimain, "AUDIT_DROITS", audit)
    return TestClient(apimain.app), fichiers[2], audit


def _pair(ip):
    return {"X-SecuBox-Maillage": "1", "X-Real-IP": ip}


def test_services_refuse_au_pair_sans_droit_et_audite(api):
    tc, poser, audit = api
    poser([{"nom": "gk4", "empreinte": None, "statut": "suspendu", "services": []}])
    r = tc.get("/services", headers=_pair("10.10.0.9"))
    assert r.status_code == 403
    assert "droit_maillage_refus" in audit.read_text() and "10.10.0.9" in audit.read_text()


def test_services_rendu_au_pair_atelier(api):
    tc, poser, _ = api
    poser([{"nom": "gk5", "empreinte": None, "statut": "actif", "services": TOUS}])
    assert tc.get("/services", headers=_pair("10.10.0.10")).status_code == 200


def test_export_filtre_les_bans_sans_droit(api):
    tc, poser, _ = api
    poser([{"nom": "lgm-ebin", "empreinte": None, "statut": "actif", "services": ["annuaire-offres"]}], grace=0)
    from annuaire import verbs
    vu = {}

    def faux_export(journal, ops=None):
        vu["ops"] = ops
        return [{"op": "ban_publish"}, {"op": "node_publish"}]
    import pytest as _p
    mp = _p.MonkeyPatch()
    mp.setattr(verbs, "export_entries", faux_export)
    try:
        r = tc.get("/log/export", headers=_pair("10.10.0.7"))
    finally:
        mp.undo()
    assert r.status_code == 200 and [e["op"] for e in r.json()["entries"]] == ["node_publish"]


def test_route_droits_self(api, monkeypatch):
    tc, poser, _ = api
    monkeypatch.setenv("SECUBOX_TABLEAU_DE_BORD", "0")
    poser([{"nom": "gk5", "empreinte": None, "statut": "actif", "services": ["bans-waf"]}])
    r = tc.get("/droits/self", headers=_pair("10.10.0.10"))
    assert r.json() == {"politique": True, "services": ["bans-waf"]}
    assert tc.get("/droits/self").status_code == 401                              # hors écouteur du maillage : gardé


CLE_GK2 = "M" * 43 + "="
PAIRS_MAILLAGE = [{"mesh_ip": "10.10.0.9", "name": "gk4", "public_key": "K" * 43 + "="},
                  {"mesh_ip": "10.10.0.7", "name": "lgm-ebin", "public_key": "L" * 43 + "="},
                  {"mesh_ip": "10.10.0.1", "name": "gk2", "public_key": CLE_GK2}]


def _ancre(tmp_path, nom="gk2", cle=CLE_GK2):
    import hashlib
    a = tmp_path / "ancre-maitre.json"
    a.write_text(json.dumps({"cle_publique": cle, "adresse": "192.168.1.200", "nom": nom,
                             "empreinte": hashlib.sha256(cle.encode()).hexdigest()[:16]}))
    return a


def test_relever_droits_seulement_du_maitre_de_l_ancre(tmp_path):
    from annuaire import mesh_sync
    cache = tmp_path / "droits-self.json"
    vus = []

    def lire(url):
        vus.append(url)
        return {"politique": True, "services": ["annuaire-offres"]}             # un pair quelconque qui prétend avoir une politique
    assert mesh_sync.relever_droits(PAIRS_MAILLAGE, lire, cache, ancre=_ancre(tmp_path)) is True
    assert vus == ["http://10.10.0.1:8799/api/v1/annuaire/droits/self"]
    assert json.loads(cache.read_text())["services"] == ["annuaire-offres"]


def test_relever_droits_sans_ancre_ne_demande_a_personne(tmp_path):
    from annuaire import mesh_sync
    cache = tmp_path / "droits-self.json"
    vus = []
    assert mesh_sync.relever_droits(PAIRS_MAILLAGE, lambda u: vus.append(u) or {"politique": True, "services": []}, cache,
                                    ancre=tmp_path / "absente.json") is False
    assert vus == [] and not cache.exists()


def test_relever_droits_maitre_sans_politique_ne_note_rien(tmp_path):
    from annuaire import mesh_sync
    cache = tmp_path / "droits-self.json"
    assert mesh_sync.relever_droits(PAIRS_MAILLAGE, lambda u: {"politique": False, "services": TOUS}, cache,
                                    ancre=_ancre(tmp_path)) is False
    assert not cache.exists()


def test_noter_droits_self_ne_suit_pas_un_lien(tmp_path):
    cible = tmp_path / "cible"
    cible.write_text("intact")
    lien = tmp_path / "droits-self.json"
    lien.symlink_to(cible)
    D.noter_droits_self({"politique": True, "services": ["bans-waf"]}, lien, maintenant=T0)
    assert cible.read_text() == "intact" and not lien.is_symlink()
    assert json.loads(lien.read_text())["services"] == ["bans-waf"]
    assert oct(lien.stat().st_mode & 0o777) == "0o644"


def test_fail_closed_si_autoload_installe_sans_projection(fichiers, tmp_path):
    droits, pairs, _ = fichiers
    marque = tmp_path / "autoload"
    marque.mkdir()
    assert D.decider("10.10.0.10", "bans-waf", droits, pairs, maintenant=T0, autoload_dir=marque) == (False, "politique absente")
    assert D.droits_de("10.10.0.10", droits, pairs, maintenant=T0, autoload_dir=marque) == {"politique": True, "services": []}
    assert D.decider("10.10.0.10", "bans-waf", droits, pairs, maintenant=T0, autoload_dir=tmp_path / "non")[0]


def test_ecouteur_maillage_sert_droits_self():
    from pathlib import Path
    tpl = (Path(__file__).resolve().parents[1] / "nginx" / "annuaire-mesh.conf.tpl").read_text()
    bloc = tpl.split("location = /api/v1/annuaire/droits/self {", 1)[1].split("\n    }", 1)[0]
    assert "limit_except GET { deny all; }" in bloc and "X-SecuBox-Maillage 1" in bloc


def test_relever_droits_refuse_un_homonyme_sans_la_cle_de_l_ancre(tmp_path):
    from annuaire import mesh_sync
    vus = []
    pairs = [{"mesh_ip": "10.10.0.66", "name": "gk2", "public_key": "Z" * 43 + "="}]         # même nom, autre clé
    assert mesh_sync.relever_droits(pairs, lambda u: vus.append(u) or {"politique": True, "services": []},
                                    tmp_path / "d.json", ancre=_ancre(tmp_path)) is False
    assert vus == []


def test_read_mesh_peers_garde_la_cle(tmp_path):
    from annuaire import mesh_sync
    f = tmp_path / "wg_mesh.json"
    f.write_text(json.dumps({"peers": [{"name": "gk2", "mesh_ip": "10.10.0.1", "public_key": CLE_GK2}]}))
    assert mesh_sync.read_mesh_peers(str(f))[0]["public_key"] == CLE_GK2


def test_peremption_auditee_une_fois_par_jour(tmp_path):
    cache, audit = tmp_path / "droits-self.json", tmp_path / "audit.log"
    D.noter_droits_self({"politique": True, "services": TOUS}, cache, maintenant=T0)
    bans = [{"ip": "1.1.1.1", "publisher": "x"}]
    for h in (49, 50, 60):
        D.bans_a_appliquer(bans, "x", cache, maintenant=T0 + h * 3600, audit=audit)
    assert audit.read_text().count("droits_self_perimes") == 1
    D.bans_a_appliquer(bans, "x", cache, maintenant=T0 + 74 * 3600, audit=audit)
    assert audit.read_text().count("droits_self_perimes") == 2
