# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Lot 2 SBX TV PRIVACY (#3374), passe de correction : garde fermée en cas d'échec, systeme/connectivite protégés,
audit des corrections, portée des corrections, classification en cache."""
import json
import stat
import time
from pathlib import Path

import pytest

from api import dnstv, dnstv_regles as R, dnstv_taxonomie as T
from test_dnstv_ctl_api import api, ctl, monde  # noqa: F401  (fixtures)

LISTES = Path(__file__).resolve().parents[1] / "lists"
MAC = "00:24:d4:00:00:01"
IP = "192.168.1.95"


def taxo(**kw):
    return T.Taxonomie.depuis_dossier(LISTES, **kw)


# ── arbitrages ───────────────────────────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("domaine", ["mafreebox.free.fr", "x.proxad.net", "api.miwifi.com", "accounts.google.com", "www.icloud.com"])
def test_systeme_et_connectivite_sont_proteges(domaine):
    assert T.depuis_ancienne("systeme") == "INCONNU" and T.depuis_ancienne("connectivite") == "INCONNU"
    assert T.refus_auto(taxo(), domaine) is not None


def test_quanteec_inconnu_et_npaw_telemetrie():
    assert taxo().classer("cdn.quanteec.com")["categorie"] == "INCONNU"
    assert taxo().classer("npaw.com")["categorie"] == "TELEMETRIE"


def test_domaine_inconnu_source_aucune():
    c = taxo().classer("rien.example.org")
    assert (c["categorie"], c["source"], c["confiance"]) == ("INCONNU", "aucune", 0)


def test_une_confirmation_automatique_sur_a_ne_leve_pas_la_garde_sur_b():
    r = R.Regles()
    rid = r.proposer("tv-a", "pub-inconnue.example", 50, "faible", 1)["id"]
    r.transiter(rid, "essai", "auto", "essai automatique", 2)
    r.transiter(rid, "confirme", "auto", "essai sans régression", 3)
    assert T.confirmes_par_admin(r) == set()
    assert T.refus_auto(taxo(), "pub-inconnue.example", confirmes_admin=T.confirmes_par_admin(r)) is not None


def test_une_confirmation_admin_leve_la_garde():
    r = R.Regles()
    rid = r.proposer("tv-a", "pub-inconnue.example", 50, "faible", 1, origine="admin")["id"]
    r.transiter(rid, "essai", "admin", "", 2)
    r.transiter(rid, "confirme", "admin", "", 3)
    assert T.confirmes_par_admin(r) == {"pub-inconnue.example"}
    assert T.refus_auto(taxo(), "pub-inconnue.example", confirmes_admin={"pub-inconnue.example"}) is None


def test_l_essai_manuel_d_un_domaine_protege_expire_normalement():
    r = R.Regles()
    rid = r.proposer("tv-banc", "k7.ftven.fr", 50, "faible", 1, origine="admin")["id"]
    r.transiter(rid, "essai", "admin", "", 10)
    r.expirer(10 + R.ESSAI_S + 1)
    assert r.get(rid)["etat"] == "retire"


# ── 1. fermé en cas d'échec ──────────────────────────────────────────────────────────────────────────
def test_corrections_illisibles_sautent_aussi_l_ajout_et_le_profil(monkeypatch, tmp_path):
    from test_dnstv_ajout_moteur import Rep, charger_script, donnees_tv, lancer
    t = int(time.time())
    mod = charger_script(monkeypatch, tmp_path, {"actif": True, "ajout_auto": True, "clients": []})
    donnees_tv(tmp_path, t)
    T.ecrire_manuelles(T.corriger({}, "c.2mdn.net", None, "CDN", t), tmp_path)
    (tmp_path / T.FICHIER).write_text("{abîmé")                                  # la correction CDN n'est plus lisible
    assert lancer(mod, lambda: Rep(), t) == 0
    assert R.charger(tmp_path).actives("tv-fb5b") == []                          # c.2mdn.net n'est pas posé : rien ne l'est
    assert dnstv.lire_etat(tmp_path)[0]["clients"] == []


# ── 2. droits ────────────────────────────────────────────────────────────────────────────────────────
def test_classification_json_en_0640(tmp_path):
    T.ecrire_manuelles(T.corriger({}, "a.example.com", None, "CDN", 1), tmp_path)
    assert stat.S_IMODE((tmp_path / T.FICHIER).stat().st_mode) == 0o640


# ── 4. portée ────────────────────────────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("domaine,cat", [("fr", "PUBLICITE"), ("co.uk", "PUBLICITE"), ("com.fr", "CDN"), ("ftven.fr", "PUBLICITE"),
                                         ("francetelevisions.fr", "TRACKING")])
def test_correction_trop_large_refusee(domaine, cat):
    with pytest.raises(T.ErreurTaxonomie, match="large|public|invalide"):
        T.corriger({}, domaine, None, cat, 1, reference=T.charger_reference(LISTES / "reference-tv.txt"))


def test_correction_vers_protegee_sur_un_parent_permise():
    m = T.corriger({}, "ftven.fr", None, "STREAMING", 1, reference=T.charger_reference(LISTES / "reference-tv.txt"))
    assert m[("", "ftven.fr")]["categorie"] == "STREAMING"


# ── 5. référence ─────────────────────────────────────────────────────────────────────────────────────
def test_reference_rejets_remontes_au_manifeste(tmp_path):
    import hashlib
    for f in LISTES.iterdir():
        (tmp_path / f.name).write_bytes(f.read_bytes())
    ref = tmp_path / "reference-tv.txt"
    ref.write_text(ref.read_text() + "x.example.com TOASTER # mauvais\n")
    man = json.loads((tmp_path / "MANIFEST.json").read_text())
    man["reference-tv.txt"] = hashlib.sha256(ref.read_bytes()).hexdigest()
    (tmp_path / "MANIFEST.json").write_text(json.dumps(man))
    bons, rejets = T.charger_reference_detail(ref)
    assert bons and len(rejets) == 1
    assert any("reference-tv.txt" in p and "TOASTER" in p for p in dnstv.verifier_manifeste(tmp_path))


# ── 3. audit ─────────────────────────────────────────────────────────────────────────────────────────
def _etat_v2(monde):
    dnstv.ecrire_etat({"actif": True, "clients": [{"ip": IP, "nom": "TV banc", "mode": "auto", "mac": MAC}],
                       "schema": 2, "appareils": {MAC: {"nom": "TV banc"}}}, monde["etat"])


def _lignes_audit(monde):
    f = monde["tmp"] / "audit.log"
    return [json.loads(x) for x in f.read_text().splitlines()] if f.exists() else []


@pytest.fixture
def api_audit(api, monde, monkeypatch):
    from api import dnstv_routes as r
    import importlib.machinery
    import importlib.util
    from test_dnstv_ctl_api import CTL

    def ctl_entree(action, entree):
        loader = importlib.machinery.SourceFileLoader("tv_ctl_audit", str(CTL))
        spec = importlib.util.spec_from_loader("tv_ctl_audit", loader)
        m = importlib.util.module_from_spec(spec)
        loader.exec_module(m)
        if m.main(["secubox-adguard-tv", action], entree=entree) != 0:
            raise r.HTTPException(502, "audit refusé")
    monkeypatch.setattr(r, "_ctl_entree", ctl_entree)
    return api


def test_correction_auditee(api_audit, monde):
    _etat_v2(monde)
    assert api_audit.post("/adblock-tv/classification", json={"domaine": "ads.exemple.net", "categorie": "PUBLICITE", "mac": MAC}).status_code == 200
    assert api_audit.post("/adblock-tv/classification", json={"domaine": "ads.exemple.net", "categorie": "TRACKING", "mac": MAC}).status_code == 200
    a = [x for x in _lignes_audit(monde) if x["action"] == "classification"]
    assert len(a) == 2
    assert {"ts", "module", "action", "acteur", "domaine", "mac", "ancienne", "nouvelle"} <= set(a[1])
    assert a[1]["acteur"] == "admin" and a[1]["ancienne"] == "PUBLICITE" and a[1]["nouvelle"] == "TRACKING"
    assert MAC not in json.dumps(a) and a[1]["mac"].startswith("00:24:d4:")


def test_audit_impossible_la_correction_n_est_pas_ecrite(api, monde, monkeypatch):
    from api import dnstv_routes as r
    _etat_v2(monde)

    def echec(action, entree):
        raise r.HTTPException(502, "contrôleur injoignable")
    monkeypatch.setattr(r, "_ctl_entree", echec)
    assert api.post("/adblock-tv/classification", json={"domaine": "a.example.com", "categorie": "CDN"}).status_code == 502
    assert T.charger_manuelles(monde["etat"]) == {}


@pytest.mark.parametrize("entree", ['{"acteur": "admin; rm", "domaine": "a.example.com", "mac": "maison", "ancienne": null, "nouvelle": "CDN"}',
                                    '{"acteur": "admin", "domaine": "a b", "mac": "maison", "ancienne": null, "nouvelle": "CDN"}',
                                    '{"acteur": "admin", "domaine": "a.example.com", "mac": "maison", "ancienne": null, "nouvelle": "TOASTER"}',
                                    '{"acteur": "admin", "domaine": "a.example.com", "mac": "00:24:d4:00:00:01", "ancienne": null, "nouvelle": "CDN"}',
                                    '{"acteur": "admin", "domaine": "a.example.com", "mac": "maison", "ancienne": null, "nouvelle": "CDN", "x": 1}',
                                    'pas du json'])
def test_le_controleur_refuse_un_enregistrement_d_audit_hostile(monde, entree):
    import importlib.machinery
    import importlib.util
    from test_dnstv_ctl_api import CTL
    loader = importlib.machinery.SourceFileLoader("tv_ctl_audit2", str(CTL))
    spec = importlib.util.spec_from_loader("tv_ctl_audit2", loader)
    m = importlib.util.module_from_spec(spec)
    loader.exec_module(m)
    assert m.main(["secubox-adguard-tv", "audit-classification"], entree=entree) != 0
    assert _lignes_audit(monde) == []


def test_sudoers_borne_le_verbe_d_audit():
    s = (Path(__file__).resolve().parents[1] / "sudoers.d" / "secubox-adguard-tv").read_text()
    assert "/usr/sbin/secubox-adguard-tv audit-classification" in s and "*" not in s


# ── 7. cache ─────────────────────────────────────────────────────────────────────────────────────────
def test_classification_sans_cache_rend_vide(api, monde):
    _etat_v2(monde)
    j = api.get("/adblock-tv/classification").json()
    assert j["cache"] is False and j["domaines"] == []


def _remplir_cache(monde):
    _etat_v2(monde)
    t = int(time.time())
    mag = dnstv.Magasin(monde["etat"] / "dnstv.db")
    mag.ajouter([(dnstv.Evenement(t - 50, IP, "k7.ftven.fr", "A", "NOERROR", "ALLOWED"), ""),
                 (dnstv.Evenement(t - 10, IP, "ad.doubleclick.net", "A", "NXDOMAIN", "BLOCKED"), "advertising")])
    etat, _ = dnstv.lire_etat(monde["etat"])
    lignes = T.construire_classification(etat, taxo(), mag.observations(dnstv._jour(t - 86400)), [])
    T.ecrire_cache(lignes, t, monde["etat"])
    return t


def test_cache_0640_et_lecteur_voit_mac_tronquee_et_jour(api, monde):
    t = _remplir_cache(monde)
    assert stat.S_IMODE((monde["etat"] / T.FICHIER_CACHE).stat().st_mode) == 0o640
    j = api.get(f"/adblock-tv/classification?mac={MAC}&categorie=STREAMING").json()
    assert j["cache"] is True and [x["domaine"] for x in j["domaines"]] == ["k7.ftven.fr"]
    x = j["domaines"][0]
    assert MAC not in json.dumps(j) and x["mac"].startswith("00:24:d4:") and x["derniere_observation"] == dnstv._jour(t - 50)
    assert "ips" not in x


def test_detail_complet_en_require_jwt(api, monde):
    t = _remplir_cache(monde)
    j = api.get("/adblock-tv/classification/detail?categorie=PUBLICITE").json()
    x = j["domaines"][0]
    assert x["domaine"] == "ad.doubleclick.net" and x["mac"] == MAC and x["derniere_observation"] == t - 10 and x["ips"] == [IP]
    from secubox_core import auth
    from api import dnstv_routes as r
    gardes = {(y.path, tuple(sorted(y.methods))): {d.call for d in y.dependant.dependencies} for y in r.router.routes}
    assert auth.require_jwt in gardes[("/adblock-tv/classification/detail", ("GET",))]


def test_le_moteur_rafraichit_le_cache(monkeypatch, tmp_path):
    from test_dnstv_ajout_moteur import Rep, charger_script, lancer
    t = int(time.time())
    mod = charger_script(monkeypatch, tmp_path, {"actif": True, "clients": [{"ip": IP, "nom": "TV banc", "mode": "auto", "mac": MAC}]})
    dnstv.Magasin(tmp_path / "dnstv.db").ajouter([(dnstv.Evenement(t - 5, IP, "k7.ftven.fr", "A", "NOERROR", "ALLOWED"), "")])
    assert lancer(mod, lambda: Rep(), t) == 0
    c = T.lire_cache(tmp_path)
    assert c and any(x["domaine"] == "k7.ftven.fr" and x["categorie"] == "STREAMING" for x in c["domaines"])


def test_construire_classification_ajoute_regles_et_corrections_non_observees():
    etat = {"clients": [{"ip": IP, "nom": "TV banc", "mode": "auto", "mac": MAC}]}
    r = R.Regles()
    r.proposer("tv-banc", "regle.example.com", 40, "faible", 1)
    m = T.corriger({}, "maison.example.com", None, "CDN", 1)
    lignes = T.construire_classification(etat, taxo(manuelles=m, regles=r), {}, r.liste())
    cles = {(x["domaine"], x["mac"]) for x in lignes}
    assert ("regle.example.com", MAC) in cles and ("maison.example.com", None) in cles
