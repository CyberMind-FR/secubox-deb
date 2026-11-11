# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3661 — présence certifiée (preuve de possession, transfert vérifié), copies servies aux abonnés, répartition."""
# ruff: noqa: F811 — fixtures pytest importées (cx, api) puis reçues en paramètre
import hashlib
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from test_cycle_3647 import T0, Noeud, abonnement  # noqa: E402
from test_donnees_3653 import api, b2, cx, retrait  # noqa: E402,F401
from test_espace_3659 import _propagation  # noqa: E402

from secubox_mirrornet import catalogue, espace, objets, presence, transfert  # noqa: E402

REG = {"taille_max_mo": 1, "garder": 2, "reserve_mo": 0, "certif_s": 900, "service_simultane": 4}


@pytest.fixture(autouse=True)
def _vierge():
    transfert._REPRISE.clear()
    espace.REFUS.clear()
    presence._DERNIERES.clear()
    yield
    transfert._REPRISE.clear()
    presence._DERNIERES.clear()


def _trio(soi_nom, contenus=(b"v1",)):
    """P producteur (10.10.0.11), G gardien de l'espace (10.10.0.7), A abonné du jeu (10.10.0.9)."""
    p, g, a = Noeud("gk6"), Noeud("gk12"), Noeud("gk2")
    soi = {"p": p, "g": g, "a": a}[soi_nom]
    sid, esp, sub_esp, ex = _propagation(p, g, soi, list(contenus))
    debut = min(T0, datetime.now(timezone.utc)) - timedelta(minutes=1)
    s = a.signe("service_subscribe", dict(abonnement(a, sid)["payload"], requested_at=debut.isoformat()))
    ex["entrees"].append(s)
    ex["noeuds"][a.did] = {"boxname": "gk2", "mesh_ip": "10.10.0.9", "niveau": "LIMITED", "cause": "t"}
    return p, g, a, sid, esp, sub_esp, s["payload"]["subscription_id"], ex


def _flux_ok(contenus, urls):
    def flux(url):
        urls.append(url)
        yield next(c for c in contenus if b2(c) in url)
    return flux


# --- index ---------------------------------------------------------------------------------------------------------

def test_abonne_voit_la_replique_et_l_espace_l_abonne(cx):
    p, g, a, sid, *_r, ex = _trio("a")
    catalogue.synchroniser(cx, ex, T0)
    assert [tuple(r) for r in cx.execute("SELECT gardien_did, producteur_did, etat FROM replique")] == [(g.did, p.did, "Actif")]
    assert cx.execute("SELECT COUNT(*) FROM abonne_relaye").fetchone()[0] == 0           # son propre abonnement


def test_espace_voit_l_abonne_relaye(cx):
    p, g, a, sid, *_r, ex = _trio("g")
    catalogue.synchroniser(cx, ex, T0)
    assert [tuple(r) for r in cx.execute("SELECT abonne_did, etat FROM abonne_relaye")] == [(a.did, "Actif")]


def test_replique_ignoree_si_le_jeu_n_est_pas_au_signataire(cx):
    """Un tiers « confie » le jeu d'un autre à un espace : aucune réplique."""
    p, g, a, sid, esp, _se, _sa, ex = _trio("a")
    x = Noeud("x")
    ex["entrees"] = [e for e in ex["entrees"] if not (e["op"] == "service_subscribe" and e["author"] == p.did)]
    ex["entrees"].append(x.signe("service_subscribe", dict(abonnement(x, esp)["payload"], jeux=[sid])))
    catalogue.synchroniser(cx, ex, T0)
    assert cx.execute("SELECT COUNT(*) FROM replique").fetchone()[0] == 0


# --- répartition (abonné) -----------------------------------------------------------------------------------------------

def test_sources_ordonnees_et_echec_en_dernier(cx):
    p, g, a, *_r, ex = _trio("a")
    catalogue.synchroniser(cx, ex, T0)
    t = transfert.a_tirer(cx)[0]
    s = transfert.sources(cx, a.did, t)
    assert {d for d, _ in s} == {p.did, g.did}
    attendu = sorted([p.did, g.did], key=lambda d: hashlib.sha256(f"{a.did}|{t['empreinte']}|{d}".encode()).hexdigest())
    assert [d for d, _ in s] == attendu
    transfert.noter_presence(cx, attendu[0], t["empreinte"], "transfert", False, "x")
    assert [d for d, _ in transfert.sources(cx, a.did, t)][-1] == attendu[0]


def test_bascule_sur_la_source_suivante_dans_la_meme_passe(cx):
    p, g, a, *_r, ex = _trio("a")
    catalogue.synchroniser(cx, ex, T0)
    t = transfert.a_tirer(cx)[0]
    premier, second = [d for d, _ in transfert.sources(cx, a.did, t)]
    ips = {p.did: "10.10.0.11", g.did: "10.10.0.7"}
    urls = []

    def flux(url):
        urls.append(url)
        if ips[premier] in url:
            raise OSError("503")
        yield b"v1"
    st = transfert.tirer(cx, REG, flux=flux)
    assert st["recues"] == 1 and len(urls) == 2 and ips[second] in urls[1]
    assert cx.execute("SELECT source FROM objet").fetchone()[0] == second
    if premier == g.did:
        assert cx.execute("SELECT statut FROM presence WHERE gardien_did = ?", (g.did,)).fetchone()[0] == "echec"
    else:
        assert cx.execute("SELECT statut FROM presence WHERE gardien_did = ?", (g.did,)).fetchone()[0] == "ok"


def test_replique_qui_ment_est_declassee(cx):
    p, g, a, *_r, ex = _trio("a")
    catalogue.synchroniser(cx, ex, T0)

    def flux(url):
        yield b"faux" if "10.10.0.7" in url else b"v1"
    transfert.tirer(cx, REG, flux=flux)
    assert objets.present(b2(b"v1"))
    r = cx.execute("SELECT statut FROM presence WHERE gardien_did = ? AND mode = 'transfert'", (g.did,)).fetchone()
    # Si le gardien passait en premier, son mensonge est noté ; sinon il n'a pas été sollicité.
    assert r is None or r[0] == "echec"


# --- service des copies (espace) ---------------------------------------------------------------------------------------

def _espace_avec_copie(cx):
    p, g, a, sid, esp, sub_esp, sub_a, ex = _trio("g")
    catalogue.synchroniser(cx, ex, T0)
    espace.propager(cx, REG, flux=_flux_ok([b"v1"], []))
    assert objets.present(b2(b"v1"))
    return p, g, a, sid, esp, sub_esp, sub_a, ex


def test_espace_sert_l_abonne_actif_seulement(cx):
    p, g, a, sid, esp, sub_esp, sub_a, ex = _espace_avec_copie(cx)
    e = b2(b"v1")
    assert transfert.autoriser(cx, "10.10.0.9", e) is None                        # abonné Actif du jeu
    x = Noeud("x")
    ex["noeuds"][x.did] = {"boxname": "x", "mesh_ip": "10.10.0.20", "niveau": "LIMITED", "cause": "t"}
    catalogue.synchroniser(cx, ex, T0)
    assert transfert.autoriser(cx, "10.10.0.20", e) is not None                   # pas abonné
    ex["entrees"].append(a.signe("service_revoke_sub", {"op": "service_revoke_sub", "subscription_id": sub_a,
                                                        "subscriber": a.did, "motif": "", "revoked_at": T0.isoformat()}))
    catalogue.synchroniser(cx, ex, T0)
    assert transfert.autoriser(cx, "10.10.0.9", e) is not None                    # abonnement résilié


def test_espace_ne_sert_plus_si_l_espace_est_clos_ou_la_version_retiree(cx):
    p, g, a, sid, esp, sub_esp, sub_a, ex = _espace_avec_copie(cx)
    e = b2(b"v1")
    ex["entrees"].append(retrait(p, sid, b"v1"))
    catalogue.synchroniser(cx, ex, T0)
    assert transfert.autoriser(cx, "10.10.0.9", e) is not None


def test_espace_clos_ne_sert_plus(cx):
    p, g, a, sid, esp, sub_esp, sub_a, ex = _espace_avec_copie(cx)
    ex["entrees"].append(p.signe("service_revoke_sub", {"op": "service_revoke_sub", "subscription_id": sub_esp,
                                                        "subscriber": p.did, "motif": "", "revoked_at": T0.isoformat()}))
    catalogue.synchroniser(cx, ex, T0)
    assert transfert.autoriser(cx, "10.10.0.9", b2(b"v1")) is not None


# --- preuve de possession ---------------------------------------------------------------------------------------------

def test_preuve_a_l_origine_seulement_et_une_fois_par_minute(cx):
    p, g, a, *_r = _espace_avec_copie(cx)
    e = b2(b"v1")
    assert presence.autoriser_preuve(cx, "10.10.0.11", e) is None                 # le producteur
    assert presence.autoriser_preuve(cx, "10.10.0.11", e) == "trop tôt"
    assert presence.autoriser_preuve(cx, "10.10.0.9", e) is not None              # l'abonné : non
    defi = bytes(range(32))
    assert presence.preuve(e, defi) == hashlib.blake2b(b"v1", digest_size=32, key=defi).hexdigest()


def test_producteur_certifie_ou_constate_l_echec(cx):
    p, g, a, *_r, ex = _trio("p")
    catalogue.synchroniser(cx, ex, T0)
    ee, t = objets.ecrire([b"v1"], 100)
    objets.noter(cx, ee, t, p.did)
    cands = presence.a_certifier(cx, 900)
    assert [(c["gardien"], c["empreinte"]) for c in cands] == [(g.did, ee)]

    def juste(url):
        defi = bytes.fromhex(url.split("defi=")[1])
        return {"preuve": hashlib.blake2b(b"v1", digest_size=32, key=defi).hexdigest()}
    assert presence.certifier(cx, REG, demander=juste) == {"certifiees": 1, "echecs": 0}
    assert presence.a_certifier(cx, 900) == []                                     # pas avant certif_s
    assert presence.certifier(cx, dict(REG, certif_s=0), demander=lambda u: {"preuve": "0" * 64})["echecs"] == 1
    r = cx.execute("SELECT statut, motif FROM presence WHERE mode = 'preuve'").fetchone()
    assert r[0] == "echec" and "fausse" in r[1]

    def muet(url):
        raise OSError("injoignable")
    assert presence.certifier(cx, dict(REG, certif_s=0), demander=muet)["echecs"] == 1


def test_defi_neuf_a_chaque_preuve(cx):
    p, g, a, *_r, ex = _trio("p")
    catalogue.synchroniser(cx, ex, T0)
    ee, t = objets.ecrire([b"v1"], 100)
    objets.noter(cx, ee, t, p.did)
    defis = []

    def note(url):
        defis.append(url.split("defi=")[1])
        raise OSError("x")
    presence.certifier(cx, dict(REG, certif_s=0), demander=note)
    presence.certifier(cx, dict(REG, certif_s=0), demander=note)
    assert len(defis) == 2 and defis[0] != defis[1]


# --- routes ------------------------------------------------------------------------------------------------------------

def test_route_preuve_et_plafond_de_service(api, monkeypatch):
    main, tmp = api
    monkeypatch.setattr(main, "_preuve_maillage", lambda: "ab" * 32)
    P = {"X-SecuBox-Pair-Preuve": "ab" * 32}
    p, g, a, sid, esp, sub_esp, sub_a, ex = _trio("g")
    (tmp / "export.json").write_text(json.dumps(ex))
    main.synchroniser_maintenant()
    cx_ = main._base(ecriture=True)
    try:
        espace.propager(cx_, dict(REG, taille_max_mo=1), flux=_flux_ok([b"v1"], []))
    finally:
        cx_.close()
    c = TestClient(main.app)
    e = b2(b"v1")
    url = f"/pair/preuve/{e}?defi=" + "11" * 32
    assert c.get(url, headers={"X-SecuBox-Pair-IP": "10.10.0.11"}).status_code == 404        # sans preuve nginx
    r = c.get(url, headers=dict(P, **{"X-SecuBox-Pair-IP": "10.10.0.11"}))
    assert r.status_code == 200 and r.json()["preuve"] == hashlib.blake2b(b"v1", digest_size=32, key=b"\x11" * 32).hexdigest()
    assert c.get(url, headers=dict(P, **{"X-SecuBox-Pair-IP": "10.10.0.9"})).status_code == 404
    assert c.get(f"/pair/preuve/{e}?defi=zz", headers=dict(P, **{"X-SecuBox-Pair-IP": "10.10.0.11"})).status_code == 404
    # Copie servie à l'abonné ; plafond atteint : 503, le nœud qui sert décide.
    obj = f"/pair/objets/{e}"
    assert c.get(obj, headers=dict(P, **{"X-SecuBox-Pair-IP": "10.10.0.9"})).content == b"v1"
    assert main._SERVICE == {}                                                  # emplacement rendu après le flux
    import time as _t
    for k in range(4):
        main._SERVICE[1000 + k] = ("10.10.0.%d" % (50 + k), _t.monotonic())
    assert c.get(obj, headers=dict(P, **{"X-SecuBox-Pair-IP": "10.10.0.9"})).status_code == 503
    main._SERVICE.clear()
    # Plafond PAR PAIR : deux transferts en cours de ce pair suffisent.
    main._SERVICE.update({2000: ("10.10.0.9", _t.monotonic()), 2001: ("10.10.0.9", _t.monotonic())})
    assert c.get(obj, headers=dict(P, **{"X-SecuBox-Pair-IP": "10.10.0.9"})).status_code == 503
    # Emplacement périmé (client parti) : repris.
    main._SERVICE.update({2000: ("10.10.0.9", _t.monotonic() - 4000), 2001: ("10.10.0.9", _t.monotonic() - 4000)})
    assert c.get(obj, headers=dict(P, **{"X-SecuBox-Pair-IP": "10.10.0.9"})).status_code == 200
    main._SERVICE.clear()
    # Une preuve déjà en calcul : 503.
    from secubox_mirrornet import presence as pr
    pr._DERNIERES.clear()
    pr.CALCUL.acquire()
    try:
        assert c.get(url, headers=dict(P, **{"X-SecuBox-Pair-IP": "10.10.0.11"})).status_code == 503
    finally:
        pr.CALCUL.release()
    # Jamais par le préfixe d'administration.
    assert c.get(f"/api/v1/mirrornet/pair/preuve/{e}?defi=" + "11" * 32).status_code == 404


def test_lignee_montre_presence_et_repliques(api, monkeypatch):
    main, tmp = api
    p, g, a, sid, *_r, ex = _trio("p")
    (tmp / "export.json").write_text(json.dumps(ex))
    main.synchroniser_maintenant()
    cx_ = main._base(ecriture=True)
    try:
        transfert.noter_presence(cx_, g.did, b2(b"v1"), "preuve", True)
    finally:
        cx_.close()
    lg = TestClient(main.app).get(f"/api/v1/mirrornet/datasets/{sid}/lignee").json()
    assert lg["espaces"][0]["presence"]["statut"] == "ok"


# --- relecture #3661 -------------------------------------------------------------------------------------------------

def test_empreinte_d_un_autre_jeu_jamais_servie(cx):
    """Q déclare dans SON jeu l'empreinte d'un objet que l'espace détient pour P, le confie à l'espace et s'abonne à
    son propre jeu : l'espace ne lui crée pas de copie sans transfert, et ne lui sert rien."""
    p, g, a, sid, esp, sub_esp, sub_a, ex = _espace_avec_copie(cx)
    q = Noeud("q")
    o = q.signe("service_offer", {"service_id": "f" * 32, "provider": q.did, "name": "B", "kind": "dataset",
                                  "endpoint": "x", "scope": {}, "approval_mode": "auto", "description": "", "pac": None,
                                  "created_at": T0.isoformat(), "classe": "public", "tarif": {"modele": "gratuit"}})
    from test_donnees_3653 import version
    debut = (min(T0, datetime.now(timezone.utc)) - timedelta(minutes=1)).isoformat()
    s_esp = q.signe("service_subscribe", dict(abonnement(q, esp)["payload"], requested_at=debut, jeux=["f" * 32],
                                              compat_acceptee={"compat": {"classes": ["public"]}, "quotas": {"octets": 1000}}))
    s_q = q.signe("service_subscribe", dict(abonnement(q, "f" * 32)["payload"], requested_at=debut))
    ex["entrees"] += [o, version(q, "f" * 32, 1, b"v1"), s_esp, s_q]
    ex["noeuds"][q.did] = {"boxname": "q", "mesh_ip": "10.10.0.30", "niveau": "LIMITED", "cause": "t"}
    catalogue.synchroniser(cx, ex, T0)
    urls = []

    def flux(url):                                     # Q ne détient pas les octets : son écouteur ne sert rien
        urls.append(url)
        raise OSError("404")
    espace.propager(cx, REG, flux=flux)
    assert urls and "10.10.0.30" in urls[0]          # tiré chez Q, pas copié d'office
    assert transfert.autoriser(cx, "10.10.0.30", b2(b"v1")) is not None
    assert presence.autoriser_preuve(cx, "10.10.0.30", b2(b"v1")) is not None


def test_specialise_sert_seulement_sous_approbation(cx):
    p, g, a, sid, esp, sub_esp, sub_a, ex = _trio("g")
    o = [e for e in ex["entrees"] if e["op"] == "service_offer" and e["payload"]["service_id"] == sid][0]
    ex["entrees"].append(p.signe("service_offer", dict(o["payload"], approval_mode="auto")))   # offre rééditée
    catalogue.synchroniser(cx, ex, T0)
    cx.execute("UPDATE dataset_version SET classe = 'specialise'")
    espace.propager(cx, REG, flux=_flux_ok([b"v1"], []))
    cx.execute("INSERT OR IGNORE INTO copie SELECT s.id, v.id, v.empreinte, ?, ?, 'x' FROM subscription s, dataset_version v "
               "WHERE s.role = 'fournisseur'", (p.did, p.did))
    objets.ecrire([b"v1"], 100)
    assert transfert.autoriser(cx, "10.10.0.9", b2(b"v1")) is not None


def test_saturation_503_n_est_pas_un_echec_de_presence(cx):
    import urllib.error
    p, g, a, *_r, ex = _trio("a")
    catalogue.synchroniser(cx, ex, T0)

    def flux(url):
        raise urllib.error.HTTPError(url, 503, "plein", {}, None)
        yield b""
    transfert.tirer(cx, REG, flux=flux)
    assert cx.execute("SELECT COUNT(*) FROM presence").fetchone()[0] == 0


def test_datasets_anonyme_sans_source_ni_repliques(api):
    main, tmp = api
    p, g, a, sid, *_r, ex = _trio("a")
    (tmp / "export.json").write_text(json.dumps(ex))
    main.synchroniser_maintenant()
    c = TestClient(main.app)
    d = [x for x in c.get("/api/v1/mirrornet/datasets").json()["datasets"] if x["id"] == sid][0]
    assert d["derniere_version"]["repliques"] == 1
    main.app.dependency_overrides[main.require_lecture] = lambda: {"sub": None}
    d = [x for x in c.get("/api/v1/mirrornet/datasets").json()["datasets"] if x["id"] == sid][0]
    assert "repliques" not in d["derniere_version"] and "recue_de" not in d["derniere_version"]


def test_nouvel_essai_plus_tot_apres_un_echec(cx):
    """Banc #3661 : le premier défi part souvent avant que l'espace ait la copie ; un échec est réessayé après
    RETRY_ECHEC_S, une réussite seulement après certif_s."""
    p, g, a, *_r, ex = _trio("p")
    catalogue.synchroniser(cx, ex, T0)
    ee, t = objets.ecrire([b"v1"], 100)
    objets.noter(cx, ee, t, p.did)
    vieux = (datetime.now(timezone.utc) - timedelta(seconds=presence.RETRY_ECHEC_S + 5)).isoformat()
    transfert.noter_presence(cx, g.did, ee, "preuve", False, "x")
    cx.execute("UPDATE presence SET le = ?", (vieux,))
    assert len(presence.a_certifier(cx, 900)) == 1                     # échec ancien de 3 min : on redemande
    transfert.noter_presence(cx, g.did, ee, "preuve", True)
    cx.execute("UPDATE presence SET le = ?", (vieux,))
    assert presence.a_certifier(cx, 900) == []                         # réussite de 3 min : rien avant 15 min
