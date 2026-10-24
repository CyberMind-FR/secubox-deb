# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3133 — le cache fichier des services publics offerts par les AUTRES nœuds du maillage."""
import hashlib
import json
from pathlib import Path

from annuaire import pairs_services
from annuaire.crypto import canonical_bytes, did_from_pubkey, generate_keypair, sign
from annuaire.log import Journal
from annuaire.model import Identity, MemberState, Op
from annuaire.verbs import offer_service, publish_node, revoke_offer


def _membre(j):
    priv, pub = generate_keypair()
    did = did_from_pubkey(pub)
    ident = Identity(did=did, pubkey=pub.hex(), self_cert_digest=hashlib.sha256(pub).hexdigest()[:32], state=MemberState.MEMBER)
    payload = {k: v for k, v in ident.model_dump().items() if k not in ("sig", "signer_did")}
    j.append(op=Op.INVITE_ACCEPT, payload_type="Identity", payload=payload, author=did,
             sig=sign(priv, canonical_bytes(payload)), author_pubkey_hex=pub.hex())
    return priv, did


def _noeud(j, boxname, ddns, ip, enregistrer=True):
    priv, did = _membre(j)
    if enregistrer:
        publish_node(j, priv, did, node_id="sb-" + boxname, boxname=boxname, pubkey_wg="W" * 44, mesh_ip=ip, ddns=ddns)
    return priv, did


def _svc(j, priv, did, nom, endpoint):
    return offer_service(j, priv, did, name=nom, kind="service", endpoint=endpoint,
                         scope={"source": "sync", "channel": "public"}, description="d " + nom)


def test_seules_les_offres_des_autres_dans_leur_domaine_sont_retenues(tmp_path):
    j = Journal(str(tmp_path / "j.db"))
    p_loc, d_loc = _noeud(j, "locale", "loc.exemple.test", "10.10.0.1")
    p_a, d_a = _noeud(j, "alpha", "alpha.exemple.test", "10.10.0.2")
    p_x, d_x = _noeud(j, "inconnu", "x.exemple.test", "10.10.0.3", enregistrer=False)
    _svc(j, p_loc, d_loc, "Local", "https://local.loc.exemple.test")
    _svc(j, p_a, d_a, "Radio", "https://radio.alpha.exemple.test")
    _svc(j, p_a, d_a, "Hors", "https://radio.autre.exemple.test")
    _svc(j, p_a, d_a, "Piege", "https://evil.test/radio.alpha.exemple.test")
    _svc(j, p_a, d_a, "Info", "https://u:p@radio.alpha.exemple.test")
    _svc(j, p_a, d_a, "Port", "https://radio.alpha.exemple.test:8443")
    _svc(j, p_a, d_a, "Clair", "http://clair.alpha.exemple.test")
    _svc(j, p_a, d_a, "Suffixe", "https://xalpha.exemple.test")
    _svc(j, p_x, d_x, "Orphelin", "https://o.x.exemple.test")
    gone = _svc(j, p_a, d_a, "Revoquee", "https://rev.alpha.exemple.test")
    revoke_offer(j, p_a, d_a, gone.service_id)
    r = pairs_services.construire(j, d_loc)
    assert r["version"] == 1 and r["genere"].endswith("Z")
    assert len(r["pairs"]) == 1
    pair = r["pairs"][0]
    assert (pair["did"], pair["boxname"], pair["domaine"], pair["mesh_ip"]) == (d_a, "alpha", "alpha.exemple.test", "10.10.0.2")
    assert pair["services"] == [{"nom": "Radio", "endpoint": "https://radio.alpha.exemple.test", "description": "d Radio"}]


def test_lire_ecrire(tmp_path):
    c = tmp_path / "s.json"
    assert pairs_services.lire(c) is None
    c.write_text("{pas du json")
    assert pairs_services.lire(c) is None
    c.write_text(json.dumps({"version": 2}))
    assert pairs_services.lire(c) is None
    d = {"version": 1, "genere": "x", "pairs": []}
    pairs_services.ecrire(d, c)
    pairs_services.ecrire(d, c)
    assert pairs_services.lire(c) == d
    assert (c.stat().st_mode & 0o777) == 0o644
    assert [p.name for p in tmp_path.iterdir()] == ["s.json"]


def test_le_ctl_et_l_unite_portent_le_verbe():
    pkg = Path(__file__).resolve().parents[1]
    assert '"pairs-cache"' in (pkg / "sbin" / "annuairectl").read_text(encoding="utf-8")
    unite = (pkg / "systemd" / "secubox-annuaire-offres.service").read_text(encoding="utf-8")
    assert "ExecStart=/usr/sbin/annuairectl pairs-cache" in unite
    # pairs-cache EN PREMIER : il ne dépend d'aucune étape locale, et dans ce oneshot un échec d'offres-collecte ou
    # d'offer-sync arrêterait les ExecStart suivants (le cache des services des pairs resterait périmé sans fin)
    execs = [ligne.split("=", 1)[1] for ligne in unite.splitlines() if ligne.startswith("ExecStart=")]
    assert execs == ["/usr/sbin/annuairectl pairs-cache", "+/usr/sbin/annuairectl offres-collecte",
                     "/usr/sbin/annuairectl offer-sync"]
    assert "annuairectl" in (pkg / "debian" / "rules").read_text(encoding="utf-8")


def _noeud_libre(j, boxname, ddns, ip="10.10.0.9"):
    priv, did = _membre(j)
    publish_node(j, priv, did, node_id="sb-x", boxname=boxname, pubkey_wg="W" * 44, mesh_ip=ip, ddns=ddns)
    return priv, did


def _domaines(j, local="loc.exemple.test"):
    _p, d_loc = _noeud_libre(j, "locale", local, "10.10.0.1")
    return [p["domaine"] for p in pairs_services.construire(j, d_loc)["pairs"]]


def _avec_offre(j, boxname, ddns, ip="10.10.0.9"):
    priv, did = _noeud_libre(j, boxname, ddns, ip)
    _svc(j, priv, did, "S", "https://s." + ddns)
    return did


def test_ddns_a_un_seul_libelle_ecarte(tmp_path):
    j = Journal(str(tmp_path / "j.db"))
    _avec_offre(j, "com", "com")
    assert _domaines(j) == []


def test_ddns_syntaxiquement_invalide_ecarte(tmp_path):
    for mauvais in ("a..exemple.test", "-a.exemple.test", "a-.exemple.test", "a.exemple.test-"):
        j = Journal(str(tmp_path / (str(abs(hash(mauvais))) + ".db")))
        _avec_offre(j, "x", mauvais)
        assert _domaines(j) == [], mauvais


def test_ddns_revendique_par_deux_did_ecarte(tmp_path):
    j = Journal(str(tmp_path / "j.db"))
    _avec_offre(j, "un", "double.exemple.test", "10.10.0.2")
    _avec_offre(j, "deux", "double.exemple.test", "10.10.0.3")
    _avec_offre(j, "ok", "ok.exemple.test", "10.10.0.4")
    assert _domaines(j) == ["ok.exemple.test"]


def test_ddns_local_ou_son_parent_ecarte(tmp_path):
    j = Journal(str(tmp_path / "j.db"))
    _avec_offre(j, "egal", "loc.exemple.test", "10.10.0.2")
    _avec_offre(j, "parent", "exemple.test", "10.10.0.3")
    assert _domaines(j) == []


def test_ddns_parent_ambigu_ecarte_pas_les_enfants(tmp_path):
    j = Journal(str(tmp_path / "j.db"))
    _avec_offre(j, "parent", "exemple.test", "10.10.0.2")
    _avec_offre(j, "enfant", "gk3.exemple.test", "10.10.0.3")
    assert _domaines(j, local="zz.autre.test") == ["gk3.exemple.test"]


def test_mesh_ip_invalide_ou_ipv6_ecarte_et_boxname_strict(tmp_path):
    j = Journal(str(tmp_path / "j.db"))
    _avec_offre(j, "a", "a.exemple.test", "pas une ip")
    _avec_offre(j, "b", "b.exemple.test", "fd00::1")
    _avec_offre(j, "Mauvais Nom", "c.exemple.test", "10.10.0.5")
    _p, d_loc = _noeud_libre(j, "locale", "loc.exemple.test", "10.10.0.1")
    pairs = pairs_services.construire(j, d_loc)["pairs"]
    assert [(p["domaine"], p["boxname"], p["mesh_ip"]) for p in pairs] == [("c.exemple.test", "", "10.10.0.5")]


def _ctl():
    from importlib.machinery import SourceFileLoader
    from importlib.util import module_from_spec, spec_from_loader
    chemin = str(Path(__file__).resolve().parents[1] / "sbin" / "annuairectl")
    spec = spec_from_loader("annuairectl_t", SourceFileLoader("annuairectl_t", chemin))
    m = module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def _env(tmp_path, monkeypatch):
    ctl = _ctl()
    priv, pub = generate_keypair()
    cle = tmp_path / "node.key"
    cle.write_text(priv.hex())
    monkeypatch.setattr(ctl, "DB_PATH", str(tmp_path / "journal.db"))
    monkeypatch.setattr(ctl, "KEY_PATH", str(cle))
    monkeypatch.setattr(pairs_services, "CACHE_PATH", tmp_path / "cache.json")
    return ctl


def test_pairs_cache_journal_absent_laisse_l_ancien_cache(tmp_path, monkeypatch):
    import pytest
    ctl = _env(tmp_path, monkeypatch)
    ancien = b'{"version": 1, "genere": "ancien", "pairs": []}\n'
    (tmp_path / "cache.json").write_bytes(ancien)
    with pytest.raises(SystemExit) as e:
        ctl.cmd_pairs_cache(None)
    assert e.value.code != 0
    assert (tmp_path / "cache.json").read_bytes() == ancien
    assert not (tmp_path / "journal.db").exists()


def test_pairs_cache_journal_corrompu_laisse_l_ancien_cache(tmp_path, monkeypatch):
    import pytest
    ctl = _env(tmp_path, monkeypatch)
    (tmp_path / "journal.db").write_bytes(b"ceci n'est pas une base sqlite" * 50)
    (tmp_path / "cache.json").write_bytes(b'{"version": 1, "pairs": []}')
    with pytest.raises(SystemExit) as e:
        ctl.cmd_pairs_cache(None)
    assert e.value.code != 0
    assert (tmp_path / "cache.json").read_bytes() == b'{"version": 1, "pairs": []}'


def test_pairs_cache_succes(tmp_path, monkeypatch):
    ctl = _env(tmp_path, monkeypatch)
    j = Journal(str(tmp_path / "journal.db"))
    priv, did = _noeud_libre(j, "alpha", "alpha.exemple.test", "10.10.0.2")
    _svc(j, priv, did, "Radio", "https://radio.alpha.exemple.test")
    assert ctl.cmd_pairs_cache(None) == 0
    d = pairs_services.lire(tmp_path / "cache.json")
    assert d and d["pairs"][0]["services"][0]["nom"] == "Radio"
