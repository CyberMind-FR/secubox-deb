# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3021 — les offres de services de l'Annuaire viennent des VRAIS services de la box, et se tiennent à jour."""
import json
from pathlib import Path

from annuaire import offres
from annuaire.crypto import generate_keypair
from annuaire.log import Journal
from annuaire.verbs import _get_offers, genesis, offer_service

HALL = """
const AUTRE = 1;
const FEATURED = [
  {id:"securite",   label:"Sécurité",   icon:"🛡️", color:"#2e7d5b", url:"waf.gk2.secubox.in", carte:"/c.html", h:238, auth:true, admin:"/waf/"},
  // un commentaire avec des accolades {id:"piege", label:"Piège", url:"piege.gk2.secubox.in"}
  {id:"radio",      label:"Radio",      icon:"📻", color:"#111", url:"radio.gk2.secubox.in", carte:"/r.html", h:200},
  {id:"podcaster",  label:"Podcasts",   icon:"🎙️", color:"#222", url:"https://podcaster.gk2.secubox.in/", h:200},
  {id:"sans-url",   label:"Sans URL",   icon:"x", color:"#333", carte:"/x.html"},
  {id:"doublon",    label:"Doublon",    icon:"x", color:"#333", url:"radio.gk2.secubox.in"},
  {id:"mauvais",    label:"Mauvais",    icon:"x", color:"#333", url:"pas un hôte"},
];
const APRES = [{id:"nope", label:"Nope", url:"nope.example"}];
"""


def test_les_cartes_publiques_du_hall_deviennent_des_offres_app():
    o = offres.cartes_du_hall(HALL)
    assert [(x["name"], x["endpoint"]) for x in o] == [("Radio", "https://radio.gk2.secubox.in/"), ("Podcasts", "https://podcaster.gk2.secubox.in/")]
    assert all(x["kind"] == "app" and x["scope"]["source"] == "sync" and x["scope"]["channel"] == "public" for x in o)
    assert offres.cartes_du_hall("pas de curation") == []


def test_les_onions_viennent_des_dossiers_de_tor(tmp_path):
    tor = tmp_path / "hidden_services"
    (tor / "webui").mkdir(parents=True)
    (tor / "webui" / "hostname").write_text("3kdlpa3gegxallkk3qbm4vim5higxw4luammi6kubc2ew6mfsc2fayad.onion\n")
    (tor / "casse").mkdir()
    (tor / "casse" / "hostname").write_text("pas-un-onion\n")
    (tor / "vide").mkdir()
    o = offres.onions(tor)
    assert len(o) == 1 and o[0]["kind"] == "onion" and o[0]["name"] == "webui (onion)"
    assert o[0]["endpoint"] == "http://3kdlpa3gegxallkk3qbm4vim5higxw4luammi6kubc2ew6mfsc2fayad.onion/"
    assert o[0]["scope"] == {"source": "sync", "channel": "tor", "onion": "3kdlpa3gegxallkk3qbm4vim5higxw4luammi6kubc2ew6mfsc2fayad.onion", "service": "webui"}
    assert offres.onions(tmp_path / "absent") == []


def test_le_depot_apt_exige_le_module_et_le_vhost(tmp_path):
    toml = tmp_path / "haproxy.toml"
    toml.write_text('[vhosts.x]\ndomain = "x.gk2.secubox.in"\n[vhosts.apt]\ndomain = "apt.secubox.in"\n')
    marqueur = tmp_path / "repo"
    assert offres.depot_apt(toml, marqueur) == []            # module absent
    marqueur.mkdir()
    o = offres.depot_apt(toml, marqueur)
    assert o and o[0]["kind"] == "repo" and o[0]["endpoint"] == "https://apt.secubox.in/"
    toml.write_text('[vhosts.x]\ndomain = "x.gk2.secubox.in"\n')
    assert offres.depot_apt(toml, marqueur) == []            # pas de vhost apt


def test_collecte_et_fichier_de_faits(tmp_path):
    hall = tmp_path / "index.html"
    hall.write_text(HALL)
    tor = tmp_path / "hs"
    (tor / "webui").mkdir(parents=True)
    (tor / "webui" / "hostname").write_text("3kdlpa3gegxallkk3qbm4vim5higxw4luammi6kubc2ew6mfsc2fayad.onion\n")
    faits = offres.collecter_faits(tor_dir=tor, hall_index=hall, haproxy_toml=tmp_path / "absent.toml", repo_marqueur=tmp_path / "absent")
    assert [f["kind"] for f in faits] == ["app", "app", "onion"]        # ordre stable : genre puis endpoint
    chemin = tmp_path / "faits.json"
    offres.ecrire_faits(faits, chemin)
    assert offres.lire_faits(chemin) == faits
    assert offres.lire_faits(tmp_path / "absent.json") is None
    chemin.write_text("{pas du json")
    assert offres.lire_faits(chemin) is None


def test_la_synchronisation_publie_revoque_et_laisse_les_offres_manuelles(tmp_path):
    j = Journal(str(tmp_path / "j.db"))
    priv, _pub = generate_keypair()
    ident = genesis(j, priv)
    manuelle = offer_service(j, priv, ident.did, name="WAF mirror", kind="module", endpoint="http://10.10.0.1/api/v1/waf")
    faits = [{"name": "Radio", "kind": "app", "endpoint": "https://radio.gk2.secubox.in/", "description": "", "scope": {"source": "sync", "channel": "public"}},
             {"name": "webui (onion)", "kind": "onion", "endpoint": "http://abc.onion/", "description": "", "scope": {"source": "sync"}}]
    r = offres.synchroniser(j, priv, ident.did, faits)
    assert {p["name"] for p in r["publies"]} == {"Radio", "webui (onion)"} and r["revoques"] == [] and r["inchangees"] == 0
    # Idempotent.
    r2 = offres.synchroniser(j, priv, ident.did, faits)
    assert r2["publies"] == [] and r2["revoques"] == [] and r2["inchangees"] == 2
    # L'onion disparaît : son offre est révoquée ; l'offre manuelle reste.
    r3 = offres.synchroniser(j, priv, ident.did, faits[:1])
    assert [x["name"] for x in r3["revoques"]] == ["webui (onion)"]
    vivantes = {o["name"]: o for o in _get_offers(j)}
    assert set(vivantes) == {"WAF mirror", "Radio"}
    assert vivantes["WAF mirror"]["service_id"] == manuelle.service_id
    assert vivantes["Radio"]["scope"]["source"] == "sync" and vivantes["Radio"]["approval_mode"] == "auto"


def test_le_ctl_et_l_unite_portent_les_verbes():
    pkg = Path(__file__).resolve().parents[1]
    ctl = (pkg / "sbin" / "annuairectl").read_text(encoding="utf-8")
    for verbe in ('"offres-collecte"', '"offer-sync"', '"revoke-offer"'):
        assert verbe in ctl, verbe
    unite = (pkg / "systemd" / "secubox-annuaire-offres.service").read_text(encoding="utf-8")
    assert "ExecStart=+/usr/sbin/annuairectl offres-collecte" in unite
    assert "ExecStart=/usr/sbin/annuairectl offer-sync" in unite and "User=secubox" in unite
    minuterie = (pkg / "systemd" / "secubox-annuaire-offres.timer").read_text(encoding="utf-8")
    assert "OnActiveSec=" in minuterie and "OnUnitActiveSec=" in minuterie and "Persistent=true" in minuterie
    rules = (pkg / "debian" / "rules").read_text(encoding="utf-8")
    assert "secubox-annuaire-offres.service" in rules and "secubox-annuaire-offres.timer" in rules
    assert json.loads("{}") == {}
