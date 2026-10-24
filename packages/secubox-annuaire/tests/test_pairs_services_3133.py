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
    assert unite.index("offer-sync") < unite.index("pairs-cache")
    assert "annuairectl" in (pkg / "debian" / "rules").read_text(encoding="utf-8")
