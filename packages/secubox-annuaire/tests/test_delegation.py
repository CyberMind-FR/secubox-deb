# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#1720 : la délégation web vaut tant que la box aidée a consenti deux fois
(session + accord de console), tout signé par ELLE, et pas une seconde de plus."""
from annuaire.assist import delegation_active, sessions_centre

GK3 = "did:plc:" + "3" * 32   # box aidée
GK2 = "did:plc:" + "2" * 32   # centre
PIRATE = "did:plc:" + "9" * 32
MAINT = "2026-09-30T12:00:00Z"
PLUS_TARD = "2026-09-30T14:00:00Z"


def e(op, auteur, **p):
    return {"op": op, "author": auteur, "payload": {"issued_by": auteur, **p}}


def base(**extra):
    return [
        e("assist_session_open", GK3, session_id="s1", center_did=GK2, expires_ts="2026-09-30T13:00:00Z"),
        e("assist_console_grant", GK3, session_id="s1", expires_ts="2026-09-30T12:30:00Z"),
    ]


def test_session_et_accord_ouvrent_la_delegation_jusqu_a_la_plus_proche_echeance():
    assert delegation_active(base(), GK3, GK2, "s1", MAINT) == "2026-09-30T12:30:00Z"
    assert sessions_centre(base(), GK2, MAINT) == [{"box_did": GK3, "session_id": "s1", "fin": "2026-09-30T12:30:00Z"}]


def test_sans_accord_de_console_pas_de_delegation():
    j = base()[:1]
    assert delegation_active(j, GK3, GK2, "s1", MAINT) is None
    assert sessions_centre(j, GK2, MAINT) == []


def test_echue_revoquee_ou_fermee():
    assert delegation_active(base(), GK3, GK2, "s1", PLUS_TARD) is None
    assert delegation_active(base() + [e("assist_console_revoke", GK3, session_id="s1")], GK3, GK2, "s1", MAINT) is None
    assert delegation_active(base() + [e("assist_session_close", GK3, session_id="s1")], GK3, GK2, "s1", MAINT) is None


def test_un_autre_centre_n_en_profite_pas():
    assert delegation_active(base(), GK3, PIRATE, "s1", MAINT) is None
    assert sessions_centre(base(), PIRATE, MAINT) == []


def test_un_pair_ne_peut_ni_ouvrir_ni_prolonger_chez_la_box():
    # Accord signé par un pirate au nom de la box : ignoré.
    forge = [base()[0], {"op": "assist_console_grant", "author": PIRATE,
                         "payload": {"issued_by": GK3, "session_id": "s1", "expires_ts": "2026-09-30T23:00:00Z"}}]
    assert delegation_active(forge, GK3, GK2, "s1", MAINT) is None
    # Session ouverte par le pirate « pour » gk3 : ce n'est pas une session de gk3.
    j = [e("assist_session_open", PIRATE, session_id="s9", center_did=GK2, expires_ts="2026-09-30T13:00:00Z"),
         e("assist_console_grant", PIRATE, session_id="s9", expires_ts="2026-09-30T12:30:00Z")]
    assert delegation_active(j, GK3, GK2, "s9", MAINT) is None
    assert sessions_centre(j, GK2, MAINT) == [{"box_did": PIRATE, "session_id": "s9", "fin": "2026-09-30T12:30:00Z"}]


# ── Assertion d'entrée (annuaire.delegation) ────────────────────────────────
import pytest  # noqa: E402

from annuaire.crypto import did_from_pubkey, generate_keypair, public_from_private  # noqa: E402
from annuaire.delegation import Refus, emettre, verifier  # noqa: E402


def _cle():
    priv, _ = generate_keypair()
    pub = public_from_private(priv)
    return priv, pub.hex(), did_from_pubkey(pub)


def test_assertion_verifiee_par_la_box():
    priv, pub, centre = _cle()
    j = emettre(priv, GK3, "gk2", "s1", now=1000)
    p = verifier(j, self_did=GK3, pubkey_de={centre: pub}.get, now=1010)
    assert p["center_did"] == centre and p["compte"] == "gk2" and p["session_id"] == "s1"


def test_assertion_refusee():
    priv, pub, centre = _cle()
    autre_priv, autre_pub, _ = _cle()
    j = emettre(priv, GK3, "gk2", "s1", now=1000)
    with pytest.raises(Refus):          # pour une autre box
        verifier(j, self_did=GK2, pubkey_de={centre: pub}.get, now=1010)
    with pytest.raises(Refus):          # échue
        verifier(j, self_did=GK3, pubkey_de={centre: pub}.get, now=1200)
    with pytest.raises(Refus):          # centre sans identité publiée
        verifier(j, self_did=GK3, pubkey_de={}.get, now=1010)
    with pytest.raises(Refus):          # clé publiée qui n'est pas celle du centre
        verifier(j, self_did=GK3, pubkey_de={centre: autre_pub}.get, now=1010)
    with pytest.raises(Refus):          # illisible
        verifier("n'importe-quoi", self_did=GK3, pubkey_de={centre: pub}.get, now=1010)


def test_assertion_alteree_refusee():
    import base64, json
    priv, pub, centre = _cle()
    j = emettre(priv, GK3, "gk2", "s1", now=1000)
    corps = json.loads(base64.urlsafe_b64decode(j + "=" * (-len(j) % 4)))
    corps["p"]["compte"] = "admin"      # on se fait passer pour un autre compte
    j2 = base64.urlsafe_b64encode(json.dumps(corps).encode()).decode().rstrip("=")
    with pytest.raises(Refus):
        verifier(j2, self_did=GK3, pubkey_de={centre: pub}.get, now=1010)
