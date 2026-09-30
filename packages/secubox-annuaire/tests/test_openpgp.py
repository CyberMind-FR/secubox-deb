# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Clés OpenPGP liées aux box par node.key (#1736)."""
import os

from annuaire import openpgp, verbs
from annuaire.crypto import canonical_bytes, did_from_pubkey, public_from_private, sign
from annuaire.log import Journal
from annuaire.model import Op, OpenPGPBinding

CLE = ("-----BEGIN PGP PUBLIC KEY BLOCK-----\n\n" + "m" * 80 +
       "\n-----END PGP PUBLIC KEY BLOCK-----\n")
EMP_A = "A" * 40
EMP_B = "B" * 40


def _cle():
    priv = os.urandom(32)
    return priv, did_from_pubkey(public_from_private(priv))


def _journal(tmp_path, nom="journal.db"):
    return Journal(str(tmp_path / nom))


def test_liaison_signee_par_node_key_et_lue(tmp_path):
    j = _journal(tmp_path)
    priv, did = _cle()
    verbs.genesis(j, priv)
    e = verbs.openpgp_bind(j, priv, EMP_A.lower(), CLE, creee=1000, expire=0)
    assert e.op == Op.OPENPGP_BIND.value and e.author == did
    assert e.payload["usage"] == "openpgp_bind"
    l = openpgp.liaisons(j.iter_entries())
    assert l[did]["empreinte"] == EMP_A            # normalisée en majuscules
    assert openpgp.empreinte_de(j.iter_entries(), did) == EMP_A


def test_la_derniere_liaison_l_emporte(tmp_path):
    j = _journal(tmp_path)
    priv, did = _cle()
    verbs.genesis(j, priv)
    verbs.openpgp_bind(j, priv, EMP_A, CLE, 1000, 0)
    verbs.openpgp_bind(j, priv, EMP_B, CLE, 2000, 0)
    assert openpgp.empreinte_de(j.iter_entries(), did) == EMP_B


def test_une_liaison_au_nom_d_une_autre_box_ne_vaut_rien(tmp_path):
    """Un pair signe « did = gk2, empreinte = la mienne » avec SA clé :
    authentique, mais elle n'engage que lui."""
    j = _journal(tmp_path)
    priv_a, did_a = _cle()
    priv_b, did_b = _cle()
    verbs.genesis(j, priv_a)
    verbs.genesis(j, priv_b)
    charge = OpenPGPBinding(did=did_a, empreinte=EMP_B, cle_publique=CLE,
                            creee=1, expire=0).model_dump(exclude={"sig", "signer_did"})
    j.append(op=Op.OPENPGP_BIND, payload=charge, payload_type="OpenPGPBinding",
             author=did_b, author_pubkey_hex=public_from_private(priv_b).hex(),
             sig=sign(priv_b, canonical_bytes(charge)))
    assert did_a not in openpgp.liaisons(j.iter_entries())


def test_revocation_definitive_et_expiration(tmp_path):
    j = _journal(tmp_path)
    priv, did = _cle()
    verbs.genesis(j, priv)
    verbs.openpgp_bind(j, priv, EMP_A, CLE, 1000, 0)
    verbs.openpgp_revoke(j, priv, EMP_A, "compromise")
    assert did not in openpgp.liaisons(j.iter_entries())
    verbs.openpgp_bind(j, priv, EMP_A, CLE, 3000, 0)      # la même, re-liée
    assert did not in openpgp.liaisons(j.iter_entries())  # révoquée pour toujours
    verbs.openpgp_bind(j, priv, EMP_B, CLE, 4000, expire=5000)
    assert openpgp.empreinte_de(j.iter_entries(), did, maintenant=4999) == EMP_B
    assert openpgp.empreinte_de(j.iter_entries(), did, maintenant=5000) is None


def test_usage_dans_la_charge_empeche_le_rejeu_sous_un_autre_verbe(tmp_path):
    j = _journal(tmp_path)
    priv, did = _cle()
    verbs.genesis(j, priv)
    e = verbs.openpgp_revoke(j, priv, EMP_A)
    # La charge de révocation, présentée comme une liaison : refusée.
    faux = [{"op": "openpgp_bind", "payload": e.payload, "author": did}]
    assert openpgp.liaisons(faux) == {}


def test_export_import_puis_lecture_verifiee(tmp_path):
    src = _journal(tmp_path, "a.db")
    priv, did = _cle()
    verbs.genesis(src, priv)
    verbs.openpgp_bind(src, priv, EMP_A, CLE, 1000, 0)
    items = verbs.export_entries(src)
    # Lecture directe de l'export, avec vérification de chaque preuve.
    assert openpgp.empreinte_de(items, did, verifier=True) == EMP_A
    # Une signature altérée : l'entrée n'est plus crue.
    alt = [dict(i) for i in items]
    for i in alt:
        if i["op"] == "openpgp_bind":
            i["payload"] = dict(i["payload"], empreinte=EMP_B)
    assert openpgp.empreinte_de(alt, did, verifier=True) is None
    # Import chez un pair : la liaison y arrive.
    dst = _journal(tmp_path, "b.db")
    verbs.import_entries(dst, items)
    assert openpgp.empreinte_de(dst.iter_entries(), did) == EMP_A
