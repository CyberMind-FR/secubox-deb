# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>

"""Courtier de jetons applicatifs (#1298).

Le scellé est la pièce maîtresse : un jeton émis pour le téléphone ne doit pas
s'ouvrir sur la tablette, et un scellé ne doit pas pouvoir être présenté comme
celui d'un autre service.
"""
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from api.jetons_app import (Courtier, JetonIndisponible, MinteurNonImplemente)

from secubox_core.crypto import Identity, Session


class MinteurEssai:
    nom = "essai"

    def __init__(self):
        self.emis, self.revoques, self.n = [], [], 0

    def emet(self, utilisateur, etiquette):
        self.n += 1
        self.emis.append((utilisateur, etiquette))
        return f"jeton-secret-{self.n}", f"ref-{self.n}"

    def revoque(self, utilisateur, reference):
        self.revoques.append((utilisateur, reference))
        return True


@pytest.fixture
def boite(tmp_path):
    """La box, avec sa propre identité — c'est elle qui scelle."""
    box = Identity.generate()

    def sceller(cle_pub_hex, charge, aad=b""):
        return Session.establish(box, bytes.fromhex(cle_pub_hex)).encrypt(charge, aad)

    m = MinteurEssai()
    c = Courtier(sceller, minteurs={"essai": m},
                 registre=tmp_path / "jetons.jsonl")
    return c, m, box


def ouvre(appareil, box, scelle, aad=b""):
    return Session.establish(appareil, box.public_bytes()).decrypt(scelle, aad)


# ── Le scellé ────────────────────────────────────────────────────────────────

def test_seul_l_appareil_demandeur_ouvre(boite):
    c, _, box = boite
    tel, tablette = Identity.generate(), Identity.generate()
    aad = b"did:tel|essai|gerald"

    scelle = c.emet(did="did:tel", cle_publique_hex=tel.public_hex(),
                    service="essai", utilisateur="gerald", etiquette="Téléphone")

    clair = json.loads(ouvre(tel, box, scelle, aad))
    assert clair["jeton"] == "jeton-secret-1"

    # LA TABLETTE NE PEUT PAS L'OUVRIR — c'est toute la raison du scellé.
    with pytest.raises(ValueError):
        ouvre(tablette, box, scelle, aad)


def test_le_jeton_clair_ne_sort_jamais_du_courtier(boite):
    c, _, _ = boite
    tel = Identity.generate()
    scelle = c.emet(did="did:tel", cle_publique_hex=tel.public_hex(),
                    service="essai", utilisateur="gerald", etiquette="Téléphone")
    assert b"jeton-secret" not in scelle


def test_l_aad_lie_le_scelle_a_son_contexte(boite):
    # Un scellé pour « essai/gerald » ne doit pas pouvoir être présenté comme
    # celui d'un autre service ou d'un autre compte, même par son destinataire.
    c, _, box = boite
    tel = Identity.generate()
    scelle = c.emet(did="did:tel", cle_publique_hex=tel.public_hex(),
                    service="essai", utilisateur="gerald", etiquette="Tel")
    for faux in [b"did:tel|essai|bob", b"did:tel|autre|gerald", b"did:autre|essai|gerald"]:
        with pytest.raises(ValueError):
            ouvre(tel, box, scelle, faux)


# ── Le registre : de quoi révoquer, jamais le jeton ──────────────────────────

def test_le_registre_ne_contient_aucun_jeton(boite, tmp_path):
    c, _, _ = boite
    tel = Identity.generate()
    c.emet(did="did:tel", cle_publique_hex=tel.public_hex(),
           service="essai", utilisateur="gerald", etiquette="Tel")
    contenu = (tmp_path / "jetons.jsonl").read_text(encoding="utf-8")
    assert "jeton-secret" not in contenu
    assert "ref-1" in contenu          # la référence, elle, doit y être


def test_emis_pour_ne_rend_que_le_bon_appareil(boite):
    c, _, _ = boite
    a, b = Identity.generate(), Identity.generate()
    c.emet(did="did:a", cle_publique_hex=a.public_hex(), service="essai",
           utilisateur="gerald", etiquette="A")
    c.emet(did="did:b", cle_publique_hex=b.public_hex(), service="essai",
           utilisateur="gerald", etiquette="B")
    assert [x["did"] for x in c.emis_pour("did:a")] == ["did:a"]


# ── Révocation ───────────────────────────────────────────────────────────────

def test_revocation_appelle_le_service_et_se_note(boite, tmp_path):
    c, m, _ = boite
    assert c.revoque(did="did:tel", service="essai",
                     utilisateur="gerald", reference="ref-1") is True
    assert m.revoques == [("gerald", "ref-1")]
    assert "REVOQUE:ref-1" in (tmp_path / "jetons.jsonl").read_text(encoding="utf-8")


def test_une_revocation_impossible_ne_ment_pas(tmp_path):
    # Un service qui ne sait pas révoquer doit rendre False et le NOTER comme
    # « à faire à la main ». Un True menteur laisserait croire l'accès coupé.
    def sceller(_c, charge, aad=b""): return charge
    c = Courtier(sceller,
                 minteurs={"x": MinteurNonImplemente("x", "pas câblé")},
                 registre=tmp_path / "j.jsonl")
    assert c.revoque(did="d", service="x", utilisateur="u", reference="r") is False
    assert "REVOCATION-MANUELLE:r" in (tmp_path / "j.jsonl").read_text(encoding="utf-8")


# ── Refus explicites ─────────────────────────────────────────────────────────

def test_service_inconnu_refuse(boite):
    c, _, _ = boite
    tel = Identity.generate()
    with pytest.raises(JetonIndisponible, match="inconnu"):
        c.emet(did="d", cle_publique_hex=tel.public_hex(),
               service="fantome", utilisateur="u", etiquette="E")


def test_service_non_cable_refuse_avec_sa_raison(tmp_path):
    def sceller(_c, charge, aad=b""): return charge
    c = Courtier(sceller,
                 minteurs={"peertube": MinteurNonImplemente("peertube", "à câbler")},
                 registre=tmp_path / "j.jsonl")
    with pytest.raises(JetonIndisponible, match="à câbler"):
        c.emet(did="d", cle_publique_hex="00" * 32, service="peertube",
               utilisateur="u", etiquette="E")
