# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""Un navigateur retrouve SA demande par sa clé et la renouvelle (#1805)."""
import pytest

from test_acces import DID, _remet_paire, form, paire, signe  # noqa: F401
from api import profileur as P
from api.identite import verifie_signature
from api.profileur import DemandeInvalide, DemandeTropTot, Profileur, did_de_la_cle
from api.session import Portier, SessionRefusee


@pytest.fixture
def prof(tmp_path):
    return Profileur(tmp_path / "demandes.json")


@pytest.fixture
def portier(prof):
    return Portier(prof, verifie_signature)


def _retrouve(portier, priv, did=DID):
    defi = portier.defi_retrouvailles(did)
    return portier.retrouve(did, defi, signe(priv, bytes.fromhex(defi)))


# ── l'identifiant désigne la clé ──────────────────────────────────────────
def test_un_did_qui_ne_designe_pas_la_cle_est_refuse(prof):
    _, pub = paire()
    _, autre = paire()
    with pytest.raises(DemandeInvalide):
        prof.demande({**form(pub), "did": did_de_la_cle(autre)})


def test_on_ne_remplace_plus_la_cle_d_une_demande_connue(prof):
    _, pub = paire()
    prof.demande(form(pub))
    _, voleuse = paire()
    with pytest.raises(DemandeInvalide):
        prof.demande({**form(voleuse), "did": DID})
    assert prof.demande_de(DID).cle_publique == pub


# ── retrouver sans jeton de suivi ─────────────────────────────────────────
def test_la_cle_retrouve_la_demande_et_son_jeton(prof, portier):
    priv, pub = paire()
    d = prof.demande(form(pub))
    v = _retrouve(portier, priv)
    assert v["jeton"] == d.jeton and v["etat"] == "en_attente"


def test_une_autre_cle_ne_retrouve_rien(prof, portier):
    _, pub = paire()
    prof.demande(form(pub))
    voleur, _ = paire()
    with pytest.raises(SessionRefusee):
        _retrouve(portier, voleur)


def test_un_did_inconnu_recoit_un_defi_comme_les_autres(portier):
    voleur, _ = paire()
    defi = portier.defi_retrouvailles("did:sbx:" + "0" * 32)
    assert len(defi) == 64
    with pytest.raises(SessionRefusee):
        portier.retrouve("did:sbx:" + "0" * 32, defi, signe(voleur, bytes.fromhex(defi)))


def test_un_defi_de_retrouvailles_ne_sert_qu_une_fois(prof, portier):
    priv, pub = paire()
    prof.demande(form(pub))
    defi = portier.defi_retrouvailles(DID)
    sig = signe(priv, bytes.fromhex(defi))
    portier.retrouve(DID, defi, sig)
    with pytest.raises(SessionRefusee):
        portier.retrouve(DID, defi, sig)


def test_les_retrouvailles_ne_remplissent_pas_la_table_des_sessions(portier, monkeypatch):
    from api import session as S
    monkeypatch.setattr(S, "DEFIS_RETROUVAILLES_MAX", 3)
    for i in range(3):
        portier.defi_retrouvailles(f"did:sbx:{i:032x}")
    with pytest.raises(SessionRefusee):
        portier.defi_retrouvailles("did:sbx:" + "f" * 32)
    assert portier._defis == {}


def test_admis_la_cle_retrouve_l_acces(prof, portier):
    priv, pub = paire()
    prof.demande(form(pub))
    prof.accepte(DID, par="gerald")
    v = _retrouve(portier, priv)
    assert v["etat"] == "acceptee"
    # …et ce jeton retrouvé ouvre la session comme avant.
    defi = portier.defi(DID, v["jeton"])
    assert portier.ouvre(DID, v["jeton"], defi, signe(priv, bytes.fromhex(defi)))["did"] == DID


# ── renouveler ────────────────────────────────────────────────────────────
def test_renouveler_une_demande_refusee_la_remet_en_attente(prof, monkeypatch):
    _, pub = paire()
    d = prof.demande(form(pub))
    prof.refuse(DID, par="gerald")
    monkeypatch.setattr(P, "RENOUVELLEMENT_DELAI_S", 0)
    v = prof.renouvelle(DID, d.jeton)
    assert v["etat"] == "en_attente"
    n = prof.demande_de(DID)
    assert n.jeton == d.jeton and n.nom == "Gérald" and n.renouvellements == 1
    assert len(prof.en_attente()) == 1, "la même demande, pas une seconde"


def test_renouveler_trop_tot_apres_un_refus(prof):
    _, pub = paire()
    d = prof.demande(form(pub))
    prof.refuse(DID, par="gerald")
    with pytest.raises(DemandeTropTot):
        prof.renouvelle(DID, d.jeton)


def test_renouveler_une_demande_expiree_sans_delai(prof):
    _, pub = paire()
    d = prof.demande(form(pub))
    prof.demande_de(DID).demandee_le -= P.EXPIRATION_S + 10
    assert prof.renouvelle(DID, d.jeton)["etat"] == "en_attente"


def test_renouveler_exige_le_jeton(prof):
    _, pub = paire()
    prof.demande(form(pub))
    assert prof.renouvelle(DID, "faux") is None


def test_renouveler_en_attente_ou_admise_ne_change_rien(prof):
    _, pub = paire()
    d = prof.demande(form(pub))
    assert prof.renouvelle(DID, d.jeton)["etat"] == "en_attente"
    assert prof.demande_de(DID).renouvellements == 0
