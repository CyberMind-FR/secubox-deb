# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>

"""Le profileur : file d'invitation et profils (#1297)."""
import sys, time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from api.invitations import (Demande, DemandeInvalide, Profileur,
                             empreinte_courte, valide_demande)

CLE = "a" * 64
DID = "did:plc:abcdefgh1234"


def form(**kw):
    d = {"did": DID, "cle_publique": CLE, "nom": "Gérald",
         "message": "je voudrais entrer", "appareil": "iPhone"}
    d.update(kw)
    return d


@pytest.fixture
def prof(tmp_path):
    crees = []
    p = Profileur(tmp_path / "invitations.json",
                  creer_compte=lambda n, pr, did: crees.append((n, pr, did)))
    return p, crees


# ── L'empreinte remplace le QR code ──────────────────────────────────────────

def test_empreinte_lisible_et_stable():
    e = empreinte_courte(CLE)
    assert e == empreinte_courte(CLE)             # stable
    assert len(e.split()) == 6                    # six groupes, comparables à l'œil
    assert empreinte_courte("b" * 64) != e        # discriminante


# ── Validation du formulaire ─────────────────────────────────────────────────

@pytest.mark.parametrize("mauvais,attendu", [
    ({"did": "pasundid"}, "appareil"),
    ({"cle_publique": "zz"}, "clé publique"),
    ({"nom": ""}, "nom"),
    ({"nom": "x" * 61}, "nom"),
])
def test_formulaire_refuse_avec_un_message_utile(mauvais, attendu):
    with pytest.raises(DemandeInvalide, match=attendu):
        valide_demande(form(**mauvais))


def test_les_champs_libres_sont_bornes():
    d = valide_demande(form(message="m" * 5000, appareil="a" * 500))
    assert len(d.message) == 500 and len(d.appareil) == 60


# ── Une demande par appareil ─────────────────────────────────────────────────

def test_redemander_met_a_jour_au_lieu_d_empiler(prof):
    p, _ = prof
    p.demande(form(message="premier"))
    p.demande(form(message="second"))
    attente = p.en_attente()
    assert len(attente) == 1 and attente[0]["message"] == "second"


def test_un_deja_admis_ne_recree_pas_de_demande(prof):
    p, _ = prof
    p.demande(form())
    p.accepte(DID, par="admin")
    d = p.demande(form(message="encore"))
    assert d.etat == "acceptee"
    assert p.en_attente() == []


# ── Admission ────────────────────────────────────────────────────────────────

def test_admission_donne_user_et_cree_le_compte(prof):
    p, crees = prof
    p.demande(form())
    d = p.accepte(DID, par="gerald")
    assert d.profil == "user" and d.etat == "acceptee"
    assert crees == [("Gérald", "user", DID)]
    assert p.profil_de(DID) == "user"


def test_l_admission_ne_fabrique_JAMAIS_un_admin(prof):
    # La règle la plus importante du fichier : promouvoir est un geste à part.
    p, _ = prof
    p.demande(form())
    with pytest.raises(DemandeInvalide, match="promouvoir"):
        p.accepte(DID, par="gerald", profil="admin")
    assert p.profil_de(DID) == "guest"   # rien n'a bougé


def test_on_ne_traite_pas_deux_fois(prof):
    p, _ = prof
    p.demande(form()); p.accepte(DID, par="a")
    with pytest.raises(DemandeInvalide, match="déjà"):
        p.accepte(DID, par="a")
    with pytest.raises(DemandeInvalide, match="déjà"):
        p.refuse(DID, par="a")


# ── Promotion et révocation ──────────────────────────────────────────────────

def test_promotion_vers_admin_possible_APRES_admission(prof):
    p, _ = prof
    p.demande(form()); p.accepte(DID, par="a")
    p.promeut(DID, vers="admin", par="a")
    assert p.profil_de(DID) == "admin"


def test_on_ne_promeut_pas_un_non_admis(prof):
    p, _ = prof
    p.demande(form())
    with pytest.raises(DemandeInvalide, match="aucun accès"):
        p.promeut(DID, vers="admin", par="a")


def test_revocation_garde_la_trace(prof):
    p, _ = prof
    p.demande(form()); p.accepte(DID, par="a")
    p.revoque(DID, par="a")
    assert p.profil_de(DID) == "guest"
    # La demande n'est pas effacée : un appareil écarté ne doit pas revenir
    # sans que personne ne s'en souvienne.
    assert p._demandes[DID].motif_refus == "accès révoqué"


# ── Ce que chacun a le droit de savoir ───────────────────────────────────────

def test_le_demandeur_ne_voit_ni_le_motif_ni_qui_a_tranche(prof):
    p, _ = prof
    p.demande(form())
    j = p._demandes[DID].jeton
    p.refuse(DID, par="gerald", motif="compte en double")
    vue = p.suivi(DID, j)
    assert vue["etat"] == "refusee"
    assert "motif_refus" not in vue and "traitee_par" not in vue


def test_le_suivi_exige_le_bon_jeton(prof):
    p, _ = prof
    p.demande(form())
    assert p.suivi(DID, "mauvais-jeton") is None
    assert p.suivi(DID, p._demandes[DID].jeton) is not None


def test_la_vue_admin_ne_divulgue_pas_le_jeton_de_suivi(prof):
    p, _ = prof
    p.demande(form())
    assert "jeton" not in p.en_attente()[0]


# ── Expiration et persistance ────────────────────────────────────────────────

def test_une_demande_oubliee_expire(prof):
    p, _ = prof
    p.demande(form())
    p._demandes[DID].demandee_le = int(time.time()) - 30 * 24 * 3600
    assert p.en_attente() == []
    assert p._demandes[DID].etat == "expiree"


def test_la_file_survit_au_redemarrage(tmp_path):
    chemin = tmp_path / "inv.json"
    a = Profileur(chemin)
    a.demande(form())
    a.accepte(DID, par="gerald")
    b = Profileur(chemin)          # nouveau processus
    assert b.profil_de(DID) == "user"


def test_une_entree_corrompue_ne_perd_pas_les_autres(tmp_path):
    chemin = tmp_path / "inv.json"
    p = Profileur(chemin)
    p.demande(form())
    brut = chemin.read_text(encoding="utf-8").replace(
        '"demandes": [', '"demandes": [{"casse": true}, ', 1)
    chemin.write_text(brut, encoding="utf-8")
    assert Profileur(chemin).profil_de(DID) == "guest"   # pas d'exception
