# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Tests du parcours d'accès (#1344)."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils as asym_utils

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from api.identite import (CleInvalide, charge_cle, empreinte_courte,  # noqa: E402
                          nom_de_compte, verifie_signature)
from api.profileur import DemandeInvalide, Profileur  # noqa: E402
from api.session import Portier, SessionRefusee  # noqa: E402

DID = "did:sbx:appareil-de-test-0001"


def paire():
    """Une paire P-256, et sa publique au format que rend WebCrypto."""
    priv = ec.generate_private_key(ec.SECP256R1())
    pub = priv.public_key().public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.UncompressedPoint)
    return priv, pub.hex()


def signe(priv, message: bytes) -> str:
    """Signe comme le fait WebCrypto : `r ‖ s`, PAS du DER."""
    der = priv.sign(message, ec.ECDSA(hashes.SHA256()))
    r, s = asym_utils.decode_dss_signature(der)
    return (r.to_bytes(32, "big") + s.to_bytes(32, "big")).hex()


@pytest.fixture
def prof(tmp_path):
    return Profileur(tmp_path / "demandes.json")


def form(cle):
    return {"did": DID, "cle_publique": cle, "nom": "Gérald",
            "appareil": "Portable", "message": "bonjour"}


# ── L'identité ──────────────────────────────────────────────────────────────

def test_une_cle_hors_courbe_est_refusee():
    """Un point BIEN FORMÉ mais hors courbe passerait un filtre de forme et ne
    vérifierait jamais aucune signature. On le refuse à l'entrée, quand on peut
    encore le dire au demandeur."""
    faux = "04" + "11" * 64
    with pytest.raises(CleInvalide):
        charge_cle(faux)


def test_empreinte_stable_et_lisible():
    _, pub = paire()
    e = empreinte_courte(pub)
    assert e == empreinte_courte(pub)              # stable
    assert len(e.split(" ")) == 6                  # six groupes
    assert all(len(g) == 4 for g in e.split(" "))  # de quatre


def test_signature_webcrypto_verifiee():
    """WebCrypto rend `r ‖ s` et `cryptography` attend du DER — c'est l'erreur
    d'appariement classique entre les deux mondes."""
    priv, pub = paire()
    msg = bytes.fromhex("ab" * 32)
    assert verifie_signature(pub, msg, signe(priv, msg)) is True
    # Signature d'un AUTRE message : refusée.
    assert verifie_signature(pub, b"autre chose", signe(priv, msg)) is False
    # Signature d'une AUTRE clé : refusée.
    autre, _ = paire()
    assert verifie_signature(pub, msg, signe(autre, msg)) is False
    # Format douteux : refusé sans lever.
    assert verifie_signature(pub, msg, "pas du hex") is False


# ── La file ─────────────────────────────────────────────────────────────────

def test_admission_ouvre_un_acces_guest(prof):
    _, pub = paire()
    prof.demande(form(pub))
    d = prof.accepte(DID, par="gerald")
    assert d.profil == "guest" and d.etat == "acceptee"


def test_admission_n_offre_aucun_choix_de_profil(prof):
    """Plus fort qu'un contrôle qui refuserait `admin` : il n'y a rien à
    contrôler."""
    _, pub = paire()
    prof.demande(form(pub))
    with pytest.raises(TypeError):
        prof.accepte(DID, par="gerald", profil="admin")
    assert prof.accepte(DID, par="gerald").profil == "guest"


def test_la_cle_bidon_de_la_v1_est_refusee(prof):
    """LA RÉGRESSION QU'ON NE VEUT PAS REVOIR. La première version envoyait 32
    octets aléatoires en guise de clé publique ; l'empreinte comparée par
    l'administrateur n'engageait donc personne."""
    with pytest.raises(DemandeInvalide, match="P-256|courbe"):
        prof.demande(form("ab" * 32))


# ── La session ──────────────────────────────────────────────────────────────

@pytest.fixture
def portier(prof):
    return Portier(prof, verifie_signature)


def admis(prof):
    priv, pub = paire()
    d = prof.demande(form(pub))
    prof.accepte(DID, par="gerald")
    return priv, d.jeton


def test_le_parcours_complet_ouvre_une_session(prof, portier):
    """LE CHAÎNON QUI MANQUAIT : la file savait dire « accepté », personne
    n'ouvrait la porte."""
    priv, jeton = admis(prof)
    defi = portier.defi(DID, jeton)
    ouvert = portier.ouvre(DID, jeton, defi, signe(priv, bytes.fromhex(defi)))
    assert ouvert["profil"] == "guest" and ouvert["nom"] == "Gérald"


def test_un_jeton_sans_la_cle_n_ouvre_rien(prof, portier):
    """Le jeton de suivi voyage et s'affiche. S'il suffisait, quiconque le
    lirait entrerait à la place du demandeur — et l'empreinte comparée par
    l'administrateur n'aurait servi à rien."""
    _, jeton = admis(prof)
    defi = portier.defi(DID, jeton)
    voleur, _ = paire()
    with pytest.raises(SessionRefusee):
        portier.ouvre(DID, jeton, defi, signe(voleur, bytes.fromhex(defi)))


def test_un_defi_ne_sert_qu_une_fois(prof, portier):
    priv, jeton = admis(prof)
    defi = portier.defi(DID, jeton)
    portier.ouvre(DID, jeton, defi, signe(priv, bytes.fromhex(defi)))
    with pytest.raises(SessionRefusee):
        portier.ouvre(DID, jeton, defi, signe(priv, bytes.fromhex(defi)))


def test_une_signature_fausse_consomme_le_defi(prof, portier):
    """Sinon l'attaquant dispose d'autant de tentatives qu'il veut sur la même
    cible : il rejouerait le défi jusqu'à tomber juste."""
    priv, jeton = admis(prof)
    defi = portier.defi(DID, jeton)
    voleur, _ = paire()
    with pytest.raises(SessionRefusee):
        portier.ouvre(DID, jeton, defi, signe(voleur, bytes.fromhex(defi)))
    # Même avec la BONNE clé, le défi est mort.
    with pytest.raises(SessionRefusee):
        portier.ouvre(DID, jeton, defi, signe(priv, bytes.fromhex(defi)))


def test_pas_de_defi_sans_admission(prof, portier):
    _, pub = paire()
    d = prof.demande(form(pub))          # déposée, pas acceptée
    with pytest.raises(SessionRefusee):
        portier.defi(DID, d.jeton)


def test_la_revocation_ferme_la_porte(prof, portier):
    priv, jeton = admis(prof)
    prof.revoque(DID, par="gerald")
    with pytest.raises(SessionRefusee):
        portier.defi(DID, jeton)


def test_la_session_se_note(prof, portier):
    """Un accès accordé dont personne n'a jamais rien fait est un parcours
    resté en plan — et c'est précisément ce qu'on ne voyait pas."""
    priv, jeton = admis(prof)
    assert prof.suivi(DID, jeton)["session_ouverte"] is False
    defi = portier.defi(DID, jeton)
    portier.ouvre(DID, jeton, defi, signe(priv, bytes.fromhex(defi)))
    prof.note_session(DID)
    assert prof.suivi(DID, jeton)["session_ouverte"] is True


# ── LE NOM DE COMPTE, ET L'ESCALADE QU'IL FERME ─────────────────────────────

def test_le_nom_de_compte_derive_de_la_cle_pas_du_nom_declare():
    """LA RÈGLE DE SÛRETÉ DU MODULE.

    Le nom déclaré arrive par un formulaire OUVERT. S'en servir comme
    identifiant de compte laisserait quiconque annoncer « admin » — et la voie
    de création, qui écrit un mot de passe, réinitialiserait le compte existant
    portant ce nom. Une porte d'entrée deviendrait une prise de contrôle.
    """
    _, a = paire()
    _, b = paire()
    # Deux clés différentes → deux comptes différents, quel que soit le nom
    # que l'un et l'autre déclarent.
    assert nom_de_compte(a) != nom_de_compte(b)
    # La même clé → le même compte, de façon stable.
    assert nom_de_compte(a) == nom_de_compte(a)
    # Et le nom produit ne contient RIEN de ce qu'un inconnu a pu écrire.
    assert nom_de_compte(a).startswith("sbx-")
    assert len(nom_de_compte(a)) == len("sbx-") + 12


def test_le_provisionnement_ne_touche_pas_a_un_compte_existant(prof, monkeypatch):
    """`set_password(provision=True)` RÉINITIALISE un compte déjà là. Comme le
    nom dérive de la clé, un compte de ce nom EST cet appareil — on le laisse
    tel quel plutôt que de lui réécrire un secret."""
    ecrits = []
    existants = set()

    def creer(nom, profil, did, cle):
        compte = nom_de_compte(cle)
        if compte in existants:
            return                 # déjà provisionné : on ne retouche à rien
        existants.add(compte)
        ecrits.append(compte)

    _, pub = paire()
    p = Profileur(prof.chemin, creer_compte=creer)
    p.demande(form(pub))
    p.accepte(DID, par="gerald")
    assert len(ecrits) == 1

    # Une seconde admission du MÊME appareil n'écrit pas une seconde fois.
    p.revoque(DID, par="gerald")
    p.demande(form(pub))
    p.accepte(DID, par="gerald")
    assert len(ecrits) == 1


# ── LE LIEN D'ENTRÉE À USAGE UNIQUE (#1354) ─────────────────────────────────

from api.lien import LienInvalide, Liens, TTL_S  # noqa: E402


def test_le_lien_ne_sert_qu_une_fois():
    """LA PROPRIÉTÉ QUI COMPTE, et c'est un DÉTECTEUR autant qu'une limite.

    L'usage unique n'empêche pas l'interception — un lien est un porteur, il
    suffit de le lire. Mais il la REND VISIBLE : le destinataire légitime qui
    trouve un lien mort sait que quelqu'un est passé avant lui, et peut le dire.
    Un lien réutilisable laisserait les deux entrer sans que personne ne s'en
    aperçoive.
    """
    L = Liens()
    j = L.emet("did:sbx:a")
    assert L.consomme(j) == "did:sbx:a"
    with pytest.raises(LienInvalide):
        L.consomme(j)


def test_un_lien_inconnu_est_refuse_comme_un_lien_servi():
    """UN SEUL MESSAGE POUR LES TROIS CAS. Distinguer « inconnu » de « déjà
    servi » apprendrait à qui essaie qu'un lien a existé — donc qu'une personne
    a été admise."""
    L = Liens()
    with pytest.raises(LienInvalide):
        L.consomme("jamais-emis")
    with pytest.raises(LienInvalide):
        L.consomme("")


def test_le_lien_perime_ne_sert_plus(monkeypatch):
    L = Liens()
    j = L.emet("did:sbx:a")
    # On avance le temps plutôt que d'attendre six heures.
    import api.lien as m
    vrai = m.time.monotonic
    monkeypatch.setattr(m.time, "monotonic", lambda: vrai() + TTL_S + 1)
    with pytest.raises(LienInvalide):
        L.consomme(j)


def test_le_jeton_n_est_pas_conserve_en_clair():
    """On garde l'EMPREINTE, pas le jeton : un journal, une trace mémoire ou un
    vidage ne doivent pas rendre le lien réutilisable."""
    L = Liens()
    j = L.emet("did:sbx:a")
    assert all(j not in str(v.__dict__) for v in L._liens.values())


def test_l_adresse_est_validee_sans_etre_verifiee(prof):
    """L'expression n'atteste pas qu'une adresse existe — rien ne le peut sans
    y écrire. Elle écarte ce qui ne PEUT PAS en être une, pour que le champ ne
    devienne pas un second champ de texte libre."""
    _, pub = paire()
    f = form(pub)
    f["email"] = "pas-une-adresse"
    with pytest.raises(DemandeInvalide, match="adresse"):
        prof.demande(f)
    # Vide : accepté, le champ est facultatif.
    f["email"] = ""
    assert prof.demande(f).email == ""
    # Correcte : conservée en minuscules.
    f["email"] = "Gerald@Example.FR"
    assert prof.demande(f).email == "gerald@example.fr"
