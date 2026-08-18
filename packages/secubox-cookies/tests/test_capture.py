# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""#1058 phase 1 — magasin des cookies capturés (valeurs réelles).

Distinct de l'ingest mitm_events, qui ne garde que les NOMS. Ici on garde les
valeurs, chiffrées, pour rejouer une session — mais seulement pendant une
fenêtre d'armement explicite, et jamais en clair hors de l'export.
"""

import time

import pytest

from api.capture import MagasinCapture


@pytest.fixture
def magasin(tmp_path):
    return MagasinCapture(
        fichier=tmp_path / "captures.enc",
        cle_fichier=tmp_path / "capture.key",
    )


def _cookie(nom="SID", valeur="secret-de-session", expire=None):
    return {"name": nom, "value": valeur, "domain": ".youtube.com",
            "path": "/", "expires": expire or int(time.time()) + 3600,
            "secure": True, "httponly": True}


# ── armement ───────────────────────────────────────────────────────────────

def test_hors_fenetre_rien_nest_capture(magasin):
    # Sans armement explicite, la capture n'écrit rien : le silence n'ouvre
    # jamais la collecte de valeurs de session.
    n = magasin.recevoir("www.youtube.com", [_cookie()])
    assert n == 0
    assert magasin.pour_hote("www.youtube.com") == []


def test_arme_puis_capture(magasin):
    magasin.armer(duree_s=60)
    n = magasin.recevoir("www.youtube.com", [_cookie()])
    assert n == 1
    assert len(magasin.pour_hote("www.youtube.com")) == 1


def test_la_fenetre_se_referme_seule(magasin):
    magasin.armer(duree_s=0)  # fenêtre déjà close
    assert not magasin.est_arme()
    assert magasin.recevoir("www.youtube.com", [_cookie()]) == 0


def test_desarmer_stoppe_la_capture(magasin):
    magasin.armer(duree_s=60)
    magasin.desarmer()
    assert not magasin.est_arme()
    assert magasin.recevoir("www.youtube.com", [_cookie()]) == 0


# ── le secret ne fuit jamais ────────────────────────────────────────────────

def test_la_valeur_nest_jamais_dans_le_statut(magasin):
    magasin.armer(duree_s=60)
    magasin.recevoir("www.youtube.com", [_cookie(valeur="TRES-SECRET-42")])
    st = magasin.statut()
    assert "TRES-SECRET-42" not in repr(st)
    # le statut dit l'hôte, le nombre, la fraîcheur — pas les valeurs
    h = [x for x in st["hotes"] if x["hote"] == "www.youtube.com"][0]
    assert h["cookies"] == 1
    assert "valeur" not in repr(h).lower() or "TRES-SECRET" not in repr(h)


def test_le_fichier_sur_disque_est_chiffre(magasin, tmp_path):
    magasin.armer(duree_s=60)
    magasin.recevoir("www.youtube.com", [_cookie(valeur="EN-CLAIR-INTERDIT")])
    brut = (tmp_path / "captures.enc").read_bytes()
    assert b"EN-CLAIR-INTERDIT" not in brut
    assert b"youtube" not in brut  # même l'hôte est chiffré


def test_la_cle_est_a_acces_restreint(magasin, tmp_path):
    magasin.armer(duree_s=60)
    magasin.recevoir("www.youtube.com", [_cookie()])
    import stat
    mode = (tmp_path / "capture.key").stat().st_mode
    assert stat.S_IMODE(mode) == 0o600


# ── expiration ──────────────────────────────────────────────────────────────

def test_un_cookie_expire_nest_pas_rendu(magasin):
    magasin.armer(duree_s=60)
    magasin.recevoir("www.youtube.com",
                     [_cookie(nom="frais", expire=int(time.time()) + 3600),
                      _cookie(nom="perime", expire=int(time.time()) - 10)])
    noms = [c["name"] for c in magasin.pour_hote("www.youtube.com")]
    assert "frais" in noms and "perime" not in noms


def test_une_session_de_cookies_de_session_survit(magasin):
    # expires=0 (ou absent) = cookie de session : pas d'expiration à l'horloge,
    # il vaut tant que la capture le détient.
    magasin.armer(duree_s=60)
    magasin.recevoir("www.youtube.com", [_cookie(nom="sess", expire=0)])
    assert [c["name"] for c in magasin.pour_hote("www.youtube.com")] == ["sess"]


# ── recapture enrichissante ─────────────────────────────────────────────────

def test_recapturer_remplace_la_valeur(magasin):
    magasin.armer(duree_s=60)
    magasin.recevoir("www.youtube.com", [_cookie(nom="SID", valeur="vieux")])
    magasin.recevoir("www.youtube.com", [_cookie(nom="SID", valeur="neuf")])
    cs = magasin.pour_hote("www.youtube.com")
    assert len(cs) == 1 and cs[0]["value"] == "neuf"


# ── export Netscape (ce que yt-dlp lit) ─────────────────────────────────────

def test_export_netscape_pour_un_hote(magasin):
    magasin.armer(duree_s=60)
    magasin.recevoir("www.youtube.com", [_cookie(nom="SID", valeur="abc")])
    txt = magasin.netscape(["www.youtube.com"])
    assert txt.startswith("# Netscape HTTP Cookie File")
    lignes = [l for l in txt.splitlines() if l and not l.startswith("#")]
    assert len(lignes) == 1
    champs = lignes[0].split("\t")
    assert len(champs) == 7  # domain flag path secure expiry name value
    assert champs[0] == ".youtube.com"
    assert champs[5] == "SID" and champs[6] == "abc"


def test_export_regroupe_les_domaines_dune_famille(magasin):
    # Réclamation par hôte : un connecteur demande plusieurs hôtes (youtube +
    # google), on assemble un seul cookies.txt.
    magasin.armer(duree_s=60)
    magasin.recevoir("www.youtube.com", [_cookie(nom="SID", valeur="a")])
    magasin.recevoir("accounts.google.com",
                     [{"name": "SAPISID", "value": "b", "domain": ".google.com",
                       "path": "/", "expires": int(time.time()) + 3600,
                       "secure": True, "httponly": True}])
    txt = magasin.netscape(["www.youtube.com", "accounts.google.com"])
    lignes = [l for l in txt.splitlines() if l and not l.startswith("#")]
    assert len(lignes) == 2


def test_export_ignore_les_expires(magasin):
    magasin.armer(duree_s=60)
    magasin.recevoir("www.youtube.com",
                     [_cookie(nom="perime", expire=int(time.time()) - 10)])
    lignes = [l for l in magasin.netscape(["www.youtube.com"]).splitlines()
              if l and not l.startswith("#")]
    assert lignes == []


# ── persistance ─────────────────────────────────────────────────────────────

def test_le_magasin_se_relit_apres_redemarrage(magasin, tmp_path):
    magasin.armer(duree_s=60)
    magasin.recevoir("www.youtube.com", [_cookie(nom="SID", valeur="persiste")])
    autre = MagasinCapture(fichier=tmp_path / "captures.enc",
                           cle_fichier=tmp_path / "capture.key")
    cs = autre.pour_hote("www.youtube.com")
    assert len(cs) == 1 and cs[0]["value"] == "persiste"


def test_oublier_un_hote(magasin):
    magasin.armer(duree_s=60)
    magasin.recevoir("www.youtube.com", [_cookie()])
    magasin.oublier("www.youtube.com")
    assert magasin.pour_hote("www.youtube.com") == []


# ── avatars (profils) ───────────────────────────────────────────────────────

def test_deux_avatars_ne_se_melangent_pas(magasin):
    # Deux identités distinctes — le compte perso, le compte de l'asso — ne
    # doivent jamais partager leurs cookies.
    magasin.armer(duree_s=60, profil="perso")
    magasin.recevoir("www.youtube.com", [_cookie(nom="SID", valeur="moi")])
    magasin.armer(duree_s=60, profil="asso")
    magasin.recevoir("www.youtube.com", [_cookie(nom="SID", valeur="nous")])

    assert magasin.pour_hote("www.youtube.com", profil="perso")[0]["value"] == "moi"
    assert magasin.pour_hote("www.youtube.com", profil="asso")[0]["value"] == "nous"


def test_un_avatar_couvre_plusieurs_hotes(magasin):
    # L'avatar « mon-youtube » = les cookies youtube.com ET google.com, qui
    # ensemble forment l'identité. L'export du profil les assemble.
    magasin.armer(duree_s=60, profil="mon-youtube")
    magasin.recevoir("www.youtube.com", [_cookie(nom="SID", valeur="a")])
    magasin.recevoir("accounts.google.com",
                     [{"name": "SAPISID", "value": "b", "domain": ".google.com",
                       "path": "/", "expires": 0, "secure": True, "httponly": True}])
    lignes = [l for l in magasin.netscape(profil="mon-youtube").splitlines()
              if l and not l.startswith("#")]
    assert len(lignes) == 2


def test_lister_les_avatars(magasin):
    magasin.armer(duree_s=60, profil="perso")
    magasin.recevoir("www.youtube.com", [_cookie()])
    magasin.armer(duree_s=60, profil="asso")
    magasin.recevoir("facebook.com", [_cookie(nom="c_user")])
    av = {a["avatar"] for a in magasin.avatars()}
    assert av == {"perso", "asso"}


def test_le_profil_actif_disparait_du_statut_apres_desarmement(magasin):
    magasin.armer(duree_s=60, profil="perso")
    magasin.recevoir("www.youtube.com", [_cookie()])
    magasin.desarmer()
    assert magasin.statut()["profil_actif"] is None


# ── marqueur partage avec sbxmitm (#1058 phase 3) ───────────────────────────

@pytest.fixture
def magasin_marque(tmp_path):
    return MagasinCapture(
        fichier=tmp_path / "captures.enc",
        cle_fichier=tmp_path / "capture.key",
        marqueur=tmp_path / "armed",
    )


def test_armer_ecrit_le_marqueur(magasin_marque, tmp_path):
    magasin_marque.armer(duree_s=120, profil="perso", hotes=["youtube.com"])
    m = tmp_path / "armed"
    assert m.exists()
    import json, time
    d = json.loads(m.read_text())
    # exactement les champs que le captureArm de sbxmitm attend
    assert d["profil"] == "perso"
    assert d["hotes"] == ["youtube.com"]
    assert d["deadline"] > time.time()


def test_desarmer_retire_le_marqueur(magasin_marque, tmp_path):
    magasin_marque.armer(duree_s=120)
    assert (tmp_path / "armed").exists()
    magasin_marque.desarmer()
    assert not (tmp_path / "armed").exists()


def test_le_marqueur_est_a_acces_restreint(magasin_marque, tmp_path):
    magasin_marque.armer(duree_s=120)
    import stat
    assert stat.S_IMODE((tmp_path / "armed").stat().st_mode) == 0o600


def test_sans_marqueur_configure_armer_ne_plante_pas(magasin):
    # Le magasin doit rester utilisable meme sans chemin de marqueur (tests,
    # usage hors-ligne) : armer ne fait alors qu'ouvrir la fenetre interne.
    magasin.armer(duree_s=60)
    assert magasin.est_arme()
