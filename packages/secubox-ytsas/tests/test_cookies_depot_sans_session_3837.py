# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3837 — un cookies.txt déposé SANS cookie de session (export fait déconnecté
ou tronqué) doit être détecté comme invalide, pour que le dépôt le refuse au lieu
de l'accepter puis d'échouer plus tard en « auth requise »."""
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "lxc" / "app"))
from cookies_verif import cookies_session_presents  # noqa: E402

# Fichier réel constaté sur gk2 : 114 octets, en-tête + un cookie de consentement,
# aucune session.
SANS_SESSION = (
    "# Netscape HTTP Cookie File\n"
    ".youtube.com\tTRUE\t/\tTRUE\t0\tSOCS\tCAI\n"
    ".youtube.com\tTRUE\t/\tTRUE\t0\tCONSENT\tYES+1\n"
)

# Export fait en étant connecté : contient des cookies de session.
AVEC_SESSION = (
    "# Netscape HTTP Cookie File\n"
    ".youtube.com\tTRUE\t/\tTRUE\t0\tSOCS\tCAI\n"
    "#HttpOnly_.youtube.com\tTRUE\t/\tTRUE\t1800000000\t__Secure-1PSID\tAAAA\n"
    ".google.com\tTRUE\t/\tTRUE\t1800000000\tSAPISID\tBBBB\n"
    "#HttpOnly_.youtube.com\tTRUE\t/\tTRUE\t1800000000\tLOGIN_INFO\tCCCC\n"
)


def test_refuse_sans_session():
    assert cookies_session_presents(SANS_SESSION) is False


def test_accepte_avec_session():
    assert cookies_session_presents(AVEC_SESSION) is True


def test_refuse_vide():
    assert cookies_session_presents("") is False
    assert cookies_session_presents("   \n# commentaire seul\n") is False


def test_tolere_espaces_au_lieu_de_tabs():
    # Certains exports séparent par espaces ; le cookie de session reste détecté.
    ligne = ".youtube.com TRUE / TRUE 1800000000 __Secure-3PSID ZZZZ"
    assert cookies_session_presents(ligne) is True


def test_httponly_prefixe_non_pris_pour_un_commentaire():
    # Une ligne #HttpOnly_ est une donnée, pas un commentaire : son cookie compte.
    ligne = "#HttpOnly_.google.com\tTRUE\t/\tTRUE\t1800000000\tSAPISID\tXXXX"
    assert cookies_session_presents(ligne) is True


def test_refuse_sid_dun_autre_site():
    # Un cookie nommé SID mais d'un autre domaine ne doit pas valider la session.
    ligne = ".exemple.org\tTRUE\t/\tTRUE\t1800000000\tSID\tZZZZ"
    assert cookies_session_presents(ligne) is False
