# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""L'adresse tracée d'une connexion ne se choisit pas côté client (#1753).

HAProxy ajoute l'adresse réelle EN FIN de X-Forwarded-For ; tout ce qui la
précède vient de l'appelant. Épinglé par une chaîne « forgée, réelle,
sauts locaux » : lire la gauche rendrait la forgée.
"""
from types import SimpleNamespace

from secubox_core.auth import adresse_client


def _req(xff=None, hote=None):
    entetes = {} if xff is None else {"X-Forwarded-For": xff}
    return SimpleNamespace(headers=entetes,
                           client=SimpleNamespace(host=hote) if hote else None)


def test_la_gauche_forgee_n_est_pas_retenue():
    assert adresse_client(_req("6.6.6.6, 203.0.113.9, 127.0.0.1")) == "203.0.113.9"


def test_sauts_locaux_ignores_ipv6_compris():
    assert adresse_client(_req("203.0.113.9, 127.0.0.1, ::1")) == "203.0.113.9"


def test_x_real_ip_du_client_ignore():
    r = _req("203.0.113.9")
    r.headers["X-Real-IP"] = "6.6.6.6"
    assert adresse_client(r) == "203.0.113.9"


def test_sans_chaine_l_hote_de_la_connexion():
    assert adresse_client(_req(None, hote="192.168.1.20")) == "192.168.1.20"


def test_seulement_des_sauts_locaux_et_socket_unix():
    assert adresse_client(_req("127.0.0.1")) == ""


def test_ligne_ajoutee_par_haproxy_retenue():
    """HAProxy `option forwardfor` ajoute une LIGNE ; la première est celle
    du client. Lire seulement la première rendait la forgée (mesuré sur gk3)."""
    from starlette.datastructures import Headers
    r = SimpleNamespace(headers=Headers(raw=[(b"x-forwarded-for", b"6.6.6.6"),
                                             (b"x-forwarded-for", b"203.0.113.7")]),
                        client=None)
    assert adresse_client(r) == "203.0.113.7"
