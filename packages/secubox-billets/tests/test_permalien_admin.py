# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""L'adresse publique dans la reponse admin (#1024)."""
import importlib

from api.routes import jwt_admin


def test_permalien_avec_base(monkeypatch):
    monkeypatch.setattr(jwt_admin, "SITE_URL", "https://billets.gk2.secubox.in")
    assert jwt_admin._permalien("mon-billet-abcd1234") == \
        "https://billets.gk2.secubox.in/b/mon-billet-abcd1234"


def test_barre_finale_de_la_base_absorbee(monkeypatch):
    monkeypatch.setattr(jwt_admin, "SITE_URL", "https://billets.gk2.secubox.in/")
    assert jwt_admin._permalien("x") == "https://billets.gk2.secubox.in/b/x"


def test_sans_base_on_rend_un_chemin_relatif(monkeypatch):
    # PAS d'adresse fabriquee : `/b/x` est vrai pour qui parle deja a billets,
    # alors qu'un `http://localhost/...` invente serait un lien mort donne
    # pour bon — exactement le genre d'erreur qu'on ne decouvre qu'en cliquant.
    monkeypatch.setattr(jwt_admin, "SITE_URL", "")
    assert jwt_admin._permalien("x") == "/b/x"


def test_sans_slug_rien():
    assert jwt_admin._permalien(None) == ""
    assert jwt_admin._permalien("") == ""


def test_la_vue_porte_les_deux_noms(monkeypatch):
    monkeypatch.setattr(jwt_admin, "SITE_URL", "https://billets.example")
    v = jwt_admin._view({"id": "01ABC", "slug": "titre-01abc", "body": "x",
                         "status": "published", "style": None, "ref_url": None,
                         "embed_url": None, "published_at": 1, "created_at": 1})
    assert v["permalink"] == "https://billets.example/b/titre-01abc"
    assert v["url"] == v["permalink"]


def test_lecture_par_identifiant_rend_l_adresse(monkeypatch):
    """La liste est bornee a 200 : un billet plus ancien y devenait invisible,
    et rien ne distinguait « absent » de « au-dela de la borne »."""
    import inspect
    from api.routes import jwt_admin as ja
    src = inspect.getsource(ja.register_jwt_admin)
    assert '@app.get("/admin/api/billets/{billet_id}")' in src
    assert "get_by_id" in src
