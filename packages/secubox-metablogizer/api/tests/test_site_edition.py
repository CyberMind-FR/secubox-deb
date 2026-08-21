# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox-Deb :: metablogizer — édition des détails d'un site (#1089)

CyberMind — https://cybermind.fr

`fusionner` applique un patch d'édition sur un `site.json` : seules les clés
éditables passent, une valeur nulle efface, le nom et les champs dérivés
(version/last_updated calculés par git) ne sont jamais persistés, et le
résultat est validé contre le schéma — un alias qui n'est pas un domaine est
refusé AVANT écriture (défense en profondeur : la génération nginx le refiltre).
"""
from __future__ import annotations

from site_schema import fusionner

BASE = {
    "name": "anibal-amiot",
    "domain": "anibal-amiot.fr",
    "published": True,
    "title": "Livrée d Hermès",
}


def test_les_champs_editables_sont_appliques():
    out, errs = fusionner(BASE, {
        "description": "Reliure d'art",
        "category": "artisanat",
        "tags": ["reliure", "hermes"],
        "source_url": "https://github.com/anibaledel/livreedhermes.git",
        "gitea_repo": "https://gitea.gk2.secubox.in/gandalf/anibal-amiot",
    })
    assert errs == []
    assert out["description"] == "Reliure d'art"
    assert out["category"] == "artisanat"
    assert out["tags"] == ["reliure", "hermes"]
    assert out["source_url"] == "https://github.com/anibaledel/livreedhermes.git"
    assert out["gitea_repo"].endswith("/anibal-amiot")
    # les champs non touchés survivent
    assert out["title"] == "Livrée d Hermès"
    assert out["domain"] == "anibal-amiot.fr"


def test_les_aliases_multiples_sont_acceptes():
    out, errs = fusionner(BASE, {"aliases": [
        "www.anibal-amiot.fr", "anibal-amiot.com", "www.anibal-amiot.com"]})
    assert errs == []
    assert out["aliases"] == [
        "www.anibal-amiot.fr", "anibal-amiot.com", "www.anibal-amiot.com"]


def test_une_source_url_non_http_est_refusee():
    """source_url et gitea_repo deviennent des href sur la page : une URI
    `javascript:` y serait un XSS stocké. Le schéma n'accepte que http(s)://."""
    out, errs = fusionner(BASE, {"source_url": "javascript:alert(document.cookie)"})
    assert errs, "une source_url non http(s) doit être refusée"
    out2, errs2 = fusionner(BASE, {"gitea_repo": "javascript:fetch('/x')"})
    assert errs2, "un gitea_repo non http(s) doit être refusé"


def test_une_source_url_https_passe():
    out, errs = fusionner(BASE, {
        "source_url": "https://github.com/anibaledel/livreedhermes.git"})
    assert errs == []
    assert out["source_url"].startswith("https://")


def test_un_alias_qui_n_est_pas_un_domaine_est_refuse():
    """La garde d'injection : `server_name` recopie un alias — un point-virgule
    ouvrirait un bloc. On refuse AVANT d'écrire."""
    out, errs = fusionner(BASE, {"aliases": ["pas; un domaine {"]})
    assert errs, "un alias non conforme doit produire une erreur de validation"


def test_le_nom_n_est_jamais_modifie_par_un_patch():
    out, errs = fusionner(BASE, {"name": "autre-site"})
    assert out["name"] == "anibal-amiot"


def test_les_champs_derives_ne_sont_pas_persistes():
    """version/last_updated sont RECALCULÉS par enrich() à la lecture ; les
    graver figerait une valeur périmée."""
    base = dict(BASE, version="v1.2.3", last_updated="2026-01-01T00:00:00Z")
    out, errs = fusionner(base, {"title": "T"})
    assert "version" not in out
    assert "last_updated" not in out


def test_une_valeur_nulle_efface_le_champ():
    base = dict(BASE, category="ancienne")
    out, errs = fusionner(base, {"category": None})
    assert errs == []
    assert "category" not in out


def test_les_cles_inconnues_sont_ignorees():
    out, errs = fusionner(BASE, {"arbitraire": "x", "title": "Neuf"})
    assert "arbitraire" not in out
    assert out["title"] == "Neuf"
