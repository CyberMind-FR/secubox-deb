# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""Déballage d'archive et enregistrement du domaine (#1023)."""
import io
import json
import zipfile
from pathlib import Path

import pytest

from publish.content import extract_archive, _prefixe_enveloppe
from routers.publish import enregistre_domaine, publie_vhost
import routers.publish as rp


def zip_de(membres: dict) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for nom, contenu in membres.items():
            z.writestr(nom, contenu)
    return buf.getvalue()


# ── Le dossier enveloppe ──────────────────────────────────────────────────

def test_enveloppe_unique_detectee():
    assert _prefixe_enveloppe(["site/index.html", "site/assets/a.css"]) == "site/"


def test_pas_d_enveloppe_si_fichier_a_la_racine():
    # Une archive DEJA bien formee ne doit pas etre touchee : deballer
    # jetterait l'index.html de la racine.
    assert _prefixe_enveloppe(["index.html", "assets/a.css"]) == ""


def test_pas_d_enveloppe_si_deux_dossiers():
    assert _prefixe_enveloppe(["a/x.html", "b/y.html"]) == ""


def test_archive_enveloppee_donne_un_index(tmp_path):
    # Le cas exact de #1023 : `zip -r gk2net.zip gk2net/`.
    r = extract_archive(tmp_path, zip_de({"gk2net/index.html": "<h1>ok</h1>",
                                          "gk2net/assets/a.css": "body{}"}),
                        "gk2net.zip")
    assert r["index_present"] is True
    assert r["enveloppe"] == "gk2net"
    assert (tmp_path / "index.html").read_text() == "<h1>ok</h1>"
    assert (tmp_path / "assets" / "a.css").exists()


def test_archive_plate_inchangee(tmp_path):
    r = extract_archive(tmp_path, zip_de({"index.html": "x", "a/b.css": "y"}),
                        "site.zip")
    assert r["index_present"] is True and r["enveloppe"] == ""
    assert (tmp_path / "a" / "b.css").exists()


def test_deballage_ne_desarme_pas_la_garde_zip_slip(tmp_path):
    from publish.content import ContentError
    with pytest.raises(ContentError):
        extract_archive(tmp_path, zip_de({"site/../../dehors.html": "x"}),
                        "site.zip")


# ── Le domaine enregistre ─────────────────────────────────────────────────

def test_domaine_ecrit_dans_site_json(tmp_path):
    assert enregistre_domaine(tmp_path, "www.gk2.secubox.in")["ok"] is True
    doc = json.loads((tmp_path / "site.json").read_text())
    assert doc["domain"] == "www.gk2.secubox.in"
    assert doc["name"] == tmp_path.name


def test_domaine_preserve_les_autres_champs(tmp_path):
    (tmp_path / "site.json").write_text(json.dumps(
        {"name": "x", "title": "Mon site", "version": "2.1"}))
    enregistre_domaine(tmp_path, "a.example.org")
    doc = json.loads((tmp_path / "site.json").read_text())
    assert doc["title"] == "Mon site" and doc["version"] == "2.1"


def test_site_json_illisible_n_est_pas_ecrase(tmp_path):
    # Perdre titre et version parce qu'on n'a pas su relire le fichier serait
    # un remede pire que le mal.
    (tmp_path / "site.json").write_text("{ ceci n'est pas du json")
    r = enregistre_domaine(tmp_path, "a.example.org")
    assert r["ok"] is False
    assert (tmp_path / "site.json").read_text().startswith("{ ceci")


# ── La regeneration ───────────────────────────────────────────────────────

def test_vhost_signale_l_absence_de_generateur(monkeypatch):
    monkeypatch.setattr(rp, "regenerer_nginx", None)
    assert publie_vhost("a.example.org")["ok"] is False


def test_vhost_ne_masque_pas_une_exception(monkeypatch):
    def boum():
        raise OSError("nginx -t injoignable")
    monkeypatch.setattr(rp, "regenerer_nginx", boum)
    r = publie_vhost("a.example.org")
    assert r["ok"] is False and "injoignable" in r["detail"]


def test_vhost_reussi(monkeypatch):
    monkeypatch.setattr(rp, "regenerer_nginx", lambda: (True, 163, "Published 163 sites"))
    r = publie_vhost("a.example.org")
    assert r["ok"] is True and r["sites"] == 163
