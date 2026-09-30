# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""get_cookie_audit_config() rend-il le socle RGPD du classifieur ? (#1777)

La fusion 7ebe27403a avait efface `_COOKIE_CLASSIFIER_DEFAULTS` et la fusion
des motifs : #1311 a rebranche le lecteur avec `classifier = {}`, si bien que
CHAQUE cookie tombait en « unclassified ». Aucun test ne l'a vu, car les tests
du collecteur passent leur classifieur a la main.
"""
from pathlib import Path

import secubox_core.config as cfg


def _conf(monkeypatch, tmp_path: Path, texte: str) -> None:
    fichier = tmp_path / "secubox.conf"
    fichier.write_text(texte)
    monkeypatch.setattr(cfg, "_CONF_PATHS", [fichier])
    monkeypatch.setattr(cfg, "_CONFIG", None)


def test_le_socle_rgpd_est_present_sans_configuration(monkeypatch, tmp_path):
    _conf(monkeypatch, tmp_path, "[global]\nhostname = 't'\n")
    out = cfg.get_cookie_audit_config()
    assert out["enabled"] is False, "le collecteur ne doit pas s'allumer seul"
    cls = out["classifier"]
    assert set(cls) == {"strictly_necessary", "functional", "analytics", "marketing"}
    assert r"^_ga" in cls["analytics"]
    assert r"^_fbp$" in cls["marketing"]
    assert r"^csrftoken$" in cls["strictly_necessary"]


def test_les_motifs_de_l_exploitant_s_ajoutent_au_socle(monkeypatch, tmp_path):
    _conf(monkeypatch, tmp_path,
          "[cookie_audit]\nenabled = true\n"
          "[cookie_audit.classifier]\nanalytics = ['^mon_suivi$']\n")
    cls = cfg.get_cookie_audit_config()["classifier"]
    assert cls["analytics"][0] == "^mon_suivi$", "l'exploitant passe en premier"
    assert r"^_ga" in cls["analytics"], "le socle ne se perd jamais en silence"
    assert len(cls["analytics"]) == len(set(cls["analytics"]))


def test_override_n_applique_que_l_exploitant(monkeypatch, tmp_path):
    _conf(monkeypatch, tmp_path,
          "[cookie_audit]\nclassifier_override = true\n"
          "[cookie_audit.classifier]\nmarketing = ['^pub$']\n")
    cls = cfg.get_cookie_audit_config()["classifier"]
    assert cls["marketing"] == ["^pub$"]
    assert cls["analytics"] == []
