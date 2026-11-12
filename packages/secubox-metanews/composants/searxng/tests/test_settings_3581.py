# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3581 — settings.yml généré depuis le TOML : clés du POC de gk0, délais et suspensions bornés, jamais de secret."""
from pathlib import Path

import pytest
import yaml

from sbx_searxng import config as C

COMPOSANT = Path(__file__).resolve().parents[1]


def test_exemple_identique_aux_defauts(cfg):
    assert cfg == C.valider(C.DEFAUTS)
    assert C.charger(COMPOSANT / "absent.toml") == cfg               # TOML absent = défauts


def test_cles_du_poc_et_bornes(cfg):
    d = yaml.safe_load(C.rendre_yaml(C.generer_settings(cfg)))
    assert d["use_default_settings"] is True
    assert d["general"] == {"instance_name": "SecuBox", "enable_metrics": False}
    assert d["server"] == {"bind_address": "10.100.0.85", "port": 8888, "limiter": False, "public_instance": False, "image_proxy": False}
    assert d["search"]["safe_search"] == 0 and d["search"]["formats"] == ["html", "json"]
    assert d["ui"]["default_locale"] == "fr"
    assert d["outgoing"] == {"request_timeout": 3.0, "max_request_timeout": 6.0}
    assert d["search"]["ban_time_on_fail"] == 5 and d["search"]["max_ban_time_on_fail"] == 120
    assert "engines" not in d


def test_aucun_secret_dans_le_fichier(cfg):
    texte = C.rendre_yaml(C.generer_settings(cfg))
    assert "secret_key" not in yaml.safe_load(texte)["server"]
    assert "ultrasecretkey" not in texte
    assert "SEARXNG_SECRET" in texte                                   # l'en-tête dit d'où vient le secret


def test_le_toml_ne_peut_pas_porter_de_secret(tmp_path):
    f = tmp_path / "searxng.toml"
    f.write_text('[searxng]\nsecret_key = "abc"\n')
    with pytest.raises(C.ConfigInvalide, match="clé inconnue"):
        C.charger(f)
    f.write_text('[server]\nsecret_key = "abc"\n')
    with pytest.raises(C.ConfigInvalide, match="section"):
        C.charger(f)


def test_moteurs_desactives_pilotes_par_le_toml(tmp_path, cfg):
    f = tmp_path / "searxng.toml"
    f.write_text('[searxng]\nmoteurs_desactives = ["brave", "google", "brave"]\n')
    c = C.charger(f)
    d = yaml.safe_load(C.rendre_yaml(C.generer_settings(c)))
    assert d["engines"] == [{"name": "brave", "disabled": True}, {"name": "google", "disabled": True}]
    C.valider_settings(C.rendre_yaml(C.generer_settings(c)), c)


@pytest.mark.parametrize("toml", [
    '[lxc]\nip = "192.168.1.5"\n',                       # hors de br-lxc
    '[lxc]\nip = "10.100.0.1"\n',                        # la passerelle
    '[lxc]\npath = "/data/../etc"\n',
    '[lxc]\nname = "a;b"\n',
    '[lxc]\nmemoire_max = "unlimited"\n',
    '[searxng]\nport = 80\n',
    '[searxng]\nrequest_timeout = 10.0\nmax_request_timeout = 6.0\n',
    '[searxng]\nmoteurs_desactives = ["$(reboot)"]\n',
    '[searxng]\ninstance_name = "a\\nb"\n',
    '[searxng]\nsafe_search = true\n',
    'pas du toml',
])
def test_configuration_refusee(tmp_path, toml):
    f = tmp_path / "searxng.toml"
    f.write_text(toml)
    with pytest.raises(C.ConfigInvalide):
        C.charger(f)


def test_validation_du_fichier_ecrit(cfg):
    bon = C.rendre_yaml(C.generer_settings(cfg))
    assert C.valider_settings(bon, cfg)["server"]["port"] == 8888
    for mauvais in ("", "server: [", "- a\n- b\n", bon.replace("use_default_settings: true", "use_default_settings: false"),
                    bon.replace("  image_proxy: false", "  image_proxy: false\n  secret_key: x"),
                    bon.replace("bind_address: 10.100.0.85", "bind_address: 0.0.0.0"),
                    bon.replace("  - json\n", "")):
        with pytest.raises(C.ConfigInvalide):
            C.valider_settings(mauvais, cfg)
