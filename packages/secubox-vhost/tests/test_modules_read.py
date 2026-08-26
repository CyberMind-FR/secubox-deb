# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# See LICENCE-CMSD-1.0.md for terms.
"""Tests du rattachement vhost -> module SecuBox (#1217)."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from api import modules_read  # noqa: E402
from api.modules_read import module_de  # noqa: E402


def _registre(tmp_path):
    modules_read._cache["signature"] = None  # le cache ne doit pas fuir d'un test à l'autre
    (tmp_path / "gitea.toml").write_text(
        'id = "gitea"\ncategory = "infra"\nruntime = "lxc"\n'
        'portal = { domain = "gitea.gk2.secubox.in" }\n')
    (tmp_path / "depot.toml").write_text('id = "depot"\ncategory = "infra"\nruntime = "native"\n')
    (tmp_path / "casse.toml").write_text("ceci n'est pas du toml [[[")
    return tmp_path


def test_lien_declare_est_certain(tmp_path):
    m = module_de("gitea.gk2.secubox.in", _registre(tmp_path))
    assert m["id"] == "gitea" and m["certain"] is True
    assert m["runtime"] == "lxc"


def test_lien_deduit_du_nom_est_marque_incertain(tmp_path):
    """Une déduction sur le nom ne doit jamais s'afficher comme un fait."""
    m = module_de("depot.gk2.secubox.in", _registre(tmp_path))
    assert m["id"] == "depot" and m["certain"] is False


def test_vhost_sans_module(tmp_path):
    assert module_de("anibal-amiot.fr", _registre(tmp_path)) is None


def test_manifeste_illisible_n_empeche_pas_les_autres(tmp_path):
    """Un TOML cassé ne doit pas condamner tout le registre."""
    assert module_de("gitea.gk2.secubox.in", _registre(tmp_path)) is not None


def test_registre_absent_est_silencieux(tmp_path):
    modules_read._cache["signature"] = None
    assert module_de("gitea.gk2.secubox.in", tmp_path / "nulle-part") is None


def test_vhost_vide(tmp_path):
    assert module_de("", _registre(tmp_path)) is None


def test_casse_ignoree(tmp_path):
    assert module_de("GITEA.GK2.Secubox.IN", _registre(tmp_path))["certain"] is True


def test_socket_nginx_fait_foi(tmp_path):
    """Le socket vers lequel la conf route est un FAIT, pas une ressemblance.

    depot.gk2.secubox.in porte le nom d'un dépôt mais est servi par une
    gouttelette de l'aggregator : le nom aurait fait désigner le mauvais module.
    """
    r = _registre(tmp_path)
    (r / "aggregator.toml").write_text('id = "aggregator"\ncategory = "infra"\nruntime = "native"\n')
    modules_read._cache["signature"] = None
    conf = "server_name depot.gk2.secubox.in;\n proxy_pass http://unix:/run/secubox/aggregator.sock:/api/v1/droplet/depot;\n"
    m = module_de("depot.gk2.secubox.in", r, content=conf)
    assert m["id"] == "aggregator" and m["certain"] is True


def test_socket_inconnu_retombe_sur_le_nom(tmp_path):
    r = _registre(tmp_path)
    conf = "proxy_pass http://unix:/run/secubox/inexistant.sock:/;\n"
    m = module_de("depot.gk2.secubox.in", r, content=conf)
    assert m["id"] == "depot" and m["certain"] is False
