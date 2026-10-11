# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2335 : mediaflow et ndpid sont servis par l'agrégateur — plus de démon uvicorn dédié (~150 Mo) ni de socket dédiée — sans casser leurs routes ni leur répertoire de données."""
import importlib.util
import re
from pathlib import Path

RACINE = Path(__file__).resolve().parents[2]
DPI = RACINE / "packages" / "secubox-dpi"


def _lire(p):
    return Path(p).read_text(encoding="utf-8")


def test_dpi_ne_livre_plus_les_unites_dediees():
    r = _lire(DPI / "debian" / "rules")
    actives = [l for l in r.splitlines() if not l.lstrip().startswith("#")]
    assert not any("secubox-ndpid.service" in l or "secubox-mediaflow.service" in l for l in actives)
    assert any("yt-dlp-refresh" in l for l in actives)                       # le rafraîchissement de yt-dlp, lui, reste (minuterie séparée)


def test_ndpid_est_declare_dans_l_agregateur_et_son_ancien_demon_desactive():
    s = _lire(DPI / "composants" / "ndpid" / "debian" / "postinst")
    assert '"ndpid"' in s and "aggregator.toml" in s and "disable --now secubox-ndpid.service" in s
    assert '[ "$NOUVEAU" = "oui" ]' in s and "restart secubox-aggregator" in s   # redémarrage seulement si ndpid vient d'y être déclaré


def test_mediaflow_ancien_demon_desactive_sans_redemarrer_l_agregateur_pour_rien():
    s = _lire(DPI / "composants" / "mediaflow" / "debian" / "postinst")
    assert "disable --now secubox-mediaflow.service" in s and "systemctl enable secubox-mediaflow.service" not in s
    assert '"mediaflow"' in s and '[ "$NOUVEAU" = "oui" ]' in s


def test_les_routes_visent_l_agregateur_pas_une_socket_dediee():
    for f in (DPI / "composants" / "ndpid" / "nginx" / "ndpid.conf", DPI / "composants" / "mediaflow" / "nginx" / "mediaflow.conf",
              RACINE / "packages" / "secubox-hub" / "nginx" / "webui.conf", RACINE / "common" / "nginx" / "modules.d" / "mediaflow.conf"):
        t = _lire(f)
        assert "/run/secubox/ndpid.sock" not in t and "/run/secubox/mediaflow.sock" not in t, f
    assert "aggregator.sock:/api/v1/ndpid/" in _lire(DPI / "composants" / "ndpid" / "nginx" / "ndpid.conf")
    assert "aggregator.sock:/api/v1/ndpid/" in _lire(RACINE / "packages" / "secubox-hub" / "nginx" / "webui.conf")


def test_ndpid_cree_son_repertoire_de_donnees_a_l_import(tmp_path, monkeypatch):
    """L'agrégateur importe le module sans déclencher le hook de démarrage : le répertoire ne doit plus en dépendre."""
    src = _lire(DPI / "composants" / "ndpid" / "api" / "main.py")
    assert re.search(r"^_assurer_donnees\(\)$", src, re.M) and "except OSError" in src
