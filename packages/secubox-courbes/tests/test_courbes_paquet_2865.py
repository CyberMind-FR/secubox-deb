# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2865 — secubox-courbes : Courbes (/grafana/) et Glances (/glances/) sans secubox-metrics (350 Mo de processus), pour le profil minimal."""
import re
import tomllib
from pathlib import Path

PKG = Path(__file__).resolve().parents[1]
REPO = PKG.parents[1]
CONTROL = (PKG / "debian" / "control").read_text(encoding="utf-8")


def _depends(control: str) -> str:
    """Le champ Depends seul (lignes de continuation, sans commentaires)."""
    m = re.search(r"^Depends:((?:.*\n)(?: .*\n|#.*\n)*)", control.split("Package: secubox-courbes", 1)[1], re.M)
    return "\n".join(l for l in m.group(1).splitlines() if not l.startswith("#"))


def test_le_paquet_est_leger_et_ne_depend_pas_de_metrics():
    dep = _depends(CONTROL)
    assert "secubox-metrics" not in dep
    assert "python3-psutil" in dep and "secubox-core" in dep
    for lourd in ("matplotlib", "fpdf", "weasyprint", "maxminddb"):
        assert lourd not in dep


def test_il_livre_les_deux_pages_la_declaration_groupable_et_le_releve():
    assert (PKG / "www" / "grafana" / "index.html").is_file() and (PKG / "www" / "glances" / "index.html").is_file()
    assert (PKG / "groupable.d" / "courbes").is_file() and (PKG / "api" / "main.py").is_file()
    assert (PKG / "systemd" / "secubox-courbes-serie.timer").is_file() and (PKG / "systemd" / "secubox-courbes-serie.service").is_file()
    ids = {__import__("json").loads(f.read_text(encoding="utf-8"))["id"] for f in (PKG / "menu.d").glob("*.json")}
    assert {"grafana", "glances"} <= ids


def test_le_module_est_servi_a_la_racine_sans_prefixe():
    """L'agrégateur retire /api/v1/courbes : routes à la racine, aucun fichier nginx (convention des modules à socket)."""
    src = (PKG / "api" / "main.py").read_text(encoding="utf-8")
    assert '@app.get("/series"' in src and '@app.get("/systeme"' in src and '@app.get("/health"' in src
    assert "/api/v1/" not in src.replace("/api/v1/courbes", "")


def test_les_pages_appellent_l_api_de_courbes():
    for page in ("grafana", "glances"):
        s = (PKG / "www" / page / "index.html").read_text(encoding="utf-8")
        assert "/api/v1/courbes/" in s and "/api/v1/metrics/" not in s, page


def test_le_releve_ecrit_au_meme_endroit_que_metrics():
    """L'historique de 7 jours de gk2 est conservé : même fichier."""
    from secubox_courbes import serie
    assert str(serie.FICHIER) == "/var/lib/secubox/metrics/series.jsonl"


def test_metrics_depend_de_courbes_et_ne_garde_plus_la_copie():
    ctl = (REPO / "packages" / "secubox-metrics" / "debian" / "control").read_text(encoding="utf-8")
    assert "secubox-courbes" in ctl
    assert not (REPO / "packages" / "secubox-metrics" / "api" / "serie.py").exists()
    assert not (REPO / "packages" / "secubox-metrics" / "api" / "systeme.py").exists()


def test_courbes_quitte_minimal_3218():
    """#2865 l'embarquait dans minimal ; le banc de l'ESPRESSObin de 1 Go (#3218) en a fait un surplus : Conflicts, profil et minuterie."""
    m = (REPO / "packages" / "secubox-minimal" / "debian" / "control").read_text(encoding="utf-8")
    assert not re.search(r"^ secubox-courbes", m.split("Conflicts:")[0], re.M)
    assert re.search(r"^Conflicts:(.*\n)*?.*secubox-courbes", m, re.M)
    toml = tomllib.loads((REPO / "packages" / "secubox-profiles" / "profiles" / "minimal.toml").read_text(encoding="utf-8"))
    assert "courbes" not in toml["on"] and "courbes-serie" in toml["minuteurs_off"]
