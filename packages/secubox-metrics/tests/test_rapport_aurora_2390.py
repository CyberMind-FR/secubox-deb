# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2390 : le rapport de fréquentation parle Aurora (page sombre, tuiles, carte), sur les primitives communes de pdf_aurora ; le rapport de sécurité reste identique."""
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "api"))
pytest.importorskip("fpdf")
pytest.importorskip("matplotlib")
import pdf_aurora as A  # noqa: E402
import rapport  # noqa: E402

JOURS = [f"2026-10-{d:02d}" for d in range(1, 8)]
PAYS = [{"code": "FR", "n": 40, "drapeau": ""}, {"code": "US", "n": 12, "drapeau": ""}]


def _vh(nom, v):
    return {"vhost": nom, "visites": v, "requetes": v * 5, "visiteurs": v // 3, "octets": v * 1000, "robots": v, "part_robots": 12.5, "erreurs": 3,
            "navigateurs": {"Chrome": v}, "plateformes": {"Linux": v}, "statuts": {"2xx": v * 4, "5xx": 2}, "pays": PAYS}


VUE = {"actif": True, "periode": "semaine", "du": JOURS[0], "au": JOURS[-1],
       "serie": [{"jour": j, "visites": 10 + i, "requetes": 50, "sondes": 0, "erreurs": 1} for i, j in enumerate(JOURS)],
       "total": {"visites": 100, "visiteurs": 40, "requetes": 500, "erreurs": 9, "top_referents": [{"hote": "exemple.fr", "n": 5}], "directs_pct": 50.0, "navigateurs": {"Chrome": 10}, "plateformes": {"Linux": 10}},
       "vhosts": [_vh("a.test", 60), _vh("é–“ nom.test", 40)]}
DETAIL = dict(_vh("a.test", 60), serie=[{"jour": j, "visites": 5, "visiteurs": 2, "requetes": 20, "sondes": 0, "erreurs": 1} for j in JOURS], periode="semaine",
              cumul={"depuis": "2026-01-01", "visites": 500, "requetes": 1, "base": 440}, pays_cumul={"FR": 90, "DE": 3}, membres=["a.test", "b.test"],
              top_chemins=[{"chemin": "/é–/ü", "n": 4}], top_referents=[{"hote": "exemple.fr", "n": 5}], directs_pct=40.0)


def test_pdf_tous_et_vhost_se_fabriquent():
    assert rapport.construire_pdf(VUE)[:5] == b"%PDF-"
    assert rapport.construire_pdf(VUE, DETAIL)[:5] == b"%PDF-"


def test_cas_pauvres_ne_cassent_pas():
    vide = {"actif": True, "periode": "jour", "du": JOURS[0], "au": JOURS[0], "serie": [{"jour": JOURS[0], "visites": 1}], "total": {}, "vhosts": []}
    assert rapport.construire_pdf(vide)[:5] == b"%PDF-"
    assert rapport.construire_pdf(vide, {"vhost": "x", "periode": "jour"})[:5] == b"%PDF-"


def test_pdf_aurora_importable_et_palette_sombre():
    assert A.FOND == (6, 13, 27) and A.CYAN == (41, 182, 246)
    assert sum(A.FOND) < 100                      # fond sombre


def test_une_mesure_absente_est_un_tiret_pas_un_zero():
    assert A.n(None) == "—" and A.octets(None) == "—" and A.n(0) == "0"
    tuiles = rapport._tuiles_aurora({"visites": 3}, [])
    valeurs = {t[0]: t[1] for t in tuiles}
    assert valeurs["Visites"] == "3" and valeurs["Erreurs"] == "—" and valeurs["Bande passante"] == "—"


def test_les_textes_sont_latin1():
    assert A.txt("é–“x”→·…").encode("latin-1")
    assert rapport._date_fr("2026-10-01") == "01/10/2026"


@pytest.mark.skipif(not shutil.which("pdftoppm"), reason="pdftoppm absent")
def test_la_premiere_page_est_sombre(tmp_path):
    f = tmp_path / "r.pdf"
    f.write_bytes(rapport.construire_pdf(VUE))
    subprocess.run(["pdftoppm", "-r", "20", "-png", "-f", "1", "-l", "1", str(f), str(tmp_path / "p")], check=True)
    png = next(tmp_path.glob("p*.png")).read_bytes()
    import io
    import matplotlib.image as mpimg
    px = mpimg.imread(io.BytesIO(png))
    assert px[2, 2, :3].max() < 0.2               # coin de page : le fond Aurora, pas du blanc


def test_rapport_securite_reste_sur_les_primitives_communes():
    import rapport_securite as RS
    assert RS._panneau is A.panneau and RS._rangee_tuiles is A.rangee_tuiles and RS.graphe_carte is A.graphe_carte and RS.PALETTE is A.PALETTE
    assert RS.graphe_carte({"FR": 3})[:8] == b"\x89PNG\r\n\x1a\n"
    assert RS.construire_pdf_securite({"genere": __import__("datetime").datetime(2026, 10, 11), "waf": {}, "actor": {}, "dpi": None})[:5] == b"%PDF-"
