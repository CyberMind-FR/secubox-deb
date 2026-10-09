# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""Page Actor Intelligence (admin.gk2/actor/, actor.gk2) : vues de la maquette, données réelles seulement."""
import re
from pathlib import Path

HTML = (Path(__file__).resolve().parents[1] / "www" / "actor" / "index.html").read_text()


def test_vue_d_ensemble_tuiles_carte_et_evenements():
    for ident in ("tuiles", "carteMonde", "paysTop", "even"):
        assert f'id="{ident}"' in HTML, ident
    for fonction in ("function carteMonde(", "function rendEven(", "function rendTuiles(", "function aperçu("):
        assert fonction in HTML, fonction
    assert "/api/v1/actor/overview" in HTML


def test_la_fiche_a_la_courbe_24h_et_les_techniques():
    assert "function courbe(" in HTML and "activite_acteurs" in HTML
    assert "Techniques observées" in HTML and "techniques" in HTML


def test_les_tuiles_suivent_le_score_de_la_page():
    # critiques / suspects / observés : même échelle que palierScore() (70 / 45), jamais un second barème
    assert re.search(r"function rendTuiles\([^)]*\)\{[^}]*score\(", HTML, re.S)


def test_l_apercu_n_est_relu_qu_une_fois_par_minute():
    assert re.search(r"55000|60000", HTML)


def test_valeurs_serveur_echappees_et_aucune_ressource_externe():
    assert "esc(e.acteur" in HTML and "esc(e.type" in HTML and "esc(e.module" in HTML
    assert "http://" not in HTML.replace("http://www.w3.org/2000/svg", "")


def test_pas_de_donnees_inventees():
    assert "Math.random" not in HTML


def test_moteur_absent_ou_en_demarrage_est_dit_clairement():
    assert "en démarrage ou injoignable" in HTML and "nouvel essai automatique" in HTML


def test_les_scripts_de_la_page_sont_du_javascript_valide():
    # une apostrophe non échappée dans une chaîne casserait tout le script sans qu'aucun test de contenu ne le voie
    import re
    import shutil
    import subprocess
    import tempfile
    if shutil.which("node") is None:
        return
    for i, js in enumerate(re.findall(r"<script(?![^>]*\bsrc=)[^>]*>(.*?)</script>", HTML, re.S)):
        with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False) as f:
            f.write(js)
        r = subprocess.run(["node", "--check", f.name], capture_output=True, text=True)
        assert r.returncode == 0, f"script {i + 1} : {r.stderr.strip().splitlines()[-1] if r.stderr else 'erreur'}"


def test_les_robots_connus_sont_classes_a_part_et_echappes():
    """#2201 : une tuile et une ligne dédiées, alimentées par `robots` de l'aperçu ; jamais dans les paliers critiques/suspects/observés."""
    assert "function rendRobots(" in HTML and "APERCU.robots" in HTML
    assert "accès de robots connus" in HTML and "esc(x.famille)" in HTML
    corps = re.search(r"function rendTuiles\(\)\{(.*?)\n\}", HTML, re.S).group(1)
    assert "rendRobots()" in corps
    assert "score(a)" in corps and "robot" not in corps.split("rendRobots()")[0].lower().replace("acteurs", "")   # le barème des acteurs ignore les robots
