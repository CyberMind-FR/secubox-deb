# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""Release : la MOCHAbin ne publie que lite et isp ; `full` (2,6 Go) dépasse les 2 Gio d'un fichier de release GitHub
et faisait échouer l'étape « Create GitHub Release » (alpha 9). Les autres cartes ne changent pas."""
import importlib.util
from pathlib import Path

RACINE = Path(__file__).resolve().parents[2]
_s = importlib.util.spec_from_file_location("matrice", RACINE / ".github/scripts/matrice-images.py")
m = importlib.util.module_from_spec(_s)
_s.loader.exec_module(m)


def _profils(carte):
    return [x["profile"] for x in m.matrice(RACINE, [carte]) if x["board"] == carte]


def test_mochabin_publie_lite_et_isp_seulement():
    assert _profils("mochabin") == ["lite", "isp"]


def test_les_autres_cartes_sont_inchangees():
    assert _profils("rpi400") == ["lite", "isp", "full"]          # #2497 : lite ajouté pour la carte
    assert _profils("vm-x64") == ["full", "isp"]


def test_la_matrice_par_defaut_ne_contient_aucun_full_mochabin():
    toutes = m.matrice(RACINE, ["mochabin", "vm-x64", "rpi400", "espressobin-v7"])
    assert {"board": "mochabin", "profile": "full"} not in toutes


def test_l_espressobin_ne_publie_que_lite():
    """Depuis la refonte des profils (#2146), isp porte l'hebergement (8 Go) : jamais sur une carte de 1 a 2 Go."""
    assert _profils("espressobin-v7") == ["lite"]
    assert _profils("espressobin-ultra") == ["lite"]


def test_un_profil_force_ne_construit_que_celui_la_2497():
    assert m.matrice(RACINE, ["rpi400"], "lite") == [{"board": "rpi400", "profile": "lite"}]
    assert m.matrice(RACINE, ["rpi400", "vm-x64"], "isp") == [{"board": "rpi400", "profile": "isp"}, {"board": "vm-x64", "profile": "isp"}]
    assert _profils("rpi400") == ["lite", "isp", "full"]                              # auto : inchangé par la présence du paramètre


def test_la_ligne_de_commande_accepte_auto_et_refuse_un_profil_inconnu(tmp_path):
    import subprocess, sys
    base = [sys.executable, str(RACINE / ".github/scripts/matrice-images.py"), "--racine", str(RACINE), "--cartes", "rpi400"]
    assert subprocess.run(base + ["--profil", "lite"], capture_output=True, text=True).stdout.strip() == '{"include": [{"board": "rpi400", "profile": "lite"}]}'
    assert subprocess.run(base + ["--profil", "auto"], capture_output=True, text=True).returncode == 0
    assert subprocess.run(base + ["--profil", "enorme"], capture_output=True, text=True).returncode == 2


def test_le_workflow_propose_le_choix_du_profil_et_le_transmet():
    wf = (RACINE / ".github/workflows/build-image.yml").read_text(encoding="utf-8")
    assert "profile:" in wf and "options: [auto, lite, isp, full, minimal]" in wf   # #2816 : minimal, à la demande
    assert "--profil '${{ github.event.inputs.profile || 'auto' }}'" in wf


def test_le_profil_minimal_se_demande_a_la_main_sans_changer_les_defauts_2816():
    """#2816 : `minimal` (DPI, dns-guard, ad-guard, NAC, Freebox) est choisissable en declenchement manuel ; la matrice publiee ne change pas."""
    import importlib.util
    spec = importlib.util.spec_from_file_location("matrice_images", RACINE / ".github/scripts/matrice-images.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    assert m.matrice(RACINE, ["espressobin-v7"], "minimal") == [{"board": "espressobin-v7", "profile": "minimal"}]
    assert m.matrice(RACINE, ["espressobin-v7"]) == [{"board": "espressobin-v7", "profile": "lite"}]
    assert "minimal" in m.PROFILS_ACCEPTES
