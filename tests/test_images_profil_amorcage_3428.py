# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3428 : une image par matériel de référence, en profil d'AMORÇAGE strict (lite, minimal sur ESPRESSObin) ;
le profil final s'installe depuis premier pas (apt)."""
import importlib.util
import re
import subprocess
from pathlib import Path

RACINE = Path(__file__).resolve().parents[1]
LIVE = (RACINE / "image/build-live-usb.sh").read_text(encoding="utf-8")
RPI = (RACINE / "image/build-rpi-usb.sh").read_text(encoding="utf-8")
WF_LIVE = (RACINE / ".github/workflows/build-all-live-usb.yml").read_text(encoding="utf-8")


def test_live_usb_profil_lite_par_defaut_et_all_pour_l_ancien_comportement():
    assert 'IMAGE_PROFILE="lite"' in LIVE
    assert '--profile)        IMAGE_PROFILE="${2#secubox-}"' in LIVE
    assert "lite|minimal|isp|full|all) ;;" in LIVE
    # Hors « all », la fermeture Depends du méta-paquet seule ; le sélecteur échoue franchement s'il manque.
    assert 'if [[ "${IMAGE_PROFILE}" != "all" ]]; then' in LIVE
    assert re.search(r'select-profile-debs\.py" "\$\{_tous\}" "\$\{IMAGE_PROFILE\}" "\$\{ROOTFS\}/tmp/secubox-debs" amd64', LIVE)
    assert 'select-profile-debs.py" "${_tous}" kiosk' in LIVE          # --kiosk : secubox-kiosk (Recommends de lite) ajouté
    # Repli apt : le méta-paquet du profil, plus secubox-full en dur.
    assert 'APT_PROFILE_PKGS="secubox-${IMAGE_PROFILE}"' in LIVE
    assert "--force-confdef secubox-full'" not in LIVE


def test_live_usb_syntaxe_et_option_refusee():
    assert subprocess.run(["bash", "-n", str(RACINE / "image/build-live-usb.sh")]).returncode == 0
    assert subprocess.run(["bash", "-n", str(RACINE / "image/build-rpi-usb.sh")]).returncode == 0


def test_rpi_profil_lite_par_defaut_et_kiosque_ajoute():
    assert 'PROFILE_TAG="${PROFILE_TAG:-lite}"' in RPI
    assert "lite|minimal|isp) IMG_SIZE=\"8G\"" in RPI
    assert 'select-profile-debs.py" "${_ksrc}" kiosk' in RPI


def test_workflow_live_usb_profils_de_la_matrice():
    assert WF_LIVE.count('extra_args: "--kiosk --profile lite"') == 2      # x64 et rpi400 (rpi-arm64 = lite + kiosque HDMI)
    assert "--board mochabin \\\n            --profile lite" in WF_LIVE  # image eMMC embarquée : lite


def test_matrice_build_image_une_image_par_materiel():
    spec = importlib.util.spec_from_file_location("matrice", RACINE / ".github/scripts/matrice-images.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    assert m.matrice(RACINE, ["mochabin", "vm-x64", "rpi400", "espressobin-v7"]) == [
        {"board": "mochabin", "profile": "lite"}, {"board": "vm-x64", "profile": "lite"},
        {"board": "rpi400", "profile": "lite"}, {"board": "espressobin-v7", "profile": "minimal"}]


def _depends(paquet):
    txt = (RACINE / f"packages/{paquet}/debian/control").read_text(encoding="utf-8")
    bloc = txt.split("\nDepends:", 1)[1].split("\nRecommends:", 1)[0]
    return {m for m in re.findall(r"^\s*(secubox-[a-z0-9-]+)", bloc, re.M)}, txt


def test_lite_porte_tout_ce_qu_il_faut_au_premier_pas_et_au_kiosque():
    deps, txt = _depends("secubox-lite")
    for indispensable in ("secubox-premier-pas", "secubox-auth", "secubox-portal", "secubox-hub", "secubox-aggregator",
                          "secubox-haproxy", "secubox-waf-ng", "secubox-pilotage-agent", "secubox-netmodes",
                          "secubox-profiles", "secubox-core", "secubox-console"):
        assert indispensable in deps, indispensable
    assert re.search(r"^Recommends:.*secubox-kiosk", txt, re.M)
    # nginx vient de secubox-core ; le lanceur du kiosque de secubox-premier-pas, dont dépend secubox-kiosk.
    assert re.search(r"^\s*nginx,", (RACINE / "packages/secubox-core/debian/control").read_text(), re.M)
    assert "secubox-premier-pas" in (RACINE / "packages/secubox-kiosk/debian/control").read_text()


def test_verify_profile_lite_et_minimal_verts():
    for p in ("lite", "minimal"):
        r = subprocess.run(["bash", str(RACINE / "scripts/verify-profile.sh"), p], capture_output=True, text=True)
        assert r.returncode == 0, r.stdout + r.stderr


def test_meta_paquet_verifie_dans_l_image_et_profil_rpi_borne():
    assert LIVE.count('|| err "secubox-${IMAGE_PROFILE} non configuré') == 1
    assert '|| err "${_meta} non installé depuis' in LIVE and "secubox-full' 2>/dev/null || true" not in LIVE
    assert "lite|minimal|isp|full) ;;" in RPI and '|| err "secubox-${PROFILE_TAG} non installé' in RPI


def test_select_profile_debs_refuse_une_dependance_manquante(tmp_path, monkeypatch):
    spec = importlib.util.spec_from_file_location("sel", RACINE / "image/select-profile-debs.py")
    sel = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(sel)
    index = {"secubox-lite": (tmp_path / "l.deb", {"secubox-absent"})}
    assert sel._copier(index, ["secubox-lite"], tmp_path / "d", "lite") == 1
    assert not (tmp_path / "d").exists()
