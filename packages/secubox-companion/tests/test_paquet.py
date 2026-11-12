# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Paquet secubox-companion : garde sur l'APK, version.json, en-têtes SPDX, exclusion du CI."""
import hashlib
import json
import shutil
import subprocess
from pathlib import Path

import pytest

PAQUET = Path(__file__).resolve().parents[1]
DEPOT = PAQUET.parents[1]
LIEN = "secubox://associer?box=https%3A%2F%2Fadmin.gk12.secubox.in"


def fausse_apk(tmp_path):
    apk = tmp_path / "test.apk"
    apk.write_bytes(b"PK\x03\x04" + bytes(range(256)) * 40)
    return apk


def test_rules_echoue_sans_apk(tmp_path):
    r = subprocess.run(["make", "-f", "debian/rules", "override_dh_auto_install", "P=" + str(tmp_path / "p"),
                        "APK=" + str(tmp_path / "absent.apk")],
                       cwd=PAQUET, capture_output=True, text=True)
    assert r.returncode != 0
    assert "APK introuvable" in r.stderr
    assert not (tmp_path / "p").exists()


def test_version_json_cinq_cles_et_empreinte(tmp_path):
    apk = fausse_apk(tmp_path)
    r = subprocess.run(["sh", "build/version-json.sh", str(apk), "2.0", "7"], cwd=PAQUET, capture_output=True, text=True, check=True)
    d = json.loads(r.stdout)
    assert list(d) == ["version", "version_code", "sha256", "taille", "fichier"]
    assert d["version"] == "2.0" and d["version_code"] == 7 and d["fichier"] == "secubox-companion.apk"
    assert d["sha256"] == hashlib.sha256(apk.read_bytes()).hexdigest()
    assert d["taille"] == apk.stat().st_size


def test_version_json_echoue_sans_apk(tmp_path):
    r = subprocess.run(["sh", "build/version-json.sh", str(tmp_path / "absent.apk"), "2.0", "7"], cwd=PAQUET, capture_output=True, text=True)
    assert r.returncode != 0


def test_installation_des_quatre_fichiers(tmp_path):
    apk = fausse_apk(tmp_path)
    p = tmp_path / "p"
    subprocess.run(["make", "-f", "debian/rules", "override_dh_auto_install", "P=" + str(p), "APK=" + str(apk)],
                   cwd=PAQUET, capture_output=True, text=True, check=True)
    www = p / "usr/share/secubox/www/companion"
    assert sorted(f.name for f in www.iterdir()) == ["index.html", "qrcode.js", "secubox-companion.apk", "version.json"]
    d = json.loads((www / "version.json").read_text())
    assert d["sha256"] == hashlib.sha256((www / "secubox-companion.apk").read_bytes()).hexdigest()
    assert (p / "usr/share/secubox/menu.d/companion.json").is_file()


def test_menu_meme_categorie_que_mobile():
    menu = json.loads((PAQUET / "menu.d/companion.json").read_text())
    mobile = json.loads((PAQUET.parent / "secubox-mobile/menu.d/1-mobile.json").read_text())
    assert menu["id"] == "companion" and menu["category"] == mobile["category"] and menu["path"] == "/companion/"


def test_espaces_du_hub():
    t = json.loads((PAQUET.parent / "secubox-hub/espaces.json").read_text())
    assert "companion" in t["modules"]


def test_spdx_sur_chaque_fichier_nouveau():
    fichiers = [f for f in PAQUET.rglob("*") if f.is_file() and f.suffix in (".py", ".sh", ".html", ".js", ".md")]
    fichiers += [PAQUET / "debian/rules", PAQUET / "debian/control"]
    assert len(fichiers) >= 7
    for f in fichiers:
        assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in f.read_text(encoding="utf-8")[:600], f


def test_exclu_du_ci():
    wf = (DEPOT / ".github/workflows/build-packages.yml").read_text(encoding="utf-8")
    assert 'SKIP_CI="secubox-companion"' in wf
    assert '*" $pkg "*) echo "::notice::$pkg : binaire construit hors-CI' in wf


def test_profils_et_dependance_mobile():
    for profil in ("mobile", "full"):
        assert '"companion"' in (PAQUET.parent / f"secubox-profiles/profiles/{profil}.toml").read_text(encoding="utf-8")
    assert "secubox-companion" in (PAQUET.parent / "secubox-mobile/debian/control").read_text(encoding="utf-8")


def test_qr_identique_a_la_bibliotheque_de_reference(tmp_path):
    """La copie de qrcode.js (seconde copie des bits de format corrigée) donne les mêmes modules que la lib `qrcode`."""
    qrcode = pytest.importorskip("qrcode")
    if shutil.which("node") is None:
        pytest.skip("node absent")
    js = tmp_path / "m.mjs"
    js.write_text("import {matriceQR} from %s; const r = matriceQR(process.argv[2]);"
                  " console.log(JSON.stringify({v: r.version, m: r.matrix}));" % json.dumps((PAQUET / "www/companion/qrcode.js").as_uri()))
    for texte in (LIEN, "secubox://associer?box=https%3A%2F%2Fadmin.gk2.secubox.in", "x" * 150):
        sortie = json.loads(subprocess.run(["node", str(js), texte], capture_output=True, text=True, check=True).stdout)
        q = qrcode.QRCode(version=sortie["v"], error_correction=qrcode.constants.ERROR_CORRECT_L, mask_pattern=0, border=0)
        q.add_data(texte)
        q.make(fit=False)
        assert [[1 if c else 0 for c in ligne] for ligne in q.get_matrix()] == sortie["m"]
