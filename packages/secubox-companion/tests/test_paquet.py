# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Paquet secubox-companion : garde sur l'APK, version.json, en-têtes SPDX, exclusion du CI."""
import hashlib
import json
import re
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


def test_ni_profils_ni_dependance_mobile():
    """Companion s'installe à la demande : ni la clé mobile (pas de certificat valide) ni les profils ne le portent."""
    for profil in ("mobile", "full"):
        assert '"companion"' not in (PAQUET.parent / f"secubox-profiles/profiles/{profil}.toml").read_text(encoding="utf-8")
    assert "secubox-companion" not in (PAQUET.parent / "secubox-mobile/debian/control").read_text(encoding="utf-8")


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


def test_menu_porte_l_unite_aggregator():
    assert json.loads((PAQUET / "menu.d/companion.json").read_text())["unite"] == "aggregator"


def test_route_nginx_apk_et_version_json():
    conf = (PAQUET / "nginx/companion.conf").read_text(encoding="utf-8")
    apk = conf.split("location = /companion/secubox-companion.apk")[1].split("location = /companion/version.json")[0]
    assert "types { }" in apk and "default_type application/vnd.android.package-archive;" in apk
    assert 'add_header Cache-Control "no-cache" always;' in apk and 'add_header X-Content-Type-Options nosniff always;' in apk
    ver = conf.split("location = /companion/version.json")[1]
    assert 'add_header Cache-Control "no-cache" always;' in ver
    # une route exacte, pas de proxy ni de vhost
    assert "proxy_pass" not in conf and "server {" not in conf


def test_route_installee_dans_routes_d_et_incluse_par_le_serveur_admin(tmp_path):
    apk = fausse_apk(tmp_path)
    p = tmp_path / "p"
    subprocess.run(["make", "-f", "debian/rules", "override_dh_auto_install", "P=" + str(p), "APK=" + str(apk)],
                   cwd=PAQUET, capture_output=True, text=True, check=True)
    assert (p / "etc/nginx/secubox-routes.d/companion.conf").is_file()
    webui = (PAQUET.parent / "secubox-hub/nginx/webui.conf").read_text(encoding="utf-8")
    assert "include /etc/nginx/secubox-routes.d/*.conf;" in webui


@pytest.mark.skipif(shutil.which("nginx") is None, reason="nginx absent")
def test_nginx_accepte_la_route(tmp_path):
    (tmp_path / "www/companion").mkdir(parents=True)
    (tmp_path / "www/companion/secubox-companion.apk").write_bytes(b"PK")
    (tmp_path / "www/companion/version.json").write_text("{}")
    (tmp_path / "nginx.conf").write_text(
        "pid %s/n.pid; error_log %s/e.log; events {} http { access_log off; client_body_temp_path %s/b; proxy_temp_path %s/p;"
        " server { listen 127.0.0.1:19091; root %s/www; include %s; } }"
        % (tmp_path, tmp_path, tmp_path, tmp_path, tmp_path, PAQUET / "nginx/companion.conf"))
    r = subprocess.run(["nginx", "-t", "-c", str(tmp_path / "nginx.conf")], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr


def test_postinst_teste_nginx_avant_de_recharger():
    sh = (PAQUET / "debian/postinst").read_text(encoding="utf-8")
    assert sh.index("nginx -t") < sh.index("systemctl reload nginx")


def test_strip_nondeterminism_exclut_les_apk():
    assert "dh_strip_nondeterminism -X.apk" in (PAQUET / "debian/rules").read_text(encoding="utf-8")


def test_version_identique_partout():
    rules = (PAQUET / "debian/rules").read_text(encoding="utf-8")
    v = re.search(r"^VERSION = (\S+)", rules, re.M).group(1)
    code = re.search(r"^VERSION_CODE = (\d+)", rules, re.M).group(1)
    app = DEPOT / "secubox-companion"
    gradle = (app / "android/app/build.gradle").read_text(encoding="utf-8")
    assert re.search(r'versionName "%s"' % re.escape(v), gradle) and re.search(r"versionCode %s\b" % code, gradle)
    assert re.search(r'VERSION_LOCALE = "%s"' % re.escape(v), (app / "www/core/app.js").read_text(encoding="utf-8"))
    java = next((app / "android/app/src/main/java").rglob("BoxActivity.java")).read_text(encoding="utf-8")
    assert re.search(r'SUFFIXE_UA = " SecuBoxCompanion/%s"' % re.escape(v), java)
    assert (PAQUET / "debian/changelog").read_text(encoding="utf-8").startswith("secubox-companion (%s." % v)
