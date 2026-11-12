# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Companion 2.0 : couche Android, vérifiée par lecture des sources (sans construire l'APK)."""
import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path

RACINE = Path(__file__).resolve().parents[1]
APP = RACINE / "android" / "app"
JAVA = APP / "src" / "main" / "java" / "in" / "secubox" / "companion"
MANIFESTE = APP / "src" / "main" / "AndroidManifest.xml"
NS = "{http://schemas.android.com/apk/res/android}"


def _source(nom):
    return (JAVA / nom).read_text(encoding="utf-8")


def _sans_commentaires(java):
    java = re.sub(r"/\*.*?\*/", "", java, flags=re.S)
    # Commentaire de ligne : « // » en début de ligne ou précédé d'un blanc (pas « https:// »).
    return re.sub(r"(?m)(^|\s)//[^\n]*", r"\1", java)


def _activites():
    racine = ET.parse(MANIFESTE).getroot()
    return {a.get(NS + "name"): a for a in racine.iter("activity")}


def test_lien_profond_secubox_associer_sur_main_activity():
    main = _activites()[".MainActivity"]
    trouve = False
    for filtre in main.iter("intent-filter"):
        actions = {a.get(NS + "name") for a in filtre.iter("action")}
        categories = {c.get(NS + "name") for c in filtre.iter("category")}
        donnees = [(d.get(NS + "scheme"), d.get(NS + "host")) for d in filtre.iter("data")]
        if ("secubox", "associer") in donnees:
            assert actions == {"android.intent.action.VIEW"}
            assert categories == {"android.intent.category.DEFAULT", "android.intent.category.BROWSABLE"}
            trouve = True
    assert trouve, "intent-filter secubox://associer absent de MainActivity"


def test_box_activity_declaree_non_exportee():
    box = _activites().get(".BoxActivity")
    assert box is not None, "BoxActivity non déclarée"
    assert box.get(NS + "exported") == "false"
    assert not list(box.iter("intent-filter")), "BoxActivity ne doit recevoir aucun intent implicite"


def test_box_activity_sans_pont_natif():
    src = _source("BoxActivity.java")
    assert "addJavascriptInterface" not in src
    assert "com.getcapacitor" not in src
    assert "evaluateJavascript" not in src


def test_user_agent_companion():
    src = _source("BoxActivity.java")
    assert '" SecuBoxCompanion/2.0"' in src
    assert "getUserAgentString()" in src


def test_box_activity_garde_l_origine_et_n_ouvre_que_http_https():
    code = _sans_commentaires(_source("BoxActivity.java"))
    assert "shouldOverrideUrlLoading" in code
    assert "ACTION_VIEW" in code
    assert re.search(r'"https"\.equals\(', code) and re.search(r'"http"\.equals\(', code)
    for interdit in ('"intent"', '"file"', "parseUri", "setAllowFileAccess(true)"):
        assert interdit not in code
    assert "setAllowFileAccess(false)" in code
    assert "isForMainFrame" in code
    assert "finish()" in code


def test_version_android_2_0():
    gradle = (APP / "build.gradle").read_text(encoding="utf-8")
    assert re.search(r"^\s*versionCode 7\s*$", gradle, re.M)
    assert re.search(r'^\s*versionName "2\.0"\s*$', gradle, re.M)


def test_capacitor_sans_allow_navigation():
    brut = (RACINE / "capacitor.config.json").read_text(encoding="utf-8")
    assert "allowNavigation" not in brut
    json.loads(brut)


def test_package_json_2_0():
    pkg = json.loads((RACINE / "package.json").read_text(encoding="utf-8"))
    assert pkg["version"] == "2.0.0"
    assert pkg["scripts"]["test"].startswith("node --test tests/")
    assert "cap sync" not in json.dumps(pkg["scripts"])


def test_main_activity_lien_profond_et_plugin():
    code = _sans_commentaires(_source("MainActivity.java"))
    assert "onNewIntent" in code
    assert '"https://localhost/#associer="' in code
    i_plugin = code.index("registerPlugin(BoitePlugin.class)")
    i_super = code.index("super.onCreate")
    assert i_plugin < i_super


def test_plugin_boite():
    code = _sans_commentaires(_source("BoitePlugin.java"))
    assert '@CapacitorPlugin(name = "Boite")' in code
    assert re.search(r"public void ouvrir\(PluginCall", code)
    assert re.search(r"public void navigateur\(PluginCall", code)
    assert "BoxActivity.class" in code
    assert '"joignable", true' in code
    assert "#injoignable=" in code
    assert "addJavascriptInterface" not in code


def test_en_tetes_spdx():
    for nom in ("MainActivity.java", "BoitePlugin.java", "BoxActivity.java"):
        assert _source(nom).startswith("// SPDX-License-Identifier: LicenseRef-CMSD-1.0\n"), nom
