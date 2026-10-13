# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2597 — /config-advisor/ au profil Aurora : test statique + vrai navigateur, API simulée."""
import json
import re
from pathlib import Path

import pytest

PAGE = Path(__file__).resolve().parents[1] / "www" / "config-advisor" / "index.html"
SRC = PAGE.read_text(encoding="utf-8")


def test_page_autonome_sans_dialogue_natif():
    assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in SRC
    assert re.findall(r'<script src="([^"]+)"', SRC) == ["/shared/sidebar.js"]
    assert "googleapis" not in SRC and "hybrid-dark" not in SRC and "crt-engine" not in SRC
    for interdit in ("confirm(", "alert(", "prompt(", "innerHTML"):
        assert interdit not in SRC
    assert "sbxVue" in SRC and "onglet: 'config-advisor'" in SRC and "demo" in SRC and "embed" in SRC
    assert "sbx_token" in SRC and "onclick=" not in SRC


def test_routes_a_l_identique_et_route_fantome_disparue():
    # écritures de l'ancienne page : POST /audit et POST /fix/<id>, sans corps
    assert "ecrire('/audit')" in SRC and "'/fix/' + encodeURIComponent" in SRC
    assert "method: 'POST'" in SRC and SRC.count("method: 'POST'") == 1
    # lectures réelles de l'API
    assert "lire('/report')" in SRC and "lire('/history" in SRC
    # l'ancienne page lisait /recommendations et security_score, qui n'existent pas
    assert "/recommendations" not in SRC and "security_score" not in SRC and "fix_available" not in SRC


def test_chaque_correctif_propose_existe_cote_api():
    api = (PAGE.parents[2] / "api" / "main.py").read_text(encoding="utf-8")
    bloc = api.split("fixes = {", 1)[1].split("}", 1)[0]
    ids_api = set(re.findall(r'"([A-Z0-9-]+)":', bloc))
    ids_page = set(re.findall(r"'([A-Z0-9-]+)': \[", SRC.split("const CORRECTIFS", 1)[1].split("};", 1)[0]))
    assert ids_page == ids_api and len(ids_api) == 6


playwright = pytest.importorskip("playwright.sync_api")


@pytest.fixture(scope="module")
def navigateur():
    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch()
        yield b
        b.close()


def c(check_id, name, cat, sev, status, **kw):
    return {"check_id": check_id, "name": name, "category": cat, "severity": sev, "status": status,
            "description": kw.get("d", "desc " + check_id), "finding": kw.get("f"), "remediation": kw.get("r"), "reference": "CIS 1"}


RAPPORT = {"id": "audit-1", "timestamp": "2026-10-13T08:00:00Z", "duration_ms": 10, "total_checks": 5, "passed": 2, "failed": 1, "warnings": 1, "skipped": 1, "score": 50.0,
           "results": [c("ANSSI-R28", "SSH root login disabled", "authentication", "critical", "fail", f="PermitRootLogin yes", r="PermitRootLogin no"),
                       c("FS-02", "Cron directory permissions", "filesystem", "medium", "warning", d="<b>x</b>"),
                       c("SUDO-01", "No NOPASSWD in sudoers", "access_control", "high", "warning"),
                       c("FS-01", "/etc/shadow permissions", "filesystem", "critical", "pass"),
                       c("KERNEL-01", "Kernel hardening", "kernel", "medium", "skip")]}
HIST = {"history": [{"id": "a2", "timestamp": "2026-10-13T08:00:00Z", "score": 50.0, "passed": 2, "failed": 1},
                    {"id": "a1", "timestamp": "2026-10-12T08:00:00Z", "score": 25.0, "passed": 1, "failed": 2}]}
API = {"/report": (200, RAPPORT), "/history": (200, HIST), "/audit": (200, RAPPORT), "/fix/ANSSI-R28": (200, {"success": True, "action": "Set PermitRootLogin no"})}


def ouvre(navigateur, url, routes, taille=None):
    ctx = navigateur.new_context(viewport=taille or {"width": 1300, "height": 900})
    p = ctx.new_page()
    erreurs, appels = [], []
    p.on("pageerror", lambda e: erreurs.append(str(e)))

    def fichier(r, *_):
        chemin = r.request.url.split("http://sbx.test/", 1)[1].split("?")[0]
        if chemin.startswith("shared/"):
            r.fulfill(status=200, content_type="text/css" if chemin.endswith(".css") else "application/javascript", body="")
        elif chemin.rstrip("/") == "config-advisor":
            r.fulfill(status=200, content_type="text/html", body=SRC)
        else:
            r.fulfill(status=404, body="")
    p.route("http://sbx.test/**", fichier)

    def api(r, *_):
        chemin = r.request.url.split("/api/v1/config-advisor", 1)[1].split("?")[0]
        appels.append((r.request.method, chemin, r.request.post_data))
        statut, corps = routes.get(chemin, (404, {"detail": "absent"}))
        r.fulfill(status=statut, content_type="application/json", body=json.dumps(corps))
    p.route("http://sbx.test/api/v1/config-advisor/**", api)
    p.goto(url)
    return ctx, p, erreurs, appels


def test_tuiles_recommandations_et_tableau(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/config-advisor/", API)
    p.wait_for_selector("#reco .reco")
    assert [p.inner_text(i) for i in ("#tScore", "#tPass", "#tWarn", "#tFail", "#tCrit", "#tTotal")] == ["50", "2", "1", "1", "1", "5"]
    assert "1 ignorés" in p.inner_text("#sTotal") and p.inner_text("#etat") == "À RENFORCER"
    assert p.locator("#reco .reco").count() == 3
    assert "<b>x</b>" in p.inner_text("#reco")                       # affiché tel quel, jamais interprété
    assert p.locator("#bTous tr").count() == 5 and p.locator("#courbe circle").count() == 2 and p.is_visible("#courbe")
    assert err == []
    ctx.close()


def test_correctif_confirmation_dans_la_page_puis_post_sans_corps(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/config-advisor/", API)
    p.wait_for_selector("#reco .reco")
    p.locator("#reco .reco").first.get_by_text("Appliquer le correctif").click()
    assert "PermitRootLogin no" in p.inner_text("#reco .conf") and "sshd_config" in p.inner_text("#reco .conf")
    assert not [a for a in appels if a[0] == "POST"]               # rien avant confirmation
    p.get_by_text("Annuler").click()
    assert p.locator("#reco .conf").count() == 0 and not [a for a in appels if a[0] == "POST"]
    p.locator("#reco .reco").first.get_by_text("Appliquer le correctif").click()
    p.get_by_text("Confirmer").click()
    p.wait_for_function("document.getElementById('rReco').textContent.includes('Correctif appliqué')")
    assert ("POST", "/fix/ANSSI-R28", None) in appels and err == []
    ctx.close()


def test_lancer_un_audit_poste_sans_corps(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/config-advisor/", API)
    p.wait_for_selector("#reco .reco")
    p.click("#audit")
    p.wait_for_function("document.getElementById('rReco').textContent.includes('Audit terminé')")
    assert ("POST", "/audit", None) in appels and err == []
    ctx.close()


def test_aucun_audit_n_est_pas_une_erreur_de_session(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/config-advisor/", {"/report": (404, {"detail": "No audit report available"}), "/history": (200, {"history": []})})
    p.wait_for_function("document.getElementById('etat').textContent === 'AUCUN AUDIT'")
    assert not p.is_visible("#session") and p.inner_text("#tScore") == "—" and "lancez un audit" in p.inner_text("#reco") and err == []
    ctx.close()


def test_sans_session_bandeau_et_tirets(navigateur):
    refus = {k: (401, {"detail": "jeton requis"}) for k in ("/report", "/history")}
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/config-advisor/", refus)
    p.wait_for_selector("#session:not([hidden])")
    assert "session requise" in p.inner_text("#session") and p.inner_text("#etat") == "SESSION REQUISE"
    assert [p.inner_text(i) for i in ("#tScore", "#tPass", "#tWarn", "#tFail", "#tCrit", "#tTotal")] == ["—"] * 6 and err == []
    ctx.close()


def test_demonstration_annoncee_et_actions_inertes(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/config-advisor/?demo=1", {})
    p.wait_for_selector("#reco .reco")
    assert p.is_visible("#demo") and "DÉMONSTRATION" in p.inner_text("#demo")
    p.locator("#reco .reco").first.get_by_text("Appliquer le correctif").click()
    p.get_by_text("Confirmer").click()
    p.wait_for_function("document.getElementById('rReco').textContent.includes('inerte')")
    p.click("#audit")
    p.wait_for_function("document.getElementById('rReco').textContent.includes('inerte')")
    assert appels == [] and err == []
    ctx.close()


def test_telephone_sans_debordement(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/config-advisor/?embed=1", API, taille={"width": 420, "height": 800})
    p.wait_for_selector("#reco .reco")
    assert p.evaluate("document.documentElement.scrollWidth <= innerWidth + 1")
    assert not p.is_visible("#sidebar") and err == []
    ctx.close()
