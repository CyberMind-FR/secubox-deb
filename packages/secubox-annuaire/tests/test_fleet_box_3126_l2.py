# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""#3126 L2 tâche 8 — page de la box dans la Flotte : actions du catalogue, confirmation forte, support, journal, flux SSE.

Tests statiques (analyse du JS) puis comportement (Chromium via Playwright, API simulée). XSS-strict : toute donnée en textContent."""
import json
import pathlib
import re
import shutil
import subprocess
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).parent))
from test_fleet_page_aurora_2487 import PAGE, _nav  # noqa: E402

HTML = PAGE.read_text(encoding="utf-8")
MAINTENANT = 4102444800
HTML_MALVEILLANT = "<img src=x onerror=alert(1)>"


def _js():
    m = re.search(r"// ===== pilotage-box =====(.*?)// ===== fin pilotage-box =====", HTML, re.S)
    assert m, "bloc JS pilotage-box délimité introuvable"
    return m.group(1)


# ---------------------------------------------------------------- statiques

def test_bloc_et_panneau_presents():
    assert 'id="pb-pan"' in HTML and "<!-- fin pb-pan -->" in HTML
    assert "/api/v1/pilotage/boxes/" in _js() and "/operations" in _js()


def test_aucune_donnee_en_innerhtml():
    """Aucune affectation innerHTML (ni outerHTML, insertAdjacentHTML, document.write, attribut d'événement) dans toute la page."""
    assert not re.search(r"outerHTML|insertAdjacentHTML|document\.write|\bon[a-z]+\s*=\s*['\"]", HTML.split("<script>", 1)[1])
    for m in re.finditer(r"innerHTML\s*(\+?=)\s*([^;\n]*)", HTML):
        assert re.fullmatch(r"\s*(['\"`])[^$\"'`]*\1\s*", m.group(2)) and m.group(1) == "=", f"innerHTML non constant : {m.group(0)}"
    assert not re.search(r"innerHTML", _js())
    assert "textContent" in _js()


def test_flux_par_fetch_et_authorization_pas_eventsource():
    js = _js()
    assert "EventSource" not in HTML
    assert "/flux" in js and "getReader" in js and "TextDecoder" in js and "Authorization" in js


def test_dedoublonnage_par_job_et_par_id():
    js = _js()
    assert re.search(r"\bjob\b", js) and re.search(r"\bid\b", js)
    assert "new Set" in js or "new Map" in js or "seen" in js.lower()


def test_gestion_de_la_coupure_et_de_la_perte():
    js = _js()
    assert "expiree" in js and "/login.html" in js and "termine" in js and "perte" in js


def test_syntaxe_js_node():
    node = shutil.which("node")
    if not node:
        pytest.skip("node absent")
    scripts = re.findall(r"<script>(.*?)</script>", HTML, re.S)
    assert scripts
    tmp = pathlib.Path(__file__).parent / "_pb_syntaxe.js"
    try:
        tmp.write_text(scripts[-1], encoding="utf-8")
        r = subprocess.run([node, "--check", str(tmp)], capture_output=True, text=True)
    finally:
        tmp.unlink(missing_ok=True)
    assert r.returncode == 0, r.stderr


# ---------------------------------------------------------------- comportement

def box(cle="maillage:gk5", nom="gk5", reseau="maillage", client=None, en_ligne=True, mains=False):
    return {"cle": cle, "nom": nom, "reseau": reseau, "client": client, "adresse": "10.10.0.5", "en_ligne": en_ligne, "vu_le": MAINTENANT,
            "agent_version": "0.1.1", "mains_liees": mains, "memoire_dispo_mo": 812, "swap_utilise_pct": 12, "cpu_pct": 3.4,
            "services_en_echec": 0, "boucles_24h": 2, "inventaire_le": MAINTENANT, "inventaire_partiel": False}


def sse(*evts):
    return "".join(f"event: {n}\ndata: {json.dumps(d)}\n\n" for n, d in evts)


class Faux:
    """API simulée : enregistre les appels, rend les corps configurés."""
    def __init__(self, boites, operations=None, supports=None, flux=None, flux_statut=200, reponse_action=None, statut_action=200):
        self.boites, self.operations, self.supports = boites, operations or [], supports or []
        self.flux, self.flux_statut = flux or "", flux_statut
        self.reponse_action, self.statut_action = reponse_action or {"operation": 1, "etat": "accepte", "job": "j1", "raison": "", "operation_etat": "accepte"}, statut_action
        self.posts, self.nb_ops, self.nb_flux, self.deletes = [], 0, 0, []

    def __call__(self, r):
        u, meth = r.request.url, r.request.method
        ok = lambda corps, st=200: r.fulfill(status=st, content_type="application/json", body=json.dumps(corps))   # noqa: E731
        if "/pilotage/operations" in u:
            self.nb_ops += 1
            return ok(self.operations)
        if u.endswith("/flux"):
            self.nb_flux += 1
            if self.flux_statut != 200:
                return ok({"detail": "vue en direct refusée"}, self.flux_statut)
            return r.fulfill(status=200, content_type="text/event-stream", body=self.flux)
        if "/support" in u and meth == "GET":
            return ok(self.supports)
        if "/support" in u and meth == "DELETE":
            self.deletes.append(u)
            return ok({"id": "s1", "etat": "accepte"})
        if "/support" in u and meth == "POST":
            self.posts.append((u, json.loads(r.request.post_data or "{}")))
            return ok({"id": "s9", "etat": "consentement", "job": "", "raison": ""})
        if "/actions/" in u and meth == "POST":
            self.posts.append((u, json.loads(r.request.post_data or "{}")))
            return ok(self.reponse_action, self.statut_action) if self.statut_action == 200 else ok({"detail": "confirmation : retapez exactement le nom de la box"}, self.statut_action)
        if "/releve" in u and meth == "POST":
            self.posts.append((u, {}))
            return ok({"accepte": True}, 202)
        if "/pilotage/boxes" in u:
            return ok(self.boites)
        return ok({"nodes": []})


def ouvrir(faux, extra=None, attente="#pb-actions"):
    def sc(pg):
        pg.wait_for_selector("#pil-body tr")
        pg.click("#pil-body tr:nth-child(1)")
        pg.wait_for_selector("#pb-pan:not([hidden])")
        pg.wait_for_timeout(500)
        return extra(pg) if extra else None
    return _nav(sc, api=faux)


def boutons(pg):
    return pg.evaluate("[...document.querySelectorAll('#pb-actions button.pb-go')].map(b => [b.dataset.action, b.disabled])")


def test_mains_liees_boutons_desactives_releve_reste():
    f = Faux([box(mains=True)])
    (bts, releve, texte), erreurs, natifs = ouvrir(f, lambda pg: (boutons(pg), pg.is_enabled("#pb-releve"), pg.inner_text("#pb-etat")))
    assert erreurs == [] and natifs == []
    assert len(bts) == 7 and all(d for _, d in bts) and releve and "mains liées" in texte.lower()


def test_mains_liees_inconnues_par_prudence_desactive():
    f = Faux([box(mains=None)])
    (bts, texte), erreurs, _ = ouvrir(f, lambda pg: (boutons(pg), pg.inner_text("#pb-etat")))
    assert erreurs == [] and all(d for _, d in bts) and "inconnu" in texte.lower()


def test_box_hors_ligne_actions_desactivees():
    f = Faux([box(en_ligne=False)])
    (bts, releve), erreurs, _ = ouvrir(f, lambda pg: (boutons(pg), pg.is_enabled("#pb-releve")))
    assert erreurs == [] and all(d for _, d in bts) and not releve


def test_actions_libres_sur_box_du_proprietaire_sans_confirmation():
    f = Faux([box()])

    def sc(pg):
        etat = dict(boutons(pg))
        pg.fill("#pb-actions [data-action=service-redemarrer] input.pb-arg", "secubox-hub.service")
        pg.click("#pb-actions button[data-action=service-redemarrer]")
        pg.wait_for_timeout(400)
        return etat
    etat, erreurs, _ = ouvrir(f, sc)
    assert erreurs == [] and etat["maj-paquets"] is False and etat["service-redemarrer"] is True      # service : unité à saisir
    url, corps = f.posts[-1]
    assert url.endswith("/actions/service-redemarrer")
    assert corps["args"] == {"unite": "secubox-hub.service"} and corps.get("confirmation") in (None,) and "support" not in corps


@pytest.mark.parametrize("action,arg", [("reboot", None), ("service-arreter", "secubox-hub.service"), ("renouveler", None), ("renommer", "gk6")])
def test_confirmation_forte_exige_le_nom_exact(action, arg):
    f = Faux([box()])

    def sc(pg):
        sel = f"#pb-actions [data-action={action}]"
        if arg:
            pg.fill(sel + " input.pb-arg", arg)
        bouton = sel + " button.pb-go"
        d0 = pg.is_disabled(bouton)
        pg.fill(sel + " input.pb-conf", "gk")
        d1 = pg.is_disabled(bouton)
        pg.fill(sel + " input.pb-conf", "GK5")
        d2 = pg.is_disabled(bouton)
        pg.fill(sel + " input.pb-conf", "gk5 ")
        d3 = pg.is_disabled(bouton)
        pg.fill(sel + " input.pb-conf", "gk5")
        d4 = pg.is_disabled(bouton)
        pg.click(bouton)
        pg.wait_for_timeout(400)
        return d0, d1, d2, d3, d4
    ds, erreurs, _ = ouvrir(f, sc)
    assert erreurs == [] and ds == (True, True, True, True, False)
    assert f.posts and f.posts[-1][1]["confirmation"] == "gk5"
    if arg:
        assert list(f.posts[-1][1]["args"].values()) == [arg]


def test_confirmation_refusee_400_affichee_sans_planter():
    f = Faux([box()], statut_action=400)

    def sc(pg):
        pg.fill("#pb-actions [data-action=reboot] input.pb-conf", "gk5")
        pg.click("#pb-actions [data-action=reboot] button.pb-go")
        pg.wait_for_timeout(400)
        return pg.inner_text("#pb-msg")
    msg, erreurs, _ = ouvrir(f, sc)
    assert erreurs == [] and "400" in msg and "retapez" in msg


def test_arguments_invalides_gardent_le_bouton_desactive():
    f = Faux([box()])

    def sc(pg):
        pg.fill("#pb-actions [data-action=service-demarrer] input.pb-arg", "ssh.service")
        a = pg.is_disabled("#pb-actions [data-action=service-demarrer] button.pb-go")
        pg.fill("#pb-actions [data-action=service-demarrer] input.pb-arg", "secubox-hub.service")
        b = pg.is_disabled("#pb-actions [data-action=service-demarrer] button.pb-go")
        pg.fill("#pb-actions [data-action=renommer] input.pb-arg", "Mauvais_Nom")
        pg.fill("#pb-actions [data-action=renommer] input.pb-conf", "gk5")
        c = pg.is_disabled("#pb-actions [data-action=renommer] button.pb-go")
        return a, b, c
    r, erreurs, _ = ouvrir(f, sc)
    assert erreurs == [] and r == (True, False, True)


def test_box_cliente_sans_support_aucune_action_seulement_demander_et_releve():
    f = Faux([box("autoload:b1", "b1", "autoload", "lgm")])

    def sc(pg):
        return (pg.locator("#pb-actions button.pb-go").count(), pg.is_visible("#pb-sup-demander"), pg.is_enabled("#pb-sup-demander"),
                pg.is_enabled("#pb-releve"), pg.inner_text("#pb-etat"), pg.is_visible("#pb-live"))
    (n, dem, dem_actif, rel, etat, live), erreurs, _ = ouvrir(f, sc)
    assert erreurs == [] and n == 0 and dem and dem_actif and rel and "support" in etat.lower()
    assert f.nb_flux == 0            # R-L2-31 : pas de vue en direct hors session (le maître répondrait 403)


def test_box_cliente_demande_de_support_envoyee_avec_duree():
    f = Faux([box("autoload:b1", "b1", "autoload", "lgm")])

    def sc(pg):
        pg.fill("#pb-sup-duree", "45")
        pg.click("#pb-sup-demander")
        pg.wait_for_timeout(400)
        return pg.inner_text("#pb-msg")
    msg, erreurs, _ = ouvrir(f, sc)
    assert erreurs == [] and f.posts[-1][0].endswith("/support") and f.posts[-1][1] == {"duree_min": 45}
    assert "accord du détenteur" in msg


def test_box_cliente_support_en_attente_dit_en_attente_de_l_accord():
    f = Faux([box("autoload:b1", "b1", "autoload", "lgm")], supports=[{"id": "s1", "etat": "en_attente", "duree_min": 30, "fin": None}])

    def sc(pg):
        return pg.locator("#pb-actions button.pb-go").count(), pg.inner_text("#pb-etat"), pg.is_visible("#pb-sup-fermer")
    (n, etat, fermer), erreurs, _ = ouvrir(f, sc)
    assert erreurs == [] and n == 0 and "en attente de l’accord du détenteur" in etat and fermer


def test_box_cliente_support_ouvert_catalogue_complet_avec_session_et_flux():
    f = Faux([box("autoload:b1", "b1", "autoload", "lgm")], supports=[{"id": "s1", "etat": "ouvert", "duree_min": 30, "fin": MAINTENANT}],
             flux=sse(("etat", {"box": "b1", "cle": "autoload:b1", "connecte": True, "en_ligne": True, "support": "s1"})),
             reponse_action={"operation": 3, "etat": "consentement", "job": "", "raison": "", "operation_etat": "consentement"})

    def sc(pg):
        bts = boutons(pg)
        pg.click("#pb-actions [data-action=reboot] button.pb-go")      # pas de saisie de nom : l'accord du détenteur en tient lieu
        pg.wait_for_timeout(400)
        return bts, pg.inner_text("#pb-msg"), pg.locator("#pb-actions input.pb-conf").count(), pg.is_visible("#pb-sup-fermer")
    (bts, msg, confs, fermer), erreurs, _ = ouvrir(f, sc)
    assert erreurs == [] and len(bts) == 7 and confs == 0 and fermer
    assert f.nb_flux >= 1
    url, corps = f.posts[-1]
    assert url.endswith("/actions/reboot") and corps["support"] == "s1" and corps.get("confirmation") in (None,)
    assert "en attente de l’accord du détenteur" in msg


def test_box_cliente_support_echu_retire_les_actions():
    f = Faux([box("autoload:b1", "b1", "autoload", "lgm")], supports=[{"id": "s1", "etat": "ouvert", "duree_min": 30, "fin": 1700000000}])
    n, erreurs, _ = ouvrir(f, lambda pg: pg.locator("#pb-actions button.pb-go").count())
    assert erreurs == [] and n == 0


def test_journal_texte_brut_resultat_inconnu_orpheline_sans_reponse():
    ops = [
        {"id": 5, "cle": "maillage:gk5", "nom": "gk5", "job": "j5", "action": "reboot", "args": {"unite": HTML_MALVEILLANT}, "acteur": HTML_MALVEILLANT,
         "etat": "termine", "raison": HTML_MALVEILLANT, "etape": "terminee", "pct": 100, "rc": -1, "resume": HTML_MALVEILLANT, "demande_le": MAINTENANT,
         "maj_le": MAINTENANT, "fin_le": MAINTENANT, "resultat": "inconnu"},
        {"id": 4, "cle": "maillage:gk5", "job": "orph", "action": None, "args": {}, "acteur": None, "etat": "termine", "raison": None, "etape": None,
         "pct": 100, "rc": 0, "resume": "ok", "demande_le": MAINTENANT, "maj_le": MAINTENANT, "fin_le": MAINTENANT, "resultat": "succes"},
        {"id": 3, "cle": "maillage:gk5", "job": None, "action": "maj-paquets", "args": {}, "acteur": "admin", "etat": "sans_reponse", "raison": None,
         "etape": None, "pct": None, "rc": None, "resume": None, "demande_le": MAINTENANT, "maj_le": MAINTENANT, "fin_le": None, "resultat": None},
        {"id": 2, "cle": "maillage:gk5", "job": "jp", "action": "renommer", "args": {"nom": "gk6"}, "acteur": "admin", "etat": "refuse", "raison": "plafond",
         "etape": None, "pct": None, "rc": None, "resume": None, "demande_le": MAINTENANT, "maj_le": MAINTENANT, "fin_le": None, "resultat": None},
    ]
    f = Faux([box()], operations=ops)

    def sc(pg):
        return (pg.locator("#pb-ops tr").count(), pg.inner_text("#pb-ops"), pg.locator("#pb-ops img, #pb-pan img").count(),
                pg.evaluate("document.getElementById('pb-ops').textContent.includes('<img src=x onerror=alert(1)>')"))
    (n, texte, imgs, brut), erreurs, natifs = ouvrir(f, sc)
    assert erreurs == [] and natifs == [] and n == 4 and imgs == 0 and brut
    assert "résultat inconnu" in texte and "sans réponse" in texte.lower() and "plafond" in texte.lower()
    assert "non rattachée" in texte or "sans demande" in texte


def test_flux_dedoublonne_par_job_et_par_id():
    evt = {"type": "X_SECUBOX_OperationProgress", "job": "j1", "etape": "installation", "pct": 50, "box": "gk5", "cle": "maillage:gk5"}
    done = {"type": "X_SECUBOX_OperationDone", "job": "j1", "rc": 0, "resume": HTML_MALVEILLANT, "box": "gk5", "cle": "maillage:gk5"}
    cons = {"type": "X_SECUBOX_Consent", "id": "c1", "etat": "en_attente", "box": "gk5", "cle": "maillage:gk5"}
    f = Faux([box()], flux=sse(("operation", evt), ("operation", evt), ("operation", done), ("operation", done), ("etat", cons), ("etat", cons),
                               ("etat", {"box": "gk5", "cle": "maillage:gk5", "connecte": True, "en_ligne": True, "support": None})))

    def sc(pg):
        return pg.locator("#pb-live li").count(), pg.inner_text("#pb-live"), pg.locator("#pb-live img").count()
    (n, texte, imgs), erreurs, natifs = ouvrir(f, sc)
    assert erreurs == [] and natifs == [] and imgs == 0
    assert texte.count("j1") == 1 and texte.count("c1") <= 1 and "100" in texte
    assert HTML_MALVEILLANT in texte


def test_flux_perte_et_reconnexion_relisent_les_operations():
    f = Faux([box()], flux=sse(("etat", {"perte": 3})))

    def sc(pg):
        avant = f.nb_ops
        pg.wait_for_timeout(4500)       # fin du flux simulé : reconnexion après 3 s, relecture
        return avant, f.nb_ops, f.nb_flux
    (avant, apres, nflux), erreurs, _ = ouvrir(f, sc)
    assert erreurs == []
    assert apres > avant and nflux >= 2


def test_flux_session_expiree_retour_a_la_connexion():
    f = Faux([box()], flux=sse(("etat", {"box": "gk5", "cle": "maillage:gk5", "session": "expiree"})))
    def sc(pg):
        pg.wait_for_selector("#pil-body tr")
        pg.click("#pil-body tr:nth-child(1)")
        pg.wait_for_timeout(1200)
        return pg.url
    url, erreurs, _ = _nav(sc, api=f)
    assert "/login.html" in url


def test_flux_support_termine_retire_les_actions_et_ferme():
    f = Faux([box("autoload:b1", "b1", "autoload", "lgm")], supports=[{"id": "s1", "etat": "ouvert", "duree_min": 30, "fin": MAINTENANT}],
             flux=sse(("etat", {"box": "b1", "cle": "autoload:b1", "support": "termine"})))

    def sc(pg):
        pg.wait_for_timeout(500)
        f.supports = [{"id": "s1", "etat": "ferme", "duree_min": 30, "fin": MAINTENANT}]
        pg.wait_for_timeout(500)
        return pg.inner_text("#pb-etat"), pg.locator("#pb-actions button.pb-go").count(), f.nb_flux
    (etat, n, nflux), erreurs, _ = ouvrir(f, sc)
    assert erreurs == []
    assert n == 0 and "terminé" in etat.lower()
    assert nflux == 1                # pas de reconnexion à un flux fermé


def test_flux_403_pas_de_reconnexion():
    f = Faux([box()], flux_statut=403)
    (nflux, msg), erreurs, _ = ouvrir(f, lambda pg: (pg.wait_for_timeout(3600), f.nb_flux, pg.inner_text("#pb-live-etat"))[1:])
    assert erreurs == [] and nflux == 1 and msg


def test_mains_liees_bascule_en_direct():
    f = Faux([box(mains=False)], flux=sse(("etat", {"type": "X_SECUBOX_HandsTied", "etat": "on", "box": "gk5", "cle": "maillage:gk5"})))
    bts, erreurs, _ = ouvrir(f, lambda pg: boutons(pg))
    assert erreurs == [] and all(d for _, d in bts)


def test_box_tiree_pas_de_nom_en_html_dans_le_titre():
    f = Faux([box(nom=HTML_MALVEILLANT)])
    (titre, imgs), erreurs, natifs = ouvrir(f, lambda pg: (pg.inner_text("#pb-titre"), pg.locator("#pb-pan img").count()))
    assert erreurs == [] and natifs == [] and imgs == 0 and HTML_MALVEILLANT in titre
