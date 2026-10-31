# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3338 — Boutique pour l'Alpha 20 : installation de bout en bout (Ouvrir mène à l'app réelle, suivi qui ne reste
jamais bloqué, erreurs en français)."""
import pytest

from test_boutique_3148 import FICHES, mod, ouvre, playwright  # noqa: F401 — simulateur partagé
from test_boutique_3148 import navigateur  # noqa: F401,F811 — fixture partagée


def test_url_de_l_app_vhost_ou_administration(navigateur):
    """Ouvrir mène à l'app réelle : son vhost (`ouvrir: "vhost"` dans la fiche) sinon l'administration de la box,
    sur le domaine de la boutique (boutique.<domaine> → <app>.<domaine>, admin.<domaine>)."""
    ctx, p, erreurs, _ = ouvre(navigateur)
    assert FICHES["secubox-jellyfin"].get("ouvrir") == "vhost"
    u = p.evaluate("urlApp({id:'secubox-jellyfin'},'boutique.gk2.secubox.in','https:')")
    assert u == "https://jellyfin.gk2.secubox.in/"
    u = p.evaluate("urlApp({id:'secubox-wireguard'},'boutique.gk2.secubox.in','https:')")
    assert u == "https://admin.gk2.secubox.in/wireguard/"
    u = p.evaluate("urlApp({id:'secubox-wireguard'},'admin.gk2.secubox.in','https:')")   # page servie sous admin.<domaine>/appstore/
    assert u == "https://admin.gk2.secubox.in/wireguard/"
    assert not erreurs
    ctx.close()


def test_suivi_tolere_un_job_pas_encore_visible(navigateur):
    """Juste après le 202, /jobs peut ne pas encore lister l'installation : pas de « suivi perdu » au premier tour."""
    etat = {"n": 0}

    def donnees(u):
        if u.endswith("/jobs"):
            etat["n"] += 1
            if etat["n"] <= 2:
                return {"jobs": {}}
            if etat["n"] <= 3:
                return {"jobs": {"secubox-peertube": {"etat": "en-cours", "verbe": "install"}}}
            return {"jobs": {"secubox-peertube": {"etat": "ok"}}}
        if u.endswith("/catalog"):
            return {"modules": [mod("secubox-peertube", "misc", etat["n"] > 3)]}
        return None
    ctx, p, erreurs, _ = ouvre(navigateur, donnees=donnees, requete="?sonde=80")
    p.click("[role=tab]:text-is(\"Apps\")")
    p.locator(".app", has_text="PeerTube").locator("button.get").click()
    p.wait_for_selector(".toast.on:has-text('est installée')", timeout=5000)
    assert p.locator(".app", has_text="PeerTube").locator("button.get").inner_text() == "Ouvrir"
    assert not erreurs
    ctx.close()


@pytest.mark.parametrize("statut,attendu", [(409, "Une autre installation est en cours"),
                                            (404, "n’est plus proposée"),
                                            (500, "Installation impossible")])
def test_erreurs_lisibles_en_francais(navigateur, statut, attendu):
    ctx, p, _, _ = ouvre(navigateur, install=(statut, {"detail": "une autre opération est en cours : secubox-x"}))
    p.click("[role=tab]:text-is(\"Apps\")")
    p.locator(".app", has_text="PeerTube").locator("button.get").click()
    p.wait_for_selector(".toast.on:has-text('" + attendu + "')")
    assert p.locator(".app", has_text="PeerTube").locator("button.get").inner_text() == "Obtenir"   # jamais bloqué
    ctx.close()


def test_echec_du_job_rend_le_bouton_et_dit_pourquoi(navigateur):
    def donnees(u):
        if u.endswith("/jobs"):
            return {"jobs": {"secubox-peertube": {"etat": "echec", "message": "apt : paquet introuvable"}}}
        return None
    ctx, p, _, _ = ouvre(navigateur, donnees=donnees, requete="?sonde=80")
    p.click("[role=tab]:text-is(\"Apps\")")
    p.locator(".app", has_text="PeerTube").locator("button.get").click()
    p.wait_for_selector(".toast.on:has-text('apt : paquet introuvable')", timeout=5000)
    assert p.locator(".app", has_text="PeerTube").locator("button.get").inner_text() == "Obtenir"
    ctx.close()


# ── Volet 2 : fiches réelles, tirées des paquets ─────────────────────────────────────────────────────────────────

def test_catalogue_porte_le_texte_du_paquet(tmp_path):
    """Le catalogue reprend la description de debian/control (résumé = première ligne sans « SecuBox — », détail =
    paragraphe long) : la boutique n'invente rien."""
    import importlib.util
    import pathlib
    spec = importlib.util.spec_from_file_location(
        "gen", pathlib.Path(__file__).resolve().parents[1] / "scripts" / "gen-appstore-catalog.py")
    gen = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gen)
    r, d = gen.description_paquet(pathlib.Path(__file__).resolve().parents[2] / "secubox-radio" / "debian" / "control")
    assert r and not r.startswith("SecuBox") and "radio" in r.lower()
    assert d and "playlist" in d.lower() and "\n" not in d.split(". ")[0]
    assert gen.description_paquet(tmp_path / "absent") == ("", "")


def test_sans_fiche_la_boutique_prend_le_texte_du_paquet(navigateur):
    cat = {"modules": [dict(mod("secubox-radioz", "media"), resume="Radio partagée", detail="Une playlist commune.")]}

    def donnees(u):
        return cat if u.endswith("/catalog") else None
    ctx, p, erreurs, _ = ouvre(navigateur, donnees=donnees)
    p.click("[role=tab]:text-is(\"Apps\")")
    ligne = p.locator(".app", has_text="Radioz")
    assert "Radio partagée" in ligne.inner_text()
    assert "[À COMPLÉTER]" not in p.content()
    assert not erreurs
    ctx.close()


def test_a_completer_seulement_en_administration():
    import pathlib
    www = pathlib.Path(__file__).resolve().parents[1] / "www" / "appstore"
    assert "[À COMPLÉTER]" in (www / "index.html").read_text(encoding="utf-8")
    assert "[À COMPLÉTER]" not in (www / "boutique.html").read_text(encoding="utf-8")


# ── Volet 3 : formule de la box ──────────────────────────────────────────────────────────────────────────────────

def test_app_hors_formule_sans_obtenir(navigateur):
    cat = {"modules": [dict(mod("secubox-peertube", "misc"), hors_formule=True, formule_requise="Médias"),
                       mod("secubox-radio", "media")]}

    def donnees(u):
        return cat if u.endswith("/catalog") else None
    ctx, p, erreurs, appels = ouvre(navigateur, donnees=donnees)
    p.click("[role=tab]:text-is(\"Apps\")")
    b = p.locator(".app", has_text="PeerTube").locator("button.get")
    assert b.inner_text() == "Formule Médias" and b.is_disabled()
    p.locator(".app", has_text="PeerTube").click()
    p.wait_for_selector("dialog[open]:has-text('Disponible avec la formule Médias')")
    assert not [a for a in appels if a[0] == "POST"]
    assert p.locator(".app", has_text="Radio").locator("button.get").inner_text() == "Obtenir"
    assert not erreurs
    ctx.close()
