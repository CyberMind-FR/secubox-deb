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
