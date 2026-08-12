# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: profiles — réveil des applications Streamlit (#1018).

28 vhosts routés vers le conteneur Streamlit rendaient 502 en 0,1 seconde :
aucun réveil n'était tenté, alors que l'unité de chaque application existait,
simplement arrêtée.

Deux exigences se croisent ici, et le second groupe de tests protège la
seconde :

  - une application routée doit être réveillée ;
  - un vhost inconnu ne doit RIEN réveiller. Le code portait déjà cette garde,
    explicitement : « un 5xx ne doit pas devenir un droit de démarrer un
    service arbitraire ». L'ouvrir aurait été le vrai défaut.
"""

import pytest

from api import streamlit_apps as sa


# ── Le nom d'application entre dans une unité systemd lancée en root ──────

@pytest.mark.parametrize("nom", ["cpf", "hermes", "files_40", "secubox_control",
                                 "yijing360", "test2new", "a", "A-b_9"])
def test_les_noms_produits_par_la_forge_sont_acceptes(nom):
    assert sa.nom_valide(nom)


@pytest.mark.parametrize("nom", [
    "", "  ", "../evil", "a/b", "a b", "a;rm -rf /", "a@b", "a\nb",
    "a$(id)", "a`id`", "x" * 65, "app.service", "-", "a|b",
])
def test_tout_le_reste_est_refuse(nom):
    """LA GARDE QUI COMPTE. Ce nom devient `streamlit-app@<nom>.service`,
    démarré en root. Un `..`, un `/`, un `@` ou un espace y désignerait une
    autre unité que celle voulue."""
    assert not sa.nom_valide(nom), f"accepté à tort : {nom!r}"


def test_un_nom_refuse_n_est_jamais_execute():
    appels = []

    def run(argv):
        appels.append(argv)
        return 0, ""

    r = sa.reveille("../evil", run=run)
    assert r["status"] == "refused"
    assert appels == [], "une commande a ete lancee malgre le refus"


# ── Du vhost à l'application ──────────────────────────────────────────────

def test_l_application_est_la_premiere_etiquette():
    assert sa.app_depuis_vhost("cpf.gk2.secubox.in") == "cpf"
    assert sa.app_depuis_vhost("files_40.gk2.secubox.in") == "files_40"


def test_un_vhost_sans_point_ou_douteux_ne_donne_rien():
    for v in ("", "localhost", "..gk2.secubox.in", "a b.gk2.secubox.in"):
        assert sa.app_depuis_vhost(v) is None, v


# ── La liste se déduit des routes, jamais d'une liste tenue à la main ─────

def test_seuls_les_vhosts_routes_vers_le_conteneur_sont_retenus():
    routes = {
        "cpf.gk2.secubox.in": ["10.100.0.50", 8501],
        "hermes.gk2.secubox.in": ["10.100.0.50", 8502],
        "nextcloud.gk2.secubox.in": ["10.100.0.40", 80],   # autre conteneur
        "admin.gk2.secubox.in": ["192.168.1.200", 9080],   # l'hote
    }
    assert sa.vhosts_streamlit(routes, "10.100.0.50") == [
        "cpf.gk2.secubox.in", "hermes.gk2.secubox.in"]


def test_une_route_malformee_ne_fait_pas_tout_echouer():
    # Le fichier de routes est ecrit par plusieurs outils : une entree abimee
    # ne doit pas priver de reveil les 27 autres applications.
    routes = {
        "cpf.gk2.secubox.in": ["10.100.0.50", 8501],
        "casse.gk2.secubox.in": None,
        "vide.gk2.secubox.in": [],
    }
    assert sa.vhosts_streamlit(routes, "10.100.0.50") == ["cpf.gk2.secubox.in"]


def test_des_routes_absentes_ne_reveillent_rien():
    # C'EST LA GARDE, pas une commodite : sans routes lisibles, aucun vhost
    # n'est reconnu comme Streamlit et le repli reste ferme.
    assert sa.vhosts_streamlit({}, "10.100.0.50") == []
    assert sa.vhosts_streamlit(None, "10.100.0.50") == []


# ── Le réveil lui-même ────────────────────────────────────────────────────

def test_le_reveil_demarre_la_bonne_unite_dans_le_conteneur():
    vu = {}

    def run(argv):
        vu["argv"] = argv
        return 0, ""

    r = sa.reveille("cpf", run=run)
    assert r["status"] == "woken"
    assert "streamlit-app@cpf.service" in vu["argv"]
    assert "start" in vu["argv"]
    # Le conteneur est vise explicitement : sans -P, lxc-attach chercherait
    # dans /var/lib/lxc et ne trouverait rien sur cette board.
    assert "-P" in vu["argv"] and "/data/lxc" in vu["argv"]


def test_un_echec_est_rapporte_pas_avale():
    def run(argv):
        return 1, "Failed to start streamlit-app@absent.service: Unit not found."

    r = sa.reveille("absent", run=run)
    assert r["status"] == "failed"
    assert "Unit not found" in r["detail"]
