# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3189 — Unbound lent de gk2 (2026-10-26) : arrêt 115 s, démarrage 38 à 112 s. Le client `systemctl restart`, tué à
120 s par le contrôleur, déclarait en échec un redémarrage qui aboutissait, et le retour automatique aussi (« retour
INCOMPLET ») : une première application coupait le LAN pour rien. Le redémarrage part désormais sans bloquer et son
issue réelle est attendue : nouveau démarrage, échec, ou délai déduit de l'unité (arrêt + démarrage + 30 s, borné à
[180 s, 900 s]). Horloge et pauses simulées : aucun test n'attend vraiment."""
import fcntl
import math
import os

import pytest

from api import routeur_ctl as rc
from api.routeur_rendu import CHEMINS
from test_routeur_ctl_3189 import (
    ANCIEN_PONT, CFG42, CFG50, NGINX_T, Faux, Horloge, audits, etat_fichier, preparer_racine,
)


@pytest.fixture(autouse=True)
def umask_022():
    ancien = os.umask(0o022)                        # contrôles de droits de l'arbre root seul (voir test_routeur_ctl)
    yield
    os.umask(ancien)


@pytest.fixture
def racine(tmp_path):
    return preparer_racine(tmp_path / "racine")


@pytest.fixture
def faux(racine):
    return Faux(racine)


@pytest.fixture
def ctx(racine, faux):
    return rc.Contexte(racine=racine, executer=faux, maintenant=Horloge(), attendre=faux.attendre,
                       monotone=faux.monotone)


UNBOUND = "unbound.service"
REDEMARRER = ["systemctl", "restart", "--no-block", UNBOUND]
EST_ACTIF = ["systemctl", "is-active", UNBOUND]
P = 5.0                                             # relevé toutes les 5 s


def _relances(faux) -> int:
    return faux.journal.count(REDEMARRER)


def _seconde_relance_rapide(faux):
    """Le retour qui suit l'échec relance Unbound à son tour : celle-là aboutit tout de suite."""
    def regler(argv):
        if _relances(faux) == 2:                       # journalisée avant l'appel du crochet
            faux.unbound_file = faux.unbound_arret = faux.unbound_demarrage = 0.0
            faux.unbound_issue = "active"
    faux.sur(*REDEMARRER, fonction=regler)


# --- durées systemd, délai déduit de l'unité --------------------------------------------------------------------------

@pytest.mark.parametrize("texte, secondes", [
    ("1min 30s", 90), ("10min", 600), ("600ms", 0.6), ("1h", 3600), ("1.5s", 1.5), ("0", 0), ("45", 45),
    ("2min 500ms", 120.5), ("100us", 0.0001), ("1d 2h", 93600), ("1w", 604800), (" 1min 30s\n", 90),
    ("1min30s", 90), ("5sec", 5), ("2minutes", 120), ("3hours", 10800), ("250msec", 0.25), ("7µs", 7e-6),
])
def test_duree_systemd(texte, secondes):
    assert rc._duree_systemd(texte) == pytest.approx(secondes)


def test_duree_systemd_infinie():
    assert rc._duree_systemd("infinity") == math.inf


@pytest.mark.parametrize("texte", ["", "   ", "abc", "-5s", "5 parsecs", "1min, 30s", "nan", "inf", "1e3s", "s",
                                   "1min 30x", "١٢s"])
def test_duree_systemd_illisible(texte):
    assert rc._duree_systemd(texte) is None


@pytest.mark.parametrize("sortie, delai", [
    ("10min\n1min 30s\n", 720),                      # gk2 : drop-in TimeoutStartSec=600, arrêt par défaut 90 s
    ("1min 30s\n1min 30s\n", 210),                   # défauts de systemd
    ("5s\n5s\n", 180),                               # plancher
    ("20min\n10min\n", 900),                         # plafond
    ("infinity\n1min 30s\n", 900),                   # TimeoutStartSec=infinity : plafond
    ("", 900), ("10min\n", 900), ("n'importe\n1min\n", 900), ("1min\n2min\n3min\n", 900),   # illisible : plafond
])
def test_delai_unbound(ctx, faux, sortie, delai):
    faux.unbound_delais = sortie
    assert rc._delai_unbound(ctx) == delai
    assert faux.journal == [["systemctl", "show", "-p", "TimeoutStopUSec", "-p", "TimeoutStartUSec", "--value", UNBOUND]]


def test_constantes():
    assert (rc.PAUSE_UNBOUND, rc.MARGE_UNBOUND, rc.DELAI_UNBOUND_MIN, rc.DELAI_UNBOUND_MAX) == (P, 30, 180, 900)


def test_delai_unbound_systemctl_en_echec(ctx, faux):
    faux.echouer("systemctl", "show", "-p", "TimeoutStopUSec")
    assert rc._delai_unbound(ctx) == rc.DELAI_UNBOUND_MAX == 900


# --- appliquer : redémarrage lent, échec, délai ------------------------------------------------------------------------

def test_redemarrage_lent_reussi(ctx, racine, faux):
    """Rejeu de gk2 : arrêt 115 s, démarrage 85 s. Plus de 120 s : succès, ni échec ni retour, minuteur armé."""
    faux.unbound_arret, faux.unbound_demarrage = 115.0, 85.0
    sortie = rc.appliquer(ctx, CFG42, "admin")
    assert sortie["etat"] == "en_attente"
    assert _relances(faux) == 1
    assert faux.pauses == [P] * 40 + [rc.PAUSE_DHCP]                           # 200 s attendues, puis le DHCP
    assert [a["action"] for a in audits(racine)] == ["appliquer"]
    assert "Unbound redémarré" in audits(racine)[-1]["detail"]
    assert any("--unit=secubox-netmodes-retour" in a for a in faux.journal)
    i = faux.journal.index(REDEMARRER)
    assert faux.journal[i + 1:].count(EST_ACTIF) == 41                          # relevé toutes les PAUSE_UNBOUND s
    assert faux.journal.index(["systemctl", "enable", "secubox-lan-dhcp.service"]) > i + 41


def test_unbound_en_echec_echec_d_etape_et_retour(ctx, racine, faux):
    faux.unbound_arret, faux.unbound_demarrage, faux.unbound_issue = 10.0, 5.0, "failed"
    _seconde_relance_rapide(faux)
    with pytest.raises(rc.Echec, match="unbound.service a échoué.*configuration précédente restaurée"):
        rc.appliquer(ctx, CFG42, "admin")
    assert _relances(faux) == 2                                                 # bascule, puis retour
    assert faux.pauses == [P] * 3                                               # vu « failed » à 15 s, pas avant
    actions = [(a["action"], a["acteur"]) for a in audits(racine)]
    assert ("appliquer-echec", "admin") in actions and ("retour", "echec") in actions
    assert "INCOMPLET" not in audits(racine)[-1]["detail"]
    assert etat_fichier(racine)["etat"] == "inactif"
    assert (racine / "etc/systemd/network/10-br-lan.network").read_text() == ANCIEN_PONT
    assert not any("--unit=secubox-netmodes-retour" in a for a in faux.journal)


def test_delai_depasse_echec_d_etape(ctx, racine, faux):
    faux.unbound_issue = "activating"                                          # ne finit jamais
    _seconde_relance_rapide(faux)
    with pytest.raises(rc.Echec, match="unbound.service n'est pas redevenu actif en 720 s"):
        rc.appliquer(ctx, CFG42, "admin")
    assert faux.pauses == [P] * 144                                             # 720 s = 10 min + 1 min 30 s + 30 s
    assert ("retour", "echec") in [(a["action"], a["acteur"]) for a in audits(racine)]
    assert etat_fichier(racine)["etat"] == "inactif"
    assert not any("--unit=secubox-netmodes-retour" in a for a in faux.journal)


def test_delai_plafonne_a_900_s(ctx, racine, faux):
    faux.unbound_delais = "infinity\ninfinity\n"
    faux.unbound_issue = "activating"
    _seconde_relance_rapide(faux)
    with pytest.raises(rc.Echec, match="n'est pas redevenu actif en 900 s"):
        rc.appliquer(ctx, CFG42, "admin")
    assert sum(faux.pauses) == 900


def test_delai_plancher_180_s(ctx, racine, faux):
    faux.unbound_delais = "5s\n5s\n"
    faux.unbound_issue = "activating"
    _seconde_relance_rapide(faux)
    with pytest.raises(rc.Echec, match="n'est pas redevenu actif en 180 s"):
        rc.appliquer(ctx, CFG42, "admin")
    assert sum(faux.pauses) == 180


def test_ancien_demarrage_jamais_pris_pour_un_succes(ctx, racine, faux):
    """Travail resté dans la file de PID 1 : Unbound « active », mais depuis AVANT la relance. Pas un succès."""
    faux.unbound_file = math.inf
    _seconde_relance_rapide(faux)
    with pytest.raises(rc.Echec, match="n'est pas redevenu actif en 720 s"):
        rc.appliquer(ctx, CFG42, "admin")
    assert faux.pauses == [P] * 144
    i = faux.journal.index(REDEMARRER)
    assert faux.journal[i + 1] == EST_ACTIF                                     # vu actif dès le premier relevé…
    assert faux.journal[i + 2] == ["systemctl", "show", "-p", "ActiveEnterTimestampMonotonic", "--value", UNBOUND]
    assert ("retour", "echec") in [(a["action"], a["acteur"]) for a in audits(racine)]   # … mais pas redémarré


def test_ancien_demarrage_puis_nouveau(ctx, racine, faux):
    faux.unbound_file = 20.0                                                   # 20 s en file, « active » périmé
    rc.appliquer(ctx, CFG42, "admin")
    assert faux.pauses == [P] * 4 + [rc.PAUSE_DHCP]
    assert "retour" not in [a["action"] for a in audits(racine)]


def test_echec_d_avant_la_relance_ignore(ctx, racine, faux):
    """Unbound déjà « failed » (ex. le retour qui suit son échec) : tant que la relance n'a pas commencé, `is-active`
    rend encore l'ancien « failed ». Seul un échec postérieur au début du nouveau démarrage compte."""
    faux.unbound["etat"] = "failed"
    faux.unbound_file = 10.0
    sortie = rc.appliquer(ctx, CFG42, "admin")
    assert sortie["etat"] == "en_attente"
    assert faux.pauses == [P] * 2 + [rc.PAUSE_DHCP]
    assert "retour" not in [a["action"] for a in audits(racine)]


def test_horodatages_illisibles_echec_sans_relance(ctx, racine, faux):
    faux.echouer("systemctl", "show", "-p", "ActiveEnterTimestampMonotonic")
    with pytest.raises(rc.Echec, match="horodatages de unbound.service illisibles"):
        rc.appliquer(ctx, CFG42, "admin")
    assert REDEMARRER not in faux.journal
    assert ("retour", "echec") in [(a["action"], a["acteur"]) for a in audits(racine)]


def test_verrou_unbound_tenu_pendant_toute_l_attente(ctx, racine, faux):
    """secubox-dns-lan ne touche pas Unbound pendant qu'on attend son redémarrage."""
    faux.unbound_arret, faux.unbound_demarrage = 115.0, 85.0
    tenus = []

    def essayer(argv):
        fd = os.open(racine / "run/lock/secubox-dns-lan.lock", os.O_RDWR)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            tenus.append(False)
        except BlockingIOError:
            tenus.append(True)
        finally:
            os.close(fd)

    faux.sur(*EST_ACTIF, fonction=essayer)
    rc.appliquer(ctx, CFG42, "admin")
    assert len(tenus) == 41 and all(tenus)


# --- retour : même attente, au démarrage aussi -------------------------------------------------------------------------

def _seconde_en_attente(ctx, faux):
    rc.appliquer(ctx, CFG42, "admin")
    rc.confirmer(ctx, "admin")
    rc.appliquer(ctx, CFG50, "admin")                       # en attente : le retour change le drop-in Unbound
    faux.journal.clear()
    faux.pauses.clear()


@pytest.mark.parametrize("acteur", ["admin", "minuteur"])
def test_retour_unbound_lent_complet(ctx, racine, faux, acteur):
    _seconde_en_attente(ctx, faux)
    faux.unbound_arret, faux.unbound_demarrage = 115.0, 85.0
    sortie = rc.retour(ctx, acteur)
    assert sortie["etat"] == "actif"
    assert "INCOMPLET" not in audits(racine)[-1]["detail"]
    assert "interface: 192.168.42.1" in (racine / CHEMINS["unbound"].lstrip("/")).read_text()
    assert faux.pauses == [P] * 40 + [rc.PAUSE_DHCP]


def test_retour_unbound_en_echec_incomplet(ctx, racine, faux):
    _seconde_en_attente(ctx, faux)
    faux.unbound_issue = "failed"
    with pytest.raises(rc.Echec, match="retour incomplet : Unbound : unbound.service a échoué"):
        rc.retour(ctx, "admin")
    assert ["systemctl", "restart", "secubox-lan-dhcp.service"] in faux.journal   # les étapes suivantes ont lieu


def test_retour_demarrage_attend_unbound_sans_bloquer_dhcp_ni_nginx(ctx, racine, faux):
    """retour-boot est After=unbound : attendre Unbound ne s'interbloque pas ; DHCP et nginx restent --no-block."""
    _seconde_en_attente(ctx, faux)
    faux.unbound_arret, faux.unbound_demarrage = 115.0, 85.0
    sortie = rc.retour_si_en_attente(ctx)
    assert sortie["etat"] == "actif"
    assert faux.pauses == [P] * 40                                              # Unbound seul : rien pour DHCP, nginx
    assert REDEMARRER in faux.journal
    assert ["systemctl", "restart", "--no-block", "secubox-lan-dhcp.service"] in faux.journal
    assert ["systemctl", "reload", "--no-block", "nginx.service"] in faux.journal
    assert faux.journal.index(REDEMARRER) < faux.journal.index(
        ["systemctl", "restart", "--no-block", "secubox-lan-dhcp.service"])


def test_retour_demarrage_delai_depasse_poursuit(ctx, racine, faux):
    _seconde_en_attente(ctx, faux)
    faux.unbound_issue = "activating"
    with pytest.raises(rc.Echec, match="retour incomplet : Unbound : unbound.service n'est pas redevenu actif en 720 s"):
        rc.retour_si_en_attente(ctx)
    assert faux.pauses == [P] * 144
    assert ["systemctl", "restart", "--no-block", "secubox-lan-dhcp.service"] in faux.journal
    assert ["systemctl", "reload", "--no-block", "nginx.service"] in faux.journal
    assert etat_fichier(racine)["etat"] == "actif"
    assert NGINX_T not in faux.journal                                          # aucun nginx -t au retour
