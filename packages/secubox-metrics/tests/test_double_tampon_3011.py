# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3011 — double tampon réel des vues par vhost.

Avant : chaque vue était recalculée SUR LE CHEMIN DE LA REQUÊTE (7-8 s, 100 000 entrées sur gk2) et la
collecte modifiait les compteurs EN PLACE pendant qu'une requête les lisait (« dictionary changed size
during iteration » → 500 → page vide, puis la passe suivante recalculait tout). Désormais : la vue servie
est un instantané complet ; la collecte rebâtit les vues demandées dans un tampon puis bascule d'un coup ;
lectures et collecte s'excluent par un verrou.
"""
import datetime
import threading

import pytest


def _ligne(hote, ip, quand):
    return f'{hote} {ip} - - [{quand}] "GET / HTTP/1.1" 200 100 "-" "Mozilla/5.0"\n'


@pytest.fixture
def agregateur(tmp_path, monkeypatch):
    from api import vhost_stats as V
    quand = datetime.datetime.now().strftime("%d/%b/%Y:10:00:00 +0100")
    log = tmp_path / "secubox-hosts.log"
    log.write_text(_ligne("ganimed.fr", "93.184.216.34", quand))
    monkeypatch.setattr(V, "JOURNAL_HOTES", log)
    monkeypatch.setattr(V, "REP_LOGS", tmp_path)
    monkeypatch.setattr(V, "CACHE", tmp_path / "vhost_stats.json")
    ag = V.VhostStatsAggregator()

    def ajoute(n):
        with log.open("a") as fh:
            for i in range(n):
                fh.write(_ligne("ganimed.fr", f"93.184.216.{40 + i}", quand))
    return ag, ajoute


def _espion(monkeypatch):
    from api import vhost_stats as V
    appels = []
    original = V.VhostStatsAggregator.current

    def espion(self, periode="jour", grouper=False):
        appels.append((periode, grouper))
        return original(self, periode, grouper)
    monkeypatch.setattr(V.VhostStatsAggregator, "current", espion)
    return appels


def test_les_vues_de_base_sont_pretes_apres_la_collecte_sans_calcul_sur_la_requete(agregateur, monkeypatch):
    ag, _ = agregateur
    ag.collecter()
    appels = _espion(monkeypatch)
    v = ag.vue("jour", False)
    assert v["total"]["requetes"] == 1
    assert appels == [], "la vue de base a été recalculée sur le chemin de la requête"


def test_une_vue_jamais_demandee_se_fabrique_une_fois_puis_vit_dans_le_tampon(agregateur, monkeypatch):
    ag, _ = agregateur
    ag.collecter()
    appels = _espion(monkeypatch)
    a = ag.vue("mois", True)
    b = ag.vue("mois", True)
    assert appels == [("mois", True)] and a is b


def test_la_collecte_rebatit_les_vues_demandees_puis_bascule_d_un_coup(agregateur, monkeypatch):
    from api import vhost_stats as V
    ag, ajoute = agregateur
    ag.collecter()
    v1 = ag.vue("semaine", True)
    assert v1["total"]["requetes"] == 1
    ajoute(2)
    original = V.VhostStatsAggregator.current
    servies = []

    def pendant(self, periode="jour", grouper=False):
        servies.append(self._vues.get(("semaine", True)))    # ce que la requête recevrait PENDANT la fabrication
        return original(self, periode, grouper)
    monkeypatch.setattr(V.VhostStatsAggregator, "current", pendant)
    ag.collecter()
    assert servies and all(s is v1 for s in servies), "le tampon actif a changé avant la fin de la fabrication"
    monkeypatch.setattr(V.VhostStatsAggregator, "current", original)
    v2 = ag.vue("semaine", True)
    assert v2["total"]["requetes"] == 3 and v2 is not v1


def test_la_relecture_d_un_vhost_rebatit_aussi_les_vues(agregateur, monkeypatch):
    ag, ajoute = agregateur
    ag.collecter()
    assert ag.vue("jour", False)["total"]["requetes"] == 1
    ajoute(2)
    ag.rafraichir("ganimed.fr")
    appels = _espion(monkeypatch)
    assert ag.vue("jour", False)["total"]["requetes"] == 3
    assert appels == []


def test_lectures_et_collecte_s_excluent_par_un_verrou(agregateur, monkeypatch):
    ag, _ = agregateur
    assert isinstance(ag._verrou, type(threading.RLock()))
    tenu = []
    fusion = ag._fusion
    monkeypatch.setattr(ag, "_fusion", lambda jours: tenu.append(ag._verrou._is_owned()) or fusion(jours))
    ag.current("jour", False)
    ag.detail("ganimed.fr", "jour") if ag._jours else None
    tailler = ag._tailler
    monkeypatch.setattr(ag, "_tailler", lambda: tenu.append(ag._verrou._is_owned()) or tailler())
    ag.collecter()
    assert tenu and all(tenu), f"une lecture ou une collecte s'est faite sans le verrou : {tenu}"


def test_une_vue_oubliee_depuis_une_heure_n_est_plus_rebatie(agregateur, monkeypatch):
    from api import vhost_stats as V
    ag, _ = agregateur
    horloge = {"t": 1000.0}
    monkeypatch.setattr(V.time, "monotonic", lambda: horloge["t"])
    ag.collecter()
    ag.vue("mois", True)
    horloge["t"] += V.VUE_OUBLI + 1
    appels = _espion(monkeypatch)
    ag.collecter()
    assert ("mois", True) not in appels and ("mois", True) not in ag._vues
    assert ("jour", False) in ag._vues          # les vues de base, elles, restent toujours prêtes
