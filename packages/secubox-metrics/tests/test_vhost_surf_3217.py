# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3217 — un seau de statistiques par origine Surf : 1,4 Go et redémarrages en boucle sur gk2.

Surf sert chaque site distant (et chaque pisteur) sous sa propre origine `surf-<hôte-aplati>.<box>`, pour cloisonner les
cookies. vhost_stats en faisait autant de « sites » : 9 231 seaux le 26/10 (7 936 à deux requêtes ou moins), 152 878
sur 30 jours, un cache de 83 Mo et 1,4 Go de RAM. Le relais Surf est UN site ; et aucun flot de noms ne doit plus faire
grossir la mémoire sans borne."""
import datetime
import json
from collections import Counter

from api import vhost_stats as V

JOUR = datetime.date.today().isoformat()


def _journal(tmp_path, monkeypatch, hotes):
    quand = datetime.datetime.now().strftime("%d/%b/%Y:10:00:00 +0100")
    log = tmp_path / "secubox-hosts.log"
    log.write_text("".join(f'{h} 93.184.216.34 - - [{quand}] "GET /page HTTP/1.1" 200 100 "-" "Mozilla/5.0"\n'
                           for h in hotes))
    monkeypatch.setattr(V, "JOURNAL_HOTES", log)
    monkeypatch.setattr(V, "REP_LOGS", tmp_path)
    monkeypatch.setattr(V, "CACHE", tmp_path / "cache.json")


def test_cle_de_seau():
    assert V.cle_seau("surf-www-lemonde-fr.gk2.secubox.in") == "surf.gk2.secubox.in"
    assert V.cle_seau("surf-connect-facebook-net.gk3.secubox.in") == "surf.gk3.secubox.in"
    assert V.cle_seau("surf-coursera_assets-s3-amazonaws-com.gk2.secubox.in") == "surf.gk2.secubox.in"   # vu sur gk2
    for inchange in ("surf.gk2.secubox.in", "ganimed.fr", "surfeurs.fr", "surf-x", "www.surf-shop.fr",
                     "radio.gk2.secubox.in"):
        assert V.cle_seau(inchange) == inchange


def test_les_origines_surf_comptent_comme_un_seul_site(tmp_path, monkeypatch):
    origines = [f"surf-site{i}-fr.gk2.secubox.in" for i in range(500)]
    _journal(tmp_path, monkeypatch, origines + ["ganimed.fr"])
    ag = V.VhostStatsAggregator()
    ag.collecter()
    assert set(ag._jours[JOUR]) == {"surf.gk2.secubox.in", "ganimed.fr"}
    assert ag._jours[JOUR]["surf.gk2.secubox.in"]["requetes"] == 500


def test_plafond_de_seaux_par_jour(tmp_path, monkeypatch):
    """Un flot de noms (scanner, en-têtes Host inventés) ne fait plus grossir la mémoire : au-delà du plafond, un seul
    seau « (autres) » ; les sites déjà connus continuent de compter chez eux."""
    monkeypatch.setattr(V, "PLAFOND_SEAUX_JOUR", 3)
    _journal(tmp_path, monkeypatch, ["a.fr", "b.fr", "c.fr", "d.fr", "e.fr", "a.fr"])
    ag = V.VhostStatsAggregator()
    ag.collecter()
    seaux = ag._jours[JOUR]
    assert set(seaux) == {"a.fr", "b.fr", "c.fr", V.AUTRES}
    assert seaux[V.AUTRES]["requetes"] == 2 and seaux["a.fr"]["requetes"] == 2


def test_le_cache_existant_est_fusionne_au_rechargement(tmp_path, monkeypatch):
    """Les 152 878 seaux déjà en cache sur gk2 fondent dès la mise à jour, sans perdre un compte."""
    cache = tmp_path / "cache.json"
    vieux = (datetime.date.today() - datetime.timedelta(days=60)).isoformat()
    cache.write_text(json.dumps({
        "version": 2, "suivi": {},
        "cumul": {"surf-a-fr.gk2.secubox.in": {"depuis": "2026-09-01", "visites": 4, "requetes": 6, "pays": {"FR": 4}},
                  "surf-b-fr.gk2.secubox.in": {"depuis": "2026-08-15", "visites": 1, "requetes": 1, "pays": {"DE": 1}}},
        "jours": {JOUR: {
            "surf-a-fr.gk2.secubox.in": {"visites": 2, "requetes": 3, "ips": ["93.184.216.34"], "chemins": {"/x": 2},
                                         "sans_ref": 1},
            "surf-b-fr.gk2.secubox.in": {"visites": 3, "requetes": 4, "ips": ["198.51.100.7", "93.184.216.34"],
                                         "chemins": {"/x": 1, "/y": 2}, "sans_ref": 2},
            "ganimed.fr": {"visites": 1, "requetes": 1, "ips": []}}},
    }))
    monkeypatch.setattr(V, "CACHE", cache)
    ag = V.VhostStatsAggregator()
    surf = ag._jours[JOUR]["surf.gk2.secubox.in"]
    assert set(ag._jours[JOUR]) == {"surf.gk2.secubox.in", "ganimed.fr"}
    assert (surf["visites"], surf["requetes"], surf["sans_ref"]) == (5, 7, 3)
    assert surf["ips"] == {"93.184.216.34", "198.51.100.7"} and surf["chemins"] == Counter({"/x": 3, "/y": 2})
    c = ag.cumul_de("surf.gk2.secubox.in")
    assert (c["depuis"], c["pays"]) == ("2026-08-15", {"FR": 4, "DE": 1})
    assert c["visites"] == 5 + 5                                  # cumul permanent (4 + 1) + fenêtre (2 + 3)
    assert vieux not in ag._jours


def test_sans_ref_survit_a_un_redemarrage(tmp_path, monkeypatch):
    """La part d'accès directs (#1059) était relue au chargement mais jamais écrite : elle repartait de zéro."""
    cache = tmp_path / "cache.json"
    monkeypatch.setattr(V, "CACHE", cache)
    ag = V.VhostStatsAggregator()
    ag._jours[JOUR]["ganimed.fr"].update({"visites": 10, "sans_ref": 7})
    cache.write_text(json.dumps(ag._serialiser()))
    assert V.VhostStatsAggregator()._jours[JOUR]["ganimed.fr"]["sans_ref"] == 7


def test_la_fusion_respecte_le_plafond_d_ip(monkeypatch):
    monkeypatch.setattr(V, "PLAFOND_IP", 3)
    t, s = V._vierge(), V._vierge()
    t["ips"] = {"203.0.113.1", "203.0.113.2"}
    s["ips"] = {"203.0.113.3", "203.0.113.4"}
    V._ajouter(t, s, plafond_ip=V.PLAFOND_IP)
    assert len(t["ips"]) == 3 and t["ips_debordees"] is True
