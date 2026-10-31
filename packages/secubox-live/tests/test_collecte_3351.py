# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""secubox-live (#3351) : le collecteur agrège des sources existantes sans jamais publier d'adresse, de compte ni de secret."""
import json
import re
import sqlite3
import sys
import time
from pathlib import Path

ICI = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ICI))

from live import collecte as C  # noqa: E402

MAINTENANT = 1793440000  # 2026-10-31


def _pilotage(tmp: Path) -> Path:
    db = tmp / "pilotage.db"
    cx = sqlite3.connect(db)
    cx.executescript("""
    CREATE TABLE boites(cle TEXT PRIMARY KEY, nom TEXT NOT NULL, adresse TEXT NOT NULL, reseau TEXT NOT NULL, client TEXT,
      abonnement TEXT, agent_version TEXT NOT NULL DEFAULT '', vu_le INTEGER NOT NULL, inventaire_le INTEGER,
      inventaire_partiel INTEGER NOT NULL DEFAULT 0, boot_id TEXT NOT NULL DEFAULT '');
    CREATE TABLE inventaire(cle TEXT NOT NULL, chemin TEXT NOT NULL, valeur_json TEXT NOT NULL, releve_le INTEGER NOT NULL,
      tronque INTEGER NOT NULL DEFAULT 0, PRIMARY KEY(cle, chemin));
    """)
    cx.execute("INSERT INTO boites(cle,nom,adresse,reseau,vu_le) VALUES('maillage:gk4','gk4','10.10.0.9','maillage',?)",
               (MAINTENANT - 30,))
    cx.execute("INSERT INTO boites(cle,nom,adresse,reseau,vu_le) VALUES('maillage:gk5','gk5','10.10.0.10','maillage',?)",
               (MAINTENANT - 3600,))
    for chemin, v in (("Device.DeviceInfo.ModelName", "Raspberry Pi 400 Rev 1.0"),
                      ("Device.DeviceInfo.MemoryStatus.Total", 3881000),
                      ("Device.DeviceInfo.MemoryStatus.Free", 1940500),
                      ("Device.DeviceInfo.ProcessStatus.CPUUsage", 7),
                      ("Device.DeviceInfo.UpTime", 93600),
                      ("Device.X_SECUBOX_Pilotage.Interface", "distante")):
        cx.execute("INSERT INTO inventaire VALUES('maillage:gk4',?,?,?,0)", (chemin, json.dumps(v), MAINTENANT - 30))
    cx.commit()
    cx.close()
    return db


def _menaces(tmp: Path) -> Path:
    log = tmp / "waf-threats.log"
    lignes = []
    for i, (cat, action) in enumerate((("sqli", "block"), ("scanner:nikto", "block"), ("scanner:nuclei", "detect"),
                                       ("bruteforce", "ban"), ("sqli", "block"))):
        lignes.append(json.dumps({"timestamp": time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime(MAINTENANT - 60 * (i + 1))),
                                  "client_ip": "203.0.113.%d" % (i + 1), "host": "hall.gk2.secubox.in",
                                  "category": cat, "action": action, "user_agent": "x"}))
    log.write_text("\n".join(lignes) + "\n")
    return log


def _vhosts(tmp: Path) -> Path:
    f = tmp / "vhost_stats.json"
    jours = {"2026-10-30": {"hall.gk2.secubox.in": {"visites": 40, "requetes": 300, "ips": ["198.51.100.4"],
                                                    "pays": {"FR": 30, "DE": 5}}},
             "2026-10-31": {"hall.gk2.secubox.in": {"visites": 12, "requetes": 90, "ips": ["198.51.100.9"],
                                                    "pays": {"FR": 10, "BE": 2}}}}
    f.write_text(json.dumps({"version": 2, "jours": jours, "cumul": {}}))
    return f


def _sources(tmp: Path) -> C.Sources:
    conf = tmp / "live.toml"
    conf.write_text('mise_en_production = "2026-03-01"\n[roles]\ngk2 = "maître"\ngk4 = "banc"\n'
                    '[[feuille_de_route]]\nnom = "Alpha 20"\netat = "bientôt"\n')
    return C.Sources(pilotage_db=_pilotage(tmp), menaces=[_menaces(tmp)], vhost_stats=_vhosts(tmp),
                     nft_etat=tmp / "absent.json", dpi=tmp / "absent-dpi.json", haproxy_toml=tmp / "absent.toml",
                     configuration=conf, github_cache=tmp / "github.json", geoip=[], local_nom="gk2")


def test_noeuds_issus_du_pilotage_sans_adresse(tmp_path):
    etat = C.collecter(_sources(tmp_path), maintenant=MAINTENANT, reseau=False)
    noms = {n["nom"]: n for n in etat["noeuds"]}
    assert noms["gk4"]["etat"] == "interface distante" and noms["gk4"]["materiel"] == "Raspberry Pi 400 Rev 1.0"
    assert noms["gk4"]["memoire"] == 50 and noms["gk4"]["cpu"] == 7 and noms["gk4"]["role"] == "banc"
    assert noms["gk5"]["etat"] == "hors ligne"
    assert "gk2" in noms                                     # le maître lui-même, relevé localement
    assert etat["tuiles"]["noeuds_en_ligne"] == 2 and etat["tuiles"]["noeuds_total"] == 3


def test_jamais_d_adresse_ni_de_secret_dans_l_etat(tmp_path):
    etat = C.collecter(_sources(tmp_path), maintenant=MAINTENANT, reseau=False)
    texte = json.dumps(etat)
    assert not re.search(r"\b\d{1,3}(\.\d{1,3}){3}\b", texte), texte
    assert "client_ip" not in texte and "ips" not in json.dumps(etat.get("histo"))
    assert "user_agent" not in texte


def test_garde_finale_retire_toute_adresse():
    sale = {"a": "vu depuis 10.0.0.1", "b": ["2001:db8::1", "ok"], "c": {"d": "fe80::1%eth0"}}
    propre = C.nettoyer(sale)
    assert "10.0.0.1" not in json.dumps(propre) and "2001:db8" not in json.dumps(propre) and "fe80" not in json.dumps(propre)


def test_garde_ne_retire_pas_les_heures():
    assert C.nettoyer({"le": "2026-10-31T08:30:00Z", "t": "il y a 1 h"}) == {"le": "2026-10-31T08:30:00Z", "t": "il y a 1 h"}


def test_menaces_par_categorie_et_heure(tmp_path):
    etat = C.collecter(_sources(tmp_path), maintenant=MAINTENANT, reseau=False)
    cats = {m["categorie"]: m["n"] for m in etat["menaces"]}
    assert cats == {"sqli": 2, "scanner": 2, "bruteforce": 1}
    assert etat["tuiles"]["menaces_24h"] == 5 and etat["tuiles"]["bloquees_24h"] == 4
    assert sum(p["bloquees"] for p in etat["waf_heure"]) == 4 and len(etat["waf_heure"]) == 60


def test_historique_et_dates_reelles(tmp_path):
    etat = C.collecter(_sources(tmp_path), maintenant=MAINTENANT, reseau=False)
    assert etat["production"] == {"depuis": "2026-03-01", "historique_depuis": "2026-10-30"}
    jours = {h["jour"]: h for h in etat["histo"]}
    assert jours["2026-10-30"]["visites"] == 40 and jours["2026-10-31"]["attaques"] == 5
    assert etat["cartes"]["visiteurs"][0] == {"code": "FR", "n": 40}


def test_source_absente_reste_nulle(tmp_path):
    etat = C.collecter(_sources(tmp_path), maintenant=MAINTENANT, reseau=False)
    assert etat["dpi"] is None and etat["tuiles"]["bans_actifs"] is None and etat["tuiles"]["sites_publies"] is None
    assert etat["tuiles"]["disponibilite_30j"] is None and etat["dev"] is None
    assert etat["cartes"]["attaques"] is None                 # pas de base GeoIP : jamais de pays inventé


def test_dpi_garde_seulement_les_usages(tmp_path):
    s = _sources(tmp_path)
    s.dpi.write_text(json.dumps({"usages": [{"nom": "Web", "octets": 10, "pct": 60.0}, {"nom": "Vidéo", "pct": 40.0}],
                                 "appareils": [{"nom": "tel-de-marie", "octets": 5}]}))
    etat = C.collecter(s, maintenant=MAINTENANT, reseau=False)
    assert etat["dpi"] == [{"nom": "Web", "pct": 60.0}, {"nom": "Vidéo", "pct": 40.0}]
    assert "marie" not in json.dumps(etat)


def test_ecriture_atomique(tmp_path):
    cible = tmp_path / "live" / "etat.json"
    C.ecrire(cible, {"version": 1})
    assert json.loads(cible.read_text()) == {"version": 1} and oct(cible.stat().st_mode & 0o777) == "0o644"
