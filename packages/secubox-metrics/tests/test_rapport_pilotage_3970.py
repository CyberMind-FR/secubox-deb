# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3970 : rapport de pilotage hebdomadaire et relevé quotidien.

Collecte bornée en flux (journaux tournés et compressés, lignes corrompues, plafonds), « non mesuré » jamais remplacé par 0, écart
seulement entre deux semaines mesurées, décisions par seuils écrits, relevé atomique et tourné, PDF de six pages sans adresse IP."""
import gzip
import json
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import tracemalloc
from datetime import date, datetime, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "api"))
import releve_quotidien as RQ  # noqa: E402
import rapport_pilotage as RP  # noqa: E402

PKG = Path(__file__).resolve().parents[1]
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b|\b[0-9a-f]{1,4}(?::[0-9a-f]{0,4}){2,7}\b", re.I)


def ts(jour: str, h: int = 12, m: int = 0) -> float:
    return datetime.fromisoformat(f"{jour}T{h:02d}:{m:02d}:00").replace(tzinfo=RQ.PARIS).timestamp()


def ligne(jour, h, action, host="www.a.test", cat="lfi", ip="203.0.113.9", **kw):
    t = datetime.fromtimestamp(ts(jour, h), RQ.PARIS).isoformat()
    return json.dumps({"timestamp": t, "host": host, "category": cat, "severity": "high", "action": action, "client_ip": ip, **kw}) + "\n"


# ── jours de Paris, masquage ──────────────────────────────────────────────
def test_jours_de_paris_et_changement_d_heure():
    t0, t1 = RQ.bornes("2026-10-25")                      # passage à l'heure d'hiver : 25 h
    assert t1 - t0 == 25 * 3600
    t0, t1 = RQ.bornes("2026-03-29")                      # heure d'été : 23 h
    assert t1 - t0 == 23 * 3600
    assert RQ.jour_de(ts("2026-11-20", 0, 30)) == "2026-11-20"
    assert RQ.hier(ts("2026-11-23", 0, 20)) == "2026-11-22"
    assert RP.periode("2026-11-22") == (RQ.jours_entre("2026-11-16", "2026-11-22"), RQ.jours_entre("2026-11-09", "2026-11-15"))


def test_aucune_adresse_ne_passe_le_masque():
    t = RQ.sans_ip("de 203.0.113.9 et 2001:db8::1 ou ::ffff:10.0.0.1 à 12:30:45, ACT-0042")
    assert "203.0.113.9" not in t and "2001:db8" not in t and "10.0.0.1" not in t
    assert "12:30:45" in t and "ACT-0042" in t
    assert RQ.nom_site("198.51.100.7:443") == "(adresse IP nue)" and RQ.nom_site("[2001:db8::2]:8443") == "(adresse IP nue)"
    assert RQ.nom_site("WWW.A.test:443") == "www.a.test" and RQ.nom_site("") == "(sans nom)"


# ── lecture en flux bornée ────────────────────────────────────────────────
def test_ligne_trop_longue_sautee_et_budget(tmp_path):
    f = tmp_path / "j.log"
    f.write_bytes(b'{"a":1}\n' + b"x" * (RQ.LIGNE_MAX + 50) + b"\n" + b'{"b":2}\n')
    c = RQ.Counter()
    assert [x.strip() for x in RQ.lignes(f, RQ.Budget(1 << 20), c)] == [b'{"a":1}', b'{"b":2}']
    assert c["trop_longues"] == 1
    b = RQ.Budget(10)
    assert len(list(RQ.lignes(f, b))) == 1 and b.epuise


def _journaux(tmp_path, jours):
    """Journal courant (dernier jour), .1 clair (avant-dernier), .2.gz … (les plus vieux) + une ligne corrompue."""
    base = tmp_path / "waf-threats.log"
    for i, (j, contenu) in enumerate(reversed(jours)):
        cible = base if i == 0 else Path(f"{base}.{i}") if i == 1 else Path(f"{base}.{i}.gz")
        texte = "".join(contenu) + ("{corrompu\n" if i == 1 else "")
        if str(cible).endswith(".gz"):
            with gzip.open(cible, "wt") as g:
                g.write(texte)
        else:
            cible.write_text(texte)
        os.utime(cible, (ts(j, 23, 59), ts(j, 23, 59)))
    return base


def test_journaux_tournes_compresses_corrompus_et_couverture(tmp_path):
    base = _journaux(tmp_path, [
        ("2026-11-19", [ligne("2026-11-19", 23, "detect")]),
        ("2026-11-20", [ligne("2026-11-20", 3, "banned"), ligne("2026-11-20", 3, "warning", cat="sqli"), ligne("2026-11-20", 4, "robot", cat="robots")]),
        ("2026-11-21", [ligne("2026-11-21", 10, "leurre_redirige", servies=5, ip="2001:db8::5"), ligne("2026-11-21", 11, "detect", host="198.51.100.1")]),
    ])
    m = RQ.lire_menaces(base, geo=lambda ip: "US" if ip.startswith("203.") else None)
    assert m.erreurs["illisibles"] == 1
    fin = ts("2026-11-22", 1)
    assert RQ.resume_waf(m, "2026-11-19", fin) is None          # première ligne à 23 h : jour non couvert → non mesuré
    r = RQ.resume_waf(m, "2026-11-20", fin)
    assert r["couches"] == {"arrete": 1, "refuse": 1, "detourne": 0, "passe": 0, "robots": 1}
    assert r["bloquees"] == 2 and r["hostiles"] == 2 and r["categories"] == {"lfi": 1, "sqli": 1}
    assert r["heures"][3] == 2 and r["pays"] == {"US": [2, 2]}
    r = RQ.resume_waf(m, "2026-11-21", fin)
    assert r["couches"]["detourne"] == 5 and r["bloquees"] == 5      # un leurre compte les requêtes servies
    assert "(adresse IP nue)" in r["sites_hostiles"]
    assert RQ.resume_waf(m, "2026-11-22", ts("2026-11-23", 1))["bloquees"] == 0      # couvert, sans menace : 0 réel
    assert RQ.resume_waf(m, "2026-11-22", ts("2026-11-22", 12)) is None                # jour en cours : non mesuré
    assert RQ.lire_menaces(tmp_path / "absent.log") is None


def test_budget_epuise_laisse_les_vieux_jours_non_mesures(tmp_path):
    base = _journaux(tmp_path, [("2026-11-19", [ligne("2026-11-19", 1, "banned")] * 50), ("2026-11-20", [ligne("2026-11-20", 1, "banned")] * 50),
                                ("2026-11-21", [ligne("2026-11-21", 1, "banned")])])
    taille = (base.stat().st_size + Path(f"{base}.1").stat().st_size) + 10
    m = RQ.lire_menaces(base, budget_octets=taille)
    assert m.erreurs["budget_epuise"] == 1
    fin = ts("2026-11-22", 2)
    assert RQ.resume_waf(m, "2026-11-19", fin) is None               # le .2.gz incomplet n'est pas compté du tout
    assert RQ.resume_waf(m, "2026-11-21", fin)["bloquees"] == 1


def test_archive_tronquee_arrete_la_couverture_sans_planter(tmp_path):
    base = _journaux(tmp_path, [("2026-11-19", [ligne("2026-11-19", 1, "banned")] * 400), ("2026-11-20", [ligne("2026-11-20", 1, "banned")]),
                                ("2026-11-21", [ligne("2026-11-21", 1, "banned")])])
    gz = Path(f"{base}.2.gz")
    gz.write_bytes(gz.read_bytes()[:-30])
    m = RQ.lire_menaces(base)
    assert m.erreurs["fichiers_illisibles"] == 1 and "2026-11-19" not in m.jours
    assert RQ.resume_waf(m, "2026-11-21", ts("2026-11-22", 1))["bloquees"] == 1


def test_fichier_plus_vieux_que_la_fenetre_saute_mais_couverture_gardee(tmp_path):
    base = _journaux(tmp_path, [("2026-11-10", [ligne("2026-11-10", 5, "banned")]), ("2026-11-20", [ligne("2026-11-20", 8, "banned")]),
                                ("2026-11-21", [ligne("2026-11-21", 8, "banned")])])
    m = RQ.lire_menaces(base, depuis=ts("2026-11-20", 0) - 3600)
    assert m.erreurs["fichiers_anciens_ignores"] == 1 and "2026-11-10" not in m.jours
    assert RQ.resume_waf(m, "2026-11-20", ts("2026-11-22", 1))["bloquees"] == 1


def test_plafond_des_cles_et_memoire_bornee(tmp_path, monkeypatch):
    monkeypatch.setattr(RQ, "CLES_MAX", 50)
    base = tmp_path / "waf-threats.log"
    with open(base, "w") as f:
        f.write(ligne("2026-11-19", 23, "detect"))
        for i in range(20000):
            f.write(ligne("2026-11-20", i % 24, "banned", host=f"h{i}.test", cat=f"c{i}"))
    tracemalloc.start()
    m = RQ.lire_menaces(base)
    pic = tracemalloc.get_traced_memory()[1]
    tracemalloc.stop()
    j = m.jours["2026-11-20"]
    assert len(j["sites_bloques"]) <= 51 and j["sites_bloques"]["autres"] == 20000 - 50
    assert len(j["categories"]) <= 51
    assert pic < 8 << 20                                    # 20 000 hôtes distincts : quelques Mo, pas une table par hôte


# ── bans, propositions, DNS, nginx, disponibilité, instantanés ────────────
def test_bans_par_jour_et_propositions_en_attente(tmp_path):
    b = tmp_path / "bans.jsonl"
    b.write_text("".join(json.dumps(e) + "\n" for e in [
        {"ip": "203.0.113.1", "cat": "lfi", "sev": "high", "at": ts("2026-11-18", 9), "exp": 0, "action": "ban"},
        {"ip": "203.0.113.1", "cat": "lfi", "sev": "high", "at": ts("2026-11-20", 9), "exp": 0, "action": "ban"},
        {"ip": "203.0.113.1", "cat": "lfi|prolonge", "sev": "high", "at": ts("2026-11-20", 10), "exp": 0, "action": "ban"},
        {"ip": "203.0.113.2", "cat": "scan", "sev": "high", "at": ts("2026-11-20", 11), "exp": 0, "action": "ban"},
        {"ip": "203.0.113.2", "at": ts("2026-11-20", 12), "action": "unban"}]) + "pas du json\n")
    r = RQ.lire_bans(b)
    assert r["jours"]["2026-11-20"] == {"bans": 2, "adresses": 2, "prolongations": 1}
    assert RQ.resume_bans(r, "2026-11-19", ts("2026-11-21", 1)) == {"bans": 0, "adresses": 0, "prolongations": 0}   # mesuré : 0 réel
    assert RQ.resume_bans(r, "2026-11-17", ts("2026-11-21", 1)) is None                                           # avant le journal
    mes = tmp_path / "mesures.jsonl"
    mes.write_text("".join(json.dumps(e) + "\n" for e in [
        {"ts": ts("2026-11-19", 9), "ip": "203.0.113.2", "decision": "a_bannir"},        # banni ensuite : plus en attente
        {"ts": ts("2026-11-20", 9), "ip": "203.0.113.3", "decision": "a_bannir"},
        {"ts": ts("2026-11-20", 9), "ip": "203.0.113.4", "decision": "ecarte:protegee"}]))
    a = RQ.lire_attente(mes, r["dernier_ban"])
    assert a == {"proposees": 2, "en_attente": 1, "plus_ancienne": ts("2026-11-20", 9)}
    assert RQ.lire_attente(tmp_path / "absent.jsonl") is None


def test_dns_nginx_dispo(tmp_path):
    db = tmp_path / "dnstv.db"
    with sqlite3.connect(db) as cx:
        cx.execute("CREATE TABLE dnstv_counts(jour TEXT, client TEXT, domaine TEXT, categorie TEXT, decision TEXT, hits INTEGER)")
        cx.executemany("INSERT INTO dnstv_counts VALUES (?,?,?,?,?,?)", [("2026-11-20", "c", "a.test", "pub", "BLOCKED", 7),
                       ("2026-11-20", "c", "b.test", "pub", "BLOCKED", 3), ("2026-11-20", "c", "ok.test", "", "ALLOWED", 90)])
    assert RQ.lire_dns(db, "2026-11-19", "2026-11-21") == {"2026-11-20": {"requetes": 100, "filtrees": 10, "domaines": 2}}
    assert RQ.lire_dns(tmp_path / "absent.db", "a", "b") is None
    ng = {"depuis": "2026-11-15", "maj": "2026-11-22T08:00:00+01:00",
          "jours": {"2026-11-20": {"a.test": {"requetes": 10, "visites": 4, "robots": 3, "sondes": 1, "erreurs": 0},
                                   "203.0.113.5": {"requetes": 2, "visites": 0, "robots": 0, "sondes": 2, "erreurs": 2}}}}
    assert RQ.nginx_jour(ng, "2026-11-20")["requetes"] == 12 and "(adresse IP nue)" in RQ.nginx_jour(ng, "2026-11-20")["par_site"]
    assert RQ.nginx_jour(ng, "2026-11-21")["requetes"] == 0          # dans le suivi : 0 réel
    assert RQ.nginx_jour(ng, "2026-11-22") is None and RQ.nginx_jour(ng, "2026-11-14") is None
    st = tmp_path / "disponibilite.json"
    st.write_text(json.dumps({"noeud": "gk", "jours": {"2026-11-20": {"connus": 1440, "operationnels": 1437},
                                                       "2026-11-21": {"connus": 100, "operationnels": 100}}}))
    d = RQ.lire_dispo(st, ["2026-11-20", "2026-11-21", "2026-11-22"], noeud="gk")
    assert d == {"2026-11-20": round(100 * 1437 / 1440, 3), "2026-11-21": None, "2026-11-22": None}   # trop peu de relevés : non mesuré
    assert RQ.lire_dispo(st, ["2026-11-20"], noeud="autre") is None and RQ.lire_dispo(tmp_path / "x.json", ["2026-11-20"]) is None


def test_instantanes_sonde_et_sante(tmp_path):
    maintenant = ts("2026-11-22", 0, 25)
    s = tmp_path / "status.json"
    s.write_text(json.dumps({"timestamp": datetime.fromtimestamp(maintenant - 60, timezone.utc).isoformat(), "vhosts": {
        "a.test": {"status": "ok", "latency_ms": 80.0}, "b.test": {"status": "slow", "latency_ms": 900.0},
        "c.test": {"status": "ok", "latency_ms": 100.0}, "d.test": {"status": "down", "latency_ms": None}}}))
    r = RQ.lire_latence(s, maintenant)
    assert r["mediane_ms"] == 100.0 and r["lents"] == [("b.test", 900.0)] and r["injoignables"] == ["d.test"]
    assert RQ.lire_latence(s, maintenant + 3600) is None                  # sonde arrêtée : non mesuré
    dr = tmp_path / "doctor.json"
    dr.write_text(json.dumps({"generated_at": datetime.fromtimestamp(maintenant, timezone.utc).isoformat(), "checks": {
        "nginx": {"ok": False}, "gitea-lxc": {"ok": True, "details": {"veille_normale": True}},
        "comptes-admin": {"ok": False, "niveau": "avertissement"}, "autre": {"ok": False}}}))
    sa = RQ.lire_sante(dr, maintenant)
    assert sa["vitaux_ko"] == ["nginx"] and sa["avertissements"] == ["autre", "comptes-admin"] and sa["ok"] == 1


def test_acteurs_lus_par_la_vue_reduite():
    vus = []

    def lire(chemin):
        vus.append(chemin)
        if chemin.startswith("/api/v1/actor/radar"):
            return {"acteurs": [{"id": "ACT-0001", "risque": {"valeur": 40}, "action_proposee": "OBSERVE"},
                                {"id": "ACT-0002", "risque": {"valeur": 95}, "niveau": "BLOCK", "action_proposee": "blocage temporaire réversible (ban 1 h)", "scenario": "sondes"}]}
        return {"src": {"ips": 12}, "bans": 3, "detail": {"jours": {"debut": 0, "pas": 86400, "valeurs": [1, None]}}}
    a = RQ.lire_acteurs(lire)
    assert [x["id"] for x in a["acteurs"]] == ["ACT-0002", "ACT-0001"] and a["a_bloquer"] == 1 and a["acteurs"][0]["adresses"] == 12
    assert all(c.startswith("/api/v1/actor/") for c in vus)
    assert RQ.lire_acteurs(lambda c: None) is None


# ── relevé : atomique, borné, tourné ──────────────────────────────────────
def test_releve_remplace_le_jour_trie_et_garde_les_autres(tmp_path):
    d = tmp_path / "releve"
    RQ.ecrire_releve(d, {"jour": "2026-11-21", "waf": {"bloquees": 1}})
    RQ.ecrire_releve(d, {"jour": "2026-11-20", "waf": {"bloquees": 2}})
    RQ.ecrire_releve(d, {"jour": "2026-11-21", "waf": {"bloquees": 3}})
    f = d / "releve-202611.jsonl"
    assert [json.loads(x)["jour"] for x in f.read_text().splitlines()] == ["2026-11-20", "2026-11-21"]
    assert RQ.lire_releves(d, ["2026-11-21"])["2026-11-21"]["waf"]["bloquees"] == 3
    assert oct(f.stat().st_mode & 0o777) == "0o640" and not list(d.glob(".*tmp"))
    with open(f, "a") as h:
        h.write("{corrompu\n" + json.dumps({"jour": "pas-une-date"}) + "\n")
    assert sorted(RQ.lire_mois(f)) == ["2026-11-20", "2026-11-21"]
    with pytest.raises(ValueError):
        RQ.ecrire_releve(d, {"jour": "../x"})


def test_releve_ligne_bornee():
    gros = {"jour": "2026-11-20", "waf": {"pays": {f"P{i}": [i, i] for i in range(3000)}, "sites_bloques": {f"s{i}.test": i for i in range(3000)},
                                          "sites_hostiles": {}, "categories": {}}, "nginx": {"par_site": {f"s{i}": i for i in range(3000)}}}
    ligne_ = RQ.borner(gros, 4096)
    assert len(ligne_.encode()) <= 4096 and json.loads(ligne_)["jour"] == "2026-11-20"


def test_releve_rotation_treize_mois(tmp_path):
    for m in ("202510", "202511", "202512", "202611"):
        (tmp_path / f"releve-{m}.jsonl").write_text("")
    (tmp_path / "autre.txt").write_text("")
    assert RQ.purger(tmp_path, date(2026, 11, 26)) == ["releve-202510.jsonl"]
    assert sorted(p.name for p in tmp_path.iterdir()) == ["autre.txt", "releve-202511.jsonl", "releve-202512.jsonl", "releve-202611.jsonl"]


def test_releve_ecrit_hier_avec_instantanes_et_rattrape_sans(tmp_path):
    maintenant = ts("2026-11-23", 0, 25)
    srcs = {"menaces": None, "bans": None, "dns": None, "nginx": None, "dispo": None}
    inst = {"latence": {"mediane_ms": 90.0}, "sante": None, "acteurs": {"suivis": 3, "a_bloquer": 0}, "attente": None}
    r = RQ.releve(maintenant=maintenant, dossier=tmp_path, sources=srcs, instantanes=inst)
    assert r["ecrits"] == RQ.jours_entre("2026-11-16", "2026-11-22")
    rel = RQ.lire_releves(tmp_path, r["ecrits"])
    assert rel["2026-11-22"]["latence"] == {"mediane_ms": 90.0} and rel["2026-11-22"]["waf"] is None
    assert rel["2026-11-20"]["latence"] is None                          # un instantané ne vaut que pour la veille
    assert not IP_RE.search((tmp_path / "releve-202611.jsonl").read_text())
    r2 = RQ.releve(maintenant=maintenant, dossier=tmp_path, sources=srcs, instantanes=inst)
    assert r2["ecrits"] == ["2026-11-22"]                                # rien à rattraper


def test_resume_nginx_du_service_sans_adresse():
    pytest.importorskip("fastapi")
    from vhost_stats import VhostStatsAggregator, _vierge
    agg = VhostStatsAggregator.__new__(VhostStatsAggregator)
    import threading
    agg._verrou = threading.RLock()
    agg._maj = "2026-11-22T08:00:00+01:00"
    s = _vierge()
    s.update({"requetes": 5, "visites": 2, "robots": 1})
    s["ips"].add("203.0.113.8")
    agg._jours = {"2026-11-19": {"a.test": s}, "2026-11-20": {"a.test": s}}
    r = agg.resume_jours()
    assert r["depuis"] == "2026-11-20" and r["jours"]["2026-11-20"]["a.test"]["requetes"] == 5
    assert "203.0.113.8" not in json.dumps(r)


# ── rapport : chiffres, écarts, décisions, verdict ────────────────────────
def _vide(fin="2026-11-22"):
    cur, prec = RP.periode(fin)
    return {"jours": cur, "precedents": prec, "par_jour": {j: {"jour": j, **{c: None for c in RP.CLES_JOUR}} for j in prec + cur},
            "genere": ts("2026-11-23", 6), "exemple": False, "instant": {}}


def test_non_mesure_jamais_zero_et_semaine_complete_exigee():
    d = _vide()
    for j in d["jours"][1:]:
        d["par_jour"][j]["bans"] = {"bans": 2, "adresses": 2, "prolongations": 0}
    k = {x["cle"]: x for x in RP.kpis(d)}
    assert k["bans"]["valeur"] is None and k["bans"]["texte"] == "non mesuré" and k["bans"]["sous"] == "mesuré 6 jours sur 7"
    assert k["bans"]["serie"][0] is None and k["bans"]["serie"][1] == 2.0
    d["par_jour"][d["jours"][0]]["bans"] = {"bans": 0, "adresses": 0, "prolongations": 0}
    k = {x["cle"]: x for x in RP.kpis(d)}
    assert k["bans"]["valeur"] == 12 and k["bans"]["ecart"] is None and "non mesurée" in k["bans"]["sous"]
    for j in d["precedents"]:
        d["par_jour"][j]["bans"] = {"bans": 1, "adresses": 1, "prolongations": 0}
    k = {x["cle"]: x for x in RP.kpis(d)}
    assert k["bans"]["ecart"] == ("+71,4 %", 1)


def test_ecarts_et_accords():
    assert RP.ecart(None, 3, "compte") is None and RP.ecart(3, None, "compte") is None
    assert RP.ecart(0, 0, "compte") == ("stable", 0) and RP.ecart(5, 0, "compte")[0].startswith("nouveau")
    assert RP.ecart(99.95, 99.91, "points") == ("+0,04 point", 1) and RP.ecart(99.0, 99.5, "points") == ("-0,50 point", -1)
    assert RP.ecart(99.0, 97.0, "points") == ("+2,00 points", 1)
    assert RP.ecart(84, 95, "ms") == ("-11 ms", -1)
    assert RP.pl(0, "a", "b") == "a" and RP.pl(1, "a", "b") == "a" and RP.pl(2, "a", "b") == "b"
    assert RP.compte(1, "requête", "requêtes") == "1 requête" and RP.compte(1200, "requête", "requêtes") == "1 200 requêtes"
    assert RP.compte(None, "x", "y") == "non mesuré"


def test_verdict_construit_des_mesures():
    d = RP.donnees_exemple()
    ks = RP.kpis(d)
    v = RP.verdict(d, ks, [{}])
    assert v.startswith("Service disponible à 99,") and "requêtes servies ; 1 décision à prendre" in v
    for k in ks:
        if k["cle"] == "dispo":
            k["valeur"] = None
    assert RP.verdict(d, ks, []).startswith("180") and "adresse" not in RP.verdict(d, ks, [])
    assert RP.manques(ks) == "Non mesuré cette semaine : disponibilité."
    assert RP.verdict(_vide(), RP.kpis(_vide()), []) == "Semaine incomplètement mesurée ; rien à décider"


def test_decisions_par_seuils_et_rien_a_decider():
    d = _vide()
    assert [x["regle"] for x in RP.decisions(d)] == ["mesure_absente"]
    d = RP.donnees_exemple()
    assert [x["regle"] for x in RP.decisions(d)] == ["ban_en_attente", "acteur_a_bloquer"]
    d["instant"]["attente"]["en_attente"] = 0
    d["instant"]["acteurs"]["acteurs"][1]["mesure"] = {"niveau": "DENY"}
    assert RP.decisions(d) == []
    d["instant"]["sante"]["vitaux_ko"] = ["nginx"]
    d["instant"]["latence"]["injoignables"] = ["a.test", "b.test"]
    dec = RP.decisions(d)
    assert [x["regle"] for x in dec] == ["service_vital", "site_injoignable"]
    assert "Remettre en service le contrôle « nginx »" == dec[0]["titre"] and dec[1]["titre"] == "Rétablir 2 sites injoignables"
    assert "a.test, b.test." in dec[1]["raison"]
    for j in d["jours"]:
        d["par_jour"][j]["dispo"] = 99.0
        d["par_jour"][j]["latence"] = {"mediane_ms": 700.0}
        d["par_jour"][j]["waf"]["sites_bloques"] = {"www.exemple.test": d["par_jour"][j]["waf"]["bloquees"]}
    d["instant"]["sante"]["vitaux_ko"] = []
    d["instant"]["latence"]["injoignables"] = []
    regles = [x["regle"] for x in RP.decisions(d)]
    assert regles == ["dispo", "latence", "site_sous_attaque"] and len(RP.decisions(d)) == RP.DECISIONS_MAX


def test_pic_et_parts():
    j = RQ.jours_entre("2026-11-16", "2026-11-22")
    assert RP.pic([100, 120, 110, 900, 100, None, 105], j) == {"jour": "2026-11-19", "valeur": 900, "facteur": 900 / 105}
    assert RP.pic([100, 120, 110, 300, 100, 90, 105], j) is None            # sous 3 fois la médiane
    assert RP.pic([10, 12, 11, 400, 10, 9, 10], j) is None                  # sous 500
    assert RP.parts({"a": [1] * 7, "b": [None] + [1] * 6}) == [("a", None, "7"), ("b", None, "non mesuré sur 1 jour")]
    assert RP.parts({"a": [1] * 7, "b": [3] * 7}) == [("a", 25.0, "25,0 %"), ("b", 75.0, "75,0 %")]


def test_serie_acteur_par_jour_utc():
    debut = datetime(2026, 11, 16, tzinfo=timezone.utc).timestamp()
    a = {"jours": {"debut": debut, "pas": 86400, "valeurs": [1, None, 3, 4, 5, 6, 7]}}
    assert RP.serie_acteur(a, RQ.jours_entre("2026-11-16", "2026-11-22")) == [1.0, None, 3.0, 4.0, 5.0, 6.0, 7.0]
    assert RP.serie_acteur({}, ["2026-11-16"]) == [None]


def test_fusion_vivant_puis_releve():
    v = {"2026-11-20": {"waf": None, "bans": {"bans": 1}}}
    r = {"2026-11-20": {"waf": {"bloquees": 9}, "bans": {"bans": 5}}}
    f = RP.fusionner(v, r, ["2026-11-20", "2026-11-21"])
    assert f["2026-11-20"]["waf"] == {"bloquees": 9} and f["2026-11-20"]["bans"] == {"bans": 1} and f["2026-11-21"]["waf"] is None


# ── configuration et envoi ────────────────────────────────────────────────
def test_config_desactivee_par_defaut_et_destinataire_du_waf(tmp_path):
    assert RP.config(tmp_path / "absent.toml") == {"actif": False, "destinataire": "", "noeud": ""}
    c = tmp_path / "metrics.toml"
    c.write_text('[rapport.waf]\ndestinataire = "a@b.test"\n[rapport.pilotage]\nactif = "oui"\n')
    assert RP.config(c) == {"actif": False, "destinataire": "a@b.test", "noeud": ""}       # seul `true` active
    envois = []
    r = RP.executer(lambda: 1 / 0, None, lambda *a, **k: envois.append(a), {"actif": False, "destinataire": "a@b.test"})
    assert not r["envoye"] and not envois
    r = RP.executer(RP.donnees_exemple, lambda d: b"%PDF", lambda pdf, dest, *a, **k: {"envoye": True, "destinataire": dest, "objet": k["objet"]},
                    {"actif": True, "destinataire": "a@b.test"})
    assert r["envoye"] and "rapport de pilotage" in r["objet"]


def test_main_sans_activation_ne_produit_rien(monkeypatch, capsys):
    monkeypatch.setattr(RP, "CONF", Path("/nonexistent/metrics.toml"))
    monkeypatch.setattr(RP, "collecter", lambda *a, **k: pytest.fail("aucune collecte quand le rapport est désactivé"))
    assert RP.main([]) == 0 and "désactivé" in capsys.readouterr().err


# ── PDF de bout en bout ───────────────────────────────────────────────────
def _texte(pdf: bytes, tmp_path) -> list[str]:
    if not shutil.which("pdftotext"):
        pytest.skip("pdftotext absent")
    f = tmp_path / "r.pdf"
    f.write_bytes(pdf)
    out = subprocess.run(["pdftotext", "-layout", str(f), "-"], check=True, timeout=60, capture_output=True, text=True).stdout
    return out.split("\f")


def test_pdf_exemple_six_pages_sans_adresse(tmp_path):
    pytest.importorskip("fpdf")
    d = RP.donnees_exemple()
    # Des adresses glissées partout où un texte libre entre : elles ne doivent pas sortir.
    d["instant"]["acteurs"]["acteurs"][0]["scenario"] = "Sondes depuis 203.0.113.77 et 2001:db8::77"
    d["instant"]["latence"]["injoignables"] = ["198.51.100.9"]
    d["par_jour"][d["jours"][0]]["waf"]["sites_bloques"]["192.0.2.44"] = 5
    pdf = RP.construire_pdf(d)
    pages = [p for p in _texte(pdf, tmp_path) if p.strip()]
    assert len(pages) == 6
    tout = "\n".join(pages)
    assert not IP_RE.search(tout), IP_RE.search(tout)
    assert "ACT-0" not in tout and "Acteur A" in tout
    assert all("Données d'exemple" in p for p in pages)
    assert "Le trafic, couche par couche" in pages[1] and "Les acteurs suivis" in pages[4] and "Décider pour la semaine prochaine" in pages[5]


def test_pdf_sans_aucune_mesure(tmp_path):
    pytest.importorskip("fpdf")
    pages = [p for p in _texte(RP.construire_pdf(_vide()), tmp_path) if p.strip()]
    assert len(pages) == 6
    tout = "\n".join(pages)
    assert "non mesuré" in tout and "Semaine incomplètement mesurée" in pages[0]
    assert "Rendre lisible le journal des menaces" in pages[5]
    assert " 0 requête" not in tout


# ── paquet ────────────────────────────────────────────────────────────────
def _unite(nom):
    return (PKG / "systemd" / nom).read_text()


def test_unites_durcies_minuteur_pilotage_desactive_releve_active():
    for nom in ("secubox-metrics-releve.service", "secubox-metrics-rapport-pilotage.service"):
        u = _unite(nom)
        for directive in ("Type=oneshot", "User=secubox", "NoNewPrivileges=true", "ProtectSystem=strict", "ProtectHome=true", "PrivateTmp=true",
                          "ProtectKernelTunables=true", "ProtectControlGroups=true", "RestrictSUIDSGID=true", "LockPersonality=true",
                          "UMask=0027", "MemoryMax="):
            assert directive in u, (nom, directive)
    assert "IPAddressDeny=any" in _unite("secubox-metrics-releve.service") and "StateDirectory=secubox/metrics" in _unite("secubox-metrics-releve.service")
    assert "OnCalendar=Mon" in _unite("secubox-metrics-rapport-pilotage.timer")
    post = (PKG / "debian" / "postinst").read_text()
    assert "secubox-metrics-releve.timer" in post and "start secubox-metrics-releve.timer" in post
    assert "rapport-pilotage" not in post.replace("Le minuteur du rapport de pilotage", "")
    rules = (PKG / "debian" / "rules").read_text()
    assert "-Xsecubox-metrics-rapport-pilotage.timer" in rules and "--no-enable --no-start secubox-metrics-rapport-pilotage.service" in rules
    assert "-Xsecubox-metrics-releve.service" in rules and "dh_installsystemd --no-start secubox-metrics-releve.service" in rules
    for f in ("releve.service", "releve.timer", "rapport-pilotage.service", "rapport-pilotage.timer"):
        assert f"systemd/secubox-metrics-{f}" in rules
    # l'ancien rapport du lundi est inchangé
    assert "OnCalendar=Mon *-*-* 07:00:00" in _unite("secubox-metrics-rapport.timer")
    assert (PKG / "debian" / "changelog").read_text().startswith("secubox-metrics (1.32.1-1~trixie1) trixie;")


def test_emojis_drapeaux_et_pays_des_populations():
    assert RP.drapeau("FR") == "\U0001F1EB\U0001F1F7" and RP.drapeau("autres") is None and RP.drapeau("fr") is None
    assert RP.icone_categorie("ssh brute force") == "🔑" and RP.icone_categorie("inconnue") == "🛡️"
    pops = [{"adresses": 100, "pays_top": [["US", 50], ["CN", 25]]}, {"adresses": 40, "pays_top": [["US", 50], "x"]}, {"adresses": None}]
    assert RP.pays_populations(pops) == [("US", 70.0), ("CN", 25.0)]
    if RP.EMOJI_POLICE.exists():
        pytest.importorskip("PIL")
        assert RP.emoji_png("🛡️").startswith(b"\x89PNG")


def test_pdf_porte_des_images_d_emoji(tmp_path):
    pytest.importorskip("fpdf")
    pytest.importorskip("PIL")
    if not RP.EMOJI_POLICE.exists():
        pytest.skip("police couleur absente")
    pdf = RP.construire_pdf(RP.donnees_exemple())
    assert pdf.count(b"/Subtype /Image") > 20


def test_libelles_francais_et_niveaux_courts():
    assert RP.libelle_categorie("aspirateur_ua") == "Outil d'aspiration"
    assert RP.libelle_categorie("auth_smtp:sasl_failed") == "Mots de passe sur la messagerie"
    assert RP.libelle_categorie("host_anomaly:unrouted") == "Noms non servis" and RP.libelle_categorie("host_anomaly:ip_literal") == "Accès par adresse IP"
    assert RP.libelle_categorie("scanners|prolonge") == "Outils de balayage" and RP.libelle_categorie("leurre_redirige") == "Détournées vers un leurre"
    d = RP.donnees_exemple()
    d["instant"]["acteurs"]["acteurs"][1]["action"] = "blocage temporaire réversible (ban 1 h, puis 24 h)"
    assert "acteur_a_bloquer" in [x["regle"] for x in RP.decisions(d)]                 # la décision suit le niveau, pas le texte
