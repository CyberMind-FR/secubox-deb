# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3734 : mémoire des leurres — ingestion à curseur du journal des menaces, attaquants, dictionnaire, rejeux."""
import json
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from api import leurres_memoire as lm  # noqa: E402

T0 = 1794700000


def ligne(ip, service, t, agent="balayeur", client="", essais=None, action="banned"):
    e = {"timestamp": "", "client_ip": ip, "host": service, "category": "leurre:" + service, "action": action,
         "user_agent": client, "tool": "authwatch", "agent": agent, "at": t}
    if essais:
        e["essais"] = [{"compte": c, "mot_de_passe": m} for c, m in essais]
    return json.dumps(e, ensure_ascii=False) + "\n"


@pytest.fixture
def m(tmp_path):
    journal = tmp_path / "waf-threats.log"
    journal.write_text("")
    return lm.Memoire(tmp_path / "leurres.db", journal), journal


def ajoute(journal, *lignes):
    with open(journal, "a", encoding="utf-8") as f:
        f.writelines(lignes)


def test_ingestion_ne_garde_que_les_leurres_et_ne_relit_pas(m):
    mem, j = m
    ajoute(j, '{"client_ip":"203.0.113.1","category":"scanners","at":%d}\n' % T0,
           ligne("203.0.113.1", "vnc", T0, "sondeur", "vnc client RFB 003.003"), "pas du json\n")
    assert mem.ingerer(T0 + 1) == 1
    assert mem.ingerer(T0 + 2) == 0
    ajoute(j, ligne("203.0.113.2", "telnet", T0 + 5, "force-brute", "telnet", [("root", "xc3511")]))
    assert mem.ingerer(T0 + 6) == 1
    assert mem.resume(T0 + 6)["attaquants"] == 2


def test_ligne_incomplete_attendue_au_tour_suivant(m):
    mem, j = m
    entiere = ligne("203.0.113.3", "rdp", T0)
    ajoute(j, entiere[:40])
    assert mem.ingerer(T0) == 0
    ajoute(j, entiere[40:])
    assert mem.ingerer(T0) == 1


def test_rotation_finit_l_ancien_fichier_puis_reprend_au_debut(m):
    mem, j = m
    ajoute(j, ligne("203.0.113.1", "vnc", T0))
    mem.ingerer(T0)
    ajoute(j, ligne("203.0.113.2", "vnc", T0 + 1))            # écrite avant la rotation, pas encore lue
    os.rename(j, str(j) + ".1")
    j.write_text(ligne("203.0.113.3", "vnc", T0 + 2))
    assert mem.ingerer(T0 + 3) == 2
    assert mem.resume(T0 + 3)["attaquants"] == 3


def test_local_et_horodatage_du_journal(m):
    mem, j = m
    e = json.loads(ligne("local", "telnet", 0, "force-brute", "telnet", [("a", "b")], action="detect"))
    del e["at"]
    e["timestamp"] = "2026-11-15T09:42:50+01:00"
    ajoute(j, json.dumps(e) + "\n")
    mem.ingerer(T0)
    a = mem.attaquants(T0 + 86400)[0]
    assert a["ip"] == "local" and a["derniere"] == 1794732170


def test_attaquants_regroupes_par_adresse(m):
    mem, j = m
    ajoute(j, ligne("203.0.113.24", "telnet", T0, "force-brute", "telnet négociation fffd18",
                    [("root", "xc3511"), ("admin", "xc3511")]),
           ligne("203.0.113.24", "redis", T0 + 3600, "sondeur", "redis INFO"),
           ligne("198.51.100.7", "rdp", T0 + 10, "force-brute", "rdp cookie mstshash", [("administrator", "")]))
    mem.ingerer(T0 + 4000)
    a = {x["ip"]: x for x in mem.attaquants(T0 + 4000)}
    v = a["203.0.113.24"]
    assert v["services"] == ["redis", "telnet"] and v["profil"] == "force-brute" and v["visites"] == 2
    assert v["premiere"] == T0 and v["derniere"] == T0 + 3600 and v["nb_essais"] == 2
    assert v["essais"] == [{"compte": "root", "mot_de_passe": "xc3511"}, {"compte": "admin", "mot_de_passe": "xc3511"}]
    assert v["rejeu"] is True and a["198.51.100.7"]["rejeu"] is False
    assert [x["ip"] for x in mem.attaquants(T0 + 4000, filtre="xc3511")] == ["203.0.113.24"]
    assert [x["ip"] for x in mem.attaquants(T0 + 4000, filtre="mstshash")] == ["198.51.100.7"]
    assert [x["ip"] for x in mem.attaquants(T0 + 4000, profil="force-brute")] == ["203.0.113.24", "198.51.100.7"]


def test_fiche_d_une_adresse(m):
    mem, j = m
    ajoute(j, ligne("203.0.113.24", "telnet", T0, "force-brute", "telnet", [("root", "a")]),
           ligne("203.0.113.24", "vnc", T0 + 9, "sondeur", "vnc client RFB 003.008"))
    mem.ingerer(T0 + 10)
    f = mem.fiche("203.0.113.24", T0 + 10)
    assert [v["service"] for v in f["visites"]] == ["vnc", "telnet"]
    assert f["visites"][1]["essais"] == [{"compte": "root", "mot_de_passe": "a"}]
    assert mem.fiche("203.0.113.99", T0)["visites"] == []


def test_dictionnaire(m):
    mem, j = m
    ajoute(j, ligne("203.0.113.1", "telnet", T0, "force-brute", "t", [("root", "xc3511"), ("admin", "xc3511"), ("root", "")]),
           ligne("203.0.113.2", "telnet", T0, "force-brute", "t", [("root", "xc3511")]),
           ligne("203.0.113.3", "redis", T0, "force-brute", "r", [("", "123456")]))
    mem.ingerer(T0)
    d = mem.dictionnaire(T0)
    assert d["mots_de_passe"][0] == {"mot_de_passe": "xc3511", "comptes": 2, "adresses": 2, "essais": 3}
    assert {"mot_de_passe": "", "comptes": 1, "adresses": 1, "essais": 1} in d["mots_de_passe"]
    assert d["comptes"][0] == {"compte": "root", "adresses": 2, "essais": 3}
    assert d["couples"] == 4


def test_rejeux_trois_formes(m):
    mem, j = m
    ajoute(j, ligne("203.0.113.1", "telnet", T0, "force-brute", "outil-x", [("root", "vizxv"), ("admin", "vizxv")]),
           ligne("203.0.113.2", "telnet", T0, "force-brute", "outil-y", [("root", "vizxv")]),
           ligne("198.51.100.9", "telnet", T0, "force-brute", "outil-y", [("root", "vizxv")]),
           ligne("203.0.113.1", "redis", T0, "sondeur", "outil-x"),
           ligne("203.0.113.7", "vnc", T0, "balayeur", ""))
    mem.ingerer(T0)
    r = mem.rejeux(T0)
    assert r["mot_de_passe_plusieurs_comptes"] == [
        {"mot_de_passe": "vizxv", "comptes": ["admin", "root"], "adresses": 3}]
    g = r["couple_plusieurs_adresses"][0]
    assert (g["compte"], g["mot_de_passe"]) == ("root", "vizxv")
    assert g["adresses"] == ["198.51.100.9", "203.0.113.1", "203.0.113.2"] and g["blocs"] == 2
    assert r["client_plusieurs_leurres"] == [{"client": "outil-x", "services": ["redis", "telnet"], "adresses": 1}]
    assert mem.resume(T0)["rejeux"] == 3


def test_resume_et_par_leurre(m):
    mem, j = m
    ajoute(j, ligne("203.0.113.1", "telnet", T0, "force-brute", "t", [("root", "a")]),
           ligne("203.0.113.1", "telnet", T0 + 1, "force-brute", "t", [("root", "a")]),
           ligne("local", "vnc", T0, "sondeur", "v", action="detect"))
    mem.ingerer(T0 + 2)
    r = mem.resume(T0 + 2)
    assert r["attaquants"] == 1 and r["couples"] == 1 and r["touches"] == 3
    assert r["par_leurre"]["telnet"] == 2 and r["par_leurre"]["vnc"] == 1
    assert r["premiere"] == T0


def test_fenetre_et_purge(m):
    mem, j = m
    ajoute(j, ligne("203.0.113.1", "vnc", T0), ligne("203.0.113.2", "vnc", T0 + 31 * 86400))
    mem.ingerer(T0 + 31 * 86400)
    assert [a["ip"] for a in mem.attaquants(T0 + 31 * 86400)] == ["203.0.113.2"]
    assert mem.purger(T0 + 31 * 86400) == 1
    assert mem.fiche("203.0.113.1", T0 + 31 * 86400)["visites"] == []


def test_base_ouverte_au_groupe(m):
    mem, j = m
    ancien = os.umask(0o027)
    try:
        mem.ingerer(T0)
    finally:
        os.umask(ancien)
    assert mem.chemin.stat().st_mode & 0o777 == 0o660


def test_champs_bornes(m):
    mem, j = m
    ajoute(j, ligne("203.0.113.1", "telnet", T0, "force-brute", "c" * 900, [("u" * 500, "p" * 500)] * 40))
    mem.ingerer(T0)
    v = mem.fiche("203.0.113.1", T0)["visites"][0]
    assert len(v["client"]) == 200 and len(v["essais"]) == 10 and len(v["essais"][0]["compte"]) == 128
