# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Chantier #4014 : couche nDPI des populations (services hors HTTP, risques, forme JA4, outil probable), phrases de lecture
« indice », couches de ruptures, relevé nDPI absent / illisible / périmé. Adresses de DOCUMENTATION seulement."""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from api import couche_ndpi as N  # noqa: E402
from api import populations as P  # noqa: E402
from api import profil as F  # noqa: E402

MAINTENANT = 1_795_759_000.0
DOC = ["192.0.2.%d" % i for i in range(1, 101)] + ["198.51.100.%d" % i for i in range(1, 101)]
JA4_LIB = "t13d0805h1_aaaaaaaaaaaa_bbbbbbbbbbbb"
JA4_NAV = "t13d1516h2_8daaf6152771_02713d6af862"


def releve_ndpid(sources, genere=MAINTENANT - 60, complet=True):
    return {"version": 1, "genere": int(genere), "complet": complet, "sources": sources}


def src(hors=(), risques=(), ja4="", fam="", ua="absent", agent="indetermine", premier=MAINTENANT - 600):
    return {"hors_waf": list(hors), "risques_notables": list(risques), "ja4": ja4, "ja4_famille": fam, "ua_famille": ua,
            "agent": agent, "premier": int(premier), "services": {}}


def ecrire(tmp, nom, d):
    p = tmp / nom
    p.write_text(json.dumps(d))
    return str(p)


def test_forme_ja4_tronquee_et_famille():
    assert N.forme_ja4(JA4_NAV) == "t13d1516h2"
    assert N.famille_ja4(JA4_NAV) == "nav" and N.famille_ja4(JA4_LIB) == "lib"
    assert N.forme_ja4("pas un ja4") == "" and N.famille_ja4(None) == ""


def test_rapprochement_par_adresse_et_phrases(tmp_path):
    sources = {}
    for i, ip in enumerate(DOC[:40]):            # 40 adresses vues : 37 visent Telnet/VNC, 30 faux navigateurs
        sources[ip] = src(hors=["Telnet/23", "VNC/5900"] if i < 37 else [], risques=["Possible Exploit"] if i < 20 else [],
                          ja4=JA4_LIB if i < 30 else JA4_NAV, fam="lib" if i < 30 else "nav", ua="navigateur",
                          agent="outil_probable" if i < 30 else "coherent")
    sources["203.0.113.9"] = src(hors=["SSH/22"])  # hors population : ne doit rien compter
    chemin = ecrire(tmp_path, "c.json", releve_ndpid(sources))
    lus, etat = N.lire(MAINTENANT, (chemin, str(tmp_path / "absent.json")))
    assert etat["etat"] == "disponible" and etat["source"] == "ndpid"
    n = N.par_population(DOC[:100], lus)
    assert n["adresses_vues"] == 40 and n["part_vues"] == 40 and n["part_hors_http"] == 37
    assert ["SSH/22", 3] not in n["services_hors_http"] and n["services_hors_http"][0][0] in ("Telnet/23", "VNC/5900")
    assert n["empreintes"][0] == ["t13d0805h1", 75, "lib"] and n["part_faux_navigateur"] == 75
    textes = {li["code"]: li for li in N.lecture(n)}
    assert textes["ndpi_hors_http"]["texte"] == "Hors HTTP : 37 % de ses adresses visent aussi Telnet ou VNC."
    assert textes["ndpi_faux_navigateur"]["indice"] is True and "(indice)" in textes["ndpi_faux_navigateur"]["texte"]
    assert "Possible Exploit" in textes["ndpi_risque"]["texte"] and "ndpi_bibliotheque" not in textes
    assert not any(ip in json.dumps(n) + json.dumps(N.lecture(n)) for ip in sources)


def test_sbxdpi_brut_en_repli_sans_ua(tmp_path):
    brut = {"genere": int(MAINTENANT - 30), "complet": False, "sources": {
        ip: {"premier": int(MAINTENANT - 100), "services": {"VNC/5900": 2, "TLS/443": 1}, "risques": {"Missing SNI TLS Extn": 1},
             "ja4": {JA4_LIB: 3}} for ip in DOC[:20]}}
    lus, etat = N.lire(MAINTENANT, (str(tmp_path / "absent.json"), ecrire(tmp_path, "s.json", brut)))
    assert etat == {"etat": "partiel", "source": "sbxdpi", "genere": int(MAINTENANT - 30), "sources": 20}
    n = N.par_population(DOC[:20], lus)
    assert n["services_hors_http"] == [["VNC/5900", 100]] and n["risques"] == []     # le bruit connu est écarté
    codes = [li["code"] for li in N.lecture(n)]
    assert "ndpi_bibliotheque" in codes and "ndpi_faux_navigateur" not in codes       # sans UA : jamais « faux navigateur »


def test_absent_illisible_perime(tmp_path):
    absent = str(tmp_path / "x.json")
    assert N.lire(MAINTENANT, (absent, absent))[0] is None
    (tmp_path / "bad.json").write_text("{pas du json")
    lus, etat = N.lire(MAINTENANT, (str(tmp_path / "bad.json"), absent))
    assert lus is None and etat["etat"] == "indisponible" and "illisible" in etat["raison"]
    vieux = ecrire(tmp_path, "v.json", releve_ndpid({DOC[0]: src()}, genere=MAINTENANT - N.PERIME_S - 10))
    lus, etat = N.lire(MAINTENANT, (vieux, absent))
    assert lus is None and "périmé" in etat["raison"]
    assert N.par_population(DOC, None) is None and N.lecture(None) == []


def test_memoire_et_couches_ruptures(tmp_path):
    chemin = str(tmp_path / N.MEMOIRE)
    sources = {DOC[0]: {**N._norm_ndpid(src(hors=["Telnet/23"])), "premier": int(MAINTENANT - 600)},
               DOC[1]: N._norm_ndpid(src(agent="outil_probable"))}
    m = N.memoriser(chemin, sources, MAINTENANT)
    assert set(m["hors_http"]) == {DOC[0]} and set(m["outil"]) == {DOC[1]}
    assert N.memoriser(chemin, None, MAINTENANT + 60)["hors_http"] == m["hors_http"]   # sans relevé : rien n'est effacé
    cs = N.couches(m, int(MAINTENANT // F.QUART), F.QUART, F.RODAGE_Q, F.couche)
    assert [c["id"] for c in cs] == ["ndpi_hors_http", "ndpi_outil"]
    assert set(cs[0]["fenetres"]) == {"1h", "8h", "1j", "7j"} and cs[0]["fenetres"]["1h"]["sens"] == "insuffisant"
    ru = F.ruptures(MAINTENANT, {}, None, {}, None, cs)
    assert [c["id"] for c in ru["couches"]][-2:] == ["ndpi_hors_http", "ndpi_outil"]


def test_assembler_sans_et_avec_ndpi():
    a = P._Agregat()
    for ip in DOC[:30]:
        a.tentatives[(P._jour(MAINTENANT).toordinal(), ip, "collecte", "forge.example")] = (5, MAINTENANT - 100, MAINTENANT - 50, 0)
    classer = lambda ip: (64496, "Doc", "hebergeur")  # noqa: E731
    sans = P.assembler([a], MAINTENANT, lambda ip: "", classer, [], [], [], ndpi=(None, {"etat": "indisponible"}, None))
    assert sans["ndpi"] == "indisponible" and sans["complet"] is True
    assert all("ndpi" not in p for p in sans["populations"])
    sources = {ip: N._norm_ndpid(src(hors=["VNC/5900"])) for ip in DOC[:30]}
    avec = P.assembler([a], MAINTENANT, lambda ip: "", classer, [], [], [], ndpi=(sources, {"etat": "disponible"}, None))
    pop = avec["populations"][0]
    assert pop["ndpi"]["part_hors_http"] == 100
    assert any(li["code"] == "ndpi_hors_http" for li in pop["lecture"])
    assert not any(ip in json.dumps(avec) for ip in DOC[:30])
