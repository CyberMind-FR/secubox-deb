# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""#4011 — entrée / sortie par vhost : vague d'aspiration Gitea synthétique, bans, WAF, sessions, double tampon."""

import json
import re
import time

import pytest

import entree_sortie as es

UA_ASPI = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0 Safari/537.36"
UA_HUMAIN = "Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0"
UA_ROBOT = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
FORGE = "gitea.example.org"
T0 = 1795600800            # 2026-11-26 07:00 UTC, une heure pleine
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def date_nginx(t):
    return time.strftime("%d/%b/%Y:%H:%M:%S +0000", time.gmtime(t))


def ligne(ip, t, chemin, statut=200, octets=5000, ua=UA_HUMAIN, hote=FORGE, methode="GET"):
    return f'{hote} {ip} - - [{date_nginx(t)}] "{methode} {chemin} HTTP/1.1" {statut} {octets} "-" "{ua}"\n'


def menace(ip, t, chemin, categorie, action, ua=UA_ASPI, hote=FORGE):
    return json.dumps({"timestamp": time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime(t)), "client_ip": ip, "host": hote,
                       "method": "GET", "path": chemin, "category": categorie, "action": action, "user_agent": ua}) + "\n"


class Bans:
    def __init__(self):
        self.etat, self.panne = {}, False

    def __call__(self):
        if self.panne:
            raise OSError("nft indisponible")
        return dict(self.etat)


@pytest.fixture
def banc(tmp_path, monkeypatch):
    monkeypatch.setattr(es, "AMORCE", 1 << 30)       # tout lire des journaux synthétiques
    (tmp_path / "nginx").mkdir()
    (tmp_path / "waf").mkdir()
    horloge = {"t": T0}
    bans = Bans()

    def fabriquer():
        return es.EntreeSortie(rep_logs=tmp_path / "nginx", menaces=tmp_path / "waf" / "waf-threats.log",
                               etat=tmp_path / "cache" / "etat.json", rapport=tmp_path / "cache" / "es.json",
                               bans=bans, horloge=lambda: horloge["t"])

    (tmp_path / "nginx" / "secubox-hosts.log").write_text("")
    (tmp_path / "waf" / "waf-threats.log").write_text("")
    return tmp_path, horloge, bans, fabriquer


def ajouter(f, texte):
    with open(f, "a") as fh:
        fh.write(texte)


def vague(tmp_path, debut):
    """Aspirateur Gitea : UA figé, adresses tournantes, src/commit, blame, raw ; un humain et un robot à côté."""
    lignes = []
    for i in range(400):
        ip = f"203.0.113.{i % 200 + 1}"
        verbe = ("src/commit", "blame/commit", "raw/commit", "commits/branch")[i % 4]
        lignes.append(ligne(ip, debut + i * 5, f"/gandalf/depot/{verbe}/{'ab' * 20}/fichier{i}.go", ua=UA_ASPI))
    lignes += [ligne("192.0.2.10", debut + 60, "/", ua=UA_HUMAIN),
               ligne("192.0.2.10", debut + 90, "/assets/css/index.css", ua=UA_HUMAIN),
               ligne("192.0.2.10", debut + 300, "/explore/repos", ua=UA_HUMAIN),
               ligne("192.0.2.10", debut + 600, "/user/login", ua=UA_HUMAIN),
               ligne("198.51.100.7", debut + 100, "/robots.txt", ua=UA_ROBOT),
               ligne("198.51.100.8", debut + 110, "/api/v1/version", ua="curl/8.5.0"),
               ligne("198.51.100.9", debut + 120, "/wp-login.php", statut=404, ua=UA_HUMAIN),
               ligne("192.0.2.200", debut + 130, "/", ua="SecuBox-WAF-SelfTest/1.0")]
    ajouter(tmp_path / "nginx" / "secubox-hosts.log", "".join(lignes))


def test_typage_vague_aspiration_et_reductions(banc):
    tmp_path, horloge, bans, fabriquer = banc
    agg = fabriquer()
    agg.collecter()                                   # ligne de base des bans
    vague(tmp_path, T0)
    ajouter(tmp_path / "waf" / "waf-threats.log",
            "".join(menace(f"203.0.113.{i}", T0 + 2000 + i, "/gandalf/depot/src/commit/x", "aspirateur_ua", "banned")
                    for i in range(1, 31)))
    horloge["t"] = T0 + 2100
    agg.collecter()
    # les bans posés : les adresses aspiratrices renvoient des paquets, refusés avant HTTP
    bans.etat = {f"203.0.113.{i}": 50 for i in range(1, 31)}
    horloge["t"] = T0 + 3000
    agg.collecter()
    bans.etat = {f"203.0.113.{i}": 80 for i in range(1, 31)}
    horloge["t"] = T0 + 3600 + 10                    # l'heure T0 est close : fenêtre « 1h »
    r = agg.collecter()

    v = next(x for x in r["vhosts"] if x["vhost"] == FORGE)
    b = v["fenetres"]["1h"]
    pv = b["entree"]["par_visite"]
    assert pv["aspirateur"]["requetes"] >= 30 + (400 - es.SEUIL_RAFALE)   # bloqués WAF + au-delà du seuil de rafale
    assert pv["humain"]["requetes"] >= 4
    assert pv["robot"]["requetes"] == 1
    assert pv["outil"]["requetes"] == 1
    assert pv["sonde"]["requetes"] == 1
    assert b["entree"]["par_page"]["forge"] == 430
    assert b["entree"]["par_page"]["statique"] >= 2
    assert b["entree"]["par_page"]["admin"] >= 2
    assert b["reductions"]["waf"]["requetes"] == 30
    assert b["reductions"]["erreurs"]["c4xx"] == 1
    # 50 paquets refusés dans l'heure close, 30 de plus dans l'heure entamée, imputés au vhost visité
    assert b["reductions"]["bans"]["paquets"] == 30 * 50
    assert v["fenetres"]["en_cours"]["reductions"]["bans"]["paquets"] == 30 * 30
    assert b["entree"]["requetes"] == 437                    # 407 lignes nginx (auto-test exclu) + 30 bloquées WAF
    assert b["sortie"]["requetes"] == 437 - 30 - 1
    assert r["complet"] is True


def test_autotest_exclu(banc):
    tmp_path, horloge, bans, fabriquer = banc
    agg = fabriquer()
    ajouter(tmp_path / "nginx" / "secubox-hosts.log",
            "".join(ligne("192.0.2.200", T0 + i, "/", ua="SecuBox-WAF-SelfTest/2.1") for i in range(50)))
    horloge["t"] = T0 + 3700
    r = agg.collecter()
    assert r["total"]["fenetres"]["1h"]["entree"]["requetes"] == 0


def test_sessions_coupees_a_30_min_et_robots_exclus(banc):
    tmp_path, horloge, bans, fabriquer = banc
    agg = fabriquer()
    lignes = [ligne("192.0.2.20", T0 + 0, "/"), ligne("192.0.2.20", T0 + 120, "/a"), ligne("192.0.2.20", T0 + 300, "/b"),
              # pause de 31 min : nouvelle session, d'une seule page
              ligne("192.0.2.20", T0 + 300 + 31 * 60, "/c"),
              ligne("192.0.2.21", T0 + 10, "/"),                       # une page : durée inconnue
              ligne("192.0.2.21", T0 + 20, "/style.css"),              # ressource : ne prolonge pas
              ligne("198.51.100.7", T0 + 30, "/", ua=UA_ROBOT), ligne("198.51.100.7", T0 + 900, "/x", ua=UA_ROBOT),
              ligne("198.51.100.8", T0 + 30, "/", ua="python-requests/2.31"), ligne("198.51.100.8", T0 + 600, "/y", ua="python-requests/2.31")]
    ajouter(tmp_path / "nginx" / "secubox-hosts.log", "".join(lignes))
    horloge["t"] = T0 + 3 * 3600
    r = agg.collecter()
    vis = r["total"]["fenetres"]["8h"]["visiteurs"]
    assert vis["sessions"] == 3
    assert vis["une_page"] == 2
    assert vis["pages"] == 5
    assert vis["duree_mediane_s"] == 300                    # 300 s (borne) pour la seule session de plusieurs pages


def test_double_tampon_passe_degradee(banc):
    tmp_path, horloge, bans, fabriquer = banc
    agg = fabriquer()
    vague(tmp_path, T0)
    horloge["t"] = T0 + 3700
    complet = agg.collecter()
    assert complet["complet"]
    bans.panne = True
    horloge["t"] = T0 + 3900
    r = agg.collecter()
    assert r["complet"] is True and "passe_degradee" in r
    assert r["genere"] == complet["genere"]
    disque = json.loads((tmp_path / "cache" / "es.json").read_text())
    assert disque["complet"] is True and disque["genere"] == complet["genere"]
    # reprise : le curseur persisté évite de recompter
    agg2 = fabriquer()
    bans.panne = False
    agg2.collecter()
    agg2.collecter()
    assert agg2.rapport()["total"]["fenetres"]["1h"]["entree"]["requetes"] == 407


def test_aucune_ip_ni_ua_ni_empreinte(banc):
    tmp_path, horloge, bans, fabriquer = banc
    agg = fabriquer()
    agg.collecter()
    vague(tmp_path, T0)
    ajouter(tmp_path / "waf" / "waf-threats.log", menace("203.0.113.9", T0 + 50, "/.env", "scanners", "banned"))
    bans.etat = {"203.0.113.9": 12}
    horloge["t"] = T0 + 3700
    agg.collecter()
    for f in (tmp_path / "cache" / "es.json", tmp_path / "cache" / "etat.json"):
        txt = f.read_text()
        assert not IP_RE.search(txt), f
        assert "Mozilla" not in txt and "curl" not in txt
        for sid in list(agg._sessions):
            assert sid[1] not in txt


def test_tendance_mediane_fenetres_precedentes(banc):
    tmp_path, horloge, bans, fabriquer = banc
    agg = fabriquer()
    lignes = []
    for h in range(6):                                # 6 heures calmes, puis une heure x10
        n = 20 if h < 5 else 200
        lignes += [ligne("192.0.2.30", T0 + h * 3600 + i, f"/p{i}") for i in range(n)]
    ajouter(tmp_path / "nginx" / "secubox-hosts.log", "".join(lignes))
    horloge["t"] = T0 + 6 * 3600 + 5
    r = agg.collecter()
    t = r["total"]["tendance"]["1h"]["entree"]
    assert t["sens"] == "hausse" and t["mediane"] == 20 and t["courant"] == 200


def test_classer_page():
    assert es.classer_page("GET", "/u/r/src/commit/abc/f.go") == "forge"
    assert es.classer_page("GET", "/u/r/blame/commit/abc/f.go") == "forge"
    assert es.classer_page("GET", "/api/v1/x") == "api"
    assert es.classer_page("GET", "/user/login?redirect=/") == "admin"
    assert es.classer_page("GET", "/static/app.js") == "statique"
    assert es.classer_page("GET", "/videos/watch.mp4") == "medias"
    assert es.classer_page("GET", "/blog/article") == "page"
    assert es.classer_page("PUT", "/blog/article") == "autre"
