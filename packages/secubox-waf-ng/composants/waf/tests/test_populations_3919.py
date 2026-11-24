# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Chantier #3919, tâche 5 : relevé « populations d'attaquants » du module WAF.

Calcul pur sur les lignes du journal des menaces (7 jours, journaux tournés et compressés compris), cache fichier en
double tampon, route `GET /populations` lue par gk3 (garde `require_lecture_ai`). Adresses de test : publiques
NEUTRES générées (`8.{i}.0.1`) ou `2606:4700::1` ; aucune signature d'attaquant réelle."""
import gzip
import json
import os
import socketserver
import stat
import sys
import threading
import types
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from api import populations as P  # noqa: E402

MAINTENANT = datetime(2026, 11, 24, 12, 0, 0, tzinfo=timezone.utc).timestamp()
JOUR = 86400


def _ligne(ip, categorie, il_y_a_s=3600, host="forge.exemple.test", path="/", action="detect", **extra):
    d = {"timestamp": datetime.fromtimestamp(MAINTENANT - il_y_a_s, tz=timezone.utc).isoformat(),
         "client_ip": ip, "host": host, "method": "GET", "path": path, "category": categorie,
         "severity": "high", "rule_id": "x-001", "action": action, "user_agent": "", "tool": ""}
    d.update(extra)
    return json.dumps(d)


def _classer(classe="inconnu", asn=0, org=""):
    return lambda ip: (asn, org, classe)


def _calc(lignes, **kw):
    args = dict(maintenant=MAINTENANT, pays=lambda ip: "", classer=_classer(),
                campagnes_smtp=[], campagnes_profileur=[], rotation=[])
    args.update(kw)
    return P.calculer(lignes, **args)


def _pop(releve, ident):
    return next(p for p in releve["populations"] if p["id"] == ident)


# ── table des familles : copie exacte de reseau.Famille (Go, TestFamille) ──────────────────────────────────────────

def test_famille_table():
    cas = [
        ("auth_smtp_bruteforce", "messagerie"),
        ("auth_ssh_bruteforce", "acces_distant"),
        ("leurre_ssh", "acces_distant"),
        ("aspirateur_ua", "collecte"),
        ("recon_crawler", "collecte"),
        ("robots", "collecte"),
        ("scanners", "balayage_web"),
        ("honeypot", "balayage_web"),
        ("lfi", "balayage_web"),
        ("api_abuse", "balayage_web"),
        ("waf_fingerprint", "balayage_web"),
        ("host_anomaly:unrouted", "balayage_web"),
        ("rotation:asn", "collecte"),
        ("inconnue", "autre"),
    ]
    for entree, attendu in cas:
        assert P.famille(entree) == attendu, entree


def test_masquer_compte_comme_go():
    assert P.masquer_compte("") == "…"
    assert P.masquer_compte("abc") == "…"
    assert P.masquer_compte("gerald") == "ger…"
    assert P.masquer_compte("éèàù") == "éèà…"
    assert P.masquer_compte("ger…") == "ger…"   # idempotent : un compte déjà masqué le reste


# ── règles de population ─────────────────────────────────────────────────────────────────────────────────────────

def test_rotation_collecte():
    lignes = [_ligne(f"8.{i}.0.1", "aspirateur_ua") for i in range(60)]
    r = _calc(lignes, classer=_classer("proxy_loue", 212238, "Loueur exemple"))
    pops = [p for p in r["populations"] if p["famille"] == "collecte"]
    assert len(pops) == 1
    p = pops[0]
    assert p["adresses"] == 60 and p["une"] == 100 and p["le3"] == 100
    assert p["rotation"] is True
    assert p["classes"] == {"proxy_loue": 100}
    assert p["reseaux"] == 1
    assert p["reseaux_top"] == [{"asn": 212238, "org": "Loueur exemple", "classe": "proxy_loue", "adresses": 60}]
    assert p["nom_cible"] == "forge.exemple.test" and p["cibles"] == ["forge.exemple.test"]
    assert r["complet"] is True and r["fenetre_jours"] == 7


def test_pas_de_rotation_sous_50_adresses():
    r = _calc([_ligne(f"8.{i}.0.1", "aspirateur_ua") for i in range(49)])
    assert _pop(r, "famille:collecte")["rotation"] is False


def test_messagerie_reunie():
    smtp = [{"id": "0a1b2c3d", "compte": "ger…", "sources": 9, "premier": int(MAINTENANT) - 7200,
             "dernier": int(MAINTENANT) - 60},
            {"id": "4e5f6a7b", "compte": "adm…", "sources": 4, "premier": int(MAINTENANT) - 7200,
             "dernier": int(MAINTENANT) - 60}]
    lignes = [_ligne(f"8.{i}.0.1", "auth_smtp:sasl_failed", host="smtp", path="gerald", tool="authwatch",
                     campagne="0a1b2c3d") for i in range(9)]
    lignes += [_ligne(f"9.{i}.0.1", "auth_smtp:sasl_failed", host="smtp", path="admin", tool="authwatch",
                      campagne="4e5f6a7b") for i in range(4)]
    r = _calc(lignes, campagnes_smtp=smtp)
    pops = [p for p in r["populations"] if p["famille"] == "messagerie"]
    assert len(pops) == 1
    p = pops[0]
    assert p["id"] == "famille:messagerie"
    assert p["cibles"] == ["ger…", "adm…"]
    assert p["nom_cible"] == "ger…"
    assert p["adresses"] == 13
    # jamais un compte en clair, nulle part dans le relevé
    texte = json.dumps(r, ensure_ascii=False)
    assert "gerald" not in texte and '"admin"' not in texte


def test_profileur_population_si_10_adresses():
    ips = [f"8.{i}.0.1" for i in range(12)]
    petites = [f"9.{i}.0.1" for i in range(3)]
    prof = [{"signature": "00aa11bb22cc33dd", "attaquants": ips},
            {"signature": "44ee55ff66007788", "attaquants": petites}]
    lignes = [_ligne(ip, "scanners") for ip in ips + petites]
    r = _calc(lignes, campagnes_profileur=prof)
    p = _pop(r, "profileur:00aa11bb22cc33dd")
    assert p["adresses"] == 12 and p["famille"] == "balayage_web"
    # la petite campagne se fond dans sa famille
    assert _pop(r, "famille:balayage_web")["adresses"] == 3
    assert not any(x["id"] == "profileur:44ee55ff66007788" for x in r["populations"])


def test_autre_exclu():
    r = _calc([_ligne("8.1.0.1", "sqli"), _ligne("8.2.0.1", "xss")])
    assert r["populations"] == []


def test_rotation_etat_population():
    lignes = [_ligne(f"8.{i}.0.1", "rotation:0123abcd", action="banned") for i in range(5)]
    etat = [{"signature": "0123abcd" + "e" * 56, "hote": "forge.exemple.test", "sources": 70, "une": 95, "le3": 99,
             "classes": {"proxy_loue": 90, "acces": 10}, "bannies": 5, "dernier": int(MAINTENANT) - 30}]
    r = _calc(lignes, rotation=etat)
    p = _pop(r, "rotation:0123abcd")
    assert p["famille"] == "collecte" and p["rotation"] is True
    assert p["adresses"] == 5 and p["bans"] == 5 and p["etat"] == "bannie"
    assert p["nom_cible"] == "forge.exemple.test"
    # la famille collecte ne reprend pas ces lignes
    assert not any(x["id"] == "famille:collecte" for x in r["populations"])


def test_rotation_etat_sans_lignes():
    etat = [{"signature": "89abcdef" + "0" * 56, "hote": "forge.exemple.test", "sources": 60, "une": 90, "le3": 97,
             "classes": {"proxy_loue": 80}, "bannies": 0, "dernier": int(MAINTENANT) - 30}]
    p = _pop(_calc([], rotation=etat), "rotation:89abcdef")
    assert p["adresses"] == 60 and p["une"] == 90 and p["le3"] == 97 and p["etat"] == "observee"
    assert p["classes"] == {"proxy_loue": 80} and len(p["serie"]) == 7


# ── robustesse ──────────────────────────────────────────────────────────────────────────────────────────────────

def test_lignes_fautives():
    lignes = ["", "   ", "{tronqué", "null", "[]", '"chaine"', "{\"client_ip\": 3}",
              _ligne("local", "scanners"),
              _ligne("192.168.1.5", "scanners"),
              _ligne("999.1.1.1", "scanners"),
              _ligne("8.8.0.1", "scanners", timestamp="pas une date"),
              json.dumps({"client_ip": "8.9.0.1", "category": ["liste"], "timestamp": "2026-11-24T10:00:00Z"}),
              _ligne("2606:4700::1", "scanners")]
    r = _calc(lignes)
    p = _pop(r, "famille:balayage_web")
    assert p["adresses"] == 1
    texte = json.dumps(r)
    assert "local" not in texte and "192.168.1.5" not in texte


def test_serie_7_jours():
    lignes = []
    for k in range(7):                                  # J-k : k+1 lignes
        lignes += [_ligne("8.1.0.1", "scanners", il_y_a_s=k * JOUR + 60)] * (k + 1)
    lignes.append(_ligne("8.1.0.1", "scanners", il_y_a_s=9 * JOUR))   # hors fenêtre
    p = _pop(_calc(lignes), "famille:balayage_web")
    assert p["serie"] == [7, 6, 5, 4, 3, 2, 1]
    assert p["premier"] == int(MAINTENANT - 6 * JOUR - 60) and p["dernier"] == int(MAINTENANT - 60)


def test_id_stable():
    lignes = [_ligne(f"8.{i}.0.1", "aspirateur_ua") for i in range(20)]
    lignes += [_ligne(f"9.{i}.0.1", "scanners") for i in range(5)]
    a, b = _calc(lignes), _calc(list(reversed(lignes)))
    assert [p["id"] for p in a["populations"]] == [p["id"] for p in b["populations"]]
    assert {p["id"] for p in a["populations"]} == {"famille:collecte", "famille:balayage_web"}


def test_cves_population():
    lignes = [_ligne(f"8.{i}.0.1", "aspirateur_ua") for i in range(5)]
    lignes.append(_ligne("8.2.0.1", "ia_filtres_critique", rule_id="ia-CVE-2026-0001-x"))
    lignes.append(_ligne("9.9.0.1", "ia_filtres_haute", rule_id="CVE-2026-9999"))    # hors population
    r = _calc(lignes)
    assert _pop(r, "famille:collecte")["cves"] == ["CVE-2026-0001"]


def test_cves_bornees_a_20():
    lignes = [_ligne("8.1.0.1", "scanners")]
    lignes += [_ligne("8.1.0.1", "ia_filtres_moyenne", rule_id=f"CVE-2026-{1000 + i}") for i in range(30)]
    cves = _pop(_calc(lignes), "famille:balayage_web")["cves"]
    assert len(cves) == 20 and cves == sorted(cves) and len(set(cves)) == 20


# test_acl_datascope : DOCUMENTÉ, pas testé ici. Le cache doit rester lisible par le groupe `secubox-datascope`
# (tâche 12 pose l'ACL dans le postinst) : ecrire_cache écrit en 0640, jamais en 0600 (vérifié par test_double_tampon).


def test_recouvrement():
    lignes = [_ligne("8.1.0.1", "scanners"), _ligne("8.2.0.1", "scanners"), _ligne("8.3.0.1", "scanners"),
              _ligne("8.1.0.1", "aspirateur_ua"), _ligne("8.2.0.1", "aspirateur_ua")]
    r = _calc(lignes)
    assert r["recouvrement"] == {"adresses_communes": 2, "adresses_total": 3}


def test_classes_et_pays():
    lignes = [_ligne(f"8.{i}.0.1", "scanners") for i in range(4)]
    lignes.append(_ligne("8.9.0.1", "scanners", asn=64500, asn_org="Org ligne", reseau_classe="hebergeur"))
    appels = []

    def classer(ip):
        appels.append(ip)
        return (212238, "Loueur", "proxy_loue")

    r = _calc(lignes, classer=classer, pays=lambda ip: "US" if ip.startswith("8.0") or ip.startswith("8.1") else "GB")
    p = _pop(r, "famille:balayage_web")
    assert "8.9.0.1" not in appels                        # la ligne portait déjà son réseau
    assert p["classes"] == {"proxy_loue": 80, "hebergeur": 20}
    assert p["pays_top"] == [["GB", 60], ["US", 40]]
    assert p["reseaux"] == 2


def test_ligne_avec_asn_sans_classe_passe_par_le_catalogue():
    lignes = [_ligne("8.1.0.1", "scanners", asn=212238, asn_org="Loueur")]
    r = _calc(lignes, classer=_classer("inconnu"), classe_asn=lambda asn: "proxy_loue" if asn == 212238 else "inconnu")
    assert _pop(r, "famille:balayage_web")["classes"] == {"proxy_loue": 100}


def test_memoire_bornee(monkeypatch):
    monkeypatch.setattr(P, "MAX_ADRESSES", 5)
    r = _calc([_ligne(f"8.{i}.0.1", "scanners") for i in range(10)])
    assert r["complet"] is False
    assert _pop(r, "famille:balayage_web")["adresses"] == 5


def test_etat_inactive_et_bannie():
    r = _calc([_ligne("8.1.0.1", "scanners", il_y_a_s=2 * JOUR),
               _ligne("8.2.0.1", "aspirateur_ua", action="banned")])
    assert _pop(r, "famille:balayage_web")["etat"] == "inactive"
    c = _pop(r, "famille:collecte")
    assert c["etat"] == "bannie" and c["bans"] == 1


def test_campagne_actord_rapprochee():
    lignes = [_ligne(f"8.{i}.0.1", "aspirateur_ua") for i in range(3)]
    actord = [{"signature": "sig-autre", "famille": "balayage_web", "cibles_noms": ["forge.exemple.test"]},
              {"signature": "sig-bonne", "famille": "collecte", "cibles_noms": ["x.test", "forge.exemple.test"]}]
    assert _pop(_calc(lignes, campagnes_actord=actord), "famille:collecte")["campagne_actord"] == "sig-bonne"
    assert _pop(_calc(lignes), "famille:collecte")["campagne_actord"] is None
    assert _pop(_calc(lignes, campagnes_actord=None), "famille:collecte")["campagne_actord"] is None


# ── sources : journaux tournés, catalogue, actord ───────────────────────────────────────────────────────────────

def test_lignes_du_journal_tournes_et_gzip(tmp_path):
    (tmp_path / "waf-threats.log").write_text("c1\nc2\n")
    (tmp_path / "waf-threats.log.1").write_text("b1\n")
    with gzip.open(tmp_path / "waf-threats.log.2.gz", "wt") as f:
        f.write("a1\na2\n")
    (tmp_path / "waf-threats.log.3.gz").write_bytes(b"\x1f\x8b pas du gzip")   # corrompu : ignoré
    (tmp_path / "autre.log").write_text("zz\n")
    assert [x.strip() for x in P.lignes_du_journal(str(tmp_path))] == ["a1", "a2", "b1", "c1", "c2"]


def test_lignes_du_journal_ignore_les_vieux_fichiers(tmp_path):
    vieux = tmp_path / "waf-threats.log.5"
    vieux.write_text("vieux\n")
    t = MAINTENANT - 30 * JOUR
    os.utime(vieux, (t, t))
    (tmp_path / "waf-threats.log").write_text("neuf\n")
    assert [x.strip() for x in P.lignes_du_journal(str(tmp_path), maintenant=MAINTENANT)] == ["neuf"]


def test_catalogue_operateur_gagne(tmp_path):
    livre = tmp_path / "livre.toml"
    livre.write_text("[classes]\nproxy_loue = [212238, 64500]\nhebergeur = [64501]\n")
    oper = tmp_path / "oper.toml"
    oper.write_text("[classes]\nacces = [64500]\n")
    faux = tmp_path / "faux.toml"
    faux.write_text("[classes]\nfournisseur_imaginaire = [64502]\n")
    cat = P.charger_catalogue([str(livre), str(tmp_path / "absent.toml"), str(faux), str(oper)])
    assert cat == {212238: "proxy_loue", 64500: "acces", 64501: "hebergeur"}


def test_annuaire_sans_base_rend_inconnu(tmp_path):
    a = P.Annuaire(str(tmp_path / "absent.mmdb"), str(tmp_path / "absent-pays.mmdb"), [])
    assert a.classer("8.8.8.8") == (0, "", "inconnu")
    assert a.pays("8.8.8.8") == ""
    a.fermer()


def test_annuaire_classe_par_catalogue_jamais_par_le_nom():
    class Base:
        def get(self, ip):
            return {"autonomous_system_number": 64500, "autonomous_system_organization": "Exemple Proxy Hosting ISP"}

    a = P.Annuaire(None, None, [])
    a._asn = Base()
    assert a.classer("8.8.8.8") == (64500, "Exemple Proxy Hosting ISP", "inconnu")
    a._classes = {64500: "hebergeur"}
    assert a.classer("8.8.8.8") == (64500, "Exemple Proxy Hosting ISP", "hebergeur")
    assert a.classer("192.168.1.1") == (0, "", "inconnu")


def test_lire_campagnes_actord_absent(tmp_path):
    assert P.lire_campagnes_actord(str(tmp_path / "absent.sock")) is None


def test_lire_campagnes_actord_vue_complete(tmp_path):
    chemin = str(tmp_path / "actor.sock")
    entetes = []

    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            entetes.append((self.path, self.headers.get("X-Sbx-Vue")))
            corps = json.dumps([{"signature": "s1", "famille": "collecte", "cibles_noms": ["a.test"]}]).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(corps)))
            self.end_headers()
            self.wfile.write(corps)

        def log_message(self, *a):
            pass

    class Serveur(socketserver.UnixStreamServer):
        def get_request(self):
            req, _ = super().get_request()
            return req, ("local", 0)

    srv = Serveur(chemin, H)
    th = threading.Thread(target=srv.serve_forever, daemon=True)
    th.start()
    try:
        assert P.lire_campagnes_actord(chemin) == [{"signature": "s1", "famille": "collecte", "cibles_noms": ["a.test"]}]
    finally:
        srv.shutdown()
        srv.server_close()
    assert entetes == [("/campaigns", "complete")]


# ── cache en double tampon ──────────────────────────────────────────────────────────────────────────────────────

def test_double_tampon(tmp_path):
    cache = tmp_path / "populations.json"
    complet = {"genere_le": int(MAINTENANT), "complet": True, "populations": [{"id": "famille:collecte"}]}
    assert P.ecrire_cache(str(cache), complet) is True
    assert stat.S_IMODE(cache.stat().st_mode) == 0o640       # lisible par le groupe (ACL datascope, tâche 12)
    partiel = {"genere_le": int(MAINTENANT) + 600, "complet": False, "populations": []}
    assert P.ecrire_cache(str(cache), partiel) is False
    assert P.lire_cache(str(cache))["complet"] is True
    tardif = {"genere_le": int(MAINTENANT) + 7200, "complet": False, "populations": []}
    assert P.ecrire_cache(str(cache), tardif) is True
    assert P.lire_cache(str(cache))["complet"] is False
    assert [x.name for x in tmp_path.iterdir()] == ["populations.json"]     # aucun fichier temporaire laissé


def test_lire_cache_illisible(tmp_path):
    assert P.lire_cache(str(tmp_path / "absent.json")) is None
    (tmp_path / "x.json").write_text("{tronqué")
    assert P.lire_cache(str(tmp_path / "x.json")) is None
    (tmp_path / "y.json").write_text('{"genere_le": 1}')
    assert P.lire_cache(str(tmp_path / "y.json")) is None


# ── route ────────────────────────────────────────────────────────────────────────────────────────────────────────

def _importer_waf():
    """api.main exige geoip2 (absent de l'environnement de test) : un faux module suffit."""
    try:
        import geoip2  # noqa: F401
    except ImportError:
        g = types.ModuleType("geoip2")
        g.database, g.errors = types.ModuleType("geoip2.database"), types.ModuleType("geoip2.errors")
        g.errors.AddressNotFoundError = type("AddressNotFoundError", (Exception,), {})
        sys.modules.update({"geoip2": g, "geoip2.database": g.database, "geoip2.errors": g.errors})
    from api import main as waf
    return waf


@pytest.fixture
def waf(monkeypatch, tmp_path):
    w = _importer_waf()
    monkeypatch.setattr(w, "POPULATIONS_CACHE", tmp_path / "populations.json")
    monkeypatch.setattr(w, "_maintenant", lambda: MAINTENANT)
    w.app.dependency_overrides.clear()
    w.app.dependency_overrides[w.require_lecture_ai] = lambda: {"sub": "lecteur"}
    yield w
    w.app.dependency_overrides.clear()


def test_route_sans_cache(waf):
    from fastapi.testclient import TestClient
    rep = TestClient(waf.app).get("/populations")
    assert rep.status_code == 200 and rep.json() == {"disponible": False}
    route = next(r for r in waf.app.routes if getattr(r, "path", "") == "/populations")
    assert any(dep.call is waf.require_lecture_ai for dep in route.dependant.dependencies)


def test_route_lit_le_cache_sans_recalcul(waf, monkeypatch, tmp_path):
    from fastapi.testclient import TestClient
    releve = {"genere_le": int(MAINTENANT) - 120, "complet": True, "fenetre_jours": 7,
              "populations": [{"id": "famille:collecte"}], "recouvrement": {"adresses_communes": 0, "adresses_total": 1}}
    (tmp_path / "populations.json").write_text(json.dumps(releve))
    monkeypatch.setattr(waf._populations, "calculer", lambda *a, **k: pytest.fail("recalcul à la requête"))
    j = TestClient(waf.app).get("/populations").json()
    assert j["disponible"] is True and j["age_s"] == 120 and j["populations"] == [{"id": "famille:collecte"}]


def test_rafraichir_ecrit_le_cache(waf, monkeypatch, tmp_path):
    journaux = tmp_path / "journaux"
    journaux.mkdir()
    (journaux / "waf-threats.log").write_text("\n".join(
        _ligne(f"8.{i}.0.1", "aspirateur_ua", il_y_a_s=60) for i in range(3)) + "\n")
    monkeypatch.setattr(waf, "THREATS_LOG", str(journaux / "waf-threats.log"))
    monkeypatch.setattr(waf, "CAMPAIGNS_FILE", str(tmp_path / "absent-campaigns.json"))
    monkeypatch.setattr(waf._populations, "AUTHWATCH_CAMPAGNES", str(tmp_path / "absent-authwatch.json"))
    monkeypatch.setattr(waf._populations, "ROTATION_ETAT", str(tmp_path / "absent-rotation.json"))
    monkeypatch.setattr(waf._populations, "ACTORD_SOCK", str(tmp_path / "absent.sock"))
    monkeypatch.setattr(waf._populations, "BASE_ASN", str(tmp_path / "absent.mmdb"))
    monkeypatch.setattr(waf._populations, "BASE_PAYS", str(tmp_path / "absent-pays.mmdb"))
    waf._rafraichir_populations(MAINTENANT)
    r = json.loads((tmp_path / "populations.json").read_text())
    p = next(x for x in r["populations"] if x["id"] == "famille:collecte")
    assert p["adresses"] == 3 and p["campagne_actord"] is None and r["complet"] is True
