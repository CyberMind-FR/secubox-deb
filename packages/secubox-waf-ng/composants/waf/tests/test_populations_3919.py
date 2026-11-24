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
        ("auth_smtp:leurre", "messagerie"),
        ("auth_imap:leurre_pop3", "messagerie"),
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


def test_leurres_de_messagerie_audit_hors_populations():
    """#3924 : un compte réel (téléphone du propriétaire) ou le mode observer ne fait pas un attaquant ; un ban, si."""
    cats = ("auth_smtp:leurre", "auth_imap:leurre", "auth_imap:leurre_pop3")
    lignes = [_ligne(f"8.{i}.0.1", c, host="smtp", path="gk2…", tool="authwatch", severity="audit")
              for i, c in enumerate(cats)]
    assert _calc(lignes)["populations"] == []
    lignes += [_ligne(f"9.{i}.0.1", c, host="smtp", path="…", tool="authwatch", action="banned") for i, c in enumerate(cats)]
    lignes += [_ligne("9.9.0.1", "auth_smtp:sasl_failed", host="smtp", path="x", severity="audit")]   # hors leurres : compte
    assert _pop(_calc(lignes), "famille:messagerie")["adresses"] == 4


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


# Accès de DataScope au cache : reporté à #3921 ; ecrire_cache écrit en 0640 (vérifié par test_double_tampon).


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
    i = _pop(r, "famille:balayage_web")
    assert i["etat"] == "inactive" and i["actives_24h"] == 0 and i["bannies_24h"] == 0
    c = _pop(r, "famille:collecte")
    assert c["etat"] == "bannie" and c["bans"] == 1 and c["actives_24h"] == 1 and c["bannies_24h"] == 1


@pytest.mark.parametrize("bannies,etat", [(0, "observee"), (1, "observee"), (4, "observee"), (5, "bannie"), (10, "bannie")])
def test_bannie_exige_la_moitie_des_adresses_actives(bannies, etat):
    """Un seul ban sur mille adresses ne fait pas une population « bannie » (revue I3)."""
    lignes = [_ligne(f"8.{i}.0.1", "scanners", action="banned" if i < bannies else "detect") for i in range(10)]
    # adresses muettes depuis plus de 24 h, toutes bannies alors : hors du compte
    lignes += [_ligne(f"9.{i}.0.1", "scanners", il_y_a_s=2 * JOUR, action="banned") for i in range(50)]
    p = _pop(_calc(lignes), "famille:balayage_web")
    assert p["actives_24h"] == 10 and p["bannies_24h"] == bannies and p["etat"] == etat
    assert p["bans"] == bannies + 50 and p["adresses"] == 60


def test_ban_ancien_d_une_adresse_encore_active_ne_compte_pas():
    lignes = [_ligne("8.1.0.1", "scanners", il_y_a_s=3 * JOUR, action="banned"), _ligne("8.1.0.1", "scanners")]
    p = _pop(_calc(lignes), "famille:balayage_web")
    assert p["actives_24h"] == 1 and p["bannies_24h"] == 0 and p["bans"] == 1 and p["etat"] == "observee"


@pytest.mark.parametrize("meme,attendu", [(30, True), (29, False)])
def test_rotation_de_famille_exige_un_pivot(meme, attendu):
    """60 adresses à une tentative : rotation si la première cible reçoit la moitié des événements au moins, sinon non."""
    lignes = [_ligne(f"8.{i}.0.1", "scanners", host="pivot.exemple.test" if i < meme else f"h{i}.exemple.test") for i in range(60)]
    p = _pop(_calc(lignes), "famille:balayage_web")
    assert p["adresses"] == 60 and p["le3"] == 100 and p["rotation"] is attendu


def test_rotation_du_profileur_inchangee():
    ips = [f"8.{i}.0.1" for i in range(60)]
    lignes = [_ligne(ip, "scanners", host=f"h{i}.exemple.test") for i, ip in enumerate(ips)]
    r = _calc(lignes, campagnes_profileur=[{"signature": "00aa11bb22cc33dd", "attaquants": ips}])
    assert _pop(r, "profileur:00aa11bb22cc33dd")["rotation"] is True


@pytest.mark.parametrize("hote", ["203.0.113.9", "203.0.113.9:443", "[2001:db8::1]", "[2001:db8::1]:443", "2001:db8::1",
                                  "203.0.113.9.", "010.1.2.3", "3405803785", "0xcb007109", "exemple.0x7f"])
def test_jamais_un_hote_adresse(hote):
    assert P._hote(hote) is None
    etat = [{"signature": "0123abcd" + "e" * 56, "hote": hote, "sources": 70, "dernier": int(MAINTENANT) - 30}]
    r = _calc([_ligne("8.1.0.1", "scanners", host=hote)], rotation=etat)
    assert all(p["cibles"] == [] and p["nom_cible"] == "" for p in r["populations"]) and len(r["populations"]) == 2


def test_ports_balayes_pas_un_hote():
    assert P._hote("ports:2") is None and P._hote("ports.exemple.test") == "ports.exemple.test"


def test_hotes_ordinaires_gardes():
    for h in ("forge.exemple.test", "git2", "a1.exemple.test", "smtp"):
        assert P._hote(h) == h
    assert P._hote("Forge.exemple.test:443") == "forge.exemple.test"


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
    # le plus récent d'abord : au plafond d'adresses, ce sont les plus anciennes qui manquent
    assert [x.strip() for x in P.lignes_du_journal(str(tmp_path))] == ["c1", "c2", "b1", "a1", "a2"]


def test_plafond_garde_les_adresses_du_jour(monkeypatch, tmp_path):
    monkeypatch.setattr(P, "MAX_ADRESSES", 3)
    (tmp_path / "waf-threats.log").write_text("\n".join(_ligne(f"8.{i}.0.1", "scanners") for i in range(2)) + "\n")
    (tmp_path / "waf-threats.log.1").write_text(
        "\n".join(_ligne(f"9.{i}.0.1", "scanners", il_y_a_s=2 * JOUR) for i in range(5)) + "\n")
    r = _calc(P.lignes_du_journal(str(tmp_path), maintenant=MAINTENANT))
    p = _pop(r, "famille:balayage_web")
    assert r["complet"] is False and p["adresses"] == 3 and p["actives_24h"] == 2


# ── lot 1b : coût du relevé (agrégats gardés, lignes écartées sans décodage, pas de double compte) ─────────────────

def _journaux(tmp_path, courant=3, tourne=4):
    d = tmp_path / "journaux"
    d.mkdir()
    (d / "waf-threats.log").write_text("\n".join(_ligne(f"8.{i}.0.1", "scanners") for i in range(courant)) + "\n")
    (d / "waf-threats.log.1").write_text("\n".join(
        _ligne(f"9.{i}.0.1", "aspirateur_ua", il_y_a_s=JOUR + 60, action="banned") for i in range(tourne)) + "\n")
    with gzip.open(d / "waf-threats.log.2.gz", "wt") as f:
        f.write("\n".join(_ligne(f"9.{i}.0.1", "auth_smtp:sasl_failed", il_y_a_s=2 * JOUR, host="smtp", path="gerald")
                          for i in range(tourne)) + "\n"
                + _ligne("9.1.0.1", "ia_filtres_haute", il_y_a_s=2 * JOUR, rule_id="CVE-2026-0007") + "\n")
    for n in ("waf-threats.log", "waf-threats.log.1", "waf-threats.log.2.gz"):
        os.utime(d / n, (MAINTENANT, MAINTENANT))
    return d


def _assemble(d, reserve, **kw):
    args = dict(maintenant=MAINTENANT, pays=lambda ip: "", classer=_classer(), campagnes_smtp=[],
                campagnes_profileur=[], rotation=[])
    args.update(kw)
    return P.assembler(P.agregats_du_journal(str(d), reserve and str(reserve), MAINTENANT), **args)


def test_agregats_gardes_meme_releve_et_journaux_tournes_non_relus(tmp_path, monkeypatch):
    d, reserve = _journaux(tmp_path), tmp_path / "agregats"
    sans = _assemble(d, None)
    premier = _assemble(d, reserve)
    lus = []
    vrai = P.agreger
    monkeypatch.setattr(P, "agreger", lambda lignes, m: (lus.append(1), vrai(lignes, m))[1])
    second = _assemble(d, reserve)
    assert sans == premier == second
    assert len(lus) == 1                                  # le journal courant seulement
    assert _pop(second, "famille:messagerie")["cibles"] == ["ger…"] and "gerald" not in json.dumps(second)
    assert _pop(second, "famille:collecte")["cves"] == ["CVE-2026-0007"]
    # les autres sources s'appliquent aux agrégats gardés : profileur apparu depuis
    prof = [{"signature": "00aa11bb22cc33dd", "attaquants": [f"9.{i}.0.1" for i in range(12)]}]
    assert _pop(_assemble(d, reserve, campagnes_profileur=prof), "profileur:00aa11bb22cc33dd")["adresses"] == 4
    fichiers = sorted(reserve.iterdir())
    assert len(fichiers) == 2 and all(stat.S_IMODE(f.stat().st_mode) == 0o640 for f in fichiers)
    assert stat.S_IMODE(reserve.stat().st_mode) in (0o2770, 0o770)
    assert all("gerald" not in f.read_text() for f in fichiers)      # jamais un compte en clair, même en réserve


def test_reserve_au_groupe_secubox_waf(tmp_path, monkeypatch):
    """Dossier 2770 et fichiers 0640 au groupe secubox-waf : lisibles après le chown de l'unité du WAF."""
    gid = os.getgid()
    monkeypatch.setattr(P, "_gid_waf", lambda: gid)
    d, reserve = _journaux(tmp_path), tmp_path / "agregats"
    reserve.mkdir(0o700)                                      # dossier d'une version antérieure : remis en ordre
    _assemble(d, reserve)
    assert stat.S_IMODE(reserve.stat().st_mode) == 0o2770 and reserve.stat().st_gid == gid
    for f in reserve.iterdir():
        assert stat.S_IMODE(f.stat().st_mode) == 0o640 and f.stat().st_gid == gid


@pytest.mark.parametrize("gid", [None, 0])
def test_reserve_sans_le_groupe_continue(tmp_path, monkeypatch, gid):
    """Groupe absent, ou qu'on ne peut pas donner : la réserve sert quand même."""
    monkeypatch.setattr(P, "_gid_waf", lambda: gid)
    d, reserve = _journaux(tmp_path), tmp_path / "agregats"
    ref = _assemble(d, None)
    assert _assemble(d, reserve) == ref and len(list(reserve.iterdir())) == 2


def test_temporaires_abandonnes_effaces(tmp_path):
    d, reserve = _journaux(tmp_path), tmp_path / "agregats"
    reserve.mkdir()
    vieux, neuf = reserve / ".tmp-vieux", reserve / ".tmp-neuf"
    for f, age in ((vieux, 7200), (neuf, 60)):
        f.write_text("x")
        os.utime(f, (MAINTENANT - age, MAINTENANT - age))
    _assemble(d, reserve)
    assert not vieux.exists() and neuf.exists()


def _corrompre(d, cle, valeur):
    d[cle] = valeur
    return d


@pytest.mark.parametrize("abime", [
    lambda d: _corrompre(d, "ips", ["9.0.0.1", 3] * 9), lambda d: _corrompre(d, "ips", ["x" * 500] * 9),
    lambda d: _corrompre(d, "cles", ["famille inventée"] * 9), lambda d: _corrompre(d, "cibles", ["203.0.113.9"] * 9),
    lambda d: _corrompre(d, "cibles", ["<script>"] * 9), lambda d: _corrompre(d, "t", ["1"] * 8),
    lambda d: _corrompre(d, "t", [1.5] * 8), lambda d: _corrompre(d, "t", [-1] * 8), lambda d: _corrompre(d, "t", [True] * 8),
    lambda d: _corrompre(d, "t", [10 ** 30] * 8), lambda d: _corrompre(d, "t", {"a": 1}),
    lambda d: _corrompre(d, "reseaux", [[0, "64500", 0, "acces"]]), lambda d: _corrompre(d, "reseaux", [[0, 64500, 0, "inventee"]]),
    lambda d: _corrompre(d, "cves", {"9.0.0.1": {"<b>": 1}}), lambda d: _corrompre(d, "cves", []), lambda d: _corrompre(d, "complet", 1)])
def test_agregat_de_types_faux_recalcule(tmp_path, abime):
    d, reserve = _journaux(tmp_path), tmp_path / "agregats"
    ref = _assemble(d, reserve)
    for f in reserve.iterdir():
        f.write_text(json.dumps(abime(json.loads(f.read_text()))))
    assert _assemble(d, reserve) == ref


def test_agregat_trop_gros_profond_ou_lien_recalcule(tmp_path, monkeypatch):
    d, reserve = _journaux(tmp_path), tmp_path / "agregats"
    ref = _assemble(d, reserve)
    fichiers = list(reserve.iterdir())
    fichiers[0].write_text("[" * 200_000)                      # RecursionError, pas une ValueError
    fichiers[1].unlink()
    (tmp_path / "ailleurs.json").write_text("{}")
    fichiers[1].symlink_to(tmp_path / "ailleurs.json")
    assert _assemble(d, reserve) == ref
    monkeypatch.setattr(P, "MAX_AGREGAT_OCTETS", 10)
    assert _assemble(d, reserve) == ref


def test_memo_adresses_de_types_faux_recherche_de_nouveau(tmp_path, monkeypatch):
    class A:
        def signature(self): return [1]
        def classer(self, ip): return (64500, "Org", "inconnu")
        def classe_asn(self, asn): return "hebergeur"
        def pays(self, ip): return "FR"
    (tmp_path / "adresses.json").write_text(json.dumps({"signature": [1], "adresses": {
        "a": [True, "x", "FR"], "b": [1, 7, "FR"], "c": [1, "x", "<b>"], "d": "x", "e": [-4, "x", "FR"]}}))
    m = P.MemoAdresses(A(), str(tmp_path))
    for ip in "abcde":
        assert m.classer(ip) == (64500, "Org", "hebergeur") and m.pays(ip) == "FR", ip


def test_agregat_recalcule_si_le_journal_change_et_perime_efface(tmp_path):
    d, reserve = _journaux(tmp_path), tmp_path / "agregats"
    _assemble(d, reserve)
    avant = {f.name for f in reserve.iterdir()}
    (reserve / "etranger.txt").write_text("gardé")
    with open(d / "waf-threats.log.1", "a") as f:
        f.write(_ligne("9.200.0.1", "aspirateur_ua", il_y_a_s=JOUR) + "\n")
    os.utime(d / "waf-threats.log.1", (MAINTENANT + 1, MAINTENANT + 1))
    assert _pop(_assemble(d, reserve), "famille:collecte")["adresses"] == 5
    apres = {f.name for f in reserve.iterdir()} - {"etranger.txt"}
    assert len(apres) == 2 and len(avant & apres) == 1 and (reserve / "etranger.txt").exists()


@pytest.mark.parametrize("contenu", ["", "{tronqué", "[]", '{"v": 1}', '{"v": 999, "t": []}',
                                     '{"v":1,"complet":true,"ips":[],"cles":[],"cibles":[],"orgs":[],"reseaux":[],"cves":{},"t":[1,9,9,9,1,1,1,0]}'])
def test_agregat_illisible_recalcule(tmp_path, contenu):
    d, reserve = _journaux(tmp_path), tmp_path / "agregats"
    ref = _assemble(d, reserve)
    for f in reserve.iterdir():
        f.write_text(contenu)
    assert _assemble(d, reserve) == ref


def test_reserve_impossible_meme_releve(tmp_path):
    d = _journaux(tmp_path)
    (tmp_path / "fichier").write_text("x")
    ref = _assemble(d, None)
    assert _assemble(d, tmp_path / "fichier") == ref
    assert _assemble(d, tmp_path / "absent" / "sous") == ref
    (tmp_path / "lien").symlink_to(tmp_path)
    assert _assemble(d, tmp_path / "lien") == ref


def test_rotation_pendant_la_passe_jamais_deux_fois_le_meme_fichier(tmp_path):
    d = _journaux(tmp_path)
    (d / "waf-threats.log.1").unlink()
    os.link(d / "waf-threats.log", d / "waf-threats.log.1")          # le courant vu sous ses deux noms
    assert _pop(_assemble(d, None), "famille:balayage_web")["serie"][-1] == 3


def test_rotation_pendant_l_ouverture_rien_de_perdu(tmp_path, monkeypatch):
    """`log` devient `log.1` entre l'ouverture des deux : on recommence, l'ancien `.1` n'est pas oublié."""
    d = _journaux(tmp_path)
    (d / "waf-threats.log.2.gz").unlink()
    vrai, fait = open, []

    def ouvrir(chemin, *a, **k):
        f = vrai(chemin, *a, **k)
        if str(chemin).endswith("waf-threats.log") and not fait:
            fait.append(1)
            os.rename(d / "waf-threats.log.1", d / "waf-threats.log.2")
            os.rename(d / "waf-threats.log", d / "waf-threats.log.1")
            (d / "waf-threats.log").write_text("")
        return f

    monkeypatch.setattr("builtins.open", ouvrir)
    r = _assemble(d, None)
    assert fait and _pop(r, "famille:balayage_web")["adresses"] == 3 and _pop(r, "famille:collecte")["adresses"] == 4
    assert sum(_pop(r, "famille:balayage_web")["serie"]) == 3


def test_compression_en_cours_le_gz_partiel_est_ignore(tmp_path):
    d = _journaux(tmp_path)
    (d / "waf-threats.log.2").write_bytes(gzip.decompress((d / "waf-threats.log.2.gz").read_bytes()))
    assert sum(_pop(_assemble(d, None), "famille:messagerie")["serie"]) == 4


def test_ligne_hors_sujet_jamais_decodee(monkeypatch):
    decodees = []
    vrai = json.loads
    monkeypatch.setattr(P.json, "loads", lambda s: (decodees.append(s), vrai(s))[1])
    compact = json.dumps(json.loads(_ligne("8.1.0.1", "xss")), separators=(",", ":"))
    decodees.clear()
    r = _calc([_ligne("8.1.0.1", "sqli"), compact, _ligne("8.2.0.1", "scanners")])
    assert len(decodees) == 1 and _pop(r, "famille:balayage_web")["adresses"] == 1


def test_categorie_dans_un_champ_hostile_ne_trompe_pas_le_tri():
    """Un chemin qui contient `"category":"sqli"` (guillemets échappés par JSON) ne fait pas écarter la ligne."""
    for sep in ((",", ":"), (", ", ": ")):
        for piege in ('","category":"sqli","x":"', '{"category": "xss"}'):
            ligne = json.dumps(json.loads(_ligne("8.1.0.1", "scanners", host=piege, path=piege)), separators=sep)
            assert _pop(_calc([ligne]), "famille:balayage_web")["adresses"] == 1
    # et une catégorie échappée en unicode reste lue
    assert _calc([_ligne("8.1.0.1", "scanners").replace('"scanners"', '"\\u0073canners"')])["populations"][0]["adresses"] == 1


def test_classe_du_catalogue_courant_sur_l_historique():
    """Une ligne écrite « inconnu » avant l'ajout de son ASN au catalogue prend la classe d'aujourd'hui."""
    lignes = [_ligne("8.1.0.1", "scanners", asn=22773, asn_org="Cox", reseau_classe="inconnu")]
    r = _calc(lignes, classe_asn=lambda asn: "acces" if asn == 22773 else "inconnu")
    assert _pop(r, "famille:balayage_web")["classes"] == {"acces": 100}


def test_adresses_cherchees_une_seule_fois_entre_les_passes(tmp_path, monkeypatch):
    recherches = []

    class Base:
        def __init__(self, chemin):
            self.chemin = chemin

        def get(self, ip):
            recherches.append(ip)
            if "ASN" in self.chemin:
                return {"autonomous_system_number": 64500, "autonomous_system_organization": "Exemple"}
            return {"country": {"iso_code": "FR"}}

        def close(self):
            pass

    asn, pays, cat = tmp_path / "ASN.mmdb", tmp_path / "Country.mmdb", tmp_path / "cat.toml"
    asn.write_text("a")
    pays.write_text("p")
    cat.write_text("[classes]\nhebergeur = [64500]\n")
    d = _journaux(tmp_path)
    _sources_absentes(monkeypatch, tmp_path)
    monkeypatch.setattr(P, "_maxminddb", types.SimpleNamespace(open_database=Base))
    monkeypatch.setattr(P, "BASES_ASN", (str(asn),))
    monkeypatch.setattr(P, "BASES_PAYS", (str(pays),))
    monkeypatch.setattr(P, "CATALOGUES", (str(cat),))
    sortie = tmp_path / "sortie"
    sortie.mkdir()

    def passe():
        recherches.clear()
        assert P.rafraichir(str(d), str(sortie / "p.json"), str(tmp_path / "absent.json"), MAINTENANT)
        r = P.lire_cache(str(sortie / "p.json"))
        assert r["complet"] is True and _pop(r, "famille:collecte")["pays_top"] == [["FR", 100]]
        return _pop(r, "famille:collecte")["classes"], len(recherches)

    assert passe() == ({"hebergeur": 100}, 2 * 7)          # 7 adresses, une recherche par base
    assert passe() == ({"hebergeur": 100}, 0)
    cat.write_text("[classes]\nacces = [64500]\n")        # catalogue changé : appliqué sans rien rechercher
    assert passe() == ({"acces": 100}, 0)
    pays.write_text("base renouvelée")                     # base changée : tout est recherché de nouveau
    assert passe()[1] == 2 * 7


def test_cibles_bornees_par_journal(monkeypatch):
    monkeypatch.setattr(P, "MAX_CIBLES_JOURNAL", 5)
    a = P.agreger([_ligne("8.1.0.1", "scanners", host=f"h{i}.exemple.test") for i in range(50)], MAINTENANT)
    assert len(a.tentatives) <= 6 and sum(v[0] for v in a.tentatives.values()) == 50


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


def _sources_absentes(monkeypatch, tmp_path):
    monkeypatch.setattr(P, "AUTHWATCH_CAMPAGNES", str(tmp_path / "absent-authwatch.json"))
    monkeypatch.setattr(P, "ROTATION_ETAT", str(tmp_path / "absent-rotation.json"))
    monkeypatch.setattr(P, "ACTORD_SOCK", str(tmp_path / "absent.sock"))
    monkeypatch.setattr(P, "BASES_ASN", (str(tmp_path / "absent.mmdb"),))
    monkeypatch.setattr(P, "BASES_PAYS", (str(tmp_path / "absent-pays.mmdb"),))


def test_cli_ecrit_le_cache(monkeypatch, tmp_path, capsys):
    import time
    journaux = tmp_path / "journaux"
    journaux.mkdir()
    (journaux / "waf-threats.log").write_text("\n".join(
        _ligne(f"8.{i}.0.1", "aspirateur_ua", il_y_a_s=MAINTENANT - time.time() + 60) for i in range(3)) + "\n")
    _sources_absentes(monkeypatch, tmp_path)
    cache = tmp_path / "populations.json"
    rc = P.main(["--ecrire", str(cache), "--journal", str(journaux), "--campagnes", str(tmp_path / "absent.json")])
    assert rc == 0
    r = P.lire_cache(str(cache))
    p = next(x for x in r["populations"] if x["id"] == "famille:collecte")
    assert p["adresses"] == 3 and p["campagne_actord"] is None and r["complet"] is True
    assert isinstance(r["duree_s"], float) and r["duree_s"] >= 0
    assert set(r["manques"]) == {"base_asn", "base_pays"}
    assert json.loads(capsys.readouterr().out.strip())["ecrit"] is True


def test_cli_en_processus_separe(tmp_path):
    """Le vrai point d'entrée `python3 -m api.populations`, lancé depuis le dossier qui contient le paquet `api`."""
    import subprocess
    journaux = tmp_path / "journaux"
    journaux.mkdir()
    (journaux / "waf-threats.log").write_text("{tronqué\n")
    cache = tmp_path / "populations.json"
    r = subprocess.run([sys.executable, "-m", "api.populations", "--ecrire", str(cache), "--journal", str(journaux),
                        "--campagnes", str(tmp_path / "absent.json")],
                       cwd=str(Path(__file__).resolve().parent.parent), capture_output=True, timeout=60)
    assert r.returncode == 0, r.stderr
    assert P.lire_cache(str(cache))["populations"] == []


def test_lanceur_nice_et_processus(waf, monkeypatch):
    import asyncio
    appels = []

    class Proc:
        returncode = 0

        async def communicate(self):
            return b"", b""

    async def faux_exec(*argv, **kw):
        appels.append((argv, kw))
        return Proc()

    monkeypatch.setattr(asyncio, "create_subprocess_exec", faux_exec)
    assert asyncio.run(waf._lancer_populations()) == 0
    argv, kw = appels[0]
    assert list(argv) == ["nice", "-n", "10", "ionice", "-c", "2", "-n", "7", sys.executable, "-m", "api.populations", "--ecrire",
                          str(waf.POPULATIONS_CACHE)]
    assert kw["cwd"] == str(Path(waf.__file__).resolve().parent.parent)
    assert (Path(kw["cwd"]) / "api" / "populations.py").is_file()
    assert waf.POPULATIONS_PERIODE == 1800 and waf.POPULATIONS_DELAI == 540 < waf.POPULATIONS_PERIODE


def test_lanceur_jamais_deux_a_la_fois(waf, monkeypatch):
    import asyncio
    lances = []

    async def lent():
        lances.append(1)
        await asyncio.sleep(0.05)
        return 0

    monkeypatch.setattr(waf, "_lancer_populations", lent)
    monkeypatch.setattr(waf, "_populations_tache", None)

    async def scenario():
        assert waf._demarrer_populations() is True
        assert waf._demarrer_populations() is False        # passe en cours : pas de seconde
        await waf._populations_tache
        assert waf._demarrer_populations() is True
        await waf._populations_tache

    asyncio.run(scenario())
    assert lances == [1, 1]


def test_lanceur_arrete_attend_la_fin_du_processus(waf, monkeypatch):
    """À l'arrêt de l'API, le processus est tué ET attendu : jamais deux passes à la fois après un redémarrage."""
    import asyncio
    suite = []

    class Proc:
        returncode = None

        async def communicate(self):
            await asyncio.sleep(10)

        def kill(self):
            suite.append("tué")

        async def wait(self):
            suite.append("attendu")
            return -9

    async def faux_exec(*argv, **kw):
        return Proc()

    monkeypatch.setattr(asyncio, "create_subprocess_exec", faux_exec)

    async def scenario():
        t = asyncio.create_task(waf._lancer_populations())
        await asyncio.sleep(0.02)
        t.cancel()
        with pytest.raises(asyncio.CancelledError):
            await t

    asyncio.run(scenario())
    assert suite == ["tué", "attendu"]


def test_lanceur_tue_au_dela_du_delai(waf, monkeypatch):
    import asyncio
    tue = []

    class Proc:
        returncode = None

        async def communicate(self):
            await asyncio.sleep(10)

        def kill(self):
            tue.append(1)

        async def wait(self):
            return -9

    async def faux_exec(*argv, **kw):
        return Proc()

    monkeypatch.setattr(asyncio, "create_subprocess_exec", faux_exec)
    monkeypatch.setattr(waf, "POPULATIONS_DELAI", 0.05)
    assert asyncio.run(waf._lancer_populations()) is None
    assert tue == [1]


def test_bases_geoip_ordre_de_repli(monkeypatch, tmp_path):
    essais = []

    class Base:
        def __init__(self, chemin):
            self.chemin = chemin

        def close(self):
            pass

    def ouvrir(chemin):
        essais.append(chemin)
        if chemin.endswith("ouvrable.mmdb"):
            return Base(chemin)
        raise FileNotFoundError(chemin)

    monkeypatch.setattr(P, "_maxminddb", types.SimpleNamespace(open_database=ouvrir))
    assert P.BASES_PAYS == ("/var/lib/secubox/geoip/GeoLite2-Country.mmdb", "/var/lib/GeoIP/GeoLite2-Country.mmdb",
                            "/usr/share/GeoIP/GeoLite2-Country.mmdb")
    assert P.BASES_ASN == ("/var/lib/GeoIP/GeoLite2-ASN.mmdb", "/var/lib/secubox/geoip/GeoLite2-ASN.mmdb",
                           "/usr/share/GeoIP/GeoLite2-ASN.mmdb")
    a = P.Annuaire(["/a/absente.mmdb", "/b/ouvrable.mmdb", "/c/ouvrable.mmdb"], ["/x/absente.mmdb", "/y/absente.mmdb"], [])
    assert a._asn.chemin == "/b/ouvrable.mmdb" and a.disponible and not a.pays_disponible
    assert essais == ["/a/absente.mmdb", "/b/ouvrable.mmdb", "/x/absente.mmdb", "/y/absente.mmdb"]
    # le relevé signale chaque base qu'aucun chemin n'a ouverte
    essais.clear()
    _sources_absentes(monkeypatch, tmp_path)
    monkeypatch.setattr(P, "BASES_ASN", ("/a/absente.mmdb", "/b/ouvrable.mmdb"))
    monkeypatch.setattr(P, "BASES_PAYS", ("/x/absente.mmdb",))
    cache = tmp_path / "p.json"
    assert P.rafraichir(str(tmp_path), str(cache), str(tmp_path / "absent.json"), MAINTENANT) is True
    assert P.lire_cache(str(cache))["manques"] == ["base_pays"]
