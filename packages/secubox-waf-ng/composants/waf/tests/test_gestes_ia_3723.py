# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""#3723 : ban d'adresse d'office, `prolonger`, plafonds par geste, porte du mode SADE.

`wafctl` est simulé (`gestes_ia._executer`, banc de #3716) ; le journal des menaces et le fichier du mode SADE
(`/run/secubox/sade-mode.json`) sont des fichiers du dossier de test. Rien ne touche un pare-feu ni une box.
"""
from __future__ import annotations

import json
import os
import secrets
import subprocess
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from .test_gestes_ia_3716 import _ban_journal, _bloc_peuple, c  # noqa: F401  (fixture `c` réutilisée)

from api import gestes_ia as _g  # noqa: E402  (chemin posé par le module de #3716)

#: Les vraies fonctions, avant que la fixture de #3716 ne les remplace (ni réseau ni DNS dans les autres tests).
_VRAIES = {"_fcrdns": _g._fcrdns, "robot_verifie": _g.robot_verifie, "_lire_threatmesh_peers": _g._lire_threatmesh_peers}

IP = "198.51.100.7"


def _iso(instant: float) -> str:
    return datetime.fromtimestamp(instant, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _rfc3339_local(instant: float) -> str:
    """Comme sbxwaf (`time.Now().Format(time.RFC3339)`) : heure locale avec son décalage, ex. 2026-11-21T11:15:56+01:00."""
    return datetime.fromtimestamp(instant).astimezone().isoformat(timespec="seconds")


class Gk2:
    """Le banc de #3716, plus le journal des menaces et le fichier du mode SADE."""

    def __init__(self, banc, tmp_path):
        object.__setattr__(self, "banc", banc)
        object.__setattr__(self, "tmp", tmp_path)

    def __getattr__(self, nom):
        return getattr(self.banc, nom)

    def __setattr__(self, nom, valeur):          # `g.bans = …` : les bans de `waf_ban` du banc de #3716
        setattr(self.banc, nom, valeur)

    def menace(self, ip, age_s=600, champ="client_ip", horodatage=None):
        """Une ligne au format de sbxwaf (threatlog.go, logEntry) : `timestamp` RFC 3339 local, pas de champ `at`."""
        e = {"timestamp": horodatage or _rfc3339_local(time.time() - age_s), champ: ip, "host": "x.example",
             "method": "GET", "path": "/.env", "category": "scanners", "severity": "medium", "rule_id": "r1",
             "action": "blocked", "user_agent": "curl/8"}
        with open(self.g.JOURNAL_MENACES, "a", encoding="utf-8") as f:
            f.write(json.dumps(e) + "\n")

    def sade(self, mode, age_s=0, liste=(), brut=None):
        p = self.g.FICHIER_SADE
        if brut is not None:
            p.write_text(brut, encoding="utf-8")
            p.chmod(0o644)
            return
        p.write_text(json.dumps({"mode": mode, "depuis": _iso(time.time() - age_s), "liste_blanche": list(liste)}),
                     encoding="utf-8")
        p.chmod(0o644)                              # comme publier_mode : jamais modifiable par le groupe ou les autres

    def prolonger(self, ident, duree_s, conseil="c-2", **extra):
        return self.c.post("/ai/prolonger", json={"geste": "prolonger", "id": ident, "duree_s": duree_s,
                                                  "conseil": conseil, "motif": "", "mode": "auto", **extra})


@pytest.fixture
def gk2_simule(c, tmp_path, monkeypatch):  # noqa: F811
    monkeypatch.setattr(c.g, "JOURNAL_MENACES", tmp_path / "waf-threats.log")
    monkeypatch.setattr(c.g, "FICHIER_SADE", tmp_path / "sade-mode.json")
    return Gk2(c, tmp_path)


def _motif(r):
    return r.json()["detail"]["motif"]


# ── ban d'adresse d'office ─────────────────────────────────────────────
def test_ban_auto_adresse_vue_24h_accepte(gk2_simule):
    g = gk2_simule
    g.menace(IP, age_s=23 * 3600)
    r = g.ban(IP, duree_s=3600, mode="auto")          # la durée du client ne fait pas foi : gk2 la calcule
    assert r.status_code == 200, r.text
    corps = r.json()
    assert corps["duree_s"] == 86400
    assert g.faux.appel("ban")[-3:] == [IP, "86400s", "--exiger-protegees"]   # protegees.env exigé (garde root)
    ligne = g.lignes_journal()[-1]
    assert ligne["geste"] == "ban" and ligne["mode"] == "auto" and ligne["duree_s"] == 86400
    assert ligne["fin"] == ligne["at"] + 86400 == corps["fin"]


def test_ban_auto_adresse_vue_champ_ip_historique(gk2_simule):
    gk2_simule.menace(IP, champ="ip")                  # ancien moteur Python : champ « ip »
    assert gk2_simule.ban(IP, mode="auto").status_code == 200


def test_ban_auto_ligne_au_format_reel_de_sbxwaf(gk2_simule):
    """Ligne écrite telle que sbxwaf l'écrit (threatlog.go) : `timestamp` RFC 3339 à décalage non nul, pas d'`at`."""
    g = gk2_simule
    il_y_a = datetime.now(timezone(timedelta(hours=1))) - timedelta(hours=2)
    ligne = ('{"timestamp":"%s","client_ip":"%s","host":"gk2.example","method":"GET","path":"/wp-login.php",'
             '"category":"scanners","severity":"medium","rule_id":"scan-001","action":"blocked","user_agent":"x"}'
             % (il_y_a.isoformat(timespec="seconds"), IP))
    assert "+01:00" in ligne
    g.g.JOURNAL_MENACES.write_text(ligne + "\n", encoding="utf-8")
    assert g.ban(IP, mode="auto").status_code == 200
    # la même ligne vieille de 25 h, ou sans décalage horaire (illisible), ne vaut pas « vue »
    for ts in ((datetime.now(timezone(timedelta(hours=1))) - timedelta(hours=25)).isoformat(timespec="seconds"),
               datetime.now().strftime("%Y-%m-%dT%H:%M:%S")):
        g.g.JOURNAL_MENACES.write_text(ligne.replace(il_y_a.isoformat(timespec="seconds"), ts) + "\n", "utf-8")
        assert not g.g.vue_recemment(IP, int(time.time()))


def test_champ_at_n_est_pas_un_horodatage_de_menace(gk2_simule):
    """sbxwaf n'écrit pas `at` : une ligne qui n'aurait que lui n'est jamais « vue »."""
    with open(gk2_simule.g.JOURNAL_MENACES, "w", encoding="utf-8") as f:
        f.write(json.dumps({"client_ip": IP, "at": int(time.time())}) + "\n")
    assert not gk2_simule.g.vue_recemment(IP, int(time.time()))


def test_ban_auto_adresse_jamais_vue_refuse(gk2_simule):
    g = gk2_simule
    assert _motif(g.ban(IP, mode="auto")) == "non_vue"           # journal des menaces absent
    g.menace(IP, age_s=25 * 3600)                                  # vue il y a plus de 24 h
    g.menace("198.51.100.70")                                      # une autre adresse au même préfixe texte
    g.menace("198.51.100.77")
    r = g.ban(IP, mode="auto")
    assert r.status_code == 409 and _motif(r) == "non_vue"
    assert "ban" not in g.faux.verbes()
    refus = [x for x in g.audit() if x["action"] == "ai-ban-refus"]
    assert refus and "non_vue" in refus[-1]["detail"]


def test_ban_auto_journal_menaces_lu_par_sa_fin(gk2_simule, monkeypatch):
    g = gk2_simule
    monkeypatch.setattr(g.g, "_TAILLE_LECTURE_MENACES", 4096)
    g.menace(IP)
    for i in range(200):                                           # le passage récent pousse la ligne hors de la fin
        g.menace(f"203.0.113.{i % 250 + 1}")
    assert _motif(g.ban(IP, mode="auto")) == "non_vue"


def test_ban_auto_adresse_protegee_refuse(gk2_simule):
    g = gk2_simule
    g.menace(IP)
    g.sade("active", liste=["10.0.0.0/8", "2a01:db8::/48", "198.51.100.0/28"])
    for mode in ("auto", "clic"):                                  # liste blanche SADE : jamais visée, même en clic
        r = g.ban(IP, mode=mode)
        assert r.status_code == 409 and _motif(r) == "protegee", (mode, r.text)
    assert _motif(g.ban("198.51.100.0/24")) == "protegee"          # un bloc qui la recouvre
    assert g.faux.appels == []
    # pair du maillage, Freebox (protegees.env) : la garde root de wafctl rend son motif
    g.sade("active")
    g.faux.reponses["ban"] = (1, "", "refus:protegee\n")
    r = g.ban(IP, mode="auto")
    assert r.status_code == 409 and _motif(r) == "protegee"
    g.faux.reponses["ban"] = (1, "", "refus:pair\n")
    assert _motif(g.ban(IP, mode="auto")) == "pair"
    assert not [e for e in g.lignes_journal() if e.get("type") == "ban"]


def test_ban_auto_recidive_multiplie_par_4_borne_7j(gk2_simule):
    g = gk2_simule
    now = int(time.time())
    g.menace(IP)
    g.journal(_ban_journal(IP, now - 200000, now - 100000, mode="auto"))
    assert g.ban(IP, mode="auto").json()["duree_s"] == 345600         # 96 h
    ident = g.lignes_journal()[-1]["id"]
    g.journal({"ts": "", "at": now, "type": "annule", "id": ident, "cible": IP, "cause": "couvert"})
    assert g.ban(IP, mode="auto").json()["duree_s"] == 604800         # 24 h × 16 > 7 j : borné
    ident = g.lignes_journal()[-1]["id"]
    g.journal({"ts": "", "at": now, "type": "annule", "id": ident, "cible": IP, "cause": "couvert"})
    assert g.ban(IP, mode="auto").json()["duree_s"] == 604800         # jamais plus
    assert [a[-2] for a in g.faux.appels if "ban" in a] == ["345600s", "604800s", "604800s"]


def test_ban_auto_recidive_ignore_les_bans_retires(gk2_simule):
    g = gk2_simule
    now = int(time.time())
    g.menace(IP)
    retire = _ban_journal(IP, now - 9000, now + 80000, mode="auto")
    g.journal(retire, {"ts": "", "at": now - 100, "type": "annule", "id": retire["id"], "cible": IP, "cause": "unban"},
              _ban_journal("198.51.100.8", now - 200000, now - 100000, mode="auto"))
    assert g.ban(IP, mode="auto").json()["duree_s"] == 86400


def test_ban_auto_adresse_deja_bannie_par_le_waf(gk2_simule):
    g = gk2_simule
    g.menace(IP)
    g.bans = [{"ip": IP, "reason": "scanners"}]
    assert _motif(g.ban(IP, mode="auto")) == "deja_actif"


# ── prolonger ──────────────────────────────────────────────────────────
def _actif(g, cible=IP, reste=80000, mode="auto"):
    now = int(time.time())
    e = _ban_journal(cible, now - 100, now + reste, mode=mode)
    g.journal(e)
    return e


def test_prolonger_ne_raccourcit_jamais(gk2_simule):
    g = gk2_simule
    e = _actif(g)
    r = g.prolonger(e["id"], 3600)
    assert r.status_code == 409 and _motif(r) == "raccourcit"
    assert g.faux.appels == []
    r = g.prolonger(e["id"], 172800)
    assert r.status_code == 200, r.text
    assert g.faux.appel("prolonger")[-2:] == [IP, "172800s"]           # retrait + ajout en une transaction
    corps = r.json()
    assert corps["id"] == e["id"] and corps["cible"] == IP
    ligne = g.lignes_journal()[-1]
    assert ligne["type"] == "prolonge" and ligne["geste"] == "prolonger" and ligne["id"] == e["id"]
    assert ligne["fin"] == corps["fin"] >= int(time.time()) + 172800 - 5
    actions = [x["action"] for x in g.audit()]
    assert actions.index("ai-prolonger-demande") < actions.index("ai-prolonger")
    actifs = g.c.get("/ai/etat").json()["actifs"]
    assert [a["fin"] for a in actifs if a["id"] == e["id"]] == [corps["fin"]]
    # la prolongation fait foi ensuite : une durée plus courte que la nouvelle fin raccourcirait
    assert _motif(g.prolonger(e["id"], 100000)) == "raccourcit"


def test_prolonger_bloc_passe_par_waf_blocs(gk2_simule):
    g = gk2_simule
    e = _actif(g, cible="203.0.113.0/24")
    fin_blocs = int(time.time()) + 300000
    g.faux.reponses["ban-bloc"] = (0, json.dumps({"ok": True, "motif": None, "fin": fin_blocs}) + "\n", "")
    r = g.prolonger(e["id"], 259200)
    assert r.status_code == 200, r.text
    assert g.faux.appel("ban-bloc")[-2:] == ["203.0.113.0/24", "259200s"]
    assert "/usr/bin/systemd-run" in g.faux.appel("ban-bloc")
    assert r.json()["fin"] == fin_blocs == g.lignes_journal()[-1]["fin"]


def test_prolonger_borne_7j(gk2_simule):
    g = gk2_simule
    e = _actif(g)
    r = g.prolonger(e["id"], 604801)
    assert r.status_code == 409 and _motif(r) == "duree"
    assert g.faux.appels == []
    assert g.prolonger(e["id"], 604800).status_code == 200


def test_prolonger_id_inconnu_ou_autre_source(gk2_simule):
    g = gk2_simule
    now = int(time.time())
    echu = _ban_journal(IP, now - 90000, now - 10)
    annule = _ban_journal("198.51.100.8", now - 100, now + 9000)
    g.journal(echu, annule, {"ts": "", "at": now, "type": "annule", "id": annule["id"], "cible": "198.51.100.8"})
    g.bans = [{"ip": "198.51.100.9", "reason": "sqli"}]                 # banni par le WAF : jamais par un id ai-ban
    for ident in (secrets.token_hex(16), echu["id"], annule["id"]):
        r = g.prolonger(ident, 172800)
        assert r.status_code == 409 and _motif(r) == "inconnu"
    assert g.faux.appels == []
    assert g.c.post("/ai/prolonger", json={"geste": "prolonger", "id": "198.51.100.9", "duree_s": 172800,
                                           "conseil": "c", "motif": ""}).status_code == 422
    assert g.c.post("/ai/prolonger", json={"geste": "ban", "id": echu["id"], "duree_s": 172800,
                                           "conseil": "c", "motif": ""}).status_code == 422


def test_prolonger_liste_blanche_refuse(gk2_simule):
    g = gk2_simule
    e = _actif(g)
    g.sade("active", liste=["198.51.100.7/32"])
    assert _motif(g.prolonger(e["id"], 172800)) == "protegee"
    assert g.faux.appels == []


def test_prolonger_audit_demande_impossible_rien_n_est_fait(gk2_simule, monkeypatch):
    g = gk2_simule
    e = _actif(g)
    vrai = g.g._config["audit"]

    def audit(action, detail, user):
        if action == "ai-prolonger-demande":
            raise OSError("disque plein")
        vrai(action, detail, user)
    monkeypatch.setitem(g.g._config, "audit", audit)
    r = g.prolonger(e["id"], 172800)
    assert r.status_code == 503 and _motif(r) == "audit"
    assert g.faux.appels == []


def test_plafond_prolonger_30_par_heure(gk2_simule):
    g = gk2_simule
    e = _actif(g)
    now = int(time.time())
    g.journal(*[{"ts": "", "at": now - 60 * i - 1, "type": "prolonge", "id": secrets.token_hex(16), "fin": now + 9000,
                 "geste": "prolonger"} for i in range(30)])
    r = g.prolonger(e["id"], 172800)
    assert r.status_code == 409 and _motif(r) == "plafond_heure"


# ── plafonds par geste ─────────────────────────────────────────────────
def test_plafond_ban_adresse_60_par_heure(gk2_simule):
    g = gk2_simule
    now = int(time.time())
    g.journal(*[_ban_journal(f"192.0.2.{i}", now - 50 * i - 1, now - 1, mode="clic") for i in range(59)])
    g.menace(IP)
    assert g.ban(IP, mode="auto").status_code == 200                  # 60e : admis (clic et auto sommés)
    r = g.ban("198.51.100.8")                                           # 61e, même en clic
    assert r.status_code == 409 and _motif(r) == "plafond_heure"
    # le bloc a ses propres plafonds
    assert g.ban("203.0.113.0/24").status_code == 200


def test_plafond_ban_adresse_400_par_jour(gk2_simule):
    g = gk2_simule
    now = int(time.time())
    g.journal(*[_ban_journal(f"192.0.2.{i % 250}", now - 3600 - 200 * i, now - 1) for i in range(400)])
    assert _motif(g.ban(IP)) == "plafond_jour"


def test_lignes_anciennes_sans_geste_comptees_par_la_forme(gk2_simule):
    g = gk2_simule
    now = int(time.time())
    g.journal(*[_ban_journal(f"203.0.{i}.0/24", now - 60 * i - 1, now - 1, mode="auto") for i in range(5)])
    g.bans = _bloc_peuple(20)
    assert _motif(g.ban("203.0.113.0/24", mode="auto")) == "plafond_auto"
    g.menace(IP)
    assert g.ban(IP, mode="auto").status_code == 200                  # les adresses ne sont pas des blocs


def test_etat_plafonds_par_geste_et_mode_sade(gk2_simule):
    g = gk2_simule
    now = int(time.time())
    g.journal(_ban_journal(IP, now - 100, now + 3600, mode="auto"),
              _ban_journal("203.0.113.0/24", now - 100, now + 3600, mode="auto"),
              {"ts": "", "at": now - 10, "type": "prolonge", "id": secrets.token_hex(16), "fin": now + 9000,
               "geste": "prolonger"})
    e = g.c.get("/ai/etat").json()
    assert e["sade_mode"] is None
    pg = e["plafonds_par_geste"]
    assert pg["ban"] == {"heure": 60, "jour": 400, "restant_heure": 59, "restant_jour": 399}
    assert pg["ban_bloc"] == {"heure": 5, "jour": 20, "restant_heure": 4, "restant_jour": 19}
    assert pg["prolonger"] == {"heure": 30, "jour": 100, "restant_heure": 29, "restant_jour": 99}
    g.sade("reactive")
    assert g.c.get("/ai/etat").json()["sade_mode"] == "reactive"


# ── porte du mode SADE ─────────────────────────────────────────────────
def test_mode_sade_observe_refuse_tout_auto(gk2_simule):
    g = gk2_simule
    g.sade("observe")
    g.menace(IP)
    g.bans = _bloc_peuple(20)
    for cible in (IP, "203.0.113.0/24"):
        r = g.ban(cible, mode="auto")
        assert r.status_code == 409 and _motif(r) == "sade_observe"
    assert g.faux.appels == []
    e = _actif(g, cible="198.51.100.9")
    assert _motif(g.prolonger(e["id"], 172800)) == "sade_observe"
    # revue finale I2 (spec SADE « OBSERVE = zéro action ») : le clic aussi
    assert _motif(g.ban("198.51.100.8")) == "sade_observe"


def test_mode_sade_porte_avant_tout_controle(gk2_simule, monkeypatch):
    g = gk2_simule
    g.sade("observe")

    def interdit():
        raise AssertionError("journal lu avant la porte du mode")
    monkeypatch.setattr(g.g, "_lire_journal", interdit)
    assert _motif(g.ban(IP, mode="auto")) == "sade_observe"


def test_mode_sade_reactive_auto_limiter_seul(gk2_simule):
    g = gk2_simule
    g.sade("reactive")
    g.menace(IP)
    r = g.ban(IP, mode="auto")
    assert r.status_code == 409 and _motif(r) == "sade_reactive"
    assert g.ban("198.51.100.8").status_code == 200
    g.sade("active")
    assert g.ban(IP, mode="auto").status_code == 200


@pytest.mark.parametrize("etat", ["perime", "illisible", "mode_inconnu", "futur"])
def test_mode_sade_perime_vaut_observe(gk2_simule, etat):
    g = gk2_simule
    if etat == "perime":
        g.sade("active", age_s=16 * 60)
    elif etat == "illisible":
        g.sade("", brut="{pas du json")
    elif etat == "mode_inconnu":
        g.sade("tout_permis")
    else:
        g.sade("active", age_s=-3600)
    g.menace(IP)
    assert g.g.mode_sade() == "observe"
    assert _motif(g.ban(IP, mode="auto")) == "sade_observe"


def test_mode_sade_frais_depuis_14_min(gk2_simule):
    gk2_simule.sade("active", age_s=14 * 60)
    assert gk2_simule.g.mode_sade() == "active"


def test_mode_sade_illisible_refuse_le_clic_faute_de_liste_blanche(gk2_simule):
    g = gk2_simule
    g.sade("", brut="{pas du json")
    r = g.ban("198.51.100.8")
    assert r.status_code == 409 and _motif(r) == "sade_observe"       # illisible = observe : le clic aussi (I2)
    g.sade("active", liste=["pas un réseau"])
    assert _motif(g.ban("198.51.100.8")) == "etat"
    assert g.faux.appels == []


def test_fichier_mode_absent_comportement_actuel(gk2_simule):
    g = gk2_simule
    assert g.g.mode_sade() is None
    g.bans = _bloc_peuple(20)
    assert g.ban("203.0.113.0/24", mode="auto").status_code == 200
    g.menace(IP)
    assert g.ban(IP, mode="auto").status_code == 200
    assert g.ban("198.51.100.8").status_code == 200


# ── ronde de correction 1 : cibles protégées des gestes d'office ───────
def test_robot_verifie_jamais_banni_d_office(gk2_simule, monkeypatch):
    g = gk2_simule
    g.menace(IP)
    monkeypatch.setattr(g.g, "_fcrdns", lambda ip: "googlebot.com" if ip == IP else "")
    r = g.ban(IP, mode="auto")
    assert r.status_code == 409 and _motif(r) == "protegee"
    assert g.ban(IP).status_code == 200                                  # le clic reste à l'humain (WAF : robots)


def test_dns_robot_en_doute_refuse_d_office(gk2_simule, monkeypatch):
    g = gk2_simule
    g.menace(IP)

    def panne(ip):
        raise g.g.ProtectionInconnue("dns inverse : 2")
    monkeypatch.setattr(g.g, "_fcrdns", panne)
    r = g.ban(IP, mode="auto")
    assert r.status_code == 409 and _motif(r) == "protegee_inconnue"
    assert g.faux.appels == []


def test_robot_dns_trop_lent_refuse(gk2_simule, monkeypatch):
    monkeypatch.setattr(gk2_simule.g, "_DELAI_DNS_S", 0.05)
    monkeypatch.setattr(gk2_simule.g, "_fcrdns", lambda ip: time.sleep(0.5) or "")
    with pytest.raises(gk2_simule.g.ProtectionInconnue):
        _VRAIES["robot_verifie"](IP)


def test_fcrdns_inverse_confirme_par_le_direct(gk2_simule, monkeypatch):
    import socket as s
    g = gk2_simule.g
    inverse = {"198.51.100.7": ("crawl-1.googlebot.com.", [], ["198.51.100.7"]),
               "198.51.100.8": ("crawl-1.googlebot.com.evil.example", [], ["198.51.100.8"]),
               "198.51.100.9": ("crawl-2.googlebot.com", [], ["198.51.100.9"])}
    direct = {"crawl-1.googlebot.com": "198.51.100.7", "crawl-2.googlebot.com": "203.0.113.1"}  # 9 : usurpateur

    def gethostbyaddr(ip):
        if ip in inverse:
            return inverse[ip]
        if ip == "198.51.100.10":
            raise s.herror(2, "Host name lookup failure")             # TRY_AGAIN
        raise s.herror(1, "Unknown host")
    monkeypatch.setattr(g.socket, "gethostbyaddr", gethostbyaddr)
    monkeypatch.setattr(g.socket, "getaddrinfo",
                        lambda nom, *_a, **_k: [(2, 1, 6, "", (direct[nom], 0))])
    vraie = _VRAIES["_fcrdns"]
    assert vraie("198.51.100.7") == "googlebot.com"
    assert vraie("198.51.100.8") == ""                                   # suffixe de texte : pas le domaine
    assert vraie("198.51.100.9") == ""                                   # le direct ne revient pas à l'adresse
    assert vraie("198.51.100.11") == ""                                  # aucun nom inverse
    with pytest.raises(g.ProtectionInconnue):
        vraie("198.51.100.10")


def test_pair_wg_mesh_jamais_banni_d_office(gk2_simule):
    g = gk2_simule
    g.menace(IP)
    g.g.WG_MESH.write_text(json.dumps({"peers": [{"mesh_ip": "10.10.0.5", "endpoint": f"{IP}:51820"}]}))
    r = g.ban(IP, mode="auto")
    assert r.status_code == 409 and _motif(r) == "protegee"
    g.bans = _bloc_peuple(20, base="198.51.100.")
    assert _motif(g.ban("198.51.100.0/24", mode="auto")) == "protegee"     # un bloc qui contient un pair
    e = _actif(g, cible=IP)
    assert _motif(g.prolonger(e["id"], 172800)) == "protegee"
    assert g.faux.appels == []


def test_wg_mesh_illisible_refuse_d_office(gk2_simule):
    g = gk2_simule
    g.menace(IP)
    g.g.WG_MESH.write_text("{tronqué")
    assert _motif(g.ban(IP, mode="auto")) == "protegee_inconnue"
    # revue finale M1 : le clic passe aussi la garde des pairs (source muette : jamais « aucun pair »)
    assert _motif(g.ban("198.51.100.8")) == "protegee_inconnue"


def test_pair_threatmesh_jamais_banni_d_office(gk2_simule, monkeypatch):
    g = gk2_simule
    g.menace(IP)
    monkeypatch.setattr(g.g, "_lire_threatmesh_peers",
                        lambda: {"node": "gk2", "peers": [{"address": "[2001:db8::1]:7000"}, {"ip": IP}]})
    r = g.ban(IP, mode="auto")
    assert r.status_code == 409 and _motif(r) == "protegee"


def test_threatmesh_injoignable_refuse_d_office(gk2_simule, monkeypatch, tmp_path):
    g = gk2_simule
    g.menace(IP)
    monkeypatch.setattr(g.g, "_lire_threatmesh_peers", _VRAIES["_lire_threatmesh_peers"])
    monkeypatch.setattr(g.g, "SOCKET_THREATMESH", str(tmp_path / "absent.sock"))
    with pytest.raises(g.g.ProtectionInconnue):
        g.g.pairs_threatmesh()                                         # socket absente : jamais « aucun pair »
    r = g.ban(IP, mode="auto")
    assert r.status_code == 409 and _motif(r) == "protegee_inconnue"
    assert _motif(g.ban("198.51.100.8")) == "protegee_inconnue"        # M1 : le clic aussi
    monkeypatch.setattr(g.g, "_lire_threatmesh_peers", lambda: {"node": "gk2"})
    with pytest.raises(g.g.ProtectionInconnue):
        g.g.pairs_threatmesh()                                         # forme inattendue


def test_ban_d_office_passe_exiger_protegees_a_wafctl(gk2_simule):
    """protegees.env absent + adresse d'office : la garde root (waf-blocs verifier --exiger) refuse."""
    g = gk2_simule
    g.menace(IP)
    g.faux.reponses["ban"] = (1, "", "refus:garde_illisible\n")
    r = g.ban(IP, mode="auto")
    assert r.status_code == 409 and _motif(r) == "garde_illisible"
    assert g.faux.appel("ban")[-1] == "--exiger-protegees"
    assert not [e for e in g.lignes_journal() if e.get("type") == "ban"]
    g.faux.reponses["ban"] = (0, "[..] ban ok\n", "")
    g.ban("198.51.100.8")
    assert g.faux.appels[-1][-1] == "86400s"                           # le clic n'exige pas protegees.env


# ── waf-blocs verifier --exiger, wafctl ban --exiger-protegees / prolonger ─
COMPOSANT = Path(__file__).resolve().parent.parent
WAF_BLOCS = COMPOSANT / "scripts" / "waf-blocs"
WAFCTL = COMPOSANT / "scripts" / "wafctl"


@pytest.fixture
def wb(monkeypatch, tmp_path):
    import importlib.machinery
    import importlib.util
    chargeur = importlib.machinery.SourceFileLoader("waf_blocs_3723", str(WAF_BLOCS))
    spec = importlib.util.spec_from_loader("waf_blocs_3723", chargeur)
    module = importlib.util.module_from_spec(spec)
    chargeur.exec_module(module)
    hote = json.dumps([{"addr_info": [{"local": "198.18.0.1"}]}])
    monkeypatch.setattr(module, "executer", lambda argv: hote if argv[0] == module.IP else "")
    return module


def test_waf_blocs_exiger_protegees_pour_une_adresse_d_office(wb, monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(wb, "PROTEGEES_ENV", tmp_path / "absent.env")
    assert wb.main(["verifier", IP]) == 0                               # clic : fichier absent = rien de protégé
    assert wb.main(["verifier", IP, "--exiger"]) == 6                   # d'office : fichier absent = refus
    capsys.readouterr()
    commente = tmp_path / "commente.env"
    commente.write_text("# SECUBOX_WAF_PROTEGEES=\n")
    monkeypatch.setattr(wb, "PROTEGEES_ENV", commente)
    assert wb.main(["verifier", IP, "--exiger"]) == 6
    assert json.loads(capsys.readouterr().out.splitlines()[-1])["motif"] == "garde_illisible"
    declare = tmp_path / "declare.env"
    declare.write_text("SECUBOX_WAF_PROTEGEES=198.51.100.7/32\n")
    monkeypatch.setattr(wb, "PROTEGEES_ENV", declare)
    assert wb.main(["verifier", IP, "--exiger"]) == 3                   # la Freebox déclarée : protegee
    assert wb.main(["verifier", IP, "--autre"]) == 64                   # toute autre option : usage


def _wafctl_banc(tmp_path, code_garde=0, code_get=0):
    """wafctl réel, `waf-blocs` et `nft` remplacés par des faux qui notent leurs arguments (et le lot de `nft -f`)."""
    bin_ = tmp_path / "bin"
    bin_.mkdir(exist_ok=True)
    garde = bin_ / "waf-blocs"
    garde.write_text(f'#!/bin/bash\necho "$*" >> {tmp_path}/garde.log\n'
                     f'[ {code_garde} -eq 0 ] && echo \'{{"ok": true, "motif": null}}\' && exit 0\n'
                     f'echo \'{{"ok": false, "motif": "garde_illisible"}}\'; exit {code_garde}\n')
    nft = bin_ / "nft"
    nft.write_text(f'#!/bin/bash\necho "$*" >> {tmp_path}/nft.log\n'
                   f'if [ "$1" = "-f" ]; then cat > {tmp_path}/lot.nft; exit 0; fi\n'
                   f'case "$1" in get) exit {code_get} ;; -j) [ "$2" = list ] && exit {code_get} ;; esac\nexit 0\n')
    for f in (garde, nft):
        f.chmod(0o755)
    script = tmp_path / "wafctl"
    script.write_text(WAFCTL.read_text().replace("/usr/sbin/waf-blocs", str(garde)))
    env = {**os.environ, "PATH": f"{bin_}:{os.environ['PATH']}"}

    def lancer(*args):
        return subprocess.run(["bash", str(script), *args], check=False, timeout=30, capture_output=True,
                              text=True, env=env)
    return lancer


def test_wafctl_prolonger_une_seule_transaction_nft(tmp_path):
    lancer = _wafctl_banc(tmp_path)
    r = lancer("prolonger", IP, "172800s")
    assert r.returncode == 0, r.stderr
    assert (tmp_path / "lot.nft").read_text() == (
        f"delete element inet secubox waf_ban {{ {IP} }}\n"
        f"add element inet secubox waf_ban {{ {IP} timeout 172800s }}\n")
    assert (tmp_path / "garde.log").read_text().split() == ["verifier", IP, "--exiger"]
    nft = (tmp_path / "nft.log").read_text().splitlines()
    assert nft[0] == "-j list set inet secubox waf_ban" and nft[-1] == "-f -"
    assert not any(x.startswith("add element") for x in nft)            # jamais un `add` hors transaction


def test_wafctl_prolonger_refuse_une_adresse_absente(tmp_path):
    r = _wafctl_banc(tmp_path, code_get=1)("prolonger", IP, "172800s")
    assert r.returncode == 1 and "refus:absent" in r.stderr
    assert not (tmp_path / "lot.nft").exists()                          # jamais un nouveau ban par ce verbe


def test_wafctl_prolonger_garde_d_office(tmp_path):
    r = _wafctl_banc(tmp_path, code_garde=6)("prolonger", IP, "172800s")
    assert r.returncode == 1 and "refus:garde_illisible" in r.stderr
    assert not (tmp_path / "lot.nft").exists()


@pytest.mark.parametrize("args", [("prolonger", IP), ("prolonger", IP, "1d", "x"), ("prolonger", "10.0.0.1", "1d"),
                                  ("prolonger", IP, "1w"), ("prolonger", "2001:db8::1", "1d")])
def test_wafctl_prolonger_arguments_refuses(tmp_path, args):
    assert _wafctl_banc(tmp_path)(*args).returncode == 1
    assert not (tmp_path / "lot.nft").exists()


def test_wafctl_ban_exiger_protegees(tmp_path):
    lancer = _wafctl_banc(tmp_path)
    assert lancer("ban", IP, "86400s", "--exiger-protegees").returncode == 0
    assert lancer("ban", IP, "86400s").returncode == 0
    assert (tmp_path / "garde.log").read_text().splitlines() == [f"verifier {IP} --exiger", f"verifier {IP}"]
    assert lancer("ban", IP, "86400s", "--autre").returncode == 1
    assert lancer("ban", IP, "86400s", "--exiger-protegees", "x").returncode == 1


def test_sudoers_prolonger_exact():
    s = (COMPOSANT / "sudoers" / "secubox-waf").read_text()
    assert "Cmnd_Alias SBX_WAF_PROLONGER = /usr/sbin/wafctl prolonger *" in s
    assert "secubox ALL=(root) NOPASSWD: SBX_WAF_PROLONGER" in s


# ── fichier du mode SADE forgeable (/run/secubox 1777) ─────────────────
def test_mode_sade_mauvais_proprietaire_vaut_observe(gk2_simule, monkeypatch):
    g = gk2_simule
    g.sade("active", liste=["198.51.100.0/24"])
    monkeypatch.setattr(g.g, "_uids_sade", lambda: {0, os.getuid() + 1})   # le fichier n'est pas à root ni à SOC
    assert g.g.mode_sade() == "observe"
    assert g.g.lire_sade()["liste"] == []
    g.menace(IP)
    assert _motif(g.ban(IP, mode="auto")) == "sade_observe"


@pytest.mark.parametrize("mode", [0o666, 0o664, 0o646])
def test_mode_sade_modifiable_par_d_autres_vaut_observe(gk2_simule, mode):
    g = gk2_simule
    g.sade("active")
    g.g.FICHIER_SADE.chmod(mode)
    assert g.g.mode_sade() == "observe"
