# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3839 — SADE : cartes 3 (Neutralisation locale) et 4 (Apprentissage) vivantes, critères mesurés, gestes gradués
exécutables depuis la file d'approbation (limiter, leurre, prolonger par `sudo wafctl`).

Aucun fichier réel de gk2 ni sudo réel : journaux et résumés vivent dans tmp_path, `subprocess.run` est un faux.
"""
import copy
import json
import os
import re
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from fastapi.testclient import TestClient  # noqa: E402

from api import defense, defense_etat, main, phases, sade_auto  # noqa: E402
from secubox_core.auth import require_jwt, require_lecture  # noqa: E402

ADMIN = {"Authorization": "Bearer admin"}
LECTURE = {"Authorization": "Bearer lecteur"}
PAGE = (Path(__file__).resolve().parents[1] / "www" / "soc" / "defense.html").read_text(encoding="utf-8")
JOUR = 86400


# ── environnement ─────────────────────────────────────────────────────────────────────────────────

class Substrat:
    """actord (propositions), threatmesh (/peers) ; le WAF HTTP ne doit JAMAIS être appelé pour les gestes gradués."""

    def __init__(self):
        self.rep = {("actord", "/proposals"): {"genere_le": 1763630000, "shadow": True, "propositions": []},
                    ("threatmesh", "/peers"): {"peers": []}}
        self.ecrits = []

    def lire(self, source, chemin, entetes=None, delai=3.0):
        cle = (source, chemin.split("?")[0])
        if cle in self.rep:
            return {"ok": True, "donnees": copy.deepcopy(self.rep[cle]), "erreur": None}
        return {"ok": False, "donnees": None, "erreur": "socket absent"}

    def ecrire(self, source, chemin, corps, entetes=None, delai=10.0):
        self.ecrits.append((source, chemin, dict(corps)))
        return {"ok": True, "donnees": {"success": True}, "erreur": None}


class Fini:
    def __init__(self, code=0, stdout="", stderr=""):
        self.returncode, self.stdout, self.stderr = code, stdout, stderr


class Sudo:
    """Faux `subprocess.run` : journalise chaque argv ; `nft -j list set` rend `self.ensemble`."""

    def __init__(self):
        self.appels = []
        self.ensemble = []          # éléments de waf_ban (forme `nft -j`)
        self.sortie = Fini(0, '{"fin": 1}\n')

    def __call__(self, argv, **kw):
        self.appels.append(list(argv))
        if "nft" in argv[2]:
            return Fini(0, json.dumps({"nftables": [{"metainfo": {}}, {"set": {"name": "waf_ban",
                                                                               "elem": self.ensemble}}]}))
        return self.sortie

    def wafctl(self):
        return [a for a in self.appels if a[2] == "/usr/sbin/wafctl"]


faux = None
sudo = None


@pytest.fixture(autouse=True)
def isole(tmp_path, monkeypatch):
    global faux, sudo
    monkeypatch.setenv("SECUBOX_SOC_DEFENSE_DB", str(tmp_path / "defense.db"))
    monkeypatch.setenv("SECUBOX_AUDIT_LOG", str(tmp_path / "audit.log"))
    monkeypatch.setenv("SECUBOX_TABLEAU_DE_BORD", "0")
    monkeypatch.setenv("SECUBOX_SOC_WG_MESH", str(tmp_path / "wg_mesh-absent.json"))
    monkeypatch.setenv("SECUBOX_SOC_AI_BAN", str(tmp_path / "ai-ban.jsonl"))
    monkeypatch.setenv("SECUBOX_SOC_WAF_MENACES", str(tmp_path / "waf-threats.log"))
    monkeypatch.setenv("SECUBOX_SOC_INDICES", str(tmp_path / "waf-indices-etat.json"))
    monkeypatch.setenv("SECUBOX_SOC_FILTRES_IA", str(tmp_path / "filtres-ia.json"))
    monkeypatch.setattr(defense, "ROUTES_PROC", str(tmp_path / "route-absente"))
    faux, sudo = Substrat(), Sudo()
    monkeypatch.setattr(defense.substrat, "lire", faux.lire)
    monkeypatch.setattr(defense.substrat, "ecrire", faux.ecrire)
    monkeypatch.setattr(sade_auto.subprocess, "run", sudo)
    defense._CACHE.clear()
    phases.vider()
    yield
    faux = sudo = None


@pytest.fixture
def client():
    main.app.dependency_overrides[require_lecture] = lambda: {"sub": "lecteur"}
    main.app.dependency_overrides[require_jwt] = lambda: {"sub": "gerald"}
    yield TestClient(main.app)
    main.app.dependency_overrides.pop(require_lecture, None)
    main.app.dependency_overrides.pop(require_jwt, None)


def _ecrire_jsonl(chemin, lignes):
    Path(chemin).write_text("".join(json.dumps(x) + "\n" for x in lignes), encoding="utf-8")


def _journal_ai(tmp_path, *entrees):
    _ecrire_jsonl(tmp_path / "ai-ban.jsonl", entrees)


def _geste(type_, age_s, cible="203.0.113.7", mode=None, ident=None):
    at = int(time.time()) - age_s
    e = {"ts": "x", "at": at, "type": type_, "id": ident or os.urandom(16).hex(), "cible": cible, "fin": at + 3600}
    if type_ == "ban":
        e["mode"] = mode or "auto"
        e["geste"] = "ban_bloc" if "/" in cible else "ban"
    else:
        e["geste"] = {"leurre": "leurre", "limite": "limiter", "partage": "partager"}.get(type_, type_)
    return e


def _menace(age_s, **champs):
    ts = (datetime.now(timezone.utc) - timedelta(seconds=age_s)).astimezone().isoformat(timespec="seconds")
    return {"timestamp": ts, "client_ip": "203.0.113.9", "host": "x.gk2.net", "category": "scanners",
            "severity": "medium", "action": "warning", **champs}


def _indices(tmp_path, maj=None, mode=0o644, **valeurs):
    d = {"maj": int(time.time()) if maj is None else maj, "partages": 4, "revus_chez_pairs": 1,
         "contenus_chez_pairs": 0, **valeurs}
    p = tmp_path / "waf-indices-etat.json"
    p.write_text(json.dumps(d), encoding="utf-8")
    os.chmod(p, mode)


def _iso_z(age_s):
    return (datetime.now(timezone.utc) - timedelta(seconds=age_s)).strftime("%Y-%m-%dT%H:%M:%SZ")


def _filtres(tmp_path, ids, genere_age_s=60):
    gen = (datetime.now(timezone.utc) - timedelta(seconds=genere_age_s)).isoformat()
    (tmp_path / "filtres-ia.json").write_text(json.dumps({"genere_le": gen, "filtres": [{"id": i} for i in ids]}),
                                              encoding="utf-8")


def _audit_cvectl(tmp_path, *lignes):
    with open(tmp_path / "audit.log", "a", encoding="utf-8") as f:
        for age, action, detail in lignes:
            f.write(json.dumps({"ts": _iso_z(age), "module": "cve-triage", "action": f"leurre_filtres-ia-{action}",
                                "result": "ok", "detail": detail}) + "\n")


def _status(client):
    r = client.get("/defense/status", headers=LECTURE)
    assert r.status_code == 200
    return r.json()


# ── tests du plan (brief) ──────────────────────────────────────────────────────────────────────────

def test_status_phases_forme(client, tmp_path):
    _journal_ai(tmp_path, _geste("leurre", 600))
    _ecrire_jsonl(tmp_path / "waf-threats.log", [_menace(300, category="leurre_redirige", action="leurre_redirige",
                                                         severity="audit", servies=5)])
    _indices(tmp_path)
    _filtres(tmp_path, [])
    ph = _status(client)["phases"]
    assert set(ph) == {"p3", "p4"}
    assert ph["p3"]["livree"] is True and isinstance(ph["p3"]["active"], bool)
    assert set(ph["p3"]["critere"]) == {"rediriges_24h", "tentatives_valides_24h"}
    assert ph["p4"]["livree"] is True and isinstance(ph["p4"]["active"], bool)
    assert set(ph["p4"]["critere"]) == {"partages", "revus_chez_pairs", "contenus_chez_pairs", "filtres_confirmes"}
    assert ph["p3"]["critere"] == {"rediriges_24h": 5, "tentatives_valides_24h": 0}
    assert ph["p4"]["critere"] == {"partages": 4, "revus_chez_pairs": 1, "contenus_chez_pairs": 0,
                                   "filtres_confirmes": 0}
    assert ph["p4"]["active"] is True  # 4 indicateurs partagés


def test_p3_inactive_en_observe(client, tmp_path):
    _journal_ai(tmp_path, _geste("leurre", 600), _geste("ban", 600, mode="auto"))
    for mode in ("observe", "reactive"):
        if mode != "observe":
            defense_etat.changer_mode(mode, "test")
        phases.vider()
        assert _status(client)["phases"]["p3"]["active"] is False, mode


def test_p3_active_avec_leurre_24h(client, tmp_path):
    defense_etat.changer_mode("active", "test")
    _journal_ai(tmp_path, _geste("leurre", 3600))
    assert _status(client)["phases"]["p3"]["active"] is True
    # hors fenêtre, ou geste qui n'est pas de la neutralisation d'office : inactive
    for entrees in ([_geste("leurre", JOUR + 600)], [_geste("ban", 600, mode="clic")], [_geste("limite", 600)],
                    [_geste("partage", 600)], []):
        _journal_ai(tmp_path, *entrees)
        phases.vider()
        defense._CACHE.clear()
        assert _status(client)["phases"]["p3"]["active"] is False, entrees
    for e in (_geste("ban", 600, mode="auto"), _geste("ban", 600, cible="203.0.113.0/24", mode="auto")):
        _journal_ai(tmp_path, e)
        phases.vider()
        assert _status(client)["phases"]["p3"]["active"] is True, e
    # un ban d'office annulé pour défaut d'audit n'a jamais été posé
    b = _geste("ban", 600, mode="auto")
    _journal_ai(tmp_path, b, {"ts": "x", "at": b["at"], "type": "annule", "id": b["id"], "cause": "audit"})
    phases.vider()
    assert _status(client)["phases"]["p3"]["active"] is False
    # journal illisible en ACTIVE : on ne sait pas (None), jamais un « inactive » inventé
    p = tmp_path / "ai-ban.jsonl"
    p.unlink()
    p.mkdir()
    phases.vider()
    assert _status(client)["phases"]["p3"]["active"] is None


def test_critere_indisponible_jamais_zero(client, tmp_path):
    ph = _status(client)["phases"]
    assert ph["p3"]["critere"] == {"rediriges_24h": None, "tentatives_valides_24h": None}
    assert ph["p4"]["critere"] == {"partages": None, "revus_chez_pairs": None, "contenus_chez_pairs": None,
                                   "filtres_confirmes": None}
    assert ph["p4"]["active"] is None
    # somme des `servies` (lignes bornées par adresse), pas le nombre de lignes ; hors 24 h ignoré
    _ecrire_jsonl(tmp_path / "waf-threats.log", [
        _menace(JOUR + 60, category="leurre_redirige", action="leurre_redirige", servies=100),
        _menace(3000, category="leurre_redirige", action="leurre_redirige", servies=30),
        _menace(200, category="leurre_redirige", action="leurre_redirige", servies=7),
        _menace(100, action="detect"), _menace(90, action="detect", client_ip="local"),
        _menace(80, action="warning"), _menace(JOUR + 5, action="detect")])
    phases.vider()
    assert _status(client)["phases"]["p3"]["critere"] == {"rediriges_24h": 37, "tentatives_valides_24h": 1}
    # résumé des indices douteux (écriture de groupe), périmé ou du futur : indisponible
    for kw in ({"mode": 0o664}, {"maj": int(time.time()) - 7200}, {"maj": int(time.time()) + 600},
               {"partages": "4"}, {"revus_chez_pairs": None}):
        _indices(tmp_path, **kw)
        phases.vider()
        c = _status(client)["phases"]["p4"]["critere"]
        assert c["partages"] is None and c["revus_chez_pairs"] is None, kw
    # livraisons des pairs inconnues : les comptes des pairs restent None, le partage local est su
    _indices(tmp_path, revus_chez_pairs=None, contenus_chez_pairs=None)
    phases.vider()
    c = _status(client)["phases"]["p4"]["critere"]
    assert c["partages"] == 4 and c["revus_chez_pairs"] is None and c["contenus_chez_pairs"] is None
    # filtres : cache périmé ⇒ None ; actif depuis ≥ 24 h ⇒ confirmé ; trop récent ⇒ non ; retiré puis remis ⇒ date
    _filtres(tmp_path, ["ia-a", "ia-b", "ia-c"], genere_age_s=7200)
    phases.vider()
    assert _status(client)["phases"]["p4"]["critere"]["filtres_confirmes"] is None
    _filtres(tmp_path, ["ia-a", "ia-b", "ia-c"])
    _audit_cvectl(tmp_path, (2 * JOUR, "appliquer", "2 filtre(s) : ia-a, ia-b"),
                  (JOUR + 600, "retirer", "ia-b retiré"), (3600, "appliquer", "1 filtre(s) : ia-b"),
                  (1800, "appliquer", "1 filtre(s) : ia-c"))
    phases.vider()
    assert _status(client)["phases"]["p4"]["critere"]["filtres_confirmes"] == 1
    # une ligne d'application tronquée (ids manquants) : on ne sait pas, jamais un compte inventé
    _audit_cvectl(tmp_path, (60, "appliquer", "3 filtre(s) : ia-d, ia-e"))
    _filtres(tmp_path, ["ia-a", "ia-f"])
    phases.vider()
    assert _status(client)["phases"]["p4"]["critere"]["filtres_confirmes"] is None


def test_approve_limiter_passe_par_gestes_ia(client, tmp_path):
    """Les gestes gradués approuvés passent par les verbes de wafctl qu'utilise le compte ai-ban (gestes_ia), en
    `sudo -n` à argv exact, audités avant et après ; jamais par le POST /ban du WAF."""
    defense_etat.changer_mode("reactive", "test")
    props = faux.rep[("actord", "/proposals")]["propositions"]
    props += [{"actor": "ACT-0101", "mode": "LIMITER", "raison": "rafale", "ttl_s": 0, "ips": ["203.0.113.40"],
               "priorite": 50},
              {"actor": "ACT-0102", "mode": "LEURRE", "raison": "scanner", "ttl_s": 7200,
               "ips": ["2001:db8::40", "203.0.113.41"], "priorite": 50},
              {"actor": "ACT-0103", "mode": "PROLONGER", "raison": "récidive", "ttl_s": 172800,
               "ips": ["203.0.113.42"], "priorite": 50},
              {"actor": "ACT-0104", "mode": "LIMITER", "raison": "x", "ttl_s": 600, "ips": ["203.0.113.43"],
               "priorite": 50},
              {"actor": "ACT-0105", "mode": "LIMITER", "raison": "x", "ttl_s": 0, "ips": ["192.168.1.9"],
               "priorite": 50},
              {"actor": "ACT-0106", "mode": "PROLONGER", "raison": "x", "ttl_s": 3600, "ips": ["203.0.113.44"],
               "priorite": 50}]
    lim = defense.empreinte("limiter", ["203.0.113.40"], None)
    r = client.post("/defense/approve", json={"empreinte": lim}, headers={"Cookie": "s=1"})  # pas de porteur requis
    assert r.status_code == 200 and r.json()["etat"] == "applique", r.json()
    assert sudo.wafctl() == [["sudo", "-n", "/usr/sbin/wafctl", "limiter", "203.0.113.40", "21600s"]]
    assert faux.ecrits == [] and defense_etat.decision(lim)["etat"] == "applique"
    audit = [json.loads(x) for x in (tmp_path / "audit.log").read_text(encoding="utf-8").splitlines()]
    assert [a["action"] for a in audit[-2:]] == ["sade-approuve-demande", "sade-approuve-resultat"]
    assert audit[-2]["geste"] == "limiter" and audit[-2]["duree"] == "21600s" and audit[-2]["operateur"] == "gerald"
    assert audit[-1]["issue"] == "applique"

    leu = defense.empreinte("leurre", ["2001:db8::40", "203.0.113.41"], 7200)
    assert client.post("/defense/approve", json={"empreinte": leu}, headers=ADMIN).status_code == 200
    assert sudo.wafctl()[-2:] == [["sudo", "-n", "/usr/sbin/wafctl", "leurre", "2001:db8::40", "7200s"],
                                  ["sudo", "-n", "/usr/sbin/wafctl", "leurre", "203.0.113.41", "7200s"]]

    # prolonger : seulement un ban présent, jamais plus court que ce qui reste
    pro = defense.empreinte("prolonger", ["203.0.113.42"], 172800)
    r = client.post("/defense/approve", json={"empreinte": pro}, headers=ADMIN)
    assert r.status_code == 409 and r.json()["cause"] == "absent"
    sudo.ensemble = [{"elem": {"val": "203.0.113.42", "timeout": 86400, "expires": 80000}}]
    r = client.post("/defense/approve", json={"empreinte": pro}, headers=ADMIN)
    assert r.status_code == 200, r.json()
    assert sudo.wafctl()[-1] == ["sudo", "-n", "/usr/sbin/wafctl", "prolonger", "203.0.113.42", "172800s"]
    assert ["sudo", "-n", "/usr/sbin/nft", "-j", "list", "set", "inet", "secubox", "waf_ban"] in sudo.appels
    court = defense.empreinte("prolonger", ["203.0.113.44"], 3600)
    sudo.ensemble = [{"elem": {"val": "203.0.113.44", "timeout": 86400, "expires": 80000}}]
    r = client.post("/defense/approve", json={"empreinte": court}, headers=ADMIN)
    assert r.status_code == 409 and r.json()["cause"] == "raccourcit"

    n = len(sudo.wafctl())
    r = client.post("/defense/approve", json={"empreinte": defense.empreinte("limiter", ["203.0.113.43"], 600)},
                    headers=ADMIN)
    assert r.status_code == 409 and r.json()["cause"] == "duree_invalide"  # limiter : 1 h à 24 h
    r = client.post("/defense/approve", json={"empreinte": defense.empreinte("limiter", ["192.168.1.9"], None)},
                    headers=ADMIN)
    assert r.status_code == 403 and r.json()["cause"] == "liste_blanche"
    assert len(sudo.wafctl()) == n

    # wafctl refuse (garde root) : jamais « appliqué »
    sudo.sortie = Fini(1, "", "refus:protegee\n")
    faux.rep[("actord", "/proposals")]["propositions"].append(
        {"actor": "ACT-0107", "mode": "LIMITER", "raison": "x", "ttl_s": 0, "ips": ["203.0.113.45"], "priorite": 50})
    e = defense.empreinte("limiter", ["203.0.113.45"], None)
    r = client.post("/defense/approve", json={"empreinte": e}, headers=ADMIN)
    assert r.status_code == 502 and r.json()["cause"] == "wafctl" and "refus:protegee" in r.json()["error"]
    assert defense_etat.decision(e)["etat"] == "en_attente"
    assert faux.ecrits == []


def test_approve_geste_inconnu_refuse(client):
    defense_etat.changer_mode("active", "test")
    props = faux.rep[("actord", "/proposals")]["propositions"]
    for i, mode in enumerate(("PARTAGER", "QUARANTINE", "BAN_BLOC", "UNBAN", "TARPIT")):
        props.append({"actor": f"ACT-02{i:02d}", "mode": mode, "raison": "x", "ttl_s": 3600,
                      "ips": ["203.0.113.50"], "priorite": 50})
    for g in ("partager", "quarantaine", "ban_bloc", "unban", "tarpit"):
        e = defense.empreinte(g, ["203.0.113.50"], 3600)
        r = client.post("/defense/approve", json={"empreinte": e, "simuler": True}, headers=ADMIN)
        assert r.status_code == 409 and r.json()["cause"] == "gestes_non_livres", g
    assert sudo.appels == [] and faux.ecrits == []
    assert defense.GESTES_EXECUTABLES == ("ban", "limiter", "leurre", "prolonger")
    p = {x["geste"]: x["executable"] for x in client.get("/defense/proposals", headers=ADMIN).json()["propositions"]}
    assert p == {"partager": False, "quarantaine": False, "ban_bloc": False, "unban": False, "tarpit": False}


def test_page_sans_tag_v2_4_7():
    assert "V2 4-7" not in PAGE
    f = re.search(r"function rendPhases.*?\n  }\n", PAGE, re.S).group(0)
    assert "'Neutralisation locale'" in f and re.search(r"'Neutralisation locale'[^\]]*'active', mesure3\]", f)
    assert "phases.p4.active" in f or "p4.active" in f
    assert "relevé indisponible" in f
    assert "requêtes servies par le leurre en 24 h" in PAGE and "indicateurs partagés" in PAGE
    assert "revu chez un pair" in PAGE
    b = re.search(r'<button[^>]*data-mode="aggressive"[^>]*>', PAGE).group(0)
    assert " disabled" in b
    assert 'title="seuils abaissés, réservé au banc — ouverture sur accord du propriétaire"' in b


def test_aggressive_toujours_409(client):
    assert "aggressive" not in defense_etat.MODES_OUVERTS
    r = client.post("/defense/mode", json={"mode": "aggressive"}, headers=ADMIN)
    assert r.status_code == 409 and r.json()["cause"] == "gestes_non_livres"
    assert defense_etat.mode_courant() == "observe"
