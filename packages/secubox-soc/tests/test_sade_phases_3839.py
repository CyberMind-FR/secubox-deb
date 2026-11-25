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
        _menace(80, action="warning"), _menace(JOUR + 5, action="detect"),
        _menace(70, category="rotation:0a1b2c3d", action="detect"), _menace(60, category=None, action="warning")])
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


def _proposer(mode, ips, ttl=0, acteur=None):
    n = len(faux.rep[("actord", "/proposals")]["propositions"]) + 101
    faux.rep[("actord", "/proposals")]["propositions"].append(
        {"actor": acteur or f"ACT-{n:04d}", "mode": mode, "raison": "x", "ttl_s": ttl, "ips": list(ips),
         "priorite": 50})
    return defense.empreinte(mode.lower(), list(ips), ttl if ttl > 0 else None)


def _audit(tmp_path):
    return [json.loads(x) for x in (tmp_path / "audit.log").read_text(encoding="utf-8").splitlines()]


def test_approve_limiter_passe_par_gestes_ia(client, tmp_path):
    """Un geste gradué approuvé est MIS EN FILE (202, `approuve`) sans aucun sudo dans l'API ; le passage suivant de
    sade-auto l'exécute par le verbe de wafctl qu'utilise le compte ai-ban (gestes_ia), audité avant et après, une
    seule fois, au nom de l'administrateur ; jamais par le POST /ban du WAF."""
    defense_etat.changer_mode("reactive", "test")      # REACTIVE : la file des approuvées s'exécute aussi
    lim = _proposer("LIMITER", ["203.0.113.40"])
    r = client.post("/defense/approve", json={"empreinte": lim}, headers={"Cookie": "s=1"})  # pas de porteur requis
    assert r.status_code == 202 and r.json()["etat"] == "approuve", r.json()
    assert sudo.appels == [] and faux.ecrits == []
    assert defense_etat.decision(lim)["etat"] == "approuve"
    a = _audit(tmp_path)[-1]
    assert a["action"] == "sade-approuve-demande" and a["geste"] == "limiter" and a["duree"] == "21600s"
    assert a["operateur"] == "gerald"
    p = {x["geste"]: x for x in client.get("/defense/proposals", headers=ADMIN).json()["propositions"]}
    assert p["limiter"]["etat"] == "approuve" and p["limiter"]["executable"] is True

    out = sade_auto.executer()
    assert out["approuvees_executees"] == ["203.0.113.40"] and out["erreur"] is None, out
    assert sudo.wafctl() == [["sudo", "-n", "/usr/sbin/wafctl", "limiter", "203.0.113.40", "21600s"]]
    d = defense_etat.decision(lim)
    assert d["etat"] == "applique" and d["par"] == "gerald"         # jamais « sade-auto »
    actions = [x["action"] for x in _audit(tmp_path)]
    assert actions[-2:] == ["sade-approuve-execution", "sade-approuve-resultat"]
    assert all(x["operateur"] == "gerald" for x in _audit(tmp_path)[-2:])
    assert defense_etat.bans_auto_depuis(3600) == 0                   # ni plafond auto ni retour en OBSERVE
    assert defense_etat.mode_courant() == "reactive"
    # double passage : jamais deux fois
    sade_auto.executer()
    assert len(sudo.wafctl()) == 1
    # la page voit l'issue réelle (administrateur seulement)
    lecteur = {x["geste"]: x for x in client.get("/defense/proposals", headers=LECTURE).json()["propositions"]}
    assert lecteur["limiter"]["etat"] == "applique" and "resultat" not in lecteur["limiter"]
    main.app.dependency_overrides[defense._est_admin] = lambda: True
    try:
        p = {x["geste"]: x for x in client.get("/defense/proposals", headers=ADMIN).json()["propositions"]}
    finally:
        main.app.dependency_overrides.pop(defense._est_admin, None)
    assert p["limiter"]["etat"] == "applique" and "sade-auto" in p["limiter"]["resultat"]
    assert faux.ecrits == []


def test_execution_recontrole_et_bornes(client, tmp_path, monkeypatch):
    defense_etat.changer_mode("active", "test")
    leu = _proposer("LEURRE", ["2001:db8::40", "203.0.113.41"], 7200)
    pro = _proposer("PROLONGER", ["203.0.113.42"], 172800)
    court = _proposer("PROLONGER", ["203.0.113.44"], 3600)
    proteg = _proposer("LIMITER", ["198.51.100.60"])
    for e in (leu, pro, court, proteg):
        assert client.post("/defense/approve", json={"empreinte": e}, headers=ADMIN).status_code == 202
    assert sudo.appels == []  # prolonger : ni nft ni wafctl dans l'API
    # entre l'approbation et l'exécution, 198.51.100.60 entre en liste blanche ; un seul ban présent, plus court
    defense_etat.ajouter_liste_blanche("198.51.100.0/24", "box amie", "gerald")
    sudo.ensemble = [{"elem": {"val": "203.0.113.42", "timeout": 86400, "expires": 80000}},
                     {"elem": {"val": "203.0.113.44", "timeout": 86400, "expires": 80000}}]
    out = sade_auto.executer()
    assert out["erreur"] is None, out
    assert sudo.wafctl() == [["sudo", "-n", "/usr/sbin/wafctl", "leurre", "2001:db8::40", "7200s"],
                             ["sudo", "-n", "/usr/sbin/wafctl", "leurre", "203.0.113.41", "7200s"],
                             ["sudo", "-n", "/usr/sbin/wafctl", "prolonger", "203.0.113.42", "172800s"]]
    assert ["sudo", "-n", "/usr/sbin/nft", "-j", "list", "set", "inet", "secubox", "waf_ban"] in sudo.appels
    assert defense_etat.decision(court)["etat"] == "en_attente"            # prolonger ne raccourcit jamais
    assert "raccourcit" in defense_etat.decision(court)["resultat"]
    assert defense_etat.decision(proteg)["etat"] == "en_attente"           # cible devenue protégée : rien
    assert "cible_protegee" in defense_etat.decision(proteg)["resultat"]
    abandons = [x for x in _audit(tmp_path) if x["action"] == "sade-approuve-abandon"]
    assert {x["motif"] for x in abandons} == {"raccourcit", "cible_protegee"}
    # bornes à l'approbation : limiter 1 h à 24 h, prolonger 1 h au moins ; IPv4 seulement pour prolonger
    for mode, ips, ttl, cause in (("LIMITER", ["203.0.113.43"], 600, "duree_invalide"),
                                  ("PROLONGER", ["203.0.113.46"], 1800, "duree_invalide"),
                                  ("PROLONGER", ["2001:db8::46"], 7200, "ipv4_seulement")):
        r = client.post("/defense/approve", json={"empreinte": _proposer(mode, ips, ttl)}, headers=ADMIN)
        assert r.status_code == 409 and r.json()["cause"] == cause, (mode, ttl)
    r = client.post("/defense/approve", json={"empreinte": _proposer("LIMITER", ["192.168.1.9"])}, headers=ADMIN)
    assert r.status_code == 403 and r.json()["cause"] == "liste_blanche"


def test_execution_echec_rendue_a_l_administrateur(client, tmp_path):
    defense_etat.changer_mode("active", "test")
    e = _proposer("LIMITER", ["203.0.113.45"])
    assert client.post("/defense/approve", json={"empreinte": e}, headers=ADMIN).status_code == 202
    sudo.sortie = Fini(1, "", "refus:protegee\n")
    sade_auto.executer()
    d = defense_etat.decision(e)
    assert d["etat"] == "en_attente" and "refus:protegee" in d["resultat"] and d["par"] == "gerald"
    assert _audit(tmp_path)[-1]["action"] == "sade-approuve-resultat" and _audit(tmp_path)[-1]["issue"] == "echec"
    # observe : la file est vidée (annulee_observe) et rien n'est exécuté
    assert client.post("/defense/approve", json={"empreinte": e}, headers=ADMIN).status_code == 202
    defense_etat.changer_mode("observe", "test")
    n = len(sudo.wafctl())
    sade_auto.executer()
    assert len(sudo.wafctl()) == n
    assert defense_etat.decision(e)["etat"] == "en_attente" and defense_etat.decision(e)["resultat"] == "annulee_observe"


def test_approbation_expiree_et_plafond_par_geste(client, tmp_path, monkeypatch):
    defense_etat.changer_mode("active", "test")
    e = _proposer("LEURRE", ["203.0.113.47"])
    assert client.post("/defense/approve", json={"empreinte": e}, headers=ADMIN).status_code == 202
    monkeypatch.setattr(defense_etat, "gestes_humains_depuis", lambda geste, s, maintenant=None: 30)  # leurre : 30/h
    out = sade_auto.executer()
    assert out["approuvees_en_attente"] == 1 and sudo.wafctl() == []
    assert defense_etat.decision(e)["etat"] == "approuve"                  # attend le passage suivant
    monkeypatch.setattr(sade_auto, "APPROBATION_MAX_S", -1)
    sade_auto.executer()
    assert defense_etat.decision(e)["etat"] == "en_attente" and "expiree" in defense_etat.decision(e)["resultat"]
    assert sudo.wafctl() == []
    a = _audit(tmp_path)[-1]
    assert a["action"] == "sade-approuve-abandon" and a["motif"] == "expiree" and a["empreinte"] == e
    assert a["operateur"] == "gerald"


def test_approbation_plus_grande_que_le_plafond_rendue_aussitot(client, tmp_path, monkeypatch):
    defense_etat.changer_mode("active", "test")
    monkeypatch.setattr(sade_auto, "PLAFONDS_APPROUVES_HEURE", {"limiter": 60, "leurre": 2, "prolonger": 30})
    e = _proposer("LEURRE", ["203.0.113.70", "203.0.113.71", "203.0.113.72"])
    assert client.post("/defense/approve", json={"empreinte": e}, headers=ADMIN).status_code == 202
    out = sade_auto.executer()
    assert out["approuvees_abandonnees"] == 1 and sudo.wafctl() == []
    d = defense_etat.decision(e)
    assert d["etat"] == "en_attente" and "plafond" in d["resultat"]
    a = _audit(tmp_path)[-1]
    assert a["action"] == "sade-approuve-abandon" and a["motif"] == "plafond"


@pytest.mark.parametrize("coupure", ["manuelle", "plafond"])
def test_observe_vide_la_file_des_approuvees(client, tmp_path, coupure):
    defense_etat.changer_mode("reactive", "test")
    e = _proposer("LIMITER", ["203.0.113.80"])
    assert client.post("/defense/approve", json={"empreinte": e}, headers=ADMIN).status_code == 202
    if coupure == "manuelle":
        assert client.post("/defense/mode", json={"mode": "observe"}, headers=ADMIN).status_code == 200
    else:
        defense_etat.changer_mode("observe", sade_auto.OPERATEUR)  # retour forcé de l'exécuteur
    d = defense_etat.decision(e)
    assert d["etat"] == "en_attente" and d["resultat"] == "annulee_observe"
    lignes = _audit(tmp_path)
    assert [x["action"] for x in lignes[-2:]] == ["sade-mode", "sade-approuve-annulee"]
    assert lignes[-1]["empreinte"] == e and lignes[-1]["motif"] == "annulee_observe"
    # retour en REACTIVE : l'approbation d'avant la coupure n'est jamais exécutée
    defense_etat.changer_mode("reactive", "test")
    sade_auto.executer()
    assert sudo.wafctl() == [] and defense_etat.decision(e)["etat"] == "en_attente"
    p = {x["geste"]: x for x in client.get("/defense/proposals", headers=LECTURE).json()["propositions"]}
    assert p["limiter"]["etat"] == "en_attente"


def test_prendre_approuvee_une_seule_fois(client):
    defense_etat.changer_mode("active", "test")
    e = _proposer("LIMITER", ["203.0.113.48"])
    assert client.post("/defense/approve", json={"empreinte": e}, headers=ADMIN).status_code == 202
    d = defense_etat.approuvees()[0]
    defense_etat.prendre_approuvee(d["empreinte"], d["generation"], d["demande_ts"], "sade-approuve-execution t=1")
    with pytest.raises(defense_etat.DejaTraitee):
        defense_etat.prendre_approuvee(d["empreinte"], d["generation"], d["demande_ts"], "sade-approuve-execution t=2")
    assert defense_etat.decision(e)["etat"] == "en_cours"


def test_phases_vol_unique(monkeypatch):
    import threading
    appels, porte = [], threading.Event()

    def lent(maintenant):
        appels.append(1)
        porte.wait(2)
        return 1, 0, False
    monkeypatch.setattr(phases, "_menaces_24h", lent)
    res = []
    fils = [threading.Thread(target=lambda: res.append(phases.phases("observe"))) for _ in range(2)]
    for f in fils:
        f.start()
    time.sleep(0.2)
    porte.set()
    for f in fils:
        f.join(3)
    assert len(appels) == 1 and len(res) == 2
    assert all(r["p3"]["critere"]["rediriges_24h"] == 1 for r in res)
    # mesures précédentes servies pendant un recalcul
    phases._cache["expire"] = 0
    porte.clear()
    t = threading.Thread(target=lambda: phases.phases("observe"))
    t.start()
    time.sleep(0.1)
    assert phases.phases("observe")["p3"]["critere"]["rediriges_24h"] == 1 and len(appels) == 2
    porte.set()
    t.join(3)


def test_retrait_de_plusieurs_filtres(client, tmp_path):
    _filtres(tmp_path, ["ia-a", "ia-b"])
    _audit_cvectl(tmp_path, (3 * JOUR, "appliquer", "2 filtre(s) : ia-a, ia-b"),
                  (2 * JOUR, "retirer", "ia-a, ia-b retirés"), (3600, "appliquer", "2 filtre(s) : ia-a, ia-b"))
    assert _status(client)["phases"]["p4"]["critere"]["filtres_confirmes"] == 0


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
    assert "revu chez un pair" in PAGE and "revus chez des pairs" in PAGE and "c4.contenus_chez_pairs" in PAGE
    assert "tentatives laissées passer" in PAGE and "tentatives valides" not in PAGE
    assert "approuve:'en file'" in PAGE
    b = re.search(r'<button[^>]*data-mode="aggressive"[^>]*>', PAGE).group(0)
    assert " disabled" in b
    assert 'title="seuils abaissés, réservé au banc — ouverture sur accord du propriétaire"' in b


def test_aggressive_toujours_409(client):
    assert "aggressive" not in defense_etat.MODES_OUVERTS
    r = client.post("/defense/mode", json={"mode": "aggressive"}, headers=ADMIN)
    assert r.status_code == 409 and r.json()["cause"] == "gestes_non_livres"
    assert defense_etat.mode_courant() == "observe"


# ── le resserrement vers OBSERVE ne dépend jamais de l'audit (#3839, fix 3) ───────────────────────────

def _audit_hs(tmp_path, monkeypatch):
    monkeypatch.setenv("SECUBOX_AUDIT_LOG", str(tmp_path / "absent" / "audit.log"))


def test_observe_manuel_sans_audit(client, tmp_path, monkeypatch):
    defense_etat.changer_mode("reactive", "test")
    e = _proposer("LIMITER", ["203.0.113.90"])
    assert client.post("/defense/approve", json={"empreinte": e}, headers=ADMIN).status_code == 202
    _audit_hs(tmp_path, monkeypatch)
    r = client.post("/defense/mode", json={"mode": "observe"}, headers=ADMIN)
    assert r.status_code == 200 and r.json()["mode"] == "observe" and r.json()["audit_indisponible"] is True
    assert defense_etat.mode_courant() == "observe"
    d = defense_etat.decision(e)
    assert d["etat"] == "en_attente" and d["resultat"] == "annulee_observe"
    st = _status(client)
    assert st["mode"] == "observe" and isinstance(st["audit_indisponible"], str)
    # ouvrir sans audit reste refusé (et le mode ne bouge pas)
    r = client.post("/defense/mode", json={"mode": "active"}, headers=ADMIN)
    assert r.status_code == 503 and r.json()["cause"] == "audit_indisponible"
    assert defense_etat.mode_courant() == "observe"
    with pytest.raises(defense_etat.AuditIndisponible):
        defense_etat.changer_mode("reactive", "test")
    # audit rétabli : l'ouverture suivante, auditée, efface l'alerte
    monkeypatch.setenv("SECUBOX_AUDIT_LOG", str(tmp_path / "audit.log"))
    assert defense_etat.changer_mode("reactive", "test") is True
    assert "audit_indisponible" not in _status(client)


def test_repli_automatique_en_observe_sans_audit(client, tmp_path, monkeypatch):
    defense_etat.changer_mode("active", "test")
    e = _proposer("LEURRE", ["203.0.113.91"])
    assert client.post("/defense/approve", json={"empreinte": e}, headers=ADMIN).status_code == 202
    _audit_hs(tmp_path, monkeypatch)
    out = {"plafond": False, "erreur": None}
    monkeypatch.setattr(defense_etat, "bans_auto_depuis", lambda s: sade_auto.PLAFOND_HEURE)
    assert sade_auto._plafond({"ips": ["203.0.113.92"], "empreinte": "0" * 64}, out) is True
    assert out["mode"] == "observe" and out["erreur"] == "audit_indisponible"
    assert defense_etat.mode_courant() == "observe"
    assert defense_etat.decision(e)["etat"] == "en_attente"
    assert "audit_indisponible" in defense_etat.alertes()
    defense_etat.changer_mode("observe", "test")  # déjà en observe : rien, jamais d'exception
