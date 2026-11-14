# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""#3716, tâche 4 : routes `/ai/ban`, `/ai/unban`, `/ai/etat` du compte de service `ai-ban`, clés gérées par root.

Le seul chemin d'écriture d'une box d'IA dans le pare-feu de gk2 : forme (IPv4 publique ou /24 exact), durée selon le
mode, plafonds, recontrôle du cas sûr pour `auto`, débannissement de ses seuls bans (par id du journal), audit de
chaque geste. `wafctl` est simulé (`gestes_ia._executer`) ; rien ne touche un pare-feu ni une box.
"""
from __future__ import annotations

import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import time
from pathlib import Path

import pytest

COMPOSANT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(COMPOSANT))
RACINE = COMPOSANT.parents[3]
RULES_CODE = RACINE / ".claude" / "RULES-CODE.md"
POSTINST = COMPOSANT.parents[1] / "debian" / "postinst"
WAFCTL = COMPOSANT / "scripts" / "wafctl"

ADMIN_SYSTEMD_RUN = ["sudo", "-n", "/usr/bin/systemd-run", "--wait", "--pipe", "--collect", "--quiet",
                     "/usr/sbin/wafctl"]
USAGER_AI = {"sub": "ai-ban", "compte_service": "ai-ban", "jti": "a" * 32, "cle": "b" * 64}


def _importer_waf():
    """api.main exige geoip2 (absent de l'environnement de test) : un faux module suffit."""
    import types
    try:
        import geoip2  # noqa: F401
    except ImportError:
        g = types.ModuleType("geoip2")
        g.database, g.errors = types.ModuleType("geoip2.database"), types.ModuleType("geoip2.errors")
        g.errors.AddressNotFoundError = type("AddressNotFoundError", (Exception,), {})
        sys.modules.update({"geoip2": g, "geoip2.database": g.database, "geoip2.errors": g.errors})
    from api import main as waf
    return waf


class FauxWafctl:
    """`wafctl` simulé : note chaque argv, rend une réponse par verbe (code, sortie, erreur)."""

    def __init__(self):
        self.appels: list[list[str]] = []
        self.reponses = {
            "ban": (0, "[..] ban ok\n", ""),
            "unban": (0, "[..] unban ok\n", ""),
            "ban-bloc": (0, '{"ok": true, "motif": null}\n', ""),
            "unban-bloc": (0, '{"ok": true, "motif": null}\n', ""),
            "blocs": (0, '{"ok": true, "motif": null, "blocs": []}\n', ""),
            "nft": (0, json.dumps({"nftables": [{"metainfo": {}}, {"set": {"name": "waf_ban", "elem": []}}]}), ""),
        }

    def __call__(self, argv):
        self.appels.append(list(argv))
        verbe = "nft" if "/usr/sbin/nft" in argv else argv[argv.index("/usr/sbin/wafctl") + 1]
        code, sortie, erreur = self.reponses[verbe]
        return subprocess.CompletedProcess(argv, code, sortie, erreur)

    def verbes(self):
        return ["nft" if "/usr/sbin/nft" in a else a[a.index("/usr/sbin/wafctl") + 1] for a in self.appels]

    def appel(self, verbe):
        return next(a for a in self.appels if a[a.index("/usr/sbin/wafctl") + 1] == verbe)


class Banc:
    def __init__(self, client, waf, g, faux, tmp_path):
        self.c, self.waf, self.g, self.faux, self.tmp = client, waf, g, faux, tmp_path
        self.bans: list[dict] = []

    def journal(self, *entrees):
        with open(self.g.JOURNAL_AI, "a", encoding="utf-8") as f:
            for e in entrees:
                f.write(json.dumps(e) + "\n")

    def lignes_journal(self):
        p = Path(self.g.JOURNAL_AI)
        return [json.loads(x) for x in p.read_text().splitlines()] if p.exists() else []

    def audit(self):
        p = self.tmp / "audit.log"
        return [json.loads(x) for x in p.read_text().splitlines()] if p.exists() else []

    def ban(self, cible, duree_s=86400, mode="clic", conseil="c-1", **extra):
        return self.c.post("/ai/ban", json={"geste": "ban", "cible": cible, "duree_s": duree_s, "mode": mode,
                                            "conseil": conseil, **extra})


def _regroupement_neuf(monkeypatch, g):
    monkeypatch.setattr(g, "_derniers_refus", {})
    monkeypatch.setattr(g, "_minuterie", {"active": None})
    monkeypatch.setattr(g, "_armer_minuterie", lambda: g._minuterie.update(active="armee"))


def _audit_qui_echoue(c, monkeypatch, *actions):
    """L'audit réel, sauf pour `actions`, qui lèvent OSError."""
    vrai = c.g._config["audit"]

    def audit(action, detail, user):
        if action in actions:
            raise OSError("disque plein")
        vrai(action, detail, user)
    monkeypatch.setitem(c.g._config, "audit", audit)


@pytest.fixture
def c(monkeypatch, tmp_path):
    from fastapi.testclient import TestClient
    waf = _importer_waf()
    from api import gestes_ia as g
    from secubox_core.compte_service import require_ai_ban
    monkeypatch.setenv("SECUBOX_WAF_GESTES_IA", "1")          # le processus désigné (agrégateur, tâche 5)
    monkeypatch.setattr(waf, "AUDIT_LOG", tmp_path / "audit.log")
    monkeypatch.setattr(g, "JOURNAL_AI", tmp_path / "ai-ban.jsonl")
    monkeypatch.setattr(g, "BANS_WAF", tmp_path / "bans.jsonl")
    _regroupement_neuf(monkeypatch, g)
    faux = FauxWafctl()
    monkeypatch.setattr(g, "_executer", faux)
    banc = Banc(TestClient(waf.app), waf, g, faux, tmp_path)
    monkeypatch.setitem(g._config, "bans", lambda: list(banc.bans))
    waf.app.dependency_overrides[require_ai_ban] = lambda: dict(USAGER_AI)
    try:
        yield banc
    finally:
        waf.app.dependency_overrides.clear()


def _ban_journal(cible, at, fin, mode="clic", ident=None):
    return {"ts": "", "at": at, "type": "ban", "id": ident or secrets.token_hex(16), "cible": cible, "fin": fin,
            "mode": mode, "conseil": "c-0", "motif": "", "jti": "c" * 32, "duree_s": fin - at}


def _bloc_peuple(n, categories=("scanners", "recon_crawler"), base="203.0.113."):
    return [{"ip": f"{base}{i + 1}", "reason": categories[i % len(categories)]} for i in range(n)]


# ── POST /ai/ban ───────────────────────────────────────────────────────
def test_ban_clic_adresse_appelle_wafctl_et_audite(c):
    r = c.ban("198.51.100.7", motif="sondes répétées")
    assert r.status_code == 200, r.text
    corps = r.json()
    assert re.fullmatch(r"[0-9a-f]{32}", corps["id"]) and corps["audit"] == corps["id"]
    assert corps["cible"] == "198.51.100.7" and corps["fin"] - int(time.time()) in range(86395, 86401)
    assert c.faux.appel("ban") == ["sudo", "-n", "/usr/sbin/wafctl", "ban", "198.51.100.7", "86400s"]
    audit = [x for x in c.audit() if x["action"] == "ai-ban"]
    assert len(audit) == 1 and audit[0]["by"] == "ai-ban" and audit[0]["module"] == "waf"
    assert corps["id"] in audit[0]["detail"] and "198.51.100.7" in audit[0]["detail"]
    assert f"cle {USAGER_AI['cle']}" in audit[0]["detail"]
    # la demande est écrite AVANT wafctl, l'issue après
    assert [x["action"] for x in c.audit()] == ["ai-ban-demande", "ai-ban"]
    assert corps["id"] in c.audit()[0]["detail"]
    ligne = c.lignes_journal()[-1]
    assert ligne["type"] == "ban" and ligne["id"] == corps["id"] and ligne["mode"] == "clic"
    assert ligne["conseil"] == "c-1" and ligne["jti"] == USAGER_AI["jti"] and ligne["fin"] == corps["fin"]


def test_ban_bloc_clic_passe_par_systemd_run(c):
    r = c.ban("203.0.113.0/24", duree_s=14400)
    assert r.status_code == 200, r.text
    argv = c.faux.appel("ban-bloc")
    assert argv[2] == "/usr/bin/systemd-run"
    assert argv == ADMIN_SYSTEMD_RUN + ["ban-bloc", "203.0.113.0/24", "14400s"]
    # le bloc déjà banni par l'administrateur est vérifié avant (wafctl blocs, lecture)
    assert c.faux.verbes() == ["blocs", "ban-bloc"]


def test_auto_refuse_une_adresse_seule(c):
    c.bans = _bloc_peuple(30)
    r = c.ban("203.0.113.5", mode="auto")
    assert r.status_code == 409 and r.json()["detail"]["motif"] == "pas_sur"
    assert "ban" not in c.faux.verbes()
    refus = [x for x in c.audit() if x["action"] == "ai-ban-refus"]
    assert len(refus) == 1 and "pas_sur" in refus[0]["detail"] and "203.0.113.5" in refus[0]["detail"]
    assert "auto" in refus[0]["detail"] and refus[0]["by"] == "ai-ban" and "nombre 1" in refus[0]["detail"]
    assert f"cle {USAGER_AI['cle']}" in refus[0]["detail"]


def test_auto_bloc_19_adresses_refuse(c):
    c.bans = _bloc_peuple(19)
    r = c.ban("203.0.113.0/24", mode="auto")
    assert r.status_code == 409 and r.json()["detail"]["motif"] == "pas_sur"
    assert "ban-bloc" not in c.faux.verbes()


@pytest.mark.parametrize("intrus", ["sqli", "waf"])
def test_auto_bloc_categorie_hors_liste_refuse(c, intrus):
    c.bans = _bloc_peuple(19) + [{"ip": "203.0.113.200", "reason": intrus}]
    r = c.ban("203.0.113.0/24", mode="auto")
    assert r.status_code == 409 and r.json()["detail"]["motif"] == "pas_sur"
    # 20 sûres et une de trop : toujours pas sûr (motifs ⊆ catégories sûres, pour TOUTES les adresses du bloc)
    c.bans = _bloc_peuple(20) + [{"ip": "203.0.113.201", "reason": intrus}]
    assert c.ban("203.0.113.0/24", mode="auto").json()["detail"]["motif"] == "pas_sur"
    assert "ban-bloc" not in c.faux.verbes()


def test_auto_bloc_sur_applique(c):
    # adresses hors du bloc (autre /24, IPv6) : ni comptées ni gênantes
    c.bans = _bloc_peuple(20) + [{"ip": "198.51.100.9", "reason": "sqli"}, {"ip": "2001:db8::5", "reason": "sqli"}]
    r = c.ban("203.0.113.0/24", mode="auto")
    assert r.status_code == 200, r.text
    assert c.faux.appel("ban-bloc")[-2:] == ["203.0.113.0/24", "86400s"]
    assert c.lignes_journal()[-1]["mode"] == "auto"


def test_auto_bloc_doublons_comptes_une_fois(c):
    c.bans = _bloc_peuple(19) + _bloc_peuple(19)
    assert c.ban("203.0.113.0/24", mode="auto").json()["detail"]["motif"] == "pas_sur"


def test_auto_duree_plus_de_24h_refuse(c):
    c.bans = _bloc_peuple(20)
    r = c.ban("203.0.113.0/24", duree_s=172800, mode="auto")
    assert r.status_code == 409 and r.json()["detail"]["motif"] == "duree"
    assert c.faux.appels == []


@pytest.mark.parametrize("cible", ["10.0.0.0/24", "203.0.113.0/23", "203.0.113.5/24", "2001:db8::1", "x"])
def test_formes_refusees_422(c, cible):
    r = c.ban(cible)
    assert r.status_code == 422
    assert c.faux.appels == [] and c.lignes_journal() == []


@pytest.mark.parametrize("cible", ["192.168.1.7", "127.0.0.1", "100.64.0.1", "224.0.0.1", "255.255.255.255",
                                   "0.0.0.0", "203.0.113.05", " 203.0.113.5", "203.0.113.5/32", "198.18.0.0/24",
                                   "::ffff:203.0.113.5", "203.0.113.0/24\n"])
def test_formes_non_globales_ou_non_canoniques_422(c, cible):
    assert c.ban(cible).status_code == 422
    assert c.faux.appels == []


def test_corps_malformes_422(c):
    base = {"geste": "ban", "cible": "198.51.100.7", "duree_s": 86400, "mode": "clic", "conseil": "c-1"}
    for corps in ({k: v for k, v in base.items() if k != "geste"},          # P9 : le geste est obligatoire
                  {**base, "geste": "unban"},
                  {**base, "inconnu": 1},                                     # extra = forbid
                  {**base, "duree_s": "86400"},                               # entier strict
                  {**base, "duree_s": True},
                  {**base, "mode": "force"},
                  {**base, "conseil": "a b"},
                  {**base, "motif": "x" * 201}):
        assert c.c.post("/ai/ban", json=corps).status_code == 422, corps
    assert c.c.post("/ai/ban", content=b"pas du json").status_code == 422
    assert c.c.post("/ai/ban", content=b"").status_code == 422
    assert c.faux.appels == []


def test_duree_clic_plus_de_7j_422(c):
    assert c.ban("198.51.100.7", duree_s=604801).status_code == 422
    assert c.ban("198.51.100.7", duree_s=3599).status_code == 422
    assert c.faux.appels == []


def test_plafond_auto_6e_refuse(c):
    now = int(time.time())
    c.journal(*[_ban_journal(f"192.0.2.{i}", now - 100 * i - 1, now + 80000, mode="auto") for i in range(5)])
    c.bans = _bloc_peuple(20)
    r = c.ban("203.0.113.0/24", mode="auto")
    assert r.status_code == 409 and r.json()["detail"]["motif"] == "plafond_auto"
    assert c.faux.appels == []
    # le clic n'est pas concerné par le plafond d'office
    assert c.ban("198.51.100.7").status_code == 200


def test_plafond_auto_jour_refuse(c):
    now = int(time.time())
    c.journal(*[_ban_journal(f"192.0.2.{i}", now - 3600 - 3000 * i, now + 1000, mode="auto") for i in range(20)])
    c.bans = _bloc_peuple(20)
    assert c.ban("203.0.113.0/24", mode="auto").json()["detail"]["motif"] == "plafond_auto"


def test_plafond_compte_31e_refuse(c):
    now = int(time.time())
    c.journal(*[_ban_journal(f"192.0.2.{i}", now - 60 * i - 1, now + 80000) for i in range(30)])
    r = c.ban("198.51.100.7")
    assert r.status_code == 409 and r.json()["detail"]["motif"] == "plafond_compte"
    assert c.faux.appels == []


def test_plafond_compte_jour_et_bans_annules_comptes(c):
    now = int(time.time())
    entrees = [_ban_journal(f"192.0.2.{i}", now - 3600 - 800 * i, now - 10) for i in range(100)]
    annules = [{"ts": "", "at": now - 5, "type": "annule", "id": e["id"], "cible": e["cible"]} for e in entrees[:50]]
    c.journal(*entrees, *annules)
    assert c.ban("198.51.100.7").json()["detail"]["motif"] == "plafond_compte"


def test_deja_actif(c):
    now = int(time.time())
    c.journal(_ban_journal("203.0.113.0/24", now - 10, now + 3600))
    r = c.ban("203.0.113.0/24")
    assert r.status_code == 409 and r.json()["detail"]["motif"] == "deja_actif"
    assert c.faux.appels == []


def test_deja_actif_annule_ou_echu_ne_compte_pas(c):
    now = int(time.time())
    a, b = _ban_journal("203.0.113.0/24", now - 10, now + 3600), _ban_journal("198.51.100.7", now - 9000, now - 10)
    c.journal(a, b, {"ts": "", "at": now - 5, "type": "annule", "id": a["id"], "cible": a["cible"]})
    assert c.ban("203.0.113.0/24").status_code == 200
    assert c.ban("198.51.100.7").status_code == 200


def test_deja_banni_par_le_waf_ou_l_administrateur_refuse(c):
    """Sans cette garde, « bannir ce qui l'est déjà, puis annuler son id » lèverait un ban du WAF ou de
    l'administrateur : ai-ban ne débannit que ce qu'il a posé."""
    c.bans = [{"ip": "198.51.100.7", "reason": "sqli"}]
    r = c.ban("198.51.100.7")
    assert r.status_code == 409 and r.json()["detail"]["motif"] == "deja_actif"
    c.faux.reponses["blocs"] = (0, json.dumps({"ok": True, "motif": None, "blocs": [
        {"bloc": "203.0.113.0/24", "debut": 1, "fin": int(time.time()) + 600000, "reste": 600000, "actif": True}]}), "")
    r = c.ban("203.0.113.0/24")
    assert r.status_code == 409 and r.json()["detail"]["motif"] == "deja_actif"
    assert "ban" not in c.faux.verbes() and "ban-bloc" not in c.faux.verbes()


def test_liste_des_blocs_illisible_refuse_503(c):
    c.faux.reponses["blocs"] = (9, '{"ok": false, "motif": "etat"}', "")
    r = c.ban("203.0.113.0/24")
    assert r.status_code == 503 and "ban-bloc" not in c.faux.verbes()


def test_refus_wafctl_protegee_rend_409_motif(c):
    c.faux.reponses["ban-bloc"] = (3, '{"ok": false, "motif": "protegee"}\n', "")
    r = c.ban("203.0.113.0/24")
    assert r.status_code == 409 and r.json()["detail"]["motif"] == "protegee"
    assert c.lignes_journal() == []
    assert [x["action"] for x in c.audit()] == ["ai-ban-demande", "ai-ban-refus"]
    c.faux.reponses["ban"] = (1, "", "refus:box\n[..] ERROR: x\n")
    r = c.ban("198.51.100.7")
    assert r.status_code == 409 and r.json()["detail"]["motif"] == "box"


@pytest.mark.parametrize("code,sortie,erreur,statut,motif", [
    (2, '{"ok": false, "motif": "privee"}', "", 409, "privee"),
    (5, '{"ok": false, "motif": "pair"}', "", 409, "pair"),
    (6, '{"ok": false, "motif": "garde_illisible"}', "", 409, "garde_illisible"),
    (7, '{"ok": false, "motif": "nft"}', "", 409, "nft"),
    (8, '{"ok": false, "motif": "duree"}', "", 409, "duree"),
    (9, '{"ok": false, "motif": "etat"}', "", 503, "etat"),
    (10, '{"ok": false, "motif": "audit"}', "", 503, "audit"),
    (11, '{"ok": false, "motif": "incoherent"}', "", 500, "incoherent"),
    (64, '{"ok": false, "motif": "usage"}', "", 500, "usage"),
    (1, "", "sudo: a password is required", 503, "wafctl"),
    (1, '{"ok": false, "motif": "<script>"}', "refus:Inconnu", 503, "wafctl"),
])
def test_codes_wafctl_etat_audit_incoherent_jamais_409(c, code, sortie, erreur, statut, motif):
    c.faux.reponses["ban-bloc"] = (code, sortie, erreur)
    r = c.ban("203.0.113.0/24")
    assert r.status_code == statut and r.json()["detail"]["motif"] == motif
    assert c.lignes_journal() == []


def test_wafctl_injoignable_ou_delai_503_et_retour_arriere(c, monkeypatch):
    appels = []

    def lent(argv):
        appels.append(list(argv))
        if "ban" in argv:
            raise subprocess.TimeoutExpired(argv, 30)
        return subprocess.CompletedProcess(argv, 0, "", "")
    monkeypatch.setattr(c.g, "_executer", lent)
    r = c.ban("198.51.100.7")
    assert r.status_code == 503 and r.json()["detail"]["motif"] == "wafctl"
    assert appels[-1] == ["sudo", "-n", "/usr/sbin/wafctl", "unban", "198.51.100.7"]
    assert c.lignes_journal() == []


def test_audit_echoue_le_ban_est_retire_et_500(c, monkeypatch):
    _audit_qui_echoue(c, monkeypatch, "ai-ban")
    r = c.ban("198.51.100.7")
    assert r.status_code == 500 and r.json()["detail"]["motif"] == "audit"
    assert c.faux.verbes()[-2:] == ["ban", "unban"]
    assert c.faux.appels[-1] == ["sudo", "-n", "/usr/sbin/wafctl", "unban", "198.51.100.7"]
    types = [x["type"] for x in c.lignes_journal()]
    assert types == ["ban", "annule"] and c.lignes_journal()[1]["cause"] == "audit"
    # le bloc : retiré par systemd-run unban-bloc
    r = c.ban("203.0.113.0/24")
    assert r.status_code == 500
    assert c.faux.appels[-1] == ADMIN_SYSTEMD_RUN + ["unban-bloc", "203.0.113.0/24"]
    # rien n'est resté actif : l'état ne montre aucun ban
    assert c.c.get("/ai/etat").json()["actifs"] == []


def test_audit_et_retour_arriere_echouent_incoherent(c, monkeypatch):
    _audit_qui_echoue(c, monkeypatch, "ai-ban")
    c.faux.reponses["unban"] = (1, "", "nft: erreur")
    r = c.ban("198.51.100.7")
    assert r.status_code == 500 and r.json()["detail"]["motif"] == "incoherent"


def test_journal_impossible_le_ban_est_retire(c, monkeypatch, tmp_path):
    monkeypatch.setattr(c.g, "JOURNAL_AI", tmp_path / "absent" / "ai-ban.jsonl")
    r = c.ban("198.51.100.7")
    assert r.status_code == 503 and r.json()["detail"]["motif"] == "journal"
    assert c.faux.verbes() == ["ban", "unban"]
    assert not [x for x in c.audit() if x["action"] == "ai-ban"]


def test_journal_illisible_refuse_avant_wafctl(c, monkeypatch, tmp_path):
    dossier = tmp_path / "journal-dossier"
    dossier.mkdir()
    monkeypatch.setattr(c.g, "JOURNAL_AI", dossier)        # un dossier : illisible comme fichier
    assert c.ban("198.51.100.7").status_code == 503
    assert c.c.get("/ai/etat").status_code == 503
    assert c.faux.appels == []


def test_journal_lien_symbolique_refuse(c, monkeypatch, tmp_path):
    cible = tmp_path / "ailleurs.jsonl"
    cible.write_text("")
    lien = tmp_path / "lien.jsonl"
    lien.symlink_to(cible)
    monkeypatch.setattr(c.g, "JOURNAL_AI", lien)
    assert c.ban("198.51.100.7").status_code == 503
    assert cible.read_text() == ""


# ── POST /ai/unban ─────────────────────────────────────────────────────
def test_unban_seulement_un_id_du_journal(c):
    r = c.c.post("/ai/unban", json={"geste": "unban", "id": "f" * 32})
    assert r.status_code == 404
    assert c.c.post("/ai/unban", json={"ip": "198.51.100.7"}).status_code == 422
    assert c.c.post("/ai/unban", json={"geste": "unban", "id": "f" * 32, "ip": "198.51.100.7"}).status_code == 422
    assert c.c.post("/ai/unban", json={"id": "f" * 32}).status_code == 422            # P9 : geste obligatoire
    assert c.c.post("/ai/unban", json={"geste": "unban", "id": "F" * 32}).status_code == 422
    # le corps d'un ban ne vaut pas pour un débannissement (P9)
    assert c.c.post("/ai/unban", json={"geste": "ban", "cible": "198.51.100.7", "duree_s": 3600,
                                       "mode": "clic", "conseil": "c"}).status_code == 422
    assert c.faux.appels == []


def test_unban_annule_puis_deja_annule(c):
    ident = c.ban("198.51.100.7").json()["id"]
    r = c.c.post("/ai/unban", json={"geste": "unban", "id": ident})
    assert r.status_code == 200 and r.json() == {"id": ident, "etat": "annule"}
    assert c.faux.appels[-1] == ["sudo", "-n", "/usr/sbin/wafctl", "unban", "198.51.100.7"]
    unban = [x for x in c.audit() if x["action"] == "ai-unban"]
    assert len(unban) == 1 and ident in unban[0]["detail"] and unban[0]["by"] == "ai-ban"
    assert c.lignes_journal()[-1]["type"] == "annule" and c.lignes_journal()[-1]["id"] == ident
    n = len(c.faux.appels)
    r = c.c.post("/ai/unban", json={"geste": "unban", "id": ident})
    assert r.json() == {"id": ident, "etat": "deja_annule"} and len(c.faux.appels) == n
    # la cible est de nouveau bannissable
    assert c.ban("198.51.100.7").status_code == 200


def test_unban_bloc_passe_par_systemd_run(c):
    ident = c.ban("203.0.113.0/24").json()["id"]
    assert c.c.post("/ai/unban", json={"geste": "unban", "id": ident}).json()["etat"] == "annule"
    assert c.faux.appels[-1] == ADMIN_SYSTEMD_RUN + ["unban-bloc", "203.0.113.0/24"]


def test_unban_echu_idempotent(c):
    now = int(time.time())
    e = _ban_journal("198.51.100.7", now - 9000, now - 1)
    c.journal(e)
    r = c.c.post("/ai/unban", json={"geste": "unban", "id": e["id"]})
    assert r.status_code == 200 and r.json() == {"id": e["id"], "etat": "echu"}
    assert c.faux.appels == []


def test_unban_wafctl_refuse_rien_n_est_journalise(c):
    ident = c.ban("198.51.100.7").json()["id"]
    c.faux.reponses["unban"] = (1, "", "sudo: a password is required")
    r = c.c.post("/ai/unban", json={"geste": "unban", "id": ident})
    assert r.status_code == 503
    assert c.lignes_journal()[-1]["type"] == "ban"
    assert [x["action"] for x in c.audit()][-1] == "ai-unban-echec"


def test_unban_audit_impossible_rien_n_est_leve(c, monkeypatch, tmp_path):
    ident = c.ban("198.51.100.7").json()["id"]
    n = len(c.faux.appels)
    monkeypatch.setattr(c.waf, "AUDIT_LOG", tmp_path / "absent" / "audit.log")
    r = c.c.post("/ai/unban", json={"geste": "unban", "id": ident})
    assert r.status_code == 503 and r.json()["detail"]["motif"] == "audit"
    assert len(c.faux.appels) == n


# ── GET /ai/etat ───────────────────────────────────────────────────────
def test_etat_rend_actifs_et_compteurs(c):
    now = int(time.time())
    actif = _ban_journal("203.0.113.0/24", now - 100, now + 3600, mode="auto")
    echu = _ban_journal("198.51.100.7", now - 7200, now - 10)
    annule = _ban_journal("198.51.100.8", now - 200, now + 3600)
    vieux = _ban_journal("198.51.100.9", now - 90000, now + 100000, mode="auto")
    c.journal(actif, echu, annule, vieux, {"ts": "", "at": now - 5, "type": "annule", "id": annule["id"],
                                           "cible": annule["cible"]}, "pas un objet", {"type": "ban", "id": "x"})
    with open(c.g.JOURNAL_AI, "a") as f:
        f.write("{tronqué\n")
    r = c.c.get("/ai/etat")
    assert r.status_code == 200, r.text
    e = r.json()
    assert sorted(a["id"] for a in e["actifs"]) == sorted([actif["id"], vieux["id"]])
    assert {"id", "cible", "fin", "mode"} == set(e["actifs"][0])
    assert e["compteurs"] == {"auto_heure": 1, "auto_jour": 1, "compte_heure": 2, "compte_jour": 3}
    assert e["plafonds"] == {"auto_heure": 5, "auto_jour": 20, "compte_heure": 30, "compte_jour": 100}
    assert c.faux.appels == []


def test_etat_refuse_un_corps(c):
    """P9 : le jeton lie le corps ; /ai/etat n'en accepte aucun (un jeton frappé pour un geste n'y vaut rien)."""
    r = c.c.request("GET", "/ai/etat", content=b'{"geste": "ban"}')
    assert r.status_code == 422


def test_etat_sans_journal(c):
    e = c.c.get("/ai/etat").json()
    assert e["actifs"] == [] and e["compteurs"]["compte_jour"] == 0


# ── gardes réelles ─────────────────────────────────────────────────────
@pytest.fixture
def c_garde(monkeypatch, tmp_path):
    """Les routes avec la VRAIE garde : box `gk2`, arbre des clés dans `tmp_path`, état neuf."""
    from fastapi.testclient import TestClient
    from secubox_core import auth
    from secubox_core import compte_service as cs
    waf = _importer_waf()
    from api import gestes_ia as g
    waf.app.dependency_overrides.clear()
    monkeypatch.setattr(cs, "DOSSIER_COMPTES_SERVICE", str(tmp_path / "comptes"))
    monkeypatch.setattr(auth, "_proprietaire_attendu", lambda chemin: os.getuid())
    monkeypatch.setattr(auth, "nom_box_locale", lambda: "gk2")
    monkeypatch.setattr(auth, "AUDIT_PILOTAGE", str(tmp_path / "audit-garde.log"))
    monkeypatch.setattr(auth, "_secret", lambda: "secret-de-la-box-gk2-assez-long-pour-hs256")
    monkeypatch.setattr(cs, "_rejeu", cs._Rejeu())
    monkeypatch.setattr(cs, "_cache_cles", {})
    monkeypatch.setattr(cs, "_derniers_refus", {})
    monkeypatch.setattr(cs, "_minuterie", {"active": None})
    monkeypatch.setattr(cs, "_armer_minuterie", lambda: None)
    monkeypatch.setattr(cs, "_DEMARRAGE", 0.0)
    monkeypatch.setenv("SECUBOX_TABLEAU_DE_BORD", "0")
    monkeypatch.setenv("SECUBOX_WAF_GESTES_IA", "1")          # le processus désigné (agrégateur, tâche 5)
    monkeypatch.setattr(waf, "AUDIT_LOG", tmp_path / "audit.log")
    monkeypatch.setattr(g, "JOURNAL_AI", tmp_path / "ai-ban.jsonl")
    monkeypatch.setattr(g, "BANS_WAF", tmp_path / "bans.jsonl")
    _regroupement_neuf(monkeypatch, g)
    faux = FauxWafctl()
    monkeypatch.setattr(g, "_executer", faux)
    monkeypatch.setitem(g._config, "bans", lambda: [])
    ban_appels = []
    monkeypatch.setattr(waf, "_ban_ip", lambda *a: (ban_appels.append(a) or (True, "ok")))
    try:
        yield TestClient(waf.app), auth, cs, faux, ban_appels, tmp_path
    finally:
        waf.app.dependency_overrides.clear()


def _cle_posee(cs, tmp_path):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    objet = Ed25519PrivateKey.generate()
    pem_pub = objet.public_key().public_bytes(serialization.Encoding.PEM,
                                              serialization.PublicFormat.SubjectPublicKeyInfo)
    pem_prive = objet.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                    serialization.NoEncryption())
    dossier = tmp_path / "comptes" / "ai-ban"
    dossier.mkdir(parents=True)
    os.chmod(tmp_path / "comptes", 0o755)
    os.chmod(dossier, 0o755)
    f = dossier / f"{cs.empreinte(pem_pub)}.pub"
    f.write_bytes(pem_pub)
    os.chmod(f, 0o644)
    return pem_prive


def test_routes_ai_refusent_session_admin(c_garde):
    client, auth, _cs, faux, _, _ = c_garde
    entete = {"Authorization": f"Bearer {auth.create_token('admin')}"}
    assert client.get("/ai/etat", headers=entete).status_code == 401
    assert client.post("/ai/ban", headers=entete, json={"geste": "ban", "cible": "198.51.100.7", "duree_s": 3600,
                                                         "mode": "clic", "conseil": "c"}).status_code == 401
    assert client.post("/ai/unban", headers=entete, json={"geste": "unban", "id": "f" * 32}).status_code == 401
    assert client.get("/ai/etat").status_code == 401                       # sans jeton
    assert faux.appels == []


def test_post_ban_refuse_jeton_ai_ban(c_garde):
    client, _auth, cs, _, ban_appels, tmp_path = c_garde
    pem_prive = _cle_posee(cs, tmp_path)
    corps = json.dumps({"ip": "198.51.100.7", "duration": "4h"}).encode()
    jeton = cs.frapper_jeton(pem_prive, "ai-ban", "gk2", corps, time.time())
    r = client.post("/ban", content=corps, headers={"Authorization": f"Bearer {jeton}",
                                                     "Content-Type": "application/json"})
    assert r.status_code == 401 and ban_appels == []


def test_jeton_ai_ban_reel_bout_en_bout(c_garde):
    """La vraie garde lit et borne le corps AVANT la route (P11) ; la route le relit depuis le cache, le valide,
    bannit ; le même jeton rejoué est refusé."""
    client, _auth, cs, faux, _, tmp_path = c_garde
    pem_prive = _cle_posee(cs, tmp_path)
    corps = json.dumps({"geste": "ban", "cible": "198.51.100.7", "duree_s": 3600, "mode": "clic",
                        "conseil": "c-9"}).encode()
    entete = {"Authorization": f"Bearer {cs.frapper_jeton(pem_prive, 'ai-ban', 'gk2', corps, time.time())}",
              "Content-Type": "application/json"}
    r = client.post("/ai/ban", content=corps, headers=entete)
    assert r.status_code == 200, r.text
    assert faux.appel("ban") == ["sudo", "-n", "/usr/sbin/wafctl", "ban", "198.51.100.7", "3600s"]
    assert client.post("/ai/ban", content=corps, headers=entete).status_code == 401      # rejeu
    # un jeton frappé pour /ai/etat (corps vide) ne vaut pas pour /ai/ban (corps vide refusé), et inversement
    vide = {"Authorization": f"Bearer {cs.frapper_jeton(pem_prive, 'ai-ban', 'gk2', b'', time.time())}"}
    assert client.post("/ai/ban", headers=vide).status_code == 422
    etat = {"Authorization": f"Bearer {cs.frapper_jeton(pem_prive, 'ai-ban', 'gk2', b'', time.time())}"}
    e = client.get("/ai/etat", headers=etat)
    assert e.status_code == 200 and e.json()["actifs"][0]["cible"] == "198.51.100.7"
    audit = [json.loads(x) for x in (tmp_path / "audit.log").read_text().splitlines()]
    assert [x["action"] for x in audit] == ["ai-ban-demande", "ai-ban"] and audit[1]["by"] == "ai-ban"
    assert all("Bearer" not in json.dumps(x) and "eyJ" not in json.dumps(x) for x in audit)


# ── exception, postinst, wafctl ────────────────────────────────────────
def test_exception_rules_code_ecrite():
    t = RULES_CODE.read_text()
    assert "#3716" in t and "require_ai_ban" in t and "test_gestes_ia_3716.py" in t
    ligne = next(x for x in t.splitlines() if "require_ai_ban" in x)
    assert ligne.startswith("| § 3 garde |") and "/ai/ban" in ligne and "/ai/unban" in ligne and "/ai/etat" in ligne
    assert "198.51.100.0/24" in ligne and "Reste ouvert" in ligne and "bans.jsonl" in ligne


def test_routes_branchees_sur_l_application():
    waf = _importer_waf()
    from secubox_core.compte_service import require_ai_ban
    routes = {(r.path, tuple(sorted(r.methods))): r for r in waf.app.routes if getattr(r, "path", "").startswith("/ai/")}
    assert set(routes) == {("/ai/ban", ("POST",)), ("/ai/unban", ("POST",)), ("/ai/etat", ("GET",))}
    for route in routes.values():
        assert require_ai_ban in [d.call for d in route.dependant.dependencies]
        assert route.body_field is None                     # P11 : aucun modèle de corps FastAPI
        assert not __import__("asyncio").iscoroutinefunction(route.endpoint)   # § 6 : pool de fils


# ── UN seul processus sert /ai/* (tâche 5) ─────────────────────────────
def test_processus_non_designe_refuse_avant_le_jeton(c, monkeypatch):
    """La mémoire de rejeu, le verrou et les plafonds sont PAR PROCESSUS : seul l'agrégateur (drapeau posé par son
    drop-in) sert /ai/*. Ailleurs (secubox-waf.service sur waf.sock, groupd), 503 `processus` AVANT toute lecture du
    jeton ou du corps : aucun jti n'y est consommé, aucun wafctl lancé, aucune ligne d'audit."""
    c.waf.app.dependency_overrides.clear()                      # la vraie garde : sans drapeau, elle n'est pas atteinte
    for valeur in (None, "", "0", "oui", " 1"):
        if valeur is None:
            monkeypatch.delenv("SECUBOX_WAF_GESTES_IA", raising=False)
        else:
            monkeypatch.setenv("SECUBOX_WAF_GESTES_IA", valeur)
        for r in (c.ban("198.51.100.7"), c.c.post("/ai/unban", json={"geste": "unban", "id": "a" * 32}),
                  c.c.get("/ai/etat")):
            assert r.status_code == 503, (valeur, r.text)
            assert r.json() == {"detail": {"motif": "processus"}}
    assert c.faux.appels == [] and c.audit() == [] and c.lignes_journal() == []


def test_processus_designe_atteint_la_garde(c, monkeypatch):
    c.waf.app.dependency_overrides.clear()
    monkeypatch.setenv("SECUBOX_WAF_GESTES_IA", "1")
    assert c.c.get("/ai/etat").status_code == 401             # le drapeau ouvre la route, pas la garde


def test_le_drapeau_passe_avant_la_garde():
    waf = _importer_waf()
    from api import gestes_ia as g
    from secubox_core.compte_service import require_ai_ban
    for route in (r for r in waf.app.routes if getattr(r, "path", "").startswith("/ai/")):
        appels = [d.call for d in route.dependant.dependencies]
        assert appels.index(g.processus_designe) < appels.index(require_ai_ban)


def test_postinst_cree_le_dossier_des_cles_root():
    t = POSTINST.read_text()
    for d in ("/etc/secubox-comptes-service", "/etc/secubox-comptes-service/ai-ban"):
        assert f"mkdir -p {d}" in t
        assert f"chown root:root {d}" in t and f"chmod 0755 {d}" in t
    assert not [x for x in t.splitlines() if "secubox-comptes-service" in x and re.search(r"\brm\b", x)]
    assert subprocess.run(["sh", "-n", str(POSTINST)], check=False, timeout=10).returncode == 0


@pytest.fixture
def wafctl_cles(tmp_path):
    """Une copie de wafctl dont la racine des clés et l'audit sont dans `tmp_path` ; `install` sans -o/-g (on n'est
    pas root)."""
    if not shutil.which("openssl") or not shutil.which("jq"):
        pytest.skip("openssl et jq requis")
    t = WAFCTL.read_text()
    assert 'CLES_RACINE="/etc/secubox-comptes-service"' in t and 'AUDIT_LOG="/var/log/secubox/audit.log"' in t
    racine, audit = tmp_path / "comptes", tmp_path / "audit.log"
    copie = tmp_path / "wafctl"
    copie.write_text(t.replace('CLES_RACINE="/etc/secubox-comptes-service"', f'CLES_RACINE="{racine}"')
                      .replace('AUDIT_LOG="/var/log/secubox/audit.log"', f'AUDIT_LOG="{audit}"'))
    bin_ = tmp_path / "bin"
    bin_.mkdir()
    faux_install = bin_ / "install"
    faux_install.write_text('#!/bin/bash\nargs=()\nwhile [ "$#" -gt 0 ]; do\n  case "$1" in -o|-g) shift 2 ;; '
                            '*) args+=("$1"); shift ;; esac\ndone\nexec /usr/bin/install "${args[@]}"\n')
    faux_install.chmod(0o755)
    env = {**os.environ, "PATH": f"{bin_}:{os.environ['PATH']}"}

    def lancer(*args):
        return subprocess.run(["bash", str(copie), "cle-ai-ban", *args], check=False, timeout=30,
                              capture_output=True, text=True, env=env)
    return lancer, racine / "ai-ban", audit


def _pub_pem(tmp_path, nom):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    pem = Ed25519PrivateKey.generate().public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    f = tmp_path / nom
    f.write_bytes(pem)
    return f, pem


def test_wafctl_cle_ai_ban_verifie_l_empreinte(wafctl_cles, tmp_path):
    from secubox_core import compte_service as cs
    lancer, dossier, audit = wafctl_cles
    t = WAFCTL.read_text()
    assert "cle-ai-ban)" in t and "openssl pkey -pubin" in t and "sha256sum" in t
    f1, pem1 = _pub_pem(tmp_path, "un.pub")
    r = lancer("ajouter", str(f1))
    assert r.returncode == 0, r.stderr
    kid1 = cs.empreinte(pem1)
    assert [p.name for p in dossier.iterdir()] == [f"{kid1}.pub"]
    assert oct((dossier / f"{kid1}.pub").stat().st_mode & 0o777) == "0o644"
    assert cs.empreinte((dossier / f"{kid1}.pub").read_bytes()) == kid1       # relue par compte_service
    lignes = [json.loads(x) for x in audit.read_text().splitlines()]
    assert lignes[-1]["action"] == "cle-ai-ban-ajout" and kid1 in lignes[-1]["detail"] and lignes[-1]["by"] == "wafctl"
    # deux clés au plus : la troisième est refusée (sinon compte_service n'en reconnaîtrait aucune)
    f2, pem2 = _pub_pem(tmp_path, "deux.pub")
    assert lancer("ajouter", str(f2)).returncode == 0
    f3, _ = _pub_pem(tmp_path, "trois.pub")
    r = lancer("ajouter", str(f3))
    assert r.returncode != 0 and len(list(dossier.iterdir())) == 2
    # la même clé deux fois : rien de changé
    assert lancer("ajouter", str(f1)).returncode == 0 and len(list(dossier.iterdir())) == 2
    r = lancer("lister")
    assert r.returncode == 0 and kid1 in r.stdout and cs.empreinte(pem2) in r.stdout and r.stdout.count("valide") == 2
    assert lancer("retirer", kid1).returncode == 0
    assert [p.name for p in dossier.iterdir()] == [f"{cs.empreinte(pem2)}.pub"]
    assert json.loads(audit.read_text().splitlines()[-1])["action"] == "cle-ai-ban-retrait"
    assert lancer("retirer", "--toutes").returncode == 0 and list(dossier.iterdir()) == []
    assert json.loads(audit.read_text().splitlines()[-1])["action"] == "cle-ai-ban-retrait"


def test_wafctl_cle_ai_ban_refuse_ce_qui_n_est_pas_ed25519(wafctl_cles, tmp_path):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    lancer, dossier, _ = wafctl_cles
    ecdsa = tmp_path / "ec.pub"
    ecdsa.write_bytes(ec.generate_private_key(ec.SECP256R1()).public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    illisible = tmp_path / "x.pub"
    illisible.write_text("pas une clé\n")
    for f in (ecdsa, illisible, tmp_path / "absent.pub"):
        assert lancer("ajouter", str(f)).returncode != 0
    assert not dossier.exists() or list(dossier.iterdir()) == []
    assert lancer("retirer", "../etc").returncode != 0
    assert lancer("retirer").returncode != 0
    assert lancer("inconnu").returncode != 0


def test_wafctl_cle_ai_ban_audit_impossible_retire_la_cle(wafctl_cles, tmp_path):
    lancer, dossier, audit = wafctl_cles
    audit.mkdir()                                       # un dossier : l'ajout seul ne peut pas l'écrire
    f1, _ = _pub_pem(tmp_path, "un.pub")
    assert lancer("ajouter", str(f1)).returncode != 0
    assert list(dossier.iterdir()) == []


def test_wafctl_cle_ai_ban_hors_sudoers():
    sudoers = (COMPOSANT / "sudoers" / "secubox-waf").read_text()
    assert not [x for x in sudoers.splitlines() if "cle-ai-ban" in x and not x.lstrip().startswith("#")]


# ── Revue 1 : couverture par une autre source (P12), lecture stricte, regroupement, demande ─────────────────────
def _bans_waf_journal(c, *records):
    with open(c.g.BANS_WAF, "a", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r) + "\n")


def _rec(ip, at, exp, action="ban"):
    return {"ip": ip, "cat": "sqli", "sev": "high", "at": at, "exp": exp, "action": action}


def _unban(c, ident):
    return c.c.post("/ai/unban", json={"geste": "unban", "id": ident})


@pytest.mark.parametrize("dernier", ["ban_futur", "ban_permanent"])
def test_unban_adresse_couverte_par_le_waf_n_est_pas_levee(c, dernier):
    now = int(time.time())
    ident = c.ban("198.51.100.7").json()["id"]
    exp = now + 7200 if dernier == "ban_futur" else 0
    _bans_waf_journal(c, _rec("198.51.100.9", now, now + 9000), _rec("198.51.100.7", now - 50, exp))
    r = _unban(c, ident)
    assert r.status_code == 200 and r.json() == {"id": ident, "etat": "couvert"}
    assert "unban" not in c.faux.verbes()
    assert c.lignes_journal()[-1]["type"] == "annule" and c.lignes_journal()[-1]["cause"] == "couvert"
    couvert = [x for x in c.audit() if x["action"] == "ai-unban-couvert"]
    assert len(couvert) == 1 and ident in couvert[0]["detail"] and couvert[0]["by"] == "ai-ban"
    assert _unban(c, ident).json()["etat"] == "deja_annule"


@pytest.mark.parametrize("records", [
    [],                                                                    # sbxwaf n'a jamais banni l'adresse
    [("198.51.100.7", -9000, -10, "ban")],                                 # échu
    [("198.51.100.7", -100, 7200, "ban"), ("198.51.100.7", -10, 0, "unban")],   # levé depuis
    [("198.51.100.8", -10, 7200, "ban")],                                  # une autre adresse
])
def test_unban_adresse_non_couverte_est_levee(c, records):
    now = int(time.time())
    ident = c.ban("198.51.100.7").json()["id"]
    _bans_waf_journal(c, *[_rec(ip, now + at, (now + exp) if exp else 0, action) for ip, at, exp, action in records])
    r = _unban(c, ident)
    assert r.json()["etat"] == "annule" and c.faux.appels[-1][-2:] == ["unban", "198.51.100.7"]


def test_unban_bans_waf_illisible_503_rien_n_est_leve(c, monkeypatch, tmp_path):
    ident = c.ban("198.51.100.7").json()["id"]
    dossier = tmp_path / "bans-dossier"
    dossier.mkdir()
    monkeypatch.setattr(c.g, "BANS_WAF", dossier)
    r = _unban(c, ident)
    assert r.status_code == 503 and r.json()["detail"]["motif"] == "etat"
    assert "unban" not in c.faux.verbes() and c.lignes_journal()[-1]["type"] == "ban"
    lien = tmp_path / "lien.jsonl"
    lien.symlink_to(tmp_path / "ailleurs.jsonl")
    monkeypatch.setattr(c.g, "BANS_WAF", lien)
    assert _unban(c, ident).status_code == 503


def test_unban_echeance_illisible_503(c):
    now = int(time.time())
    ident = c.ban("198.51.100.7").json()["id"]
    _bans_waf_journal(c, {"ip": "198.51.100.7", "at": now, "exp": "demain", "action": "ban"})
    assert _unban(c, ident).status_code == 503 and "unban" not in c.faux.verbes()


def _blocs(c, bloc, fin):
    c.faux.reponses["blocs"] = (0, json.dumps({"ok": True, "motif": None, "blocs": [
        {"bloc": bloc, "debut": 1, "fin": fin, "reste": max(0, fin - int(time.time())), "actif": True}]}), "")


def test_unban_bloc_repris_plus_tard_par_l_administrateur_n_est_pas_leve(c):
    r = c.ban("203.0.113.0/24", duree_s=3600)
    ident, fin = r.json()["id"], r.json()["fin"]
    _blocs(c, "203.0.113.0/24", fin + 6)
    r = _unban(c, ident)
    assert r.json() == {"id": ident, "etat": "couvert"} and "unban-bloc" not in c.faux.verbes()


def test_unban_bloc_a_sa_propre_fin_est_leve(c):
    r = c.ban("203.0.113.0/24", duree_s=3600)
    ident, fin = r.json()["id"], r.json()["fin"]
    _blocs(c, "203.0.113.0/24", fin + 5)                    # marge : la même fin, à l'arrondi près
    assert _unban(c, ident).json()["etat"] == "annule"
    assert c.faux.appels[-1] == ADMIN_SYSTEMD_RUN + ["unban-bloc", "203.0.113.0/24"]


def test_unban_bloc_liste_illisible_503(c):
    ident = c.ban("203.0.113.0/24").json()["id"]
    c.faux.reponses["blocs"] = (9, '{"ok": false, "motif": "etat"}', "")
    r = _unban(c, ident)
    assert r.status_code == 503 and r.json()["detail"]["motif"] == "etat"
    assert "unban-bloc" not in c.faux.verbes()


def test_unban_couvert_audit_impossible_rien_n_est_clos(c, monkeypatch):
    now = int(time.time())
    ident = c.ban("198.51.100.7").json()["id"]
    _bans_waf_journal(c, _rec("198.51.100.7", now, now + 7200))
    _audit_qui_echoue(c, monkeypatch, "ai-unban-couvert")
    r = _unban(c, ident)
    assert r.status_code == 503 and r.json()["detail"]["motif"] == "audit"
    assert c.lignes_journal()[-1]["type"] == "ban"


@pytest.mark.parametrize("mode,cible", [("clic", "198.51.100.7"), ("auto", "203.0.113.0/24")])
def test_waf_ban_illisible_refuse_503_sans_ban(c, monkeypatch, mode, cible):
    def illisible():
        raise c.g.Illisible("nft : code 1")
    monkeypatch.setitem(c.g._config, "bans", illisible)
    r = c.ban(cible, mode=mode)
    assert r.status_code == 503 and r.json()["detail"]["motif"] == "etat"
    assert "ban" not in c.faux.verbes() and "ban-bloc" not in c.faux.verbes()
    assert [x["action"] for x in c.audit()] == ["ai-ban-echec"]


@pytest.mark.parametrize("reponse", [
    (1, "", "Error: No such file or directory; did you mean table 'secubox' in family inet?"),
    (0, "", ""),
    (0, "pas du json", ""),
    (0, json.dumps({"nftables": [{"metainfo": {}}]}), ""),
    (0, json.dumps({"nftables": [{"set": {"name": "autre", "elem": []}}]}), ""),
])
def test_lire_waf_ban_strict(c, reponse):
    c.faux.reponses["nft"] = reponse
    with pytest.raises(c.g.Illisible):
        c.g.lire_waf_ban()


def test_lire_waf_ban_et_bans_stricts_sans_geoip(c, monkeypatch):
    c.faux.reponses["nft"] = (0, json.dumps({"nftables": [{"metainfo": {}}, {"set": {"name": "waf_ban", "elem": [
        {"elem": {"val": "203.0.113.1", "timeout": 3600, "expires": 100}}, "203.0.113.2",
        {"elem": {"val": {"prefix": {}}}}]}}]}), "")
    assert c.g.lire_waf_ban() == {"203.0.113.1", "203.0.113.2"}
    assert c.faux.appels[-1] == ["sudo", "-n", "/usr/sbin/nft", "-j", "list", "set", "inet", "secubox", "waf_ban"]
    monkeypatch.setattr(c.waf, "_raisons_recentes", lambda: {"203.0.113.1": "scanners"})
    monkeypatch.setattr(c.waf, "_get_geoip_reader", lambda: (_ for _ in ()).throw(AssertionError("GeoIP")))
    assert c.waf._bans_stricts() == [{"ip": "203.0.113.1", "reason": "scanners"}, {"ip": "203.0.113.2", "reason": "waf"}]


def test_main_branche_le_lecteur_strict():
    waf = _importer_waf()
    from api import gestes_ia as g
    assert g._config["bans"] is waf._bans_stricts


def test_refus_repetes_regroupes(c, monkeypatch):
    instant = [1000.0]
    monkeypatch.setattr(c.g, "_horloge", lambda: instant[0])
    for _ in range(3):
        assert c.ban("203.0.113.5", mode="auto").status_code == 409            # pas_sur
    refus = [x for x in c.audit() if x["action"] == "ai-ban-refus"]
    assert len(refus) == 1 and "nombre 1" in refus[0]["detail"]
    assert c.g._minuterie["active"] == "armee"
    assert c.ban("203.0.113.6", mode="clic", duree_s=604800).status_code == 200   # autre chose : pas de ligne
    instant[0] += c.g.INTERVALLE_AUDIT_S + 1
    assert c.ban("203.0.113.7", mode="auto").status_code == 409
    refus = [x for x in c.audit() if x["action"] == "ai-ban-refus"]
    assert len(refus) == 2 and "nombre 3" in refus[1]["detail"] and "203.0.113.7" in refus[1]["detail"]
    # la minuterie écrit les refus restés en attente
    assert c.ban("203.0.113.8", mode="auto").status_code == 409
    instant[0] += c.g.INTERVALLE_AUDIT_S + 1
    c.g._vider_en_attente()
    refus = [x for x in c.audit() if x["action"] == "ai-ban-refus"]
    assert len(refus) == 3 and "nombre 1" in refus[2]["detail"] and "203.0.113.8" in refus[2]["detail"]


def test_pannes_repetees_regroupees(c):
    c.faux.reponses["ban"] = (1, "", "sudo: a password is required")
    for _ in range(4):
        assert c.ban("198.51.100.7").status_code == 503
    echecs = [x for x in c.audit() if x["action"] == "ai-ban-echec"]
    assert len(echecs) == 1 and "nombre 1" in echecs[0]["detail"]


def test_demande_non_auditee_rien_n_est_fait(c, monkeypatch):
    _audit_qui_echoue(c, monkeypatch, "ai-ban-demande")
    r = c.ban("198.51.100.7")
    assert r.status_code == 503 and r.json()["detail"]["motif"] == "audit"
    assert "ban" not in c.faux.verbes() and c.lignes_journal() == []


def test_horloge_reculee_ne_fait_pas_sauter_le_plafond(c):
    now = int(time.time())
    c.journal(*[_ban_journal(f"192.0.2.{i}", now + 5000, now + 90000) for i in range(30)])
    assert c.ban("198.51.100.7").json()["detail"]["motif"] == "plafond_compte"
    e = c.c.get("/ai/etat").json()
    assert e["compteurs"]["compte_heure"] == 30


@pytest.fixture
def wafctl_unban(tmp_path):
    """wafctl réel (cmd_unban), avec un faux `nft` : `delete` et `get` rendent les codes demandés."""
    bin_ = tmp_path / "bin"
    bin_.mkdir()

    def lancer(code_delete, code_get):
        nft = bin_ / "nft"
        nft.write_text(f'#!/bin/bash\necho "$*" >> {tmp_path}/nft.log\ncase "$1" in\n  delete) exit {code_delete} ;;\n'
                       f'  get) exit {code_get} ;;\nesac\nexit 0\n')
        nft.chmod(0o755)
        env = {**os.environ, "PATH": f"{bin_}:{os.environ['PATH']}"}
        return subprocess.run(["bash", str(WAFCTL), "unban", "198.51.100.7"], check=False, timeout=30,
                              capture_output=True, text=True, env=env)
    return lancer


def test_wafctl_unban_absent_n_est_pas_une_erreur(wafctl_unban, tmp_path):
    r = wafctl_unban(1, 1)            # retrait refusé, élément introuvable : déjà levé
    assert r.returncode == 0, r.stderr
    assert "delete element inet secubox waf_ban { 198.51.100.7 }" in (tmp_path / "nft.log").read_text()
    assert wafctl_unban(0, 0).returncode == 0
    r = wafctl_unban(1, 0)            # retrait refusé, élément toujours là : échec
    assert r.returncode == 1 and "refusé" in r.stderr


def test_defaire_d_un_ban_deja_absent_n_est_pas_incoherent(c, monkeypatch):
    """wafctl unban d'une adresse absente rend 0 : le retour arrière d'un ban jamais posé n'est pas une incohérence."""
    _audit_qui_echoue(c, monkeypatch, "ai-ban")
    c.faux.reponses["unban"] = (0, "[..] unban 198.51.100.7\n", "")
    assert c.ban("198.51.100.7").json()["detail"]["motif"] == "audit"
