# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Actor Intelligence 2.0, phase 1 (#2240) : les bans du WAF vus comme des « actions défensives » (type, cible, raison, durée, échéance, rollback),
les décisions des états de ban, et le vocabulaire de modes PASSIVE_ONLY / SIMULATION / ACTIVE."""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from api.enforcement import actions, decisions, identifiant, mode_global, trouver  # noqa: E402

NOW = 1_800_000_000


def ban(ip, cat, at, dur=3600, action="ban"):
    return {"ip": ip, "cat": cat, "sev": "high", "at": at, "exp": at + dur, "action": action}


def test_une_ligne_du_journal_devient_une_action_complete():
    a = actions([ban("203.0.113.5", "leurre:unrouted", NOW - 600, 3600)], NOW, {"203.0.113.5"})[0]
    assert a["id"] == identifiant("203.0.113.5", NOW - 600)
    assert (a["type"], a["target"], a["reason"], a["source_decision"]) == ("nft_ban", "203.0.113.5", "leurre:unrouted", "leurre:unrouted")
    assert a["duration_s"] == 3600 and a["created_at"] == NOW - 600 and a["expires_at"] == NOW + 3000
    assert a["status"] == "active" and a["rollback"] == {"available": True, "method": "unban"}


def test_etats_actif_expire_et_leve_avant_l_echeance():
    lignes = [ban("203.0.113.1", "campagne:abc", NOW - 7200, 3600),          # échu
              ban("203.0.113.2", "campagne:abc", NOW - 60, 3600),            # dans le set nft
              ban("203.0.113.3", "actor:ACT-9", NOW - 60, 3600)]             # absent du set avant l'échéance : levé à la main
    par_ip = {a["target"]: a for a in actions(lignes, NOW, {"203.0.113.2"})}
    assert par_ip["203.0.113.1"]["status"] == "expired" and par_ip["203.0.113.1"]["rollback"]["available"] is False
    assert par_ip["203.0.113.2"]["status"] == "active"
    assert par_ip["203.0.113.3"]["status"] == "released" and par_ip["203.0.113.3"]["rollback"]["available"] is False


def test_les_lignes_unban_et_corrompues_ne_comptent_pas_comme_actions():
    lignes = [ban("203.0.113.7", "x", NOW - 10, action="unban"), {"ip": ""}, {"cat": "sans ip"}]
    assert actions(lignes, NOW, set()) == []


def test_tri_recent_d_abord_et_plafond():
    lignes = [ban(f"198.51.100.{i}", "leurre:u", NOW - 1000 + i) for i in range(10)]
    sortie = actions(lignes, NOW, set(), limite=3)
    assert len(sortie) == 3 and sortie[0]["created_at"] > sortie[1]["created_at"]


def test_trouver_par_identifiant():
    lignes = [ban("203.0.113.9", "leurre:u", NOW - 5)]
    ident = identifiant("203.0.113.9", NOW - 5)
    assert trouver(lignes, NOW, {"203.0.113.9"}, ident)["target"] == "203.0.113.9"
    assert trouver(lignes, NOW, set(), "inconnu") is None


ETAT_CAMP = {"genere_le": NOW, "mode": "propose", "candidats": [
    {"ip": "198.51.100.1", "signature": "sig1", "sondes": 10, "haute_valeur": 6, "decision": "a_bannir"},
    {"ip": "198.51.100.2", "signature": "sig1", "sondes": 9, "haute_valeur": 5, "decision": "ecarte:deja_banni"}]}
ETAT_ACT = {"genere_le": NOW, "mode": "auto", "candidats": [
    {"ip": "198.51.100.3", "actor": "ACT-7", "mode": "DENY", "deja_bans": 3, "decision": "banni"},
    {"ip": "10.0.0.5", "actor": "ACT-8", "mode": "DENY", "deja_bans": 0, "decision": "ecarte:protegee"}]}


def test_les_decisions_disent_si_elles_auraient_bloque_ou_ont_bloque():
    d = decisions({"campagnes": ETAT_CAMP, "acteurs": ETAT_ACT}, NOW)
    par_ip = {x["target"]: x for x in d}
    assert par_ip["198.51.100.1"]["decision"] == "WOULD_BLOCK" and par_ip["198.51.100.1"]["level"] == "BLOCK"
    assert par_ip["198.51.100.3"]["decision"] == "BLOCKED" and par_ip["198.51.100.3"]["level"] == "BLOCK"
    assert par_ip["198.51.100.2"]["decision"] == "OBSERVE" and "deja_banni" in par_ip["198.51.100.2"]["reason"]
    assert par_ip["10.0.0.5"]["decision"] == "OBSERVE" and par_ip["198.51.100.1"]["source"] == "campagne" and par_ip["198.51.100.3"]["source"] == "acteur"
    assert par_ip["198.51.100.1"]["evidence"] == {"sondes": 10, "haute_valeur": 6, "signature": "sig1"}


def test_etat_perime_ou_absent_ne_produit_aucune_decision():
    assert decisions({"campagnes": None, "acteurs": {"genere_le": NOW - 3600, "mode": "auto", "candidats": [{"ip": "1.1.1.1", "decision": "banni"}]}}, NOW) == []


def test_vocabulaire_des_modes():
    assert mode_global({"campagnes": ETAT_CAMP, "acteurs": ETAT_ACT}, NOW)["mode"] == "ACTIVE"
    assert mode_global({"campagnes": ETAT_CAMP, "acteurs": None}, NOW)["mode"] == "SIMULATION"
    assert mode_global({"campagnes": None, "acteurs": None}, NOW)["mode"] == "PASSIVE_ONLY"
    m = mode_global({"campagnes": ETAT_CAMP, "acteurs": ETAT_ACT}, NOW)
    assert m["detail"] == {"campagnes": "SIMULATION", "acteurs": "ACTIVE"}


# ── routes ────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
def _importer_waf():
    """api.main exige geoip2 (absent de l'environnement de test) : un faux module suffit, aucune de ces routes ne géolocalise."""
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


def _client(monkeypatch, tmp_path, lignes, etats=None, actifs=()):
    import time as _t
    from fastapi.testclient import TestClient
    waf = _importer_waf()
    from secubox_core.auth import require_jwt, require_lecture
    journal = tmp_path / "bans.jsonl"
    journal.write_text("\n".join(json.dumps(l) for l in lignes) + "\n")
    monkeypatch.setattr(waf, "BANS_JOURNAL", journal)
    monkeypatch.setattr(waf, "AUDIT_LOG", tmp_path / "audit.log")
    for cle in ("acteurs", "campagnes"):
        chemin = tmp_path / f"{cle}.json"
        if etats and etats.get(cle):
            chemin.write_text(json.dumps(etats[cle]))
        waf.ETATS_BAN[cle] = chemin
    monkeypatch.setattr(waf, "_ips_bannies_actives", lambda: set(actifs))
    appels = []
    monkeypatch.setattr(waf, "_unban_ip", lambda ip: (appels.append(ip) or (True, "ok")))
    waf.app.dependency_overrides[require_lecture] = lambda: {"sub": "lecteur"}
    waf.app.dependency_overrides[require_jwt] = lambda: {"sub": "admin"}
    return TestClient(waf.app), waf, appels


def test_get_enforcement_liste_les_actions_et_filtre_par_statut(monkeypatch, tmp_path):
    import time as _t
    now = int(_t.time())
    c, waf, _ = _client(monkeypatch, tmp_path, [ban("203.0.113.5", "leurre:u", now - 60), ban("203.0.113.6", "campagne:s", now - 7200, 3600)], actifs={"203.0.113.5"})
    try:
        tout = c.get("/enforcement").json()
        actifs = c.get("/enforcement?statut=active").json()
    finally:
        waf.app.dependency_overrides.clear()
    assert tout["total"] == 2 and actifs["total"] == 1 and actifs["actions"][0]["target"] == "203.0.113.5"


def test_rollback_retire_l_adresse_et_ecrit_l_audit(monkeypatch, tmp_path):
    import time as _t
    now = int(_t.time())
    c, waf, appels = _client(monkeypatch, tmp_path, [ban("203.0.113.5", "leurre:u", now - 60)], actifs={"203.0.113.5"})
    try:
        ident = c.get("/enforcement").json()["actions"][0]["id"]
        r = c.post(f"/enforcement/{ident}/rollback")
    finally:
        waf.app.dependency_overrides.clear()
    assert r.status_code == 200 and appels == ["203.0.113.5"]
    audit = [json.loads(l) for l in (tmp_path / "audit.log").read_text().splitlines()]
    assert audit[0]["action"] == "enforcement-rollback" and audit[0]["by"] == "admin" and "203.0.113.5" in audit[0]["detail"]


def test_rollback_refuse_une_action_inactive_ou_inconnue(monkeypatch, tmp_path):
    import time as _t
    now = int(_t.time())
    c, waf, appels = _client(monkeypatch, tmp_path, [ban("203.0.113.6", "campagne:s", now - 7200, 3600)])
    try:
        ident = c.get("/enforcement").json()["actions"][0]["id"]
        echu, inconnu = c.post(f"/enforcement/{ident}/rollback"), c.post("/enforcement/zzz/rollback")
    finally:
        waf.app.dependency_overrides.clear()
    assert echu.status_code == 409 and inconnu.status_code == 404 and appels == []


def test_rollback_exige_un_jeton_et_les_lectures_un_acces_lecture(monkeypatch, tmp_path):
    from fastapi.testclient import TestClient
    waf = _importer_waf()
    from secubox_core import auth
    monkeypatch.setattr(auth, "mode_tableau_de_bord_actif", lambda: False)
    c = TestClient(waf.app)
    assert c.post("/enforcement/abc/rollback").status_code in (401, 403)
    assert c.get("/enforcement").status_code in (401, 403) and c.get("/decisions").status_code in (401, 403)


def test_decisions_et_mode_par_l_api(monkeypatch, tmp_path):
    import time as _t
    now = int(_t.time())
    etats = {"campagnes": {**ETAT_CAMP, "genere_le": now}, "acteurs": {**ETAT_ACT, "genere_le": now}}
    c, waf, _ = _client(monkeypatch, tmp_path, [], etats=etats)
    try:
        d, m = c.get("/decisions").json(), c.get("/enforcement/mode").json()
    finally:
        waf.app.dependency_overrides.clear()
    assert {x["decision"] for x in d["decisions"]} == {"WOULD_BLOCK", "BLOCKED", "OBSERVE"} and m["mode"] == "ACTIVE"


# ── Phase 4 : les réévaluations à l'échéance (reevaluations.jsonl) ───────────────────────────────────────────────────────────────────────────
from api.enforcement import reevaluations  # noqa: E402


def ree(ip, decision, ts, applique=True, paquets=40):
    return {"ts": ts, "ip": ip, "categorie": "leurre:unrouted", "paquets": paquets, "compteur": True, "recidives": 0, "decision": decision,
            "duree_s": 86400 if decision == "EXTEND" else 0, "raison": "r", "mode": "auto", "applique": applique, "version": "v1"}


def test_les_reevaluations_sont_rendues_recentes_d_abord_avec_leurs_totaux():
    lignes = [ree("203.0.113.1", "RELEASE", NOW - 300), ree("203.0.113.2", "EXTEND", NOW - 200), ree("203.0.113.3", "EXTEND", NOW - 100, applique=False)]
    r = reevaluations(lignes, NOW, limite=10)
    assert [x["ip"] for x in r["reevaluations"]] == ["203.0.113.3", "203.0.113.2", "203.0.113.1"]
    assert r["totaux"] == {"RELEASE": 1, "EXTEND": 2, "appliquees": 2}


def test_les_reevaluations_ignorent_les_lignes_illisibles_et_bornent_la_liste():
    r = reevaluations([{"ip": "x"}, "n'importe quoi", ree("203.0.113.1", "RELEASE", NOW - 5), ree("203.0.113.2", "RELEASE", NOW - 4)], NOW, limite=1)
    assert len(r["reevaluations"]) == 1 and r["reevaluations"][0]["ip"] == "203.0.113.2" and r["totaux"]["RELEASE"] == 2


def test_une_reevaluation_est_expliquee_en_clair():
    x = reevaluations([ree("203.0.113.2", "EXTEND", NOW - 10)], NOW, limite=5)["reevaluations"][0]
    assert x["decision"] == "EXTEND" and x["duree_s"] == 86400 and x["raison"] == "r" and x["paquets"] == 40 and x["mode"] == "auto"
