# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3839 — file d'approbation SADE en REACTIVE : mode, liste blanche, geste unique, exactement une fois, audit.

Aucun socket réel : actord, threatmesh et le WAF sont des faux (le WAF factice journalise chaque POST /ban).
"""
import copy
import re
import sqlite3
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from fastapi.testclient import TestClient  # noqa: E402

from api import defense, defense_etat, main  # noqa: E402
from secubox_core.auth import require_jwt, require_lecture  # noqa: E402

ADMIN = {"Authorization": "Bearer admin"}
LECTURE = {"Authorization": "Bearer lecteur"}
P1 = defense.empreinte("ban", ["203.0.113.10"], 3600)                    # ACT-0001, score 86
P2 = defense.empreinte("ban", ["203.0.113.21", "203.0.113.20"], None)     # ACT-0002, ttl 0, score 97 (incident)
P3 = defense.empreinte("quarantaine", ["198.51.100.30"], 600)             # ACT-0003 : geste non livré
IP = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")

PROPOSITIONS = {
    "genere_le": 1763630000, "shadow": True,
    "propositions": [
        {"actor": "ACT-0001", "mode": "DENY", "raison": "attaque à forte gravité", "ttl_s": 3600,
         "ips": ["203.0.113.10"], "bans": 3, "confiance": 74, "priorite": 86, "reversible": True},
        {"actor": "ACT-0002", "mode": "DENY", "raison": "campagne", "ttl_s": 0,
         "ips": ["203.0.113.20", "203.0.113.21"], "bans": 1, "confiance": 90, "priorite": 97, "reversible": True},
        {"actor": "ACT-0003", "mode": "QUARANTINE", "raison": "appareil du LAN", "ttl_s": 600,
         "ips": ["198.51.100.30"], "bans": 0, "confiance": 80, "priorite": 70, "reversible": True},
    ],
}


class Substrat:
    """Faux substrat : `lire` (actord, threatmesh) et `ecrire` (WAF factice), avec journal des appels."""

    def __init__(self):
        self.rep = {("actord", "/proposals"): copy.deepcopy(PROPOSITIONS),
                    ("threatmesh", "/peers"): {"peers": [{"id": "p1", "name": "gk-pair", "address": "198.51.100.9:51820"}]}}
        self.lus = []
        self.appels = []      # POST /ban reçus par le WAF factice : (chemin, corps, entetes)
        self._echec = None    # (code, index de l'appel qui échoue)
        self.corps_ok = {"success": True, "message": "ok"}

    def echoue(self, code, a_partir_de=0):
        self._echec = (code, a_partir_de)

    def lire(self, source, chemin, entetes=None, delai=3.0):
        self.lus.append((source, chemin, dict(entetes or {})))
        cle = (source, chemin.split("?")[0])
        if cle in self.rep:
            return {"ok": True, "donnees": copy.deepcopy(self.rep[cle]), "erreur": None}
        return {"ok": False, "donnees": None, "erreur": "socket absent"}

    def ecrire(self, source, chemin, corps, entetes=None, delai=10.0):
        assert source == "waf"
        self.appels.append((chemin, dict(corps), dict(entetes or {})))
        if self._echec and len(self.appels) - 1 >= self._echec[1]:
            return {"ok": False, "donnees": None, "erreur": f"http {self._echec[0]} : bannissement refusé : wafctl"}
        return {"ok": True, "donnees": dict(self.corps_ok, ip=corps.get("ip")), "erreur": None}


waf_factice = None


@pytest.fixture(autouse=True)
def isole(tmp_path, monkeypatch):
    global waf_factice
    monkeypatch.setenv("SECUBOX_SOC_DEFENSE_DB", str(tmp_path / "defense.db"))
    monkeypatch.setenv("SECUBOX_AUDIT_LOG", str(tmp_path / "audit.log"))
    monkeypatch.setenv("SECUBOX_TABLEAU_DE_BORD", "0")
    monkeypatch.setattr(defense, "ROUTES_PROC", str(tmp_path / "route-absente"))
    waf_factice = Substrat()
    monkeypatch.setattr(defense.substrat, "lire", waf_factice.lire)
    monkeypatch.setattr(defense.substrat, "ecrire", waf_factice.ecrire)
    defense._CACHE.clear()
    yield
    waf_factice = None


@pytest.fixture
def client():
    main.app.dependency_overrides[require_lecture] = lambda: {"sub": "lecteur"}
    main.app.dependency_overrides[require_jwt] = lambda: {"sub": "gerald"}
    yield TestClient(main.app)
    main.app.dependency_overrides.pop(require_lecture, None)
    main.app.dependency_overrides.pop(require_jwt, None)


@pytest.fixture
def reactive():
    defense_etat.changer_mode("reactive", "test")


@pytest.fixture
def audit(tmp_path):
    return tmp_path / "audit.log"


@pytest.fixture
def proposition():
    n = [100]

    def fabrique(*cibles, mode="DENY", ttl=3600):
        n[0] += 1
        acteur = f"ACT-{n[0]:04d}"
        waf_factice.rep[("actord", "/proposals")]["propositions"].append(
            {"actor": acteur, "mode": mode, "raison": "test", "ttl_s": ttl, "ips": list(cibles), "bans": 1,
             "confiance": 80, "priorite": 50, "reversible": True})
        ttl_e = ttl if isinstance(ttl, int) and not isinstance(ttl, bool) and ttl > 0 else None
        return defense.empreinte("ban" if mode == "DENY" else mode.lower(), list(cibles), ttl_e)
    return fabrique


@pytest.fixture
def proposition_bloc(proposition):
    return proposition("203.0.113.0/24", mode="BAN_BLOC")


def _lignes(audit):
    return audit.read_text(encoding="utf-8").splitlines() if audit.exists() else []


# ── tests du plan (brief) ──────────────────────────────────────────────────────────────────────────

def test_approbation_refusee_en_observe(client):
    r = client.post("/defense/approve", json={"empreinte": P1}, headers=ADMIN)
    assert r.status_code == 409 and r.json()["cause"] == "mode"
    r = client.post("/defense/refuse", json={"empreinte": P1}, headers=ADMIN)
    assert r.status_code == 409 and r.json()["cause"] == "mode"
    assert waf_factice.appels == []


@pytest.mark.parametrize("cible", ["192.168.1.20", "10.98.0.1", "fd00::1", "127.0.0.1", "100.64.0.9",
                                   "::1", "fe80::1", "169.254.3.3", "224.0.0.1", "240.0.0.1", "0.0.0.0", "::",
                                   "255.255.255.255", "ff02::1", "::ffff:203.0.113.5", "172.20.0.1",
                                   "pas-une-ip", "203.0.113.0/24", " 203.0.113.5", ""])
def test_liste_blanche_prioritaire(client, reactive, proposition, cible):
    r = client.post("/defense/approve", json={"empreinte": proposition(cible)}, headers=ADMIN)
    assert r.status_code == 403 and r.json()["cause"] == "liste_blanche"
    assert waf_factice.appels == []


def test_simulation_n_appelle_pas_le_waf(client, reactive, audit):
    r = client.post("/defense/approve", json={"empreinte": P1, "simuler": True}, headers=ADMIN)
    assert r.status_code == 200 and r.json()["etat"] == "simule" and waf_factice.appels == []
    assert "sade-simule" in _lignes(audit)[-1] and "verdict=ok" in _lignes(audit)[-1]


def test_une_seule_application(client, reactive):
    assert client.post("/defense/approve", json={"empreinte": P1}, headers=ADMIN).status_code == 200
    r = client.post("/defense/approve", json={"empreinte": P1}, headers=ADMIN)
    assert r.status_code == 409 and r.json()["cause"] == "deja_traitee"
    assert len(waf_factice.appels) == 1
    assert defense_etat.decision(P1)["etat"] == "applique"


def test_geste_hors_ban_refuse(client, reactive, proposition_bloc):
    for pid in (proposition_bloc, P3):
        r = client.post("/defense/approve", json={"empreinte": pid}, headers=ADMIN)
        assert r.status_code == 409 and r.json()["cause"] == "gestes_non_livres", pid
    assert waf_factice.appels == []


def test_echec_du_waf_ne_marque_pas_applique(client, reactive):
    waf_factice.echoue(502)
    r = client.post("/defense/approve", json={"empreinte": P1}, headers=ADMIN)
    assert r.status_code == 502 and r.json()["cause"] == "waf" and "bannissement refusé" in r.json()["error"]
    assert defense_etat.decision(P1)["etat"] == "en_attente"
    waf_factice._echec = None  # le WAF revient : la décision se rejoue
    assert client.post("/defense/approve", json={"empreinte": P1}, headers=ADMIN).status_code == 200
    assert defense_etat.decision(P1)["etat"] == "applique"


def test_approbation_et_refus_audites(client, reactive, audit):
    assert client.post("/defense/approve", json={"empreinte": P1}, headers=ADMIN).status_code == 200
    lignes = _lignes(audit)
    dem = [x for x in lignes if " sade-approuve-demande " in x]
    res = [x for x in lignes if " sade-approuve-resultat " in x]
    assert len(dem) == 1 and len(res) == 1 and lignes.index(dem[0]) < lignes.index(res[0])
    for x in (dem[0], res[0]):
        assert f"empreinte={P1}" in x and "acteur=ACT-0001" in x and "203.0.113.10" in x
        assert "geste=ban" in x and "duree=3600s" in x and "score=86" in x and "operateur=gerald" in x
    assert "issue=applique" in res[0]
    r = client.post("/defense/refuse", json={"empreinte": P2}, headers=ADMIN)
    assert r.status_code == 200 and r.json() == {"etat": "refuse", "resultat": "proposition refusée"}
    d = _lignes(audit)[-1]
    assert " sade-refuse " in d and f"empreinte={P2}" in d and "203.0.113.20,203.0.113.21" in d
    assert "score=97" in d and "operateur=gerald" in d
    assert defense_etat.decision(P2)["etat"] == "refuse"
    r = client.post("/defense/approve", json={"empreinte": P2}, headers=ADMIN)  # refusée : plus jamais appliquée
    assert r.status_code == 409 and r.json()["cause"] == "deja_traitee"
    assert len(waf_factice.appels) == 1


# ── liste blanche : plusieurs adresses, IPv6, CIDR ajoutés, pairs, passerelle, appelant ─────────────

def test_une_adresse_protegee_refuse_toute_la_proposition(client, reactive, proposition):
    r = client.post("/defense/approve", json={"empreinte": proposition("203.0.113.40", "192.168.1.5")}, headers=ADMIN)
    assert r.status_code == 403 and r.json()["cause"] == "liste_blanche"
    assert r.json()["adresses_refusees"] == ["192.168.1.5"]
    assert waf_factice.appels == []


def _ajoute_liste_blanche(cidr):
    defense_etat.mode_courant()  # migrations
    db = sqlite3.connect(defense_etat._chemin_db())
    db.execute("INSERT INTO liste_blanche(cidr, motif, par, ts) VALUES (?, 'test', 'op', 't')", (cidr,))
    db.commit()
    db.close()


def test_liste_blanche_ipv6_par_cidr(client, reactive, proposition):
    _ajoute_liste_blanche("2001:db8:42::/48")
    r = client.post("/defense/approve", json={"empreinte": proposition("2001:db8:42::7")}, headers=ADMIN)
    assert r.status_code == 403 and r.json()["cause"] == "liste_blanche"
    assert waf_factice.appels == []
    r = client.post("/defense/approve", json={"empreinte": proposition("2001:db8:43::1")}, headers=ADMIN)
    assert r.status_code == 200 and waf_factice.appels[0][1]["ip"] == "2001:db8:43::1"


def test_liste_blanche_ipv4_par_cidr(client, reactive, proposition):
    _ajoute_liste_blanche("203.0.113.128/25")
    r = client.post("/defense/approve", json={"empreinte": proposition("203.0.113.200")}, headers=ADMIN)
    assert r.status_code == 403 and waf_factice.appels == []


def test_pair_du_maillage_protege(client, reactive, proposition):
    r = client.post("/defense/approve", json={"empreinte": proposition("198.51.100.9")}, headers=ADMIN)
    assert r.status_code == 403 and r.json()["cause"] == "liste_blanche" and waf_factice.appels == []


def test_passerelle_protegee(client, reactive, proposition, monkeypatch, tmp_path):
    f = tmp_path / "route"
    # passerelle 198.51.100.1 (petit-boutiste : 01 64 33 c6)
    f.write_text("Iface\tDestination\tGateway \tFlags\n"
                 "eth2\t00000000\t016433C6\t0003\n"
                 "eth2\t006433C6\t00000000\t0001\n")
    monkeypatch.setattr(defense, "ROUTES_PROC", str(f))
    r = client.post("/defense/approve", json={"empreinte": proposition("198.51.100.1")}, headers=ADMIN)
    assert r.status_code == 403 and waf_factice.appels == []


def test_adresse_de_l_appelant_protegee(client, reactive, proposition):
    pid = proposition("203.0.113.77")
    r = client.post("/defense/approve", json={"empreinte": pid}, headers={**ADMIN, "X-Real-IP": "203.0.113.77"})
    assert r.status_code == 403 and waf_factice.appels == []
    r = client.post("/defense/approve", json={"empreinte": pid},
                    headers={**ADMIN, "X-Forwarded-For": "198.51.100.200, 203.0.113.77"})
    assert r.status_code == 403 and waf_factice.appels == []


def test_proposition_sans_adresse(client, reactive, proposition):
    r = client.post("/defense/approve", json={"empreinte": proposition()}, headers=ADMIN)
    assert r.status_code == 409 and r.json()["cause"] == "sans_adresse" and waf_factice.appels == []


# ── porteur, durée, échecs, audit ─────────────────────────────────────────────────────────────────

def test_cookie_seul_exige_le_porteur(client, reactive):
    r = client.post("/defense/approve", json={"empreinte": P1}, headers={"Cookie": "secubox_session=abc"})
    assert r.status_code == 409 and r.json()["cause"] == "porteur_requis"
    assert waf_factice.appels == [] and defense_etat.decision(P1)["etat"] == "en_attente"


def test_porteur_seul_transmis_jamais_stocke(client, reactive, audit):
    client.post("/defense/approve", json={"empreinte": P1}, headers={**ADMIN, "Cookie": "secubox_session=abc"})
    chemin, corps, entetes = waf_factice.appels[0]
    assert chemin == "/ban" and entetes == {"Authorization": "Bearer admin"}
    assert corps == {"ip": "203.0.113.10", "duration": "3600s", "reason": "SADE ACT-0001 approuvé par gerald"}
    assert "Bearer" not in audit.read_text(encoding="utf-8")
    db = sqlite3.connect(defense_etat._chemin_db())
    assert "Bearer" not in repr(db.execute("SELECT * FROM decisions").fetchall())


def test_duree_absente_laisse_le_defaut_du_waf(client, reactive, proposition):
    assert client.post("/defense/approve", json={"empreinte": P2}, headers=ADMIN).status_code == 200
    assert all("duration" not in c[1] for c in waf_factice.appels) and len(waf_factice.appels) == 2
    waf_factice.appels.clear()
    pid = proposition("203.0.113.90", ttl=True)
    assert client.post("/defense/approve", json={"empreinte": pid}, headers=ADMIN).status_code == 200
    assert "duration" not in waf_factice.appels[0][1]


def test_echec_partiel_liste_les_adresses_bannies(client, reactive, audit):
    waf_factice.echoue(500, a_partir_de=1)
    r = client.post("/defense/approve", json={"empreinte": P2}, headers=ADMIN)
    j = r.json()
    assert r.status_code == 502 and j["cause"] == "waf" and j["etat"] == "en_attente"
    assert j["bannies"] == ["203.0.113.20"] and j["echec"] == "203.0.113.21"
    assert defense_etat.decision(P2)["etat"] == "en_attente"
    res = [x for x in _lignes(audit) if " sade-approuve-resultat " in x][-1]
    assert "issue=partiel" in res and "bannies=203.0.113.20" in res


def test_succes_sans_success_true_est_un_echec(client, reactive):
    waf_factice.corps_ok = {"success": False}
    r = client.post("/defense/approve", json={"empreinte": P1}, headers=ADMIN)
    assert r.status_code == 502 and defense_etat.decision(P1)["etat"] == "en_attente"


def test_audit_indisponible_avant_l_appel_aucun_ban(client, reactive, monkeypatch, tmp_path):
    monkeypatch.setenv("SECUBOX_AUDIT_LOG", str(tmp_path / "absent" / "audit.log"))
    r = client.post("/defense/approve", json={"empreinte": P1}, headers=ADMIN)
    assert r.status_code == 503 and r.json()["cause"] == "audit_indisponible"
    assert waf_factice.appels == []
    assert defense_etat.decision(P1)["etat"] == "en_attente"
    r = client.post("/defense/refuse", json={"empreinte": P1}, headers=ADMIN)
    assert r.status_code == 503 and defense_etat.decision(P1)["etat"] == "en_attente"
    r = client.post("/defense/approve", json={"empreinte": P1, "simuler": True}, headers=ADMIN)
    assert r.status_code == 503 and r.json()["cause"] == "audit_indisponible"


def test_simulation_ne_consomme_pas_la_decision(client, reactive):
    for _ in range(2):
        assert client.post("/defense/approve", json={"empreinte": P1, "simuler": True}, headers=ADMIN).json()["etat"] == "simule"
    assert defense_etat.decision(P1)["etat"] == "en_attente"
    assert client.post("/defense/approve", json={"empreinte": P1}, headers=ADMIN).status_code == 200
    r = client.post("/defense/approve", json={"empreinte": P1, "simuler": True}, headers=ADMIN)
    assert r.status_code == 409 and r.json()["cause"] == "deja_traitee"
    assert len(waf_factice.appels) == 1


def test_simulation_passe_tous_les_controles(client, reactive, proposition, audit):
    r = client.post("/defense/approve", json={"empreinte": proposition("10.0.0.5"), "simuler": True}, headers=ADMIN)
    assert r.status_code == 403 and r.json()["cause"] == "liste_blanche"
    assert "sade-simule" in _lignes(audit)[-1] and "verdict=liste_blanche" in _lignes(audit)[-1]
    r = client.post("/defense/approve", json={"empreinte": P1, "simuler": True}, headers={"Cookie": "s=1"})
    assert r.status_code == 409 and r.json()["cause"] == "porteur_requis"
    r = client.post("/defense/approve", json={"empreinte": P3, "simuler": True}, headers=ADMIN)
    assert r.status_code == 409 and r.json()["cause"] == "gestes_non_livres"
    defense_etat.changer_mode("observe", "test")
    r = client.post("/defense/approve", json={"empreinte": P1, "simuler": True}, headers=ADMIN)
    assert r.status_code == 409 and r.json()["cause"] == "mode"
    r = client.post("/defense/refuse", json={"empreinte": P1, "simuler": True}, headers=ADMIN)
    assert r.status_code == 409 and r.json()["cause"] == "mode"
    assert waf_factice.appels == []


def test_refus_simule(client, reactive, audit):
    r = client.post("/defense/refuse", json={"empreinte": P1, "simuler": True}, headers=ADMIN)
    assert r.status_code == 200 and r.json()["etat"] == "simule"
    assert "action=refuse" in _lignes(audit)[-1] and defense_etat.decision(P1)["etat"] == "en_attente"


def test_operateur_assaini_dans_l_audit(client, reactive, audit):
    main.app.dependency_overrides[require_jwt] = lambda: {"sub": "x\n2026 sade-approuve forge"}
    client.post("/defense/approve", json={"empreinte": P1}, headers=ADMIN)
    t = audit.read_text(encoding="utf-8")
    assert t.count("\n") == 3 and " forge" not in t  # mode, demande, résultat


def _reclame(etat="en_cours"):
    return defense_etat.reclamer(P1, "ACT-0001", "ban", "203.0.113.10", 86, 3600, "op", etat, "sade-approuve-demande x")


def test_mode_relu_dans_la_transaction():
    defense_etat.mode_courant()
    with pytest.raises(defense_etat.ModeRefuse):
        _reclame()
    defense_etat.changer_mode("reactive", "op")
    assert _reclame() == 1
    with pytest.raises(defense_etat.DejaTraitee):
        _reclame()


# ── entrées, gardes, sources ──────────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("corps", [{}, {"empreinte": 3}, {"id": "ACT-0001:ban"}, {"empreinte": "ACT-0001:ban"},
                                   {"empreinte": P1, "simuler": "oui"}, {"empreinte": P1.upper()},
                                   {"empreinte": P1[:-1]}, {"empreinte": P1 + "0"}])
def test_corps_invalide_400(client, reactive, corps):
    assert client.post("/defense/approve", json=corps, headers=ADMIN).status_code == 400
    assert waf_factice.appels == []


def test_proposition_inconnue_409_changee(client, reactive):
    r = client.post("/defense/approve", json={"empreinte": "0" * 64}, headers=ADMIN)
    assert r.status_code == 409 and r.json()["cause"] == "proposition_changee"


def test_actord_muet_503(client, reactive):
    del waf_factice.rep[("actord", "/proposals")]
    r = client.post("/defense/approve", json={"empreinte": P1}, headers=ADMIN)
    assert r.status_code == 503 and r.json()["cause"] == "actord_indisponible" and waf_factice.appels == []


def test_proposition_relue_chez_actord_avec_la_vue_complete(client, reactive):
    client.post("/defense/approve", json={"empreinte": P1}, headers=ADMIN)
    lu = [x for x in waf_factice.lus if x[:2] == ("actord", "/proposals")]
    assert lu and lu[-1][2] == {"X-Sbx-Vue": "complete"}


@pytest.mark.parametrize("route", ["/defense/approve", "/defense/refuse"])
def test_lecteur_ne_peut_pas_approuver(route, monkeypatch, reactive):
    monkeypatch.setenv("SECUBOX_JWT_SECRET", "secret-de-test-seulement")
    r = TestClient(main.app).post(route, json={"empreinte": P1}, headers=LECTURE)
    assert r.status_code in (401, 403)
    assert waf_factice.appels == [] and defense_etat.decision(P1)["etat"] == "en_attente"


# ── GET /defense/proposals ────────────────────────────────────────────────────────────────────────

def test_propositions_admin(client, reactive, monkeypatch):
    async def ok(request, creds=None):
        return {"sub": "admin"}
    monkeypatch.setattr(defense, "require_jwt", ok)
    client.post("/defense/approve", json={"empreinte": P1}, headers=ADMIN)
    j = client.get("/defense/proposals", headers=LECTURE).json()
    assert j["shadow"] is True and j["mode"] == "reactive" and j["sources"]["actord"]["ok"] is True and j["admin"] is True
    p = {x["empreinte"]: x for x in j["propositions"]}
    assert set(p) == {P1, P2, P3}
    assert p[P1] == {"id": "ACT-0001:ban", "empreinte": P1, "menace_id": "ACT-0001", "cible": "203.0.113.10",
                     "geste": "ban", "score": 86, "bande": "usager", "motif": "attaque à forte gravité",
                     "validation_humaine": False, "etat": "applique", "ttl_s": 3600, "executable": True}
    assert p[P2]["validation_humaine"] is True and p[P2]["bande"] == "incident" and p[P2]["etat"] == "en_attente"
    assert p[P2]["cible"] == "203.0.113.20, 203.0.113.21"
    assert p[P3]["executable"] is False


def test_propositions_lecteur_masquees(client):
    # pas de surcharge de `defense.require_jwt` : le porteur « lecteur » n'est pas un administrateur réel
    j = client.get("/defense/proposals", headers=LECTURE)
    assert not IP.search(j.text) and "2001:" not in j.text and j.json()["admin"] is False
    p = {x["id"]: x for x in j.json()["propositions"]}
    assert p["ACT-0001:ban"]["cible"] == "cible-1" and p["ACT-0002:ban"]["cible"] == "cible-2, cible-3"
    assert all("empreinte" not in x for x in j.json()["propositions"])
    assert P1 not in j.text and P2 not in j.text


def test_propositions_actord_muet(client):
    del waf_factice.rep[("actord", "/proposals")]
    j = client.get("/defense/proposals", headers=LECTURE).json()
    assert j["propositions"] == [] and j["sources"]["actord"]["ok"] is False and j["shadow"] is None


def test_propositions_sans_jeton_401(monkeypatch):
    assert TestClient(main.app).get("/defense/proposals").status_code == 401


# ── fix round 1 : empreinte, liaison à l'affiché, ré-armement, reprise, plafonds ──────────────────

def _props():
    return waf_factice.rep[("actord", "/proposals")]["propositions"]


def test_redemarrage_d_actord_meme_adresses_meme_decision(client, reactive):
    assert client.post("/defense/approve", json={"empreinte": P1}, headers=ADMIN).status_code == 200
    _props()[0]["actor"] = "ACT-0042"  # actord redémarré : nouvel identifiant, mêmes adresses, même durée
    r = client.post("/defense/approve", json={"empreinte": P1}, headers=ADMIN)
    assert r.status_code == 409 and r.json()["cause"] == "deja_traitee" and len(waf_factice.appels) == 1


def test_identifiant_recycle_autres_adresses_nouvelle_decision(client, reactive, monkeypatch):
    async def ok(request, creds=None):
        return {"sub": "admin"}
    monkeypatch.setattr(defense, "require_jwt", ok)
    assert client.post("/defense/approve", json={"empreinte": P1}, headers=ADMIN).status_code == 200
    _props()[0]["ips"] = ["203.0.113.99"]  # ACT-0001 désigne désormais un autre acteur
    nouvelle = defense.empreinte("ban", ["203.0.113.99"], 3600)
    j = client.get("/defense/proposals", headers=LECTURE).json()
    ligne = next(x for x in j["propositions"] if x["menace_id"] == "ACT-0001")
    assert ligne["empreinte"] == nouvelle and ligne["etat"] == "en_attente"
    assert client.post("/defense/approve", json={"empreinte": nouvelle}, headers=ADMIN).status_code == 200
    assert defense_etat.decision(P1)["etat"] == "applique" and defense_etat.decision(nouvelle)["etat"] == "applique"


def test_empreinte_normalisee():
    assert defense.empreinte("ban", ["::ffff:203.0.113.5", "2001:DB8:0::1"], 60) == \
        defense.empreinte("ban", ["2001:db8::1", "203.0.113.5"], 60)
    assert defense.empreinte("ban", ["203.0.113.5"], 60) != defense.empreinte("ban", ["203.0.113.5"], 61)
    assert defense.empreinte("ban", ["203.0.113.5"], None) != defense.empreinte("quarantaine", ["203.0.113.5"], None)


def _vieillir(emp, champ, secondes):
    db = sqlite3.connect(defense_etat._chemin_db())
    from datetime import datetime, timedelta, timezone
    ts = (datetime.now(timezone.utc) - timedelta(seconds=secondes)).strftime("%Y-%m-%dT%H:%M:%SZ")
    db.execute(f"UPDATE decisions SET {champ} = ? WHERE empreinte = ?", (ts, emp))
    db.commit()
    db.close()


def test_ban_expire_rearme_une_nouvelle_generation(client, reactive, audit):
    assert client.post("/defense/approve", json={"empreinte": P1}, headers=ADMIN).status_code == 200
    _vieillir(P1, "tranche_ts", 3600 + 200)  # ttl 3600 + 5 min pas encore écoulés
    assert client.post("/defense/approve", json={"empreinte": P1}, headers=ADMIN).status_code == 409
    _vieillir(P1, "tranche_ts", 3600 + 301)
    assert defense_etat.decision(P1)["etat"] == "en_attente"
    assert client.post("/defense/approve", json={"empreinte": P1}, headers=ADMIN).status_code == 200
    d = defense_etat.decision(P1)
    assert d["generation"] == 2 and d["etat"] == "applique" and len(waf_factice.appels) == 2
    assert "generation=2" in [x for x in _lignes(audit) if "sade-approuve-demande" in x][-1]


def test_ban_sans_duree_rearme_apres_4h(client, reactive):
    assert client.post("/defense/approve", json={"empreinte": P2}, headers=ADMIN).status_code == 200
    _vieillir(P2, "tranche_ts", 4 * 3600 + 200)
    assert defense_etat.decision(P2)["etat"] == "applique"
    _vieillir(P2, "tranche_ts", 4 * 3600 + 301)
    assert defense_etat.decision(P2)["etat"] == "en_attente"


def test_refus_rearme_apres_24h(client, reactive):
    assert client.post("/defense/refuse", json={"empreinte": P1}, headers=ADMIN).status_code == 200
    _vieillir(P1, "tranche_ts", 23 * 3600)
    assert client.post("/defense/approve", json={"empreinte": P1}, headers=ADMIN).json()["cause"] == "deja_traitee"
    _vieillir(P1, "tranche_ts", 24 * 3600 + 10)
    assert client.post("/defense/approve", json={"empreinte": P1}, headers=ADMIN).status_code == 200
    assert defense_etat.decision(P1)["generation"] == 2


def test_proposition_changee_aucun_appel(client, reactive, audit):
    _props()[0]["ips"] = ["203.0.113.10", "203.0.113.66"]  # l'acteur a gagné une adresse depuis l'affichage
    for simuler in (True, False):
        r = client.post("/defense/approve", json={"empreinte": P1, "simuler": simuler}, headers=ADMIN)
        assert r.status_code == 409 and r.json()["cause"] == "proposition_changee"
    assert waf_factice.appels == [] and defense_etat.decision(P1)["etat_enregistre"] is None
    assert "sade-approuve-refus cause=proposition_changee" in _lignes(audit)[-1]
    _props()[0]["ttl_s"] = 7200
    _props()[0]["ips"] = ["203.0.113.10"]
    assert client.post("/defense/approve", json={"empreinte": P1}, headers=ADMIN).json()["cause"] == "proposition_changee"


def test_reprise_trop_tot_puis_bloquee_reprise(client, reactive, audit):
    _reclame()  # simule un processus mort après la réclamation
    r = client.post("/defense/reprendre", json={"empreinte": P1}, headers=ADMIN)
    assert r.status_code == 409 and r.json()["cause"] == "pas_bloquee"
    assert defense_etat.decision(P1)["etat"] == "en_cours"
    _vieillir(P1, "demande_ts", int(defense.DELAI_WAF_S) + 50)  # 1 adresse : seuil 30 + 60 s
    assert client.post("/defense/reprendre", json={"empreinte": P1}, headers=ADMIN).status_code == 409
    _vieillir(P1, "demande_ts", int(defense.DELAI_WAF_S) + 61)
    r = client.post("/defense/reprendre", json={"empreinte": P1}, headers=ADMIN)
    assert r.status_code == 200 and r.json()["etat"] == "en_attente"
    assert defense_etat.decision(P1)["etat"] == "en_attente"
    d = _lignes(audit)[-1]
    assert " sade-reprise " in d and f"empreinte={P1}" in d and "operateur=gerald" in d
    assert client.post("/defense/approve", json={"empreinte": P1}, headers=ADMIN).status_code == 200


def test_reprise_hors_en_cours_et_audit_ko(client, reactive, monkeypatch, tmp_path):
    assert client.post("/defense/reprendre", json={"empreinte": P1}, headers=ADMIN).json()["cause"] == "pas_bloquee"
    assert client.post("/defense/reprendre", json={"empreinte": "x"}, headers=ADMIN).status_code == 400
    _reclame()
    _vieillir(P1, "demande_ts", 3600)
    monkeypatch.setenv("SECUBOX_AUDIT_LOG", str(tmp_path / "absent" / "audit.log"))
    r = client.post("/defense/reprendre", json={"empreinte": P1}, headers=ADMIN)
    assert r.status_code == 503 and defense_etat.decision(P1)["etat"] == "en_cours"


def test_reprise_reservee_a_l_administrateur(monkeypatch):
    monkeypatch.setenv("SECUBOX_JWT_SECRET", "secret-de-test-seulement")
    assert TestClient(main.app).post("/defense/reprendre", json={"empreinte": P1}, headers=LECTURE).status_code in (401, 403)


def test_entree_de_liste_blanche_illisible_echec_ferme(client, reactive, audit):
    defense_etat.mode_courant()
    db = sqlite3.connect(defense_etat._chemin_db())
    db.execute("INSERT INTO liste_blanche(cidr, motif, par, ts) VALUES ('203.0.113.0/33', 'faute', 'op', 't')")
    db.commit()
    db.close()
    r = client.post("/defense/approve", json={"empreinte": P1}, headers=ADMIN)
    assert r.status_code == 403 and r.json()["cause"] == "liste_blanche" and waf_factice.appels == []
    assert r.json()["entrees_illisibles"] == ["203.0.113.0/33"]
    assert "liste_blanche_illisible" in _lignes(audit)[-1]


def test_pairs_non_verifies_signales(client, reactive, audit):
    del waf_factice.rep[("threatmesh", "/peers")]
    r = client.post("/defense/approve", json={"empreinte": P1, "simuler": True}, headers=ADMIN)
    assert r.status_code == 200 and r.json()["pairs_maillage"] == "non_verifies"
    assert "pairs_maillage=non_verifies" in _lignes(audit)[-1]
    r = client.post("/defense/approve", json={"empreinte": P1}, headers=ADMIN)
    assert r.status_code == 200 and r.json()["pairs_maillage"] == "non_verifies"
    assert all("pairs_maillage=non_verifies" in x for x in _lignes(audit)[-2:])


def test_pairs_verifies_dans_l_audit(client, reactive, audit):
    r = client.post("/defense/approve", json={"empreinte": P1}, headers=ADMIN)
    assert "pairs_maillage" not in r.json()
    assert "pairs_maillage=verifies" in [x for x in _lignes(audit) if "sade-approuve-demande" in x][-1]


def test_duree_trop_longue_refusee(client, reactive, proposition):
    pid = proposition("203.0.113.91", ttl=10_000_000)
    r = client.post("/defense/approve", json={"empreinte": pid}, headers=ADMIN)
    assert r.status_code == 409 and r.json()["cause"] == "duree_invalide"
    assert waf_factice.appels == [] and defense_etat.decision(pid)["etat_enregistre"] is None
    assert client.post("/defense/approve", json={"empreinte": proposition("203.0.113.92", ttl=9_999_999)},
                       headers=ADMIN).status_code == 200


def test_trop_d_adresses_refuse(client, reactive, proposition):
    trop = proposition(*[f"203.0.113.{i}" for i in range(100, 133)])
    r = client.post("/defense/approve", json={"empreinte": trop}, headers=ADMIN)
    assert r.status_code == 409 and r.json()["cause"] == "trop_d_adresses"
    assert waf_factice.appels == [] and defense_etat.decision(trop)["etat_enregistre"] is None
    assert client.post("/defense/approve", json={"empreinte": proposition(*[f"203.0.113.{i}" for i in range(100, 132)])},
                       headers=ADMIN).status_code == 200
    assert len(waf_factice.appels) == 32


def test_delai_waf_plus_long_que_wafctl(client, reactive, audit):
    assert defense.DELAI_WAF_S >= 25
    vus = []
    orig = waf_factice.ecrire

    def espion(source, chemin, corps, entetes=None, delai=10.0):
        vus.append(delai)
        return {"ok": False, "donnees": None, "erreur": "délai"}
    defense.substrat.ecrire = espion
    try:
        r = client.post("/defense/approve", json={"empreinte": P1}, headers=ADMIN)
    finally:
        defense.substrat.ecrire = orig
    assert vus == [defense.DELAI_WAF_S]
    assert r.status_code == 502 and r.json()["issue"] == "incertain"
    assert "issue=incertain" in [x for x in _lignes(audit) if "sade-approuve-resultat" in x][-1]


def test_chronologie_masquee_pour_un_lecteur(client, monkeypatch):
    import json
    actors = Path(__file__).resolve().parent / "donnees" / "substrat" / "actord_actors.json"
    waf_factice.rep[("actord", "/actors")] = json.loads(actors.read_text(encoding="utf-8"))
    _props()[0]["raison"] = "vu depuis 203.0.113.10 et 2001:db8::7 à 09:47:00"
    j = client.get("/defense/threats/ACT-0001", headers=LECTURE)
    assert j.status_code == 200
    libs = [c["libelle"] for c in j.json()["chronologie"] if c["capteur"] == "actord"]
    assert libs == ["vu depuis cible-1 et cible-2 à 09:47:00"]
    assert not IP.search(j.text) and "2001:db8" not in j.text

    async def ok(request, creds=None):
        return {"sub": "admin"}
    monkeypatch.setattr(defense, "require_jwt", ok)
    defense._CACHE.clear()
    libs = [c["libelle"] for c in client.get("/defense/threats/ACT-0001", headers=LECTURE).json()["chronologie"]
            if c["capteur"] == "actord"]
    assert libs == ["vu depuis 203.0.113.10 et 2001:db8::7 à 09:47:00"]


def test_masquer_ipv6_suivie_de_deux_points_et_ipv4_mappee():
    from api import defense
    assert defense._masquer("adresse 2001:db8::5: refus", {}) == "adresse cible-1: refus"
    m = {}
    assert defense._masquer("vu ::ffff:203.0.113.9 puis 64:ff9b::198.51.100.7.", m) == "vu cible-1 puis cible-2."
    assert defense._masquer("à 09:47:00 depuis 203.0.113.9.", {}) == "à 09:47:00 depuis cible-1."


def test_conclure_lie_a_la_demande():
    defense_etat.changer_mode("reactive", "op")
    rec = _reclame()
    assert rec.demande_ts
    defense_etat.conclure(P1, int(rec), "applique", "x", "1999-01-01T00:00:00Z")  # fil retardataire d'une autre demande
    assert defense_etat.etats_decisions()[P1] == "en_cours"
    defense_etat.conclure(P1, int(rec), "applique", "ok", rec.demande_ts)
    assert defense_etat.etats_decisions()[P1] == "applique"


def test_masquer_ipv4_avec_port_ou_collee():
    from api import defense
    assert defense._masquer("ip=203.0.113.9:8080, essai", {}) == "ip=cible-1:8080, essai"
    assert defense._masquer("a203.0.113.9", {}) == "acible-1"
