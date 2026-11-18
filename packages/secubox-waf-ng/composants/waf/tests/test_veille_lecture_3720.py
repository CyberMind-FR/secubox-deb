# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""#3720 : routes de lecture de la veille V2 (gk3) sur le WAF de gk2 — flux à curseur du journal des menaces,
`depuis` sur `/enforcement`, `limite` sur `/campaigns`, `/mesures`, `/actord/propositions`, garde
`require_lecture_ou_compte("ai-lecture")` (jeton lié à GET et au chemin VU PAR L'APPLICATION : nginx retire
`/api/v1/waf`, gk3 signe donc `/menaces/flux`, `/enforcement`…)."""
from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

import pytest

COMPOSANT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(COMPOSANT))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_gestes_ia_3716 import FauxWafctl, _importer_waf, _regroupement_neuf  # noqa: E402

L1 = {"timestamp": "2026-11-14T00:36:03+01:00", "client_ip": "203.0.113.21", "category": "auth_smtp:sasl_failed"}


def _ligne(i: int) -> bytes:
    return (json.dumps({**L1, "path": f"/p{i}"}) + "\n").encode()


@pytest.fixture
def v(monkeypatch, tmp_path):
    """L'application du WAF avec la VRAIE garde, une clé `ai-lecture` posée, des journaux dans `tmp_path`."""
    from fastapi.testclient import TestClient
    from secubox_core import auth
    from secubox_core import compte_service as cs
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
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
    monkeypatch.setenv("SECUBOX_WAF_GESTES_IA", "1")
    monkeypatch.setattr(waf, "AUDIT_LOG", tmp_path / "audit.log")
    monkeypatch.setattr(waf, "THREATS_LOG", str(tmp_path / "waf-threats.log"))
    monkeypatch.setattr(waf, "BANS_JOURNAL", tmp_path / "bans.jsonl")
    monkeypatch.setattr(waf, "MESURES_JOURNAL", tmp_path / "mesures.jsonl")
    monkeypatch.setattr(waf, "ACTORD_PROPOSITIONS", tmp_path / "actord-propositions.json")
    monkeypatch.setattr(waf, "CAMPAIGNS_FILE", str(tmp_path / "campaigns.json"))
    monkeypatch.setattr(waf, "_ips_bannies_actives", lambda: set())
    monkeypatch.setattr(g, "JOURNAL_AI", tmp_path / "ai-ban.jsonl")
    _regroupement_neuf(monkeypatch, g)
    monkeypatch.setattr(g, "_executer", FauxWafctl())
    monkeypatch.setitem(g._config, "bans", lambda: [])
    objet = Ed25519PrivateKey.generate()
    pem_pub = objet.public_key().public_bytes(serialization.Encoding.PEM,
                                              serialization.PublicFormat.SubjectPublicKeyInfo)
    dossier = tmp_path / "comptes" / "ai-lecture"
    dossier.mkdir(parents=True)
    os.chmod(tmp_path / "comptes", 0o755)
    os.chmod(dossier, 0o755)
    f = dossier / f"{cs.empreinte(pem_pub)}.pub"
    f.write_bytes(pem_pub)
    os.chmod(f, 0o644)
    prive = objet.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                serialization.NoEncryption())

    class V:
        c, w, t, auth_ = TestClient(waf.app), waf, tmp_path, auth

        def get(self, chemin, params=None, signe=None, **kw):
            """GET avec un jeton ai-lecture signé sur `signe` (défaut : le chemin de la requête)."""
            j = cs.frapper_jeton(prive, "ai-lecture", "gk2", b"", time.time(), methode="GET",
                                 chemin=signe or chemin)
            return self.c.get(chemin, params=params, headers={"Authorization": f"Bearer {j}"}, **kw)
    try:
        yield V()
    finally:
        waf.app.dependency_overrides.clear()


# ── flux à curseur ─────────────────────────────────────────────────────
def test_flux_curseur(v):
    log = v.t / "waf-threats.log"
    log.write_bytes(b"".join(_ligne(i) for i in range(5)) + b'{"partielle":')   # dernière ligne en cours
    ino = os.stat(log).st_ino
    r = v.get("/menaces/flux", params={"max": 3})
    assert r.status_code == 200, r.text
    d = r.json()
    assert [x["ligne"]["path"] for x in d["lignes"]] == ["/p0", "/p1", "/p2"]
    assert d["lignes"][0]["position"] == f"{ino}:0" and d["lignes"][1]["position"] == f"{ino}:{len(_ligne(0))}"
    assert d["rotation"] is False and d["trou"] is False
    d2 = v.get("/menaces/flux", params={"depuis": d["suivant"], "max": 100}).json()
    assert [x["ligne"]["path"] for x in d2["lignes"]] == ["/p3", "/p4"]          # jamais la ligne partielle
    with open(log, "ab") as f:
        f.write(b'"x"}\n')
    d3 = v.get("/menaces/flux", params={"depuis": d2["suivant"]}).json()
    assert [x["ligne"] for x in d3["lignes"]] == [{"partielle": "x"}]
    # un curseur au milieu d'une ligne : 422, jamais une ligne coupée
    assert v.get("/menaces/flux", params={"depuis": f"{ino}:3"}).status_code == 422


def test_flux_rotation_sans_trou(v):
    log, tourne = v.t / "waf-threats.log", v.t / "waf-threats.log.1"
    log.write_bytes(b"".join(_ligne(i) for i in range(4)))
    d = v.get("/menaces/flux", params={"max": 2}).json()
    log.rename(tourne)                                  # logrotate : renommage, l'inode part en .1
    with open(tourne, "ab") as f:                       # écrite juste avant la rotation
        f.write(_ligne(4))
    log.write_bytes(b"".join(_ligne(i) for i in range(5, 8)))
    vus = [x["ligne"]["path"] for x in d["lignes"]]
    suivant, rotation = d["suivant"], False
    for _ in range(10):
        d = v.get("/menaces/flux", params={"depuis": suivant, "max": 2}).json()
        rotation |= d["rotation"]
        assert d["trou"] is False
        vus += [x["ligne"]["path"] for x in d["lignes"]]
        if not d["lignes"]:
            break
        suivant = d["suivant"]
    assert vus == [f"/p{i}" for i in range(8)] and rotation
    assert d["suivant"] == f"{os.stat(log).st_ino}:{log.stat().st_size}"


def test_flux_inode_inconnu_signale_un_trou(v):
    log = v.t / "waf-threats.log"
    log.write_bytes(_ligne(0))
    d = v.get("/menaces/flux", params={"depuis": "1:0"}).json()
    assert d["trou"] is True and d["rotation"] is True and [x["ligne"]["path"] for x in d["lignes"]] == ["/p0"]


def test_flux_max_borne(v):
    log = v.t / "waf-threats.log"
    log.write_bytes(b"".join(_ligne(i) for i in range(2500)))
    d = v.get("/menaces/flux", params={"max": 2000}).json()
    assert len(d["lignes"]) == 2000
    for p in ({"max": 2001}, {"max": 0}, {"max": "x"}, {"depuis": "abc"}, {"depuis": "1:2:3"},
              {"depuis": "1" * 21 + ":0"}, {"depuis": "-1:0"}):
        assert v.get("/menaces/flux", params=p).status_code == 422, p


def test_flux_plafond_d_octets(v, monkeypatch):
    monkeypatch.setattr(v.w, "FLUX_OCTETS_MAX", 3 * len(_ligne(0)) + 5)
    (v.t / "waf-threats.log").write_bytes(b"".join(_ligne(i) for i in range(20)))
    d = v.get("/menaces/flux", params={"max": 2000}).json()
    assert len(d["lignes"]) == 3


def test_flux_ligne_illisible_et_demesuree_ne_bloquent_pas(v):
    from api import veille_lecture as vl
    (v.t / "waf-threats.log").write_bytes(b"pas du json\n" + b"x" * (vl.LIGNE_MAX + 10) + b"\n" + _ligne(1))
    d = v.get("/menaces/flux").json()
    assert [x.get("motif") for x in d["lignes"]] == ["illisible", "trop_longue", None]
    assert d["lignes"][2]["ligne"]["path"] == "/p1"


# ── /enforcement?depuis ────────────────────────────────────────────────
def _ban(ip, at, exp=None, action="ban"):
    return {"ip": ip, "cat": "leurre:u", "sev": "high", "at": at, "exp": exp or at + 3600, "action": action}


def test_enforcement_depuis(v, monkeypatch):
    now = int(time.time())
    lignes = [_ban(f"203.0.113.{i}", now - 5000 + i * 100) for i in range(40)]
    (v.t / "bans.jsonl").write_text("".join(json.dumps(x) + "\n" for x in lignes))
    depuis = now - 5000 + 30 * 100
    d = v.get("/enforcement", params={"depuis": depuis}).json()
    assert [a["created_at"] for a in d["actions"]] == [now - 5000 + i * 100 for i in range(30, 40)]
    assert d["complet"] is True and d["depuis"] == depuis
    d = v.get("/enforcement", params={"depuis": depuis, "limite": 4}).json()
    assert [a["target"] for a in d["actions"]] == [f"203.0.113.{i}" for i in range(30, 34)] and d["complet"] is False
    # lecture par la FIN : la remontée s'arrête bien avant le début du journal
    from api import veille_lecture as vl
    vrai, lus = vl.lire_fin_jsonl, []

    def espion(chemin, garder, arreter, *a):
        return vrai(chemin, garder, lambda r: (lus.append(r) or arreter(r)), *a)
    monkeypatch.setattr(vl, "lire_fin_jsonl", espion)
    v.get("/enforcement", params={"depuis": depuis})
    assert len(lus) < 25
    for p in ({"depuis": -1}, {"depuis": "x"}, {"depuis": 10**11}, {"limite": 0}, {"limite": 1001},
              {"statut": "autre"}):
        assert v.get("/enforcement", params=p).status_code == 422, p


def test_lecture_par_la_fin_bornee_en_octets(tmp_path):
    from api import veille_lecture as vl
    p = tmp_path / "j.jsonl"
    p.write_text("".join(json.dumps({"at": i}) + "\n" for i in range(10000)) + '{"at": 99')
    recs, complet = vl.lire_fin_jsonl(p, lambda r: True, lambda r: False, 1000, 10**6)
    assert not complet and recs and recs[-1] == {"at": 9999} and len(recs) < 100


# ── /campaigns?limite ──────────────────────────────────────────────────
def test_campagnes_limite(v):
    camps = [{"signature": f"s{i}", "attaquants": ["203.0.113.1"], "exemple_sequence": ["/"] * 20} for i in range(60)]
    (v.t / "campaigns.json").write_text(json.dumps({"attaquants": 1, "campagnes": camps}))
    assert len(v.get("/campaigns").json()["campagnes"]) == 20             # défaut inchangé
    d = v.get("/campaigns", params={"limite": 60}).json()
    assert len(d["campagnes"]) == 60 and len(d["campagnes"][0]["exemple_sequence"]) == 12
    for p in ({"limite": 0}, {"limite": 1001}, {"limite": "x"}):
        assert v.get("/campaigns", params=p).status_code == 422, p


# ── /mesures, /actord/propositions ─────────────────────────────────────
def test_mesures_et_propositions(v):
    (v.t / "mesures.jsonl").write_text("".join(json.dumps({"ts": t, "actor": "ACT-0001"}) + "\n"
                                               for t in (100, 200, "2026-11-14T00:00:00Z")))
    d = v.get("/mesures", params={"depuis": 150}).json()
    assert [m["ts"] for m in d["mesures"]] == [200, "2026-11-14T00:00:00Z"] and d["complet"]
    for p in ({"depuis": -1}, {"limite": 0}, {"limite": 2001}):
        assert v.get("/mesures", params=p).status_code == 422, p
    assert v.get("/actord/propositions").json() == {"available": False, "motif": "absent", "propositions": None}
    (v.t / "actord-propositions.json").write_text(json.dumps({"propositions": [{"ip": "203.0.113.9"}]}))
    assert v.get("/actord/propositions").json()["propositions"] == {"propositions": [{"ip": "203.0.113.9"}]}


# ── garde ──────────────────────────────────────────────────────────────
ROUTES_AI_LECTURE = ["/alerts", "/menaces/flux", "/enforcement", "/bans", "/campaigns", "/decisions",
                     "/reevaluations", "/stats", "/geoip/{ip}", "/mesures", "/actord/propositions"]


def test_routes_ai_lecture_get_seulement(v):
    garde = v.w.require_lecture_ai
    for chemin in ROUTES_AI_LECTURE:
        route = next(r for r in v.w.app.routes if getattr(r, "path", None) == chemin)
        assert route.methods == {"GET"}, chemin
        assert garde in [d.call for d in route.dependant.dependencies], chemin
    # aucune route POST ni d'administration n'admet le jeton
    assert v.get("/history").status_code == 401 and v.get("/info").status_code == 401
    (v.t / "bans.jsonl").write_text("")
    from secubox_core import compte_service as cs
    assert v.c.post("/ban", json={"ip": "203.0.113.1"}).status_code == 401
    # le jeton signé pour un chemin ne vaut pas pour un autre
    assert v.get("/campaigns", signe="/menaces/flux").status_code == 401
    assert v.get("/menaces/flux").status_code == 200
    assert cs.COMPTES_LIES_REQUETE["ai-lecture"] == frozenset({"GET"})


def test_chemin_signe_est_celui_vu_par_l_application(v):
    """nginx (`location /api/v1/waf/ { proxy_pass …waf.sock:/; }`) retire le préfixe : gk3 signe `/menaces/flux`."""
    conf = (COMPOSANT / "nginx" / "waf.conf").read_text()
    assert "location /api/v1/waf/ {" in conf and "proxy_pass http://unix:/run/secubox/waf.sock:/;" in conf
    (v.t / "waf-threats.log").write_bytes(_ligne(0))
    assert v.get("/menaces/flux", params={"max": 5}).status_code == 200
    assert v.get("/menaces/flux", signe="/api/v1/waf/menaces/flux").status_code == 401
    readme = (COMPOSANT.parents[1] / "README.md").read_text()
    for chemin in ("/menaces/flux", "/enforcement", "/campaigns", "/mesures", "/actord/propositions", "/ai/etat"):
        assert f"`{chemin}`" in readme, chemin


def test_ai_etat_ouvert_a_ai_lecture(v):
    r = v.get("/ai/etat")
    assert r.status_code == 200, r.text
    assert "actifs" in r.json()
    assert v.get("/ai/etat", signe="/menaces/flux").status_code == 401


def test_sans_porteur_comportement_anonyme_inchange(v, monkeypatch):
    async def anonyme(request, creds):
        return {"tableau_de_bord": True, "sub": None}
    monkeypatch.setattr(v.auth_, "require_lecture", anonyme)
    (v.t / "campaigns.json").write_text(json.dumps({"attaquants": 0, "campagnes": []}))
    assert v.c.get("/campaigns").status_code == 200
    # un porteur EdDSA mal formé ne retombe JAMAIS en anonyme
    assert v.c.get("/campaigns", headers={"Authorization": "Bearer pas.un.jeton"}).status_code == 401


def test_propositions_motifs_et_journal_espace(v, monkeypatch):
    p = v.t / "actord-propositions.json"
    notes = []
    monkeypatch.setattr(v.w, "_propositions_logue", {})
    monkeypatch.setattr(v.w.log, "warning", lambda *a: notes.append(a[1]))
    assert v.get("/actord/propositions").json()["motif"] == "absent"
    p.write_text("{pas du json")
    assert v.get("/actord/propositions").json() == {"available": False, "motif": "invalide", "propositions": None}
    p.write_text("{}")
    vrai_open = open

    def refuse(chemin, *a, **k):
        if Path(chemin) == p:
            raise PermissionError(13, "Permission denied")
        return vrai_open(chemin, *a, **k)
    monkeypatch.setattr("builtins.open", refuse)
    assert v.get("/actord/propositions").json()["motif"] == "illisible"
    assert v.get("/actord/propositions").json()["motif"] == "illisible"
    monkeypatch.setattr("builtins.open", vrai_open)
    assert notes == ["absent", "invalide", "illisible"]          # une ligne par motif (10 min)


def test_flux_ligne_demesuree_compte_dans_le_plafond(v, monkeypatch):
    from api import veille_lecture as vl
    monkeypatch.setattr(v.w, "FLUX_OCTETS_MAX", vl.LIGNE_MAX * 2)
    grande = b"x" * (vl.LIGNE_MAX * 3) + b"\n"
    (v.t / "waf-threats.log").write_bytes(grande + grande + _ligne(0))
    d = v.get("/menaces/flux").json()
    assert [x.get("motif") for x in d["lignes"]] == ["trop_longue"]        # plafond atteint après le premier saut
    d = v.get("/menaces/flux", params={"depuis": d["suivant"]}).json()
    assert [x.get("motif") for x in d["lignes"]] == ["trop_longue"]


def test_actord_publie_au_groupe_secubox_waf():
    unite = (COMPOSANT.parents[1] / "systemd" / "secubox-actord.service").read_text()
    assert "SupplementaryGroups=secubox-waf" in unite and "actord-ingest" not in unite.split("SupplementaryGroups=")[1].splitlines()[0]
