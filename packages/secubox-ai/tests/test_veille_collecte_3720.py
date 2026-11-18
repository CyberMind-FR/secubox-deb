# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Collecteur de la veille V2 (#3720) : normalisation sur le jeu de référence, idempotence, pannes, refus 401,
sources garde / dns / actord, rapprochement des compteurs. Aucun réseau : le client est simulé."""
import asyncio
import collections
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from veille import base, collecte, normaliser
from veille.client import ClientGk2, ErreurGk2, routes
from veille.sources import actord, bans, campagnes, dns, garde, menaces, toutes

PAQUET = Path(__file__).resolve().parents[1]
DONNEES = PAQUET / "tests" / "donnees"
T0 = datetime(2026, 11, 18, 12, 0, tzinfo=timezone.utc)


def _menaces():
    return [json.loads(x) for x in (DONNEES / "menaces.jsonl").read_text(encoding="utf-8").splitlines() if x.strip()]


class Faux:
    """Client simulé : `reponses[nom]` = objet, exception ou fonction(params)."""

    def __init__(self, reponses, horloge=T0.timestamp()):
        self.reponses = reponses
        self.appels = []
        self._h = horloge

    def horloge(self):
        return self._h

    async def get(self, nom, params=None):
        self.appels.append((nom, dict(params or {})))
        r = self.reponses[nom]
        if isinstance(r, Exception):
            raise r
        return r(params or {}) if callable(r) else r


def _flux(lignes, taille=500):
    """Flux de menaces simulé : positions `1:<n>`."""
    def rendre(params):
        debut = int(params["depuis"].split(":")[1]) if params.get("depuis") else 0
        page = lignes[debut:debut + taille]
        return {"lignes": [{"position": f"1:{debut + i + 1}", "ligne": json.dumps(x)} for i, x in enumerate(page)],
                "suivant": f"1:{debut + len(page)}", "rotation": False, "trou": False}
    return rendre


@pytest.fixture
def db(tmp_path):
    d = base.ouvrir(tmp_path / "veille.db")
    yield d
    d.close()


def _passe(db, client, sources, quand=T0, **kw):
    return asyncio.run(collecte.passe(db, client, sources, quand, **kw))


def test_normalisation_jeu_reference():
    lignes = _menaces()
    assert len(lignes) == 180
    evts = [normaliser.evenement("menaces", x, id_source=f"1:{i}") for i, x in enumerate(lignes)]
    familles = collections.Counter(e.famille for e in evts)
    assert familles == collections.Counter(x["category"].split(":")[0] for x in lignes)
    assert {"host_anomaly", "auth_smtp", "honeypot", "scanners"} <= set(familles)
    smtp = next(e for e in evts if e.famille == "auth_smtp")
    assert smtp.sous_famille == "sasl_failed" and smtp.gravite == "high"
    # +01:00 → UTC
    assert evts[0].horodatage == "2026-11-13T23:36:03Z"
    assert all(e.horodatage.endswith("Z") for e in evts)
    locales = [e for e in evts if e.attributs.get("local")]
    assert len(locales) == 8 and all(e.ip_src is None and e.bloc24 is None for e in locales)
    doc = next(e for e in evts if e.ip_src and e.ip_src.startswith("192.0.2."))
    assert doc.bloc24 == "192.0.2.0/24" and doc.attributs["exclu_correlation"] == "documentation"
    assert len({e.empreinte for e in evts}) == 180          # doublons exacts réels gardés (positions distinctes)
    # autotest du WAF marqué ; |prolonge → attribut ; message tronqué
    auto = normaliser.evenement("menaces", dict(lignes[2], user_agent="SecuBox-WAF-SelfTest/1", rule_id="x" * 2000))
    assert auto.attributs["autotest"] is True and len(auto.message) == 512
    ban = normaliser.evenement("bans", {"at": 1794510050, "cat": "leurre:unrouted|prolonge", "ip": "8.8.8.8",
                                        "sev": "medium"})
    assert (ban.famille, ban.sous_famille, ban.attributs["prolonge"]) == ("leurre", "unrouted", True)
    assert "exclu_correlation" not in ban.attributs and ban.bloc24 == "8.8.8.0/24"


def test_idempotence(db):
    client = Faux({"menaces_flux": _flux(_menaces())})
    assert _passe(db, client, [menaces.Menaces()]) == {"menaces": "ok"}
    assert db.execute("SELECT COUNT(*) FROM evenements").fetchone()[0] == 180
    # même lot relu depuis le début : rien de plus
    db.execute("UPDATE curseurs SET position = NULL, derniere_lecture = NULL")
    _passe(db, client, [menaces.Menaces()], T0 + timedelta(minutes=1))
    assert db.execute("SELECT COUNT(*) FROM evenements").fetchone()[0] == 180
    assert db.execute("SELECT position, lus_total FROM curseurs").fetchone() == ("1:180", 180)
    # bans relus sur la même seconde : sans doublon
    at = int(T0.timestamp()) - 3600
    acts = {"actions": [{"id": "a1", "created_at": at, "target": "8.8.8.8", "cat": "scanners"}],
            "complet": True}
    c2 = Faux({"enforcement": acts})
    _passe(db, c2, [bans.Bans()])
    _passe(db, c2, [bans.Bans()], T0 + timedelta(hours=1))
    assert db.execute("SELECT COUNT(*) FROM evenements WHERE source='bans'").fetchone()[0] == 1
    assert c2.appels[-1][1]["depuis"] == at


def test_reprise_apres_panne(db):
    lignes = _menaces()
    flux = _flux(lignes, taille=100)
    client = Faux({"menaces_flux": flux})
    src = [menaces.Menaces()]
    _passe(db, client, src)
    assert db.execute("SELECT position FROM curseurs").fetchone()[0] == "1:100"
    client.reponses["menaces_flux"] = ErreurGk2(None, "ConnectError")
    for k in range(1, 6):                       # gk2 injoignable plusieurs heures
        assert _passe(db, client, src, T0 + timedelta(hours=k)) == {"menaces": "en_panne"}
    pos, etat = db.execute("SELECT position, etat FROM curseurs").fetchone()
    assert (pos, etat) == ("1:100", "en_panne")
    client.reponses["menaces_flux"] = flux
    assert _passe(db, client, src, T0 + timedelta(hours=6)) == {"menaces": "ok"}
    assert client.appels[-1][1]["depuis"] == "1:100"
    assert db.execute("SELECT COUNT(*) FROM evenements").fetchone()[0] == 180      # sans perte ni doublon
    assert db.execute("SELECT etat, derniere_erreur FROM curseurs").fetchone() == ("ok", None)
    # actord : illisible = panne, absent = source vide normale
    c = Faux({"actord": {"available": False, "motif": "illisible", "propositions": None}})
    assert _passe(db, c, [actord.Actord()]) == {"actord": "en_panne"}
    c.reponses["actord"] = {"available": False, "motif": "absent", "propositions": None}
    assert _passe(db, c, [actord.Actord()], T0 + timedelta(hours=1)) == {"actord": "ok"}


def test_espacement_apres_401(db):
    client = Faux({"menaces_flux": ErreurGk2(401, "refus"), "enforcement": ErreurGk2(401, "refus")})
    src = [menaces.Menaces(), bans.Bans()]
    t, attentes = T0, []
    for _ in range(8):
        etats = _passe(db, client, src, t)
        assert etats == {"menaces": "en_panne", "bans": "en_panne"}
        prochain = json.loads(db.execute("SELECT derniere_erreur FROM curseurs WHERE source='menaces'").fetchone()[0])
        p = datetime.fromisoformat(prochain["prochain"].replace("Z", "+00:00"))
        attentes.append((p - t).total_seconds())
        # avant l'échéance : pas d'appel
        n = len(client.appels)
        _passe(db, client, [src[0]], p - timedelta(seconds=1))
        assert len(client.appels) == n
        t = max(p, datetime.fromisoformat(json.loads(db.execute(
            "SELECT derniere_erreur FROM curseurs WHERE source='bans'").fetchone()[0])["prochain"].replace("Z", "+00:00")))
    assert attentes[:3] == [30, 60, 120] and max(attentes) == 900 and attentes[-1] == 900
    # une ligne d'audit par motif et par 10 min (deux sources, même motif, même passe : une seule)
    lignes = db.execute("SELECT horodatage, objet FROM audit_chaine ORDER BY id").fetchall()
    assert lignes[0][1] == "refus_401"
    instants = [datetime.fromisoformat(h.replace("Z", "+00:00")) for h, _ in lignes]
    assert all((b - a).total_seconds() >= 600 for a, b in zip(instants, instants[1:]))
    assert len(lignes) < 8 * 2


def test_sources_ajoutees_garde_dns_actord(db):
    noms = {s.nom for s in toutes()}
    assert {"menaces", "bans", "bans_actifs", "blocs", "campagnes", "decisions", "reevaluations", "posture",
            "garde", "actord", "mesures", "dns"} == noms
    hist = {"heures": 24, "lignes": [
        {"id": 7, "menace": "infection", "debut": 1794585358, "fin": None, "etat": "active", "nom": "tv-salon",
         "motif": "dga"},
        {"menace": "intrusion", "debut": 1794585000, "n": 3, "adresses": ["8.8.8.8"], "etat": "active"}]}
    alertes = {"alertes": [{"id": "a1", "timestamp": "2026-11-18T11:00:00+00:00", "client_ip": "192.168.1.20",
                            "category": "dga:nxdomain", "severity": "high", "domaine": "x.example"}],
               "depuis": "…", "suivant": "1794999600:1", "complet": True, "trou": False}
    props = {"available": True, "propositions": [{"id": "p1", "ts": 1794585358, "ip": "8.8.4.4",
                                                  "categorie": "scanners", "sev": "high"}]}
    c = Faux({"garde_historique": hist, "dns_alertes": alertes, "actord": props})
    etats = _passe(db, c, [garde.Garde(), dns.Dns(), actord.Actord()])
    assert etats == {"garde": "ok", "dns": "ok", "actord": "ok"}
    fam = set(db.execute("SELECT source, famille FROM evenements").fetchall())
    assert fam == {("garde", "infection"), ("garde", "intrusion"), ("dns", "dga"), ("actord", "scanners")}
    assert db.execute("SELECT COUNT(*) FROM evenements WHERE source='garde'").fetchone()[0] == 2
    # dns : premier appel `depuis`, ensuite `apres=<suivant>`
    assert "depuis" in c.appels[1][1]
    _passe(db, c, [dns.Dns()], T0 + timedelta(minutes=5))
    assert c.appels[-1][1] == {"apres": "1794999600:1"}
    # campagnes en faits
    camp = {"available": True, "attaquants": 3, "campagnes": [{"signature": "cea8627e6f2c5244", "outil": "zgrab",
                                                               "attaquants": 3, "sondes": 277, "haute_valeur": 213}]}
    _passe(db, Faux({"campaigns": camp}), [campagnes.Campagnes()])
    assert db.execute("SELECT id, sondes FROM campagnes").fetchall() == [("cea8627e6f2c5244", 277)]


def test_rapprochement_compteurs(db):
    lignes = _menaces()
    _passe(db, Faux({"menaces_flux": _flux(lignes)}), [menaces.Menaces()])
    stats = collections.Counter(x["category"] for x in lignes)
    stats[next(iter(stats))] += 1                               # gk2 a compté une ligne de plus (< 1 %)
    r = collecte.rapprocher(db, dict(stats), T0 - timedelta(days=30), T0)
    assert r["total_local"] == 180 and r["total_gk2"] == 181
    assert r["ecart"] <= 0.01
    stats[next(iter(stats))] += 10
    assert collecte.rapprocher(db, dict(stats), T0 - timedelta(days=30), T0)["ecart"] > 0.01


def test_client_signe_get_et_chemin_exact():
    cle = Ed25519PrivateKey.generate()
    pem = cle.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                            serialization.NoEncryption())
    vus = []

    def repondre(req):
        vus.append(req)
        return httpx.Response(200, json={"lignes": []})
    table = routes({"veille": {"routes": {"garde_etat": {"url": "/garde/etat", "signe": "/api/v1/garde/etat"},
                                          "mauvaise": {"url": "/x", "signe": "/x?y=1"}}}})
    assert "mauvaise" not in table
    c = ClientGk2("https://admin.gk2.example/api/v1", "gk2", pem, table, transport=httpx.MockTransport(repondre),
                  horloge=lambda: T0.timestamp())
    asyncio.run(c.get("menaces_flux", {"depuis": "1:2", "max": 500}))
    req = vus[0]
    assert req.method == "GET" and req.url.path == "/api/v1/waf/menaces/flux"
    jeton = req.headers["authorization"].split()[1]
    rec = jwt.decode(jeton, cle.public_key(), algorithms=["EdDSA"], audience="gk2",
                     options={"verify_exp": False, "verify_iat": False})
    assert (rec["sub"], rec["methode"], rec["chemin"]) == ("ai-lecture", "GET", "/menaces/flux")

    c401 = ClientGk2("https://g/api/v1", "gk2", pem, transport=httpx.MockTransport(lambda r: httpx.Response(401)))
    with pytest.raises(ErreurGk2) as e:
        asyncio.run(c401.get("stats"))
    assert e.value.code == 401


def test_trou_et_rotation_signales(db, caplog):
    lignes = _menaces()[:3]

    def flux(params):
        r = _flux(lignes)(params)
        r.update(trou=True, rotation=True)
        return r
    c = Faux({"menaces_flux": flux})
    with caplog.at_level("INFO", logger="secubox-ai-veille"):
        assert _passe(db, c, [menaces.Menaces()]) == {"menaces": "ok"}
    assert any("trou" in r.message and r.levelname == "WARNING" for r in caplog.records)
    assert any("rotation" in r.message and r.levelname == "INFO" for r in caplog.records)
    pos, err = db.execute("SELECT position, derniere_erreur FROM curseurs").fetchone()
    assert pos == "1:3" and json.loads(err) == {"trous": 1}
    _passe(db, c, [menaces.Menaces()], T0 + timedelta(minutes=1))
    assert json.loads(db.execute("SELECT derniere_erreur FROM curseurs").fetchone()[0]) == {"trous": 2}
    assert db.execute("SELECT COUNT(*) FROM audit_chaine WHERE operation='collecte_trou'").fetchone()[0] == 2


def test_horodatage_naif_ignore_et_faits_mal_formes(db, caplog):
    sans_decalage = dict(_menaces()[0], timestamp="2026-11-14T00:36:03")
    c = Faux({"menaces_flux": _flux([sans_decalage, _menaces()[1]])})
    with caplog.at_level("WARNING", logger="secubox-ai-veille"):
        _passe(db, c, [menaces.Menaces()])
    assert db.execute("SELECT COUNT(*) FROM evenements").fetchone()[0] == 1
    assert any("ignorée" in r.message for r in caplog.records)
    assert normaliser.utc("2026-11-14T00:36:03") is None
    assert normaliser.utc("2026-11-14T00:36:03", naif_utc=True) == "2026-11-14T00:36:03Z"
    collecte._ranger_faits(db, {"campagnes": [None, {"outil": "x"}, {"id": "s1"}], "blocs": ["x", {"bloc24": "1.2.3.0/24"}]},
                           "2026-11-18T12:00:00Z")
    assert db.execute("SELECT id FROM campagnes").fetchall() == [("s1",)]
    assert db.execute("SELECT bloc24 FROM blocs").fetchall() == [("1.2.3.0/24",)]
