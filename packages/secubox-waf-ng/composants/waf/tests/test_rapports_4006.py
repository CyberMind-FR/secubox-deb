# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Chantier #4006 : rapports de menaces multi-historiques, rédigés par l'IA et vérifiés par le code.

Cas réel rejoué : le dossier de l'aspirateur de la forge et la réponse fautive de Jarvis (Gemma local, 27/11) — 4 phrases
fausses (causalité inventée, capacité de la box, tactique supposée) sur 7, que la consigne n'avait pas empêchées. Le reste :
historique et récurrences sur données synthétiques (adresses de DOCUMENTATION), repli sans IA, aucune adresse rendue."""
import asyncio
import gzip
import ipaddress
import json
import sys
import types
from datetime import datetime, timedelta
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from api import rapports as R  # noqa: E402
from api import verif_rapport as V  # noqa: E402

ICI = Path(__file__).resolve().parent / "donnees"
DOSSIER_27_11 = json.loads((ICI / "rapport_4006_aspirateur.json").read_text(encoding="utf-8"))
JARVIS_27_11 = (ICI / "rapport_4006_jarvis.txt").read_text(encoding="utf-8")
MAINTENANT = datetime(2026, 11, 27, 12, 0, 0).timestamp()      # midi local : les jours de la box sont locaux
JOUR = 86400


def _doc(ip):
    try:
        a = ipaddress.ip_address(str(ip))
    except ValueError:
        return None
    return str(a) if any(a in ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")) else None


@pytest.fixture(autouse=True)
def adresses_de_documentation(monkeypatch):
    monkeypatch.setattr(R._pop, "_adresse_publique", _doc)


# ── cas réel du 27/11 ───────────────────────────────────────────────────────────────────────────────────────────────

FAUSSES = ("a aussi révélé un biais", "a corrigé ce problème", "sait déjà déduire des profils", "exploitant les failles du WAF")
JUSTES = ("13 630 bans", "4 retours sur 11 249", "double tampon")


def test_cas_reel_27_11_quatre_fausses_retirees_trois_justes_gardees():
    v = V.verifier(JARVIS_27_11, DOSSIER_27_11)
    gardees = [g["texte"] for g in v["gardees"]]
    retirees = [r["texte"] for r in v["retirees"]]
    assert v["phrases"] == 7 and v["retenues"] == 3 and v["taux_retenues_pct"] == 43
    for f in FAUSSES:
        assert any(f in t for t in retirees) and not any(f in t for t in gardees), f
    for j in JUSTES:
        assert any(j in t for t in gardees), j
    # l'hypothèse de réaction est gardée MARQUÉE ; les deux autres sont des faits
    statuts = {g["texte"][:20]: g["statut"] for g in v["gardees"]}
    assert sorted(statuts.values()) == ["hypothese", "retenue", "retenue"]
    assert "(hypothèse) Les adresses semblent jetables" in V.texte_publie(v["gardees"])


def test_cas_reel_motifs_de_retrait_documentes():
    v = V.verifier(JARVIS_27_11, DOSSIER_27_11)
    motifs = " ".join(m for r in v["retirees"] for m in r["motifs"])
    assert "causalité" in motifs and "capacité" in motifs


@pytest.mark.parametrize("phrase,motif", [
    ("La période observée s'est terminée le 30/08.", "mal attribuée"),               # 30/08 est un début, pas une fin
    ("Au total, 27 118 adresses IP ont été bannies.", "mal attribué"),              # 27 118 est un nombre de BANS
    ("Le ban dès la 1re requête du 24/11 a donné 13 631 bans.", "absent"),          # chiffre inventé
    ("Le 25/11, 13 630 bans ont été posés.", "date absente"),
    ("Les requêtes venaient d'OVH vers forge.gk2.secubox.in.", "nom absent du dossier : OVH"),   # opérateur inventé
    ("Les requêtes visaient mail.gk2.secubox.in avec 4 retours.", "nom absent"),     # hôte inventé
    ("La CVE-2024-3094 a été tentée 4 fois.", "nom absent"),
    ("Les bans sont en forte hausse depuis le 24/11.", "tendance"),
    ("L'attaque est sophistiquée.", "non adossée"),
])
def test_phrases_inventees_retirees(phrase, motif):
    v = V.verifier(phrase, DOSSIER_27_11)
    assert v["retenues"] == 0 and motif in " ".join(v["retirees"][0]["motifs"]), v["retirees"]


@pytest.mark.parametrize("phrase", [
    "Le ban dès la 1re requête du 24/11 a donné 13 630 bans ; la liste compte 20 931 adresses.",
    "L'infrastructure est louée : 62 % des adresses chez des proxys loués.",
    "La forge forge.gk2.secubox.in reçoit 97 % des requêtes, catégorie aspirateur_ua.",
    "Sur 90 jours, 27 118 bans ont été posés sur 9 874 réseaux /24.",
])
def test_phrases_adossees_gardees(phrase):
    assert V.verifier(phrase, DOSSIER_27_11)["retenues"] == 1


def test_adresse_ip_jamais_rendue():
    v = V.verifier("L'adresse 203.0.113.7 et 2001:db8::1 ont fait 4 retours.", DOSSIER_27_11)
    assert v["retenues"] == 0 and v["retirees"][0]["texte"] is None
    assert "203.0.113" not in json.dumps(v) and "2001:db8" not in json.dumps(v)


# ── historique long, récurrences, phases, liens (synthétique) ──────────────────────────────────────────────────────

def _ban(ip, cat, jours_avant, heure=3):
    j = datetime.fromtimestamp(MAINTENANT) - timedelta(days=jours_avant)
    at = j.replace(hour=heure, minute=0, second=0).timestamp()
    return json.dumps({"ip": ip, "cat": cat, "sev": "high", "at": int(at), "exp": int(at) + 3600, "action": "ban"})


def _etat(tmp_path):
    """Deux vagues d'aspiration séparées de 20 jours d'extinction : la seconde ramène 3 /24 et 2 adresses déjà vus.
    Un repérage (scanners) précède. Une prolongation, une adresse privée et une hors fenêtre sont écartées."""
    v1 = [f"192.0.2.{i}" for i in range(1, 11)] + [f"198.51.100.{i}" for i in range(1, 6)]
    v2 = ["192.0.2.1", "192.0.2.2", "192.0.2.200"] + [f"198.51.100.{i}" for i in range(100, 110)] + ["203.0.113.5"]
    lignes = [_ban("203.0.113.9", "scanners", 60 - k) for k in range(4)]
    lignes += [_ban(ip, "aspirateur_ua", 40 - (k % 3)) for k, ip in enumerate(v1)]
    lignes += [_ban(ip, "aspirateur_ua", 15 - (k % 2), heure=4) for k, ip in enumerate(v2)]
    lignes += [_ban("192.0.2.1", "aspirateur_ua|prolonge", 14), _ban("10.0.0.1", "aspirateur_ua", 14),
               _ban("192.0.2.3", "aspirateur_ua", 120)]
    # une partie du passé dans l'archive mensuelle (bans-AAAAMM.jsonl.gz)
    d = datetime.fromtimestamp(MAINTENANT)
    m = d.month - 1 or 12
    archive = tmp_path / f"bans-{d.year if d.month > 1 else d.year - 1:04d}{m:02d}.jsonl.gz"
    with gzip.open(archive, "wt", encoding="utf-8") as f:
        f.write("\n".join(lignes[:10]) + "\n")
    (tmp_path / "bans.jsonl").write_text("\n".join(lignes[10:]) + "\nligne illisible\n", encoding="utf-8")
    return v1, v2


def test_historique_vagues_recurrences_phases(tmp_path):
    v1, v2 = _etat(tmp_path)
    bans = R.lire_bans(str(tmp_path), MAINTENANT)
    assert bans.lisible and bans.n == 4 + len(v1) + len(v2)
    ips = set(bans.ips_par_cat["aspirateur_ua"]) | {"203.0.113.9"}
    h = R.historique(ips, bans, MAINTENANT, lambda ip: "Opérateur A" if ip.startswith("192.0.2.") else "Opérateur B")
    assert len(h["serie_jour"]) == 90 and sum(h["serie_jour"]) == h["bans"] == bans.n
    assert sum(s["bans"] for s in h["serie_semaine"]) == h["bans"]
    assert [v["bans"] for v in h["vagues"]] == [len(v1), len(v2)]     # le repérage (4 bans) reste sous MIN_BANS_VAGUE
    (r,) = h["recurrences"]
    assert r["extinction_jours"] >= R.EXTINCTION_JOURS and r["adresses_revenues"] == 2 and r["blocs24_revenus"] == 2
    assert r["operateurs_revenus"] == ["Opérateur A", "Opérateur B"]
    assert [p["phase"] for p in h["phases"]] == ["repérage", "collecte"] and h["enchainement_type"] is True


def test_liens_entre_sujets(tmp_path):
    _etat(tmp_path)
    bans = R.lire_bans(str(tmp_path), MAINTENANT)
    a = {"genre": "campagne", "id": "famille:collecte", "nom": "A", "ips": set(bans.ips_par_cat["aspirateur_ua"]),
         "pop": {"cibles": ["forge.example.test"], "profil": {"ua_premier": "Mozilla/5.0 X"}}}
    b = {"genre": "acteur", "id": "ACT-0001", "nom": "B", "ips": set(sorted(bans.ips_par_cat["aspirateur_ua"])[3:]),
         "pop": {"cibles": ["forge.example.test"], "profil": {"ua_premier": "Mozilla/5.0 X"}}}
    for s in (a, b):
        s["_h"] = R.historique(s["ips"], bans, MAINTENANT, lambda ip: "")
    li = R.liens([a, b])
    (l_a,) = li["campagne:famille:collecte"]
    assert l_a["avec"] == "acteur:ACT-0001" and {"empreinte", "cibles", "adresses_communes"} <= set(l_a["motifs"])


def _calcul(tmp_path):
    _etat(tmp_path)
    bans = R.lire_bans(str(tmp_path), MAINTENANT)
    releve = {"populations": [{"id": "famille:collecte", "famille": "collecte", "nom_cible": "forge.example.test",
                               "adresses": 25, "lecture": [{"code": "adresses_jetables", "valeur": 1,
                                                            "texte": "Adresses jetables : 1 retours sur 120 relâchées."}]}]}
    sujets = R.sujets_campagnes(releve, None, bans)
    return R.calculer(sujets, bans, MAINTENANT, lambda ip: "Opérateur A",
                      [{"date": (datetime.fromtimestamp(MAINTENANT) - timedelta(days=3)).date().isoformat(),
                        "libelle": "ban dès la première requête"}])


def test_dossier_sans_adresse_et_lecture_par_regles_toujours_adossee(tmp_path):
    r = _calcul(tmp_path)
    brut = json.dumps(r, ensure_ascii=False)
    assert not V.IPV4.search(brut) and "192.0.2" not in brut and "198.51.100" not in brut
    rap = r["rapports"]["campagne:famille:collecte"]
    d = rap["dossier"]
    assert d["chiffres"]["vagues"] == 2 and d["recurrences"] and d["jalons"]
    assert "bannir au réseau /24 plutôt qu'à l'adresse" in d["pistes"]
    v = V.verifier("\n".join(rap["regles"]), d)
    assert v["taux_retenues_pct"] == 100, v["retirees"]
    assert R.markdown(rap, None).startswith("# Rapport de menace")


def test_double_tampon(tmp_path):
    cache = tmp_path / "rapports.json"
    assert R.ecrire_cache(str(cache), {"complet": True, "genere_le": 1000, "rapports": {"a": {}}, "sujets": []})
    assert not R.ecrire_cache(str(cache), {"complet": False, "genere_le": 1600, "rapports": {}, "sujets": []})
    assert R.lire_cache(str(cache))["rapports"] == {"a": {}}
    assert R.ecrire_cache(str(cache), {"complet": False, "genere_le": 1000 + R.DOUBLE_TAMPON_S + 1, "rapports": {}, "sujets": []})


def test_rafraichir_sources_absentes_partiel(tmp_path, monkeypatch):
    monkeypatch.setattr(R._pop, "BASES_ASN", (str(tmp_path / "absent.mmdb"),))
    monkeypatch.setattr(R._pop, "BASES_PAYS", (str(tmp_path / "absent-pays.mmdb"),))
    monkeypatch.setattr(R, "JALONS", str(tmp_path / "absent.json"))
    assert R.rafraichir(str(tmp_path / "r.json"), MAINTENANT, str(tmp_path), str(tmp_path / "absent.json"),
                        str(tmp_path / "absent-prof.json"), str(tmp_path / "absent.sock"))
    r = R.lire_cache(str(tmp_path / "r.json"))
    assert r["complet"] is False and "populations" in r["manques"] and "actord" in r["manques"]


# ── rédaction IA et repli ───────────────────────────────────────────────────────────────────────────────────────────

class _Rep:
    def __init__(self, code, corps=None):
        self.status_code, self._c = code, corps

    def json(self):
        return self._c


class _Client:
    def __init__(self, texte=None, sante=200, envoyes=None):
        self.texte, self.sante, self.envoyes = texte, sante, envoyes if envoyes is not None else []

    async def get(self, url, **_):
        return _Rep(self.sante)

    async def post(self, url, json=None):
        self.envoyes.append(json)
        return _Rep(200, {"choices": [{"message": {"content": self.texte}}]})


def test_redaction_verifiee_et_dossier_seul_envoye():
    envoyes = []
    res = asyncio.run(R.rediger("campagne:famille:collecte", DOSSIER_27_11, ["http://127.0.0.1:8096"],
                                client=_Client(JARVIS_27_11, envoyes=envoyes)))
    assert res["etat"] == "fait" and res["taux_retenues_pct"] == 43 and res["retenues"] == 3
    assert "révélé" not in res["texte"] and "13 630 bans" in res["texte"]
    (corps,) = envoyes
    assert corps["messages"][1]["content"] == "<dossier>" + json.dumps(DOSSIER_27_11, ensure_ascii=False) + "</dossier>"
    md = R.markdown({"dossier": DOSSIER_27_11, "regles": ["Fait."]}, res)
    assert "43 % de phrases retenues" in md and "(hypothèse)" in md


@pytest.mark.parametrize("urls,client,motif", [
    ([], None, "aucun moteur"),
    (["http://127.0.0.1:8096"], _Client("x", sante=503), "endormi"),
])
def test_repli_sans_ia(urls, client, motif):
    res = asyncio.run(R.rediger("campagne:x", DOSSIER_27_11, urls, client=client))
    assert res["etat"] == "repli" and motif in res["motif"]
    md = R.markdown({"dossier": DOSSIER_27_11, "regles": ["Sur 90 jours : 27 118 bans."]}, res)
    assert "Sur 90 jours : 27 118 bans." in md and "seule la lecture par règles" in md


def test_repli_moteur_injoignable():
    class Panne(_Client):
        async def get(self, url, **_):
            import httpx
            raise httpx.ConnectError("refusé")
    res = asyncio.run(R.rediger("campagne:x", DOSSIER_27_11, ["http://127.0.0.1:1"], client=Panne()))
    assert res["etat"] == "repli" and "injoignable" in res["motif"]


def test_urls_moteurs_voie_zia(tmp_path):
    z = tmp_path / "zia.toml"
    z.write_text('llm_url = "http://127.0.0.1:8091"\nllm_urls = ["http://127.0.0.1:8096", "http://10.0.0.9:80"]\n')
    assert R.urls_moteurs({}, str(z)) == ["http://127.0.0.1:8096", "http://127.0.0.1:8091"]   # http hors boucle : refusé
    assert R.urls_moteurs({"rapports": {"llm_urls": ["https://ia.example.test"]}}, str(z)) == ["https://ia.example.test"]


# ── routes ──────────────────────────────────────────────────────────────────────────────────────────────────────────

def _importer_waf():
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
    monkeypatch.setattr(w, "RAPPORTS_CACHE", tmp_path / "rapports.json")
    monkeypatch.setattr(w._rapports, "CACHE_IA", str(tmp_path / "ia.json"))
    monkeypatch.setattr(w._rapports.lire_ia, "__defaults__", (str(tmp_path / "ia.json"),))
    monkeypatch.setattr(w, "_maintenant", lambda: MAINTENANT)
    w.app.dependency_overrides.clear()
    w.app.dependency_overrides[w.require_lecture_ai] = lambda: {"sub": "lecteur"}
    yield w
    w.app.dependency_overrides.clear()


def test_routes_lecture_et_gardes(waf, tmp_path):
    from fastapi.testclient import TestClient
    c = TestClient(waf.app)
    assert c.get("/rapports").json() == {"disponible": False}
    assert c.get("/rapports/campagne/famille:collecte").status_code == 503
    r = _calcul(tmp_path)
    r["complet"] = True
    R.ecrire_cache(str(tmp_path / "rapports.json"), r)
    j = c.get("/rapports").json()
    assert j["disponible"] and j["sujets"][0]["cle"] == "campagne:famille:collecte"
    d = c.get("/rapports/campagne/famille:collecte").json()
    assert d["regles"] and d["ia"] is None and d["markdown"].startswith("# Rapport")
    assert not V.IPV4.search(json.dumps(d))
    assert c.get("/rapports/inconnu/x").status_code == 404 and c.get("/rapports/campagne/absent").status_code == 404
    for chemin in ("/rapports", "/rapports/{genre}/{ident}"):
        route = next(x for x in waf.app.routes if getattr(x, "path", "") == chemin)
        assert any(dep.call is waf.require_lecture_ai for dep in route.dependant.dependencies)
    route = next(x for x in waf.app.routes if getattr(x, "path", "") == "/rapports/{genre}/{ident}/rediger")
    assert route.methods == {"POST"} and any(dep.call is waf.require_jwt for dep in route.dependant.dependencies)
