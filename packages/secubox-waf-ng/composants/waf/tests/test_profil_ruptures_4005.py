# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Chantier #4005 : profil déduit des populations, lecture factuelle par règles, ruptures par couches, double lecture
et double tampon.

Cas reproduit : une vague d'aspiration d'une forge (user-agent unique, proxys loués, pages src/commit, retours rares,
pic puis extinction). Adresses de DOCUMENTATION seulement (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) : le relevé
écarte d'ordinaire les adresses non publiques, le test les admet par `_adresse_publique` remplacée."""
import ipaddress
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from api import populations as P  # noqa: E402
from api import profil as F  # noqa: E402

MAINTENANT = datetime(2026, 11, 27, 12, 0, 0, tzinfo=timezone.utc).timestamp()
JOUR = 86400
UA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36"
DOC = ["192.0.2.%d" % i for i in range(1, 255)] + ["198.51.100.%d" % i for i in range(1, 255)] + \
      ["203.0.113.%d" % i for i in range(1, 255)]


@pytest.fixture(autouse=True)
def adresses_de_documentation(monkeypatch):
    monkeypatch.setattr(P, "_adresse_publique", lambda ip: str(ipaddress.ip_address(ip)) if _ip(ip) else None)


def _ip(ip):
    try:
        ipaddress.ip_address(str(ip))
        return True
    except ValueError:
        return False


def _ligne(ip, il_y_a_s, categorie="aspirateur_ua", host="forge.example.test", path="/alice/depot/src/commit/0123456789abcdef/a.c",
           ua=UA, method="GET", action="detect"):
    return json.dumps({"timestamp": datetime.fromtimestamp(MAINTENANT - il_y_a_s, tz=timezone.utc).isoformat(),
                       "client_ip": ip, "host": host, "method": method, "path": path, "category": categorie,
                       "severity": "medium", "rule_id": "", "action": action, "user_agent": ua})


def _vague():
    """1 500 requêtes il y a 4 jours (le pic), une dizaine aujourd'hui ; un seul user-agent, une seule forge."""
    lignes = []
    for k in range(1500):
        chemin = ("/alice/depot/src/commit/%040x/f.c" % k) if k % 3 else ("/alice/depot/blame/commit/%040x/f.c" % k)
        lignes.append(_ligne(DOC[k % len(DOC)], 4 * JOUR + k, path=chemin, action="banned" if k < 600 else "detect"))
    for k in range(10):
        lignes.append(_ligne(DOC[k], 600 + k))
    return lignes


def _calc(lignes, externes=None):
    return P.calculer(lignes, MAINTENANT, pays=lambda ip: "", classer=lambda ip: (64500, "Loueur", "proxy_loue"),
                      campagnes_smtp=[], campagnes_profileur=[], rotation=[], externes=externes)


def _pop(r, ident="famille:collecte"):
    return next(p for p in r["populations"] if p["id"] == ident)


# ── classes de pages ────────────────────────────────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("methode,chemin,attendu", [
    ("GET", "/alice/depot/src/commit/0123abcd/dossier/a.c", "src/commit"),
    ("GET", "/alice/depot/blame/commit/0123abcd/a.c?x=1", "blame/commit"),
    ("GET", "/alice/depot/raw/branch/main/a.c", "raw/branch"),
    ("GET", "/alice/depot/commits/branch/main", "commits/branch"),
    ("GET", "/alice/depot/commit/0123abcd", "commit"),
    ("GET", "/", "/"),
    ("GET", "/wp-login.php", "/wp-login.php"),
    ("GET", "/api/v1/x", "/api/…"),
    ("GET", "/0123456789abcdef0123/x", "/*/…"),
    ("GET", "/<script>", "/*"),
    ("", "garbage", F.HORS_HTTP),
])
def test_classer_page(methode, chemin, attendu):
    assert F.classer_page(methode, chemin) == attendu


def test_page_d_authentification_est_un_compte():
    assert F.classer_page("POST", "admin@example.test", auth=True) == F.COMPTE


# ── profil et lecture factuelle ─────────────────────────────────────────────────────────────────────────────────

def test_lecture_de_la_vague_d_aspiration():
    relaches = {ip: MAINTENANT - 3 * JOUR for ip in DOC[:400]}
    bans = F.BansLus()
    bans.retour = {DOC[0]: MAINTENANT - 2 * JOUR, DOC[1]: MAINTENANT - 2 * JOUR}     # 2 retours sur 400
    r = _calc(_vague(), externes=(relaches, bans))
    p = _pop(r)
    pr = p["profil"]
    assert pr["ua_distincts"] == 1 and pr["ua_premier_part"] == 100 and pr["ua_premier"] == UA
    assert pr["methodes"][0] == ["GET", 100]
    assert [x[0] for x in pr["pages"][:2]] == ["src/commit", "blame/commit"]
    assert pr["vhosts"][0] == ["forge.example.test", 100]
    assert p["retours"] == {"relachees": 400, "retours": 2, "delai_median_s": JOUR}
    textes = [x["texte"] for x in p["lecture"]]
    assert "Empreinte unique : 1 user-agent pour 100 % des requêtes." in textes
    assert "Infrastructure louée : 100 % d'adresses chez des hébergeurs/proxys." in textes
    assert "Adresses jetables : 2 retours sur 400 relâchées, délai médian 24 h." in textes
    assert "Vague éteinte : 10 requêtes aujourd'hui contre 1 500 au pic." in textes
    assert "Cible unique : 100 % des requêtes sur forge.example.test." in textes
    assert "Lecture seule : 100 % de GET." in textes
    assert all(isinstance(x["valeur"], (int, float)) for x in p["lecture"])      # chaque phrase porte son chiffre


def test_lecture_ne_publie_aucune_adresse():
    r = _calc(_vague(), externes=({ip: MAINTENANT - 3 * JOUR for ip in DOC[:200]}, F.BansLus()))
    texte = json.dumps(_pop(r)["lecture"]) + json.dumps(_pop(r)["profil"])
    assert not any(ip in texte for ip in DOC)


def test_empreinte_majoritaire_et_ciblee():
    lignes = [_ligne(DOC[k], 3600 + k) for k in range(70)]
    lignes += [_ligne(DOC[k], 3600 + k, ua="robot-%d" % k, host="autre.example.test", path="/") for k in range(30)]
    p = _pop(_calc(lignes))
    textes = [x["texte"] for x in p["lecture"]]
    assert "Empreinte majoritaire : un même user-agent pour 70 % des requêtes (31 user-agents au total)." in textes
    assert "Empreinte ciblée : ce user-agent vise forge.example.test pour 100 % de ses requêtes." in textes


def test_peu_de_requetes_pas_de_lecture_d_empreinte():
    p = _pop(_calc([_ligne(DOC[k], 3600 + k) for k in range(10)]))
    assert not [x for x in p["lecture"] if x["code"].startswith("empreinte")]


def test_profil_garde_dans_la_reserve():
    a = P.agreger(_vague(), MAINTENANT)
    b = P._deranger(json.loads(json.dumps(P._ranger(a))))
    assert b is not None and b.profils == a.profils and b.quarts == a.quarts and b.premier_ban == a.premier_ban
    abime = P._ranger(a)
    abime["profils"]["collecte"]["n"] = "beaucoup"
    assert P._deranger(json.loads(json.dumps(abime))) is None


def test_lire_bans_et_retours(tmp_path):
    (tmp_path / "reevaluations.jsonl").write_text("\n".join(json.dumps(x) for x in [
        {"ts": MAINTENANT - 3 * JOUR, "ip": DOC[0], "categorie": "aspirateur_ua", "decision": "RELEASE"},
        {"ts": MAINTENANT - 3 * JOUR, "ip": DOC[1], "categorie": "aspirateur_ua", "decision": "RELEASE"},
        {"ts": MAINTENANT - 3 * JOUR, "ip": DOC[2], "categorie": "aspirateur_ua", "decision": "EXTEND"},
    ]) + "\n")
    (tmp_path / "bans.jsonl").write_text("\n".join(json.dumps(x) for x in [
        {"ip": DOC[0], "cat": "aspirateur_ua", "at": MAINTENANT - 4 * JOUR, "action": "ban"},
        {"ip": DOC[0], "cat": "aspirateur_ua|prolonge", "at": MAINTENANT - 2 * JOUR, "action": "ban"},   # pas un retour
        {"ip": DOC[0], "cat": "aspirateur_ua", "at": MAINTENANT - JOUR, "action": "ban"},              # retour
        {"ip": DOC[1], "cat": "sqli", "at": MAINTENANT - JOUR, "action": "ban"},                       # famille hors relevé
    ]) + "\n")
    rel, ok = F.lire_relaches(str(tmp_path), MAINTENANT)
    assert ok and set(rel) == {DOC[0], DOC[1]}
    b = F.lire_bans(str(tmp_path), MAINTENANT, rel, P.famille)
    assert b.lisible and b.retour == {DOC[0]: MAINTENANT - JOUR} and sum(b.quarts.values()) == 2
    assert F.retours_population([DOC[0], DOC[1], DOC[3]], rel, b.retour) == {
        "relachees": 2, "retours": 1, "delai_median_s": 2 * JOUR}


# ── ruptures ────────────────────────────────────────────────────────────────────────────────────────────────────

def _bruit(fin, quarts=8 * 96, base=6):
    """Un bruit déterministe de 3 à 9 par quart d'heure sur 8 jours."""
    return {q: base - 3 + (q * 7919) % 7 for q in range(fin - quarts, fin)}


def test_rupture_sur_un_pic_x10():
    fin = int(MAINTENANT // F.QUART)
    s = _bruit(fin)
    for q in range(fin - 4, fin):
        s[q] *= 10
    c = F.couche("x", "X", "journal", s, fin, fin - 8 * 96)
    assert c["fenetres"]["1h"]["sens"] == "hausse" and c["fenetres"]["1h"]["facteur"] >= 5
    assert c["fenetres"]["7j"]["sens"] == "insuffisant"            # 8 jours ne font pas 4 semaines précédentes


def test_pas_de_rupture_sur_du_bruit():
    fin = int(MAINTENANT // F.QUART)
    c = F.couche("x", "X", "journal", _bruit(fin), fin, fin - 8 * 96)
    assert {f["sens"] for f in c["fenetres"].values()} <= {"stable", "insuffisant"}


def test_pas_de_hausse_sous_le_volume_minimal():
    fin = int(MAINTENANT // F.QUART)
    s = {q: 0 for q in range(fin - 8 * 96, fin)}
    s[fin - 1] = 6                                                  # 0 → 6 : facteur infini, mais 6 < 10
    assert F.couche("x", "X", "journal", s, fin, fin - 8 * 96)["fenetres"]["1h"]["sens"] == "stable"


def test_baisse_signalee():
    fin = int(MAINTENANT // F.QUART)
    s = {q: 40 for q in range(fin - 8 * 96, fin)}
    for q in range(fin - 96, fin):
        s[q] = 1
    assert F.couche("x", "X", "journal", s, fin, fin - 8 * 96)["fenetres"]["1j"]["sens"] == "baisse"


def test_ruptures_du_releve_et_mesures_neuves():
    r = _calc(_vague())
    ids = {c["id"] for c in r["ruptures"]["couches"]}
    assert {"adresses_neuves", "blocs24_neufs", "asn_neufs", "alertes:collecte", "vhost:forge.example.test"} <= ids
    assert "bans_poses" not in ids                                  # bans.jsonl non lu : pas de couche inventée
    neuves = next(c for c in r["ruptures"]["couches"] if c["id"] == "adresses_neuves")
    assert len(neuves["jours"]) == F.HISTO_JOURS


# ── double lecture ──────────────────────────────────────────────────────────────────────────────────────────────

def _bans_lus(fin, par_quart):
    b = F.BansLus()
    b.quarts = {q: par_quart for q in range(fin - 8 * 96, fin)}
    b.debut_q = fin - 8 * 96
    return b


def test_double_lecture_concordante():
    fin = int(MAINTENANT // F.QUART)
    journal = {"b": {q: 10 for q in range(fin - 8 * 96, fin)}}
    r = F.ruptures(MAINTENANT, journal, fin - 8 * 96, {}, _bans_lus(fin, 10))
    c = next(c for c in r["couches"] if c["id"] == "bans_poses")
    assert c["double"]["ecart"] is False and c["double"]["valeurs"]["1j"] == {"a": 960, "b": 960, "ecart": False}
    assert r["ecarts"] == 0


def test_double_lecture_ecart_signale():
    fin = int(MAINTENANT // F.QUART)
    journal = {"b": {q: 20 for q in range(fin - 8 * 96, fin)}}       # le journal voit deux fois plus de bans
    r = F.ruptures(MAINTENANT, journal, fin - 8 * 96, {}, _bans_lus(fin, 10))
    c = next(c for c in r["couches"] if c["id"] == "bans_poses")
    assert c["double"]["ecart"] is True and c["double"]["valeurs"]["1j"] == {"a": 960, "b": 1920, "ecart": True}
    assert r["ecarts"] >= 1


def test_double_lecture_tolere_le_petit_ecart():
    assert F.ecart(100, 110) is False and F.ecart(3, 7) is False and F.ecart(100, 130) is True


# ── double tampon : une passe dégradée ne remplace pas un relevé complet ──────────────────────────────────────

def _sources_absentes(monkeypatch, tmp_path):
    monkeypatch.setattr(P, "AUTHWATCH_CAMPAGNES", str(tmp_path / "absent-authwatch.json"))
    monkeypatch.setattr(P, "ROTATION_ETAT", str(tmp_path / "absent-rotation.json"))
    monkeypatch.setattr(P, "ACTORD_SOCK", str(tmp_path / "absent.sock"))
    monkeypatch.setattr(P, "BASES_ASN", (str(tmp_path / "absent.mmdb"),))
    monkeypatch.setattr(P, "BASES_PAYS", (str(tmp_path / "absent-pays.mmdb"),))


def test_passe_degradee_ne_remplace_pas_le_complet(monkeypatch, tmp_path):
    _sources_absentes(monkeypatch, tmp_path)
    journaux, etat = tmp_path / "journaux", tmp_path / "etat"
    journaux.mkdir()
    etat.mkdir()
    (journaux / "waf-threats.log").write_text("\n".join(_vague()) + "\n")
    (etat / "bans.jsonl").write_text(json.dumps({"ip": DOC[0], "cat": "aspirateur_ua", "at": MAINTENANT - 60,
                                                 "action": "ban"}) + "\n")
    cache = str(tmp_path / "populations.json")
    assert P.rafraichir(str(journaux), cache, str(tmp_path / "absent.json"), MAINTENANT, str(etat)) is True
    complet = P.lire_cache(cache)
    assert complet["complet"] is True and complet["ruptures"]["bans_lisibles"] is True
    # bans.jsonl devenu illisible (ici : un dossier) : passe dégradée, relevé complet gardé
    (etat / "bans.jsonl").unlink()
    (etat / "bans.jsonl").mkdir()
    assert P.rafraichir(str(journaux), cache, str(tmp_path / "absent.json"), MAINTENANT + 600, str(etat)) is False
    garde = P.lire_cache(cache)
    assert garde["genere_le"] == complet["genere_le"] and garde["complet"] is True
    assert garde["ruptures"]["bans_lisibles"] is True


# ── auto-test du WAF (health-doctor) : jamais une population, jamais une rupture ──────────────────────────────

def test_lignes_d_auto_test_ne_creent_pas_de_rupture():
    ua = "SecuBox-WAF-SelfTest/1 (health-doctor)"
    lignes = [_ligne(DOC[k % 50], 7 * JOUR - k * 600, categorie="lfi", ua=ua, path="/../../etc/passwd") for k in range(900)]
    lignes += [_ligne(DOC[0], 60 + k, categorie="lfi", ua=ua, action="banned") for k in range(500)]   # pic final
    r = _calc(lignes)
    assert r["populations"] == []
    assert r["ruptures"]["signalees"] == 0
    assert not any(c["id"].startswith("alertes:") for c in r["ruptures"]["couches"])


def test_bans_d_auto_test_ecartes_par_l_adresse(tmp_path, monkeypatch):
    monkeypatch.undo()                     # règle réelle : une adresse de documentation ne compte pas
    (tmp_path / "bans.jsonl").write_text("\n".join(json.dumps(
        {"ip": "198.51.100.77", "cat": "lfi", "at": MAINTENANT - 60 * k, "action": "ban"}) for k in range(300)) + "\n")
    b = F.lire_bans(str(tmp_path), MAINTENANT, {}, P.famille, P._adresse_publique)
    assert b.lisible and b.quarts == {} and b.premier == {}


def test_double_lecture_ignore_bans_de_sbx_authwatch_4008():
    """#4008 : les bans posés par sbx-authwatch (leurres de service, auth_) n'entrent pas dans bans.jsonl : jamais comptés côté journal."""
    from api.populations import pose_par_sbxwaf
    assert not pose_par_sbxwaf("leurre:telnet", "telnet")
    assert not pose_par_sbxwaf("leurre:rdp", "")
    assert not pose_par_sbxwaf("auth_ssh", "gk2")
    assert pose_par_sbxwaf("leurre:unrouted", "exemple.secubox.in")
    assert pose_par_sbxwaf("host_anomaly:unrouted", "exemple.fr")
    assert pose_par_sbxwaf("xss", "hall.gk2.secubox.in")
