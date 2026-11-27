# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Bibliothèque figée OWASP CRS / Nuclei (#4020) : construction, vérificateur, rejeu, livraison, vue."""

import importlib.machinery
import importlib.util
import json
import re
import sys
from pathlib import Path

import pytest

WAF = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(WAF / "bibliotheque"))
import construire as c  # noqa: E402

sys.path.pop(0)
sys.path.insert(0, str(WAF / "api"))
import bibliotheque as vue  # noqa: E402
import populations  # noqa: E402

sys.path.pop(0)

_loader = importlib.machinery.SourceFileLoader("waf_rules_sync_bib", str(WAF / "scripts" / "waf-rules-sync"))
_spec = importlib.util.spec_from_loader("waf_rules_sync_bib", _loader)
sync = importlib.util.module_from_spec(_spec)
_loader.exec_module(sync)

LIVREE = WAF / "config" / "bibliotheque"
IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

CRS_913 = r'''
SecRule TX:DETECTION_PARANOIA_LEVEL "@lt 1" "id:913011,phase:1,pass,nolog,skipAfter:END"
SecRule REQUEST_HEADERS:User-Agent "@rx (?i)(?:nikto|sqlmap)" \
    "id:913100,\
    phase:1,\
    block,\
    t:none,\
    msg:'Found User-Agent associated with security scanner',\
    tag:'paranoia-level/1',\
    severity:'CRITICAL',\
    setvar:'tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}'"
SecRule REQUEST_HEADERS:User-Agent "@pmFromFile scanners.data" \
    "id:913101,phase:1,block,t:none,tag:'paranoia-level/2',severity:'CRITICAL'"
'''
CRS_930 = r'''
SecRule REQUEST_FILENAME "@pmFromFile restricted-files.data" \
    "id:930130,phase:1,block,t:none,t:utf8toUnicode,t:urlDecodeUni,t:normalizePathWin,\
    msg:'Restricted File Access Attempt',tag:'paranoia-level/1',severity:'CRITICAL'"
SecRule ARGS "@rx (?=foo)bar" "id:930199,phase:2,block,t:none,tag:'paranoia-level/1',severity:'CRITICAL'"
SecRule ARGS "@rx etc/passwd" "id:930198,phase:2,block,t:none,t:htmlEntityDecode,tag:'paranoia-level/1'"
SecRule ARGS "@rx ^x" "id:930197,phase:2,block,t:none,chain,tag:'paranoia-level/1'"
    SecRule ARGS "@rx y" "t:none"
SecRule TX:ANOMALY "@ge 5" "id:930196,phase:2,block,tag:'paranoia-level/1'"
'''
NUCLEI = {
    "http/exposures/configs/git-config.yaml": """id: git-config
info:
  name: Git Config - Detect
  severity: medium
  tags: config,git,exposure
http:
  - method: GET
    path:
      - "{{BaseURL}}/.git/config"
""",
    "http/technologies/wordpress-detect.yaml": """id: wordpress-akismet
info:
  name: WordPress Akismet
  severity: info
  metadata:
    product: wordpress
  tags: tech,wordpress
http:
  - method: GET
    path:
      - "{{BaseURL}}/wp-content/plugins/akismet/readme.txt"
      - "{{BaseURL}}/{{path}}/x"
""",
    "http/exposed-panels/root.yaml": """id: racine-panel
info:
  name: Racine
  severity: info
  tags: panel
http:
  - method: GET
    path:
      - "{{BaseURL}}"
""",
    "http/misconfiguration/raw.yaml": """id: brut
info:
  name: Brut
  severity: low
http:
  - raw:
      - "GET /x HTTP/1.1"
""",
}


@pytest.fixture
def sources(tmp_path):
    crs = tmp_path / "crs" / "rules"
    crs.mkdir(parents=True)
    (crs / "REQUEST-913-SCANNER-DETECTION.conf").write_text(CRS_913, encoding="utf-8")
    (crs / "REQUEST-930-APPLICATION-ATTACK-LFI.conf").write_text(CRS_930, encoding="utf-8")
    (crs / "restricted-files.data").write_text("# commentaire\n.htpasswd\n.git/\nab\n", encoding="utf-8")
    nuc = tmp_path / "nuclei"
    for rel, texte in NUCLEI.items():
        f = nuc / rel
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(texte, encoding="utf-8")
    return tmp_path / "crs", nuc


def _par_id(cands):
    return {x.id: x for x in cands}


def test_conversion_crs_et_ecarts_comptes(sources):
    crs, _ = sources
    bilan = c.Bilan()
    cands = _par_id(c.crs_candidats(crs, bilan))
    ua = cands["bib-crs-913100-ua"]
    assert (ua.champ, ua.famille, ua.severite, ua.ref) == ("ua", "ua_outils", "critical", "CRS 913100")
    exp = cands["bib-crs-930130-chemin"]
    assert exp.famille == "fichiers_exposes" and exp.pattern == r"(?:\.git/|\.htpasswd)"   # « ab » trop court
    ec = bilan.ecartees
    assert ec["ua_outils"]["niveau de paranoïa > 1"] == 1
    assert ec["lfi"]["transformation htmlentitydecode"] == 1
    assert ec["lfi"]["règle chaînée"] == 1
    assert ec["lfi"]["anomalie cumulée (cible TX)"] == 1
    assert "bib-crs-930199-requete" in cands        # converti, puis écarté par le vérificateur RE2


def test_verificateur_rejette_le_non_re2_et_les_pages_secubox(sources):
    crs, _ = sources
    cands = _par_id(c.crs_candidats(crs, c.Bilan()))
    assert c.verifier(cands["bib-crs-930199-requete"], set()).startswith("regex hors RE2")
    page = c.Candidat(id="x", famille="sondes_techno", techno="t", severite="low", champ="chemin",
                      pattern=r"^/login\.html$", source="nuclei", ref="r", desc="", exact="/login.html")
    assert c.verifier(page, c.CHEMINS_SECUBOX_FIXES) == "page de SecuBox"
    assert c.verifier(cands["bib-crs-913100-ua"], set()) is None


def test_echapper_reste_compatible_re2():
    m = c.echapper("/a b.c(d)-e~f")
    assert m == r"/a b\.c\(d\)-e~f" and re.fullmatch(m, "/a b.c(d)-e~f")


def test_conversion_nuclei(sources):
    _, nuc = sources
    bilan = c.Bilan()
    cands = {x.exact: x for x in c.nuclei_candidats(nuc, bilan)}
    assert set(cands) == {"/.git/config", "/wp-content/plugins/akismet/readme.txt"}
    wp = cands["/wp-content/plugins/akismet/readme.txt"]
    assert (wp.famille, wp.techno, wp.champ, wp.ref) == ("sondes_techno", "wordpress", "chemin", "nuclei wordpress-akismet")
    assert wp.pattern == r"^/wp-content/plugins/akismet/readme\.txt$"
    assert cands["/.git/config"].techno == "git"
    assert bilan.ecartees["panneaux_admin"]["chemin trop générique"] == 1
    assert bilan.ecartees["defauts_web"]["requête brute, charges ou fuzzing"] == 1


def _req(chemin, statut, client="c1", hote="site.example", ua="mozilla/5.0"):
    return f"{hote}\t{client}\tGET\t{chemin}\t{statut}\t{ua}\n"


def test_rejeu_rejette_un_motif_qui_touche_un_2xx_legitime(sources):
    _, nuc = sources
    cands = c.nuclei_candidats(nuc, c.Bilan())
    reqs = c.lire_journal([_req("/wp-content/plugins/akismet/readme.txt", 200),     # vrai WordPress
                           _req("/.git/config", 404, client="c2")])
    c.rejouer(cands, reqs, None)
    par = {x.exact: x for x in cands}
    assert par["/wp-content/plugins/akismet/readme.txt"].legitimes == ["site.example"]
    assert par["/.git/config"].legitimes == [] and par["/.git/config"].touches == 1


def test_rejeu_une_sonde_evidente_ne_vaut_pas_legitime(sources):
    _, nuc = sources
    cands = c.nuclei_candidats(nuc, c.Bilan())
    lignes = [_req("/.git/config", 200, client="sonde")] + [_req(f"/n{i}", 404, client="sonde") for i in range(10)]
    c.rejouer(cands, c.lire_journal(lignes), None)
    assert {x.exact: x for x in cands}["/.git/config"].legitimes == []


def test_construction_complete_sans_adresse(sources, tmp_path):
    crs, nuc = sources
    j = tmp_path / "j.tsv"
    j.write_text(_req("/wp-content/plugins/akismet/readme.txt", 200, hote="198.51.100.7")
                 + _req("/.git/config", 404, client="c9"), encoding="utf-8")
    regles, rapport = c.construire(crs, nuc, [j], {"owasp-crs": "t", "nuclei-templates": "t"})
    cats = regles["categories"]
    assert all(k.startswith("bib_") and v["mode"] == "detect" and v["bibliotheque"] for k, v in cats.items())
    ids = {p["id"] for v in cats.values() for p in v["patterns"]}
    assert not any("akismet" in i for i in ids)                    # rejeté au rejeu
    assert rapport["familles"]["sondes_techno"]["rejetees_rejeu"] == 1
    assert "(adresse)" in rapport["rejets_par_vhost"]
    assert not IP.search(json.dumps(rapport)) and not IP.search(json.dumps(regles))


def test_selection_par_famille_et_bornes(monkeypatch):
    def cand(i, fam, exact=None):
        return c.Candidat(id=f"bib-{fam}-{i}", famille=fam, techno="t", severite="low", champ="chemin",
                          pattern="x", source="s", ref="r", desc="", exact=exact)
    monkeypatch.setattr(c, "REGEX_MAX", 2)
    bilan = c.Bilan()
    out = c.borner([cand(i, "php") for i in range(5)] + [cand(0, "sqli")] + [cand(1, "lfi", "/a")], bilan)
    assert sorted(x.famille for x in out) == ["lfi", "php", "php"]
    assert bilan.ecartees["php"]["borne de regex par famille"] == 3
    assert bilan.ecartees["sqli"]["famille différée (coût au banc, édition suivante)"] == 1


# ── bibliothèque livrée ─────────────────────────────────────────────────────────────────────────────

def test_bibliotheque_livree_coherente_et_sans_adresse():
    cats = json.loads((LIVREE / "categories.json").read_text(encoding="utf-8"))
    rapport = json.loads((LIVREE / "rapport.json").read_text(encoding="utf-8"))
    for texte in ((LIVREE / "categories.json").read_text(), (LIVREE / "rapport.json").read_text()):
        assert not IP.search(texte)
    vus = set()
    for nom, cat in cats["categories"].items():
        assert nom.startswith("bib_") and cat["mode"] == "detect" and cat["bibliotheque"] is True
        for p in cat["patterns"]:
            assert p["id"] not in vus and c.hors_re2(p["pattern"]) is None
            vus.add(p["id"])
            assert p["champ"] in ("chemin", "requete", "ua", "corps") and p["ref"] and p["source"]
    assert rapport["total_retenues"] == len(vus)
    assert (LIVREE / "LICENCES" / "OWASP-CRS-LICENSE-Apache-2.0.txt").is_file()
    assert (LIVREE / "LICENCES" / "NUCLEI-TEMPLATES-LICENSE-MIT.txt").is_file()


def test_sync_ajoute_la_bibliotheque_en_fin_sans_ecraser():
    livre = {"categories": {"scanners": {"patterns": []}}}
    bib = {"categories": {"bib_ua_outils": {"bibliotheque": True, "mode": "detect", "patterns": []},
                          "scanners": {"bibliotheque": True, "patterns": [{"id": "x"}]},
                          "bib_faux": {"patterns": []}}}
    out = sync.avec_bibliotheque(livre, bib)
    assert list(out["categories"]) == ["scanners", "bib_ua_outils"]
    assert out["categories"]["scanners"] == {"patterns": []}


def test_sync_garde_le_mode_choisi_pour_une_famille():
    livre = sync.avec_bibliotheque({"categories": {}}, {"categories": {
        "bib_php": {"bibliotheque": True, "mode": "detect", "patterns": [{"id": "a", "pattern": "a"}]}}})
    vivant = {"categories": {"bib_php": {"bibliotheque": True, "mode": "escalate", "ban_seuil": 2,
                                         "ban_duree": "24h", "mode_choisi": True, "patterns": []}}}
    cat = sync.fusionne(livre, vivant)["categories"]["bib_php"]
    assert (cat["mode"], cat["ban_seuil"], cat["patterns"]) == ("escalate", 2, [{"id": "a", "pattern": "a"}])


# ── vue de la page Modes et populations ─────────────────────────────────────────────────────────────

def test_populations_classe_les_etiquettes_de_la_bibliotheque():
    assert populations.famille("bib:fichiers_exposes:git") == "balayage_web"
    assert populations.famille("bib:ua_outils:generique") == "balayage_web"


def test_vue_somme_les_touches_par_famille(tmp_path):
    rap = tmp_path / "rapport.json"
    rap.write_text(json.dumps({"sources": {"owasp-crs": "v"}, "familles": {
        "php": {"retenues": 8, "regex": 8, "chemins_exacts": 0, "importees": 21, "rejetees_rejeu": 0,
                "touches_rejouees": 26},
        "rce": {"retenues": 0}}}), encoding="utf-8")
    stats = {"categories": {"bib:php:generique": {"touches": 3, "par_jour": [0, 0, 0, 0, 1, 1, 1]},
                            "bib:php:wordpress": {"touches": 2, "par_jour": [0, 0, 0, 0, 0, 0, 2]},
                            "scanners": {"touches": 99}}}
    vue.configurer(categories=lambda: {"source": "box", "categories": {
        "bib_php": {"name": "B", "mode": "escalate", "ban_seuil": 3, "ban_duree": "24h"}}},
        stats7j=lambda: stats, rapport=rap)
    out = vue.lire_bibliotheque()
    assert list(out["familles"]) == ["php"]                    # famille sans règle livrée : absente
    f = out["familles"]["php"]
    assert f["identifier_seulement"] is False and f["regles"] == 8 and f["touches_rejouees"] == 26
    assert f["touches_7j"]["touches"] == 5 and f["touches_7j"]["par_jour"][-1] == 3
    assert f["touches_7j"]["technos"] == {"generique": 3, "wordpress": 2}
    vue.configurer(categories=lambda: {"categories": {}}, stats7j=lambda: {"categories": None}, rapport=rap)
    f = vue.lire_bibliotheque()["familles"]["php"]
    assert f["presente"] is False and f["identifier_seulement"] is True and f["touches_7j"] is None
