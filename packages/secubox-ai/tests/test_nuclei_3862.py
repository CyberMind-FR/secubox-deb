# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Tour de filtres WAF Nuclei (#3862), porté du POC gk0 (`relais/tests/test_filtres.py`).

Aucun réseau ni git : `executer` et `telecharger` sont injectés au collecteur ; la veille parle au gk2 simulé de
test_apprentissage_3723 (vraie garde `require_ai_filtres`, vrais contrôles `wafgen.filtres_ia`)."""
import asyncio
import gzip
import hashlib
import json
import os
import re
import subprocess
import tomllib
from datetime import timedelta
from pathlib import Path

import httpx
import pytest
import yaml

from test_apprentissage_3723 import POLITIQUES, _maintenant
import test_apprentissage_3723 as _apprentissage
from veille import apprentissage, decisions, nuclei as F, politiques, retention
from veille.service import Veille

PAQUET = Path(__file__).resolve().parents[1]
T = 1_800_000_000.0

MODELE_RAW = """id: CVE-2024-1234

info:
  name: Exemple - RCE
  severity: critical
  classification:
    cvss-score: 9.8
    cve-id: CVE-2024-1234
  metadata:
    vendor: exemple
    product: ExempleCMS
  tags: cve,cve2024,rce,exemple

http:
  - raw:
      - |
        GET /exemple/cgi-bin/vuln.cgi HTTP/1.1
        Host: {{Hostname}}

    matchers:
      - type: word
        words:
          - "uid="
"""

MODELE_PATH = """id: CVE-2023-9999
info:
  name: Fuite
  severity: high
  classification:
    cve-id: CVE-2023-9999
  metadata:
    vendor: Acme
  tags: cve,exposure
http:
  - method: GET
    path:
      - "{{BaseURL}}/acme/api/%64ebug/config"
"""


@pytest.fixture(autouse=True)
def _comptes(tmp_path, monkeypatch):
    """Le compte du collecteur est, en test, celui qui lance les tests ; la liste de refus réelle n'est jamais lue."""
    monkeypatch.setattr(F, "_proprietaire_attendu", lambda: os.getuid())
    monkeypatch.setattr(F, "REFUSES", tmp_path / "refuses-absent.txt")


def modele(texte, fichier="http/cves/2024/CVE-2024-1234.yaml"):
    return {"texte": texte, "doc": yaml.safe_load(texte), "fichier": fichier}


# ── filtre_depuis_nuclei (POC, à l'identique) ─────────────────────────
def test_raw_chemin_unique_donne_chemin_exact():
    f = F.filtre_depuis_nuclei(modele(MODELE_RAW))
    assert f["id"] == "ia-cve-2024-1234-" + hashlib.sha1(b"/exemple/cgi-bin/vuln.cgi").hexdigest()[:6]
    assert f["cve"] == "CVE-2024-1234"
    assert f["motif_type"] == "chemin_exact" and f["motif"] == "/exemple/cgi-bin/vuln.cgi"
    assert f["produit"] == "exemplecms" and f["famille"] == "rce" and f["cvss"] == 9.8
    assert f["parametre"] is None and f["version"] == 1 and f["kev"] is False and f["epss"] is None
    assert f["sources"][0]["type"] == "nuclei" and f["sources"][0]["url"].endswith("CVE-2024-1234.yaml")
    assert F.verifier_local(f) is None and F.valider_candidat(f) is None


def test_path_pourcent_refuse_sans_decodage():
    assert F.filtre_depuis_nuclei(modele(MODELE_PATH)) is None      # « % » : jamais décodé, écarté


def test_path_simple_et_famille_exposure():
    f = F.filtre_depuis_nuclei(modele(MODELE_PATH.replace("%64ebug", "debug")))
    assert f["motif"] == "/acme/api/debug/config" and f["famille"] == "divulgation" and f["produit"] == "acme"
    assert f["cvss"] is None


def test_tout_motif_produit_est_sous_chaine_du_modele():
    variantes = [MODELE_RAW, MODELE_PATH.replace("%64ebug", "debug"), MODELE_RAW.replace("vuln.cgi", "x/y/zz.php"),
                 MODELE_PATH.replace("/acme/api/%64ebug/config", "/wp-content/plugins/acme/readme.txt")]
    for t in variantes:
        f = F.filtre_depuis_nuclei(modele(t))
        assert f is not None and f["motif"] in t


def test_multi_requetes_refuse():
    doc = MODELE_RAW.replace("http:\n  - raw:", "http:\n  - method: GET\n    path:\n      - \"{{BaseURL}}/a/bcdefghij\"\n"
                             "  - raw:")
    assert F.filtre_depuis_nuclei(modele(doc)) is None
    deux = MODELE_PATH.replace('      - "{{BaseURL}}/acme/api/%64ebug/config"\n',
                               '      - "{{BaseURL}}/acme/api/one/xx"\n      - "{{BaseURL}}/acme/api/two/xx"\n')
    assert F.filtre_depuis_nuclei(modele(deux)) is None


def test_sans_cve_refuse():
    assert F.filtre_depuis_nuclei(modele(MODELE_RAW.replace("    cve-id: CVE-2024-1234\n", ""))) is None


def test_sans_produit_refuse():
    sans = MODELE_RAW.replace("    vendor: exemple\n    product: ExempleCMS\n", "    verified: true\n")
    assert F.filtre_depuis_nuclei(modele(sans)) is None


def test_motif_absent_du_texte_refuse():
    m = modele(MODELE_RAW)
    m["texte"] = m["texte"].replace("/exemple/cgi-bin/vuln.cgi", "/autre")
    assert F.filtre_depuis_nuclei(m) is None


def test_variable_autre_que_baseurl_refuse():
    assert F.filtre_depuis_nuclei(modele(MODELE_PATH.replace("%64ebug", "{{randstr}}"))) is None


def test_pourcent_restant_ou_controle_refuse():
    assert F.filtre_depuis_nuclei(modele(MODELE_PATH.replace("%64ebug", "%2525x"))) is None
    assert F.filtre_depuis_nuclei(modele(MODELE_PATH.replace("%64ebug", "%0aebug"))) is None


def test_specificite_insuffisante_refusee():
    assert F.filtre_depuis_nuclei(modele(MODELE_RAW.replace("/exemple/cgi-bin/vuln.cgi", "/a/b.c"))) is None


def test_requete_avec_point_d_interrogation_refusee():
    p = MODELE_PATH.replace("/acme/api/%64ebug/config", "/acme/index.php?page=../../etc/passwd")
    assert F.filtre_depuis_nuclei(modele(p)) is None


def test_collecter_lit_le_depot_et_suffixe_les_doublons(tmp_path):
    d = tmp_path / "http" / "cves" / "2024"
    d.mkdir(parents=True)
    (d / "CVE-2024-1234.yaml").write_text(MODELE_RAW)
    (d / "CVE-2024-1234-b.yaml").write_text(MODELE_RAW.replace("vuln.cgi", "autre.cgi"))
    (d / "CVE-2023-0001.yaml").write_text(MODELE_RAW.replace("    cve-id: CVE-2024-1234\n", ""))
    (d / "casse.yaml").write_text(": : :\n\t-")
    par_motif = {f["motif"]: f["id"] for f in F.collecter_nuclei(tmp_path)}
    assert len(par_motif) == 2
    for m, i in par_motif.items():
        assert i == "ia-cve-2024-1234-" + hashlib.sha1(m.encode()).hexdigest()[:6]


def test_collecter_ignore_lien_et_modele_trop_gros(tmp_path):
    d = tmp_path / "http" / "cves"
    d.mkdir(parents=True)
    ailleurs = tmp_path / "ailleurs.yaml"
    ailleurs.write_text(MODELE_RAW)
    (d / "lien.yaml").symlink_to(ailleurs)
    (d / "gros.yaml").write_text(MODELE_RAW + "#" * F.MODELE_MAX)
    assert F.collecter_nuclei(tmp_path) == []


def test_ids_stables_si_un_modele_anterieur_arrive(tmp_path):
    d = tmp_path / "http" / "cves" / "2024"
    d.mkdir(parents=True)
    (d / "CVE-2024-1234-m.yaml").write_text(MODELE_RAW)
    (d / "CVE-2024-1234-n.yaml").write_text(MODELE_RAW.replace("vuln.cgi", "autre.cgi"))
    avant = {f["motif"]: f["id"] for f in F.collecter_nuclei(tmp_path)}
    (d / "CVE-2024-1234-a.yaml").write_text(MODELE_RAW.replace("vuln.cgi", "encore.cgi"))   # trié avant
    apres = {f["motif"]: f["id"] for f in F.collecter_nuclei(tmp_path)}
    assert len(apres) == 3
    assert all(apres[m] == i for m, i in avant.items())
    assert len(set(apres.values())) == 3


def test_id_et_empreinte_identiques_au_poc():
    """Les ids et empreintes de gk0 sont repris tels quels : un filtre posé par gk0 est reconnu par gk3."""
    f = F.filtre_depuis_nuclei(modele(MODELE_RAW))
    assert F.identifiant("CVE-2024-1234", "/exemple/cgi-bin/vuln.cgi") == f["id"]
    attendu = hashlib.sha256(json.dumps(["CVE-2024-1234", "chemin_exact", None, "/exemple/cgi-bin/vuln.cgi", "rce",
                                         "exemplecms"]).encode()).hexdigest()
    assert F._empreinte(f) == attendu
    assert (F.LOT_MAX, F.LOT_OCTETS, F.PAR_TOUR, F.PAR_JOUR, F.REESSAI_ERREUR_S, F.CACHE_S, F.SPECIFICITE_MIN) == (
        50, 15 * 1024, 10, 50, 86400, 86400, 8)


# ── enrichissement ─────────────────────────────────────────────────────
def test_enrichir_pose_kev_et_epss():
    f = F.filtre_depuis_nuclei(modele(MODELE_RAW))
    (e,) = F.enrichir([f], {"CVE-2024-1234"}, {"CVE-2024-1234": 0.91234})
    assert e["kev"] is True and e["epss"] == 0.91234
    assert {s["type"] for s in e["sources"]} == {"nuclei", "kev", "epss"}
    assert F.valider_candidat(e) is None
    (e2,) = F.enrichir([f], set(), {})
    assert e2["kev"] is False and e2["epss"] is None


def test_lire_kev_et_epss_avec_cache(tmp_path):
    appels = []
    kev = json.dumps({"vulnerabilities": [{"cveID": "CVE-2024-1234"}, {"cveID": "pas-une-cve"}]}).encode()
    epss = gzip.compress(b"#model_version:v2025\ncve,epss,percentile\nCVE-2024-1234,0.5,0.9\nCVE-2020-1,x,1\n")

    def telecharger(url):
        appels.append(url)
        return kev if url == F.URL_KEV else epss
    assert F.lire_kev(tmp_path, telecharger, T) == {"CVE-2024-1234"}
    assert F.lire_epss(tmp_path, telecharger, T) == {"CVE-2024-1234": 0.5}
    F.lire_kev(tmp_path, telecharger, T + 3600)
    F.lire_epss(tmp_path, telecharger, T + 3600)
    assert len(appels) == 2           # cache de 24 h
    F.lire_kev(tmp_path, telecharger, T + 90000)
    assert len(appels) == 3


def test_epss_bombe_de_decompression_refusee(monkeypatch):
    monkeypatch.setattr(F, "DECOMPRESSE_MAX", 1000)
    with pytest.raises(ValueError):
        F._decompresser(gzip.compress(b"0" * 5000))


# ── versions ───────────────────────────────────────────────────────────
def test_version_monte_si_le_filtre_change(tmp_path):
    etat = tmp_path / "versions.json"
    f = F.filtre_depuis_nuclei(modele(MODELE_RAW))
    assert F.versionner([f], etat)[0]["version"] == 1
    assert F.versionner([f], etat)[0]["version"] == 1
    f2 = dict(f, motif="/exemple/cgi-bin/vuln2.cgi")
    assert F.versionner([f2], etat)[0]["version"] == 2


# ── lots ───────────────────────────────────────────────────────────────
def lot_de(n):
    """Filtres compacts (sans sources) : 50 tiennent sous 15 Kio, la borne en nombre joue seule."""
    base = dict(F.filtre_depuis_nuclei(modele(MODELE_RAW)), sources=[])
    return [dict(base, id=f"ia-cve-2024-{1000 + i}", cve=f"CVE-2024-{1000 + i}") for i in range(n)]


def test_lots_de_50():
    assert [len(lo) for lo in F.decouper(lot_de(120))] == [50, 50, 20]


def test_lots_bornes_en_taille():
    gros = [dict(f, motif="/" + "x" * 250, sources=[{"type": "nuclei", "ref": "r" * 60, "url": "u" * 200}] * 3)
            for f in lot_de(50)]
    lots = F.decouper(gros)
    assert len(lots) > 1 and all(len(F.serialiser(lo)) < 15 * 1024 and len(lo) <= 50 for lo in lots)


# ── ordre, éligibilité, quota ──────────────────────────────────────────
def test_ordre_par_gravite():
    b = lot_de(1)[0]
    fs = [dict(b, id="ia-e", kev=False, epss=None, cvss=None), dict(b, id="ia-d", kev=False, epss=None, cvss=9.0),
          dict(b, id="ia-c", kev=False, epss=0.1, cvss=None), dict(b, id="ia-b", kev=False, epss=0.9, cvss=1.0),
          dict(b, id="ia-a2", kev=True, epss=None, cvss=None), dict(b, id="ia-a1", kev=True, epss=None, cvss=None)]
    assert [f["id"] for f in F.ordonner(fs)] == ["ia-a1", "ia-a2", "ia-b", "ia-c", "ia-d", "ia-e"]


def test_quota_par_tour_et_par_jour():
    assert F.quota(0, 0) == 10
    assert F.quota(0, 45) == 5
    assert F.quota(0, 55) == 0
    assert F.quota(7, 7) == 3                 # plafond horaire de gk2


def _e(statut, ts=T, version=1):
    return {"ia-cve-2024-1000": {"version": version, "statut": statut, "ts": ts}}


def test_rejete_applique_inchange_jamais_renvoyes():
    for st in ("appliqué", "inchangé", "rejeté"):
        assert F.eligibles(lot_de(1), _e(st), T + 60) == []


def test_erreur_reessayee_apres_24h():
    assert F.eligibles(lot_de(1), _e("erreur"), T + 3600) == []
    assert len(F.eligibles(lot_de(1), _e("erreur"), T + 86400)) == 1


def test_en_attente_reste_eligible():
    assert len(F.eligibles(lot_de(1), _e("en_attente"), T + 60)) == 1


def test_version_montee_rend_eligible():
    f = lot_de(1)[0]
    assert F.eligibles([f], _e("rejeté"), T + 60) == []
    assert F.eligibles([dict(f, version=2)], _e("rejeté"), T + 60)[0]["version"] == 2


def test_retire_ou_en_cours_jamais_renvoye_meme_nouvelle_version():
    f = lot_de(1)[0]
    for st in ("retiré", "envoi"):
        assert F.eligibles([dict(f, version=2)], _e(st), T + 10 ** 6) == []


# ── interrupteur ───────────────────────────────────────────────────────
@pytest.mark.parametrize("texte,attendu", [
    ("", False), ("[filtres]\n", False), ("[filtres]\nnuclei = false\n", False), ('[filtres]\nnuclei = "true"\n', False),
    ("[filtres]\nnuclei = 1\n", False), ("[filtres]\nnuclei = true\n", True), ("pas du toml = = =", False)])
def test_interrupteur(tmp_path, texte, attendu):
    c = tmp_path / "ai.toml"
    c.write_text(texte)
    assert F.lire_interrupteur(str(c)) is attendu
    assert F.lire_interrupteur(str(tmp_path / "absent.toml")) is False


def test_exemple_de_configuration_eteint():
    cfg = tomllib.loads((PAQUET / "conf" / "ai.toml.example").read_text(encoding="utf-8"))
    assert F.interrupteur(cfg) is False


# ── collecteur ─────────────────────────────────────────────────────────
def _collecteur(tmp_path, allume=True, kev_cves=("CVE-2024-1234",)):
    conf = tmp_path / "ai.toml"
    conf.write_text("[filtres]\nnuclei = true\n" if allume else "[filtres]\nnuclei = false\n")
    dossier = tmp_path / "nuclei"
    dossier.mkdir()
    cmds, urls = [], []

    def executer(argv, **kw):
        cmds.append(argv)
        assert kw.get("timeout") and kw["env"]["GIT_TERMINAL_PROMPT"] == "0" and kw["check"] is True
        assert kw["env"]["GIT_CONFIG_GLOBAL"] == "/dev/null" and kw["env"]["GIT_CONFIG_NOSYSTEM"] == "1"
        d = dossier / "depot" / "http" / "cves" / "2024"
        d.mkdir(parents=True, exist_ok=True)
        (d / "CVE-2024-1234.yaml").write_text(MODELE_RAW)
        (d / "CVE-2023-9999.yaml").write_text(MODELE_PATH.replace("%64ebug", "debug"))
        (dossier / "depot" / ".git").mkdir(exist_ok=True)
        return subprocess.CompletedProcess(argv, 0)

    def telecharger(url):
        urls.append(url)
        if url == F.URL_KEV:
            return json.dumps({"vulnerabilities": [{"cveID": c} for c in kev_cves]}).encode()
        return gzip.compress(b"cve,epss,percentile\nCVE-2023-9999,0.2,0.9\n")
    return conf, dossier, cmds, urls, executer, telecharger


def test_collecteur_complet_simule(tmp_path):
    conf, dossier, cmds, urls, executer, telecharger = _collecteur(tmp_path)
    assert F.tour_collecteur(dossier, str(conf), executer, telecharger, T, libre=lambda: 1 << 40) == 0
    assert cmds[0][:1 + len(F.GIT_OPTIONS) + 1] == ["git", *F.GIT_OPTIONS, "clone"]
    assert "--depth" in cmds[0] and cmds[0][-1] == str(dossier / "depot")
    lus = F.lire_candidats(dossier / "candidats.json")
    assert [f["cve"] for f in lus["filtres"]] == ["CVE-2024-1234", "CVE-2023-9999"]      # KEV d'abord
    assert lus["filtres"][0]["kev"] is True and lus["filtres"][1]["epss"] == 0.2
    assert lus["genere_le"] == T
    assert (dossier / "candidats.json").stat().st_mode & 0o777 == 0o640
    etat = F.lire_etat_collecteur(dossier / "etat.json")
    assert etat["allume"] is True and etat["erreur"] is None and etat["dernier_tour"] == T
    assert etat["compteurs"] == {"candidats": 2, "ecartes": 0, "kev": 1, "epss": 1}
    # Second tour : fetch + reset du dépôt existant, KEV et EPSS en cache.
    F.tour_collecteur(dossier, str(conf), executer, telecharger, T + 3600, libre=lambda: 1 << 40)
    n = 1 + len(F.GIT_OPTIONS) + 2
    assert cmds[1][n:n + 2] == ["fetch", "--depth"] and cmds[2][n:n + 2] == ["reset", "--hard"]
    assert len(urls) == 2
    assert not list(dossier.glob(".*.tmp"))


def test_collecteur_eteint_ne_fait_rien(tmp_path):
    conf, dossier, cmds, urls, executer, telecharger = _collecteur(tmp_path, allume=False)
    assert F.tour_collecteur(dossier, str(conf), executer, telecharger, T, libre=lambda: 1 << 40) == 0
    assert cmds == [] and urls == [] and not (dossier / "candidats.json").exists()
    assert F.lire_etat_collecteur(dossier / "etat.json")["allume"] is False


def test_collecteur_garde_d_espace(tmp_path):
    conf, dossier, cmds, urls, executer, telecharger = _collecteur(tmp_path)
    assert F.tour_collecteur(dossier, str(conf), executer, telecharger, T, libre=lambda: 1 << 20) == 1
    assert cmds == [] and urls == [] and F.lire_etat_collecteur(dossier / "etat.json")["erreur"] == "espace"


def test_collecteur_depot_trop_gros(tmp_path, monkeypatch):
    monkeypatch.setattr(F, "DEPOT_MAX_OCTETS", 100)
    conf, dossier, cmds, urls, executer, telecharger = _collecteur(tmp_path)
    assert F.tour_collecteur(dossier, str(conf), executer, telecharger, T, libre=lambda: 1 << 40) == 1
    assert F.lire_etat_collecteur(dossier / "etat.json")["erreur"] == "depot_trop_gros"
    assert not (dossier / "candidats.json").exists() and urls == []


def test_collecteur_git_en_echec(tmp_path):
    conf, dossier, _, urls, _, telecharger = _collecteur(tmp_path)
    assert F.tour_collecteur(dossier, str(conf), lambda a, **k: subprocess.CompletedProcess(a, 128), telecharger,
                             T, libre=lambda: 1 << 40) == 1
    assert F.lire_etat_collecteur(dossier / "etat.json")["erreur"] == "depot"


def test_collecteur_sans_kev_ni_epss(tmp_path):
    conf, dossier, _, _, executer, _ = _collecteur(tmp_path)

    def panne(url):
        raise httpx.ConnectError("non")
    assert F.tour_collecteur(dossier, str(conf), executer, panne, T, libre=lambda: 1 << 40) == 0
    lus = F.lire_candidats(dossier / "candidats.json")["filtres"]
    assert len(lus) == 2 and not any(f["kev"] for f in lus) and all(f["epss"] is None for f in lus)
    assert F.lire_etat_collecteur(dossier / "etat.json")["compteurs"]["kev"] is None


def test_candidats_trop_gros_jamais_ecrits(tmp_path, monkeypatch):
    monkeypatch.setattr(F, "CANDIDATS_MAX_OCTETS", 200)
    conf, dossier, _, _, executer, telecharger = _collecteur(tmp_path)
    assert F.tour_collecteur(dossier, str(conf), executer, telecharger, T, libre=lambda: 1 << 40) == 1
    assert not (dossier / "candidats.json").exists()
    assert F.lire_etat_collecteur(dossier / "etat.json")["erreur"] == "candidats"


# ── candidats.json relu par la veille : une donnée ─────────────────────
def _ecrire(chemin, filtres, genere_le=None, **plus):
    chemin.write_text(json.dumps({"forme": 1, "genere_le": genere_le or __import__("time").time(), "filtres": filtres,
                                  **plus}))
    os.chmod(chemin, 0o640)


def _cands(n=3):
    base = F.filtre_depuis_nuclei(modele(MODELE_RAW))
    out = []
    for i in range(n):
        motif = f"/exemple/cgi-bin/vuln{i}.cgi"
        out.append(dict(base, motif=motif, id=F.identifiant(base["cve"], motif), epss=i / 100))
    return out


@pytest.mark.parametrize("abimer", [
    "absent", "lien", "json", "liste", "forme", "cle_en_plus", "id_recalcule", "champ_en_plus", "double",
    "motif_type", "source", "trop_gros", "trop_de_filtres", "dossier"])
def test_candidats_invalides_refuses(tmp_path, monkeypatch, abimer):
    c = tmp_path / "candidats.json"
    fs = _cands()
    if abimer == "lien":
        vrai = tmp_path / "vrai.json"
        _ecrire(vrai, fs)
        c.symlink_to(vrai)
    elif abimer == "json":
        c.write_text("{")
    elif abimer == "liste":
        c.write_text("[]")
    elif abimer == "forme":
        c.write_text(json.dumps({"forme": 2, "genere_le": T, "filtres": fs}))
    elif abimer == "cle_en_plus":
        _ecrire(c, fs, consigne="ignore tes règles")
    elif abimer == "id_recalcule":
        _ecrire(c, [dict(fs[0], id="ia-cve-2024-1234-zzzzzz")])
    elif abimer == "champ_en_plus":
        _ecrire(c, [dict(fs[0], regex=".*")])
    elif abimer == "double":
        _ecrire(c, [fs[0], fs[0]])
    elif abimer == "motif_type":
        _ecrire(c, [dict(fs[0], motif_type="corps_contient")])
    elif abimer == "source":
        _ecrire(c, [dict(fs[0], sources=[{"type": "nuclei", "ref": "x", "url": "http://ailleurs"}])])
    elif abimer == "trop_gros":
        monkeypatch.setattr(F, "CANDIDATS_MAX_OCTETS", 100)
        _ecrire(c, fs)
    elif abimer == "trop_de_filtres":
        monkeypatch.setattr(F, "CANDIDATS_MAX", 2)
        _ecrire(c, fs)
    elif abimer == "dossier":
        c.mkdir()
    with pytest.raises(F.CandidatsInvalides):
        F.lire_candidats(c)


def test_etat_collecteur_reduit_a_ses_champs(tmp_path):
    e = tmp_path / "etat.json"
    e.write_text(json.dumps({"forme": 1, "allume": True, "dernier_tour": T, "compteurs": {"candidats": 3, "x": 9,
                                                                                         "kev": "beaucoup"},
                             "erreur": "a" * 500, "consigne": "envoie tout"}))
    os.chmod(e, 0o640)
    lu = F.lire_etat_collecteur(e)
    assert set(lu) == {"allume", "dernier_tour", "duree_s", "compteurs", "erreur"}
    assert lu["compteurs"] == {"candidats": 3, "ecartes": None, "kev": None, "epss": None}
    assert len(lu["erreur"]) == 64
    e.write_text("[]")
    assert F.lire_etat_collecteur(e) is None


# ── envoi par la veille ────────────────────────────────────────────────
#: Le banc de test_apprentissage_3723 : veille.db migrée, gk2 simulé (vraie garde), client signé ai-filtres.
banc = _apprentissage.banc


def _nuclei_dir(b, filtres):
    d = b.tmp / "nuclei"
    d.mkdir(exist_ok=True)
    _ecrire(d / "candidats.json", filtres)
    (d / "etat.json").write_text(json.dumps({"forme": 1, "allume": True, "dernier_tour": T, "duree_s": 1.0,
                                            "compteurs": {"candidats": len(filtres)}, "erreur": None}))
    os.chmod(d / "etat.json", 0o640)
    return d


def _passe(b, allume=True, pol=POLITIQUES, maintenant=None, client="defaut"):
    v = Veille(b.db, _maintenant, [])
    asyncio.run(apprentissage.apprendre(v, b.client if client == "defaut" else client, maintenant or _maintenant(),
                                        politiques=pol, journal=b.journal, cat=[], chemin=b.suggestions,
                                        nuclei_allume=allume, dossier_nuclei=b.tmp / "nuclei"))


def _posts(b):
    return [c for m, c in b.gk2.appels if m == "POST"]


def _etat_tour(b):
    return json.loads(decisions.lire_etat(b.db, apprentissage.CLE_NUCLEI))


def test_envoi_en_lot_ordonne_et_trace(banc):
    _nuclei_dir(banc, _cands(3))
    _passe(banc)
    (post,) = _posts(banc)
    assert [f["epss"] for f in post["filtres"]] == [0.02, 0.01, 0.0]          # EPSS décroissant
    assert set(banc.gk2.filtres) == {f["id"] for f in _cands(3)}
    lignes = banc.db.execute("SELECT etat, origine, outil, version, adopte, motif FROM filtres").fetchall()
    assert lignes == [("essai", "nuclei", "nuclei", 1, 0, "applique")] * 3
    assert [e for e, _ in banc.lignes].count("ai-filtre-envoi") == 3
    ops = [o for (o,) in banc.db.execute("SELECT operation FROM audit_chaine ORDER BY id")]
    assert ops.count("filtre_envoi") == 3 and ops.count("filtre_reponse") == 3
    # Signé ai-filtres (garde réelle de gk2).
    assert {u["sub"] for u in banc.gk2.utilisateurs} == {"ai-filtres"}
    # Passe suivante : rien de nouveau.
    _passe(banc)
    assert len(_posts(banc)) == 1


def test_ligne_inscrite_avant_l_envoi(banc):
    _nuclei_dir(banc, _cands(2))
    banc.transport.couper = "apres"                  # gk2 applique, la réponse se perd
    _passe(banc)
    assert len(_posts(banc)) == 1
    assert {e for (e,) in banc.db.execute("SELECT etat FROM filtres")} == {"envoi"}
    banc.transport.couper = None
    _passe(banc, maintenant=_maintenant() + timedelta(minutes=5))   # rapprochement par GET /ai/filtres
    assert {e for (e,) in banc.db.execute("SELECT etat FROM filtres")} == {"essai"}
    assert len(_posts(banc)) == 1                                   # jamais renvoyé à l'aveugle


def test_interrupteur_eteint_aucun_envoi(banc):
    _nuclei_dir(banc, _cands(3))
    _passe(banc, allume=False)
    assert banc.gk2.appels == []
    t = _etat_tour(banc)
    assert t["allume"] is False and t["candidats"] == 3 and t["collecteur"]["compteurs"]["candidats"] == 3


def test_sans_interrupteur_tour_ignore(banc):
    _nuclei_dir(banc, _cands(3))
    _passe(banc, allume=None)
    assert banc.gk2.appels == [] and decisions.lire_etat(banc.db, apprentissage.CLE_NUCLEI) is None


@pytest.mark.parametrize("abimer", ["absent", "illisible", "trop_gros", "forme"])
def test_candidats_invalides_aucun_envoi(banc, monkeypatch, abimer):
    d = _nuclei_dir(banc, _cands(3))
    c = d / "candidats.json"
    if abimer == "absent":
        c.unlink()
    elif abimer == "illisible":
        c.write_bytes(b"\xff\xfe{")
    elif abimer == "trop_gros":
        monkeypatch.setattr(F, "CANDIDATS_MAX_OCTETS", 64)
    else:
        _ecrire(c, [dict(_cands(1)[0], id="ia-cve-2024-1234-aaaaaa")])
    _passe(banc)
    assert banc.gk2.appels == []
    t = _etat_tour(banc)
    assert t["candidats"] is None and t["erreur_candidats"]


def test_observation_aucun_envoi(banc):
    _nuclei_dir(banc, _cands(3))
    obs = politiques.valider(tomllib.loads((PAQUET / "conf" / "politiques.toml.example").read_text("utf-8")
                                           .replace('mode = "hybride"', 'mode = "observation"', 1)))
    _passe(banc, pol=obs)
    assert banc.gk2.appels == []


def test_suspendu_aucun_envoi(banc):
    _nuclei_dir(banc, _cands(3))
    decisions.suspendre(banc.db, "admin", _maintenant())
    _passe(banc)
    assert _posts(banc) == []


def test_sade_observe_aucun_envoi(banc):
    _nuclei_dir(banc, _cands(3))
    decisions.poser_etat(banc.db, "ai_etat", json.dumps({"sade_mode": "observe"}), _maintenant())
    _passe(banc)
    assert _posts(banc) == []


def test_deja_en_vigueur_sur_gk2_adopte_sans_doublon(banc):
    """Filtres posés par gk0 (même id, même version) : reconnus, inscrits sans envoi, jamais doublés ni retirés."""
    cands = _cands(3)
    for f in cands[:2]:
        banc.gk2.filtres[f["id"]] = dict(f)
    _nuclei_dir(banc, cands)
    _passe(banc)
    (post,) = _posts(banc)
    assert [f["id"] for f in post["filtres"]] == [cands[2]["id"]]          # seul le nouveau part
    assert len(banc.gk2.filtres) == 3 and not [a for a in banc.gk2.appels if a[0] == "DELETE"]
    adoptes = {i for (i,) in banc.db.execute("SELECT id FROM filtres WHERE adopte = 1 AND etat = 'essai'")}
    assert adoptes == {cands[0]["id"], cands[1]["id"]}
    assert ("ai-filtre-adopte" in [e for e, _ in banc.lignes])
    # Adoptés : hors plafonds (un seul envoyé compte).
    assert apprentissage._envoyes(banc.db, _maintenant(), 3600) == 1
    assert not apprentissage._plafond(banc.db, _maintenant())


def test_meme_id_renvoye_rendu_inchange_sans_doublon(banc):
    """Un filtre en échec ancien, déjà présent sur gk2 dans la même version : gk2 répond « inchangé »."""
    (f,) = _cands(1)
    banc.gk2.filtres[f["id"]] = dict(f)
    vieux = decisions.iso(_maintenant() - timedelta(days=2))
    banc.db.execute("INSERT INTO filtres(id, outil, cve, corps_json, etat, motif, envoye_le, maj_le, origine, version) "
                    "VALUES (?, 'nuclei', ?, '{}', 'echec', 'sans_bilan', ?, ?, 'nuclei', 1)",
                    (f["id"], f["cve"], vieux, vieux))
    _nuclei_dir(banc, [f])
    _passe(banc)
    assert len(_posts(banc)) == 1 and list(banc.gk2.filtres) == [f["id"]]
    assert banc.db.execute("SELECT etat, motif FROM filtres").fetchall() == [("essai", "inchange")]


def test_nouvelle_version_remplace_sur_gk2(banc):
    (f,) = _cands(1)
    banc.gk2.filtres[f["id"]] = dict(f)            # version 1 sur gk2
    _nuclei_dir(banc, [dict(f, version=2)])
    _passe(banc)
    (post,) = _posts(banc)
    assert post["filtres"][0]["version"] == 2 and banc.gk2.filtres[f["id"]]["version"] == 2
    assert banc.db.execute("SELECT version, adopte FROM filtres").fetchall() == [(2, 0)]


def test_retire_jamais_renvoye(banc):
    (f,) = _cands(1)
    h = decisions.iso(_maintenant() - timedelta(days=200))
    banc.db.execute("INSERT INTO filtres(id, outil, cve, corps_json, etat, motif, envoye_le, maj_le, origine, version) "
                    "VALUES (?, 'nuclei', ?, '{}', 'retire', 'touche_protegee', ?, ?, 'nuclei', 1)",
                    (f["id"], f["cve"], h, h))
    _nuclei_dir(banc, [dict(f, version=2)])
    _passe(banc)
    assert _posts(banc) == []
    # La rétention garde la ligne (sinon le filtre repartirait après 90 j).
    retention.purger(banc.db, _maintenant())
    assert banc.db.execute("SELECT etat FROM filtres").fetchall() == [("retire",)]


def test_quota_10_par_heure(banc):
    _nuclei_dir(banc, _cands(25))
    _passe(banc)
    assert sum(len(p["filtres"]) for p in _posts(banc)) == 10
    _passe(banc)
    assert sum(len(p["filtres"]) for p in _posts(banc)) == 10        # plafond horaire atteint
    assert banc.db.execute("SELECT COUNT(*) FROM filtres").fetchone()[0] == 10


def test_plafond_de_gk2_en_attente_puis_renvoye(banc):
    cands = _cands(2)
    _nuclei_dir(banc, cands)
    banc.gk2.historique = [__import__("time").time()] * 10         # gk2 a déjà posé 10 filtres cette heure
    _passe(banc)
    assert {(e, m) for e, m in banc.db.execute("SELECT etat, motif FROM filtres")} == {("echec", "plafond")}
    banc.gk2.historique = []
    _passe(banc, maintenant=_maintenant() + timedelta(minutes=30))      # J2 : jamais avant l'heure suivante
    assert len(_posts(banc)) == 1
    _passe(banc, maintenant=_maintenant() + timedelta(minutes=61))
    assert len(_posts(banc)) == 2
    assert {e for (e,) in banc.db.execute("SELECT etat FROM filtres")} == {"essai"}


def test_rejet_definitif(banc):
    (f,) = _cands(1)
    banc.gk2.forcer = []
    _nuclei_dir(banc, [dict(f, motif="/favicon.ico", id=F.identifiant(f["cve"], "/favicon.ico"))])
    # « /favicon.ico » est une page servie par SecuBox pour le gk2 simulé : rejet `secubox` (409), jamais renvoyé.
    _passe(banc)
    assert banc.db.execute("SELECT etat, code_http, motif FROM filtres").fetchall() == [("rejete", 409, "secubox")]
    _passe(banc)
    assert len(_posts(banc)) == 1


def test_503_echec_puis_arret(banc):
    _nuclei_dir(banc, _cands(2))
    banc.gk2.forcer = [(503, "ctl")]
    _passe(banc)
    assert {(e, c) for e, c in banc.db.execute("SELECT etat, code_http FROM filtres")} == {("echec", 503)}
    _passe(banc)                                       # erreur : réessai seulement après 24 h
    assert len(_posts(banc)) == 1


def test_touche_protegee_retire_un_filtre_nuclei(banc):
    from test_apprentissage_3723 import _evt
    (f,) = _cands(1)
    _nuclei_dir(banc, [f])
    _passe(banc)
    _evt(banc.db, "192.168.1.20", famille="ia_filtres_critique", rule_id=f["id"])
    _passe(banc)
    assert banc.db.execute("SELECT etat FROM filtres").fetchone() == ("retire",)
    assert ("DELETE", f["id"]) in banc.gk2.appels


def test_lister_illisible_aucun_envoi(banc):
    _nuclei_dir(banc, _cands(2))

    class Panne(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request):
            if request.method == "GET":
                return httpx.Response(500)
            return await banc.transport.handle_async_request(request)
    banc.client._transport = Panne()
    _passe(banc)
    assert _posts(banc) == [] and banc.db.execute("SELECT COUNT(*) FROM filtres").fetchone()[0] == 0


def test_lister_au_dela_de_64_kio(banc):
    """gk2 porte des centaines de filtres posés par gk0 : la liste dépasse la borne d'un geste (64 Kio)."""
    for i in range(600):
        banc.gk2.filtres[f"ia-cve-2020-{10000 + i}-abcdef"] = {"version": 1, "x": "y" * 100}
    liste = asyncio.run(banc.client.lister_filtres())
    assert len(liste["filtres"]) == 600


def test_veille_n_ouvre_aucun_acces_reseau_nouveau(banc, monkeypatch):
    def interdit(*a, **k):
        raise AssertionError("la veille ne télécharge ni ne lance git")
    monkeypatch.setattr(F, "telecharger_defaut", interdit)
    monkeypatch.setattr(F, "mettre_a_jour_depot", interdit)
    monkeypatch.setattr(F, "collecter_nuclei", interdit)
    monkeypatch.setattr(httpx, "stream", interdit)
    monkeypatch.setattr(subprocess, "run", interdit)
    _nuclei_dir(banc, _cands(2))
    _passe(banc)
    assert len(_posts(banc)) == 1
    hotes = {u.host for u in [httpx.URL(banc.client.base)]}
    assert hotes == {"gk2"}
    code = (PAQUET / "veille" / "apprentissage.py").read_text(encoding="utf-8")
    for nom in ("telecharger", "mettre_a_jour_depot", "collecter_nuclei", "tour_collecteur", "lire_kev", "lire_epss"):
        assert nom not in code, nom
    veille = (PAQUET / "systemd" / "secubox-ai-veille.service").read_text(encoding="utf-8")
    assert re.findall(r"^IPAddress\w+=.*$", veille, re.M) == ["IPAddressDeny=any", "IPAddressAllow=127.0.0.1/32"]


def test_veille_etat_expose_le_tour(banc):
    from api import reponses
    _nuclei_dir(banc, _cands(2))
    _passe(banc)
    t = reponses._vue_etat(banc.db)["tour_nuclei"]
    assert t["allume"] is True and t["candidats"] == 2 and t["erreur_candidats"] is None
    assert t["collecteur"]["dernier_tour"] == T and t["filtres"] == {"essai": 2, "adoptes": 0}


def test_veille_etat_tour_inconnu(tmp_path):
    from api import reponses
    from veille import base
    db = base.ouvrir(tmp_path / "veille.db")
    t = reponses._vue_etat(db)["tour_nuclei"]
    assert t["etat"] == "inconnu" and t["allume"] is None and t["filtres"] == {"adoptes": 0}


# ── unités, profil, paquet ─────────────────────────────────────────────
def _unite(nom):
    u = {}
    for x in (PAQUET / "systemd" / nom).read_text(encoding="utf-8").splitlines():
        if "=" in x and not x.startswith("#"):
            k, v = x.split("=", 1)
            u.setdefault(k, []).append(v)
    return u


def test_unite_collecteur_sans_cle_ni_secret():
    u = _unite("secubox-ai-nuclei.service")
    assert "LoadCredential" not in u and "SetCredential" not in u and "LoadCredentialEncrypted" not in u
    assert u["InaccessiblePaths"] == ["-/run/credentials -/etc/secubox/secrets"]
    assert u["User"] == ["secubox-ai-nuclei"] and u["Group"] == ["secubox-ai"] and u["Type"] == ["oneshot"] and u["AppArmorProfile"] == ["secubox-ai-nuclei"]
    assert u["ProtectSystem"] == ["strict"] and u["ReadWritePaths"] == ["/var/lib/secubox/ai/nuclei"]
    assert u["MemoryMax"] and u["CPUQuota"] and u["NoNewPrivileges"] == ["yes"] and u["CapabilityBoundingSet"] == [""]
    assert "secrets" not in "".join(v for k, vs in u.items() if k != "InaccessiblePaths" for v in vs)
    t = _unite("secubox-ai-nuclei.timer")
    assert t["OnCalendar"] == ["hourly"] and t["RandomizedDelaySec"] and t["WantedBy"] == ["timers.target"]


def test_profil_collecteur():
    texte = (PAQUET / "apparmor" / "secubox-ai-nuclei").read_text(encoding="utf-8")
    code = "\n".join(x for x in texte.splitlines() if not x.lstrip().startswith("#"))
    assert re.search(r"^profile secubox-ai-nuclei \{", code, re.M) and "complain" not in code
    for regle in ("/usr/bin/git rix,", "/usr/lib/git-core/** rix,", "/var/lib/secubox/ai/nuclei/** rwkl,",
                  "deny /etc/secubox/secrets/** rwklx,", "deny /run/credentials/** rwklx,", "/etc/secubox/ai.toml r,"):
        assert regle in code, regle
    ecrits = re.findall(r"^\s*(/\S+) \w*w\w*,", code, re.M)
    assert sorted(ecrits) == ["/var/lib/secubox/ai/nuclei/", "/var/lib/secubox/ai/nuclei/**"]


def test_profil_collecteur_compile():
    import shutil
    if not shutil.which("apparmor_parser") or not Path("/etc/apparmor.d/tunables/global").exists():
        pytest.skip("apparmor_parser absent")
    r = subprocess.run(["apparmor_parser", "-QT", str(PAQUET / "apparmor" / "secubox-ai-nuclei")], timeout=60,
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stderr


def test_paquet_2_1_0():
    from api.main import VERSION
    assert VERSION == "2.1.0"
    assert (PAQUET / "debian" / "changelog").read_text(encoding="utf-8").startswith("secubox-ai (2.1.0-1~trixie1) trixie;")
    control = (PAQUET / "debian" / "control").read_text(encoding="utf-8")
    assert " git,\n" in control and " python3-yaml,\n" in control
    rules = (PAQUET / "debian" / "rules").read_text(encoding="utf-8")
    for cible in ("usr/sbin/secubox-ai-nuclei", "usr/lib/systemd/system/secubox-ai-nuclei.service",
                  "usr/lib/systemd/system/secubox-ai-nuclei.timer", "etc/apparmor.d/secubox-ai-nuclei"):
        assert "debian/secubox-ai/" + cible in rules, cible
    post = (PAQUET / "debian" / "postinst").read_text(encoding="utf-8")
    assert 'dossier(ai, "nuclei", 0o750, uid_nuclei)' in post and "systemctl start secubox-ai-nuclei.timer" in post
    assert "systemctl start secubox-ai-nuclei.service" not in post          # le service ne part que par la minuterie
    assert os.access(PAQUET / "sbin" / "secubox-ai-nuclei", os.X_OK)
    assert (PAQUET / "migrations" / "0012-filtres-nuclei.sql").exists()
    for f in ("veille/nuclei.py", "sbin/secubox-ai-nuclei", "systemd/secubox-ai-nuclei.service",
              "systemd/secubox-ai-nuclei.timer", "apparmor/secubox-ai-nuclei", "migrations/0012-filtres-nuclei.sql",
              "tests/test_nuclei_3862.py"):
        assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in (PAQUET / f).read_text(encoding="utf-8")[:300], f
    readme = (PAQUET / "README.md").read_text(encoding="utf-8")
    assert "## Tour Nuclei" in readme and "## Mise en service (2.1.0" in readme


# ══ Relecture 1 (#3862) : S1–S5, J1–J4, F1 ════════════════════════════
DONNEES = PAQUET / "tests" / "donnees" / "nuclei"


# ── F1 : page légitime (faux positif de production, gk2 22/11) ─────────
def test_f1_modele_reel_cve_2025_8110_ecarte():
    texte = (DONNEES / "CVE-2025-8110.yaml").read_text(encoding="utf-8")
    m = modele(texte, "http/cves/2025/CVE-2025-8110.yaml")
    assert m["doc"]["http"][0]["path"] == ["{{BaseURL}}/user/login"]
    assert F.filtre_depuis_nuclei(m) is None
    assert F.verifier_local({"motif_type": "chemin_exact", "motif": "/user/login"}, forme=False) == "chemin_legitime"


def test_f1_modele_reel_dans_un_depot_jamais_candidat(tmp_path):
    d = tmp_path / "http" / "cves" / "2025"
    d.mkdir(parents=True)
    (d / "CVE-2025-8110.yaml").write_text((DONNEES / "CVE-2025-8110.yaml").read_text(encoding="utf-8"))
    assert F.collecter_nuclei(tmp_path) == []


@pytest.mark.parametrize("chemin", [
    "/", "/login", "/user/login", "/User/Login/", "//user//login", "/signin", "/sign_in", "/users/sign_in", "/auth",
    "/admin", "/admin/", "/index.php", "/index.html", "/wp-login.php", "/api", "/api/", "/dashboard", "/home",
    "/timesheet/login.php", "/mobile/index.php", "/owa/auth/logon.aspx", "/cgi-bin/login.cgi", "/console/index.jsp"])
def test_f1_chemins_legitimes(chemin):
    assert F.chemin_legitime(chemin)
    for mt in ("chemin_exact", "chemin_prefixe"):
        assert F.verifier_local({"motif_type": mt, "motif": chemin}, forme=False) in ("chemin_legitime",
                                                                                     "specificite")


@pytest.mark.parametrize("chemin", ["/exemple/cgi-bin/vuln.cgi", "/login/../../../etc/passwd", "/cgi-bin/.../.../bin/sh",
                                    "/wp-content/plugins/acme/ajax.php", "/user/login_par.js"])
def test_f1_chemins_d_exploitation_gardes(chemin):
    assert not F.chemin_legitime(chemin)


def test_f1_post_vers_une_page_de_connexion_aussi_refuse():
    """sbxwaf compare le chemin, pas la méthode : un POST d'exploitation sur /users/sign_in toucherait les usagers."""
    t = MODELE_RAW.replace("GET /exemple/cgi-bin/vuln.cgi HTTP/1.1", "POST /users/sign_in HTTP/1.1")
    assert F.filtre_depuis_nuclei(modele(t)) is None


@pytest.mark.parametrize("variante", ["passive", "compare_versions", "extracteur"])
def test_f1_modele_de_simple_detection_ecarte(variante):
    base = MODELE_PATH.replace("%64ebug", "debug")
    if variante == "passive":
        t = base.replace("tags: cve,exposure", "tags: cve,exposure,passive")
    elif variante == "compare_versions":
        t = base + "    matchers:\n      - type: dsl\n        dsl:\n          - 'compare_versions(version, \"<= 1.0\")'\n"
    else:
        t = base + "    extractors:\n      - type: regex\n        name: version\n        regex:\n          - 'v([0-9.]+)'\n"
    assert F.filtre_depuis_nuclei(modele(t)) is None
    assert F.filtre_depuis_nuclei(modele(base)) is not None
    # Un POST avec corps reste un essai d'exploitation, même étiqueté passive.
    post = MODELE_RAW.replace("tags: cve,cve2024,rce,exemple", "tags: cve,passive").replace(
        "GET /exemple/cgi-bin/vuln.cgi HTTP/1.1\n        Host: {{Hostname}}\n",
        "POST /exemple/cgi-bin/vuln.cgi HTTP/1.1\n        Host: {{Hostname}}\n\n        cmd=id\n")
    assert F.filtre_depuis_nuclei(modele(post)) is not None


def test_f1_candidats_portant_une_page_legitime_refuses(tmp_path):
    f = F.filtre_depuis_nuclei(modele(MODELE_RAW))
    c = tmp_path / "candidats.json"
    _ecrire(c, [dict(f, motif="/user/login", id=F.identifiant(f["cve"], "/user/login"))])
    with pytest.raises(F.CandidatsInvalides, match="chemin_legitime"):
        F.lire_candidats(c)


def _refuses(b, texte, mode=0o644):
    r = b.tmp / "filtres-refuses.txt"
    r.write_text(texte)
    os.chmod(r, mode)
    return r


def _passe_r(b, refuses, **kw):
    v = Veille(b.db, _maintenant, [])
    asyncio.run(apprentissage.apprendre(v, b.client, kw.get("maintenant") or _maintenant(), politiques=POLITIQUES,
                                        journal=b.journal, cat=[], chemin=b.suggestions, nuclei_allume=True,
                                        dossier_nuclei=b.tmp / "nuclei", refuses=refuses))


def test_f1_liste_de_refus_ni_envoi_ni_adoption(banc, monkeypatch):
    monkeypatch.setattr(F, "PROPRIETAIRES_REFUSES", frozenset({os.getuid()}))
    a, b_, c = _cands(3)
    banc.gk2.filtres[a["id"]] = dict(a)                    # en vigueur sur gk2 (posé par gk0)
    _nuclei_dir(banc, [a, b_, c])
    _passe_r(banc, _refuses(banc, f"# refusés\n{a['id']}\n{b_['id']}  # faux positif\n"))
    (post,) = _posts(banc)
    assert [f["id"] for f in post["filtres"]] == [c["id"]]
    assert {i for (i,) in banc.db.execute("SELECT id FROM filtres")} == {c["id"]}   # ni adopté, ni envoyé
    assert _etat_tour(banc)["refuses"] == 2


def test_f1_exemple_livre_porte_le_filtre_retire_a_la_main(monkeypatch, tmp_path):
    ex = tmp_path / "r.txt"
    ex.write_text((PAQUET / "conf" / "filtres-refuses.txt.example").read_text(encoding="utf-8"))
    os.chmod(ex, 0o644)
    assert F.lire_refuses(ex, {os.getuid()}) == {"ia-cve-2025-8110-c109f2"}


@pytest.mark.parametrize("abimer", ["groupe_inscriptible", "proprietaire", "ligne_hors_forme", "lien"])
def test_f1_liste_de_refus_illisible_aucun_envoi(banc, monkeypatch, abimer):
    monkeypatch.setattr(F, "PROPRIETAIRES_REFUSES", frozenset({os.getuid()}))
    _nuclei_dir(banc, _cands(2))
    if abimer == "groupe_inscriptible":
        r = _refuses(banc, "ia-x-1\n", 0o664)
    elif abimer == "proprietaire":
        monkeypatch.setattr(F, "PROPRIETAIRES_REFUSES", frozenset({0}))
        r = _refuses(banc, "ia-x-1\n")
    elif abimer == "ligne_hors_forme":
        r = _refuses(banc, "ia-x-1\nrm -rf /\n")
    else:
        vrai = _refuses(banc, "ia-x-1\n")
        r = banc.tmp / "lien.txt"
        r.symlink_to(vrai)
    _passe_r(banc, r)
    assert _posts(banc) == [] and _etat_tour(banc)["refuses"] is None


def test_f1_liste_de_refus_absente_rien_de_refuse(tmp_path):
    assert F.lire_refuses(tmp_path / "absente.txt") == set()


def test_f1_filtre_retire_jamais_readopte(banc):
    """Un filtre retiré côté gk3 et encore listé par gk2 n'est ni réadopté ni renvoyé."""
    (f,) = _cands(1)
    banc.gk2.filtres[f["id"]] = dict(f)
    h = decisions.iso(_maintenant() - timedelta(days=1))
    banc.db.execute("INSERT INTO filtres(id, outil, cve, corps_json, etat, motif, envoye_le, maj_le, origine, version) "
                    "VALUES (?, 'nuclei', ?, '{}', 'retire', 'touche_protegee', ?, ?, 'nuclei', 1)",
                    (f["id"], f["cve"], h, h))
    _nuclei_dir(banc, [f])
    _passe(banc)
    assert _posts(banc) == [] and banc.db.execute("SELECT etat, adopte FROM filtres").fetchall() == [("retire", 0)]


# ── S1 : imbrication, isolement de la surveillance ─────────────────────
def test_s1_candidats_tres_imbriques(tmp_path):
    c = tmp_path / "candidats.json"
    c.write_text('{"forme": 1, "genere_le": 1, "filtres": ' + "[" * 200000 + "]" * 200000 + "}")
    os.chmod(c, 0o640)
    with pytest.raises(F.CandidatsInvalides):
        F.lire_candidats(c)
    e = tmp_path / "etat.json"
    e.write_text("[" * 60000 + "]" * 60000)
    os.chmod(e, 0o640)
    assert F.lire_etat_collecteur(e) is None


def test_s1_retrait_d_office_independant_des_candidats(banc, monkeypatch):
    from test_apprentissage_3723 import _evt
    (f,) = _cands(1)
    _nuclei_dir(banc, [f])
    _passe(banc)
    _evt(banc.db, "192.168.1.20", famille="ia_filtres_critique", rule_id=f["id"])
    ordre = []
    vrai = apprentissage._surveiller

    async def surveiller(*a, **k):
        ordre.append("surveiller")
        return await vrai(*a, **k)

    def piege(*a, **k):
        ordre.append("candidats")
        raise RecursionError("piège")
    monkeypatch.setattr(apprentissage, "_surveiller", surveiller)
    monkeypatch.setattr(F, "lire_candidats", piege)
    _passe(banc)                                            # ne lève pas
    assert ordre == ["surveiller", "candidats"]
    assert banc.db.execute("SELECT etat FROM filtres").fetchone() == ("retire",)


# ── S2 : tube nommé, droits, propriétaire ──────────────────────────────
def test_s2_tube_nomme_refuse_sans_bloquer(tmp_path):
    c = tmp_path / "candidats.json"
    os.mkfifo(c, 0o640)
    debut = __import__("time").monotonic()
    with pytest.raises(F.CandidatsInvalides, match="ordinaire"):
        F.lire_candidats(c)
    assert __import__("time").monotonic() - debut < 2


def test_s2_inscriptible_par_le_groupe_refuse(tmp_path):
    c = tmp_path / "candidats.json"
    _ecrire(c, _cands(1))
    os.chmod(c, 0o660)
    with pytest.raises(F.CandidatsInvalides, match="inscriptible"):
        F.lire_candidats(c)


def test_s2_proprietaire_inattendu_refuse(tmp_path, monkeypatch):
    c = tmp_path / "candidats.json"
    _ecrire(c, _cands(1))
    monkeypatch.setattr(F, "_proprietaire_attendu", lambda: os.getuid() + 1)
    with pytest.raises(F.CandidatsInvalides, match="proprietaire"):
        F.lire_candidats(c)
    monkeypatch.setattr(F, "_proprietaire_attendu", lambda: None)          # compte absent : tout est refusé
    with pytest.raises(F.CandidatsInvalides):
        F.lire_candidats(c)


# ── S3 : compte dédié, profils, git durci ──────────────────────────────
def test_s3_compte_dedie_et_dossier():
    post = (PAQUET / "debian" / "postinst").read_text(encoding="utf-8")
    assert "adduser --system --ingroup secubox-ai --no-create-home --home /nonexistent \\\n        --shell " \
           "/usr/sbin/nologin secubox-ai-nuclei" in post
    assert "python3 -I - /var/lib/secubox ai secubox-ai secubox-ai secubox-ai-nuclei <<'DOSSIERS'" in post
    assert post.index("secubox-ai-nuclei >/dev/null") < post.index("<<'DOSSIERS'")
    assert F.COMPTE_COLLECTEUR == "secubox-ai-nuclei"


def test_s3_dossier_nuclei_au_compte_du_collecteur(tmp_path):
    import grp
    import pwd
    post = (PAQUET / "debian" / "postinst").read_text(encoding="utf-8")
    script = re.search(r"<<'DOSSIERS'(?:[^\n]*\\\n)*[^\n]*\n(.*?)\nDOSSIERS\n", post, re.S).group(1)
    compte = pwd.getpwuid(os.getuid()).pw_name
    groupe = grp.getgrgid(os.getgid()).gr_name
    r = subprocess.run([__import__("sys").executable, "-I", "-", str(tmp_path), "ai", compte, groupe, compte],
                       input=script, capture_output=True, text=True, timeout=30)
    assert r.returncode == 0, r.stderr
    assert (tmp_path / "ai" / "nuclei").stat().st_mode & 0o7777 == 0o750


def test_s3_profils_interdisent_l_ecriture_des_candidats():
    for profil in ("secubox-ai-api", "secubox-ai-veille"):
        texte = (PAQUET / "apparmor" / profil).read_text(encoding="utf-8")
        assert "  deny /var/lib/secubox/ai/nuclei/** w,\n" in texte, profil
    veille = (PAQUET / "apparmor" / "secubox-ai-veille").read_text(encoding="utf-8")
    assert "/etc/secubox/ai/filtres-refuses.txt r," in veille


def test_s3_git_durci():
    attendu = ["core.hooksPath=/dev/null", "core.fsmonitor=false", "protocol.allow=never",
               "protocol.https.allow=always", "transfer.fsckObjects=true", "core.symlinks=false"]
    assert list(F.GIT_OPTIONS) == [x for o in attendu for x in ("-c", o)]
    assert F.GIT_ENV == {"GIT_TERMINAL_PROMPT": "0", "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null"}
    u = _unite("secubox-ai-nuclei.service")
    assert {"GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_NOSYSTEM=1"} <= set(u["Environment"])


# ── S4 / S5 : erreurs dites ────────────────────────────────────────────
def test_s4_kev_en_panne_dite(tmp_path, caplog):
    conf, dossier, _, _, executer, telecharger = _collecteur(tmp_path)

    def kev_en_panne(url):
        if url == F.URL_KEV:
            raise httpx.ConnectError("non")
        return telecharger(url)
    with caplog.at_level("WARNING", logger="secubox-ai-nuclei"):
        assert F.tour_collecteur(dossier, str(conf), executer, kev_en_panne, T, libre=lambda: 1 << 40) == 0
    assert F.lire_etat_collecteur(dossier / "etat.json")["erreur"] == "kev"
    assert "KEV illisible" in caplog.text and "ConnectError" in caplog.text


def test_s4_noter_journalise_son_echec(tmp_path, caplog):
    with caplog.at_level("ERROR", logger="secubox-ai-nuclei"):
        F._noter(tmp_path / "absent" / "etat.json", T, True, {}, "x")
    assert "etat.json non écrit" in caplog.text


def test_s5_git_en_echec_journalise(tmp_path, caplog):
    def executer(argv, **kw):
        assert kw["check"] is True and kw["text"] is True
        raise subprocess.CalledProcessError(128, argv, "", "fatal: " + "x" * 5000)
    with caplog.at_level("WARNING", logger="secubox-ai-nuclei"):
        assert F.mettre_a_jour_depot(tmp_path / "depot", executer) is False
    assert "code 128" in caplog.text and "fatal" not in caplog.text[-10:] and len(caplog.text) < 1000


# ── Remarques : liens, redirections, réseau, dépôt trop gros ───────────
def test_r_http_en_lien_refuse(tmp_path):
    conf, dossier, cmds, _, executer, telecharger = _collecteur(tmp_path)
    ailleurs = tmp_path / "ailleurs"
    ailleurs.mkdir()
    (dossier / "depot").mkdir()
    (dossier / "depot" / "http").symlink_to(ailleurs)
    assert F.tour_collecteur(dossier, str(conf), executer, telecharger, T, libre=lambda: 1 << 40) == 1
    assert F.lire_etat_collecteur(dossier / "etat.json")["erreur"] == "depot_lien" and cmds == []
    assert F.collecter_nuclei(dossier / "depot") == []


def test_r_redirection_hors_https_refusee():
    def gk(req):
        if req.url.path == "/kev":
            return httpx.Response(302, headers={"location": "http://ailleurs.example/kev"})
        return httpx.Response(200, content=b"ok")
    t = httpx.MockTransport(gk)
    with pytest.raises(ValueError, match="https"):
        F.telecharger_defaut("https://cisa.example/kev", transport=t)
    assert F.telecharger_defaut("https://cisa.example/autre", transport=t) == b"ok"
    with pytest.raises(ValueError):
        F.telecharger_defaut("http://cisa.example/autre", transport=t)


def test_r_redirection_https_suivie():
    def gk(req):
        if req.url.path == "/a":
            return httpx.Response(301, headers={"location": "https://cdn.example/b"})
        return httpx.Response(200, content=b"fin")
    assert F.telecharger_defaut("https://cisa.example/a", transport=httpx.MockTransport(gk)) == b"fin"


def test_r_plages_privees_fermees():
    u = _unite("secubox-ai-nuclei.service")
    deny = u["IPAddressDeny"][0].split()
    for plage in ("link-local", "multicast", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10"):
        assert plage in deny, plage
    assert u["IPAddressAllow"] == ["127.0.0.1/32"]


def test_r_depot_trop_gros_supprime(tmp_path, monkeypatch):
    monkeypatch.setattr(F, "DEPOT_MAX_OCTETS", 100)
    conf, dossier, _, _, executer, telecharger = _collecteur(tmp_path)
    assert F.tour_collecteur(dossier, str(conf), executer, telecharger, T, libre=lambda: 1 << 40) == 1
    assert not (dossier / "depot").exists()


from test_aictl_3583 import ctl, env  # noqa: E402,F401,F811  (fixtures du contrôleur)


def test_r_preparer_rouvre_les_resolveurs_prives_au_collecteur(ctl, env, monkeypatch):  # noqa: F811
    env.conf.write_text('[gk2]\nmenaces_url = "https://admin.gk2.secubox.in/api/v1"\n')
    env.conf.chmod(0o644)
    (env.tmp / "resolv.conf").write_text("nameserver 192.168.1.200\nnameserver 127.0.0.1\n")
    monkeypatch.setattr(ctl, "resoudre", lambda h: {"192.168.1.20"})
    assert ctl.cmd_preparer() == 0
    texte = (ctl.dossier_dropin_nuclei() / "50-adresses.conf").read_text()
    assert [x for x in texte.splitlines() if x.startswith("IPAddress")] == ["IPAddressAllow=192.168.1.200/32"]
    assert ctl.texte_dropin_nuclei([]).count("IPAddressAllow") == 0


# ── J1–J4 ──────────────────────────────────────────────────────────────
def test_j1_version_perdue_repart(banc):
    (f,) = _cands(1)
    _nuclei_dir(banc, [dict(f, version=2)])
    banc.transport.couper = "apres"
    _passe(banc)
    banc.transport.couper = None
    banc.gk2.filtres[f["id"]] = dict(f, version=1)          # gk2 n'a gardé que l'ancienne version
    _passe(banc, maintenant=_maintenant() + timedelta(minutes=5))
    assert banc.db.execute("SELECT etat, motif FROM filtres").fetchall() == [("echec", "absent_apres_envoi")]
    _passe(banc, maintenant=_maintenant() + timedelta(hours=25))       # réessai d'une erreur après 24 h
    assert len(_posts(banc)) == 2 and banc.gk2.filtres[f["id"]]["version"] == 2


def test_j3_candidats_perimes_aucun_envoi(banc):
    d = _nuclei_dir(banc, _cands(2))
    _ecrire(d / "candidats.json", _cands(2), genere_le=__import__("time").time() - 49 * 3600)
    _passe(banc)
    assert _posts(banc) == [] and _etat_tour(banc)["perime"] is True
    _ecrire(d / "candidats.json", _cands(2))
    _passe(banc)
    assert len(_posts(banc)) == 1 and _etat_tour(banc)["perime"] is False


def test_j4_candidats_absents_un_seul_avertissement(banc, caplog):
    d = _nuclei_dir(banc, _cands(2))
    (d / "candidats.json").unlink()
    with caplog.at_level("WARNING", logger="secubox-ai-veille"):
        for i in range(3):
            _passe(banc, maintenant=_maintenant() + timedelta(minutes=5 * i))
    assert caplog.text.count("candidats.json refusé") == 1
