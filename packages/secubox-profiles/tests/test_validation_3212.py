# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3212 — relevé de validation d'une box : profil attendu, paquet, services, ressources.

Échantillons pris sur gk2 le 2026-10-27 (dpkg-query, .list, systemctl show, /health de l'agrégateur)."""
import json

import pytest

from api import validation as v

TAB = "\t"
DPKG = "\n".join([
    TAB.join(["secubox-full", "1.8.0-1~trixie1", "ii ", "secubox-isp (>= 1.5.0), secubox-gitea", "secubox-voicestudio"]),
    TAB.join(["secubox-isp", "1.5.0-1~trixie1", "ii ", "${misc:Depends}, secubox-lite (>= 1.5.0), secubox-p2p (>= 1.12.0)",
              "wireguard-tools"]),
    TAB.join(["secubox-lite", "1.8.1-1~trixie1", "ii ", "secubox-dns, secubox-hardening (>= 1.0), secubox-absent-x",
              "secubox-sentinelle-gsm"]),
    TAB.join(["secubox-minimal", "0.5.1-1~trixie1", "un ", "", ""]),
    TAB.join(["secubox-dns", "1.6.3-1~trixie1", "ii ", "secubox-core (>= 1.7.0), python3-httpx | python3-pip", "systemd"]),
    TAB.join(["secubox-hardening", "1.6.3-1~trixie1", "iF ", "secubox-core", ""]),
    TAB.join(["secubox-p2p", "1.19.2-1~trixie1", "ii ", "secubox-core", ""]),
    TAB.join(["secubox-core", "1.7.20-1~trixie1", "ii ", "python3", ""]),
    TAB.join(["secubox-gitea", "1.3.0-1~trixie1", "ii ", "secubox-core", ""]),
    TAB.join(["secubox-lyrion", "1.7.2-1~trixie1", "ii ", "secubox-core", ""]),
    TAB.join(["secubox-vieux", "0.1.0-1~trixie1", "rc ", "", ""]),
    TAB.join(["secubox-voicestudio", "", "un ", "", ""]),
]) + "\n"

LISTES = {
    "secubox-dns": "/.\n/usr\n/usr/lib/secubox\n/usr/lib/secubox/dns-provider\n/usr/lib/secubox/dns-provider/api\n"
                   "/usr/lib/systemd/system/secubox-dns-provider.service\n/usr/lib/systemd/system/secubox-dns.service\n",
    "secubox-p2p": "/lib/systemd/system/secubox-relais-maillage.service\n/lib/systemd/system/secubox-relais-maillage.timer\n"
                   "/lib/systemd/system/secubox-p2p-mesh@.service\n/usr/lib/systemd/system/secubox-p2p.service\n"
                   "/usr/lib/secubox/p2p\n",
    "secubox-gitea": "/usr/lib/systemd/system/secubox-gitea.service\n",
    "secubox-lyrion": "/usr/lib/systemd/system/secubox-lyrion.service\n",
    "secubox-hardening": "/usr/lib/systemd/system/secubox-hardening.service\n",
}

SHOW = """Id=secubox-dns-provider.service
ActiveState=inactive
SubState=dead
UnitFileState=disabled
Result=success
TriggeredBy=
MemoryCurrent=[not set]
CPUUsageNSec=[not set]

Id=secubox-dns.service
ActiveState=failed
SubState=failed
UnitFileState=enabled
Result=exit-code
TriggeredBy=
MemoryCurrent=[not set]
CPUUsageNSec=1000

Id=secubox-relais-maillage.service
ActiveState=inactive
SubState=dead
UnitFileState=static
Result=success
TriggeredBy=secubox-relais-maillage.timer
MemoryCurrent=[not set]
CPUUsageNSec=217830000

Id=secubox-relais-maillage.timer
ActiveState=active
SubState=waiting
UnitFileState=enabled
Result=success
TriggeredBy=

Id=secubox-p2p.service
ActiveState=active
SubState=running
UnitFileState=enabled
Result=success
TriggeredBy=
MemoryCurrent=52428800
CPUUsageNSec=9000000000

Id=secubox-gitea.service
ActiveState=inactive
SubState=dead
UnitFileState=enabled
Result=success
TriggeredBy=
MemoryCurrent=[not set]
CPUUsageNSec=[not set]

Id=secubox-lyrion.service
ActiveState=inactive
SubState=dead
UnitFileState=enabled
Result=success
TriggeredBy=
MemoryCurrent=[not set]
CPUUsageNSec=[not set]

Id=secubox-hardening.service
ActiveState=active
SubState=running
UnitFileState=enabled
Result=success
TriggeredBy=
MemoryCurrent=18446744073709551615
CPUUsageNSec=5000
"""

SANTE = {"status": "ok", "mounted": ["dns-provider", "dns", "p2p"],
         "failed": {"c3box": "main.py not found", "hardening": "exec_module: ImportError: x" * 30}}


# ── analyses pures ───────────────────────────────────────────────────────────

def test_lire_dpkg():
    p = v.lire_dpkg(DPKG)
    assert p["secubox-dns"]["version"] == "1.6.3-1~trixie1" and p["secubox-dns"]["statut"] == "ii"
    assert p["secubox-dns"]["depends"] == ["secubox-core", "python3-httpx"]          # première alternative
    assert p["secubox-isp"]["depends"] == ["secubox-lite", "secubox-p2p"]            # ${misc:Depends} écarté
    assert p["secubox-hardening"]["statut"] == "iF" and p["secubox-vieux"]["statut"] == "rc"


def test_attendus_ferme_les_depends_du_profil_le_plus_haut():
    a = v.attendus(v.lire_dpkg(DPKG))
    assert a["profil_actif"] == "full" and a["profils_installes"] == ["lite", "isp", "full"]
    assert {"secubox-isp", "secubox-lite", "secubox-gitea", "secubox-dns", "secubox-hardening", "secubox-p2p",
            "secubox-core", "secubox-absent-x"} <= a["attendus"]
    assert "python3-httpx" not in a["attendus"]                                       # hors SecuBox
    assert a["recommandes"] == {"secubox-voicestudio", "secubox-sentinelle-gsm"}


def test_aucun_profil_installe():
    a = v.attendus(v.lire_dpkg(TAB.join(["secubox-core", "1.0", "ii ", "", ""]) + "\n"))
    assert a["profil_actif"] is None and a["attendus"] == set() and a["profils_installes"] == []


def test_unites_et_modules_d_un_paquet():
    unites, modules = v.unites_et_modules(LISTES["secubox-p2p"])
    assert unites == ["secubox-p2p.service", "secubox-relais-maillage.service", "secubox-relais-maillage.timer"]
    assert modules == ["p2p"]                                                         # sans gabarit @
    assert v.unites_et_modules(LISTES["secubox-dns"])[1] == ["dns-provider"]


def test_lire_show_par_unite():
    s = v.lire_show(SHOW)
    assert s["secubox-p2p.service"]["MemoryCurrent"] == "52428800"
    assert s["secubox-relais-maillage.service"]["TriggeredBy"] == "secubox-relais-maillage.timer"


@pytest.mark.parametrize("props,sommeil,attendu", [
    ({"ActiveState": "failed"}, False, "erreur"),
    ({"ActiveState": "active"}, False, "actif"),
    ({"ActiveState": "activating"}, False, "actif"),
    ({"ActiveState": "inactive", "TriggeredBy": "x.timer", "UnitFileState": "static"}, False, "declenche"),
    ({"ActiveState": "inactive", "TriggeredBy": "", "UnitFileState": "disabled"}, False, "non_requis"),
    ({"ActiveState": "inactive", "TriggeredBy": "", "UnitFileState": "static"}, False, "non_requis"),
    ({"ActiveState": "inactive", "TriggeredBy": "", "UnitFileState": "enabled"}, True, "veille"),
    ({"ActiveState": "inactive", "TriggeredBy": "", "UnitFileState": "enabled"}, False, "arrete"),
    # Vu sur gk2 : condition de démarrage non remplie (zigbee sans clé, premier-pas déjà fait) → pas « arrêté »
    ({"ActiveState": "inactive", "UnitFileState": "enabled", "ConditionResult": "no", "Type": "simple"}, False, "non_requis"),
    # oneshot terminé avec succès (secubox-actord-ingest, provisionnements) : état normal
    ({"ActiveState": "inactive", "UnitFileState": "enabled", "ConditionResult": "yes", "Type": "oneshot",
      "Result": "success"}, False, "termine"),
    ({"ActiveState": "inactive", "UnitFileState": "enabled", "ConditionResult": "yes", "Type": "oneshot",
      "Result": "exit-code"}, False, "arrete"),
    (None, False, "inconnu"),
    ({"ActiveState": ""}, False, "inconnu"),
])
def test_etat_unite(props, sommeil, attendu):
    assert v.etat_unite(props, sommeil) == attendu


# ── collecte complète (sondes simulées) ──────────────────────────────────────

def _collecter(sante=SANTE, precedent=None, dpkg=DPKG, show=SHOW, cycles=None):
    def executer(argv):
        if argv[0] == "dpkg-query":
            return (0, dpkg) if dpkg is not None else (2, "")
        if argv[0] == "systemctl":
            return (0, show) if show is not None else (1, "")
        raise AssertionError(argv)
    return v.collecter(executer=executer, lire_liste=lambda p: LISTES.get(p, ""), sante_agregateur=lambda: sante,
                       cycles=cycles if cycles is not None else {"lyrion": "on-demand"}, precedent=precedent,
                       hostname="gk2", maintenant=1000.0)


def _ligne(r, paquet):
    return next(x for x in r["paquets"] if x["paquet"] == paquet)


def test_collecte_les_quatre_niveaux():
    r = _collecter()
    assert r["hostname"] == "gk2" and r["profil_actif"] == "full" and r["partiel"] == []
    p2p = _ligne(r, "secubox-p2p")
    assert (p2p["etat"], p2p["attendu"], p2p["version"], p2p["memoire_o"]) == ("fonctionnel", True, "1.19.2-1~trixie1", 52428800)
    assert [u["etat"] for u in p2p["unites"]] == ["actif", "declenche", "actif"]


def test_servi_par_l_agregateur_malgre_une_unite_desactivee():
    """dns-provider : unité désactivée, module monté dans l'agrégateur → pas « arrêté »."""
    r = _collecter(show=SHOW.replace("ActiveState=failed\nSubState=failed", "ActiveState=inactive\nSubState=dead")
                   .replace("UnitFileState=enabled\nResult=exit-code", "UnitFileState=disabled\nResult=success"))
    dns = _ligne(r, "secubox-dns")
    assert dns["etat"] == "fonctionnel" and dns["agregateur"] == [{"module": "dns-provider", "etat": "actif"}]


def test_unite_en_echec_et_paquet_inacheve_sont_des_erreurs():
    r = _collecter()
    dns = _ligne(r, "secubox-dns")
    assert dns["etat"] == "erreur" and any("secubox-dns.service" in e and "exit-code" in e for e in dns["erreurs"])
    hard = _ligne(r, "secubox-hardening")
    assert hard["etat"] == "erreur" and any("iF" in e for e in hard["erreurs"])
    assert hard["memoire_o"] is None                                                  # « infini » = non mesuré


def test_arrete_veille_manquant_absent_hors_profil():
    r = _collecter()
    assert _ligne(r, "secubox-gitea")["etat"] == "arrete"
    assert _ligne(r, "secubox-lyrion")["etat"] == "veille" and _ligne(r, "secubox-lyrion")["hors_profil"] is True
    manque = _ligne(r, "secubox-absent-x")
    assert (manque["etat"], manque["installe"], manque["version"]) == ("manquant", False, None)
    assert "secubox-vieux" not in [x["paquet"] for x in r["paquets"]]                 # rc : ni installé ni attendu
    voice = [x for x in r["paquets"] if x["paquet"] == "secubox-voicestudio"]
    assert not voice                                                                  # recommandé absent : pas une ligne
    assert _ligne(r, "secubox-full")["meta"] is True and _ligne(r, "secubox-full")["hors_profil"] is False


def test_echec_de_l_agregateur_borne_et_rattache_a_son_paquet():
    r = _collecter(sante={"mounted": [], "failed": {"p2p": "exec_module: " + "x" * 500}})
    p2p = _ligne(r, "secubox-p2p")
    assert p2p["etat"] == "erreur" and p2p["agregateur"][0]["etat"] == "erreur"
    assert all(len(e) <= v.MAX_TEXTE for e in p2p["erreurs"])


def test_cpu_par_difference_avec_le_releve_precedent():
    """p2p cumule 9 217 830 000 ns (service + relais) ; 5 s de plus qu'au relevé d'il y a 100 s → 5 % d'un cœur."""
    prec = {"releve_epoch": 900.0, "paquets": [{"paquet": "secubox-p2p", "cpu_ns": 9_217_830_000 - 5_000_000_000}]}
    r = _collecter(precedent=prec)
    assert _ligne(r, "secubox-p2p")["cpu_pct"] == 5.0
    assert _ligne(r, "secubox-gitea")["cpu_pct"] is None


def test_releve_partiel_annonce_jamais_de_faux_absent():
    r = _collecter(sante=None, show=None)
    assert "agrégateur injoignable" in r["partiel"] and "systemctl indisponible" in r["partiel"]
    assert _ligne(r, "secubox-p2p")["etat"] == "inconnu"
    r = _collecter(dpkg=None)
    assert "dpkg illisible" in r["partiel"] and r["paquets"] == []


def test_bornes(monkeypatch):
    monkeypatch.setattr(v, "MAX_PAQUETS", 3)
    assert len(_collecter()["paquets"]) == 3


def test_ecriture_atomique_et_relecture(tmp_path):
    chemin = tmp_path / "validation.json"
    r = _collecter()
    v.ecrire(r, chemin)
    assert v.lire(chemin) == json.loads(json.dumps(r)) and not list(tmp_path.glob("*.tmp"))
    chemin.write_text("{pas du json")
    assert v.lire(chemin) is None


# ── route et CLI ─────────────────────────────────────────────────────────────

@pytest.fixture()
def client(tmp_path, monkeypatch):
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "common"))
    from fastapi.testclient import TestClient
    import api.web as web
    monkeypatch.setenv("SECUBOX_PROFILS_VALIDATION", str(tmp_path / "releve.json"))
    app = web.create_app()
    app.dependency_overrides[web.require_lecture] = lambda: {"sub": "admin"}
    return TestClient(app), tmp_path


def test_route_rend_le_releve_de_la_box(client):
    c, d = client
    r = _collecter()
    v.ecrire(r, d / "releve.json")
    rep = c.get("/api/v1/profiles/validation")
    assert rep.status_code == 200 and rep.json()["hostname"] == "gk2" and len(rep.json()["paquets"]) == len(r["paquets"])


def test_route_sans_releve_503(client):
    c, _ = client
    rep = c.get("/api/v1/profiles/validation")
    assert rep.status_code == 503 and "relevé" in rep.json()["detail"]


def test_route_gardee():
    import api.web as web
    route = next(r for r in web.create_app().routes if getattr(r, "path", "") == "/api/v1/profiles/validation")
    assert any(d.call is web.require_lecture for d in route.dependant.dependencies)


def test_cli_releve_resume_json(monkeypatch, capsys, tmp_path):
    from api import cli
    monkeypatch.setenv("SECUBOX_PROFILS_VALIDATION", str(tmp_path / "releve.json"))
    vus = {}

    def faux(racine, chemin):
        vus.update(racine=str(racine), chemin=str(chemin))
        return _collecter()
    monkeypatch.setattr(v, "releve", faux)
    assert cli.main(["--root", str(tmp_path), "releve", "--json"]) == 0
    resume = json.loads(capsys.readouterr().out)
    assert resume["paquets"] == len(_collecter()["paquets"]) and resume["partiel"] == []
    assert resume["etats"]["erreur"] >= 1 and vus == {"racine": str(tmp_path), "chemin": str(tmp_path / "releve.json")}
