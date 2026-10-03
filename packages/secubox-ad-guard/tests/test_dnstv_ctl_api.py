# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""POC « DNS AdBlock TV » (#1943) : contrôleur root (secubox-adguard-tv) et routes /adblock-tv. Unbound simulé par deux petits scripts."""
import importlib.machinery
import importlib.util
import json
import os
import stat
import time
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from api import dnstv

ICI = Path(__file__).resolve().parents[1]
LISTES = ICI / "lists"
CTL = ICI / "sbin" / "secubox-adguard-tv"


def _script(chemin, corps):
    chemin.write_text("#!/bin/sh\n" + corps)
    chemin.chmod(chemin.stat().st_mode | stat.S_IXUSR)
    return chemin


@pytest.fixture
def monde(tmp_path, monkeypatch):
    etat = tmp_path / "etat"
    etat.mkdir()
    journal = tmp_path / "appels.log"
    checkconf = _script(tmp_path / "checkconf", f'echo checkconf >> {journal}; [ -f {tmp_path}/refuse ] && {{ echo "erreur de syntaxe" >&2; exit 1; }}; exit 0\n')
    control = _script(tmp_path / "control", f'echo "control $*" >> {journal}\nexit 0\n')
    conf = tmp_path / "unbound.d" / "94-secubox-adguard-tv.conf"
    for k, v in {"SECUBOX_ADGUARD_TV_ETAT": etat, "SECUBOX_ADGUARD_TV_LISTES": LISTES, "SECUBOX_ADGUARD_TV_UNBOUND": conf,
                 "SECUBOX_ADGUARD_TV_CHECKCONF": checkconf, "SECUBOX_ADGUARD_TV_CONTROL": control,
                 "SECUBOX_ADGUARD_TV_AUDIT": tmp_path / "audit.log", "SECUBOX_ADGUARD_TV_SANS_ROOT": "1"}.items():
        monkeypatch.setenv(k, str(v))
    monkeypatch.setattr(dnstv, "DOSSIER_ETAT", etat)
    monkeypatch.setattr(dnstv, "DOSSIER_LISTES", LISTES)
    monkeypatch.setattr(dnstv, "CONF_UNBOUND", conf)
    return {"etat": etat, "conf": conf, "journal": journal, "tmp": tmp_path}


def ctl(monde, action):
    loader = importlib.machinery.SourceFileLoader("tv_ctl", str(CTL))
    spec = importlib.util.spec_from_loader("tv_ctl", loader)
    m = importlib.util.module_from_spec(spec)
    loader.exec_module(m)
    return m.main(["secubox-adguard-tv", action])


def declarer(monde, mode="observe", actif=True, ip="192.168.1.50"):
    dnstv.ecrire_etat({"actif": actif, "clients": [{"ip": ip, "nom": "Freebox TV", "mode": mode}]}, monde["etat"])


# ── contrôleur ───────────────────────────────────────────────────────────────
def test_apply_ecrit_verifie_puis_recharge_dans_cet_ordre(monde, capsys):
    declarer(monde, "block")
    assert ctl(monde, "apply") == 0
    c = monde["conf"].read_text()
    assert "access-control-view: 192.168.1.50/32 sbx-tv-block" in c and 'local-zone: "doubleclick.net." always_nxdomain' in c
    assert monde["journal"].read_text().split() == ["checkconf", "control", "reload"]
    assert json.loads(capsys.readouterr().out)["domaines"] >= 30


def test_apply_inclut_la_liste_personnalisee_de_l_exploitant(monde):
    declarer(monde, "block")
    (monde["etat"] / "custom.txt").write_text("# mes ajouts\nmon-tracker.example\n!!!pas un nom!!!\nunnom.example # note\n")
    ctl(monde, "apply")
    c = monde["conf"].read_text()
    assert 'local-zone: "mon-tracker.example." always_nxdomain' in c and 'local-zone: "unnom.example."' in c and "pas un nom" not in c


def test_apply_refuse_par_unbound_checkconf_remet_la_version_precedente_et_ne_recharge_pas(monde):
    declarer(monde, "observe")
    ctl(monde, "apply")
    avant = monde["conf"].read_text()
    (monde["tmp"] / "refuse").write_text("")
    declarer(monde, "block")
    with pytest.raises(SystemExit) as e:
        ctl(monde, "apply")
    assert "refuse la configuration" in str(e.value) and monde["conf"].read_text() == avant
    assert monde["journal"].read_text().count("reload") == 1            # le premier apply seulement


def test_un_etat_invalide_ne_change_rien(monde):
    declarer(monde, "observe")
    ctl(monde, "apply")
    avant = monde["conf"].read_text()
    (monde["etat"] / "etat.json").write_text('{"actif": true, "clients": [{"ip": "1.2.3.4\\nserver:", "mode": "block"}]}')
    with pytest.raises(SystemExit) as e:
        ctl(monde, "apply")
    assert "rien n'est changé" in str(e.value) and monde["conf"].read_text() == avant


def test_un_lien_symbolique_a_la_place_de_l_etat_ou_de_la_liste_est_refuse(monde):
    secret = monde["tmp"] / "secret"
    secret.write_text('{"actif": true}')
    (monde["etat"] / "etat.json").symlink_to(secret)
    with pytest.raises(SystemExit):
        ctl(monde, "apply")
    (monde["etat"] / "etat.json").unlink()
    declarer(monde, "block")
    (monde["etat"] / "custom.txt").symlink_to(secret)
    with pytest.raises(SystemExit) as e:
        ctl(monde, "apply")
    assert "lien symbolique" in str(e.value) and not monde["conf"].exists()


def test_disable_retire_le_dropin_et_recharge_et_est_idempotent(monde):
    declarer(monde, "block")
    ctl(monde, "apply")
    assert ctl(monde, "disable") == 0 and not monde["conf"].exists()
    avant = monde["journal"].read_text().count("reload")
    assert ctl(monde, "disable") == 0 and monde["journal"].read_text().count("reload") == avant      # rien à retirer : pas de rechargement


def test_les_decisions_sont_auditees_sans_secret(monde):
    declarer(monde, "block")
    ctl(monde, "apply")
    ctl(monde, "disable")
    lignes = [json.loads(ligne) for ligne in (monde["tmp"] / "audit.log").read_text().splitlines()]
    assert [x["action"] for x in lignes] == ["apply", "disable"] and all(x["module"] == "ad-guard-tv" for x in lignes)


def test_le_controleur_exige_root_et_une_seule_action(monde, monkeypatch):
    monkeypatch.delenv("SECUBOX_ADGUARD_TV_SANS_ROOT")
    if os.geteuid() != 0:
        assert ctl(monde, "apply") == 3
    assert ctl(monde, "n-importe-quoi") == 2


# ── API ──────────────────────────────────────────────────────────────────────
@pytest.fixture
def api(monde, monkeypatch):
    from secubox_core import auth
    from api import dnstv_routes as r
    # Le « sudo » de l'API est remplacé par un appel direct au contrôleur (même code, même validation).
    def appel(action):
        import io
        from contextlib import redirect_stdout
        tampon = io.StringIO()
        with redirect_stdout(tampon):
            ctl(monde, action)
        return json.loads(tampon.getvalue() or "{}")
    monkeypatch.setattr(r, "_ctl", appel)
    app = FastAPI()
    app.include_router(r.router)
    app.dependency_overrides[auth.require_jwt] = lambda: {"sub": "admin"}
    app.dependency_overrides[auth.require_lecture] = lambda: {"sub": "admin"}
    return TestClient(app)


def test_activer_declarer_un_appareil_et_basculer_observe_block_dynamiquement(api, monde):
    assert api.get("/adblock-tv/status").json()["actif"] is False
    assert api.post("/adblock-tv/clients", json={"ip": "192.168.1.50", "nom": "Freebox TV salon", "mode": "observe"}).status_code == 200
    assert api.post("/adblock-tv/etat", json={"actif": True}).json()["application"]["ok"] is True
    assert "sbx-tv-observe" in monde["conf"].read_text() and "always_nxdomain" in monde["conf"].read_text()   # zones seulement dans la vue block
    r = api.post("/adblock-tv/mode", json={"mode": "block", "ip": "192.168.1.50"})
    assert r.status_code == 200 and r.json()["etat"]["clients"][0]["mode"] == "block"
    assert "access-control-view: 192.168.1.50/32 sbx-tv-block" in monde["conf"].read_text()
    assert api.post("/adblock-tv/mode", json={"mode": "observe"}).json()["etat"]["clients"][0]["mode"] == "observe"      # « tous »
    assert "access-control-view: 192.168.1.50/32 sbx-tv-observe" in monde["conf"].read_text()


def test_le_poc_se_desactive_et_se_retire_sans_trace(api, monde):
    api.post("/adblock-tv/clients", json={"ip": "192.168.1.50", "mode": "block"})
    api.post("/adblock-tv/etat", json={"actif": True})
    api.post("/adblock-tv/etat", json={"actif": False})
    assert "access-control-view" not in monde["conf"].read_text()                   # actif=false : plus aucune vue
    assert api.delete("/adblock-tv/clients/192.168.1.50").status_code == 200
    assert api.delete("/adblock-tv/clients/192.168.1.50").status_code == 404


def test_entrees_invalides_refusees(api):
    assert api.post("/adblock-tv/clients", json={"ip": "pas-une-ip", "mode": "block"}).status_code == 422
    assert api.post("/adblock-tv/clients", json={"ip": "192.168.1.50", "mode": "destruction"}).status_code == 422
    assert api.post("/adblock-tv/clients", json={"ip": "192.168.1.50", "nom": "x\nserver:", "mode": "block"}).status_code == 422
    assert api.post("/adblock-tv/mode", json={"mode": "block"}).status_code == 404            # aucun appareil déclaré
    assert api.post("/adblock-tv/mode", json={"mode": "inconnu"}).status_code == 422
    assert api.post("/adblock-tv/custom", json={"domaine": "http://x.com/chemin"}).status_code == 422
    assert api.get("/adblock-tv/stats?client=nimporte").status_code == 422


def test_liste_personnalisee_ajout_lecture_suppression(api, monde):
    api.post("/adblock-tv/clients", json={"ip": "192.168.1.50", "mode": "block"})
    api.post("/adblock-tv/etat", json={"actif": True})
    r = api.post("/adblock-tv/custom", json={"domaine": "Mon-Tracker.Example."})
    assert r.status_code == 200 and r.json()["domaine"] == "mon-tracker.example"
    assert 'local-zone: "mon-tracker.example." always_nxdomain' in monde["conf"].read_text()
    assert api.get("/adblock-tv/custom").json()["domaines"] == ["mon-tracker.example"]
    assert api.delete("/adblock-tv/custom/mon-tracker.example").status_code == 200
    assert "mon-tracker.example" not in monde["conf"].read_text() and api.get("/adblock-tv/custom").json()["domaines"] == []
    assert api.delete("/adblock-tv/custom/inconnu.example").status_code == 404


def test_un_etat_corrompu_est_signale_409_et_n_est_pas_devine(api, monde):
    (monde["etat"] / "etat.json").write_text("{ casse")
    assert api.get("/adblock-tv/status").json()["erreur"] and api.post("/adblock-tv/etat", json={"actif": True}).status_code == 409


def test_statistiques_top_et_formulation_honnete(api, monde):
    m = dnstv.Magasin(monde["etat"] / "dnstv.db")
    an = dnstv.Analyseur()
    cl = dnstv.Classifieur(dnstv.charger_listes(LISTES))
    maintenant = int(time.time())
    evts = []
    for _ in range(3):
        for ligne in ("info: doubleclick.net. always_nxdomain 192.168.1.50@5 doubleclick.net. A IN",
                      f"[{maintenant}] unbound[1:0] reply: 192.168.1.50 doubleclick.net. A IN NXDOMAIN 0 0 3"):
            e = an.ligne(ligne)
            if e:
                evts.append((e, cl.classer(e.qname)[0]))
    e = an.ligne(f"[{maintenant}] unbound[1:0] reply: 192.168.1.50 google-analytics.com. A IN NOERROR 0.01 0 40")
    evts.append((e, cl.classer(e.qname)[0]))
    m.ajouter(evts)
    s = api.get("/adblock-tv/stats").json()
    assert s["requetes"] == 4 and s["domaines_uniques"] == 2 and s["classes_bloques"] == {"advertising": 3} and s["classes_resolus"] == {"tracking": 1}
    assert s["top_bloques"][0] == {"domaine": "doubleclick.net", "categorie": "advertising", "hits": 3}
    assert "n'est pas une suppression de publicités" in s["formulation"]
    assert api.get("/adblock-tv/clients/vus").json()["clients"][0]["client"] == "192.168.1.50"
    assert api.get("/adblock-tv/status").json()["compteurs"]["bloques"] == 3


def test_dns_path_test_recue_ou_pas(api, monde):
    nom = api.post("/adblock-tv/sonde").json()["nom"]
    assert nom.endswith(".sbx-dnspath.invalid")
    assert api.get(f"/adblock-tv/path-test?nom={nom}").json()["recue"] is False                 # personne n'a interrogé
    m = dnstv.Magasin(monde["etat"] / "dnstv.db")
    e = dnstv.Analyseur().ligne(f"[{int(time.time())}] unbound[1:0] reply: 192.168.1.50 {nom}. A IN NXDOMAIN 0 0 3")
    m.ajouter([(e, None)])
    r = api.get(f"/adblock-tv/path-test?nom={nom}").json()
    assert r["recue"] is True and r["evenements"][0]["client"] == "192.168.1.50" and "utilise bien son DNS" in r["lecture"]
    assert api.get("/adblock-tv/path-test?ip=192.168.1.50").json()["recue"] is True
    assert api.get("/adblock-tv/path-test?ip=192.168.1.99").json()["recue"] is False
    assert api.get("/adblock-tv/path-test?nom=evil.example.com").status_code == 422
    assert api.get("/adblock-tv/path-test").status_code == 422


def test_bypass_liste_les_silencieux_et_les_limites_sont_documentees(api, monde, monkeypatch):
    from api import dnstv_routes as r

    class Rep:
        stdout = json.dumps([{"dst": "192.168.1.60", "lladdr": "aa:bb:cc:dd:ee:ff", "state": ["REACHABLE"]},
                             {"dst": "192.168.1.61", "lladdr": "aa:bb:cc:dd:ee:00", "state": ["STALE"]},
                             {"dst": "fe80::1", "lladdr": "aa:bb:cc:dd:ee:11", "state": ["REACHABLE"]},
                             {"dst": "192.168.1.62", "state": ["FAILED"]}])
    monkeypatch.setattr(r.subprocess, "run", lambda *a, **k: Rep())
    e = dnstv.Analyseur().ligne(f"[{int(time.time())}] unbound[1:0] reply: 192.168.1.60 x.example. A IN NOERROR 0 0 3")
    dnstv.Magasin(monde["etat"] / "dnstv.db").ajouter([(e, None)])
    b = api.get("/adblock-tv/bypass").json()
    assert [s["ip"] for s in b["silencieux"]] == ["192.168.1.61"]                     # .60 parle à la box, fe80 ignoré, .62 injoignable
    assert "limite" in b
    ids = [x["id"] for x in api.get("/adblock-tv/limites").json()["limites"]]
    assert ids == list("ABCDEFG")


def test_les_routes_d_action_exigent_le_jeton(monde):
    """Sans surcharge de dépendance, les routes d'ÉCRITURE sont refusées sans jeton."""
    from api import dnstv_routes as r
    app = FastAPI()
    app.include_router(r.router)
    c = TestClient(app)
    for methode, chemin, corps in (("post", "/adblock-tv/etat", {"actif": True}), ("post", "/adblock-tv/mode", {"mode": "block"}),
                                   ("post", "/adblock-tv/clients", {"ip": "1.2.3.4"}), ("post", "/adblock-tv/custom", {"domaine": "x.example.com"}),
                                   ("delete", "/adblock-tv/custom/x.example.com", None), ("post", "/adblock-tv/sonde", None)):
        rep = getattr(c, methode)(chemin, **({"json": corps} if corps is not None else {}))
        assert rep.status_code in (401, 403), (chemin, rep.status_code)


def test_export_donne_les_compteurs_d_un_appareil_pour_comparer_deux_instants(api, monde):
    m = dnstv.Magasin(monde["etat"] / "dnstv.db")
    an = dnstv.Analyseur()
    m.ajouter([(an.ligne(f"[{int(time.time())}] unbound[1:0] reply: 192.168.1.50 ads.example. A IN NOERROR 0 0 3"), "advertising"),
               (an.ligne(f"[{int(time.time())}] unbound[1:0] reply: 192.168.1.51 autre.example. A IN NOERROR 0 0 3"), None)])
    r = api.get("/adblock-tv/export?client=192.168.1.50").json()
    assert r["client"] == "192.168.1.50" and r["lignes"] == [{"domaine": "ads.example", "categorie": "advertising", "decision": "ALLOWED", "hits": 1}]
    assert len(api.get("/adblock-tv/export").json()["lignes"]) == 2
    assert api.get("/adblock-tv/export?client=pas-une-ip").status_code == 422
