# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#1965 : autorisations par appareil — exceptions au puits complet par `local-zone-override` (replay RMC bloqué par licensing.bitmovin.com)."""
import time

import pytest

from api import dnstv
from test_dnstv_ajout_moteur import charger_ctl, faux  # noqa: F401
from test_dnstv_detection_routes import donnees, etat_disque, faux_api  # noqa: F401  (fixtures)
from test_dnstv_ctl_api import api, ctl, monde  # noqa: F401  (fixtures)

BITMOVIN = "licensing.bitmovin.com"
V6 = "2a01:e0a:dec:c4e0:c147:c3cf:6dd7:3429"


def etat(**kw):
    base = {"actif": True, "clients": [{"ip": "192.168.1.95", "nom": "TV banc", "mode": "auto"}, {"ip": V6, "nom": "TV banc", "mode": "auto"}],
            "autorisations": {"tv-banc": [BITMOVIN]}}
    base.update(kw)
    return base


def serveur(sortie):
    return sortie.split("\nview:")[0]


def test_l_etat_valide_normalise_et_n_emet_rien_par_defaut():
    e = dnstv.valider_etat(etat(autorisations={"tv-banc": [BITMOVIN, "a.example.com", BITMOVIN]}))
    assert e["autorisations"] == {"tv-banc": ["a.example.com", BITMOVIN]}
    assert "autorisations" not in dnstv.valider_etat({"actif": True, "clients": []})              # les anciens états gardent leur format


def test_autorisations_hostiles_refusees():
    for mauvais in ("pas un dict", {"TV banc": [BITMOVIN]}, {"tv-banc": "x.example.com"}, {"tv-banc": ['a"; reboot']}, {"tv-banc": ["../x"]}, {"tv-banc": ["A B.com"]},
                    {"tv-banc": [BITMOVIN] * 3 + [f"d{i}.example.com" for i in range(60)]}, {f"tv-{i}": ["a.example.com"] for i in range(40)}, {"tv-banc": [5]}, {"": ["a.example.com"]}):
        with pytest.raises(dnstv.ErreurTV):
            dnstv.valider_etat(etat(autorisations=mauvais))
    gros = {f"tv-{i}": [f"d{j}.example.com" for j in range(30)] for i in range(20)}              # 600 domaines au total
    with pytest.raises(dnstv.ErreurTV):
        dnstv.valider_etat(etat(autorisations=gros))


def test_le_rendu_pose_un_override_par_adresse_dans_la_clause_server():
    out = dnstv.rendre_unbound(etat(), {}, {})
    s = serveur(out)
    assert f'    local-zone-override: "{BITMOVIN}." 192.168.1.95/32 transparent' in s
    assert f'    local-zone-override: "{BITMOVIN}." {V6}/128 transparent' in s
    assert "local-zone-override" not in out.split('name: "sbx-tv-auto-tv-banc"')[1]               # jamais dans une vue : dans la clause server


def test_pas_d_override_pour_un_appareil_hors_puits_ou_hors_mode_auto():
    for c in ({"puits": False, "mode": "auto"}, {"mode": "block"}, {"mode": "observe"}):
        e = etat(clients=[dict({"ip": "192.168.1.95", "nom": "TV banc", "mode": "auto"}, **c)])
        assert "local-zone-override" not in dnstv.rendre_unbound(e, {}, {})                      # ces appareils ne voient pas le puits global : rien à exempter


def test_l_exception_l_emporte_sur_une_regle_de_blocage_du_meme_nom():
    out = dnstv.rendre_unbound(etat(), {}, {"tv-banc": [BITMOVIN, "pub.example.com"]})
    bloc = out.split('name: "sbx-tv-auto-tv-banc"')[1].split("view:")[0]
    assert 'local-zone: "pub.example.com." always_nxdomain' in bloc and BITMOVIN not in bloc


def test_l_autorisation_d_un_autre_appareil_ne_touche_pas_celui_ci():
    out = dnstv.rendre_unbound(etat(autorisations={"autre": [BITMOVIN]}), {}, {})
    assert "local-zone-override" not in out


def test_un_vrai_unbound_exempte_l_appareil_et_lui_seul(tmp_path):
    """Mesuré sur l'Unbound 1.17.1 de gk2 : l'override exempte un client d'une zone GLOBALE, même dans une vue view-first."""
    import shutil
    import socket
    import subprocess
    import time as _t
    if not (shutil.which("unbound") and shutil.which("unbound-control") and shutil.which("dig")):
        pytest.skip("unbound/dig absents")
    ports = []
    for _ in range(2):
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        ports.append(s.getsockname()[1])
        s.close()
    p_amont, p_u = ports
    (tmp_path / "amont.conf").write_text(f'''server:
    interface: 127.0.0.1@{p_amont}
    access-control: 127.0.0.0/8 allow
    pidfile: {tmp_path}/b.pid
    directory: {tmp_path}
    use-syslog: no
    logfile: {tmp_path}/b.log
    local-zone: "sbx." static
    local-data: "bloque.sbx. 60 IN A 192.0.2.1"
''')
    (tmp_path / "u.conf").write_text(f'''server:
    interface: 127.0.0.1@{p_u}
    access-control: 127.0.0.0/8 allow
    do-not-query-localhost: no
    access-control-view: 127.0.0.2/32 sbx-v
    pidfile: {tmp_path}/u.pid
    directory: {tmp_path}
    use-syslog: no
    logfile: {tmp_path}/u.log
    local-zone: "bloque.sbx." always_nxdomain
    local-zone-override: "bloque.sbx." 127.0.0.2/32 transparent
view:
    name: "sbx-v"
    view-first: yes
forward-zone:
    name: "sbx."
    forward-addr: 127.0.0.1@{p_amont}
remote-control:
    control-enable: yes
    control-interface: {tmp_path}/ctl.sock
    control-use-cert: no
''')

    def q(src):
        r = subprocess.run(["dig", "+time=3", "+tries=1", "-b", src, "-p", str(p_u), "@127.0.0.1", "bloque.sbx"], capture_output=True, text=True)
        return "OK" if "192.0.2.1" in r.stdout else ("NXDOMAIN" if "NXDOMAIN" in r.stdout else r.stdout[-80:])
    subprocess.run(["unbound", "-c", str(tmp_path / "amont.conf")], check=True)
    subprocess.run(["unbound", "-c", str(tmp_path / "u.conf")], check=True)
    try:
        _t.sleep(1)
        assert q("127.0.0.2") == "OK" and q("127.0.0.3") == "NXDOMAIN"                              # exempté dans sa vue view-first ; les autres restent bloqués
    finally:
        subprocess.run(["unbound-control", "-c", str(tmp_path / "u.conf"), "-s", str(tmp_path / "ctl.sock"), "stop"], capture_output=True)
        subprocess.run(["unbound-control", "-c", str(tmp_path / "amont.conf"), "stop"], capture_output=True)


# ── contrôleur : un changement d'autorisation recharge Unbound (l'override n'est pas applicable à chaud) et s'audite ──────────────
def prep(monkeypatch, tmp_path):
    faux(tmp_path, "checkconf")
    ctl_ = faux(tmp_path, "unbound-control")
    return charger_ctl(monkeypatch, tmp_path, ctl_)


def test_le_controleur_recharge_et_audite_une_autorisation(monkeypatch, tmp_path):
    mod = prep(monkeypatch, tmp_path)
    base = {"actif": True, "clients": [{"ip": "192.168.1.95", "nom": "TV banc", "mode": "auto"}]}
    dnstv.ecrire_etat(base, tmp_path)
    mod.appliquer()
    (tmp_path / "unbound-control.log").unlink(missing_ok=True)
    dnstv.ecrire_etat(dict(base, autorisations={"tv-banc": [BITMOVIN]}), tmp_path)
    assert mod.regles_appliquer() == 0
    assert "reload" in (tmp_path / "unbound-control.log").read_text()                               # pas de chemin « à chaud » pour un override
    assert f'local-zone-override: "{BITMOVIN}." 192.168.1.95/32 transparent' in (tmp_path / "94.conf").read_text()
    audit = (tmp_path / "audit.log").read_text()
    assert '"action": "autorisation"' in audit and f"+ tv-banc {BITMOVIN}" in audit
    dnstv.ecrire_etat(base, tmp_path)
    mod.regles_appliquer()
    assert f"- tv-banc {BITMOVIN}" in (tmp_path / "audit.log").read_text()


# ── API ──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
def test_autoriser_ajoute_applique_et_retire(api, donnees):
    r = api.post("/adblock-tv/auto/appareils/TV banc/autoriser", json={"domaine": BITMOVIN})
    assert r.status_code == 200 and r.json()["autorisations"] == [BITMOVIN] and r.json()["application"]["ok"] is True
    assert etat_disque(donnees)["autorisations"] == {"tv-banc": [BITMOVIN]}
    assert f'local-zone-override: "{BITMOVIN}." 192.168.1.95/32 transparent' in donnees["conf"].read_text()
    assert api.get("/adblock-tv/auto/detection").json()["appareils"][0]["autorisations"] in ([BITMOVIN], [])
    r = api.post("/adblock-tv/auto/appareils/TV banc/autoriser", json={"domaine": BITMOVIN, "actif": False})
    assert r.status_code == 200 and r.json()["autorisations"] == [] and "autorisations" not in etat_disque(donnees)
    assert "local-zone-override" not in donnees["conf"].read_text()


def test_autoriser_refus_et_entrees_hostiles(api, donnees):
    assert api.post("/adblock-tv/auto/appareils/inconnu/autoriser", json={"domaine": BITMOVIN}).status_code == 404
    for hostile in ('a"; reboot', "../x", "A B.com", "x" * 300 + ".com", "ip.168.1.1", "com", ""):
        assert api.post("/adblock-tv/auto/appareils/TV banc/autoriser", json={"domaine": hostile}).status_code in (404, 422), hostile
    e = etat_disque(donnees)
    e["clients"].append({"ip": "192.168.1.9", "nom": "Observe", "mode": "observe"})
    dnstv.ecrire_etat(e, donnees["etat"])
    assert api.post("/adblock-tv/auto/appareils/Observe/autoriser", json={"domaine": BITMOVIN}).status_code == 422       # il ne voit pas le puits : rien à exempter
    assert "autorisations" not in etat_disque(donnees)


def test_autoriser_plafond_par_appareil(api, donnees):
    for i in range(50):
        assert api.post("/adblock-tv/auto/appareils/TV banc/autoriser", json={"domaine": f"d{i}.example.com"}).status_code == 200
    assert api.post("/adblock-tv/auto/appareils/TV banc/autoriser", json={"domaine": "de-trop.example.com"}).status_code == 422


def test_autoriser_echec_du_controleur_retablit_l_etat(faux_api):
    c, d = faux_api
    d["echec"] = True
    avant = etat_disque(d)
    assert c.post("/adblock-tv/auto/appareils/TV banc/autoriser", json={"domaine": BITMOVIN}).status_code == 502
    assert etat_disque(d) == avant


def test_refus_recents_d_un_appareil(api, donnees):
    t = int(time.time())
    m = dnstv.Magasin(donnees["etat"] / "dnstv.db")
    m.ajouter([(dnstv.Evenement(t - 30, "192.168.1.95", BITMOVIN, "A", "NXDOMAIN", "BLOCKED"), "advertising")] * 3
              + [(dnstv.Evenement(t - 20, "192.168.1.95", "ads.example.com", "A", "NXDOMAIN", "BLOCKED"), "")]
              + [(dnstv.Evenement(t - 10, "192.168.1.95", "ok.example.com", "A", "NOERROR", "ALLOWED"), "")]
              + [(dnstv.Evenement(t - 99999, "192.168.1.95", "vieux.example.com", "A", "NXDOMAIN", "BLOCKED"), "")])
    j = api.get("/adblock-tv/auto/appareils/TV banc/refus?minutes=60").json()
    par = {x["domaine"]: x for x in j["refus"]}
    assert par[BITMOVIN]["requetes"] == 3 and par["ads.example.com"]["requetes"] == 1 and "ok.example.com" not in par and "vieux.example.com" not in par
    assert j["refus"][0]["domaine"] == BITMOVIN and par[BITMOVIN]["autorise"] is False
    assert api.get("/adblock-tv/auto/appareils/inconnu/refus").status_code == 404
    assert api.get("/adblock-tv/auto/appareils/TV banc/refus?minutes=0").status_code == 422
    assert api.get("/adblock-tv/auto/appareils/TV banc/refus?minutes=99999").status_code == 422


def test_routes_synchrones_et_gardees(donnees):
    import inspect
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from secubox_core import auth
    from api import dnstv_routes as r
    assert not inspect.iscoroutinefunction(r.autoriser_domaine) and not inspect.iscoroutinefunction(r.refus_appareil)
    app = FastAPI()
    app.include_router(r.router)
    app.dependency_overrides[auth.require_lecture] = lambda: {"sub": "lecteur"}
    c = TestClient(app)
    assert c.post("/adblock-tv/auto/appareils/TV banc/autoriser", json={"domaine": BITMOVIN}).status_code in (401, 403)
    assert c.get("/adblock-tv/auto/appareils/TV banc/refus").status_code == 200
