# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3100 — le maître sert au live un lot de flash signé (code de jonction, ancre, nom, domaine)."""
import base64
import importlib
import json
import os
import stat
import subprocess
import sys
from pathlib import Path

import pytest

ICI = Path(__file__).resolve().parents[1]
RACINE = ICI.parents[1]
P2P = RACINE / "packages" / "secubox-p2p"
CTL = ICI / "sbin" / "secubox-netboot-lot"
sys.path.insert(0, str(ICI))
sys.path.insert(0, str(RACINE / "common"))


def _p2p(nom):
    import importlib.util
    spec = importlib.util.spec_from_file_location("p2p_" + nom, P2P / "api" / (nom + ".py"))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


@pytest.fixture
def monde(tmp_path, monkeypatch):
    """Clé RSA jetable, fausse CLI d'invitation, wg_mesh.json, dossiers temporaires."""
    cle = tmp_path / "netboot.key"
    pub = tmp_path / "netboot.pub"
    subprocess.run(["openssl", "genrsa", "-out", str(cle), "2048"], check=True, capture_output=True)
    subprocess.run(["openssl", "rsa", "-in", str(cle), "-pubout", "-out", str(pub)], check=True, capture_output=True)
    automesh = _p2p("automesh")
    code = automesh.encoder("192.168.1.200", "a" * 64)
    invite = tmp_path / "invite"
    appels = tmp_path / "invite-appels.jsonl"
    # fausse CLI : note ses arguments (une ligne JSON par appel) et rend le code
    invite.write_text("#!%s\nimport json, sys\nopen(%r, 'a').write(json.dumps(sys.argv[1:]) + '\\n')\n"
                      "a = sys.argv[1:]\nprint(json.dumps({'code': %r, 'nom': a[a.index('--nom') + 1], 'expire': 1}))\n"
                      % (sys.executable, str(appels), code))
    invite.chmod(0o755)
    wg = tmp_path / "wg_mesh.json"
    wg.write_text(json.dumps({"public_key": "CLEPUBLIQUEDUMAITRE="}))
    prep = tmp_path / "prepares"
    audit = tmp_path / "audit.log"
    env = {"SBX_NETBOOT_KEY": str(cle), "SBX_LOT_INVITE": str(invite), "SBX_LOT_WGMESH": str(wg),
           "SBX_LOT_P2P": str(P2P / "api"), "SBX_LOT_PREPARES": str(prep), "SBX_LOT_AUDIT": str(audit),
           "SBX_LOT_DOMAINE_MAITRE": "gk2.secubox.in", "SBX_LOT_HOTE": "gk2"}
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    return {"env": env, "pub": pub, "code": code, "prep": prep, "audit": audit, "tmp": tmp_path, "appels": appels}


def _appels(monde):
    """Arguments passés à sbx-mesh-invite, un appel par élément."""
    if not monde["appels"].exists():
        return []
    return [json.loads(x) for x in monde["appels"].read_text().splitlines()]


def _lot():
    sys.modules.pop("api.lot", None)
    return importlib.import_module("api.lot")


def test_domaine_pour():
    lot = _lot()
    assert lot.domaine_pour("gk1", "gk2.secubox.in") == "gk1.secubox.in"
    assert lot.domaine_pour("a-b2", "x.exemple.fr") == "a-b2.exemple.fr"


@pytest.mark.parametrize("nom", ["", "GK1", "1gk", "a_b", "a.b", "../x", "a" * 32, "gk1\n", "gk-"])
def test_nom_invalide_refuse(nom):
    with pytest.raises(ValueError):
        _lot().domaine_pour(nom, "gk2.secubox.in")


def test_lot_signe_verifie_avec_la_cle_publique(monde):
    r = subprocess.run([sys.executable, str(CTL), "gk1"], capture_output=True, text=True, env={**os.environ, **monde["env"]})
    assert r.returncode == 0, r.stderr
    sortie = json.loads(r.stdout)
    texte = sortie["lot"]
    d = json.loads(texte)
    assert d["version"] == 1 and d["nom"] == "gk1" and d["domaine"] == "gk1.secubox.in"
    assert d["code"] == monde["code"] and "admin_empreinte" not in d
    anc = d["ancre"]
    assert anc["cle_publique"] == "CLEPUBLIQUEDUMAITRE=" and anc["adresse"] == "192.168.1.200" and anc["nom"] == "gk2"
    assert anc["empreinte"] == _p2p("ancre").empreinte("CLEPUBLIQUEDUMAITRE=")
    sig = monde["tmp"] / "lot.sig"
    sig.write_bytes(base64.b64decode(sortie["signature"]))
    lotf = monde["tmp"] / "lot.json"
    lotf.write_bytes(texte.encode())
    v = subprocess.run(["openssl", "dgst", "-sha256", "-verify", str(monde["pub"]), "-signature", str(sig), str(lotf)],
                       capture_output=True)
    assert v.returncode == 0, v.stderr
    lotf.write_bytes(texte.replace("gk1", "gk9").encode())
    assert subprocess.run(["openssl", "dgst", "-sha256", "-verify", str(monde["pub"]), "-signature", str(sig), str(lotf)],
                          capture_output=True).returncode != 0


def test_ctl_refuse_nom_invalide(monde):
    r = subprocess.run([sys.executable, str(CTL), "../x"], capture_output=True, text=True, env={**os.environ, **monde["env"]})
    assert r.returncode != 0 and r.stdout == ""


def _client(monde):
    from fastapi.testclient import TestClient
    sys.modules.pop("api.lot", None)
    sys.modules.pop("api.main", None)
    main = importlib.import_module("api.main")
    main._LOT_COMPTEURS.clear()
    main.CTL_LOT = str(CTL)
    return main, TestClient(main.app, headers={"X-SecuBox-Netboot-Lot": "1"})


def test_preparation_consommee_une_fois(monde):
    main, c = _client(monde)
    main.app.dependency_overrides[main.require_jwt] = lambda: {"sub": "admin"}
    r = c.post("/flash/prepare", json={"nom": "gk1", "mot_de_passe": "Secret-Test-42"})
    assert r.status_code == 200, r.text
    h = {"X-Real-IP": "192.168.1.50"}
    r1 = c.get("/lot-flash", params={"nom": "gk1"}, headers=h)
    assert r1.status_code == 200, r1.text
    d1 = json.loads(r1.json()["lot"])
    assert d1["admin_empreinte"].startswith("$argon2")
    assert "flash" not in r1.json()                       # l'indicateur reste côté maître
    r2 = c.get("/lot-flash", params={"nom": "gk1"}, headers=h)
    assert "admin_empreinte" not in json.loads(r2.json()["lot"])
    assert not (monde["prep"] / "gk1.json").exists()
    assert ["--flash" in a for a in _appels(monde)] == [True, False]
    lignes = [json.loads(x) for x in monde["audit"].read_text().splitlines()]
    assert [x["evenement"] for x in lignes] == ["flash_prepare", "lot_flash_servi", "lot_flash_servi"]
    assert lignes[1]["nom"] == "gk1" and lignes[1]["adresse"] == "192.168.1.50"
    assert [lignes[1]["flash"], lignes[2]["flash"]] == [True, False]
    assert monde["code"] not in monde["audit"].read_text()


def test_mot_de_passe_jamais_en_clair_sur_disque(monde, caplog):
    main, c = _client(monde)
    main.app.dependency_overrides[main.require_jwt] = lambda: {"sub": "admin"}
    c.post("/flash/prepare", json={"nom": "gk1", "mot_de_passe": "Secret-Test-42"})
    f = monde["prep"] / "gk1.json"
    assert stat.S_IMODE(f.stat().st_mode) == 0o600
    assert "Secret-Test-42" not in f.read_text()
    d = json.loads(f.read_text())
    assert d["nom"] == "gk1" and d["admin_empreinte"].startswith("$argon2")
    from argon2 import PasswordHasher
    assert PasswordHasher().verify(d["admin_empreinte"], "Secret-Test-42")
    for p in monde["tmp"].rglob("*"):
        if p.is_file():
            assert b"Secret-Test-42" not in p.read_bytes()
    assert "Secret-Test-42" not in caplog.text


def test_prepare_exige_jwt_et_valide_le_nom(monde):
    main, c = _client(monde)
    assert c.post("/flash/prepare", json={"nom": "gk1", "mot_de_passe": "x" * 12}).status_code in (401, 403)
    main.app.dependency_overrides[main.require_jwt] = lambda: {"sub": "admin"}
    assert c.post("/flash/prepare", json={"nom": "../x", "mot_de_passe": "x" * 12}).status_code == 400
    assert c.post("/flash/prepare", json={"nom": "gk1", "mot_de_passe": "court"}).status_code == 400
    assert not (monde["prep"] / "gk1.json").exists()


def test_lot_sans_preparation_code_ordinaire(monde):
    """Sans préparation : code ordinaire (pas de --flash), lié au nom, 48 h — un nom déjà approuvé
    sera refusé par le maître (409), aucune clé de pair ne peut être remplacée."""
    main, c = _client(monde)
    r = c.get("/lot-flash", params={"nom": "gk1"}, headers={"X-Real-IP": "192.168.1.50"})
    assert r.status_code == 200, r.text
    (a,) = _appels(monde)
    assert "--flash" not in a
    assert a[a.index("--nom") + 1] == "gk1" and a[a.index("--ttl") + 1] == "172800"
    assert json.loads(monde["audit"].read_text().splitlines()[-1])["flash"] is False


def test_preparation_sans_mot_de_passe_donne_un_flash(monde):
    main, c = _client(monde)
    main.app.dependency_overrides[main.require_jwt] = lambda: {"sub": "admin"}
    r = c.post("/flash/prepare", json={"nom": "gk1"})
    assert r.status_code == 200, r.text
    d = json.loads((monde["prep"] / "gk1.json").read_text())
    assert "admin_empreinte" not in d and d["expire"] - d["cree"] == 86400
    r = c.get("/lot-flash", params={"nom": "gk1"}, headers={"X-Real-IP": "192.168.1.50"})
    assert r.status_code == 200, r.text
    assert "admin_empreinte" not in json.loads(r.json()["lot"])      # la console du live le demandera
    assert "--flash" in _appels(monde)[0]
    assert not (monde["prep"] / "gk1.json").exists()


def test_preparation_expiree_ignoree_et_supprimee(monde):
    lot = _lot()
    lot.enregistrer_preparation("gk1")
    f = monde["prep"] / "gk1.json"
    d = json.loads(f.read_text())
    d["expire"] = d["cree"] - 1
    f.write_text(json.dumps(d))
    sortie = lot.construire("gk1")
    assert sortie["flash"] is False and "--flash" not in _appels(monde)[0]
    assert list(monde["prep"].iterdir()) == []
    assert json.loads(monde["audit"].read_text().splitlines()[-1])["evenement"] == "preparation_ignoree"


def test_preparation_ancienne_sans_echeance_ignoree(monde):
    """Format d'avant (sans `expire`) : jamais pris pour une préparation valide."""
    monde["prep"].mkdir(mode=0o700)
    (monde["prep"] / "gk1.json").write_text(json.dumps({"nom": "gk1", "admin_empreinte": "$argon2id$x"}))
    assert _lot().construire("gk1")["flash"] is False


def test_preparation_prise_une_seule_fois_en_concurrence(monde):
    """Deux demandes simultanées : une seule obtient la préparation (renommage atomique)."""
    from concurrent.futures import ThreadPoolExecutor
    lot = _lot()
    for _ in range(20):
        lot.enregistrer_preparation("gk1")
        with ThreadPoolExecutor(8) as ex:
            pris = list(ex.map(lambda _i: lot.prendre_preparation("gk1"), range(8)))
        gagnants = [p for p in pris if p is not None]
        assert len(gagnants) == 1
        lot.abandonner_preparation(gagnants[0])
    assert list(monde["prep"].iterdir()) == []


def test_preparation_rendue_si_le_lot_echoue(monde):
    lot = _lot()
    lot.enregistrer_preparation("gk1")
    monde["appels"].parent.joinpath("invite").write_text("#!/bin/sh\nexit 1\n")
    with pytest.raises(RuntimeError):
        lot.construire("gk1")
    assert (monde["prep"] / "gk1.json").exists()               # remise : le prochain essai sera un flash


def test_adresse_du_maitre_portee_par_le_code(monde):
    """L'adresse jointe par le live ($server_addr du vhost :8099) est passée à sbx-mesh-invite."""
    main, c = _client(monde)
    h = {"X-Real-IP": "192.168.1.50", "X-SecuBox-Adresse-Serveur": "192.168.1.200"}
    assert c.get("/lot-flash", params={"nom": "gk1"}, headers=h).status_code == 200
    a = _appels(monde)[-1]
    assert a[a.index("--adresse") + 1] == "192.168.1.200"


@pytest.mark.parametrize("serveur", ["8.8.8.8", "127.0.0.1", "10.10.0.1", "fe80::1", "x; rm -rf /"])
def test_adresse_du_maitre_invalide_remplacee_par_la_route(monde, serveur):
    main, c = _client(monde)
    vus = []

    async def faux_run(*argv, timeout=60):
        vus.append(argv)
        if argv[0] == "ip":
            return {"rc": 0, "stdout": "192.168.1.50 dev lan0 src 192.168.1.201 uid 0 \\    cache", "stderr": ""}
        return await vrai_run(*argv, timeout=timeout)
    vrai_run = main._run
    main._run = faux_run
    h = {"X-Real-IP": "192.168.1.50", "X-SecuBox-Adresse-Serveur": serveur}
    assert c.get("/lot-flash", params={"nom": "gk1"}, headers=h).status_code == 200
    assert ("ip", "-o", "route", "get", "192.168.1.50") in vus
    a = _appels(monde)[-1]
    assert a[a.index("--adresse") + 1] == "192.168.1.201"


def test_adresse_introuvable_sans_option(monde):
    main, c = _client(monde)

    async def faux_run(*argv, timeout=60):
        if argv[0] == "ip":
            return {"rc": 2, "stdout": "", "stderr": "RTNETLINK"}
        return await vrai_run(*argv, timeout=timeout)
    vrai_run = main._run
    main._run = faux_run
    assert c.get("/lot-flash", params={"nom": "gk1"}, headers={"X-Real-IP": "192.168.1.50"}).status_code == 200
    assert "--adresse" not in _appels(monde)[-1]


def test_ctl_refuse_adresse_invalide(monde):
    for argv in (["gk1", "--adresse", "8.8.8.8"], ["gk1", "--adresse"], ["gk1", "--autre", "10.0.0.1"]):
        r = subprocess.run([sys.executable, str(CTL), *argv], capture_output=True, text=True,
                           env={**os.environ, **monde["env"]})
        assert r.returncode == 2 and r.stdout == ""
    assert _appels(monde) == []


def test_route_lot_refuse_hors_lan(monde):
    main, c = _client(monde)
    assert c.get("/lot-flash", params={"nom": "gk1"}, headers={"X-Real-IP": "8.8.8.8"}).status_code == 403
    assert c.get("/lot-flash", params={"nom": "gk1"}).status_code == 403
    assert c.get("/lot-flash", params={"nom": "../x"}, headers={"X-Real-IP": "10.0.0.5"}).status_code == 400


def test_route_lot_six_par_heure_et_par_adresse(monde):
    main, c = _client(monde)
    h = {"X-Real-IP": "10.0.0.5"}
    assert [c.get("/lot-flash", params={"nom": "gk1"}, headers=h).status_code for _ in range(6)] == [200] * 6
    assert c.get("/lot-flash", params={"nom": "gk1"}, headers=h).status_code == 429
    assert c.get("/lot-flash", params={"nom": "gk1"}, headers={"X-Real-IP": "10.0.0.6"}).status_code == 200


def test_vhost_nginx_location_lot_flash_lan_seulement():
    s = (ICI / "nginx" / "boot-vhost.conf").read_text()
    i = s.index("location = /lot-flash")
    bloc = s[i:s.index("}", i)]
    for t in ("allow 10.0.0.0/8;", "allow 172.16.0.0/12;", "allow 192.168.0.0/16;", "deny all;",
              "unix:/run/secubox/netboot.sock", "X-Real-IP $remote_addr",
              "X-SecuBox-Adresse-Serveur $server_addr;"):
        assert t in bloc


def test_route_sans_marqueur_refusee(monde):
    main, c = _client(monde)
    c.headers.pop("X-SecuBox-Netboot-Lot")
    assert c.get("/lot-flash", params={"nom": "gk1"}, headers={"X-Real-IP": "192.168.1.50"}).status_code == 404
    assert c.get("/lot-flash", params={"nom": "gk1"}, headers={"X-Real-IP": "192.168.1.50",
                                                                "X-SecuBox-Netboot-Lot": "0"}).status_code == 404


@pytest.mark.parametrize("ip", ["10.100.0.7", "10.0.3.9", "10.10.0.2"])
def test_ponts_conteneurs_et_maillage_refuses(monde, ip):
    main, c = _client(monde)
    assert c.get("/lot-flash", params={"nom": "gk1"}, headers={"X-Real-IP": ip}).status_code == 403
    ligne = json.loads(monde["audit"].read_text().splitlines()[-1])
    assert ligne["evenement"] == "lot_flash_refuse" and ligne["adresse"] == ip and ligne["raison"]
    assert c.get("/lot-flash", params={"nom": "gk1"}, headers={"X-Real-IP": "10.100.1.7"}).status_code == 200


def test_compteurs_bornes(monde):
    main, c = _client(monde)
    main._lot_admis("10.1.1.1", 0.0)
    main._lot_admis("10.1.1.2", 4000.0)           # l'entrée de plus d'une heure est élaguée
    assert "10.1.1.1" not in main._LOT_COMPTEURS
    for i in range(3000):
        main._lot_admis(f"10.2.{i // 250}.{i % 250}", 5000.0 + i)
    assert len(main._LOT_COMPTEURS) <= 1024
    assert "10.2.11.249" in main._LOT_COMPTEURS    # la plus récente reste, les plus anciennes sont évincées


def test_nginx_principal_bloque_la_route_et_vide_le_marqueur():
    n = (ICI / "nginx" / "netboot.conf").read_text()
    assert "location = /api/v1/netboot/lot-flash { return 404; }" in n
    assert n.index("lot-flash") < n.index("location /api/v1/netboot/")
    p = (RACINE / "common" / "nginx" / "secubox-proxy.conf").read_text()
    assert 'proxy_set_header   X-SecuBox-Netboot-Lot "";' in p
    assert 'proxy_set_header X-SecuBox-Netboot-Lot "1";' in (ICI / "nginx" / "boot-vhost.conf").read_text()


def test_vhost_principal_du_hub_bloque_aussi_la_route():
    w = (RACINE / "packages" / "secubox-hub" / "nginx" / "webui.conf").read_text()
    assert "location = /api/v1/netboot/lot-flash { return 404; }" in w
    assert w.index("lot-flash") < w.index("location /api/v1/netboot/ {")
