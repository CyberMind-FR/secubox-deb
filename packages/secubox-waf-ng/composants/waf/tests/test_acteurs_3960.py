# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3960 : aperçu, ban et levée d'un acteur. wafctl, actord et le DNS sont simulés ; rien ne touche un pare-feu."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

COMPOSANT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(COMPOSANT))

from tests.test_gestes_ia_3716 import _importer_waf  # noqa: E402

A, B6, C, PAIR, SESSION, ROBOT, DOUTE, BANNIE = ("198.51.100.7", "2a01:e0a:1:2::7", "203.0.113.9", "198.51.100.20",
                                                 "198.51.100.30", "198.51.100.40", "198.51.100.50", "198.51.100.60")


@pytest.fixture
def b(monkeypatch, tmp_path):
    from fastapi.testclient import TestClient
    waf = _importer_waf()
    from api import acteurs as m
    from secubox_core.auth import require_jwt
    import ipaddress

    class Banc:
        pass
    x = Banc()
    now = int(time.time())
    x.m, x.tmp = m, tmp_path
    x.events = [(A, now - 50), (B6, now - 60), (PAIR, now - 70), (SESSION, now - 70), (ROBOT, now - 80), (DOUTE, now - 80),
                (BANNIE, now - 90), ("192.168.1.9", now - 90), (C, now - 49 * 3600)]
    x.total = None
    x.appels, x.ko, x.couverts, x.usager = [], {}, [], {"sub": "gk2"}

    def chrono(acteur):
        ev = [{"src_ip": ip, "ts": ts} for ip, ts in x.events]
        return {"events": ev, "total": len(ev) if x.total is None else x.total}

    def executer(verbe, args, ips):
        x.appels.append((verbe, " ".join(args), list(ips)))
        if verbe in x.ko:
            raise x.ko[verbe]
        if verbe == "ban-lot":
            return {"poses": ips, "presents": [], "refuses": {}, "fin": int(time.time()) + 86400}
        return {"leves": [i for i in ips if i not in x.couverts], "couverts": [i for i in ips if i in x.couverts], "absents": []}

    def fcrdns(ip):
        if ip == DOUTE:
            raise m._g.ProtectionInconnue("dns")
        return "googlebot.com" if ip == ROBOT else ""
    monkeypatch.setenv("SECUBOX_WAF_GESTES_IA", "1")
    monkeypatch.setattr(waf, "AUDIT_LOG", tmp_path / "audit.log")
    monkeypatch.setattr(m, "JOURNAL", tmp_path / "acteur-ban.jsonl")
    monkeypatch.setattr(m, "SESSIONS", tmp_path / "sessions.json")
    (tmp_path / "sessions.json").write_text(json.dumps([{"ip": SESSION}]))
    monkeypatch.setattr(m, "_lire_chronologie", chrono)
    monkeypatch.setattr(m, "_executer", executer)
    monkeypatch.setitem(m._config, "liste_blanche", lambda: ["127.0.0.1"])
    monkeypatch.setattr(m, "_apercus", {})
    monkeypatch.setattr(m._g, "lire_waf_ban", lambda e="waf_ban": {BANNIE} if e == "waf_ban" else set())
    monkeypatch.setattr(m._g, "lire_sade", lambda: None)
    monkeypatch.setattr(m._g, "BANS_WAF", tmp_path / "bans.jsonl")
    monkeypatch.setattr(m._g, "pairs_wg_mesh", lambda: [ipaddress.ip_network(PAIR)])
    monkeypatch.setattr(m._g, "pairs_threatmesh", lambda: [])
    monkeypatch.setattr(m._g, "_fcrdns", fcrdns)
    waf.app.dependency_overrides[require_jwt] = lambda: dict(x.usager)
    x.waf, x.c = waf, TestClient(waf.app, headers={"X-Forwarded-For": "192.168.1.50"})
    x.audit = lambda: [json.loads(li)["action"] for li in (tmp_path / "audit.log").read_text().splitlines()]
    x.apercu = lambda **h: x.c.get("/acteurs/ACT-0001/apercu", headers=h)
    x.bannir = lambda a, acteur="ACT-0001": x.c.post(f"/acteurs/{acteur}/bannir", json={"apercu": a})
    try:
        yield x
    finally:
        waf.app.dependency_overrides.clear()


def test_apercu_trois_groupes_et_rien_d_applique(b):
    d = b.apercu().json()
    assert [x["ip"] for x in d["a_bannir"]] == [A, B6] and d["deja_bannies"] == 1 and d["reste"] == 0 and d["partiel"] is False
    assert {x["ip"]: x["motif"] for x in d["epargnees"]} == {PAIR: "pair", SESSION: "session", ROBOT: "robot",
                                                            DOUTE: "robot_inconnu", "192.168.1.9": "privee"}
    assert b.appels == []


def test_le_demandeur_n_est_jamais_dans_la_liste(b):
    d = b.apercu(**{"X-Forwarded-For": f"203.0.113.1, {A}"}).json()
    assert A not in [x["ip"] for x in d["a_bannir"]]


def test_bannir_pose_la_liste_montree_et_rien_de_plus(b):
    a = b.apercu().json()["apercu"]
    b.events.insert(0, ("198.51.100.99", int(time.time())))
    r = b.bannir(a)
    assert r.status_code == 200 and r.json()["posees"] == 2
    assert b.appels == [("ban-lot", "86400s", [A, B6])]
    assert b.audit() == ["acteur-ban-demande", "acteur-ban"]
    assert b.bannir(a).json()["detail"]["motif"] == "apercu_perime"          # usage unique
    e = b.c.get("/acteurs/ACT-0001/etat").json()
    assert e["gestes"][0]["nombre"] == 2 and e["gestes"][0]["par"] == "gk2" and e["bannies"] == 1


def test_apercu_d_un_autre_acteur_administrateur_ou_perime(b):
    a = b.apercu().json()["apercu"]
    assert b.bannir(a, "ACT-0002").status_code == 409
    b.usager = {"sub": "autre"}
    assert b.bannir(a).status_code == 409
    b.usager = {"sub": "gk2"}
    b.m._apercus[a]["at"] -= 301
    assert b.bannir(a).status_code == 409 and b.appels == []


def test_protection_devenue_illisible_ou_nouvelle(b, monkeypatch):
    a = b.apercu().json()["apercu"]
    (b.tmp / "sessions.json").write_text("{illisible")
    assert b.bannir(a).json()["detail"]["motif"] == "protegee_inconnue" and b.appels == []
    (b.tmp / "sessions.json").write_text(json.dumps([{"ip": A}]))
    assert b.bannir(a).status_code == 200 and b.appels[0][2] == [B6]


def test_plafond_de_200_adresses(b):
    now = int(time.time())
    b.events = [(f"198.51.100.{i}", now - i) for i in range(1, 250)] + [(f"203.0.113.{i}", now - 300 - i) for i in range(1, 50)]
    d = b.apercu().json()
    retirees = {x["ip"] for x in d["epargnees"]}
    assert len(d["a_bannir"]) == 200                          # celles qu'on épargne sont remplacées par les suivantes
    assert d["reste"] > 0 and not retirees & {x["ip"] for x in d["a_bannir"]}


def test_plafond_de_gestes(b):
    for _ in range(10):
        assert b.bannir(b.apercu().json()["apercu"]).status_code == 200
    assert b.bannir(b.apercu().json()["apercu"]).json()["detail"]["motif"] == "plafond"


def test_sans_audit_rien_n_est_fait_ou_tout_est_retire(b, monkeypatch):
    a = b.apercu().json()["apercu"]
    monkeypatch.setitem(b.m._config, "audit", lambda *_: (_ for _ in ()).throw(OSError()))
    assert b.bannir(a).status_code == 503 and b.appels == []
    vus = []
    monkeypatch.setitem(b.m._config, "audit", lambda action, *_: vus.append(action) if "demande" in action
                        else (_ for _ in ()).throw(OSError()))
    assert b.bannir(b.apercu().json()["apercu"]).status_code == 503
    assert [x[0] for x in b.appels] == ["ban-lot", "unban-lot"]
    assert b.c.get("/acteurs/ACT-0001/etat").json()["gestes"] == []


def _gestes(b):
    return b.c.get("/acteurs/ACT-0001/etat").json()["gestes"]


def test_refus_net_ne_defait_rien(b):
    b.ko = {"ban-lot": b.m.HTTPException(503, detail={"motif": "etat"})}
    assert b.bannir(b.apercu().json()["apercu"]).json()["detail"]["motif"] == "etat"
    assert [x[0] for x in b.appels] == ["ban-lot"] and _gestes(b) == []


def test_pose_incertaine_retiree_ou_laissee_visible(b):
    b.ko = {"ban-lot": b.m.Incertain("delai")}
    assert b.bannir(b.apercu().json()["apercu"]).json()["detail"]["motif"] == "wafctl"
    assert [x[0] for x in b.appels] == ["ban-lot", "unban-lot"] and b.appels[1][1].endswith(" incertain") and _gestes(b) == []
    b.couverts = [A]
    r = b.bannir(b.apercu().json()["apercu"])
    assert r.status_code == 500 and r.json()["detail"]["motif"] == "incoherent"
    g = _gestes(b)
    assert g[0]["nombre"] == 2 and g[0]["incertain"] is True
    b.couverts = []
    assert b.c.post(f"/acteurs/gestes/{g[0]['id']}/lever").json()["levees"] == 2 and b.appels[-1][1].endswith(" incertain")


def test_processus_tue_apres_la_pose_reste_levable(b, monkeypatch):
    a = b.apercu().json()["apercu"]
    ecrire, n = b.m._gb._ecrire_journal, []

    class Tue(BaseException):
        pass

    def coupe(entree, chemin=None):
        if entree["type"] == "ban":
            raise Tue
        n.append(entree["type"])
        return ecrire(entree, chemin)
    monkeypatch.setattr(b.m._gb, "_ecrire_journal", coupe)
    with pytest.raises(BaseException):  # noqa: B017
        b.bannir(a)
    monkeypatch.setattr(b.m._gb, "_ecrire_journal", ecrire)
    assert n == ["demande"] and _gestes(b)[0]["incertain"] is True


def test_lever_garde_les_bans_des_autres(b):
    g = b.bannir(b.apercu().json()["apercu"]).json()
    (b.tmp / "bans.jsonl").write_text(json.dumps({"ip": A, "action": "ban", "at": 1, "exp": int(time.time()) + 9000}) + "\n")
    b.couverts = [B6]
    assert b.c.post(f"/acteurs/gestes/{g['id']}/lever").json() == {"id": g["id"], "levees": 0, "gardees": 2}
    assert b.appels[-1][2] == [B6] and _gestes(b)[0]["nombre"] == 2        # second essai possible
    b.couverts = []
    assert b.c.post(f"/acteurs/gestes/{g['id']}/lever").json()["levees"] == 1 and _gestes(b)[0]["nombre"] == 1


@pytest.mark.parametrize("cas", ["sessions_absentes", "blanche_illisible", "demandeur", "sade_absente", "sade_illisible"])
def test_protection_illisible_refuse(b, monkeypatch, cas, tmp_path):
    h = {}
    if cas == "sessions_absentes":
        (b.tmp / "sessions.json").unlink()
    elif cas == "blanche_illisible":
        monkeypatch.setitem(b.m._config, "liste_blanche", lambda: ["127.0.0.1", "pas-une-adresse"])
    elif cas == "demandeur":
        h = {"X-Forwarded-For": "inconnu"}
    elif cas == "sade_absente":
        monkeypatch.setattr(b.m._g, "FICHIER_SADE", tmp_path / "rien")
        monkeypatch.setattr(b.m._g, "lire_sade", lambda: {"mode": "observe", "liste": []})
    else:
        monkeypatch.setattr(b.m._g, "lire_sade", lambda: {"mode": "active", "liste": None})
    r = b.apercu(**h)
    assert r.status_code == 503 and r.json()["detail"]["motif"] == "protegee_inconnue"


def test_executer_distingue_refus_net_et_doute(b):
    src = (COMPOSANT / "api/acteurs.py").read_text()
    espace = dict(vars(b.m))
    exec(src[src.index("def _executer("):src.index("def _liste(")], espace)  # noqa: S102 — la fonction réelle, hors du faux

    def joue(code, out="", err=""):
        espace["subprocess"] = type("S", (), {"run": staticmethod(lambda *a, **k: subprocess.CompletedProcess(a, code, out, err)),
                                              "TimeoutExpired": subprocess.TimeoutExpired})
        return espace["_executer"]("ban-lot", ["86400s"], [A])
    assert joue(0, '{"poses": []}') == {"poses": []}
    for err, motif in (("refus:etat", "etat"), ("refus:garde_illisible", "protegee_inconnue"), ("refus:nft", "wafctl")):
        with pytest.raises(b.m.HTTPException) as e:
            joue(1, "", err)
        assert e.value.detail["motif"] == motif
    for code, out, err in ((1, "", "refus:incertain"), (1, "", "sudo: boum"), (0, "pas du json", "")):
        with pytest.raises(b.m.Incertain):
            joue(code, out, err)


def test_lever_une_fois(b):
    g = b.bannir(b.apercu().json()["apercu"]).json()
    r = b.c.post(f"/acteurs/gestes/{g['id']}/lever")
    assert r.json() == {"id": g["id"], "levees": 2, "gardees": 0} and b.appels[-1] == ("unban-lot", str(g["fin"]), [A, B6])
    assert b.c.post(f"/acteurs/gestes/{g['id']}/lever").status_code == 404
    assert b.audit()[-2:] == ["acteur-lever-demande", "acteur-lever"]


def test_lecture_partielle_dite_et_identifiant_valide(b):
    b.total = 5000
    assert b.apercu().json()["partiel"] is True
    assert b.c.get("/acteurs/..%2Fstats/apercu").status_code == 404
    assert b.c.get("/acteurs/ACT-0001;x/apercu").status_code == 404


def test_toutes_les_routes_exigent_l_administrateur(b):
    b.waf.app.dependency_overrides.clear()
    for meth, u in (("get", "/acteurs/ACT-0001/etat"), ("get", "/acteurs/ACT-0001/apercu"),
                    ("post", "/acteurs/ACT-0001/bannir"), ("post", "/acteurs/gestes/" + "a" * 32 + "/lever")):
        assert getattr(b.c, meth)(u).status_code in (401, 403), u


# ── wafctl réel, faux nft et faux waf-blocs ──
@pytest.fixture
def w(tmp_path):
    bin_ = tmp_path / "bin"
    bin_.mkdir()
    (bin_ / "nft").write_text(f'#!/bin/bash\nif [ "$1" = -f ]; then cat > {tmp_path}/lot.nft; echo x >> {tmp_path}/essais; [ ! -e {tmp_path}/ko ]; exit; fi\n'
                              f'cat {tmp_path}/${{*: -1}}.json\n')
    (bin_ / "waf-blocs").write_text(f'#!/bin/bash\ncat > {tmp_path}/vu; cat {tmp_path}/verdict\n[ ! -e {tmp_path}/garde-ko ]\n')
    for f in bin_.iterdir():
        f.chmod(0o755)
    script = tmp_path / "wafctl"
    script.write_text((COMPOSANT / "scripts/wafctl").read_text().replace("/usr/sbin/waf-blocs", str(bin_ / "waf-blocs")))

    def ensemble(nom, *elems):
        (tmp_path / f"{nom}.json").write_text(json.dumps({"nftables": [{"metainfo": {}}, {"set": {"name": nom, "elem": [
            {"elem": {"val": ip, "timeout": 86400, "expires": r}} if r is not None else ip for ip, r in elems]}}]}))
    ensemble("waf_ban")
    ensemble("waf_ban6")

    def lancer(*a, entree=""):
        return subprocess.run(["bash", str(script), *a], input=entree, capture_output=True, text=True, check=False, timeout=60,
                              env={**os.environ, "PATH": f"{bin_}:{os.environ['PATH']}"})
    return lancer, ensemble, tmp_path


def test_wafctl_ban_lot(w):
    lancer, ensemble, tmp = w
    ensemble("waf_ban", (BANNIE, 500), ("198.51.100.61", None))
    (tmp / "verdict").write_text(json.dumps({A: None, B6: None, BANNIE: None, "198.51.100.61": None, PAIR: "pair"}))
    r = lancer("ban-lot", "86400s", entree=f"{A}\n{B6}\n")
    d = json.loads(r.stdout)
    assert r.returncode == 0 and d["poses"] == [A, B6] and d["presents"] == [BANNIE, "198.51.100.61"] and d["refuses"] == {PAIR: "pair"}
    lot = (tmp / "lot.nft").read_text().splitlines()
    assert [x.split(" timeout")[0] for x in lot] == [f"create element inet secubox waf_ban {{ {A}",
                                                     f"create element inet secubox waf_ban6 {{ {B6}"]
    assert all(86390 <= int(x.split("timeout ")[1].split("s")[0]) <= 86400 for x in lot)
    assert abs(d["fin"] - int(time.time()) - 86400) <= 10


@pytest.mark.parametrize("args", [["ban-lot"], ["ban-lot", "30m"], ["ban-lot", "2d"], ["ban-lot", "x"], ["unban-lot", "a;b"],
                                  ["unban-lot", "1795000000", "autre"]])
def test_wafctl_lot_arguments(w, args):
    lancer, _, tmp = w
    assert lancer(*args, entree=A).returncode != 0 and not (tmp / "lot.nft").exists()


def test_wafctl_ban_lot_garde_etat_ou_nft_en_echec(w):
    lancer, _, tmp = w
    (tmp / "verdict").write_text(json.dumps({A: None}))
    (tmp / "garde-ko").touch()
    r = lancer("ban-lot", "86400s", entree=A)
    assert r.returncode != 0 and "garde_illisible" in r.stderr
    (tmp / "garde-ko").unlink()
    (tmp / "waf_ban6.json").rename(tmp / "x")
    r = lancer("ban-lot", "86400s", entree=A)
    assert r.returncode != 0 and "refus:etat" in r.stderr and not (tmp / "lot.nft").exists()
    (tmp / "x").rename(tmp / "waf_ban6.json")
    (tmp / "ko").touch()
    r = lancer("ban-lot", "86400s", entree=A)
    assert r.returncode != 0 and "refus:nft" in r.stderr and r.stdout == ""
    assert len((tmp / "essais").read_text().split()) == 2                    # relu et rejoué une fois


def test_wafctl_unban_lot_seulement_le_notre(w):
    lancer, ensemble, tmp = w
    fin = int(time.time()) + 80000
    ensemble("waf_ban", (A, 80000), (C, 80060), (PAIR, 79990), (BANNIE, None))
    r = lancer("unban-lot", str(fin), entree="\n".join([A, C, PAIR, BANNIE, B6]))
    d = json.loads(r.stdout)
    assert d["leves"] == [A] and d["couverts"] == [C, PAIR, BANNIE] and d["absents"] == [B6]
    assert (tmp / "lot.nft").read_text() == f"delete element inet secubox waf_ban {{ {A} }}\n"
    assert json.loads(lancer("unban-lot", str(fin), "incertain", entree=C).stdout)["leves"] == [C]
    assert lancer("unban-lot", str(fin), entree="2a01::1%a;").returncode != 0


def test_waf_blocs_verifier_lot(monkeypatch, capsys):
    import importlib.machinery
    import importlib.util
    import io
    import ipaddress
    ch = importlib.machinery.SourceFileLoader("waf_blocs_3960", str(COMPOSANT / "scripts/waf-blocs"))
    m = importlib.util.module_from_spec(importlib.util.spec_from_loader(ch.name, ch))
    ch.exec_module(m)
    vus = []

    def gardes(cible, lancer, exiger=False):
        vus.append(exiger)
        return [ipaddress.ip_network("203.0.113.0/24")], set(), {ipaddress.ip_address(PAIR)}, []
    monkeypatch.setattr(m, "_gardes", gardes)
    monkeypatch.setattr(sys, "stdin", io.StringIO(f"{A}\n{C}\n{PAIR}\n198.51.100.0/24\n10.0.0.1\nrien\n2a01::1%eth0;\n"))
    assert m.main(["verifier-lot"]) == 0
    assert json.loads(capsys.readouterr().out) == {A: None, C: "protegee", PAIR: "pair", "198.51.100.0/24": "invalide",
                                                   "10.0.0.1": "privee", "rien": "invalide",
                                                   "2a01::1%eth0;": "invalide"}
    assert vus == [True]
    monkeypatch.setattr(sys, "stdin", io.StringIO("\n".join(f"198.51.100.{i}" for i in range(201))))
    assert m.main(["verifier-lot"]) != 0
