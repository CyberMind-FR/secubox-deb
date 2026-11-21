# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""#3723, revue finale des phases 4-7 : porte SADE sans fichier (I1), OBSERVE refuse tout (I2), préfixes LAN de la
box (I3), jamais d'écrasement entre gestes IA et gestes SADE (I4), pairs sur les clics (M1), plafond des levées (M4),
`non_vue` avant le DNS (M5).

Banc de #3716/#3723 (wafctl simulé) pour les routes ; wafctl réel avec de faux `nft`/`waf-blocs` pour les verbes ;
waf-blocs importé pour ses gardes. Rien ne touche un pare-feu ni une box.
"""
from __future__ import annotations

import importlib.machinery
import importlib.util
import json
import os
import secrets
import subprocess
import time
from pathlib import Path

import pytest

from .test_gestes_ia_3716 import _ban_journal, c  # noqa: F401  (fixture `c` réutilisée)
from .test_gestes_ia_3723 import _motif, gk2_simule  # noqa: F401  (fixture réutilisée)

IP4, IP6 = "198.51.100.7", "2001:db8:1::7"
COMPOSANT = Path(__file__).resolve().parent.parent
WAFCTL = COMPOSANT / "scripts" / "wafctl"


@pytest.fixture
def g(gk2_simule, tmp_path, monkeypatch):  # noqa: F811
    f = gk2_simule.faux
    now = int(time.time())
    f.reponses["limiter"] = (0, json.dumps({"fin": now + 21600}) + "\n", "")
    f.reponses["limiter-lever"] = (0, "[..] limiter-lever ok\n", "")
    f.reponses["leurre"] = (0, json.dumps({"fin": now + 86400}) + "\n", "")
    f.reponses["leurre-lever"] = (0, "[..] leurre-lever ok\n", "")
    f.reponses["indice-partager"] = (0, json.dumps({"expire": now + 86400}) + "\n", "")
    f.reponses["indice-retirer"] = (0, "[..] indice-retirer ok\n", "")
    # aucun secubox-soc sur le poste de test, sauf si un test le pose
    monkeypatch.setattr(gk2_simule.g, "MARQUEURS_SOC", (tmp_path / "soc-absent",))
    return gk2_simule


def _post(g, route, **corps):
    return g.c.post(f"/ai/{route}", json=corps)


def _limiter(g, cible=IP4, mode="auto", duree_s=21600):
    return _post(g, "limiter", geste="limiter", cible=cible, duree_s=duree_s, conseil="c-3", motif="", mode=mode)


def _leurre(g, cible=IP4, mode="auto"):
    return _post(g, "leurre", geste="leurre", cible=cible, duree_s=86400, conseil="c-4", motif="", mode=mode)


def _partager(g, cible=IP4, mode="auto"):
    return _post(g, "partager", geste="partager", cible=cible, duree_s=86400, conseil="c-5", famille="scanners",
                 mode=mode)


def _entree(type_, cible, fin=None):
    m = int(time.time())
    geste = {"limite": "limiter", "leurre": "leurre", "partage": "partager"}[type_]
    return {"ts": "", "at": m - 60, "type": type_, "geste": geste, "id": secrets.token_hex(16), "cible": cible,
            "fin": m + 3600 if fin is None else fin, "mode": "auto", "conseil": "c-0", "motif": "", "duree_s": 3600}


# ── I1 : fichier du mode absent alors que secubox-soc est installé ─────
def test_fichier_absent_soc_installe_vaut_observe(g, tmp_path, monkeypatch):
    marqueur = tmp_path / "defense.db"
    marqueur.write_text("")
    monkeypatch.setattr(g.g, "MARQUEURS_SOC", (tmp_path / "rien", marqueur))
    assert not g.g.FICHIER_SADE.exists()
    assert g.g.mode_sade() == "observe"
    g.menace(IP4)
    assert _motif(g.ban(IP4, mode="auto")) == "sade_observe"
    assert _motif(g.ban("198.51.100.8")) == "sade_observe"             # OBSERVE : le clic aussi (I2)
    assert _motif(_limiter(g)) == "sade_observe"
    assert g.faux.appels == []
    assert g.c.get("/ai/etat").json()["sade_mode"] == "observe"


def test_fichier_absent_sans_soc_aucune_porte(g):
    assert g.g.mode_sade() is None
    assert g.ban("198.51.100.8").status_code == 200


def test_marqueurs_soc_par_defaut():
    from api import gestes_ia as _g
    assert Path("/var/lib/secubox/soc/defense.db") in [Path(p) for p in _g.MARQUEURS_SOC]
    assert any(str(p).endswith("systemd/system/secubox-soc.service") for p in _g.MARQUEURS_SOC)


def test_indices_des_pairs_fichier_absent_soc_installe_refuse(g, tmp_path, monkeypatch):
    from api import indices_ip
    marqueur = tmp_path / "defense.db"
    marqueur.write_text("")
    monkeypatch.setattr(g.g, "MARQUEURS_SOC", (marqueur,))
    issue, motif = indices_ip.appliquer(IP4, "scanners", g.g.lire_sade())
    assert motif == "sade_observe" and issue != "banni"
    assert "ban" not in g.faux.verbes()


# ── I2 : OBSERVE refuse tout geste, REACTIVE admet tous les clics ──────
def test_observe_refuse_tous_les_gestes_clic_compris(g):
    g.sade("observe")
    e = g.ban("198.51.100.9")
    assert _motif(e) == "sade_observe"
    assert _motif(_limiter(g, mode="clic")) == "sade_observe"
    assert _motif(_leurre(g, mode="clic")) == "sade_observe"
    assert _motif(_partager(g, mode="clic")) == "sade_observe"
    now = int(time.time())
    b = _ban_journal(IP4, now - 100, now + 3600, mode="clic")
    g.journal(b)
    assert _motif(g.prolonger(b["id"], 172800, mode="clic")) == "sade_observe"
    assert g.faux.appels == []


def test_reactive_clics_de_tous_les_gestes_admis(g):
    g.sade("reactive")
    g.bans = [{"ip": IP4, "reason": "scanners"}]                       # partager : bannie sur gk2
    assert _motif(_leurre(g, cible="198.51.100.20", mode="auto")) == "sade_reactive"
    assert _motif(_partager(g, mode="auto")) == "sade_reactive"
    assert _limiter(g, cible="198.51.100.21", mode="auto").status_code == 200       # seul geste d'office admis
    assert _leurre(g, cible="198.51.100.22", mode="clic").status_code == 200
    assert _partager(g, mode="clic").status_code == 200
    now = int(time.time())
    b = _ban_journal("198.51.100.23", now - 100, now + 3600, mode="clic")
    g.journal(b)
    assert _motif(g.prolonger(b["id"], 172800, mode="auto")) == "sade_reactive"
    assert g.prolonger(b["id"], 172800, mode="clic").status_code == 200


@pytest.mark.parametrize("route", ["limiter", "leurre", "partager", "prolonger"])
def test_mode_obligatoire(g, route):
    corps = {"limiter": dict(geste="limiter", cible=IP4, duree_s=3600, conseil="c"),
             "leurre": dict(geste="leurre", cible=IP4, duree_s=3600, conseil="c"),
             "partager": dict(geste="partager", cible=IP4, duree_s=3600, conseil="c", famille="x"),
             "prolonger": dict(geste="prolonger", id="0" * 32, duree_s=3600, conseil="c")}[route]
    assert _post(g, route, **corps).status_code == 422
    assert _post(g, route, **corps, mode="tout").status_code == 422


# ── I3 : motif `lan` rendu par la garde root ───────────────────────────
def test_motif_lan_de_la_garde_rendu_en_409(g):
    g.faux.reponses["limiter"] = (1, "", "refus:lan\n")
    r = _limiter(g, cible=IP6)
    assert r.status_code == 409 and _motif(r) == "lan"


def _waf_blocs():
    chargeur = importlib.machinery.SourceFileLoader("waf_blocs_rf", str(COMPOSANT / "scripts" / "waf-blocs"))
    spec = importlib.util.spec_from_loader("waf_blocs_rf", chargeur)
    module = importlib.util.module_from_spec(spec)
    chargeur.exec_module(module)
    return module


IP_ADDR = json.dumps([
    {"ifname": "lo", "addr_info": [{"family": "inet", "local": "127.0.0.1", "prefixlen": 8, "scope": "host"}]},
    {"ifname": "br-lan", "addr_info": [
        {"family": "inet", "local": "192.168.1.1", "prefixlen": 24, "scope": "global"},
        {"family": "inet6", "local": "2a01:e0a:1:2::1", "prefixlen": 64, "scope": "global"},
        {"family": "inet6", "local": "fe80::1", "prefixlen": 64, "scope": "link"}]},
    {"ifname": "eth2", "addr_info": [{"family": "inet", "local": "82.64.10.5", "prefixlen": 32, "scope": "global"}]},
])


def _lancer_ip(sortie=IP_ADDR):
    def lancer(argv):
        if argv[-2:] == ["-j", "addr"]:
            return sortie
        if "wg" in argv[0]:
            return ""
        raise AssertionError(argv)
    return lancer


def test_waf_blocs_prefixe_global_on_link_motif_lan():
    wb = _waf_blocs()
    locales, prefixes = wb.adresses_et_prefixes(_lancer_ip())
    assert wb.ipaddress.ip_network("2a01:e0a:1:2::/64") in prefixes
    assert not any(n.version == 6 and n.network_address.is_link_local for n in prefixes)
    cible = wb.normaliser_cible("2a01:e0a:1:2::99")
    assert wb.motif_refus(cible, [], locales, set(), prefixes) == "lan"
    assert wb.motif_refus(wb.normaliser_cible("2a01:e0a:1:2::1"), [], locales, set(), prefixes) == "box"
    assert wb.motif_refus(wb.normaliser_cible("2a01:e0a:1:3::1"), [], locales, set(), prefixes) is None
    assert wb.CODES["lan"] not in (0, 64) and len(set(wb.CODES.values())) == len(wb.CODES)


def test_waf_blocs_verifier_refuse_le_lan(monkeypatch, tmp_path, capsys):
    wb = _waf_blocs()
    monkeypatch.setattr(wb, "executer", lambda argv, entree=None: _lancer_ip()(argv))
    monkeypatch.setattr(wb, "PROTEGEES_ENV", tmp_path / "absent.env")
    assert wb.main(["verifier", "2a01:e0a:1:2::99"]) == wb.CODES["lan"]
    assert json.loads(capsys.readouterr().out.splitlines()[-1])["motif"] == "lan"


# ── I4 : jamais d'écrasement entre gestes IA et gestes SADE ────────────
def _wafctl(tmp_path, reste="", code_get=0):
    """wafctl réel ; `nft -j get element` rend `reste` (JSON nft) ; le lot de `nft -f` est noté."""
    bin_ = tmp_path / "bin"
    bin_.mkdir(exist_ok=True)
    garde = bin_ / "waf-blocs"
    garde.write_text('#!/bin/bash\necho \'{"ok": true, "motif": null}\'\n')
    (tmp_path / "reste.json").write_text(reste)
    nft = bin_ / "nft"
    nft.write_text(f'#!/bin/bash\necho "$*" >> {tmp_path}/nft.log\n'
                   f'if [ "$1" = "-f" ]; then cat >> {tmp_path}/lot.nft; exit 0; fi\n'
                   f'if [ "$1" = "-j" ] && [ "$2" = "get" ]; then [ {code_get} -eq 0 ] || exit {code_get}; '
                   f'cat {tmp_path}/reste.json; exit 0; fi\n'
                   f'case "$1" in get) exit {code_get} ;; esac\nexit 0\n')
    for f in (garde, nft):
        f.chmod(0o755)
    dossier = tmp_path / "waf"
    dossier.mkdir(exist_ok=True)
    texte = WAFCTL.read_text()
    script = tmp_path / "wafctl"
    script.write_text(texte.replace("/usr/sbin/waf-blocs", str(garde))
                      .replace('LEURRES_IP="/var/lib/secubox/waf/leurres-ip.json"',
                               f'LEURRES_IP="{dossier}/leurres-ip.json"'))
    env = {**os.environ, "PATH": f"{bin_}:{os.environ['PATH']}"}

    def lancer(*args):
        return subprocess.run(["bash", str(script), *args], check=False, timeout=30, capture_output=True,
                              text=True, env=env)
    return lancer, dossier / "leurres-ip.json"


def _reste(ip, ensemble, expires, table="secubox_waf_ratelimit"):
    el = {"elem": {"val": ip, "timeout": expires + 10, "expires": expires}} if expires is not None else ip
    return json.dumps({"nftables": [{"metainfo": {}}, {"set": {"family": "inet", "name": ensemble, "table": table,
                                                                "elem": [el]}}]})


def test_wafctl_limiter_garde_la_fin_la_plus_tardive(tmp_path):
    lancer, _ = _wafctl(tmp_path, reste=_reste(IP4, "limite_ia_v4", 80000))
    r = lancer("limiter", IP4, "3600s")
    assert r.returncode == 0, r.stderr
    assert "timeout 80000s" in (tmp_path / "lot.nft").read_text()
    fin = json.loads(r.stdout.strip().splitlines()[-1])["fin"]
    assert abs(fin - (int(time.time()) + 80000)) <= 5


def test_wafctl_limiter_allonge_une_limite_plus_courte(tmp_path):
    lancer, _ = _wafctl(tmp_path, reste=_reste(IP4, "limite_ia_v4", 600))
    assert lancer("limiter", IP4, "3600s").returncode == 0
    assert "timeout 3600s" in (tmp_path / "lot.nft").read_text()


def test_wafctl_prolonger_garde_la_fin_la_plus_tardive(tmp_path):
    lancer, _ = _wafctl(tmp_path, reste=_reste(IP4, "waf_ban", 500000, table="secubox"))
    assert lancer("prolonger", IP4, "172800s").returncode == 0, "prolonger"
    assert "timeout 500000s" in (tmp_path / "lot.nft").read_text()


def test_wafctl_ban_ne_raccourcit_pas_un_ban_plus_long(tmp_path):
    lancer, _ = _wafctl(tmp_path, reste=_reste(IP4, "waf_ban", 500000, table="secubox"))
    r = lancer("ban", IP4, "86400s")
    assert r.returncode == 0, r.stderr
    assert not (tmp_path / "lot.nft").exists()
    assert not any(x.startswith("add element") for x in (tmp_path / "nft.log").read_text().splitlines())


def test_wafctl_ban_allonge_un_ban_plus_court(tmp_path):
    lancer, _ = _wafctl(tmp_path, reste=_reste(IP4, "waf_ban", 600, table="secubox"))
    assert lancer("ban", IP4, "86400s").returncode == 0
    assert (tmp_path / "lot.nft").read_text() == (f"delete element inet secubox waf_ban {{ {IP4} }}\n"
                                                  f"add element inet secubox waf_ban {{ {IP4} timeout 86400s }}\n")


def test_wafctl_leurre_garde_la_fin_la_plus_tardive(tmp_path):
    lancer, liste = _wafctl(tmp_path)
    assert lancer("leurre", IP4, "604800s").returncode == 0
    fin_longue = json.loads(liste.read_text())["entrees"][IP4]["fin"]
    r = lancer("leurre", IP4, "3600s")
    assert r.returncode == 0, r.stderr
    assert json.loads(liste.read_text())["entrees"][IP4]["fin"] == fin_longue
    assert json.loads(r.stdout.strip().splitlines()[-1])["fin"] == fin_longue


def test_wafctl_limiter_lever_refuse_une_limite_allongee_par_un_autre(tmp_path):
    fin = int(time.time()) + 3600
    lancer, _ = _wafctl(tmp_path, reste=_reste(IP4, "limite_ia_v4", 80000))
    r = lancer("limiter-lever", IP4, str(fin))
    assert r.returncode == 1 and "refus:couvert" in r.stderr
    assert not any(x.startswith("delete") for x in (tmp_path / "nft.log").read_text().splitlines())
    autre = tmp_path / "b"
    autre.mkdir()
    lancer, _ = _wafctl(autre, reste=_reste(IP4, "limite_ia_v4", 3590))
    assert lancer("limiter-lever", IP4, str(fin)).returncode == 0      # la sienne : levée


def test_wafctl_leurre_lever_refuse_un_leurre_allonge_par_un_autre(tmp_path):
    lancer, liste = _wafctl(tmp_path)
    assert lancer("leurre", IP4, "604800s").returncode == 0
    r = lancer("leurre-lever", IP4, str(int(time.time()) + 3600))
    assert r.returncode == 1 and "refus:couvert" in r.stderr
    assert IP4 in json.loads(liste.read_text())["entrees"]
    assert lancer("leurre-lever", IP4, str(int(time.time()) + 604800)).returncode == 0
    assert IP4 not in json.loads(liste.read_text())["entrees"]


def test_wafctl_unban_refuse_un_ban_prolonge_par_un_autre(tmp_path):
    lancer, _ = _wafctl(tmp_path, reste=_reste(IP4, "waf_ban", 500000, table="secubox"))
    r = lancer("unban", IP4, str(int(time.time()) + 3600))
    assert r.returncode == 1 and "refus:couvert" in r.stderr
    assert not any(x.startswith("delete") for x in (tmp_path / "nft.log").read_text().splitlines())


def test_wafctl_levee_conditionnelle_etat_illisible_refuse(tmp_path):
    lancer, _ = _wafctl(tmp_path, reste="pas du json")
    r = lancer("limiter-lever", IP4, str(int(time.time()) + 3600))
    assert r.returncode == 1 and "refus:etat" in r.stderr
    assert lancer("limiter-lever", IP4, "x").returncode != 0                # forme de la fin


def test_route_lever_passe_la_fin_et_rend_couvert(g):
    e = _entree("limite", IP6)
    g.journal(e)
    g.faux.reponses["limiter-lever"] = (1, "", "refus:couvert\n")
    r = _post(g, "lever", geste="lever", cible_geste="limiter", id=e["id"])
    assert r.status_code == 409 and _motif(r) == "couvert"
    assert g.faux.appel("limiter-lever")[-2:] == [IP6, str(e["fin"])]
    assert g.lignes_journal()[-1]["type"] == "limite"                    # rien n'est clos
    assert g.c.get("/ai/etat").json()["limites"][0]["id"] == e["id"]


@pytest.mark.parametrize("type_,verbe", [("limite", "limiter-lever"), ("leurre", "leurre-lever")])
def test_route_unban_d_un_geste_sans_ban_passe_la_fin(g, type_, verbe):
    e = _entree(type_, IP4)
    g.journal(e)
    g.faux.reponses[verbe] = (1, "", "refus:couvert\n")
    r = _post(g, "unban", geste="unban", id=e["id"])
    assert r.status_code == 409 and _motif(r) == "couvert"
    assert g.faux.appel(verbe)[-2:] == [IP4, str(e["fin"])]


def test_route_unban_d_un_ban_prolonge_par_sade_rend_couvert(g):
    now = int(time.time())
    b = _ban_journal(IP4, now - 100, now + 3600)
    g.journal(b)
    g.faux.reponses["unban"] = (1, "", "refus:couvert\n")
    r = _post(g, "unban", geste="unban", id=b["id"])
    assert r.status_code == 409 and _motif(r) == "couvert"
    assert g.faux.appel("unban")[-2:] == [IP4, str(b["fin"])]
    assert g.lignes_journal()[-1]["type"] == "ban"


def test_retour_arriere_ne_leve_que_ce_qu_ai_ban_a_pose(g, monkeypatch):
    """L'audit final échoue : le retour arrière de la limite porte la fin demandée (wafctl refuse si un autre l'a
    allongée)."""
    vrai = g.g._config["audit"]

    def audit(action, detail, user):
        if action == "ai-limiter":
            raise OSError("disque plein")
        vrai(action, detail, user)
    monkeypatch.setitem(g.g._config, "audit", audit)
    r = _limiter(g, cible=IP6)
    assert r.status_code == 500
    levee = g.faux.appel("limiter-lever")
    assert levee[-2] == IP6 and abs(int(levee[-1]) - (int(time.time()) + 21600)) <= 5


# ── M1 : garde des pairs du maillage sur les clics ─────────────────────
def test_clic_jamais_sur_un_pair_du_maillage(g, monkeypatch):
    monkeypatch.setattr(g.g, "_lire_threatmesh_peers", lambda: {"node": "gk2", "peers": [{"ip": IP4}]})
    r = g.ban(IP4)
    assert r.status_code == 409 and _motif(r) == "protegee"
    assert g.faux.appels == []


def test_clic_source_des_pairs_muette_refuse(g):
    g.g.WG_MESH.write_text("{tronqué")
    assert _motif(g.ban("198.51.100.8")) == "protegee_inconnue"


def test_clic_robot_verifie_reste_admis(g, monkeypatch):
    monkeypatch.setattr(g.g, "_fcrdns", lambda ip: "googlebot.com")
    assert g.ban(IP4).status_code == 200                                 # le clic reste à l'humain (robots)


# ── M4 : plafond des levées ────────────────────────────────────────────
def test_unban_plafond_30_par_heure(g):
    now = int(time.time())
    lignes = []
    for i in range(30):
        b = _ban_journal(f"192.0.2.{i + 1}", now - 200, now + 3600)
        lignes += [b, {"ts": "", "at": now - 100 + i, "type": "annule", "geste": "unban", "id": b["id"],
                       "cible": b["cible"], "cause": "unban"}]
    autre = _ban_journal(IP4, now - 200, now + 3600)
    g.journal(*lignes, autre)
    r = _post(g, "unban", geste="unban", id=autre["id"])
    assert r.status_code == 409 and _motif(r) == "plafond_heure"
    assert "unban" not in g.faux.verbes()


def test_unban_plafond_100_par_jour(g):
    now = int(time.time())
    lignes = []
    for i in range(100):
        b = _ban_journal(f"192.0.2.{i + 1}", now - 80000, now + 3600)
        lignes += [b, {"ts": "", "at": now - 80000 + i, "type": "annule", "geste": "unban", "id": b["id"],
                       "cible": b["cible"], "cause": "unban"}]
    autre = _ban_journal(IP4, now - 200, now + 3600)
    g.journal(*lignes, autre)
    assert _motif(_post(g, "unban", geste="unban", id=autre["id"])) == "plafond_jour"


# ── M5 : `non_vue` avant toute requête DNS ─────────────────────────────
def test_non_vue_avant_la_resolution_ptr(g, monkeypatch):
    def interdit(ip):
        raise AssertionError("requête DNS vers une adresse jamais vue")
    monkeypatch.setattr(g.g, "_fcrdns", interdit)
    assert _motif(g.ban(IP4, mode="auto")) == "non_vue"


# ── M3 : socle § 10 complet de secubox-waf-indices.service, compatible avec sudo ─
def test_unite_indices_socle_complet_compatible_sudo():
    unite = (COMPOSANT.parents[1] / "systemd" / "secubox-waf-indices.service").read_text()
    lignes = set(unite.splitlines())
    for ligne in ("PrivateDevices=yes", "RestrictNamespaces=yes", "RestrictSUIDSGID=yes", "ProtectClock=yes",
                  "ProtectHostname=yes", "MemoryDenyWriteExecute=yes", "SystemCallFilter=@system-service",
                  "SystemCallErrorNumber=EPERM", "NoNewPrivileges=no"):
        assert ligne in lignes, ligne
    cap = next(x for x in lignes if x.startswith("CapabilityBoundingSet="))
    # ce que sudo (changer d'identité, audit), nft / wg (netlink) et wafctl (écriture du dossier du WAF) exigent
    assert set(cap.split("=", 1)[1].split()) == {"CAP_SETUID", "CAP_SETGID", "CAP_AUDIT_WRITE", "CAP_NET_ADMIN",
                                                 "CAP_DAC_OVERRIDE", "CAP_SYS_RESOURCE"}
    regles = (COMPOSANT.parents[3] / ".claude" / "RULES-CODE.md").read_text()
    ligne = next(x for x in regles.splitlines() if "`secubox-waf-indices.service`" in x)
    assert "CapabilityBoundingSet" in ligne and "et `RestrictSUIDSGID`" not in ligne    # l'ancienne raison, fausse
