# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""#3723, tâche 2 : geste `limiter` (limite de débit par adresse, IPv4 et IPv6), `POST /ai/limiter`.

`wafctl` simulé pour la route (banc de #3716/#3723) ; `wafctl` réel avec un faux `nft` pour les verbes ; le fichier
nft vérifié par `nft -c` dans un espace de noms réseau jetable (sauté si `nft` ou `unshare` manquent).
"""
from __future__ import annotations

import json
import re
import secrets
import shutil
import subprocess
import time
from pathlib import Path

import pytest

from .test_gestes_ia_3716 import _ban_journal, c  # noqa: F401  (fixture `c` réutilisée)
from .test_gestes_ia_3723 import Gk2, _motif, _wafctl_banc, gk2_simule  # noqa: F401  (fixture réutilisée)

IP4, IP6 = "198.51.100.7", "2001:db8:1::7"
COMPOSANT = Path(__file__).resolve().parent.parent
NFT = COMPOSANT.parents[1] / "config" / "secubox-waf-ratelimit.nft"


@pytest.fixture
def g(gk2_simule):  # noqa: F811
    gk2_simule.faux.reponses["limiter"] = (0, json.dumps({"fin": int(time.time()) + 21600}) + "\n", "")
    gk2_simule.faux.reponses["limiter-lever"] = (0, "[..] limiter-lever ok\n", "")
    return gk2_simule


def _limiter(g: Gk2, cible=IP4, duree_s=21600, **extra):
    return g.c.post("/ai/limiter", json={"geste": "limiter", "cible": cible, "duree_s": duree_s, "conseil": "c-3",
                                         "motif": "", "mode": "auto", **extra})


def _limite_journal(cible, at, fin):
    return {"ts": "", "at": at, "type": "limite", "geste": "limiter", "id": secrets.token_hex(16), "cible": cible,
            "fin": fin, "mode": "auto", "conseil": "c-0", "motif": "", "duree_s": fin - at}


# ── route ──────────────────────────────────────────────────────────────
@pytest.mark.parametrize("cible", [IP4, IP6])
def test_limiter_pose_element_avec_timeout(g, cible):
    r = _limiter(g, cible)
    assert r.status_code == 200, r.text
    assert g.faux.appel("limiter")[-2:] == [cible, "21600s"]
    assert g.faux.appel("limiter")[:3] == ["sudo", "-n", "/usr/sbin/wafctl"]
    ligne = g.lignes_journal()[-1]
    assert ligne["type"] == "limite" and ligne["geste"] == "limiter" and ligne["cible"] == cible
    assert ligne["fin"] == r.json()["fin"] and r.json()["id"] == ligne["id"]
    actions = [x["action"] for x in g.audit()]
    assert actions.index("ai-limiter-demande") < actions.index("ai-limiter")
    e = g.c.get("/ai/etat").json()
    assert [x["cible"] for x in e["limites"]] == [cible]
    assert e["actifs"] == []                                            # une limite n'est pas un ban
    assert e["plafonds_par_geste"]["limiter"]["restant_heure"] == 59


@pytest.mark.parametrize("cible", ["10.0.0.1", "fd00::1", "fe80::1", "::1", "::ffff:198.51.100.7", "2002:c000:204::1",
                                   "64:ff9b::c000:201", "198.51.100.0/24", "2001:DB8:1::7", "2001:db8:1:0::7", "x"])
def test_limiter_forme_refusee_422(g, cible):
    assert _limiter(g, cible).status_code == 422
    assert g.faux.appels == []


def test_limiter_refuse_protegee(g, monkeypatch):
    g.sade("active", liste=["2001:db8:1::/48"])
    r = _limiter(g, IP6)
    assert r.status_code == 409 and _motif(r) == "protegee"            # liste blanche SADE, IPv6 comprise
    g.sade("active")
    monkeypatch.setattr(g.g, "_lire_threatmesh_peers", lambda: {"peers": [{"address": f"[{IP6}]:7000"}]})
    assert _motif(_limiter(g, IP6)) == "protegee"                       # pair du maillage
    monkeypatch.setattr(g.g, "_lire_threatmesh_peers", lambda: {"peers": []})
    monkeypatch.setattr(g.g, "_fcrdns", lambda ip: "googlebot.com")
    assert _motif(_limiter(g, IP4)) == "protegee"                       # robot vérifié
    monkeypatch.setattr(g.g, "_fcrdns", lambda ip: "")
    assert g.faux.appels == []
    g.faux.reponses["limiter"] = (1, "", "refus:protegee\n")            # Freebox (protegees.env), garde root
    assert _motif(_limiter(g, IP4)) == "protegee"
    g.faux.reponses["limiter"] = (1, "", "refus:box\n")
    assert _motif(_limiter(g, IP4)) == "box"
    assert not [e for e in g.lignes_journal() if e["type"] == "limite"]


def test_limiter_source_muette_refuse(g):
    g.g.WG_MESH.write_text("{tronqué")
    assert _motif(_limiter(g)) == "protegee_inconnue"
    assert g.faux.appels == []


@pytest.mark.parametrize("duree", [3599, 86401, 604800])
def test_limiter_duree_hors_bornes(g, duree):
    r = _limiter(g, duree_s=duree)
    assert r.status_code == 409 and _motif(r) == "duree"
    assert g.faux.appels == []


def test_limiter_bornes_admises(g):
    assert _limiter(g, IP4, 3600).status_code == 200
    assert _limiter(g, IP6, 86400).status_code == 200


def test_limiter_plafond_60h(g):
    now = int(time.time())
    g.journal(*[_limite_journal(f"192.0.2.{i}", now - 50 * i - 1, now - 1) for i in range(60)])
    r = _limiter(g)
    assert r.status_code == 409 and _motif(r) == "plafond_heure"
    # les bans ont leurs propres plafonds
    g.menace(IP4)
    assert g.ban(IP4, mode="auto").status_code == 200


def test_limiter_plafond_400_jour(g):
    now = int(time.time())
    g.journal(*[_limite_journal(f"192.0.2.{i % 250}", now - 3600 - 200 * i, now - 1) for i in range(400)])
    assert _motif(_limiter(g)) == "plafond_jour"


def test_limiter_deja_limitee(g):
    assert _limiter(g).status_code == 200
    assert _motif(_limiter(g)) == "deja_actif"
    assert g.ban(IP4).status_code == 200                                # un ban (plus fort) reste possible


def test_limiter_porte_sade(g):
    g.sade("observe")
    assert _motif(_limiter(g)) == "sade_observe"
    g.sade("reactive")                                                  # le seul geste d'office admis en reactive
    assert _limiter(g).status_code == 200
    g.menace("198.51.100.8")
    assert _motif(g.ban("198.51.100.8", mode="auto")) == "sade_reactive"


def test_limiter_audit_demande_impossible_rien_n_est_fait(g, monkeypatch):
    vrai = g.g._config["audit"]

    def audit(action, detail, user):
        if action == "ai-limiter-demande":
            raise OSError("disque plein")
        vrai(action, detail, user)
    monkeypatch.setitem(g.g._config, "audit", audit)
    assert _motif(_limiter(g)) == "audit"
    assert g.faux.appels == []


def test_limiter_audit_final_impossible_la_limite_est_levee(g, monkeypatch):
    vrai = g.g._config["audit"]

    def audit(action, detail, user):
        if action == "ai-limiter":
            raise OSError("disque plein")
        vrai(action, detail, user)
    monkeypatch.setitem(g.g._config, "audit", audit)
    r = _limiter(g)
    assert r.status_code == 500 and _motif(r) == "audit"
    assert g.faux.appel("limiter-lever")[-2] == IP4
    assert g.lignes_journal()[-1]["type"] == "annule"


def test_unban_d_une_limite_la_leve(g):
    ident = _limiter(g, IP6).json()["id"]
    r = g.c.post("/ai/unban", json={"geste": "unban", "id": ident})
    assert r.status_code == 200 and r.json()["etat"] == "annule"
    assert g.faux.appel("limiter-lever")[-2] == IP6
    assert g.c.get("/ai/etat").json()["limites"] == []
    assert g.prolonger(ident, 172800).json()["detail"]["motif"] == "inconnu"   # une limite ne se prolonge pas


# ── wafctl ─────────────────────────────────────────────────────────────
@pytest.mark.parametrize("ip,ensemble", [(IP4, "limite_ia_v4"), (IP6, "limite_ia_v6")])
def test_wafctl_limiter_une_transaction(tmp_path, ip, ensemble):
    r = _wafctl_banc(tmp_path)("limiter", ip, "21600s")
    assert r.returncode == 0, r.stderr
    lot = (tmp_path / "lot.nft").read_text()
    assert lot == (f"add element inet secubox_waf_ratelimit {ensemble} {{ {ip} }}\n"
                   f"delete element inet secubox_waf_ratelimit {ensemble} {{ {ip} }}\n"
                   f"add element inet secubox_waf_ratelimit {ensemble} {{ {ip} timeout 21600s }}\n")
    fin = json.loads(r.stdout.strip().splitlines()[-1])["fin"]
    assert abs(fin - (int(time.time()) + 21600)) <= 5
    assert (tmp_path / "garde.log").read_text().split() == ["verifier", ip, "--exiger"]


@pytest.mark.parametrize("args", [("limiter", IP4), ("limiter", IP4, "1h", "x"), ("limiter", "10.0.0.1", "1h"),
                                  ("limiter", IP4, "3599s"), ("limiter", IP4, "86401s"), ("limiter", IP4, "1w"),
                                  ("limiter", "fe80::1", "1h"), ("limiter-lever",), ("limiter-lever", IP4, "x")])
def test_wafctl_limiter_arguments_refuses(tmp_path, args):
    r = _wafctl_banc(tmp_path)(*args)
    assert r.returncode != 0, args
    assert not (tmp_path / "lot.nft").exists()


def test_wafctl_limiter_duree_hors_bornes_motif(tmp_path):
    r = _wafctl_banc(tmp_path)("limiter", IP4, "86401s")
    assert "refus:duree" in r.stderr


def test_wafctl_limiter_garde(tmp_path):
    r = _wafctl_banc(tmp_path, code_garde=6)("limiter", IP4, "3600s")
    assert r.returncode == 1 and "refus:garde_illisible" in r.stderr
    assert not (tmp_path / "lot.nft").exists()


def test_wafctl_limiter_lever(tmp_path):
    r = _wafctl_banc(tmp_path)("limiter-lever", IP6)
    assert r.returncode == 0, r.stderr
    assert "delete element inet secubox_waf_ratelimit limite_ia_v6 { 2001:db8:1::7 }" in (tmp_path / "nft.log").read_text()


def test_sudoers_limiter_exact():
    s = (COMPOSANT / "sudoers" / "secubox-waf").read_text()
    assert re.search(r"Cmnd_Alias SBX_WAF_LIMITER = /usr/sbin/wafctl limiter \*, \\\n\s+/usr/sbin/wafctl limiter-lever \*\n", s)
    assert "secubox ALL=(root) NOPASSWD: SBX_WAF_LIMITER" in s


# ── fichier nft ────────────────────────────────────────────────────────
def test_aucune_reponse_emise():
    """La limite ne fait que jeter (`drop`) : jamais `reject` ni `redirect`, jamais de réponse vers l'attaquant."""
    texte = NFT.read_text()
    regles = [ligne for ligne in texte.splitlines() if "limite_ia_v" in ligne and not ligne.strip().startswith("#")
              and "saddr" in ligne]
    assert len(regles) == 2
    for r in regles:
        assert r.rstrip().endswith("drop") and "limit rate over 5/second burst 20 packets" in r
        assert "tcp dport { 80, 443 }" in r
    code = "\n".join(x for x in texte.splitlines() if not x.strip().startswith("#"))
    for interdit in ("reject", "redirect", "dnat", "queue", "dup "):
        assert interdit not in code


def test_ensembles_limite_ia():
    texte = NFT.read_text()
    for v, t in (("v4", "ipv4_addr"), ("v6", "ipv6_addr")):
        bloc = re.search(r"set limite_ia_%s \{(.*?)\}" % v, texte, re.S).group(1)
        assert f"type {t}" in bloc and "flags timeout" in bloc and "size 4096" in bloc


def test_lan_jamais_limite():
    """La liste blanche LAN est acceptée AVANT les règles de limite."""
    texte = NFT.read_text()
    assert texte.index("ip saddr @whitelist_v4 accept") < texte.index("ip saddr @limite_ia_v4")


def test_fichier_nft_valide(tmp_path):
    if not shutil.which("nft") or not shutil.which("unshare"):
        pytest.skip("nft ou unshare absent")
    r = subprocess.run(["unshare", "-rn", "nft", "-c", "-f", str(NFT)], check=False, timeout=30, capture_output=True,
                       text=True)
    if r.returncode != 0 and ("Operation not permitted" in r.stderr or "unshare" in r.stderr):
        pytest.skip(f"espace de noms indisponible : {r.stderr.strip()[:80]}")
    assert r.returncode == 0, r.stderr
