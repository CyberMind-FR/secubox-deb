# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""#3723, tâche 3 : geste `leurre` (une adresse d'attaquant redirigée vers le théâtre de sbxwaf), `POST /ai/leurre`.

`wafctl` simulé pour la route (banc de #3716/#3723) ; `wafctl` réel, avec un faux `waf-blocs` et le fichier de la liste
dans le dossier du test, pour les verbes `leurre` et `leurre-lever`.
"""
from __future__ import annotations

import json
import os
import re
import secrets
import stat
import subprocess
import time
from pathlib import Path

import pytest

from .test_gestes_ia_3716 import _ban_journal, c  # noqa: F401  (fixture `c` réutilisée)
from .test_gestes_ia_3723 import Gk2, _motif, gk2_simule  # noqa: F401  (fixture réutilisée)

IP4, IP6 = "198.51.100.7", "2001:db8:1::7"
COMPOSANT = Path(__file__).resolve().parent.parent
WAFCTL = COMPOSANT / "scripts" / "wafctl"
SERVICE = COMPOSANT.parents[1] / "systemd" / "secubox-waf-ng.service"


def _nft6(*adresses):
    return (0, json.dumps({"nftables": [{"metainfo": {}}, {"set": {"name": "waf_ban6", "elem": list(adresses)}}]}), "")


@pytest.fixture
def g(gk2_simule):  # noqa: F811
    gk2_simule.faux.reponses["leurre"] = (0, json.dumps({"fin": int(time.time()) + 86400}) + "\n", "")
    gk2_simule.faux.reponses["leurre-lever"] = (0, "[..] leurre-lever ok\n", "")
    return gk2_simule


def _leurre(g: Gk2, cible=IP4, duree_s=86400, garder_nft=False, **extra):
    if ":" in cible and not garder_nft:
        g.faux.reponses["nft"] = _nft6()                                # waf_ban6 vide
    return g.c.post("/ai/leurre", json={"geste": "leurre", "cible": cible, "duree_s": duree_s, "conseil": "c-4",
                                        "motif": "", **extra})


def _leurre_journal(cible, at, fin):
    return {"ts": "", "at": at, "type": "leurre", "geste": "leurre", "id": secrets.token_hex(16), "cible": cible,
            "fin": fin, "mode": "auto", "conseil": "c-0", "motif": "", "duree_s": fin - at}


def _appel(g, verbe):
    """Le premier argv de wafctl de ce verbe (les lectures nft, sans wafctl, sont sautées)."""
    return next(a for a in g.faux.appels if "/usr/sbin/wafctl" in a and a[a.index("/usr/sbin/wafctl") + 1] == verbe)


def _verbes_ecriture(g):
    return [v for v in g.faux.verbes() if v in ("leurre", "leurre-lever", "ban", "limiter")]


# ── route ──────────────────────────────────────────────────────────────
@pytest.mark.parametrize("cible", [IP4, IP6])
def test_leurre_pose_et_audite(g, cible):
    r = _leurre(g, cible)
    assert r.status_code == 200, r.text
    argv = _appel(g, "leurre")
    assert argv[:3] == ["sudo", "-n", "/usr/sbin/wafctl"] and argv[-2:] == [cible, "86400s"]
    ligne = g.lignes_journal()[-1]
    assert ligne["type"] == "leurre" and ligne["geste"] == "leurre" and ligne["cible"] == cible
    assert ligne["fin"] == r.json()["fin"] and r.json()["id"] == ligne["id"]
    actions = [x["action"] for x in g.audit()]
    assert actions.index("ai-leurre-demande") < actions.index("ai-leurre")
    e = g.c.get("/ai/etat").json()
    assert [x["cible"] for x in e["leurres"]] == [cible]
    assert e["actifs"] == [] and e["limites"] == []                     # un leurre n'est ni un ban ni une limite
    assert e["plafonds_par_geste"]["leurre"] == {"heure": 30, "jour": 200, "restant_heure": 29, "restant_jour": 199}


@pytest.mark.parametrize("cible", ["10.0.0.1", "fd00::1", "fe80::1", "::1", "::ffff:198.51.100.7", "198.51.100.0/24",
                                   "2001:DB8:1::7", "x"])
def test_leurre_forme_refusee_422(g, cible):
    assert g.c.post("/ai/leurre", json={"geste": "leurre", "cible": cible, "duree_s": 86400, "conseil": "c-4",
                                        "motif": ""}).status_code == 422
    assert g.faux.appels == []


def test_leurre_geste_lie_au_corps(g):
    """P9 : le corps d'un autre geste ne vaut rien ici."""
    r = g.c.post("/ai/leurre", json={"geste": "limiter", "cible": IP4, "duree_s": 86400, "conseil": "c-4"})
    assert r.status_code == 422 and g.faux.appels == []


def test_leurre_refuse_protegee(g, monkeypatch):
    g.sade("active", liste=["198.51.100.0/24"])
    assert _motif(_leurre(g, IP4)) == "protegee"                        # liste blanche SADE
    g.sade("active")
    monkeypatch.setattr(g.g, "_lire_threatmesh_peers", lambda: {"peers": [{"address": f"[{IP6}]:7000"}]})
    assert _motif(_leurre(g, IP6)) == "protegee"                        # pair du maillage
    monkeypatch.setattr(g.g, "_lire_threatmesh_peers", lambda: {"peers": []})
    monkeypatch.setattr(g.g, "_fcrdns", lambda ip: "googlebot.com")
    assert _motif(_leurre(g, IP4)) == "protegee"                        # robot vérifié
    monkeypatch.setattr(g.g, "_fcrdns", lambda ip: "")
    assert _verbes_ecriture(g) == []
    g.faux.reponses["leurre"] = (1, "", "refus:protegee\n")             # Freebox (protegees.env), garde root
    assert _motif(_leurre(g, IP4)) == "protegee"
    g.faux.reponses["leurre"] = (1, "", "refus:box\n")
    assert _motif(_leurre(g, IP4)) == "box"
    assert not [e for e in g.lignes_journal() if e["type"] == "leurre"]


def test_leurre_source_muette_refuse(g):
    g.g.WG_MESH.write_text("{tronqué")
    assert _motif(_leurre(g)) == "protegee_inconnue"
    assert g.faux.appels == []


@pytest.mark.parametrize("duree", [1, 3599, 604801, 10 * 604800])
def test_leurre_bornes(g, duree):
    r = _leurre(g, duree_s=duree)
    assert r.status_code == 409 and _motif(r) == "duree"
    assert g.faux.appels == []


def test_leurre_bornes_admises(g):
    assert _leurre(g, IP4, 3600).status_code == 200
    assert _leurre(g, IP6, 604800).status_code == 200
    assert _appel(g, "leurre")[-1] == "3600s"


def test_leurre_plafond_30h(g):
    now = int(time.time())
    g.journal(*[_leurre_journal(f"192.0.2.{i}", now - 100 * i - 1, now + 3600) for i in range(30)])
    r = _leurre(g)
    assert r.status_code == 409 and _motif(r) == "plafond_heure"
    assert _verbes_ecriture(g) == []
    # les autres gestes ont leurs propres plafonds
    g.faux.reponses["limiter"] = (0, json.dumps({"fin": now + 3600}) + "\n", "")
    assert g.c.post("/ai/limiter", json={"geste": "limiter", "cible": IP4, "duree_s": 3600, "conseil": "c-3"}
                    ).status_code == 200


def test_leurre_plafond_200_jour(g):
    now = int(time.time())
    g.journal(*[_leurre_journal(f"192.0.2.{i % 250}", now - 3600 - 300 * i, now - 1) for i in range(200)])
    assert _motif(_leurre(g)) == "plafond_jour"


def test_leurre_deja_actif(g):
    assert _leurre(g).status_code == 200
    assert _motif(_leurre(g)) == "deja_actif"


def test_leurre_cible_deja_bannie_refuse(g):
    """Un attaquant banni n'atteint pas le leurre : 409 `deja_banni`, rien n'est levé ni posé."""
    now = int(time.time())
    g.journal(_ban_journal(IP4, now - 10, now + 3600))                  # ban ai-ban actif
    assert _motif(_leurre(g, IP4)) == "deja_banni"
    g.journal(_ban_journal("198.51.100.0/24", now - 10, now + 3600))     # bloc ai-ban actif qui la couvre
    assert _motif(_leurre(g, "198.51.100.8")) == "deja_banni"
    g.bans = [{"ip": "203.0.113.9", "reason": "scanners"}]              # banni par le WAF (waf_ban)
    assert _motif(_leurre(g, "203.0.113.9")) == "deja_banni"
    g.faux.reponses["blocs"] = (0, json.dumps({"ok": True, "motif": None, "blocs": [
        {"bloc": "192.0.2.0/24", "fin": now + 600, "reste": 600}]}), "")
    assert _motif(_leurre(g, "192.0.2.5")) == "deja_banni"              # bloc de l'administrateur (waf-blocs)
    g.faux.reponses["nft"] = _nft6(IP6)
    assert _motif(_leurre(g, IP6, garder_nft=True)) == "deja_banni"   # banni par le WAF (waf_ban6)
    assert _verbes_ecriture(g) == []
    assert "leurre-lever" not in g.faux.verbes() and "unban" not in g.faux.verbes()


def test_leurre_etat_des_bans_illisible_503(g):
    g.faux.reponses["nft"] = (1, "", "nft: erreur\n")
    assert _motif(_leurre(g, IP6, garder_nft=True)) == "etat"
    g.faux.reponses["blocs"] = (1, "", "")
    assert _motif(_leurre(g, IP4)) == "etat"
    assert _verbes_ecriture(g) == []


def test_leurre_porte_sade(g):
    g.sade("observe")
    assert _motif(_leurre(g)) == "sade_observe"
    g.sade("reactive")                                                  # reactive : limiter seul
    assert _motif(_leurre(g)) == "sade_reactive"
    g.sade("active")
    assert _leurre(g).status_code == 200


def test_leurre_audit_demande_impossible_rien_n_est_fait(g, monkeypatch):
    vrai = g.g._config["audit"]

    def audit(action, detail, user):
        if action == "ai-leurre-demande":
            raise OSError("disque plein")
        vrai(action, detail, user)
    monkeypatch.setitem(g.g._config, "audit", audit)
    assert _motif(_leurre(g)) == "audit"
    assert _verbes_ecriture(g) == []


def test_leurre_audit_final_impossible_le_leurre_est_leve(g, monkeypatch):
    vrai = g.g._config["audit"]

    def audit(action, detail, user):
        if action == "ai-leurre":
            raise OSError("disque plein")
        vrai(action, detail, user)
    monkeypatch.setitem(g.g._config, "audit", audit)
    r = _leurre(g)
    assert r.status_code == 500 and _motif(r) == "audit"
    assert _appel(g, "leurre-lever")[-1] == IP4
    assert g.lignes_journal()[-1]["type"] == "annule"


def test_leurre_wafctl_muet_leurre_leve(g, monkeypatch):
    faux = g.faux

    def muet(argv):
        if "leurre" in argv:
            faux.appels.append(list(argv))
            raise subprocess.TimeoutExpired(argv, 30)
        return faux(argv)
    monkeypatch.setattr(g.g, "_executer", muet)
    assert _motif(_leurre(g)) == "wafctl"
    assert _appel(g, "leurre-lever")[-1] == IP4                       # peut-être posé : retiré
    assert not [e for e in g.lignes_journal() if e["type"] == "leurre"]


def test_unban_d_un_leurre_le_leve(g):
    ident = _leurre(g, IP6).json()["id"]
    r = g.c.post("/ai/unban", json={"geste": "unban", "id": ident})
    assert r.status_code == 200 and r.json()["etat"] == "annule"
    assert _appel(g, "leurre-lever")[-1] == IP6
    assert g.c.get("/ai/etat").json()["leurres"] == []
    assert g.prolonger(ident, 172800).json()["detail"]["motif"] == "inconnu"   # un leurre ne se prolonge pas


# ── wafctl ─────────────────────────────────────────────────────────────
def _wafctl_leurres(tmp_path, code_garde=0):
    """wafctl réel ; `waf-blocs` simulé ; la liste dans tmp_path/waf/leurres-ip.json."""
    bin_ = tmp_path / "bin"
    bin_.mkdir(exist_ok=True)
    garde = bin_ / "waf-blocs"
    garde.write_text(f'#!/bin/bash\necho "$*" >> {tmp_path}/garde.log\n'
                     f'[ {code_garde} -eq 0 ] && echo \'{{"ok": true, "motif": null}}\' && exit 0\n'
                     f'echo \'{{"ok": false, "motif": "garde_illisible"}}\'; exit {code_garde}\n')
    garde.chmod(0o755)
    dossier = tmp_path / "waf"
    dossier.mkdir(exist_ok=True)
    liste = dossier / "leurres-ip.json"
    script = tmp_path / "wafctl"
    texte = WAFCTL.read_text()
    assert 'LEURRES_IP="/var/lib/secubox/waf/leurres-ip.json"' in texte
    script.write_text(texte.replace("/usr/sbin/waf-blocs", str(garde))
                      .replace('LEURRES_IP="/var/lib/secubox/waf/leurres-ip.json"', f'LEURRES_IP="{liste}"'))
    env = {**os.environ, "PATH": f"{bin_}:{os.environ['PATH']}"}

    def lancer(*args):
        return subprocess.run(["bash", str(script), *args], check=False, timeout=30, capture_output=True,
                              text=True, env=env)
    return lancer, liste


def _lire(liste):
    return json.loads(liste.read_text())


@pytest.mark.parametrize("ip", [IP4, IP6])
def test_leurre_ecrit_fichier_atomique(tmp_path, ip):
    lancer, liste = _wafctl_leurres(tmp_path)
    r = lancer("leurre", ip, "86400s")
    assert r.returncode == 0, r.stderr
    fin = json.loads(r.stdout.strip().splitlines()[-1])["fin"]
    assert abs(fin - (int(time.time()) + 86400)) <= 5
    doc = _lire(liste)
    assert doc == {"format": 1, "entrees": {ip: {"fin": fin, "motif": "ai-leurre"}}}
    st = liste.stat()
    assert stat.S_IMODE(st.st_mode) == 0o644 and st.st_uid == os.geteuid() and st.st_nlink == 1
    assert (tmp_path / "garde.log").read_text().split() == ["verifier", ip, "--exiger"]
    # une seconde adresse : NOUVEAU fichier (remplacement atomique), la première est gardée, aucun reste temporaire
    inode = st.st_ino
    assert lancer("leurre", "203.0.113.9", "3600s").returncode == 0
    assert liste.stat().st_ino != inode
    assert set(_lire(liste)["entrees"]) == {ip, "203.0.113.9"}
    assert sorted(p.name for p in liste.parent.iterdir()) == ["leurres-ip.json"]
    # la levée retire la seule entrée visée ; une adresse absente : succès
    assert lancer("leurre-lever", ip).returncode == 0
    assert set(_lire(liste)["entrees"]) == {"203.0.113.9"}
    assert lancer("leurre-lever", ip).returncode == 0


def test_leurre_purge_les_echues_et_ignore_un_fichier_douteux(tmp_path):
    lancer, liste = _wafctl_leurres(tmp_path)
    passe = int(time.time()) - 10
    liste.write_text(json.dumps({"format": 1, "entrees": {"203.0.113.1": {"fin": passe, "motif": "ai-leurre"},
                                                          "203.0.113.2": {"fin": passe + 9999, "motif": "x"}}}))
    liste.chmod(0o644)
    assert lancer("leurre", IP4, "3600s").returncode == 0
    assert set(_lire(liste)["entrees"]) == {"203.0.113.2", IP4}
    # un fichier inscriptible par d'autres n'est pas repris (il est remplacé)
    liste.chmod(0o666)
    assert lancer("leurre", "203.0.113.3", "3600s").returncode == 0
    assert set(_lire(liste)["entrees"]) == {"203.0.113.3"}


def test_leurre_lien_symbolique_jamais_suivi(tmp_path):
    lancer, liste = _wafctl_leurres(tmp_path)
    victime = tmp_path / "victime"
    victime.write_text("intact\n")
    liste.symlink_to(victime)
    assert lancer("leurre", IP4, "3600s").returncode == 0
    assert victime.read_text() == "intact\n"
    assert not liste.is_symlink() and IP4 in _lire(liste)["entrees"]


def test_leurre_liste_pleine_refuse(tmp_path):
    lancer, liste = _wafctl_leurres(tmp_path)
    fin = int(time.time()) + 3600
    liste.write_text(json.dumps({"format": 1, "entrees": {f"11.0.{i // 256}.{i % 256}": {"fin": fin, "motif": "x"}
                                                          for i in range(2048)}}))
    liste.chmod(0o644)
    r = lancer("leurre", IP4, "3600s")
    assert r.returncode == 1 and "refus:plein" in r.stderr
    assert IP4 not in _lire(liste)["entrees"]
    assert lancer("leurre", "11.0.0.5", "7200s").returncode == 0          # une adresse déjà listée : renouvelée


@pytest.mark.parametrize("args", [("leurre", IP4), ("leurre", IP4, "1h", "x"), ("leurre", "10.0.0.1", "1h"),
                                  ("leurre", IP4, "3599s"), ("leurre", IP4, "604801s"), ("leurre", IP4, "1w"),
                                  ("leurre", "fe80::1", "1h"), ("leurre-lever",), ("leurre-lever", IP4, "x"),
                                  ("leurre-lever", "10.0.0.1")])
def test_wafctl_leurre_arguments_refuses(tmp_path, args):
    lancer, liste = _wafctl_leurres(tmp_path)
    assert lancer(*args).returncode != 0, args
    assert not liste.exists()


def test_wafctl_leurre_duree_et_garde(tmp_path):
    lancer, liste = _wafctl_leurres(tmp_path)
    assert "refus:duree" in lancer("leurre", IP4, "604801s").stderr
    lancer, liste = _wafctl_leurres(tmp_path, code_garde=6)
    r = lancer("leurre", IP4, "3600s")
    assert r.returncode == 1 and "refus:garde_illisible" in r.stderr
    assert not liste.exists()


def test_sudoers_leurre_exact():
    s = (COMPOSANT / "sudoers" / "secubox-waf").read_text()
    assert re.search(r"Cmnd_Alias SBX_WAF_LEURRE = /usr/sbin/wafctl leurre \*, \\\n\s+/usr/sbin/wafctl leurre-lever \*\n", s)
    assert "secubox ALL=(root) NOPASSWD: SBX_WAF_LEURRE" in s
    assert "Defaults!SBX_WAF_LEURRE log_output" in s


def test_service_ne_rend_pas_la_liste_a_secubox_waf():
    """Le `chown -R` du démarrage rendait tout /var/lib/secubox/waf à secubox-waf : la liste (root seul) en est exclue."""
    texte = SERVICE.read_text()
    assert "chown -R secubox-waf:secubox-waf /var/lib/secubox/waf\n" not in texte
    ligne = next(x for x in texte.splitlines() if x.startswith("ExecStartPre=") and "/var/lib/secubox/waf" in x
                 and "chown" in x)
    assert "! -name leurres-ip.json" in ligne and "-h" in ligne
    assert "! -name '.leurres-ip.*'" in ligne                             # ni les fichiers temporaires de wafctl
