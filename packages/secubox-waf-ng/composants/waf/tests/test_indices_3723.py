# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""#3723, tâche 4 : geste `partager` — indicateurs d'adresses vérifiés entre nœuds du maillage.

- gk2 : `POST /ai/partager` publie une adresse BANNIE à cet instant (`wafctl indice-partager`, simulé ici) ;
- `wafctl` réel (faux `waf-blocs`, publication dans le dossier du test) : verbes indice-partager / -retirer / -revu ;
- pairs : `secubox-waf-indices` (`api/indices_ip.py`) lit `livraisons/ip-indices/`, ne bannit 24 h qu'une adresse vue
  HOSTILE dans son propre journal des menaces APRÈS la réception, jamais une cible protégée, 30 par heure au plus.
Rien ne touche un pare-feu ni une box.
"""
from __future__ import annotations

import json
import os
import re
import stat
import subprocess
import time
from datetime import datetime
from pathlib import Path

import pytest

from .test_gestes_ia_3716 import FauxWafctl, c  # noqa: F401  (fixture `c` réutilisée)
from .test_gestes_ia_3723 import Gk2, _motif, gk2_simule  # noqa: F401  (fixture réutilisée)

IP4, IP6 = "198.51.100.7", "2001:db8:1::7"
COMPOSANT = Path(__file__).resolve().parent.parent
PAQUET = COMPOSANT.parents[1]
WAFCTL = COMPOSANT / "scripts" / "wafctl"
DID = "did:plc:" + "a" * 32
DID2 = "did:plc:" + "b" * 32


def _nft(*adresses, nom="waf_ban"):
    return (0, json.dumps({"nftables": [{"metainfo": {}}, {"set": {"name": nom, "elem": list(adresses)}}]}), "")


# ── gk2 : POST /ai/partager ────────────────────────────────────────────
@pytest.fixture
def g(gk2_simule):  # noqa: F811
    gk2_simule.faux.reponses["indice-partager"] = (0, json.dumps({"expire": int(time.time()) + 604800}) + "\n", "")
    gk2_simule.faux.reponses["indice-retirer"] = (0, "[..] indice-retirer ok\n", "")
    return gk2_simule


def _partager(g: Gk2, cible=IP4, duree_s=604800, famille="scanners", **extra):
    return g.c.post("/ai/partager", json={"geste": "partager", "cible": cible, "duree_s": duree_s, "conseil": "c-5",
                                          "famille": famille, **extra})


def _appel(g, verbe):
    return next(a for a in g.faux.appels if "/usr/sbin/wafctl" in a and a[a.index("/usr/sbin/wafctl") + 1] == verbe)


def _ecritures(g):
    return [v for v in g.faux.verbes() if v in ("indice-partager", "indice-retirer", "ban", "leurre", "limiter")]


def test_partager_refuse_non_bannie(g):
    """Rien de non vérifié ne part : une adresse que gk2 ne bannit pas à cet instant est refusée."""
    r = _partager(g)
    assert r.status_code == 409 and _motif(r) == "non_bannie"
    assert _ecritures(g) == []
    g.faux.reponses["nft"] = _nft(nom="waf_ban6")
    assert _motif(_partager(g, IP6)) == "non_bannie"
    assert _ecritures(g) == []
    assert any(x["action"] == "ai-partager-refus" for x in g.audit())


def test_partager_journal_ai_ban_seul_ne_suffit_pas(g):
    """La vérité est nft (waf_ban) : un ban du journal ai-ban absent de l'ensemble ne vaut pas « bannie »."""
    from .test_gestes_ia_3716 import _ban_journal
    now = int(time.time())
    g.journal(_ban_journal(IP4, now - 10, now + 3600))
    assert _motif(_partager(g)) == "non_bannie"


@pytest.mark.parametrize("cible", [IP4, IP6])
def test_partager_adresse_bannie_publiee_et_auditee(g, cible):
    if ":" in cible:
        g.faux.reponses["nft"] = _nft(cible, nom="waf_ban6")
    else:
        g.bans = [{"ip": cible, "reason": "scanners"}]
    r = _partager(g, cible)
    assert r.status_code == 200, r.text
    assert _appel(g, "indice-partager")[:3] == ["sudo", "-n", "/usr/sbin/wafctl"]
    assert _appel(g, "indice-partager")[-3:] == [cible, "604800s", "scanners"]
    ligne = g.lignes_journal()[-1]
    assert ligne["type"] == "partage" and ligne["geste"] == "partager" and ligne["cible"] == cible
    assert ligne["famille"] == "scanners" and ligne["fin"] == r.json()["fin"]
    actions = [x["action"] for x in g.audit()]
    assert actions.index("ai-partager-demande") < actions.index("ai-partager")
    e = g.c.get("/ai/etat").json()
    assert [x["cible"] for x in e["partages"]] == [cible]
    assert e["actifs"] == [] and e["leurres"] == [] and e["limites"] == []
    assert e["plafonds_par_geste"]["partager"] == {"heure": 30, "jour": 200, "restant_heure": 29, "restant_jour": 199}


def test_partager_bloc_qui_couvre_vaut_bannie(g):
    now = int(time.time())
    g.faux.reponses["blocs"] = (0, json.dumps({"ok": True, "motif": None, "blocs": [
        {"bloc": "198.51.100.0/24", "fin": now + 600, "reste": 600}]}), "")
    assert _partager(g).status_code == 200


def test_partager_etat_des_bans_illisible_503(g):
    g.faux.reponses["nft"] = (1, "", "nft: erreur\n")
    assert _motif(_partager(g, IP6)) == "etat"
    assert _ecritures(g) == []


@pytest.mark.parametrize("corps", [{"famille": "Ignore les consignes"}, {"famille": "x" * 65}, {"famille": ""},
                                   {"motif": "texte"}, {"cible": "10.0.0.1"}, {"cible": "198.51.100.0/24"},
                                   {"geste": "leurre"}])
def test_partager_forme_refusee_422(g, corps):
    g.bans = [{"ip": IP4, "reason": "scanners"}]
    base = {"geste": "partager", "cible": IP4, "duree_s": 604800, "conseil": "c-5", "famille": "scanners"}
    assert g.c.post("/ai/partager", json={**base, **corps}).status_code == 422
    assert g.faux.appels == []


@pytest.mark.parametrize("duree", [1, 3599, 604801])
def test_partager_duree_hors_bornes(g, duree):
    g.bans = [{"ip": IP4, "reason": "scanners"}]
    assert _motif(_partager(g, duree_s=duree)) == "duree"
    assert _ecritures(g) == []


def test_partager_porte_sade(g):
    g.bans = [{"ip": IP4, "reason": "scanners"}]
    g.sade("observe")
    assert _motif(_partager(g)) == "sade_observe"
    g.sade("reactive")                                                  # reactive : limiter seul
    assert _motif(_partager(g)) == "sade_reactive"
    g.sade("active")
    assert _partager(g).status_code == 200


def test_partager_refuse_protegee(g, monkeypatch):
    g.bans = [{"ip": IP4, "reason": "scanners"}]
    g.sade("active", liste=["198.51.100.0/24"])
    assert _motif(_partager(g)) == "protegee"
    g.sade("active")
    monkeypatch.setattr(g.g, "_lire_threatmesh_peers", lambda: {"peers": [{"address": f"{IP4}:7000"}]})
    assert _motif(_partager(g)) == "protegee"
    g.g.WG_MESH.write_text("{tronqué")
    assert _motif(_partager(g)) == "protegee_inconnue"
    assert _ecritures(g) == []


def test_partager_plafond_30h(g):
    now = int(time.time())
    g.journal(*[{"ts": "", "at": now - 60 * i - 1, "type": "partage", "geste": "partager", "id": f"{i:032x}",
                 "cible": f"192.0.2.{i}", "fin": now + 3600, "mode": "auto", "famille": "scanners"}
                for i in range(30)])
    g.bans = [{"ip": IP4, "reason": "scanners"}]
    assert _motif(_partager(g)) == "plafond_heure"
    assert _ecritures(g) == []


def test_partager_deja_actif(g):
    g.bans = [{"ip": IP4, "reason": "scanners"}]
    assert _partager(g).status_code == 200
    assert _motif(_partager(g)) == "deja_actif"


def test_partager_garde_root_refuse(g):
    g.bans = [{"ip": IP4, "reason": "scanners"}]
    g.faux.reponses["indice-partager"] = (1, "", "refus:plein\n")
    assert _motif(_partager(g)) == "plein"
    assert not [e for e in g.lignes_journal() if e["type"] == "partage"]


def test_partager_audit_final_impossible_indicateur_retire(g, monkeypatch):
    g.bans = [{"ip": IP4, "reason": "scanners"}]
    vrai = g.g._config["audit"]

    def audit(action, detail, user):
        if action == "ai-partager":
            raise OSError("disque plein")
        vrai(action, detail, user)
    monkeypatch.setitem(g.g._config, "audit", audit)
    r = _partager(g)
    assert r.status_code == 500 and _motif(r) == "audit"
    assert _appel(g, "indice-retirer")[-1] == IP4
    assert g.lignes_journal()[-1]["type"] == "annule"


def test_unban_d_un_partage_le_retire(g):
    g.bans = [{"ip": IP4, "reason": "scanners"}]
    ident = _partager(g).json()["id"]
    r = g.c.post("/ai/unban", json={"geste": "unban", "id": ident})
    assert r.status_code == 200 and r.json()["etat"] == "annule"
    assert _appel(g, "indice-retirer")[-1] == IP4
    assert "unban" not in g.faux.verbes()                                # le ban de l'adresse reste
    assert g.c.get("/ai/etat").json()["partages"] == []


# ── wafctl : la publication ────────────────────────────────────────────
def _wafctl(tmp_path, code_garde=0):
    bin_ = tmp_path / "bin"
    bin_.mkdir(exist_ok=True)
    garde = bin_ / "waf-blocs"
    garde.write_text(f'#!/bin/bash\necho "$*" >> {tmp_path}/garde.log\n'
                     f'[ {code_garde} -eq 0 ] && echo \'{{"ok": true, "motif": null}}\' && exit 0\n'
                     f'echo \'{{"ok": false, "motif": "garde_illisible"}}\'; exit {code_garde}\n')
    garde.chmod(0o755)
    dossier = tmp_path / "waf"
    dossier.mkdir(exist_ok=True)
    pub = dossier / "ip-indices-publication.json"
    texte = WAFCTL.read_text()
    assert 'INDICES_IP="/var/lib/secubox/waf/ip-indices-publication.json"' in texte
    script = tmp_path / "wafctl"
    script.write_text(texte.replace("/usr/sbin/waf-blocs", str(garde))
                      .replace('INDICES_IP="/var/lib/secubox/waf/ip-indices-publication.json"', f'INDICES_IP="{pub}"'))
    env = {**os.environ, "PATH": f"{bin_}:{os.environ['PATH']}"}

    def lancer(*args):
        return subprocess.run(["bash", str(script), *args], check=False, timeout=30, capture_output=True,
                              text=True, env=env)
    return lancer, pub


def test_wafctl_indice_partager_publication_atomique(tmp_path):
    lancer, pub = _wafctl(tmp_path)
    r = lancer("indice-partager", IP4, "604800s", "scanners")
    assert r.returncode == 0, r.stderr
    expire = json.loads(r.stdout.strip().splitlines()[-1])["expire"]
    assert abs(expire - (int(time.time()) + 604800)) <= 5
    doc = json.loads(pub.read_text())
    assert doc == {"format": 1, "jeu": "ip-indices", "indicateurs": [{"ip": IP4, "famille": "scanners",
                                                                       "expire": expire}], "revus": []}
    st = pub.stat()
    assert stat.S_IMODE(st.st_mode) == 0o644 and st.st_uid == os.geteuid() and st.st_nlink == 1
    assert (tmp_path / "garde.log").read_text().split() == ["verifier", IP4, "--exiger"]
    inode = st.st_ino
    assert lancer("indice-partager", IP6, "3600s", "xss").returncode == 0
    assert pub.stat().st_ino != inode
    assert [i["ip"] for i in json.loads(pub.read_text())["indicateurs"]] == [IP4, IP6]
    assert sorted(p.name for p in pub.parent.iterdir()) == ["ip-indices-publication.json"]
    # revu : ajouté une fois ; retirer : l'indicateur seul
    assert lancer("indice-revu", "203.0.113.9").returncode == 0
    assert lancer("indice-revu", "203.0.113.9").returncode == 0
    assert lancer("indice-retirer", IP4).returncode == 0
    doc = json.loads(pub.read_text())
    assert [i["ip"] for i in doc["indicateurs"]] == [IP6] and doc["revus"] == ["203.0.113.9"]
    assert lancer("indice-retirer", IP4).returncode == 0                  # absent : succès


def test_wafctl_indices_purge_bornes_et_fichier_douteux(tmp_path):
    lancer, pub = _wafctl(tmp_path)
    passe = int(time.time()) - 10
    pub.write_text(json.dumps({"format": 1, "jeu": "ip-indices", "revus": [f"11.1.0.{i}" for i in range(1, 251)]
                               + [f"11.2.0.{i}" for i in range(1, 251)],
                               "indicateurs": [{"ip": "203.0.113.1", "famille": "x", "expire": passe},
                                               {"ip": "203.0.113.2", "famille": "x", "expire": passe + 9999}]}))
    pub.chmod(0o644)
    assert lancer("indice-revu", "203.0.113.50").returncode == 0
    doc = json.loads(pub.read_text())
    assert [i["ip"] for i in doc["indicateurs"]] == ["203.0.113.2"]      # échue purgée
    assert len(doc["revus"]) == 500 and doc["revus"][-1] == "203.0.113.50" and "11.1.0.1" not in doc["revus"]
    pub.chmod(0o666)                                                    # inscriptible par d'autres : remplacée
    assert lancer("indice-revu", "203.0.113.51").returncode == 0
    assert json.loads(pub.read_text()) == {"format": 1, "jeu": "ip-indices", "indicateurs": [],
                                           "revus": ["203.0.113.51"]}


def test_wafctl_indices_plein(tmp_path):
    lancer, pub = _wafctl(tmp_path)
    fin = int(time.time()) + 3600
    pub.write_text(json.dumps({"format": 1, "jeu": "ip-indices", "revus": [], "indicateurs": [
        {"ip": f"11.0.{i // 256}.{i % 256}", "famille": "x", "expire": fin} for i in range(500)]}))
    pub.chmod(0o644)
    r = lancer("indice-partager", IP4, "3600s", "scanners")
    assert r.returncode == 1 and "refus:plein" in r.stderr
    assert lancer("indice-partager", "11.0.0.5", "7200s", "scanners").returncode == 0     # déjà publiée : renouvelée


def test_wafctl_indices_lien_jamais_suivi(tmp_path):
    lancer, pub = _wafctl(tmp_path)
    victime = tmp_path / "victime"
    victime.write_text("intact\n")
    pub.symlink_to(victime)
    assert lancer("indice-revu", IP4).returncode == 0
    assert victime.read_text() == "intact\n" and not pub.is_symlink()


@pytest.mark.parametrize("args", [("indice-partager", IP4, "3600s"), ("indice-partager", IP4, "3600s", "x", "y"),
                                  ("indice-partager", "10.0.0.1", "3600s", "x"),
                                  ("indice-partager", IP4, "604801s", "x"), ("indice-partager", IP4, "3599s", "x"),
                                  ("indice-partager", IP4, "3600s", "Mauvaise famille"),
                                  ("indice-partager", "2001:DB8:1::7", "3600s", "x"),
                                  ("indice-revu",), ("indice-revu", "192.168.1.1"), ("indice-revu", IP4, "x"),
                                  ("indice-retirer",), ("indice-retirer", "10.0.0.1")])
def test_wafctl_indices_arguments_refuses(tmp_path, args):
    lancer, pub = _wafctl(tmp_path)
    assert lancer(*args).returncode != 0, args
    assert not pub.exists()


def test_wafctl_indice_partager_garde_root(tmp_path):
    lancer, pub = _wafctl(tmp_path, code_garde=6)
    r = lancer("indice-partager", IP4, "3600s", "scanners")
    assert r.returncode == 1 and "refus:garde_illisible" in r.stderr
    assert not pub.exists()


def test_sudoers_indices_exact():
    s = (COMPOSANT / "sudoers" / "secubox-waf").read_text()
    assert re.search(r"Cmnd_Alias SBX_WAF_INDICES = /usr/sbin/wafctl indice-partager \*, \\\n"
                     r"\s+/usr/sbin/wafctl indice-retirer \*, \\\n\s+/usr/sbin/wafctl indice-revu \*\n", s)
    assert "secubox ALL=(root) NOPASSWD: SBX_WAF_INDICES" in s


def test_service_ne_rend_pas_la_publication_a_secubox_waf():
    texte = (PAQUET / "systemd" / "secubox-waf-ng.service").read_text()
    ligne = next(x for x in texte.splitlines() if x.startswith("ExecStartPre=") and "/var/lib/secubox/waf" in x
                 and "chown" in x)
    assert "! -name ip-indices-publication.json" in ligne and "! -name '.ip-indices-publication.*'" in ligne


# ── pairs : secubox-waf-indices ────────────────────────────────────────
class Pair:
    def __init__(self, ii, gi, tmp, faux):
        self.ii, self.gi, self.tmp, self.faux = ii, gi, tmp, faux

    def livrer(self, indicateurs, revus=(), did=DID, nom="gk2"):
        d = self.ii.LIVRAISONS
        index = json.loads((d / "index.json").read_text()) if (d / "index.json").exists() else {}
        index[did] = {"nom": nom, "empreinte": "b2:" + "0" * 64}
        (d / (did[8:] + ".json")).write_text(json.dumps({"format": 1, "jeu": "ip-indices",
                                                          "indicateurs": list(indicateurs), "revus": list(revus)}))
        (d / "index.json").write_text(json.dumps(index))

    def menace(self, ip, instant, categorie="scanners", gravite="medium"):
        e = {"timestamp": datetime.fromtimestamp(instant).astimezone().isoformat(timespec="seconds"),
             "client_ip": ip, "host": "x.example", "method": "GET", "path": "/.env", "category": categorie,
             "severity": gravite, "rule_id": "r1", "action": "blocked", "user_agent": "curl/8"}
        with open(self.ii.MENACES, "a", encoding="utf-8") as f:
            f.write(json.dumps(e) + "\n")

    def ecritures(self):
        return [v for v in self.faux.verbes() if v != "nft"]

    def bannis(self):
        return [a[a.index("/usr/sbin/wafctl") + 2] for a in self.faux.appels
                if "/usr/sbin/wafctl" in a and a[a.index("/usr/sbin/wafctl") + 1] == "ban"]

    def audit(self):
        p = self.ii.AUDIT_LOG
        return [json.loads(x) for x in p.read_text().splitlines()] if p.exists() else []


class FauxPair(FauxWafctl):
    """wafctl simulé, plus `nft -j list set inet secubox waf_ban|waf_ban6` (droit SBX_WAF_NFTLIST) par ensemble."""

    def __init__(self):
        super().__init__()
        self.ensembles = {"waf_ban": [], "waf_ban6": []}

    def __call__(self, argv):
        if "/usr/sbin/nft" in argv and argv[-1] in self.ensembles and "nft" not in self.pannes:
            self.appels.append(list(argv))
            return subprocess.CompletedProcess(argv, 0, _nft(*self.ensembles[argv[-1]], nom=argv[-1])[1], "")
        return super().__call__(argv)

    pannes: set = set()


def _ind(ip, famille="scanners", expire=None):
    return {"ip": ip, "famille": famille, "expire": expire if expire is not None else int(time.time()) + 86400 * 6}


@pytest.fixture
def pair(c, tmp_path, monkeypatch):  # noqa: F811
    from api import indices_ip as ii
    gi = c.g
    liv = tmp_path / "livraisons" / "ip-indices"
    liv.mkdir(parents=True)
    monkeypatch.setattr(ii, "LIVRAISONS", liv)
    monkeypatch.setattr(ii, "PUBLICATION", tmp_path / "ip-indices-publication.json")
    monkeypatch.setattr(ii, "ETAT", tmp_path / "etat.json")
    monkeypatch.setattr(ii, "RESUME", tmp_path / "waf-indices-etat.json")
    monkeypatch.setattr(ii, "AUDIT_LOG", tmp_path / "audit-pair.log")
    monkeypatch.setattr(ii, "MENACES", tmp_path / "waf-threats-pair.log")
    monkeypatch.setattr(ii, "_uids_resume", lambda: {0, os.getuid()})
    sock = tmp_path / "threatmesh.sock"
    sock.write_text("")
    monkeypatch.setattr(gi, "SOCKET_THREATMESH", str(sock))
    faux = FauxPair()
    faux.pannes = set()
    faux.reponses["indice-revu"] = (0, "", "")
    monkeypatch.setattr(ii, "_executer", faux)
    return Pair(ii, gi, tmp_path, faux)


def test_pair_ne_bannit_pas_sans_vue_locale(pair):
    pair.livrer([_ind(IP4)])
    r = pair.ii.passe()
    assert r["bannis"] == 0 and pair.bannis() == []
    assert IP4 in json.loads(pair.ii.ETAT.read_text())["recus"]
    assert pair.ii.passe()["bannis"] == 0 and pair.ecritures() == []


def test_pair_deja_bannie_ici_revue_sans_ban_ni_retrait(pair, monkeypatch):
    """Le WAF local l'a déjà bannie (cas courant : elle y est hostile) : aucun ban posé, donc rien à retirer même si
    l'audit échoue ; elle est revue (reproduite ici)."""
    now = int(time.time())
    pair.livrer([_ind(IP4), _ind(IP6)])
    pair.ii.passe(now - 600)
    pair.menace(IP4, now - 60)
    pair.menace(IP6, now - 60)
    pair.faux.ensembles = {"waf_ban": [IP4], "waf_ban6": [IP6]}
    monkeypatch.setattr(pair.ii, "_auditer", lambda action, detail: (_ for _ in ()).throw(OSError("plein"))
                        if action == "waf-indice" else None)
    r = pair.ii.passe(now)
    assert r["bannis"] == 0 and r["revus"] == 2
    assert "ban" not in pair.faux.verbes() and "unban" not in pair.faux.verbes()
    assert sorted(a[-1] for a in pair.faux.appels if "indice-revu" in a) == sorted([IP4, IP6])


def test_pair_ensemble_illisible_attend(pair):
    now = int(time.time())
    pair.livrer([_ind(IP4)])
    pair.ii.passe(now - 600)
    pair.menace(IP4, now - 60)
    pair.faux.pannes = {"nft"}
    pair.faux.reponses["nft"] = (1, "", "nft: erreur\n")
    assert pair.ii.passe(now)["attente"] == 1 and "ban" not in pair.faux.verbes()


def test_pair_bannit_apres_vue_locale_hostile(pair):
    now = int(time.time())
    pair.livrer([_ind(IP4), _ind(IP6, famille="xss")])
    pair.menace(IP4, now - 3000)                                        # AVANT la réception : ne compte pas
    pair.ii.passe(now - 1200)                                           # réception
    assert pair.ii.passe(now - 1100)["bannis"] == 0
    pair.menace(IP4, now - 900, categorie="leurre_redirige", gravite="audit")   # le leurre de gk2 : pas hostile
    pair.menace(IP4, now - 800, categorie="ban")                        # décision : neutre
    pair.menace(IP6, now - 700, categorie="scanners", gravite="audit")  # gravité d'état : pas hostile
    assert pair.ii.passe(now - 600)["bannis"] == 0 and pair.bannis() == []
    pair.menace(IP4, now - 300, categorie="host_anomaly:unrouted")
    pair.menace(IP6, now - 200, categorie="xss")
    r = pair.ii.passe(now)
    assert r["bannis"] == 2 and sorted(pair.bannis()) == sorted([IP4, IP6])
    ban = next(a for a in pair.faux.appels if "ban" in a and IP4 in a)
    assert ban == ["sudo", "-n", "/usr/sbin/wafctl", "ban", IP4, "86400s", "--exiger-protegees"]
    revus = [a[-1] for a in pair.faux.appels if "indice-revu" in a]
    assert sorted(revus) == sorted([IP4, IP6])
    actions = [(x["action"], x["detail"]) for x in pair.audit()]
    assert [a for a, _ in actions].count("waf-indice-demande") == 2 and [a for a, _ in actions].count("waf-indice") == 2
    assert any("indice-maillage:scanners" in d for a, d in actions if a == "waf-indice")
    assert any("indice-maillage:xss" in d for a, d in actions if a == "waf-indice")
    # appliqué une fois : la passe suivante ne rebannit pas
    assert pair.ii.passe(now + 60)["bannis"] == 0


def test_pair_refuse_adresse_de_ses_pairs(pair, monkeypatch):
    now = int(time.time())
    pair.gi.WG_MESH.write_text(json.dumps({"peers": [{"mesh_ip": "10.10.0.2", "endpoint": f"{IP4}:51820"}]}))
    monkeypatch.setattr(pair.gi, "_lire_threatmesh_peers", lambda: {"peers": [{"address": f"[{IP6}]:7000"}]})
    pair.livrer([_ind(IP4), _ind(IP6), _ind("192.168.1.10"), _ind("203.0.113.40")])
    pair.ii.passe(now - 600)
    for ip in (IP4, IP6, "192.168.1.10", "203.0.113.40"):
        pair.menace(ip, now - 60)
    monkeypatch.setattr(pair.gi, "_fcrdns", lambda ip: "googlebot.com" if ip == "203.0.113.40" else "")
    r = pair.ii.passe(now)
    assert r["bannis"] == 0 and pair.bannis() == []
    # source de pairs muette : rien, et l'adresse reste en attente (pas refusée pour toujours)
    pair.livrer([_ind("203.0.113.41")], did=DID2, nom="gk6")
    pair.ii.passe(now - 30)
    pair.menace("203.0.113.41", now - 10)
    pair.gi.WG_MESH.write_text("{tronqué")
    assert pair.ii.passe(now)["bannis"] == 0
    pair.gi.WG_MESH.write_text(json.dumps({"peers": []}))
    assert pair.ii.passe(now + 1)["bannis"] == 1


def test_pair_sade_et_garde_root(pair):
    now = int(time.time())
    pair.livrer([_ind(IP4), _ind("203.0.113.42")])
    pair.ii.passe(now - 600)
    pair.menace(IP4, now - 60)
    pair.menace("203.0.113.42", now - 60)
    pair.gi.FICHIER_SADE.write_text(json.dumps({"mode": "observe", "depuis": datetime.now().astimezone().isoformat(),
                                                "liste_blanche": []}))
    pair.gi.FICHIER_SADE.chmod(0o644)
    assert pair.ii.passe(now)["bannis"] == 0 and pair.ecritures() == []
    pair.gi.FICHIER_SADE.unlink()
    pair.faux.reponses["ban"] = (1, "", "refus:box\n")
    r = pair.ii.passe(now)
    assert r["bannis"] == 0 and "indice-revu" not in pair.faux.verbes()
    assert any(x["action"] == "waf-indice-refus" for x in pair.audit())


def test_pair_plafond_30h(pair):
    now = int(time.time())
    ips = [f"203.0.113.{i}" for i in range(1, 36)]
    pair.livrer([_ind(ip) for ip in ips])
    pair.ii.passe(now - 600)
    for ip in ips:
        pair.menace(ip, now - 60)
    assert pair.ii.passe(now)["bannis"] == 30
    assert len(pair.bannis()) == 30
    assert pair.ii.passe(now + 60)["bannis"] == 0                       # toujours dans l'heure
    assert pair.ii.passe(now + 3700)["bannis"] == 5                     # l'heure glissante est passée


def test_indicateur_expire_ignore(pair):
    now = int(time.time())
    pair.livrer([_ind(IP4, expire=now - 601), _ind(IP6, expire=now + 300)])
    pair.ii.passe(now - 600)
    assert set(json.loads(pair.ii.ETAT.read_text())["recus"]) == {IP6}
    pair.menace(IP4, now - 60)
    pair.menace(IP6, now - 60)
    assert pair.ii.passe(now + 400)["bannis"] == 0                      # IP6 échu entre-temps
    assert pair.bannis() == []
    assert json.loads(pair.ii.ETAT.read_text())["recus"] == {}


def test_pair_livraisons_douteuses_ignorees(pair):
    d = pair.ii.LIVRAISONS
    pair.livrer([_ind(IP4)])
    vrai = pair.tmp / "vrai.json"
    vrai.write_text(json.dumps({"format": 1, "jeu": "ip-indices", "indicateurs": [_ind(IP6)], "revus": []}))
    (d / (DID2[8:] + ".json")).symlink_to(vrai)                         # lien : jamais suivi
    index = json.loads((d / "index.json").read_text())
    index[DID2] = {"nom": "gk6", "empreinte": "b2:" + "0" * 64}
    index["pas-un-did"] = {"nom": "x", "empreinte": "b2:" + "0" * 64}
    (d / "index.json").write_text(json.dumps(index))
    pair.ii.passe()
    assert set(json.loads(pair.ii.ETAT.read_text())["recus"]) == {IP4}
    # contenu à clé en trop : producteur entier ignoré
    (d / (DID[8:] + ".json")).write_text(json.dumps({"format": 1, "jeu": "ip-indices", "indicateurs": [_ind(IP6)],
                                                     "revus": [], "autre": 1}))
    pair.ii.ETAT.unlink()
    pair.ii.passe()
    assert json.loads(pair.ii.ETAT.read_text())["recus"] == {}


def test_pair_audit_impossible(pair, monkeypatch):
    now = int(time.time())
    pair.livrer([_ind(IP4)])
    pair.ii.passe(now - 600)
    pair.menace(IP4, now - 60)
    vrai = pair.ii._auditer

    def avant(action, detail):
        if action == "waf-indice-demande":
            raise OSError("disque plein")
        vrai(action, detail)
    monkeypatch.setattr(pair.ii, "_auditer", avant)
    assert pair.ii.passe(now)["bannis"] == 0 and pair.ecritures() == []

    def apres(action, detail):
        if action == "waf-indice":
            raise OSError("disque plein")
        vrai(action, detail)
    monkeypatch.setattr(pair.ii, "_auditer", apres)
    assert pair.ii.passe(now + 1)["bannis"] == 0
    assert pair.bannis() == [IP4] and "unban" in pair.faux.verbes()     # un ban non audité est retiré


def test_indices_etat_resume(pair, monkeypatch):
    now = int(time.time())
    assert pair.ii.indices_etat() is None                               # relevé indisponible, jamais un zéro inventé
    pair.ii.PUBLICATION.write_text(json.dumps({"format": 1, "jeu": "ip-indices", "revus": [], "indicateurs": [
        _ind(IP4), _ind(IP6), _ind("203.0.113.5", expire=now - 5)]}))
    pair.livrer([], revus=[IP4, "203.0.113.5"])
    pair.livrer([], revus=[IP4, IP6], did=DID2, nom="gk6")
    pair.ii.passe(now)
    assert pair.ii.indices_etat() == {"partages": 2, "revus_chez_pairs": 2, "contenus_chez_pairs": 3}
    st = pair.ii.RESUME.stat()
    assert stat.S_IMODE(st.st_mode) == 0o644
    pair.ii.RESUME.chmod(0o666)                                         # modifiable par d'autres : pas cru
    assert pair.ii.indices_etat() is None
    pair.ii.RESUME.chmod(0o644)
    monkeypatch.setattr(pair.ii, "_maintenant", lambda: now + 3600)     # périmé
    assert pair.ii.indices_etat() is None


# ── paquet ─────────────────────────────────────────────────────────────
def test_unite_minuterie_profil_et_exception():
    unite = (PAQUET / "systemd" / "secubox-waf-indices.service").read_text()
    for ligne in ("User=secubox", "Type=oneshot", "ExecStart=/usr/sbin/secubox-waf-indices", "ProtectSystem=strict",
              "ProtectHome=yes", "PrivateTmp=yes", "ProtectKernelTunables=yes", "ProtectControlGroups=yes",
              "LockPersonality=yes", "UMask=0027", "NoNewPrivileges=no", "AppArmorProfile=secubox-waf-indices",
              "StateDirectory=secubox-waf-indices", "StateDirectoryMode=0700"):
        assert ligne + "\n" in unite, ligne
    rw = next(x for x in unite.splitlines() if x.startswith("ReadWritePaths="))
    assert set(rw.split("=", 1)[1].split()) == {"/run/secubox", "-/var/log/secubox/audit.log", "-/var/lib/secubox/waf",
                                                "-/var/log/sudo-io"}
    minuterie = (PAQUET / "systemd" / "secubox-waf-indices.timer").read_text()
    assert "OnUnitActiveSec=5min\n" in minuterie and "WantedBy=timers.target" in minuterie
    profil = (PAQUET / "apparmor" / "secubox-waf-indices").read_text()
    assert "profile secubox-waf-indices /usr/sbin/secubox-waf-indices {" in profil and "complain" not in profil
    assert "deny /etc/secubox/secrets/** rwklx," in profil
    regles = (COMPOSANT.parents[3] / ".claude" / "RULES-CODE.md").read_text()
    assert "`secubox-waf-indices.service`" in regles
    regles_paquet = (PAQUET / "debian" / "rules").read_text()
    for f in ("sbin/secubox-waf-indices", "systemd/secubox-waf-indices.service", "systemd/secubox-waf-indices.timer",
              "apparmor/secubox-waf-indices"):
        assert f in regles_paquet, f
    lanceur = (PAQUET / "sbin" / "secubox-waf-indices").read_text()
    assert lanceur.startswith("#!/usr/bin/python3") and "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in lanceur
