# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#4040 — plus de boucle de recompilation : condensat des sources, zones des vues à part, espacement, pose seule sous verrou.

gk2 le 28/11 : 13 compilations en 3 h (~8 min, 600 Mo chacune), relancées par le drop-in TV d'ad-guard réécrit chaque minute."""
import fcntl
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "common"))
import secubox_unbound as U  # noqa: E402
from secubox_unbound import depot as D  # noqa: E402
from secubox_unbound import listes as L  # noqa: E402

ADBLOCK = 'server:\n    local-zone: "ads.example." always_nxdomain\n    local-zone: "pub.example." always_nxdomain\n'
ACL = "server:\n    access-control: 192.168.0.0/16 allow\n"


def tv(zones=(), first=True):
    lignes = ["server:", "    access-control-view: 192.168.1.50/32 sbx-tv-auto-salon", "view:", '    name: "sbx-tv-auto-salon"']
    if first:
        lignes.append("    view-first: yes")
    lignes += [f'    local-zone: "{z}." always_nxdomain' for z in zones]
    return "\n".join(lignes) + "\n"


class Faux(U.SystemeUnbound):
    MODULE = "test"

    def __init__(self, verrou=None):
        self.appels, self.verrou = [], verrou

    def verifier_unbound(self):
        self.appels.append("verifier")
        return True, ""

    def recharger_unbound(self):
        if self.verrou is not None:                      # la pose se fait SOUS le verrou partagé avec ad-guard
            fd = os.open(self.verrou, os.O_RDONLY)
            try:
                with pytest.raises(BlockingIOError):
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            finally:
                os.close(fd)
        self.appels.append("recharger")

    def audit(self, action, detail=""):
        pass


class Horloge:
    def __init__(self, t=1_000_000.0):
        self.t, self.sommes = t, []

    def __call__(self):
        return self.t

    def dormir(self, s):
        self.sommes.append(s)
        self.t += s


@pytest.fixture
def box(tmp_path):
    conf = tmp_path / "unbound.conf.d"
    conf.mkdir()
    (conf / "10-acl.conf").write_text(ACL)
    (conf / "94-secubox-adguard-tv.conf").write_text(tv(["appris1.example"]))
    h = Horloge()
    lieux = {"sources": tmp_path / "sources", "conf_d": conf, "etat": tmp_path / "etat.json",
             "reglages": tmp_path / "dns-listes.toml", "verrou": tmp_path / "verrou", "maintenant": h, "dormir": h.dormir}
    D.deposer_source("95-secubox-adblock.conf", ADBLOCK, lieux["sources"])
    return lieux, h, conf


def _passe(lieux, s=None):
    return D.appliquer(systeme=s or Faux(), **lieux)


# ── empreintes du contexte ───────────────────────────────────────────────────

def test_zone_de_vue_ajoutee_ne_change_que_les_zones_des_vues(tmp_path):
    f = tmp_path / "94.conf"
    f.write_text(tv(["a.example"]))
    s1, v1 = L.empreintes([f])
    f.write_text(tv(["a.example", "b.example"]))
    s2, v2 = L.empreintes([f])
    assert s1 == s2 and v1 != v2
    f.write_text(tv(["a.example", "b.example"], first=False))      # view-first : la sémantique change, structure
    assert L.empreintes([f])[0] != s2


def test_une_zone_d_un_autre_type_ou_hors_vue_reste_structurelle(tmp_path):
    f = tmp_path / "94.conf"
    f.write_text(tv() + '    local-zone: "x.example." always_transparent\n')
    s1, _ = L.empreintes([f])
    f.write_text(tv())
    assert L.empreintes([f])[0] != s1
    g = tmp_path / "50.conf"
    g.write_text('server:\n    local-zone: "y.example." always_nxdomain\n')
    s3, v3 = L.empreintes([g])
    g.write_text('server:\n    local-zone: "z.example." always_nxdomain\n')
    assert L.empreintes([g])[0] != s3 and L.empreintes([g])[1] == v3


def test_empreinte_historique_inchangee(tmp_path):
    f = tmp_path / "94.conf"
    f.write_text(tv(["a.example"]))
    e = L.empreinte([f])
    f.write_text(tv(["a.example", "b.example"]))
    assert L.empreinte([f]) != e                          # l'ancienne fonction voit toujours tout


# ── condensat des sources ────────────────────────────────────────────────────

def test_source_reecrite_a_l_identique_ne_recompile_pas(box):
    lieux, h, _conf = box
    assert _passe(lieux)["etat"] == "applique"
    src = lieux["sources"] / "95-secubox-adblock.conf"
    U.ecrire_atomique(src, ADBLOCK, 0o644)                # autre inode, autre date, même contenu
    os.utime(src, (h.t + 50, h.t + 50))
    s = Faux()
    assert _passe(lieux, s)["etat"] == "inchange" and s.appels == []


def test_source_au_contenu_change_recompile(box):
    lieux, h, _conf = box
    _passe(lieux)
    h.t += 4000
    D.deposer_source("95-secubox-adblock.conf", ADBLOCK + '    local-zone: "neuf.example." always_nxdomain\n',
                     lieux["sources"])
    s = Faux()
    assert _passe(lieux, s)["etat"] == "applique" and s.appels == ["verifier", "recharger"]


def test_pas_d_auto_declenchement_apres_sa_propre_pose(box):
    lieux, _h, _conf = box
    assert _passe(lieux)["etat"] == "applique"
    s = Faux()
    assert _passe(lieux, s)["etat"] == "inchange" and s.appels == []


# ── zones apprises des TV : appliquées à chaud par ad-guard, pas de compilation ─────

def test_regles_apprises_seules_differees_sans_compiler(box, monkeypatch):
    lieux, h, conf = box
    _passe(lieux)
    compilations = []
    vrai = L.compiler
    monkeypatch.setattr(L, "compiler", lambda *a, **k: compilations.append(1) or vrai(*a, **k))
    for i in range(10):                                   # ad-guard-auto, une règle apprise par minute
        h.t += 60
        (conf / "94-secubox-adguard-tv.conf").write_text(tv(["appris1.example"] + [f"r{j}.example" for j in range(i + 1)]))
        s = Faux()
        r = _passe(lieux, s)
        assert r["etat"] == "differe" and s.appels == []
    assert compilations == []
    h.t += D.ESPACEMENT["intervalle_vues_s"][0]           # rattrapage espacé : une seule compilation
    r = _passe(lieux)
    assert r["etat"] in ("applique", "inchange") and len(compilations) == 1
    h.t += 60
    (conf / "94-secubox-adguard-tv.conf").write_text(tv(["appris1.example", "encore.example"]))
    assert _passe(lieux)["etat"] == "differe" and len(compilations) == 1      # l'espacement repart de cette compilation


# ── espacement ───────────────────────────────────────────────────────────────

def test_intervalle_minimal_entre_deux_compilations_completes(box):
    lieux, h, conf = box
    _passe(lieux)
    t0 = h.t
    h.t += 100
    D.deposer_source("95-secubox-adblock.conf", ADBLOCK + '    local-zone: "neuf.example." always_nxdomain\n',
                     lieux["sources"])                                     # contenu changé : compilation due
    r = _passe(lieux)
    assert r["etat"] == "applique"
    assert h.sommes[-2] == pytest.approx(1800 - 100)       # attente jusqu au bout de l intervalle, puis stabilité
    assert r["t_compilation"] >= t0 + 1800


def test_stabilisation_attend_la_fin_de_la_rafale(box):
    lieux, h, conf = box
    vrai = h.dormir
    rafale = [2]

    def dormir(sec):
        vrai(sec)
        if rafale[0]:
            rafale[0] -= 1
            D.deposer_source("95-secubox-adblock.conf", ADBLOCK + f'    local-zone: "r{rafale[0]}.example." always_nxdomain\n',
                             lieux["sources"])
    lieux["dormir"] = dormir
    s = Faux()
    assert _passe(lieux, s)["etat"] == "applique"
    assert h.sommes == [20, 20, 20] and s.appels == ["verifier", "recharger"]      # UNE compilation pour toute la rafale
    assert "r0.example" in (conf / L.SORTIE).read_text()


def test_reglages_d_espacement_bornes(tmp_path):
    r = tmp_path / "r.toml"
    r.write_text('intervalle_min_s = 60\nstabilite_s = -1\nintervalle_vues_s = "x"\n')
    e = D.lire_espacement(r)
    assert e["intervalle_min_s"] == 60 and e["stabilite_s"] == 20 and e["intervalle_vues_s"] == 6 * 3600
    assert D.lire_espacement(tmp_path / "absent.toml")["intervalle_min_s"] == 1800


def test_mode_direct_sans_intervalle(box):
    lieux, h, conf = box
    _passe(lieux)
    lieux["reglages"].write_text('mode = "direct"\n')
    h.t += 10
    s = Faux()
    assert _passe(lieux, s)["etat"] == "applique"
    assert all(x == 20 for x in h.sommes) and (conf / "95-secubox-adblock.conf").is_file()   # retour arrière immédiat


# ── bascule : compilation hors verrou, pose sous verrou ────────────────────────────────

def test_compilation_hors_verrou_pose_sous_verrou(box, monkeypatch):
    lieux, _h, _conf = box
    vrai = L.compiler

    def compiler(*a, **k):
        fd = os.open(lieux["verrou"], os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)       # libre : ad-guard peut poser à chaud pendant la compilation
            fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)
        return vrai(*a, **k)
    monkeypatch.setattr(L, "compiler", compiler)
    s = Faux(verrou=lieux["verrou"])
    assert _passe(lieux, s)["etat"] == "applique" and s.appels == ["verifier", "recharger"]


def test_ancien_92_reste_en_place_si_la_verification_refuse(box):
    lieux, h, conf = box
    _passe(lieux)
    ancien = (conf / L.SORTIE).read_bytes()
    h.t += 4000
    D.deposer_source("95-secubox-adblock.conf", ADBLOCK + '    local-zone: "n.example." always_nxdomain\n', lieux["sources"])

    class Refus(Faux):
        def verifier_unbound(self):
            return False, "refus"
    s = Refus()
    assert _passe(lieux, s)["etat"] == "erreur"
    assert (conf / L.SORTIE).read_bytes() == ancien and "recharger" not in s.appels
