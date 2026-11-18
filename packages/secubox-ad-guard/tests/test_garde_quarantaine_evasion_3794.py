# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3794 : verbes `quarantaine` et `evasion` du contrôleur root, et leur rendu Unbound."""
import importlib.machinery
import importlib.util
import json
import re
import stat
import time
from pathlib import Path

import pytest

from api import dnstv

ICI = Path(__file__).resolve().parents[1]
LISTES = ICI / "lists"
CTL = ICI / "sbin" / "secubox-adguard-tv"
BOX = ("192.168.1.1", "2a01:db8::1")
TV = "192.168.1.50"


def _script(chemin, corps):
    chemin.write_text("#!/bin/sh\n" + corps)
    chemin.chmod(chemin.stat().st_mode | stat.S_IXUSR)
    return chemin


@pytest.fixture
def monde(tmp_path, monkeypatch):
    etat = tmp_path / "etat"
    etat.mkdir()
    journal = tmp_path / "appels.log"
    checkconf = _script(tmp_path / "checkconf", f'echo checkconf >> {journal}; [ -f {tmp_path}/refuse ] && exit 1; exit 0\n')
    control = _script(tmp_path / "control", f'echo "control $*" >> {journal}\nexit 0\n')
    conf = tmp_path / "unbound.d" / "94-secubox-adguard-tv.conf"
    for k, v in {"SECUBOX_ADGUARD_TV_ETAT": etat, "SECUBOX_ADGUARD_TV_LISTES": LISTES, "SECUBOX_ADGUARD_TV_UNBOUND": conf,
                 "SECUBOX_ADGUARD_TV_CHECKCONF": checkconf, "SECUBOX_ADGUARD_TV_CONTROL": control,
                 "SECUBOX_ADGUARD_TV_AUDIT": tmp_path / "audit.log", "SECUBOX_ADGUARD_TV_SANS_ROOT": "1",
                 "SECUBOX_ADGUARD_TV_APPLIQUE": tmp_path / "racine" / "applique.json",
                 "SECUBOX_ADGUARD_TV_NFT": _script(tmp_path / "nft", "exit 0\n"),
                 "SECUBOX_ADGUARD_TV_NFT_FICHIER": tmp_path / "nft.d" / "zz.nft"}.items():
        monkeypatch.setenv(k, str(v))
    monkeypatch.setattr(dnstv, "DOSSIER_ETAT", etat)
    monkeypatch.setattr(dnstv, "DOSSIER_LISTES", LISTES)
    monkeypatch.setattr(dnstv, "CONF_UNBOUND", conf)
    return {"etat": etat, "conf": conf, "tmp": tmp_path}


def ctl(*args, box=BOX, avant=None):
    loader = importlib.machinery.SourceFileLoader("tv_ctl_garde", str(CTL))
    spec = importlib.util.spec_from_loader("tv_ctl_garde", loader)
    m = importlib.util.module_from_spec(spec)
    loader.exec_module(m)
    m._adresses_box = lambda: box
    if avant:
        avant(m)
    return m.main(["secubox-adguard-tv", *args])


def vue(conf: str, nom: str) -> list:
    blocs = conf.split("view:\n")
    for b in blocs[1:]:
        if f'    name: "{nom}"' in b.splitlines()[0]:
            return b.splitlines()[1:]
    raise AssertionError(f"vue {nom} absente")


def declarer(monde, mode="block"):
    dnstv.ecrire_etat({"actif": True, "clients": [{"ip": TV, "nom": "Salon", "mode": mode, "mac": "aa:bb:cc:dd:ee:01"}]}, monde["etat"])


def fin():
    return str(int(time.time()) + 86400)


def test_quarantaine_vue_redirect_et_indispensables(monde, capsys):
    declarer(monde, "observe")
    assert ctl("quarantaine", "poser", TV, "aa:bb:cc:dd:ee:01", fin()) == 0
    assert json.loads(capsys.readouterr().out)["ok"] is True
    c = monde["conf"].read_text()
    nom = "sbx-quarantaine-4-c0a80132"
    assert f"access-control-view: {TV}/32 {nom}" in c and f"access-control-view: {TV}/32 sbx-tv-observe" not in c
    v = vue(c, nom)
    assert '    local-zone: "." redirect' in v and '    local-data: ". A 192.168.1.1"' in v and '    local-data: ". AAAA 2a01:db8::1"' in v
    for n in dnstv.INDISPENSABLES:
        assert f'    local-zone: "{n}." transparent' in v
    assert "view-first" not in "\n".join(v)                                  # rien ne retombe sur la configuration globale
    assert len(c.split("view:\n")) == len(set(re.findall(r'name: "([^"]+)"', c))) + 1     # une seule déclaration par vue
    assert json.loads(dnstv.DOSSIER_ETAT.joinpath("etat.json").read_text())["quarantaines"][0]["mac"] == "aa:bb:cc:dd:ee:01"


def test_quarantaine_garde_profil_tv(monde):
    declarer(monde, "block")
    ctl("quarantaine", "poser", TV, "-", fin())
    v = vue(monde["conf"].read_text(), "sbx-quarantaine-4-c0a80132")
    assert '    local-zone: "doubleclick.net." always_nxdomain' in v                 # #3674 : TV Privacy jamais levé
    assert '    local-zone: "." transparent' not in v


def test_lever_rend_la_vue_dorigine(monde):
    declarer(monde, "block")
    ctl("apply")
    avant = monde["conf"].read_text()
    ctl("quarantaine", "poser", TV, "-", fin())
    ctl("evasion", "poser", TV, "-", "dns.google,cloudflare-dns.com")
    assert monde["conf"].read_text() != avant
    assert ctl("quarantaine", "lever", TV) == 0
    assert ctl("evasion", "lever", TV) == 0
    assert monde["conf"].read_text() == avant
    ctl("quarantaine", "poser", TV, "aa:bb:cc:dd:ee:01", fin())
    assert ctl("quarantaine", "lever", "aa:bb:cc:dd:ee:01") == 0                 # lever par MAC
    assert monde["conf"].read_text() == avant


def test_evasion_refuse_les_noms(monde):
    declarer(monde, "observe")
    assert ctl("evasion", "poser", TV, "-", "dns.google,cloudflare-dns.com") == 0
    c = monde["conf"].read_text()
    v = vue(c, "sbx-evasion-4-c0a80132")
    assert '    local-zone: "dns.google." always_refuse' in v and '    local-zone: "cloudflare-dns.com." always_refuse' in v
    assert '    local-zone: "." transparent' in v                                    # sa vue d'origine est gardée
    assert "always_refuse" not in "\n".join(vue(c, "sbx-tv-observe"))             # la vue commune n'est pas touchée
    # Hors périmètre : le puits global reste en vigueur (view-first) et seuls les noms fermés sont refusés.
    assert ctl("evasion", "poser", "192.168.1.77", "-", "dns.google") == 0
    assert vue(monde["conf"].read_text(), "sbx-evasion-4-c0a8014d") == ["    view-first: yes", '    local-zone: "dns.google." always_refuse']


@pytest.mark.parametrize("args", [
    ("quarantaine", "poser", "192.168.1.50\nserver:", "-", "9999999999"),
    ("quarantaine", "poser", "fe80::1%eth0", "-", "9999999999"),
    ("quarantaine", "poser", "pas-une-ip", "-", "9999999999"),
    ("quarantaine", "poser", TV, "AA:BB:CC:DD:EE:01", "9999999999"),
    ("quarantaine", "poser", TV, "-", "1"),
    ("quarantaine", "poser", TV, "-", "12abc"),
    ("quarantaine", "poser", TV, "-"),
    ("quarantaine", "lever", "x;y"),
    ("evasion", "poser", TV, "-", 'dns.google"; server: x'),
    ("evasion", "poser", TV, "-", ""),
    ("evasion", "poser", TV, "-", "dns.google", "trop"),
])
def test_ip_invalide_refusee(monde, capsys, args):
    declarer(monde, "block")
    assert ctl(*args) == 1
    assert json.loads(capsys.readouterr().out)["ok"] is False
    assert "quarantaines" not in json.loads((monde["etat"] / "etat.json").read_text())


def test_quarantaine_refusee_sans_adresse_de_box(monde, capsys):
    declarer(monde, "block")
    assert ctl("quarantaine", "poser", TV, "-", fin(), box=(None, None)) == 1
    assert json.loads(capsys.readouterr().out)["ok"] is False


def test_etat_garde_borne_et_valide():
    base = {"actif": True, "clients": []}
    q = [{"ip": f"192.168.1.{i}", "mac": "", "fin": 10} for i in range(17)]
    with pytest.raises(dnstv.ErreurTV):
        dnstv.valider_etat({**base, "quarantaines": q})
    assert dnstv.valider_etat({**base, "quarantaines": q[:16]})["quarantaines"][15]["ip"] == "192.168.1.15"
    with pytest.raises(dnstv.ErreurTV):
        dnstv.valider_etat({**base, "evasions": [{"ip": TV, "mac": "", "noms": ["pas un nom"]}]})
    assert "quarantaines" not in dnstv.valider_etat(base)                        # anciens états : format inchangé


def test_quarantaine_echue_nest_plus_rendue():
    e = {"actif": True, "clients": [], "quarantaines": [{"ip": TV, "mac": "", "fin": 100}]}
    assert "sbx-quarantaine" not in dnstv.rendre_unbound(e, {}, {}, adresses_box=BOX, maintenant=200)
    assert "sbx-quarantaine" in dnstv.rendre_unbound(e, {}, {}, adresses_box=BOX, maintenant=50)


def test_sudoers_garde_verbes_limites():
    s = (ICI / "sudoers.d" / "secubox-adguard-garde").read_text()
    assert "secubox-adguard-garde" in (ICI / "debian" / "rules").read_text()
    regles = [ligne for ligne in s.splitlines() if ligne.startswith("secubox-garde ")]
    assert len(regles) == 1
    commandes = [c.strip() for c in regles[0].split("NOPASSWD:", 1)[1].split(",")]
    assert sorted(commandes) == sorted(f"/usr/sbin/secubox-adguard-tv {v} {g} *" for v in ("quarantaine", "evasion") for g in ("poser", "lever"))
    assert not [ligne for ligne in s.splitlines() if ligne.startswith("secubox ")]
    secubox = [ligne for ligne in (ICI / "sudoers.d" / "secubox-adguard-tv").read_text().splitlines() if ligne.startswith("secubox ")][0]
    assert "quarantaine" not in secubox and "evasion" not in secubox


def test_garde_prend_le_verrou_partage(monde):
    import contextlib
    from api import dnstv_regles
    declarer(monde, "block")
    journal, tenu = [], {"partage": False, "ctl": False}

    def regarder(m):
        @contextlib.contextmanager
        def partage(*a, **k):
            assert not tenu["ctl"]                                               # ordre : le verrou partagé AVANT celui du contrôleur
            tenu["partage"] = True
            journal.append("partage+")
            yield
            tenu["partage"] = False
            journal.append("partage-")
        orig_ctl = m.verrou_controleur

        @contextlib.contextmanager
        def ctlv():
            with orig_ctl():
                tenu["ctl"] = True
                yield
                tenu["ctl"] = False
        orig_ecrire, orig_rendre = m._ecrire_etat_root, m.dnstv.rendre_unbound

        def ecrire(e):
            assert tenu["partage"] and tenu["ctl"]
            journal.append("ecrire")
            return orig_ecrire(e)

        def rendre(*a, **k):
            assert tenu["partage"] and tenu["ctl"]
            journal.append("rendre")
            return orig_rendre(*a, **k)
        m.dnstv_regles.verrou = partage
        m.verrou_controleur = ctlv
        m._ecrire_etat_root = ecrire
        m.dnstv.rendre_unbound = rendre
    orig = (dnstv_regles.verrou, dnstv.rendre_unbound)
    try:
        assert ctl("quarantaine", "poser", TV, "-", fin(), avant=regarder) == 0
    finally:
        dnstv_regles.verrou, dnstv.rendre_unbound = orig
    assert journal[0] == "partage+" and journal[-1] == "partage-" and "ecrire" in journal and "rendre" in journal


def test_verrou_cree_par_root_reste_au_proprietaire_du_dossier(monde, monkeypatch):
    import os as _os
    declarer(monde, "block")
    verrou = monde["etat"] / ".regles.lock"
    verrou.unlink(missing_ok=True)
    poses = []
    vrai = _os.fchown
    monkeypatch.setattr(_os, "fchown", lambda fd, u, g: poses.append((u, g)) or vrai(fd, u, g))
    real = _os.fstat

    def faux_fstat(fd):                                                          # simule un fichier créé par root (uid différent)
        st = real(fd)
        if _os.readlink(f"/proc/self/fd/{fd}").endswith(".regles.lock"):
            return _os.stat_result((st.st_mode, st.st_ino, st.st_dev, st.st_nlink, 0, 0, *tuple(st)[6:10]))
        return st
    monkeypatch.setattr(_os, "fstat", faux_fstat)
    assert ctl("evasion", "poser", TV, "-", "dns.google") == 0
    d = monde["etat"].stat()
    assert verrou.exists() and (d.st_uid, d.st_gid) in poses
