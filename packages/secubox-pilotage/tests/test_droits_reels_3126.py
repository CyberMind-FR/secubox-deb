# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Défauts du banc gk2 (2026-10-30, #3126) : droits RÉELS du contrôleur, pas ceux d'un dossier temporaire.

1. /var/lib/secubox/p2p est 0700 secubox : le compte secubox-pilotage n'y lit rien. L'identité vient de la projection publique
   `p2p-public/pairs-enroles.json` publiée par secubox-p2p ; illisible ou absente → aucune box, refus journalisé, jamais d'exception.
2. audit.log : la règle AppArmor `a` laisse passer l'ouverture O_WRONLY|O_APPEND (le noyau la médie en MAY_APPEND) mais pas l'écriture :
   write() → rw_verify_area → security_file_permission(MAY_WRITE), refusée hors `w`. Patron du dépôt (relais Go, dns-listes, webfilter) : `w`.
3. Chaque fichier qu'un AUTRE paquet pose et que le contrôleur lit doit être atteignable avec les modes de ses postinst/code.
"""
import json
import logging
import os
import re
from pathlib import Path

import pytest

from pilotage import identite as I

ICI = Path(__file__).resolve().parents[1]
PAQUETS = ICI.parent
COMPTE, GROUPES = "secubox-pilotage", {"secubox-pilotage", "secubox"}  # SupplementaryGroups=secubox


def code(chemin: Path) -> str:
    return "\n".join(x for x in chemin.read_text(encoding="utf-8").splitlines() if not x.lstrip().startswith("#"))


# ---------------------------------------------------------------- 1. identité depuis la projection

def test_identite_lit_la_projection_publique_jamais_p2p_prive():
    assert I.PEERS_DEFAUT == Path("/var/lib/secubox/p2p-public/pairs-enroles.json")
    src = code(ICI / "pilotage" / "identite.py")
    assert "/var/lib/secubox/p2p/" not in src


def _projection(tmp_path, pairs):
    f = tmp_path / "pairs-enroles.json"
    f.write_text(json.dumps({"version": 1, "pairs": pairs}))
    return f


def test_identite_depuis_la_projection(tmp_path):
    f = _projection(tmp_path, [{"name": "gk5", "mesh_ip": "10.10.0.10", "fingerprint": "f", "joined_via": "master-link"},
                               {"name": "sans-empreinte", "mesh_ip": "10.10.0.12"}])
    I._cache.clear()
    b = I.box_par_adresse("10.10.0.10", peers=f, pairs_autoload=tmp_path / "x")
    assert b is not None and b.nom == "gk5" and b.reseau == "maillage"
    assert I.box_par_adresse("10.10.0.12", peers=f, pairs_autoload=tmp_path / "x") is None
    assert I.noms_du_maillage(peers=f, hote=lambda: "maitre") == {"gk5", "maitre"}


@pytest.mark.skipif(os.geteuid() == 0, reason="root lit tout")
def test_projection_illisible_refus_propre_et_journalise(tmp_path, caplog):
    f = _projection(tmp_path, [{"name": "gk5", "mesh_ip": "10.10.0.10", "fingerprint": "f", "joined_via": "m"}])
    f.chmod(0)
    I._cache.clear()
    with caplog.at_level(logging.WARNING, logger="pilotage.identite"):
        assert I.box_par_adresse("10.10.0.10", peers=f, pairs_autoload=tmp_path / "x") is None
        assert I.box_par_adresse("10.10.0.10", peers=f, pairs_autoload=tmp_path / "x") is None
    msgs = [r.getMessage() for r in caplog.records if str(f) in r.getMessage()]
    assert len(msgs) == 1 and "illisible" in msgs[0]  # une ligne par changement d'état, pas une par bonjour


def test_projection_absente_refus_propre_et_journalise(tmp_path, caplog):
    I._cache.clear()
    with caplog.at_level(logging.WARNING, logger="pilotage.identite"):
        assert I.box_par_adresse("10.10.0.10", peers=tmp_path / "absent.json", pairs_autoload=tmp_path / "x") is None
    assert any("absent.json" in r.getMessage() for r in caplog.records)


# ---------------------------------------------------------------- 2. audit.log : patron `w` du dépôt

PROFILS_PILOTAGE = ("secubox-pilotage-api", "secubox-pilotage-invite")


@pytest.mark.parametrize("profil", PROFILS_PILOTAGE)
def test_profils_pilotage_audit_en_w(profil):
    c = code(ICI / "apparmor" / profil)
    assert "/var/log/secubox/audit.log w," in c
    assert "/var/log/secubox/audit.log a," not in c


def test_aucun_profil_du_depot_n_accorde_audit_log_en_a_seul():
    """`a` seul casse write() sur un descripteur O_WRONLY|O_APPEND : aucun profil du dépôt ne doit y revenir."""
    fautifs = []
    for p in PAQUETS.glob("*/apparmor/*"):
        if p.is_file() and re.search(r"^\s*/var/log/secubox/audit\.log\s+a\s*,", code(p), re.M):
            fautifs.append(str(p.relative_to(PAQUETS)))
    assert fautifs == []


def test_audit_ouvre_sans_creation_en_ajout():
    src = code(ICI / "pilotage" / "audit.py")
    assert "O_WRONLY | os.O_APPEND | os.O_NOFOLLOW" in src and "O_CREAT" not in src


def test_unite_maitre_ecrit_le_journal_et_garde_le_groupe_secubox():
    u = (ICI / "systemd" / "secubox-pilotage.service").read_text()
    bloc = u[u.index("User=secubox-pilotage"):]
    bloc = bloc[:bloc.index("[Install]")]
    assert re.search(r"^ReadWritePaths=.*\s/var/log/secubox(\s|$)", bloc, re.M)
    assert "SupplementaryGroups=secubox" in bloc
    assert "InaccessiblePaths" not in bloc or "/var/log/secubox" not in bloc


# ---------------------------------------------------------------- 3. droits réels des fichiers d'autres paquets

def _derniers_modes(postinst: str, dossier: str):
    """(mode, propriétaire, groupe) du dernier `install -d` sur `dossier` dans le postinst (l'état qui reste), ou None."""
    dernier = None
    for ligne in postinst.splitlines():
        ligne = ligne.split("#")[0]
        if "install -d" not in ligne or not re.search(re.escape(dossier) + r"(\s|$)", ligne):
            continue
        m = re.search(r"-m\s+(\d+)", ligne)
        o = re.search(r"-o\s+(\S+)", ligne)
        g = re.search(r"-g\s+(\S+)", ligne)
        dernier = (int(m.group(1), 8) if m else 0o755, o.group(1) if o else "root", g.group(1) if g else "root")
    for ligne in postinst.splitlines():  # un chmod ultérieur l'emporte aussi
        m = re.search(r"chmod\s+(\d+)\s+" + re.escape(dossier) + r"(\s|$)", ligne.split("#")[0])
        if m and dernier:
            dernier = (int(m.group(1), 8),) + dernier[1:]
    return dernier


def _traversable(mode, proprio, groupe, droit):
    if proprio == COMPTE:
        return bool(mode & (droit << 6))
    if groupe in GROUPES:
        return bool(mode & (droit << 3))
    return bool(mode & droit)


# Chaque fichier lu par le contrôleur dans l'état d'un autre paquet : (chemin par défaut du code, paquet, source qui pose le dossier).
LECTURES_EXTERNES = [
    (I.PEERS_DEFAUT, "secubox-p2p", "debian/postinst"),
    (I.PAIRS_AUTOLOAD_DEFAUT, "secubox-autoload", "autoload/projection.py"),
]


@pytest.mark.parametrize("chemin,paquet,source", LECTURES_EXTERNES, ids=lambda x: str(x))
def test_fichier_externe_atteignable_par_le_compte_du_pilotage(chemin, paquet, source):
    dossier = str(chemin.parent)
    texte = code(PAQUETS / paquet / source)
    if source.endswith("postinst"):
        modes = _derniers_modes(texte, dossier)
        assert modes is not None, f"{paquet} ne crée pas {dossier}"
        assert _traversable(*modes, 0o1) and _traversable(*modes, 0o4), f"{dossier} {oct(modes[0])} {modes[1]}:{modes[2]} fermé au pilotage"
    else:  # dossier créé par le code root : mkdir et fchmod 0755, fichier 0644
        assert "0o755" in texte and "0o644" in texte
    # le profil AppArmor du contrôleur lit EXACTEMENT ce fichier et son dossier
    profil = code(ICI / "apparmor" / "secubox-pilotage-api")
    assert f"{dossier}/ r," in profil and f"{chemin} r," in profil
    # et ce qui est 0700 dans un autre paquet n'est jamais lu par le contrôleur
    p2p = code(PAQUETS / "secubox-p2p" / "debian" / "postinst")
    prive = _derniers_modes(p2p, "/var/lib/secubox/p2p")
    assert prive is not None and not _traversable(*prive, 0o1)
    assert "/var/lib/secubox/p2p/" not in profil


def test_le_test_de_droits_attrape_le_defaut_d_origine():
    """Garde du garde : l'ancien chemin (peers.json sous p2p/ 0700) serait refusé par cette analyse."""
    p2p = code(PAQUETS / "secubox-p2p" / "debian" / "postinst")
    assert not _traversable(*_derniers_modes(p2p, "/var/lib/secubox/p2p"), 0o1)
