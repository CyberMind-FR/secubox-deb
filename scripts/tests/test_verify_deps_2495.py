# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""#2495 — l'audit des dépendances d'une image : alternatives, paquets virtuels, états, et code de sortie."""
import importlib.util
import pathlib

import pytest

SCRIPT = pathlib.Path(__file__).resolve().parents[2] / "image" / "verify-deps.py"
spec = importlib.util.spec_from_file_location("verify_deps", SCRIPT)
V = importlib.util.module_from_spec(spec)
spec.loader.exec_module(V)


def _etat(tmp_path, blocs):
    d = tmp_path / "var" / "lib" / "dpkg"; d.mkdir(parents=True)
    (d / "status").write_text("\n\n".join(blocs) + "\n\n")
    return tmp_path


def _p(nom, deps="", statut="install ok installed", provides=""):
    s = f"Package: {nom}\nStatus: {statut}\nVersion: 1\n"
    if deps:
        s += f"Depends: {deps}\n"
    if provides:
        s += f"Provides: {provides}\n"
    return s.rstrip("\n")


def test_dependance_absente_est_rapportee_et_le_code_est_1(tmp_path, capsys):
    r = _etat(tmp_path, [_p("secubox-premier-pas", "python3 (>= 3.11), systemd-timesyncd | time-daemon, gpgv"), _p("python3"), _p("gpgv")])
    assert V.main([str(r)]) == 1
    err = capsys.readouterr().err
    assert "secubox-premier-pas" in err and "systemd-timesyncd | time-daemon" in err and "gpgv" not in err.replace("secubox", "")


def test_une_alternative_presente_ou_un_paquet_virtuel_fourni_suffit(tmp_path):
    r = _etat(tmp_path, [_p("secubox-core", "systemd-timesyncd | time-daemon, mail-transport-agent"), _p("chrony", provides="time-daemon"), _p("postfix", provides="mail-transport-agent")])
    assert V.manques(r / "var/lib/dpkg/status") == {}
    assert V.main([str(r)]) == 0


def test_les_contraintes_de_version_et_architectures_ne_gênent_pas_la_presence(tmp_path):
    r = _etat(tmp_path, [_p("secubox-x", "libfoo1 (>= 2.0), python3:any, bar [amd64]"), _p("libfoo1"), _p("python3"), _p("bar")])
    assert V.manques(r / "var/lib/dpkg/status") == {}


def test_un_paquet_non_installe_ou_a_moitie_installe_ne_fournit_rien(tmp_path):
    r = _etat(tmp_path, [_p("secubox-x", "dep-a, dep-b"), _p("dep-a", statut="install ok unpacked"), _p("dep-b", statut="deinstall ok config-files")])
    assert set(V.manques(r / "var/lib/dpkg/status")["secubox-x"]) == {"dep-a", "dep-b"}


def test_seuls_les_paquets_du_prefixe_sont_audites(tmp_path):
    r = _etat(tmp_path, [_p("nginx", "libabsente"), _p("secubox-y", "")])
    assert V.manques(r / "var/lib/dpkg/status") == {}


def test_statut_absent_ou_racine_invalide(tmp_path, capsys):
    assert V.main([str(tmp_path)]) == 2 and V.main([]) == 2


def test_sur_la_vraie_forme_d_un_fichier_status_multiligne(tmp_path):
    bloc = "Package: secubox-z\nStatus: install ok installed\nDepends: aaa,\n bbb | ccc,\n ddd\nDescription: x"
    r = _etat(tmp_path, [bloc, _p("aaa"), _p("ccc")])
    assert V.manques(r / "var/lib/dpkg/status") == {"secubox-z": ["ddd"]}
