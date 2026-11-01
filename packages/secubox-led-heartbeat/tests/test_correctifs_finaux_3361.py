# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Vague de corrections finale de mochabinleds (ref #3361) : propriétaires, nft, planchers."""
import json
import os
import re
import shutil
import subprocess
import time
from pathlib import Path

import pytest

import flux
import releves
from reference import Reference
from test_releves_3361 import racine  # noqa: F401  (fixture)

PAQUET = Path(__file__).resolve().parents[1]
T0 = 1793509200.0


def _nft_json(r, paquets=42):
    p = r / "run/secubox-leds/nft.json"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps({"nftables": [{"counter": {"name": "sbx_drop_in", "packets": paquets}}]}))
    return p


# -- 1. propriétaires --------------------------------------------------------------

def test_sources_declarent_leurs_proprietaires():
    p = releves.PROPRIETAIRES
    assert "secubox-actord" in p["actor"]
    assert "secubox" in p["cache"] and "secubox" in p["adguard"]
    assert set(p) >= {"actor", "cache", "adguard", "proc", "nft"}


def test_uids_root_toujours_compte_inconnu_ignore():
    assert releves._uids(("compte-qui-n-existe-pas-3361",)) == {0}
    assert 0 in releves._uids(())


@pytest.mark.parametrize("source,prefixe", [("actor", "actor."), ("cache", "waf."),
                                            ("adguard", "adguard."), ("proc", "reseau.")])
def test_mauvais_proprietaire_cle_absente(racine, monkeypatch, source, prefixe):  # noqa: F811
    p = dict(releves.PROPRIETAIRES)
    p[source] = ("compte-qui-n-existe-pas-3361",)
    monkeypatch.setattr(releves, "PROPRIETAIRES", p)
    v = releves.releves(racine)
    assert not any(k.startswith(prefixe) for k in v), source
    assert v  # les autres sources restent lues


def test_lire_exige_un_proprietaire(racine):  # noqa: F811
    j = racine / "run/secubox/actord-mesures.json"
    assert releves._lire(j, ("compte-qui-n-existe-pas-3361",)) is None
    assert releves._lire(j, (releves.pwd.getpwuid(os.getuid()).pw_name,)) is not None


# -- 2. nft.json -------------------------------------------------------------------

def test_nft_json_source_fw_bloques(racine):  # noqa: F811
    _nft_json(racine, 42)
    assert releves.releves(racine)["fw.bloques"] == 42.0


def test_nft_json_perime_ignore(racine):  # noqa: F811
    p = _nft_json(racine)
    vieux = time.time() - 61
    os.utime(p, (vieux, vieux))
    assert "fw.bloques" not in releves.releves(racine)


def test_nft_json_mauvais_proprietaire(racine, monkeypatch):  # noqa: F811
    _nft_json(racine)
    p = dict(releves.PROPRIETAIRES)
    p["nft"] = ()
    monkeypatch.setattr(releves, "PROPRIETAIRES", p)
    assert "fw.bloques" not in releves.releves(racine)


def test_nft_json_invalide_sans_zero(racine):  # noqa: F811
    (_nft_json(racine)).write_text("pas du json")
    assert "fw.bloques" not in releves.releves(racine)


def test_collecteur_ne_lance_plus_nft():
    src = (PAQUET / "usr/lib/secubox-led-heartbeat/flux.py").read_text()
    assert "subprocess" not in src and "/usr/sbin/nft" not in src


def _unite(nom):
    return (PAQUET / "systemd" / nom).read_text()


def _a(u, ligne):
    return re.search(r"^" + re.escape(ligne) + r"$", u, re.M)


def test_unite_flux_sans_capacite():
    u = _unite("secubox-led-flux.service")
    assert "AmbientCapabilities" not in u and "CAP_NET_ADMIN" not in u
    assert _a(u, "CapabilityBoundingSet=")
    assert _a(u, "RestrictAddressFamilies=AF_UNIX")


def test_apparmor_flux_sans_reseau_ni_nft():
    p = (PAQUET / "apparmor/secubox-led-flux").read_text()
    for interdit in ("capability net_admin", "network netlink", "/usr/sbin/nft", "/etc/nftables.conf",
                     "/etc/iproute2"):
        assert interdit not in p, interdit
    assert "/run/secubox-leds/nft.json r," in p


def test_unite_nft():
    u = _unite("secubox-led-nft.service")
    for ligne in ("User=root", "CapabilityBoundingSet=CAP_NET_ADMIN", "NoNewPrivileges=yes",
                  "ProtectSystem=strict", "ReadWritePaths=/run/secubox-leds", "PrivateTmp=yes",
                  "Nice=19", "CPUWeight=10", "ExecCondition=/usr/sbin/secubox-led-board",
                  "AppArmorProfile=secubox-led-nft", "RestrictAddressFamilies=AF_NETLINK AF_UNIX",
                  "ExecStart=/usr/sbin/secubox-led-nft", "After=secubox-led-flux.service",
                  "Requires=secubox-led-flux.service"):
        assert _a(u, ligne), ligne
    assert "AmbientCapabilities" not in u


def test_apparmor_nft():
    p = (PAQUET / "apparmor/secubox-led-nft").read_text()
    assert "profile secubox-led-nft" in p and "flags=(complain)" not in p
    assert "capability net_admin," in p and "network netlink raw," in p
    execs = set(re.findall(r"^\s*(\S+)\s+[a-z]*x,", p, re.M))
    noms = {e.rsplit("/", 1)[-1] for e in execs}
    permis = {"nft", "sh", "dash", "{,da}sh", "timeout", "head", "mv", "sleep", "secubox-led-nft",
              # garde ExecCondition=/usr/sbin/secubox-led-board
              "secubox-led-board", "env", "bash", "tr", "grep"}
    assert noms <= permis, noms - permis
    ecritures = re.findall(r"^\s*(\S+)\s+[a-z]*w[a-z]*,", p, re.M)
    assert ecritures and all(e.startswith("/run/secubox-leds/nft.json") for e in ecritures), ecritures


def test_script_nft():
    s = (PAQUET / "usr/sbin/secubox-led-nft").read_text()
    assert s.startswith("#!/bin/sh")
    assert "/usr/sbin/nft -j list counters" in s
    assert "timeout 5" in s and "head -c 1048576" in s
    assert "mv -f" in s and "umask 022" in s and "sleep 10" in s
    assert not re.search(r"\b(rm|chmod|cat)\b", s.split("set -u", 1)[1])
    assert "/run/secubox-leds/nft.json" in s


@pytest.mark.skipif(shutil.which("shellcheck") is None, reason="shellcheck absent")
def test_script_nft_shellcheck():
    r = subprocess.run(["shellcheck", "-s", "sh", str(PAQUET / "usr/sbin/secubox-led-nft")],
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stdout


def test_rules_postinst_prerm_nft():
    rules = (PAQUET / "debian/rules").read_text()
    for f in ("usr/sbin/secubox-led-nft", "systemd/secubox-led-nft.service", "apparmor/secubox-led-nft"):
        assert re.search(r"install -D -m \d+ " + re.escape(f) + r" ", rules), f
    assert "dh_installsystemd --name=secubox-led-nft --no-enable --no-start" in rules
    p = (PAQUET / "debian/postinst").read_text()
    assert "apparmor_parser -r /etc/apparmor.d/secubox-led-nft" in p
    assert "systemctl enable --now secubox-led-flux.service secubox-led-nft.service" in p
    assert p.index("apparmor_parser -r /etc/apparmor.d/secubox-led-nft") < p.index(
        "systemctl enable --now secubox-led-flux.service secubox-led-nft.service")
    assert "systemctl stop secubox-led-nft.service" in (PAQUET / "debian/prerm").read_text()


# -- 3. groupe actord-ingest --------------------------------------------------------

def test_postinst_groupe_actord_non_fatal():
    p = (PAQUET / "debian/postinst").read_text()
    assert re.search(r"getent group actord-ingest >/dev/null \|\| addgroup --system actord-ingest"
                     r" \\\n\s+\|\| echo ", p)


# -- 4. ad-guard --------------------------------------------------------------------

def test_adguard_immuable_et_proprietaire():
    src = (PAQUET / "usr/lib/secubox-led-heartbeat/releves.py").read_text()
    assert "?mode=ro&immutable=1" in src


def test_adguard_journalise_une_fois(tmp_path, capsys):
    releves.releves(tmp_path)
    releves.releves(tmp_path)
    err = capsys.readouterr().err
    assert err.count("ad-guard") == 1


def test_adguard_mauvais_proprietaire_journalise(racine, monkeypatch, capsys):  # noqa: F811
    p = dict(releves.PROPRIETAIRES)
    p["adguard"] = ()
    monkeypatch.setattr(releves, "PROPRIETAIRES", p)
    assert not any(k.startswith("adguard.") for k in releves.releves(racine))
    assert "ad-guard" in capsys.readouterr().err


# -- 5. planchers -------------------------------------------------------------------

def test_planchers_defaut():
    p = flux.PLANCHERS_DEFAUT
    for k in ("fw.bloques", "waf.blocages", "adguard.requetes"):
        assert p[k] == 15.0, k
    for k in ("actor.evenements", "actor.suspects", "services.degrades"):
        assert p[k] == 2.5, k
    assert p["fw.paquets_in"] == p["fw.paquets_out"] == 60.0
    assert p["reseau.octets_in"] == p["reseau.octets_out"] == 50000.0
    toml = (PAQUET / "etc/secubox/leds.toml").read_text()
    assert flux.lire_planchers(PAQUET / "etc/secubox/leds.toml") == p
    assert '"fw.bloques" = 15.0' in toml


CUMULES_TEST = ("fw.bloques", "waf.blocages", "adguard.requetes", "fw.paquets_in", "fw.paquets_out")
JAUGES_TEST = ("actor.evenements", "actor.suspects", "services.degrades")


def _box_calme():
    ref = Reference(apprentissage=0)
    prec = {}
    for i in range(200):
        v = {k: 1000.0 for k in CUMULES_TEST}
        v.update({k: 0.0 for k in JAUGES_TEST})
        flux.pas_de_collecte(ref, prec, v, T0 + 10 * i, flux.PLANCHERS_DEFAUT)
    return ref, prec, T0 + 10 * 200


@pytest.mark.parametrize("cle", CUMULES_TEST + JAUGES_TEST)
def test_deux_evenements_restent_calmes(cle):
    ref, prec, t = _box_calme()
    v = {cle: (1002.0 if cle in CUMULES_TEST else 2.0)}
    assert flux.pas_de_collecte(ref, prec, v, t, flux.PLANCHERS_DEFAUT)[cle] <= 1


@pytest.mark.parametrize("cle", CUMULES_TEST + JAUGES_TEST)
def test_vingt_evenements_alertent(cle):
    ref, prec, t = _box_calme()
    v = {cle: (1020.0 if cle in CUMULES_TEST else 20.0)}
    assert flux.pas_de_collecte(ref, prec, v, t, flux.PLANCHERS_DEFAUT)[cle] >= 2


# -- 6. documentation ---------------------------------------------------------------

def test_documentation():
    readme = (PAQUET / "README.md").read_text()
    for mot in ("secubox-led-nft", "[flux.planchers]", "nft.json", "+ 2 s", "30 s"):
        assert mot in readme, mot
    toml = (PAQUET / "etc/secubox/leds.toml").read_text()
    assert "critique => niveau 3" not in toml and "critique => niveau 4" in toml
    aide = (PAQUET / "usr/sbin/secubox-led").read_text()
    assert "trafic" not in aide
    ch = (PAQUET / "debian/changelog").read_text().split("\n -- ")[0]
    assert "dpkg propose la fusion" not in ch
    assert "conservée, à remplacer à la main" in ch and "secubox-led-nft" in ch
