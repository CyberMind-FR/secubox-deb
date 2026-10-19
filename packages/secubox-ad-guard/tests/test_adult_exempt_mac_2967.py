# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""secubox-adguard-adult-sync : exemption par MAC (#2967, suite de #2964).

Constat gk2 (2026-10-19) : l'exemption IPv4 (192.168.1.3) ne protégeait pas
l'appareil, parce que ses requêtes DNS partaient d'une adresse IPv6
temporaire (extensions de confidentialité RFC 4941, qui tourne environ
chaque jour) — jamais listée dans `adult-exempt-ip.txt`. La MAC, elle, ne
change pas : on résout ses adresses COURANTES depuis la table de
voisinage du noyau (`ip neigh show`) à chaque synchronisation."""
import importlib.machinery
import importlib.util
from pathlib import Path

import pytest

ICI = Path(__file__).resolve().parent.parent
SCRIPT = ICI / "sbin" / "secubox-adguard-adult-sync"

# Extrait réaliste de `ip -4/-6 neigh show` sur gk2 (#2967) : une IPv4
# stable, PLUSIEURS IPv6 temporaires pour la MÊME MAC (rotation), un lien
# local (fe80::, à ignorer) et une entrée FAILED (sans lladdr, à ignorer).
VOISINAGE = """\
192.168.1.3 dev eth2 lladdr ac:19:8e:ab:26:c9 REACHABLE
2a01:e0a:dec:c4e0:f757:6ef:bb85:b67d dev eth2 lladdr ac:19:8e:ab:26:c9 REACHABLE
2a01:e0a:dec:c4e0:8896:4dc8:4f84:c0b9 dev eth2 lladdr ac:19:8e:ab:26:c9 STALE
fe80::1120:1343:33d4:9f2d dev eth2 lladdr ac:19:8e:ab:26:c9 REACHABLE
2a01:e0a:dec:c4e0:ad8b:614e:27fa:6bbe dev eth2 FAILED
192.168.1.42 dev eth2 lladdr 38:07:16:94:fb:5b REACHABLE
"""


@pytest.fixture
def mod():
    loader = importlib.machinery.SourceFileLoader("adult_exempt_mac_test", str(SCRIPT))
    spec = importlib.util.spec_from_loader("adult_exempt_mac_test", loader)
    m = importlib.util.module_from_spec(spec)
    loader.exec_module(m)
    return m


def test_parse_voisinage_ignore_le_lien_local_et_les_echecs(mod):
    v = mod._parse_voisinage(VOISINAGE)
    assert v["ac:19:8e:ab:26:c9"] == {
        "192.168.1.3",
        "2a01:e0a:dec:c4e0:f757:6ef:bb85:b67d",
        "2a01:e0a:dec:c4e0:8896:4dc8:4f84:c0b9",
    }
    assert v["38:07:16:94:fb:5b"] == {"192.168.1.42"}


def test_ips_des_macs_resout_toutes_les_adresses_courantes(mod):
    ips = mod._ips_des_macs(["ac:19:8e:ab:26:c9"], lire=lambda: VOISINAGE)
    assert set(ips) == {
        "192.168.1.3",
        "2a01:e0a:dec:c4e0:f757:6ef:bb85:b67d",
        "2a01:e0a:dec:c4e0:8896:4dc8:4f84:c0b9",
    }


def test_mac_introuvable_dans_le_voisinage_ne_leve_rien(mod):
    assert mod._ips_des_macs(["00:00:00:00:00:00"], lire=lambda: VOISINAGE) == []


def test_aucune_mac_ne_consulte_pas_le_voisinage(mod, monkeypatch):
    appele = []
    monkeypatch.setattr(mod, "_voisinage_brut", lambda: appele.append(1) or "")
    assert mod._ips_des_macs([]) == []
    assert appele == []


def test_exempt_ips_fusionne_ip_figees_et_resolues_par_mac_sans_doublon(mod, tmp_path, monkeypatch):
    mod.EXEMPT_IP = tmp_path / "adult-exempt-ip.txt"
    mod.EXEMPT_IP.write_text("192.168.1.3\n")      # déjà listée en dur…
    mod.EXEMPT_MAC = tmp_path / "adult-exempt-mac.txt"
    mod.EXEMPT_MAC.write_text("ac:19:8e:ab:26:c9\n")  # … ET par MAC (même appareil)
    monkeypatch.setattr(mod, "_voisinage_brut", lambda: VOISINAGE)
    ips = mod._exempt_ips()
    assert ips.count("192.168.1.3") == 1
    assert "2a01:e0a:dec:c4e0:f757:6ef:bb85:b67d" in ips
    assert "2a01:e0a:dec:c4e0:8896:4dc8:4f84:c0b9" in ips


def test_commentaires_et_lignes_vides_ignores_dans_exempt_mac(mod, tmp_path, monkeypatch):
    mod.EXEMPT_IP = tmp_path / "adult-exempt-ip.txt"
    mod.EXEMPT_MAC = tmp_path / "adult-exempt-mac.txt"
    mod.EXEMPT_MAC.write_text("# l'appareil de la chambre\nac:19:8e:ab:26:c9  # commentaire\n\n")
    monkeypatch.setattr(mod, "_voisinage_brut", lambda: VOISINAGE)
    assert "192.168.1.3" in mod._exempt_ips()
