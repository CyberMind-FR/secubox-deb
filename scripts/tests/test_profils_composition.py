# SPDX-License-Identifier: LicenseRef-CMSD-1.0
"""Composition des profils : lite = protections, isp = lite + hebergement simple, full = isp + parc."""
import re
from pathlib import Path

RACINE = Path(__file__).resolve().parents[2]


def deps(profil):
    texte = (RACINE / "packages" / f"secubox-{profil}" / "debian" / "control").read_text()
    bloc = re.search(r"^Depends:(.*?)(?=^[A-Z][A-Za-z-]*:)", texte, re.S | re.M).group(1)
    sans_commentaires = "\n".join(l for l in bloc.splitlines() if not l.strip().startswith("#"))
    return set(re.findall(r"secubox-([a-z0-9-]+)", sans_commentaires))


PROTECTIONS = {"waf", "waf-ng", "dpi", "ndpid-engine", "toolbox", "toolbox-ng", "threats",
               "antirootkit", "mac-guard", "ad-guard", "webfilter", "vortex-firewall", "haproxy"}
APPLICATIONS = {"nextcloud", "gitea", "jellyfin", "peertube", "mail", "metablogizer", "publish", "radio"}


def test_lite_porte_toutes_les_protections():
    assert PROTECTIONS <= deps("lite")


def test_lite_ne_heberge_rien():
    assert not (APPLICATIONS & deps("lite"))


def test_isp_herite_de_lite_et_heberge_simplement():
    d = deps("isp")
    assert "lite" in d
    assert {"metablogizer", "publish"} <= d
    assert not ({"nextcloud", "gitea", "jellyfin", "peertube", "mail"} & d)


def test_full_herite_de_isp_et_porte_les_applications():
    d = deps("full")
    assert "isp" in d
    assert {"nextcloud", "gitea", "jellyfin", "peertube", "mail"} <= d
