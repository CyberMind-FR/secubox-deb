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


def _version(module):
    ch = RACINE / "packages" / f"secubox-{module}" / "debian" / "changelog"
    m = re.match(r"secubox-[a-z0-9-]+ \(([^)]+)\)", ch.read_text())
    return m.group(1) if m else None


def _num(v):
    return tuple(int(x) for x in re.findall(r"\d+", v.split("-")[0].split(":")[-1])[:3])


def test_les_contraintes_de_version_des_profils_sont_satisfaisables():
    """`secubox-lite` exigeait secubox-antirootkit (>= 1.0) alors que ce paquet est en 0.1.6 :
    le profil était impossible à installer, et toutes les images échouaient."""
    violations = []
    for profil in ("lite", "isp", "full"):
        texte = (RACINE / "packages" / f"secubox-{profil}" / "debian" / "control").read_text()
        bloc = re.search(r"^Depends:(.*?)(?=^[A-Z][A-Za-z-]*:)", texte, re.S | re.M).group(1)
        for ligne in bloc.splitlines():
            if ligne.strip().startswith("#"):
                continue
            for module, exige in re.findall(r"secubox-([a-z0-9-]+)\s*\(>=\s*([0-9][^)]*)\)", ligne):
                v = _version(module)
                if v is not None and _num(v) < _num(exige):
                    violations.append(f"secubox-{profil} exige secubox-{module} (>= {exige}), le paquet est en {v}")
    assert not violations, violations
