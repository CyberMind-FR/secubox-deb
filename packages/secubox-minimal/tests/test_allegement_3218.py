# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3218 — allègement du méta-paquet minimal, d'après le banc de l'ESPRESSObin de 1 Go (gk5, 2026-10-28).

DPI, nDPId, Courbes et Routes (netdiag) quittent les Depends et passent en Conflicts : le propriétaire ne les veut plus sur ces
box, et un Conflicts les fait retirer par apt à la mise à jour du méta-paquet."""
import re
from pathlib import Path

PAQUETS = Path(__file__).resolve().parents[2]
CONTROL = (PAQUETS / "secubox-minimal" / "debian" / "control").read_text(encoding="utf-8")
BLOC = CONTROL.split("Package: secubox-minimal", 1)[1]
RETIRES = {"secubox-dpi", "secubox-ndpid-engine", "secubox-courbes", "secubox-routes"}
SOCLE = {"secubox-core", "secubox-aggregator", "secubox-system", "secubox-hardening", "secubox-hub", "secubox-portal",
         "secubox-auth", "secubox-autoload-agent", "secubox-wireguard", "secubox-dns-guard", "secubox-ad-guard",
         "secubox-nac", "secubox-freebox", "secubox-ipv6guard", "secubox-webfilter"}


def _champ(nom):
    m = re.search(rf"^{nom}:((?:.*\n?)(?:(?:[ \t].*|#.*)\n?)*)", BLOC, re.M)
    texte = re.sub(r"^#.*$", "", m.group(1), flags=re.M) if m else ""
    return set(re.findall(r"(secubox-[a-z0-9.+-]+)", texte))


def test_les_depends_retires_ne_sont_plus_exiges():
    assert not RETIRES & _champ("Depends"), RETIRES & _champ("Depends")


def test_les_retires_sont_en_conflicts():
    assert RETIRES <= _champ("Conflicts"), RETIRES - _champ("Conflicts")


def test_le_socle_reste_exige_dont_portal_qui_livre_login_html():
    assert SOCLE <= _champ("Depends"), SOCLE - _champ("Depends")
    assert (PAQUETS / "secubox-portal" / "www" / "login.html").is_file()


def test_aucun_paquet_du_socle_n_exige_un_retire():
    """Un Conflicts sur un paquet EXIGÉ par le socle rendrait le méta-paquet ininstallable."""
    for p in SOCLE:
        ctl = (PAQUETS / p / "debian" / "control").read_text(encoding="utf-8")
        m = re.search(r"^Depends:((?:.*\n?)(?:(?:[ \t].*|#.*)\n?)*)", ctl.split(f"Package: {p}", 1)[1], re.M)
        exiges = set(re.findall(r"(secubox-[a-z0-9.+-]+)", re.sub(r"^#.*$", "", m.group(1), flags=re.M))) if m else set()
        assert not exiges & RETIRES, (p, exiges & RETIRES)

