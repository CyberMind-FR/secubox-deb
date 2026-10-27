# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3201 — paquet 1.6.0 : dnsmasq lit les fragments des ports isolés, AppArmor, sudoers, dossier du postinst."""
import re
from pathlib import Path

PKG = Path(__file__).resolve().parents[1]
DHCPD = "/var/lib/secubox-netmodes/dhcp.d"


def lire(chemin: str) -> str:
    return (PKG / chemin).read_text(encoding="utf-8")


def sans_commentaires(texte: str) -> str:
    return "\n".join(ligne for ligne in texte.splitlines() if not ligne.lstrip().startswith("#"))


def test_dhcp_lit_les_fragments():
    texte = re.sub(r"\\\n\s*", " ", lire("debian/secubox-lan-dhcp.service"))
    lignes = [ligne.strip() for ligne in texte.splitlines() if ligne.strip().startswith("ExecStart=")]
    assert lignes == ["ExecStart=/usr/sbin/dnsmasq --keep-in-foreground --conf-file=/var/lib/secubox-netmodes/lan-dhcp.conf"
                      f" --conf-dir={DHCPD},*.conf --pid-file="]


def test_apparmor_fragments():
    regles = [ligne.strip() for ligne in sans_commentaires(lire("apparmor/secubox-lan-dhcp")).splitlines() if ligne.strip()]
    assert f"{DHCPD}/ r," in regles
    assert f"{DHCPD}/*.conf r," in regles
    for regle in regles:
        if "dhcp.d" in regle:
            assert regle.endswith(" r,"), regle      # lecture seule : aucune règle en écriture


def test_sudoers_verbes_exacts():
    lignes = [ligne for ligne in sans_commentaires(lire("debian/secubox-netmodes.sudoers")).splitlines() if ligne.strip()]
    assert len(lignes) == 1
    _, commandes = lignes[0].split("NOPASSWD:", 1)
    grants = [c.strip() for c in commandes.split(",")]
    verbes = {g.split()[1] for g in grants}
    assert verbes == {"routeur-etat", "routeur-appliquer", "routeur-confirmer", "routeur-retour", "port-couper",
                      "port-retablir", "port-isoler", "port-rattacher"}
    assert len(grants) == 8
    for g in grants:
        assert g.startswith("/usr/sbin/netmodesctl ")
        assert g.count("*") == (0 if g.endswith("routeur-etat") else 1)       # un seul joker, final
        assert g.endswith("*") or g.endswith("routeur-etat")
    assert "/usr/sbin/netmodesctl port-isoler *" in grants
    assert "/usr/sbin/netmodesctl port-rattacher *" in grants


def test_postinst_dossier_fragments():
    p = sans_commentaires(lire("debian/postinst"))
    ligne = f"install -d -m 0700 -o root -g root {DHCPD}"
    assert ligne in p
    assert p.index(ligne) < p.index("systemctl restart secubox-lan-dhcp.service")
