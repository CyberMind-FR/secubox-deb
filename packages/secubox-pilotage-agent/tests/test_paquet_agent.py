# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3126 L1 : contrôles statiques du paquet secubox-pilotage-agent (unité, règles, go.mod, AppArmor)."""
import re
from pathlib import Path

RACINE = Path(__file__).resolve().parents[1]


def lire(rel):
    return (RACINE / rel).read_text(encoding="utf-8")


def sans_commentaires(txt):
    return "\n".join(l for l in txt.splitlines() if not l.lstrip().startswith("#"))


def test_unite_durcie():
    u = sans_commentaires(lire("systemd/secubox-pilotage-agent.service"))
    for d in (
        "User=secubox-pilotage", "NoNewPrivileges=yes", "ProtectSystem=strict", "ProtectHome=yes",
        "PrivateTmp=yes", "IPAddressDeny=any", "IPAddressAllow=10.10.0.1 10.64.0.1 localhost",
        "MemoryMax=32M", "Restart=on-failure", "RestartSec=10", "ReadOnlyPaths=/",
        "EnvironmentFile=-/etc/secubox/pilotage-agent.env", "ExecStart=/usr/sbin/sbx-pilotage-agent",
    ):
        assert d in u, d
    fam = re.search(r"^RestrictAddressFamilies=(.*)$", u, re.M).group(1).split()
    # AF_NETLINK : net.Interfaces() de Go lit les adresses par netlink (lecture seule sans capacité)
    assert set(fam) == {"AF_INET", "AF_UNIX", "AF_NETLINK"}
    assert "Listen" not in u and "CAP_" not in u
    assert re.search(r"^CapabilityBoundingSet=\s*$", u, re.M)  # aucune capacité
    assert "User=root" not in u


def test_regles_construisent_sans_cgo():
    r = lire("debian/rules")
    assert re.search(r"^export CGO_ENABLED\s*=\s*0", r, re.M)
    assert "-trimpath" in r
    assert "DEB_HOST_ARCH" in r and "GOARCH" in r
    assert "./cmd/sbx-pilotage-agent" in r


def test_aucune_dependance_go_tierce():
    mod = lire("go.mod")
    assert "require" not in mod
    assert re.search(r"^go 1\.22", mod, re.M)
    assert not (RACINE / "vendor").exists() and not (RACINE / "go.sum").exists()


def test_apparmor_enforce_sans_reseau_entrant():
    p = lire("apparmor/usr.sbin.sbx-pilotage-agent")
    code = sans_commentaires(p)
    assert re.search(r"^/usr/sbin/sbx-pilotage-agent\s*\{", code, re.M)
    assert "complain" not in code and "flags=" not in code  # enforce
    assert not re.search(r"\blisten\b|\baccept\b", code)
    # chaque règle inet est qualifiée (jamais « network inet stream, » nu, qui autoriserait listen)
    inet = [l for l in code.splitlines() if l.strip().startswith("network") and "inet" in l]
    assert inet and all("(" in l and "connect" in l for l in inet)
    assert "deny /etc/secubox/secrets/** r" in code
    assert "/usr/bin/systemctl rix," in code
    assert "capability" not in code


def test_paquet_coherent():
    c = lire("debian/control")
    assert "Architecture: any" in c and "Standards-Version: 4.6.2" in c
    assert lire("debian/compat").strip() == "13"
    assert lire("debian/changelog").startswith("secubox-pilotage-agent (0.1.0-1~trixie1) trixie;")
    pi = lire("debian/postinst")
    for m in ("adduser --system --no-create-home --group secubox-pilotage", "install -d -m 0755 /etc/secubox/pilotage",
              "apparmor_parser", "systemctl enable --now secubox-pilotage-agent"):
        assert m in pi, m
    assert "systemctl stop secubox-pilotage-agent" in lire("debian/prerm")


def test_entetes_spdx():
    for rel in ("debian/rules", "debian/postinst", "debian/prerm", "systemd/secubox-pilotage-agent.service",
                "apparmor/usr.sbin.sbx-pilotage-agent", "conf/pilotage-agent.env", "cmd/sbx-pilotage-agent/main.go"):
        assert "LicenseRef-CMSD-1.0" in lire(rel), rel
