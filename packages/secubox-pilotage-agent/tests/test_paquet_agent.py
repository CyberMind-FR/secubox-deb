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
    fichiers = ["debian/rules", "debian/postinst", "debian/prerm", "debian/postrm", "README.md",
                "systemd/secubox-pilotage-agent.service", "apparmor/usr.sbin.sbx-pilotage-agent",
                "conf/pilotage-agent.env", "tests/test_paquet_agent.py"]
    fichiers += [str(f.relative_to(RACINE)) for f in (RACINE / "cmd").rglob("*.go")]
    for rel in fichiers:
        assert "LicenseRef-CMSD-1.0" in lire(rel), rel


def test_apparmor_modele_de_carte_par_le_chemin_resolu():
    # /proc/device-tree est un lien : AppArmor contrôle /sys/firmware/devicetree/base/model
    code = sans_commentaires(lire("apparmor/usr.sbin.sbx-pilotage-agent"))
    assert "/sys/firmware/devicetree/base/model r," in code
    assert "/sys/class/dmi/id" not in code


def test_apparmor_dbus_restreint_a_systemd():
    code = sans_commentaires(lire("apparmor/usr.sbin.sbx-pilotage-agent"))
    assert not re.search(r"^\s*dbus\s*(\([^)]*\))?\s*bus=system\s*,", code, re.M)  # jamais de dbus nu
    assert "peer=(name=org.freedesktop.systemd1)" in code
    assert "peer=(name=org.freedesktop.DBus)" in code
    assert "ListUnitsByPatterns" in code
    assert "/run/systemd/private" not in code
    assert "/sys/fs/cgroup/ r," in code


def test_apparmor_resserre():
    code = sans_commentaires(lire("apparmor/usr.sbin.sbx-pilotage-agent"))
    assert "deny @{PROC}/[0-9]*/{cmdline,environ} r," in code
    assert re.search(r"^\s*network \([^)]*\) unix stream,", code, re.M)
    assert not re.search(r"^\s*network unix stream,", code, re.M)
    assert "/sys/devices/** r," not in code


def test_unite_confinee_et_ordonnee():
    u = sans_commentaires(lire("systemd/secubox-pilotage-agent.service"))
    for d in ("AppArmorProfile=/usr/sbin/sbx-pilotage-agent", "RestrictSUIDSGID=yes", "UMask=0027",
              "Wants=network-online.target"):
        assert d in u, d
    after = re.search(r"^After=(.*)$", u, re.M).group(1).split()
    assert {"network-online.target", "wg-quick@wg-mesh.service", "wg-quick@wg-autoload.service"} <= set(after)


def test_postinst_postrm_robustes():
    assert "[ -d /run/systemd/system ]" in lire("debian/postinst")
    assert "apparmor_parser -R" in lire("debian/postrm")


def test_regles_goarch_complet():
    r = lire("debian/rules")
    assert "armhf" in r and "386" in r and "GOARM" in r


def test_apparmor_dmi_x86_par_le_chemin_resolu():
    # /sys/class/dmi/id est un lien vers /sys/devices/virtual/dmi/id/
    code = sans_commentaires(lire("apparmor/usr.sbin.sbx-pilotage-agent"))
    assert "/sys/devices/virtual/dmi/id/{product_name,sys_vendor} r," in code
