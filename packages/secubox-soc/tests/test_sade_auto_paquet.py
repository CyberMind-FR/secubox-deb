# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""SADE ACTIVE (#3839) : unité minutée, règles, scripts du paquet et exception § 10 (contrôles statiques)."""
from pathlib import Path

PAQUET = Path(__file__).resolve().parents[1]
DEBIAN = PAQUET / "debian"
RACINE = PAQUET.parents[1]


def _lire(p):
    return Path(p).read_text(encoding="utf-8")


def _directives(texte):
    return [ligne.strip() for ligne in texte.splitlines() if ligne.strip() and not ligne.lstrip().startswith("#")]


def test_unite_service_directives():
    d = _directives(_lire(DEBIAN / "secubox-soc-sade-auto.service"))
    for attendu in (
        "Type=oneshot", "User=secubox", "Group=secubox",
        "WorkingDirectory=/usr/lib/secubox/soc",
        "ExecStart=/usr/bin/python3 -m api.sade_auto",
        "TimeoutStartSec=5min", "NoNewPrivileges=no", "ProtectSystem=strict",
        "ProtectHome=yes", "PrivateTmp=yes", "UMask=0027",
    ):
        assert attendu in d, attendu
    rw = [x for x in d if x.startswith("ReadWritePaths=")]
    assert len(rw) == 1
    chemins = rw[0].split("=", 1)[1].split()
    assert "/var/lib/secubox/soc" in chemins and "/var/log/secubox" in chemins
    assert "-/run/sudo" in chemins
    # gestes approuvés (1.12.0) : wafctl leurre écrit leurres-ip.json, sudo journalise les E/S de ces verbes
    assert "-/var/lib/secubox/waf" in chemins and "-/var/log/sudo-io" in chemins


def test_unite_sans_options_impliquant_nonewprivileges():
    texte = "\n".join(_directives(_lire(DEBIAN / "secubox-soc-sade-auto.service")))
    for interdit in ("SystemCallFilter", "RestrictSUIDSGID", "LockPersonality", "MemoryDenyWriteExecute",
                     "ProtectKernelTunables", "RestrictNamespaces", "NoNewPrivileges=yes", "NoNewPrivileges=true"):
        assert interdit not in texte, interdit


def test_minuterie():
    d = _directives(_lire(DEBIAN / "secubox-soc-sade-auto.timer"))
    for attendu in ("OnBootSec=3min", "OnCalendar=*:0/2", "Persistent=false", "WantedBy=timers.target"):
        assert attendu in d, attendu


def test_rules_installe_les_deux_unites():
    rules = _lire(DEBIAN / "rules")
    for u in ("secubox-soc-sade-auto.service", "secubox-soc-sade-auto.timer"):
        assert f"install -m 644 debian/{u} debian/secubox-soc/usr/lib/systemd/system/" in rules


def test_postinst_active_la_minuterie():
    p = _lire(DEBIAN / "postinst")
    assert "systemctl enable --now secubox-soc-sade-auto.timer >/dev/null 2>&1 || true" in p


def test_prerm_arrete_la_minuterie_et_le_service():
    p = _lire(DEBIAN / "prerm")
    assert "systemctl disable --now secubox-soc-sade-auto.timer || true" in p
    assert "systemctl stop secubox-soc-sade-auto.service || true" in p


def test_changelog_1_10_0():
    t = _lire(DEBIAN / "changelog")
    # l'entrée de la 1.10.0 (exécuteur ACTIVE) existe ; une version plus récente peut la précéder
    assert "\nsecubox-soc (1.10.0-1~trixie1) trixie; urgency=medium" in "\n" + t


def test_exception_rules_code_nomme_l_unite():
    t = _lire(RACINE / ".claude" / "RULES-CODE.md")
    lignes = [x for x in t.splitlines() if "secubox-soc-sade-auto.service" in x]
    assert lignes and "§ 10" in lignes[0]
    assert "test_sade_auto_paquet.py" in lignes[0]


def test_readme_documente_active_et_audit():
    t = _lire(PAQUET / "README.md")
    for m in ("sade-auto-demande", "sade-auto-resultat", "sade-auto-plafond", "secubox-soc-sade-auto.timer"):
        assert m in t, m
    assert "gestes_non_livres" in t  # aggressive reste refusé
