# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""#4036 — les unités rangées dans la file FIFO et la tranche basse priorité, et celles qui n'y vont jamais."""
import re
from pathlib import Path

PAQUETS = Path(__file__).resolve().parents[2]

# Décisions de sécurité ou de survie : elles partent à l'heure, jamais derrière la file.
EXCLUES = (
    "annuaire-bans-apply", "blacklist-sync", "blacklist-attrib", "escalate", "actord-ingest-garde",
    "soc-sade-auto", "waf-", "gitea-ssh-garde-maj", "wan-link-guard", "realip", "mobile-suivi",
    "ad-guard-auto", "ad-guard-tri", "tcp-etats", "pseudo-routeur", "depot-coffre",
    "masquer-jetons-journaux", "aggregator-watchdog", "health-doctor-runner", "healthbump",
    "dirs-guard", "minuteries-garde", "p2p-mesh-liveness", "ui-health", "lyrion-watchdog",
    "ytsas-conserve", "torrent-conserve", "garde-passage",
)


def _unites():
    for f in sorted(PAQUETS.glob("*/**/*.service")):
        parts = f.relative_to(PAQUETS).parts
        # Dossiers de construction (debian/<paquet>/…, debian/tmp/…) : produits jetables.
        if "debian" in parts and len(parts) - parts.index("debian") > 2:
            continue
        yield f


def test_chaque_unite_de_la_file_est_complete():
    vues = 0
    for f in _unites():
        s = f.read_text()
        if "tache-fifo" not in s:
            continue
        vues += 1
        assert "Slice=secubox-taches.slice" in s, f
        assert "AppArmorProfile=" not in s, f"{f} : le profil devrait autoriser le lanceur"
        assert len(re.findall(r"^ExecStart=", s, re.M)) == 1, f
        assert re.search(rf"^ExecStart=/usr/lib/secubox/tache-fifo --nom {re.escape(f.stem)} "
                         r"--attente-max \d+ -- \S", s, re.M), f
        if re.search(r"^ProtectSystem=strict", s, re.M):
            assert "ReadWritePaths=-/run/secubox/taches" in s, f
    assert vues >= 16


def test_aucune_decision_de_securite_derriere_la_file():
    for f in _unites():
        if any(e in f.stem for e in EXCLUES):
            s = f.read_text()
            assert "tache-fifo" not in s and "secubox-taches.slice" not in s, f


def test_le_paquet_livre_le_lanceur_la_tranche_et_le_reglage():
    rules = (PAQUETS / "secubox-core" / "debian" / "rules").read_text()
    for chemin in ("usr/lib/secubox/tache-fifo", "lib/systemd/system/secubox-taches.slice", "etc/secubox/taches.toml"):
        assert chemin in rules
    tranche = (PAQUETS / "secubox-core" / "systemd" / "secubox-taches.slice").read_text()
    assert "CPUWeight=20" in tranche and "IOWeight=20" in tranche
    tmp = (PAQUETS / "secubox-core" / "tmpfiles.d" / "secubox.conf").read_text()
    assert "d /run/secubox/taches 1777 root root" in tmp
