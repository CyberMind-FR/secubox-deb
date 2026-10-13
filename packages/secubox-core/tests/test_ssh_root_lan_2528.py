# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SSH root par mot de passe depuis le réseau local, livré par secubox-core (ref #2528).

Sur trixie, OpenSSH refuse root par mot de passe par défaut : une box neuve (RPi400) n'était joignable que par clé, même avec le bon mot
de passe. Le bloc ne vaut que pour les adresses privées ; hors du réseau local, le défaut Debian (clé seulement) reste."""
import ipaddress
import re
import shutil
import subprocess
from pathlib import Path

import pytest

PAQUET = Path(__file__).resolve().parents[1]
DROPIN = PAQUET / "ssh" / "20-secubox-root-lan.conf"
TEXTE = DROPIN.read_text()


def _match_reseaux():
    m = re.search(r"^Match Address (\S+)$", TEXTE, re.M)
    assert m, "pas de bloc Match Address"
    return [ipaddress.ip_network(x) for x in m.group(1).split(",")]


def test_le_bloc_ne_vise_que_des_reseaux_prives():
    for r in _match_reseaux():
        assert r.is_private, f"{r} n'est pas un réseau privé"
    assert {str(r) for r in _match_reseaux()} == {"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"}


def test_aucune_directive_hors_du_bloc_match():
    """Une directive globale s'appliquerait aussi depuis Internet."""
    avant = TEXTE.split("Match Address", 1)[0]
    actives = [l for l in avant.splitlines() if l.strip() and not l.lstrip().startswith("#")]
    assert actives == []


def test_le_bloc_autorise_root_et_le_mot_de_passe():
    apres = TEXTE.split("Match Address", 1)[1]
    assert re.search(r"^\s+PermitRootLogin yes$", apres, re.M)
    assert re.search(r"^\s+PasswordAuthentication yes$", apres, re.M)


def test_rules_installe_le_dropin_dans_sshd_config_d():
    rules = (PAQUET / "debian" / "rules").read_text()
    assert re.search(r"install -D -m 0?644 ssh/20-secubox-root-lan\.conf\s*\\?\s+debian/secubox-core/etc/ssh/sshd_config\.d/20-secubox-root-lan\.conf", rules)


def test_postinst_valide_avant_de_recharger_ssh():
    post = (PAQUET / "debian" / "postinst").read_text()
    i = post.index("sshd -t")
    assert "reload ssh" in post[i:i + 300], "le rechargement doit suivre la validation sshd -t"
    assert post.rindex("sshd -t", 0, post.index("reload ssh", i)) == i


@pytest.mark.skipif(not shutil.which("sshd") and not Path("/usr/sbin/sshd").exists(), reason="sshd absent")
def test_comportement_reel_de_sshd(tmp_path):
    sshd = shutil.which("sshd") or "/usr/sbin/sshd"
    (tmp_path / "c").mkdir()
    shutil.copy(DROPIN, tmp_path / "c")
    cfg = tmp_path / "sshd_config"
    cfg.write_text(f"Include {tmp_path}/c/*.conf\nPort 22\n")

    def effectif(adresse):
        p = subprocess.run([sshd, "-T", "-f", str(cfg), "-C", f"user=root,addr={adresse},host=h,laddr=192.168.1.2,lport=22"],
                           capture_output=True, text=True)
        return dict(l.split(" ", 1) for l in p.stdout.splitlines() if l.startswith("permitrootlogin "))["permitrootlogin"]

    assert effectif("192.168.1.9") == "yes"
    assert effectif("203.0.113.5") == "without-password"
