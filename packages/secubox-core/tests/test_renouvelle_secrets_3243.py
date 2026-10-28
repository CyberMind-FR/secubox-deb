# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3243 — secubox-renouvelle-secrets : les secrets d'une box sont générés SUR la box.

CONSTAT (2026-10-28) : les images publiées embarquaient les clés d'hôte SSH, la clé de signature OIDC, la clé TLS, la clé
WireGuard du p2p éphémère, le jeton d'appairage et le machine-id générés dans le chroot de CI — identiques sur toutes les box
d'une image, et téléchargeables. L'outil les renouvelle par le générateur de chaque paquet (ssh-keygen -A, secubox-oidcctl
init, postinst de secubox-p2p, openssl) ; ssh-keygen et openssl sont les vrais, le reste est simulé."""
import hashlib
import json
import os
import subprocess
from pathlib import Path

import pytest

PKG = Path(__file__).resolve().parents[1]
OUTIL = PKG / "sbin" / "secubox-renouvelle-secrets"
REGLES = PKG / "debian" / "rules"
CONSTRUCTEUR = "runnervmtest"


def _empreinte(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


@pytest.fixture
def box(tmp_path):
    r = tmp_path / "racine"
    ssh = r / "etc/ssh"
    ssh.mkdir(parents=True)
    for t in ("rsa", "ecdsa", "ed25519"):
        subprocess.run(["ssh-keygen", "-q", "-t", t, "-N", "", "-C", f"root@{CONSTRUCTEUR}", "-f", str(ssh / f"ssh_host_{t}_key")], check=True)
    (r / "etc/secubox/secrets/oidc").mkdir(parents=True)
    (r / "etc/secubox/secrets/oidc/signing.pem").write_text("ANCIEN-OIDC")
    (r / "etc/secubox/secrets/p2p").mkdir(parents=True)
    (r / "etc/secubox/secrets/p2p/pair.token").write_text("ANCIEN-JETON")
    (r / "etc/secubox/secrets/p2p/wg-ephemeral.key").write_text("ANCIENNE-CLE-WG")
    (r / "etc/secubox/tls").mkdir(parents=True)
    (r / "etc/secubox/tls/key.pem").write_text("ANCIENNE-CLE-TLS")
    (r / "etc/secubox/tls/cert.pem").write_text("ANCIEN-CERT")
    (r / "etc/secubox/users.json").write_text(json.dumps({"version": 2, "groups": [], "users": [
        {"username": "admin", "password_hash": "$argon2id$x", "role": "admin"},
        {"username": CONSTRUCTEUR, "password_hash": None, "role": "admin"}]}))
    (r / "etc/machine-id").write_text("0123456789abcdef0123456789abcdef\n")
    (r / "var/lib/dbus").mkdir(parents=True)
    (r / "var/lib/dbus/machine-id").write_text("0123456789abcdef0123456789abcdef\n")

    faux = tmp_path / "faux"
    faux.mkdir()
    appels = tmp_path / "appels.txt"

    def script(nom, corps):
        p = faux / nom
        p.write_text("#!/bin/sh\n" f"echo \"{nom} $*\" >> {appels}\n" + corps)
        p.chmod(0o755)
        return str(p)

    env = {
        "PATH": "/usr/bin:/bin", "SBX_RACINE": str(r), "SBX_HOSTNAME": "gk5",
        "SBX_SYSTEMCTL": script("systemctl", "exit 0\n"),
        "SBX_NGINX": script("nginx", "exit 0\n"),
        "SBX_USERSCTL": script("usersctl", "exit 0\n"),
        "SBX_DPKG_QUERY": script("dpkg-query", "echo 1.19.3-1~trixie1\n"),
        # le vrai `secubox-oidcctl init` crée la clé si elle manque
        "SBX_OIDCCTL": script("oidcctl", f"c={r}/etc/secubox/secrets/oidc/signing.pem\n[ -f $c ] || head -c 32 /dev/urandom | od -An -tx1 > $c\n"),
        # le vrai postinst de secubox-p2p crée jeton et clé s'ils manquent
        "SBX_P2P_POSTINST": script("p2p-postinst", f"d={r}/etc/secubox/secrets/p2p\n"
                                   "[ -f $d/pair.token ] || head -c 32 /dev/urandom | od -An -tx1 > $d/pair.token\n"
                                   "[ -f $d/wg-ephemeral.key ] || head -c 32 /dev/urandom | od -An -tx1 > $d/wg-ephemeral.key\n"),
        "SBX_MACHINE_ID_SETUP": script("machine-id-setup", f"head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \\n' > {r}/etc/machine-id\n"),
    }

    def lance(*args):
        res = subprocess.run(["bash", str(OUTIL), *args], capture_output=True, text=True, env=env, timeout=120)
        return res, (appels.read_text() if appels.exists() else "")
    return r, lance


def _tous(r: Path):
    return sorted([*(r / "etc/ssh").glob("ssh_host_*"), *(r / "etc/secubox").rglob("*.pem"),
                   *(r / "etc/secubox/secrets/p2p").glob("*"), r / "etc/machine-id", r / "etc/secubox/users.json"])


def test_constat_par_defaut_ne_change_rien(box):
    r, lance = box
    avant = {p: _empreinte(p) for p in _tous(r)}
    res, appels = lance()
    assert res.returncode == 0, res.stderr
    assert {p: _empreinte(p) for p in _tous(r)} == avant
    assert CONSTRUCTEUR in res.stdout                     # la clé d'hôte vient d'ailleurs : signalé
    for nom in ("ssh", "oidc", "tls", "p2p"):
        assert nom in res.stdout
    assert appels == ""


def test_tout_exige_oui(box):
    r, lance = box
    avant = {p: _empreinte(p) for p in _tous(r)}
    res, _ = lance("--tout")
    assert res.returncode == 2
    assert {p: _empreinte(p) for p in _tous(r)} == avant


def test_tout_renouvelle_chaque_secret_par_son_generateur(box):
    r, lance = box
    ed = r / "etc/ssh/ssh_host_ed25519_key.pub"
    avant_ed = ed.read_text()
    res, appels = lance("--tout", "--oui")
    assert res.returncode == 0, res.stderr + res.stdout
    for t in ("rsa", "ecdsa", "ed25519"):
        assert (r / f"etc/ssh/ssh_host_{t}_key").exists()
    assert ed.read_text() != avant_ed and CONSTRUCTEUR not in ed.read_text()
    assert oct((r / "etc/ssh/ssh_host_ed25519_key").stat().st_mode & 0o777) == "0o600"
    assert (r / "etc/secubox/secrets/oidc/signing.pem").read_text() != "ANCIEN-OIDC"
    assert (r / "etc/secubox/secrets/p2p/pair.token").read_text() != "ANCIEN-JETON"
    assert (r / "etc/secubox/secrets/p2p/wg-ephemeral.key").read_text() != "ANCIENNE-CLE-WG"
    cle_tls = r / "etc/secubox/tls/key.pem"
    assert "PRIVATE KEY" in cle_tls.read_text() and oct(cle_tls.stat().st_mode & 0o777) == "0o640"
    sujet = subprocess.run(["openssl", "x509", "-noout", "-subject", "-in", str(r / "etc/secubox/tls/cert.pem")],
                           capture_output=True, text=True, check=True).stdout
    assert "gk5" in sujet                                 # le nom de la box, comme secubox-firstboot
    assert "oidcctl init" in appels
    assert "p2p-postinst configure 1.19.3-1~trixie1" in appels
    assert "systemctl reload ssh" in appels and "systemctl reload nginx" in appels
    assert f"usersctl disable {CONSTRUCTEUR}" in appels and "usersctl disable admin" not in appels
    assert (r / "etc/machine-id").read_text().startswith("0123456789abcdef")   # pas sans --machine-id
    assert "SHA256:" in res.stdout                        # nouvelle empreinte, pour les known_hosts des clients


def test_audit_nomme_les_secrets_sans_jamais_leur_valeur(box):
    r, lance = box
    res, _ = lance("--tout", "--oui")
    assert res.returncode == 0, res.stderr
    texte = (r / "var/log/secubox/audit.log").read_text()
    lignes = [json.loads(ligne) for ligne in texte.splitlines()]
    assert {e["secret"] for e in lignes if e["evenement"] == "secret_renouvele"} >= {"ssh-hote", "tls", "oidc", "p2p"}
    assert any(e["evenement"] == "compte_desactive" and e["compte"] == CONSTRUCTEUR for e in lignes)
    for valeur in ("ANCIEN", (r / "etc/secubox/secrets/p2p/pair.token").read_text().strip(),
                   (r / "etc/secubox/secrets/oidc/signing.pem").read_text().strip()[:20]):
        assert valeur not in texte


def test_absents_ne_cree_que_ce_qui_manque(box):
    r, lance = box
    (r / "etc/secubox/secrets/oidc/signing.pem").unlink()
    for p in (r / "etc/ssh").glob("ssh_host_*"):
        p.unlink()
    res, appels = lance("--absents")
    assert res.returncode == 0, res.stderr
    assert (r / "etc/secubox/secrets/oidc/signing.pem").exists()
    assert (r / "etc/ssh/ssh_host_ed25519_key").exists()
    assert (r / "etc/secubox/secrets/p2p/pair.token").read_text() == "ANCIEN-JETON"
    assert (r / "etc/secubox/tls/key.pem").read_text() == "ANCIENNE-CLE-TLS"
    assert "p2p-postinst" not in appels and "usersctl" not in appels


def test_machine_id_seulement_sur_demande(box):
    r, lance = box
    res, _ = lance("--tout", "--oui", "--machine-id")
    assert res.returncode == 0, res.stderr
    assert not (r / "etc/machine-id").read_text().startswith("0123456789abcdef")
    lien = r / "var/lib/dbus/machine-id"
    assert lien.is_symlink() and os.readlink(lien) == "/etc/machine-id"
    assert "redémarr" in res.stdout


def test_le_paquet_installe_l_outil():
    assert "sbin/secubox-renouvelle-secrets" in REGLES.read_text()
