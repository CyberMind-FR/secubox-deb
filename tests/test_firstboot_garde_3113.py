# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""secubox-firstboot (ref #3113) : `secubox-firstboot --help` a rejoué tout le premier démarrage sur gk1 (secret JWT,
secubox.conf, users.json, SSH par mot de passe), sans sauvegarde. Arguments analysés, refus une fois fait, rien
d'existant écrasé."""
import os
import subprocess
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "image" / "firstboot.sh"
TEXTE = SCRIPT.read_text()


def lance(*args, env=None):
    e = {"PATH": "/usr/bin:/bin", **(env or {})}
    return subprocess.run(["bash", str(SCRIPT), *args], capture_output=True, text=True, env=e, timeout=20)


def biblio(code, env=None):
    e = {"PATH": "/usr/bin:/bin", **(env or {})}
    return subprocess.run(["bash", "-c", f"source {SCRIPT} --bibliotheque; {code}"], capture_output=True, text=True,
                          env=e, timeout=20)


def test_aide_n_execute_rien(tmp_path):
    for a in ("--help", "-h"):
        r = lance(a, env={"SECUBOX_FIRSTBOOT_MARQUEUR": str(tmp_path / "absent")})
        assert r.returncode == 0, r.stderr
        assert "Usage" in r.stdout and "--force" in r.stdout
        assert "First Boot" not in r.stdout + r.stderr


def test_argument_inconnu_refuse_sans_rien_executer(tmp_path):
    r = lance("--nimporte", env={"SECUBOX_FIRSTBOOT_MARQUEUR": str(tmp_path / "absent")})
    assert r.returncode == 2
    assert "Usage" in r.stderr and "First Boot" not in r.stdout + r.stderr


def test_deja_fait_refuse_sans_force(tmp_path):
    m = tmp_path / ".firstboot_done"
    m.touch()
    r = lance(env={"SECUBOX_FIRSTBOOT_MARQUEUR": str(m)})
    assert r.returncode == 3
    assert "--force" in r.stderr and "First Boot" not in r.stdout + r.stderr


def test_jwt_existant_est_repris(tmp_path):
    conf = tmp_path / "secubox.conf"
    conf.write_text('[api]\nsocket_dir  = "/run/secubox"\njwt_secret  = "' + "ab" * 32 + '"\n')
    r = biblio(f"jwt_existant {conf}")
    assert r.stdout.strip() == "ab" * 32
    conf.write_text('[api]\njwt_secret = "court"\n')
    assert biblio(f"jwt_existant {conf}").stdout.strip() == ""
    assert biblio(f"jwt_existant {tmp_path / 'absent'}").stdout.strip() == ""


def test_sauvegarde_horodatee_des_existants(tmp_path):
    a, b = tmp_path / "secubox.conf", tmp_path / "users.json"
    a.write_text("conf")
    os.chmod(a, 0o640)
    dest = tmp_path / "sauv"
    r = biblio(f"sauvegarde_existants {dest} {a} {b}")
    assert r.returncode == 0, r.stderr
    assert (dest / "secubox.conf").read_text() == "conf" and not (dest / "users.json").exists()
    assert (dest / "secubox.conf").stat().st_mode & 0o777 == 0o640
    assert dest.stat().st_mode & 0o777 == 0o700


def test_rien_d_existant_n_est_ecrase():
    # secubox.conf : écrit sauf si un secret JWT valide existe (repris) ; users.json : seulement s il est absent ; SSH par mot de passe
    # seulement si root n'a aucune clé.
    assert 'if [[ "${JWT_REPRIS}" != 1 ]]; then' in TEXTE
    assert 'if [[ ! -s "${USERS_JSON}" ]]' in TEXTE
    assert 'JWT_SECRET=$(jwt_existant "${SECUBOX_DIR}/secubox.conf")' in TEXTE
    assert "elif [[ ! -s /root/.ssh/authorized_keys ]]" in TEXTE
    i_sauv = TEXTE.index("sauvegarde_existants \"")
    assert i_sauv < TEXTE.index("# ── 4. SSH")


def test_exemple_du_paquet_n_est_pas_une_box_configuree():
    """Le postinst de secubox-core pose secubox.conf.example (jwt_secret vide) : le premier démarrage doit l'écrire."""
    exemple = (SCRIPT.parents[1] / "secubox.conf.example")
    assert 'jwt_secret  = ""' in exemple.read_text()
    assert biblio(f"jwt_existant {exemple}").stdout.strip() == ""


def test_ajoute_cles_sans_saut_final_ni_doublon(tmp_path):
    src, dest = tmp_path / "boot_keys", tmp_path / "authorized_keys"
    src.write_text("ssh-ed25519 AAAA1 a\r\nssh-ed25519 AAAA2 b\n")
    dest.write_text("ssh-ed25519 AAAA1 a")            # pas de saut de ligne final
    r = biblio(f"ajoute_cles {src} {dest}")
    assert r.returncode == 0, r.stderr
    assert dest.read_text() == "ssh-ed25519 AAAA1 a\nssh-ed25519 AAAA2 b\n"
    vide = tmp_path / "neuf"
    assert biblio(f"ajoute_cles {src} {vide}").returncode == 0
    assert vide.read_text() == "ssh-ed25519 AAAA1 a\nssh-ed25519 AAAA2 b\n"


def test_sauvegarde_en_echec_est_signalee(tmp_path):
    bloque = tmp_path / "fichier"
    bloque.write_text("x")
    r = biblio(f"sauvegarde_existants {bloque}/sous {tmp_path / 'a'}")   # parent = un fichier : install échoue
    assert r.returncode != 0


def test_rejeu_ajoute_les_cles_ssh_sans_remplacer():
    assert 'ajoute_cles "${BOOT_DIR}/authorized_keys" /root/.ssh/authorized_keys' in TEXTE
    assert 'log "Login     : comptes existants conservés"' in TEXTE
