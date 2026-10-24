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
    # secubox.conf, users.json : écrits seulement s'ils sont absents ; secret JWT repris ; SSH par mot de passe
    # seulement si root n'a aucune clé.
    assert 'if [[ ! -s "${SECUBOX_DIR}/secubox.conf" ]]' in TEXTE
    assert 'if [[ ! -s "${USERS_JSON}" ]]' in TEXTE
    assert 'JWT_SECRET=$(jwt_existant "${SECUBOX_DIR}/secubox.conf")' in TEXTE
    assert "elif [[ ! -s /root/.ssh/authorized_keys ]]" in TEXTE
    i_sauv = TEXTE.index("sauvegarde_existants \"")
    assert i_sauv < TEXTE.index("# ── 4. SSH")


def test_rejeu_ajoute_les_cles_ssh_sans_remplacer():
    assert 'grep -vxF -f /root/.ssh/authorized_keys "${BOOT_DIR}/authorized_keys" >> /root/.ssh/authorized_keys' in TEXTE
    assert 'log "Login     : comptes existants conservés"' in TEXTE
