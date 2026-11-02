# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3401 — interrupteur « Accès SSH » : API (demandes par fichier), secubox-sshctl, secubox-ssh-defaut, unités."""
import ctypes
import ctypes.util
import importlib.util
import json
import os
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest
from argon2 import PasswordHasher
from fastapi import FastAPI
from fastapi.testclient import TestClient

SYSTEM = Path(__file__).resolve().parents[1]
COMMON = SYSTEM.parents[1] / "common"
sys.path.insert(0, str(COMMON))

# Chargé par son chemin : le nom de paquet `api` est aussi celui des composants (ksm…) testés dans la même session.
_spec = importlib.util.spec_from_file_location("ssh_router_3401", SYSTEM / "api" / "routers" / "ssh.py")
ssh = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ssh)

CTL = SYSTEM / "sbin" / "secubox-sshctl"
DEFAUT_BIN = SYSTEM / "sbin" / "secubox-ssh-defaut"
WEB_PY = COMMON / "secubox_core" / "mot_de_passe_defaut.py"


# ── faux sshd et faux verdict, pour le ctl ──────────────────────────────
@pytest.fixture
def banc(tmp_path):
    d = tmp_path / "sshd_config.d"
    d.mkdir()
    (tmp_path / "dem").mkdir()
    (tmp_path / "res").mkdir()
    sshd = tmp_path / "sshd"
    # -T : « no » si un drop-in à nous refuse le mot de passe, et si FAUX_SSHD_IGNORE n'existe pas (garde inopérante).
    sshd.write_text(f"""#!/bin/bash
[ "$1" = "-t" ] && exit 0
if [ ! -e {tmp_path}/ignore ] && grep -qs 'PasswordAuthentication no' {d}/*.conf; then
  echo "passwordauthentication no"; else echo "passwordauthentication yes"; fi
""")
    sshd.chmod(0o755)
    defaut = tmp_path / "defaut"
    defaut.write_text(f"#!/bin/bash\nexit $(cat {tmp_path}/rc)\n")
    defaut.chmod(0o755)
    (tmp_path / "rc").write_text("0")
    env = {**os.environ, "SECUBOX_SSHCTL_ESSAI": "1", "SECUBOX_SSHD_DIR": str(d), "SECUBOX_AUDIT_LOG": str(tmp_path / "audit.log"),
           "SECUBOX_SSHD_BIN": str(sshd), "SECUBOX_SSH_DEFAUT_BIN": str(defaut),
           "SECUBOX_SSH_DEMANDES": str(tmp_path / "dem"), "SECUBOX_SSH_RESULTATS": str(tmp_path / "res")}

    def run(*args, rc="0"):
        (tmp_path / "rc").write_text(rc)
        return subprocess.run(["bash", str(CTL), *args], env=env, capture_output=True, text=True, timeout=30, check=False)
    run.dir, run.tmp = d, tmp_path
    return run


def _evenements(tmp_path):
    f = tmp_path / "audit.log"
    return [json.loads(x)["evenement"] for x in f.read_text().splitlines()] if f.exists() else []


def test_garde_posee_si_actif_ou_inconnu_levee_si_inactif(banc):
    garde = banc.dir / "05-secubox-mot-de-passe-defaut.conf"
    assert banc("garde", rc="2").returncode == 0 and garde.exists()        # inconnu = garde
    assert banc("garde", rc="10").returncode == 0 and not garde.exists()
    assert banc("garde", rc="0").returncode == 0 and garde.exists()
    assert _evenements(banc.tmp) == ["ssh_garde_defaut_posee", "ssh_garde_defaut_levee", "ssh_garde_defaut_posee"]


def test_garde_defaite_si_sshd_T_ne_l_applique_pas(banc):
    (banc.tmp / "ignore").write_text("")
    r = banc("garde", rc="0")
    assert r.returncode == 2 and not (banc.dir / "05-secubox-mot-de-passe-defaut.conf").exists()
    assert _evenements(banc.tmp) == ["ssh_garde_defaut_echec"]


@pytest.mark.parametrize("rc", ["0", "2", "1"])
def test_mot_de_passe_on_refuse_si_defaut_actif_ou_inconnu(banc, rc):
    r = banc("mot-de-passe", "on", "admin", rc=rc)
    assert r.returncode == 3 and "mot de passe par défaut" in r.stderr


def test_mot_de_passe_off_puis_on_et_retour_arriere(banc):
    f = banc.dir / "10-secubox-ssh-mot-de-passe.conf"
    assert banc("mot-de-passe", "off", "admin", rc="10").returncode == 0 and f.exists()
    assert banc("mot-de-passe", "on", "admin", rc="10").returncode == 0 and not f.exists()
    banc("mot-de-passe", "off", "admin", rc="10")
    # sshd -t refuse : le fichier d'avant revient.
    sshd = banc.tmp / "sshd"
    sshd.write_text("#!/bin/bash\nexit 1\n")
    assert banc("mot-de-passe", "on", "admin", rc="10").returncode == 2 and f.exists()
    assert not list(banc.dir.glob(".secubox-sshctl*"))


def test_etat_fonde_sur_sshd_T(banc):
    banc("garde", rc="0")
    e = json.loads(banc("etat", rc="0").stdout)
    assert e["mot_de_passe_effectif"] == "no" and not e["mot_de_passe"] and e["garde_defaut"] and e["mot_de_passe_defaut"]


@pytest.mark.parametrize("args", [["acces", "peut-etre", "admin"], ["acces", "on", "a b"], ["rm"], []])
def test_ctl_refuse_les_arguments_hors_liste(banc, args):
    assert banc(*args).returncode == 2


def test_traite_les_demandes_et_ignore_les_noms_douteux(banc):
    (banc.tmp / "dem" / "0123456789abcdef.demande").write_text(json.dumps({"verbe": "acces", "valeur": "on", "acteur": "admin"}))
    (banc.tmp / "dem" / "..%2f.demande").write_text("{}")
    assert banc("traite").returncode == 0
    r = json.loads((banc.tmp / "res" / "0123456789abcdef.json").read_text())
    assert r["code"] == 0 and not list((banc.tmp / "dem").iterdir())
    assert "ssh_acces_on" in _evenements(banc.tmp)


# ── API : dépôt de demande, résultat relu ───────────────────────────────
@pytest.fixture
def client(banc, monkeypatch):
    monkeypatch.setattr(ssh, "DEMANDES", banc.tmp / "dem")
    monkeypatch.setattr(ssh, "RESULTATS", banc.tmp / "res")
    monkeypatch.setattr(ssh, "DELAI", 10.0)
    arret = threading.Event()

    def unite_root():   # ce que ferait secubox-ssh.path
        while not arret.is_set():
            if list((banc.tmp / "dem").glob("*.demande")):
                banc("traite", rc=(banc.tmp / "rc").read_text())
            time.sleep(0.05)
    t = threading.Thread(target=unite_root, daemon=True)
    t.start()
    app = FastAPI()
    app.include_router(ssh.router)
    app.dependency_overrides[ssh.require_jwt] = lambda: {"sub": "admin"}
    yield TestClient(app)
    arret.set()


def test_routes_gardees_par_require_jwt():
    for r in ssh.router.routes:
        assert any(d.call is ssh.require_jwt for d in r.dependant.dependencies), r.path


def test_api_sans_sudo():
    assert "sudo" not in (SYSTEM / "api" / "routers" / "ssh.py").read_text().split('"""', 2)[2]


def test_acces_par_demande(client, banc):
    assert client.post("/ssh/acces", json={"actif": True}).status_code == 200
    assert "ssh_acces_on" in _evenements(banc.tmp)


def test_mot_de_passe_refuse_par_l_api_si_garde_requise(client, monkeypatch):
    monkeypatch.setattr(ssh.mdp_defaut, "garde_requise", lambda *a, **k: True)
    monkeypatch.setattr(ssh.mdp_defaut, "audit", lambda *a, **k: None)
    r = client.post("/ssh/mot-de-passe", json={"actif": True})
    assert r.status_code == 409 and "mot de passe par défaut" in r.json()["detail"]


def test_mot_de_passe_refuse_par_le_ctl_si_linux_par_defaut(client, banc, monkeypatch):
    monkeypatch.setattr(ssh.mdp_defaut, "garde_requise", lambda *a, **k: False)   # web changé…
    (banc.tmp / "rc").write_text("0")                                             # …mais Linux au défaut
    assert client.post("/ssh/mot-de-passe", json={"actif": True}).status_code == 409


def test_etat_par_demande(client):
    assert "mot_de_passe_effectif" in client.get("/ssh").json()


# ── secubox-ssh-defaut : Linux (crypt) ET web (argon2) ──────────────────
def _crypt(mdp):
    lib = ctypes.CDLL(ctypes.util.find_library("crypt") or "libcrypt.so.1")
    lib.crypt.restype = ctypes.c_char_p
    lib.crypt.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
    return lib.crypt(mdp.encode(), b"$6$saltsaltsalt$").decode()


def _defaut(tmp_path, web, linux):
    users = tmp_path / "users.json"
    users.write_text(json.dumps({"users": [{"username": "admin", "password_hash": PasswordHasher().hash(web)}]}))
    shadow = tmp_path / "shadow"
    shadow.write_text(f"root:{_crypt(linux)}:19000::::::\ndaemon:*:19000::::::\nsbx:!:19000::::::\n")
    env = {"PATH": "/usr/bin:/bin", "SECUBOX_USERS_JSON": str(users), "SECUBOX_SHADOW": str(shadow),
           "SECUBOX_DEFAUT_WEB_PY": str(WEB_PY), "SECUBOX_SSH_CACHE": str(tmp_path / "cache")}
    return subprocess.run([sys.executable, str(DEFAUT_BIN)], env=env, cwd="/", capture_output=True, text=True,
                          timeout=60, check=False)


def test_defaut_actif_si_linux_au_defaut_meme_web_change(tmp_path):
    r = _defaut(tmp_path, "une longue phrase choisie", "secubox")
    assert r.returncode == 0 and json.loads(r.stdout)["linux"] == ["root"]


def test_defaut_actif_si_web_au_defaut(tmp_path):
    assert _defaut(tmp_path, "secubox", "autre-mot-de-passe-linux").returncode == 0


def test_defaut_inactif_seulement_si_les_deux_changes_et_cache(tmp_path):
    assert _defaut(tmp_path, "une longue phrase choisie", "autre-linux").returncode == 10
    assert (tmp_path / "cache").exists() and oct((tmp_path / "cache").stat().st_mode & 0o777) == "0o600"
    assert "argon2" not in (tmp_path / "cache").read_text()


def test_defaut_inconnu_si_shadow_illisible(tmp_path):
    env = {"PATH": "/usr/bin:/bin", "SECUBOX_SHADOW": str(tmp_path / "absent"), "SECUBOX_DEFAUT_WEB_PY": str(WEB_PY)}
    r = subprocess.run([sys.executable, str(DEFAUT_BIN)], env=env, cwd="/", capture_output=True, timeout=30, check=False)
    assert r.returncode not in (0, 10)


# ── unités : durcies, déclenchées par fichier ───────────────────────────
@pytest.mark.parametrize("unite", ["secubox-ssh.service", "secubox-ssh-garde.service"])
def test_unites_root_durcies(unite):
    t = (SYSTEM / "systemd" / unite).read_text()
    for cle in ("ProtectSystem=strict", "NoNewPrivileges=true", "PrivateTmp=true", "CapabilityBoundingSet=", "UMask=0027",
                "ReadWritePaths=/etc/ssh/sshd_config.d"):
        assert cle in t, cle


def test_path_units_et_plus_de_sudoers():
    assert "DirectoryNotEmpty=/run/secubox/system/ssh" in (SYSTEM / "systemd" / "secubox-ssh.path").read_text()
    g = (SYSTEM / "systemd" / "secubox-ssh-garde.path").read_text()
    assert "PathChanged=/etc/secubox/users.json" in g and "PathChanged=/etc/shadow" in g
    post = (SYSTEM / "debian" / "postinst").read_text()
    assert "NOPASSWD: /usr/sbin/secubox-sshctl" not in post
    assert "rm -f /etc/sudoers.d/secubox-ssh" in post        # l'ancienne règle est retirée à la mise à jour


def test_retrait_garde_seulement_si_defaut_prouve_change():
    prerm = (SYSTEM / "debian" / "prerm").read_text()
    i = prerm.index("secubox-ssh-defaut")
    assert '"$rc" = "10"' in prerm[i:i + 300] and "05-secubox-mot-de-passe-defaut.conf" in prerm[i:i + 400]
