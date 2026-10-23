# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3060 — TURN : l'API (utilisateur `secubox`) délègue tout acte privilégié à `secubox-turnctl` (root, verbes exacts).

Avant : l'API lisait `/etc/turnserver.conf` (root:turnserver 0640, illisible), lançait `systemctl start|stop|restart coturn`
et `turnadmin` elle-même, et écrivait la configuration — sous `NoNewPrivileges=true`, sans sudoers : la page affichait
« — » partout et aucun bouton n'agissait. coturn tournait avec la configuration Debian par défaut, jamais celle de SecuBox."""
import re
import shutil
import subprocess
from pathlib import Path

import pytest

PAQUET = Path(__file__).resolve().parents[1]
TURN = PAQUET / "composants" / "turn"
CTL = TURN / "sbin" / "secubox-turnctl"
SUDOERS = TURN / "sudoers" / "secubox-turn"
UNITE = TURN / "debian" / "secubox-turn.service"
API = TURN / "api" / "main.py"
POSTINST = TURN / "debian" / "postinst"
RULES = PAQUET / "debian" / "rules"
CONTROL = PAQUET / "debian" / "control"
PANNEAU = TURN / "www" / "turn" / "index.html"

VERBES = ("status", "start", "stop", "restart", "enable", "generer", "secret-renouveler", "credentials",
          "users", "user-add", "user-del", "sessions", "journal", "config")


# ── ctl ────────────────────────────────────────────────────────────────────────

def test_le_ctl_existe_est_du_bash_strict_et_passe_bash_n():
    assert CTL.is_file()
    texte = CTL.read_text()
    assert texte.startswith("#!/usr/bin/env bash") or texte.startswith("#!/bin/bash")
    assert "set -euo pipefail" in texte
    subprocess.run(["bash", "-n", str(CTL)], check=True)


@pytest.mark.skipif(shutil.which("shellcheck") is None, reason="shellcheck absent")
def test_le_ctl_passe_shellcheck():
    r = subprocess.run(["shellcheck", "-S", "warning", str(CTL)], capture_output=True, text=True)
    assert r.returncode == 0, r.stdout + r.stderr


def test_le_ctl_connait_chaque_verbe_et_refuse_le_reste():
    texte = CTL.read_text()
    for v in VERBES:
        # un verbe seul (`status)`) ou dans une alternative (`start|stop|restart)`)
        assert re.search(rf"^\s*(?:[a-z-]+\|)*{re.escape(v)}(?:\|[a-z-]+)*\)", texte, re.M), f"verbe {v} absent du case"
    assert re.search(r"^\s*\*\)\s.*exit 2", texte, re.M), "un verbe inconnu doit sortir en 2"


def test_la_configuration_generee_est_celle_de_secubox_en_double_tampon():
    texte = CTL.read_text()
    # marqueur reconnu par `status` (config_secubox) et le postinst
    assert "# SecuBox" in texte and "MARQUEUR=" in texte
    # durcissement : pas de CLI, empreinte, pas de TLS ancien, journal fixe, relais vers soi-même refusé
    for cle in ("no-cli", "fingerprint", "no-tlsv1_1", "simple-log", "denied-peer-ip=127.0.0.0-127.255.255.255",
                "use-auth-secret", "static-auth-secret=", "lt-cred-mech", "realm="):
        assert cle in texte, cle
    # ombre → bascule atomique → coturn relancé → vérification → retour arrière
    assert ".sbx-nouveau" in texte and "mv -f" in texte and ".avant" in texte
    assert "is-active --quiet coturn" in texte
    assert "retour arrière" in texte or "retour arriere" in texte


def test_le_secret_vit_dans_le_dossier_des_secrets_et_jamais_dans_argv():
    texte = CTL.read_text()
    assert "/etc/secubox/secrets/turn/static-auth-secret" in texte
    assert "umask 077" in texte
    # le mot de passe d'un utilisateur long terme arrive par stdin, jamais en argument
    assert re.search(r"user-add\)", texte) and "read -r" in texte
    assert not re.search(r"user-add\)[^;]*\$\{?3", texte), "pas de mot de passe en argv"


def test_les_identifiants_temporaires_sont_hmac_sha1_du_protocole_turn_rest():
    texte = CTL.read_text()
    assert "openssl dgst -sha1 -hmac" in texte
    assert "-binary | base64" in texte


# ── sudoers ────────────────────────────────────────────────────────────────────

def test_le_sudoers_accorde_les_verbes_exacts_a_secubox_et_rien_d_autre():
    s = SUDOERS.read_text()
    assert re.search(r"^secubox ALL=\(root\) NOPASSWD: ", s, re.M)
    assert "/usr/sbin/secubox-turnctl status" in s
    assert "/usr/sbin/secubox-turnctl generer" in s
    assert "/usr/sbin/secubox-turnctl credentials [A-Za-z0-9._-]* [0-9]*" in s
    assert "/usr/sbin/secubox-turnctl user-add [A-Za-z0-9._-]*" in s
    assert "/usr/sbin/secubox-turnctl journal [0-9]*" in s
    # jamais le ctl nu (tous verbes) ni un joker global — sur les lignes de règle, pas les commentaires
    regles = "\n".join(ligne for ligne in s.splitlines() if ligne.strip() and not ligne.lstrip().startswith("#"))
    assert not re.search(r"secubox-turnctl\s*(,|$)", regles, re.M)
    assert "secubox-turnctl *" not in s and "secubox-turnctl \\*" not in s
    assert "Defaults!/usr/sbin/secubox-turnctl !requiretty" in s


# ── unité ──────────────────────────────────────────────────────────────────────

def test_l_unite_api_laisse_passer_sudo_et_ne_touche_plus_la_configuration_de_coturn():
    u = UNITE.read_text()
    service = u.split("[Service]", 1)[1]
    assert "User=secubox" in service
    assert "NoNewPrivileges=true" not in service, "sudo vers le ctl serait neutralisé"
    rw = [ligne for ligne in service.splitlines() if ligne.strip().startswith("ReadWritePaths=")]
    assert rw and "/etc/turnserver.conf" not in rw[0] and "/var/log/turnserver" not in rw[0]
    assert "ProtectHome=yes" in service and "PrivateTmp=yes" in service


# ── API ────────────────────────────────────────────────────────────────────────

def test_l_api_ne_pilote_plus_systemd_ni_turnadmin_ni_la_configuration_elle_meme():
    a = API.read_text()
    assert "secubox-turnctl" in a
    assert '"systemctl"' not in a and "turnadmin" not in a.replace("secubox-turnctl", "")
    assert "TURNSERVER_CONF.write_text" not in a and "TURNSERVER_CONF.read_text" not in a
    assert "/var/lib/secubox/turn/users.json" not in a, "les utilisateurs vivent dans la base de coturn, pas en clair"


def test_l_api_repond_par_le_ctl(monkeypatch):
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    import api.main as m

    appels = []

    def faux_ctl(*args, stdin=None, timeout=30):
        appels.append((args, stdin))
        verbe = args[0]
        if verbe == "status":
            return {"active": True, "enabled": True, "pid": 42, "uptime_seconds": 10, "realm": "turn.box.test",
                    "listening_port": 3478, "tls_port": None, "min_port": 49152, "max_port": 65535,
                    "config_secubox": True, "secret_configured": True, "users_count": 1}
        if verbe == "credentials":
            return {"username": "1:u", "password": "p", "ttl": 60, "expires": 1, "realm": "turn.box.test",
                    "turn_urls": ["turn:turn.box.test:3478"], "stun_urls": ["stun:turn.box.test:3478"]}
        if verbe == "users":
            return {"users": [{"username": "alice"}]}
        if verbe == "user-add":
            return {"success": True}
        return {"success": True, "verbe": verbe}

    monkeypatch.setattr(m, "_ctl", faux_ctl)
    m.app.dependency_overrides[m.require_jwt] = lambda: {"sub": "test"}
    c = TestClient(m.app)

    st = c.get("/status").json()
    assert st["service"]["active"] is True and st["realm"] == "turn.box.test" and st["config_secubox"] is True

    assert c.post("/restart").json()["success"] is True
    assert ("restart",) in [a for a, _ in appels]

    # le mot de passe part par stdin du ctl, pas en argv
    r = c.post("/users", json={"username": "alice", "password": "s3cret"})
    assert r.status_code == 200 and r.json()["success"] is True
    arg, entree = [x for x in appels if x[0][0] == "user-add"][0]
    assert arg == ("user-add", "alice") and entree == "s3cret\n"

    # un nom hors alphabet est refusé AVANT le ctl
    assert c.post("/users", json={"username": "a b", "password": "x"}).status_code == 422 or \
        c.post("/users", json={"username": "a b", "password": "x"}).json().get("success") is False
    assert not any(a[0] == "user-add" and a[1] == "a b" for a, _ in appels)

    # la configuration est générée : l'éditeur à la main est refusé
    assert c.post("/config", json={"content": "realm=x"}).status_code == 409
    assert c.post("/generer").json()["success"] is True

    cred = c.post("/credentials", json={"username": "u", "ttl": 60}).json()
    assert cred["password"] == "p" and cred["turn_urls"]


# ── paquet ─────────────────────────────────────────────────────────────────────

def test_rules_installe_le_ctl_et_le_sudoers_et_control_depend_de_sudo_et_openssl():
    r = RULES.read_text()
    assert "composants/turn/sbin/secubox-turnctl" in r and "usr/sbin" in r
    assert "composants/turn/sudoers/secubox-turn" in r and "etc/sudoers.d/secubox-turn" in r
    c = CONTROL.read_text()
    dep = re.search(r"(?ms)^Depends:(.*?)(?=^\S|\Z)", c).group(1)
    assert "sudo" in dep and "openssl" in dep and "coturn" in dep


def test_le_postinst_valide_le_sudoers_puis_genere_si_coturn_a_la_configuration_debian():
    p = POSTINST.read_text()
    assert "visudo -cf /etc/sudoers.d/secubox-turn" in p
    assert "secubox-turnctl generer" in p
    assert "# SecuBox" in p, "le marqueur décide : une configuration SecuBox en place n'est pas réécrite"


def test_le_panneau_ne_propose_plus_d_editeur_libre_mais_la_regeneration():
    h = PANNEAU.read_text()
    assert "/generer" in h
    assert "readonly" in h.split('id="editeur"', 1)[1][:200]
    assert "'/config', { content" not in h
