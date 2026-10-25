# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Rendu des configurations du LXC Meet : install-lxc.sh en mode essai à blanc (aucun lxc-*, aucun root)."""
import subprocess
from pathlib import Path

from conftest import _ecrire_exec, _env_ctl

RACINE = Path(__file__).resolve().parents[1]
INSTALL = RACINE / "lib" / "meet" / "install-lxc.sh"
FICHIERS = ("livekit.yaml", "meet.env", "nginx-meet.conf", "meet-backend.service", "livekit.service", "lxc-config")


def run_install(tmp_path, domaine=None):
    """Lance install-lxc.sh en essai à blanc ; renvoie (code, stderr)."""
    env = _env_ctl(tmp_path, domaine=domaine)
    # Un lxc-create qui laisse un témoin : prouve qu'aucun lxc-* n'a été appelé.
    _ecrire_exec(tmp_path / "bin" / "lxc-create", f'#!/bin/bash\ntouch "{tmp_path}/lxc-create.temoin"\n')
    env["SECUBOX_MEET_DRY_RUN"] = str(tmp_path / "rendu")
    env["SECUBOX_MEET_VERSION_FILE"] = str(RACINE / "conf" / "meet.version")
    r = subprocess.run(["bash", str(INSTALL)], capture_output=True, text=True, env=env, timeout=60)
    return r.returncode, r.stderr


def rendu(tmp_path):
    rc, err = run_install(tmp_path)
    assert rc == 0, err
    return {nom: (tmp_path / "rendu" / nom).read_text() for nom in FICHIERS}


def test_sans_domaine_refuse(tmp_path):
    rc, err = run_install(tmp_path, domaine="")
    assert rc == 1 and "domaine" in err.lower()
    assert not any(tmp_path.glob("lxc-*")) and not (tmp_path / "rendu").exists()


def test_rendu_livekit_yaml(tmp_path):
    y = rendu(tmp_path)["livekit.yaml"]
    assert "port: 7880" in y and "tcp_port: 7881" in y and "udp_port: 7882" in y and "use_external_ip: true" in y
    assert "port_range_start" not in y and "  meet: " in y and "webhooks-livekit" in y and "redis" in y


def test_rendu_env_meet(tmp_path):
    e = dict(ligne.split("=", 1) for ligne in rendu(tmp_path)["meet.env"].splitlines() if "=" in ligne)
    assert e["DJANGO_CONFIGURATION"] == "Production" and e["ALLOW_UNREGISTERED_ROOMS"] == "False"
    assert e["OIDC_OP_AUTHORIZATION_ENDPOINT"] == "https://hall.exemple.test/oidc/authorize"
    assert e["OIDC_RP_SCOPES"] == '"openid email"' and e["OIDC_USE_PKCE"] == "True" and "OIDC_OP_LOGOUT_ENDPOINT" not in e
    assert e["LIVEKIT_API_URL"] == "https://livekit.exemple.test" and e["LIVEKIT_INTERNAL_URL"] == "http://127.0.0.1:7880"
    assert e["DJANGO_ALLOWED_HOSTS"] == "visio.exemple.test" and e["DJANGO_CSRF_TRUSTED_ORIGINS"] == "https://visio.exemple.test"
    assert e["CELERY_TASK_ALWAYS_EAGER"] == "True" and e["DATA_DIR"] == "/var/lib/meet"
    # ListValue de Meet découpe sur les virgules : pas de syntaxe JSON.
    assert e["OIDC_USERINFO_FULLNAME_FIELDS"] == "name"


def test_env_secrets_generes_et_coherents(tmp_path):
    f = rendu(tmp_path)
    e = dict(ligne.split("=", 1) for ligne in f["meet.env"].splitlines() if "=" in ligne)
    secrets = tmp_path / "secrets"
    assert len(e["DJANGO_SECRET_KEY"]) >= 50 and len(e["DB_PASSWORD"]) == 32 and len(e["LIVEKIT_API_SECRET"]) == 32
    assert e["OIDC_RP_CLIENT_SECRET"] == ""
    assert f"  meet: {e['LIVEKIT_API_SECRET']}" in f["livekit.yaml"]
    for nom in ("django-secret", "db-password", "livekit-secret"):
        assert ((secrets / nom).stat().st_mode & 0o777) == 0o600
    assert (secrets.stat().st_mode & 0o777) == 0o700
    # Relancé : les secrets sont réutilisés, pas régénérés.
    avant = (secrets / "django-secret").read_text()
    assert run_install(tmp_path)[0] == 0
    assert (secrets / "django-secret").read_text() == avant


def test_secret_oidc_repris_s_il_existe(tmp_path):
    (tmp_path / "secrets").mkdir()
    (tmp_path / "secrets" / "oidc-client-secret").write_text("secretoidc123\n")
    assert "OIDC_RP_CLIENT_SECRET=secretoidc123\n" in rendu(tmp_path)["meet.env"]


def test_rendu_nginx_interne(tmp_path):
    n = rendu(tmp_path)["nginx-meet.conf"]
    assert "root /opt/meet/frontend" in n and "proxy_pass http://127.0.0.1:8000" in n
    assert "/api/" in n and "/admin/" in n and "/static/" in n and "/index.html" in n
    assert "X-Forwarded-Proto" in n and "client_max_body_size 50m" in n


def test_rendu_unites_internes(tmp_path):
    f = rendu(tmp_path)
    b, lk = f["meet-backend.service"], f["livekit.service"]
    assert "User=meet" in b and "EnvironmentFile=/etc/meet/meet.env" in b and "meet.wsgi:application" in b
    assert "After=postgresql.service redis-server.service" in b
    assert "User=livekit" in lk and "--config /etc/livekit/livekit.yaml" in lk and "After=redis-server.service" in lk


def test_config_lxc_demarre_au_boot(tmp_path):
    c = rendu(tmp_path)["lxc-config"]
    assert "lxc.start.auto = 1" in c and "lxc.idmap = u 0 100000 65536" in c and "10.100.0.195/24" in c
    assert "lxc.cgroup2.memory.max = 2147483648" in c and "lxc.net.0.link = br-lxc" in c


def test_meetctl_install_delegue_au_script(tmp_path):
    env = _env_ctl(tmp_path)
    ok = tmp_path / "faux-install.sh"
    _ecrire_exec(ok, "#!/bin/bash\necho journal\nexit 0\n")
    env["SECUBOX_MEET_INSTALL_SCRIPT"] = str(ok)
    r = subprocess.run(["bash", str(RACINE / "sbin" / "meetctl"), "install"], capture_output=True, text=True, env=env)
    assert r.returncode == 0 and r.stdout.strip() == '{"success": true}'
    _ecrire_exec(ok, "#!/bin/bash\nexit 4\n")
    r = subprocess.run(["bash", str(RACINE / "sbin" / "meetctl"), "install"], capture_output=True, text=True, env=env)
    assert r.returncode == 1 and r.stdout.strip() == '{"success": false}'
