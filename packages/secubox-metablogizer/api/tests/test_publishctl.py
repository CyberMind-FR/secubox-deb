# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""secubox-publishctl argument validation (run the script with a fake route file
and mocked nft/haproxy/certbot on PATH — validation must reject junk BEFORE any
privileged call)."""
import json
import os
import subprocess
from pathlib import Path

HELPER = Path(__file__).resolve().parents[2] / "sbin" / "secubox-publishctl"


def _run(args, env):
    return subprocess.run(["bash", str(HELPER), *args], capture_output=True, text=True, env=env)


def _env(tmp_path):
    # Fake bins that just succeed, so a VALID call would pass; validation must
    # fail earlier for bad input.
    bindir = tmp_path / "bin"
    bindir.mkdir()
    for name in ("haproxyctl", "systemctl", "certbot", "haproxy"):
        p = bindir / name
        p.write_text("#!/bin/bash\nexit 0\n")
        p.chmod(0o755)
    routes = tmp_path / "routes.json"
    routes.write_text("{}")
    env = dict(os.environ)
    env["PATH"] = f"{bindir}:{env['PATH']}"
    env["SBX_WAF_ROUTES_FILE"] = str(routes)
    env["SBX_HAPROXY_CERTS_DIR"] = str(tmp_path / "certs")
    return env, routes


def test_waf_route_rejects_bad_domain(tmp_path):
    env, _ = _env(tmp_path)
    r = _run(["waf-route", "evil;rm -rf /", "8900"], env)
    assert r.returncode != 0
    assert "ok" in r.stdout and json.loads(r.stdout)["ok"] is False


def test_waf_route_rejects_non_numeric_port(tmp_path):
    env, _ = _env(tmp_path)
    r = _run(["waf-route", "good.gk2.secubox.in", "80x"], env)
    assert r.returncode != 0


def test_waf_route_writes_host_backend(tmp_path):
    env, routes = _env(tmp_path)
    r = _run(["waf-route", "zem.gk2.secubox.in", "8900"], env)
    assert r.returncode == 0, r.stderr
    data = json.loads(routes.read_text())
    # Le bouclage, pas l'adresse LAN de gk2 : vaut sur toute box (#1823).
    assert data["zem.gk2.secubox.in"] == ["127.0.0.1", 8900]


def test_waf_route_backend_overridable(tmp_path):
    env, routes = _env(tmp_path)
    env["SBX_BACKEND_IP"] = "10.0.0.7"
    assert _run(["waf-route", "zem.gk2.secubox.in", "8900"], env).returncode == 0
    assert json.loads(routes.read_text())["zem.gk2.secubox.in"] == ["10.0.0.7", 8900]


def _nginx(tmp_path, code, sortie=""):
    p = tmp_path / "bin" / "nginx"
    p.write_text(f"#!/bin/bash\necho '{sortie}' >&2\nexit {code}\n")
    p.chmod(0o755)


BLOC = ("server {\n    listen 0.0.0.0:8900;\n    server_name a.example.org;\n"
        "    root /srv/metablogizer/sites/a/public;\n    index index.html;\n"
        "    location / {\n        try_files $uri $uri/ /index.html;\n    }\n}\n")


def _apply_env(tmp_path, prepare=BLOC, ancien="# ancien\n"):
    env, _ = _env(tmp_path)
    staging, cible = tmp_path / "staging.conf", tmp_path / "sites-enabled-metablogizer"
    staging.write_text(prepare)
    if ancien is not None:
        cible.write_text(ancien)
    env["SBX_NGINX_STAGING"], env["SBX_NGINX_SITES_FILE"] = str(staging), str(cible)
    return env, staging, cible


def test_nginx_apply_installe_teste_et_recharge(tmp_path):
    env, _, cible = _apply_env(tmp_path)
    _nginx(tmp_path, 0, "test is successful")
    r = _run(["nginx-apply"], env)
    assert r.returncode == 0, r.stdout
    assert json.loads(r.stdout)["ok"] is True
    assert cible.read_text() == BLOC


def test_nginx_apply_rend_le_jeton_de_l_appel(tmp_path):
    env, _, _ = _apply_env(tmp_path, prepare="# publishctl-jeton: 0123456789abcdef\n" + BLOC)
    _nginx(tmp_path, 0)
    assert json.loads(_run(["nginx-apply"], env).stdout)["jeton"] == "0123456789abcdef"


def test_nginx_apply_restaure_si_nginx_refuse(tmp_path):
    """nginx -t échoue : la version précédente revient, et on dit pourquoi."""
    env, _, cible = _apply_env(tmp_path)
    _nginx(tmp_path, 1, "nginx: [emerg] a duplicate default server for 0.0.0.0:8900")
    r = _run(["nginx-apply"], env)
    res = json.loads(r.stdout)
    assert r.returncode != 0 and res["ok"] is False
    assert "duplicate default server" in res["detail"]
    assert cible.read_text() == "# ancien\n"


import pytest  # noqa: E402


@pytest.mark.parametrize("contenu,motif", [
    ("include /etc/shadow;\n", "directive refusée : include"),
    ("server {\n    access_log /etc/cron.d/x;\n}\n", "directive refusée : access_log"),
    ("load_module /tmp/x.so;\n", "directive refusée : load_module"),
    # Un domaine piégé dans site.json ne fait pas entrer une directive.
    ("server {\n    server_name x.example.org; include /etc/passwd;\n}\n", "directive refusée : include"),
    ("server {\n    root /etc;\n}\n", "racine refusée"),
    ("server {\n    root /srv/../etc;\n}\n", "racine refusée"),
    ("server {\n    location / {\n        proxy_pass http://evil.example.org;\n    }\n}\n", "proxy_pass refusé"),
    ("server {\n    listen 0.0.0.0:8900 ssl;\n}\n", "listen refusé"),
])
def test_nginx_apply_refuse_ce_que_le_generateur_n_emet_pas(tmp_path, contenu, motif):
    """Root installe un fichier écrit par un compte de service : vérifié d'abord."""
    env, _, cible = _apply_env(tmp_path, prepare=contenu)
    _nginx(tmp_path, 0)
    r = _run(["nginx-apply"], env)
    res = json.loads(r.stdout)
    assert r.returncode != 0 and res["ok"] is False and motif in res["detail"]
    assert cible.read_text() == "# ancien\n", "rien n'est installé avant validation"


def test_nginx_apply_ne_cite_pas_un_contenu_etranger(tmp_path):
    """Un mot qui n'a pas la forme d'une directive n'est jamais renvoyé."""
    env, _, _ = _apply_env(tmp_path, prepare="root:$y$j9T$secret:19000:0:99999:7:::\n")
    _nginx(tmp_path, 0)
    res = json.loads(_run(["nginx-apply"], env).stdout)
    assert res["ok"] is False and "secret" not in res["detail"]


def test_nginx_apply_refuse_un_lien(tmp_path):
    env, staging, cible = _apply_env(tmp_path)
    vrai = tmp_path / "ailleurs.conf"
    vrai.write_text(BLOC)
    staging.unlink()
    staging.symlink_to(vrai)
    _nginx(tmp_path, 0)
    r = _run(["nginx-apply"], env)
    assert r.returncode != 0 and json.loads(r.stdout)["ok"] is False
    assert cible.read_text() == "# ancien\n"


def test_nginx_apply_n_accepte_aucun_argument(tmp_path):
    env, _, _ = _apply_env(tmp_path)
    _nginx(tmp_path, 0)
    r = _run(["nginx-apply", "/tmp/x.conf"], env)
    assert r.returncode != 0 and json.loads(r.stdout)["ok"] is False


def test_le_fichier_du_generateur_passe_la_validation(monkeypatch, tmp_path):
    """Intégration : ce que le générateur écrit VRAIMENT est accepté par l'aide."""
    from test_conflits_domaines import prepare, site
    main, enabled = prepare(monkeypatch, tmp_path, [site(tmp_path, "a", "a.example.org"),
                                                    site(tmp_path, "b", "b.example.org")])
    ok, _, _ = main.regenerate_nginx_config()
    assert ok
    genere = (enabled / "metablogizer").read_text()
    # Les racines du banc vivent sous tmp : on les ramène sous /srv pour l'aide.
    genere = genere.replace(str(tmp_path), "/srv/metablogizer")
    env, _, cible = _apply_env(tmp_path, prepare=genere)
    _nginx(tmp_path, 0)
    r = _run(["nginx-apply"], env)
    assert r.returncode == 0, r.stdout
    assert cible.read_text() == genere


def test_vhost_del_passe_le_nom_de_table_a_haproxyctl(tmp_path):
    """`vhost add` nomme la table par `tr '.-' '_'` ; `vhost remove` attend ce
    nom. Lui passer le domaine ne retirait rien, en répondant « Removed » (#1823)."""
    env, routes = _env(tmp_path)
    trace = tmp_path / "haproxyctl.args"
    p = tmp_path / "bin" / "haproxyctl"
    p.write_text(f"#!/bin/bash\necho \"$@\" > {trace}\nexit 0\n")
    p.chmod(0o755)
    routes.write_text(json.dumps({"guide-bip.gk2.secubox.in": ["127.0.0.1", 8900]}))
    r = _run(["vhost-del", "guide-bip.gk2.secubox.in"], env)
    assert r.returncode == 0, r.stdout
    assert trace.read_text().split() == ["vhost", "remove", "guide_bip_gk2_secubox_in"]
    assert "guide-bip.gk2.secubox.in" not in json.loads(routes.read_text())
