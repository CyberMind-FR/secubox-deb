# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Vhost de la page OpenPGP du Coffre (#1852, P5) : origine séparée, politique stricte, API réduite au strict nécessaire."""
import os
import re
import subprocess
from pathlib import Path

import pytest

PKG = Path(__file__).resolve().parents[1]
SCRIPT = PKG / "sbin" / "coffre-pgp-vhost"


def imprime(tmp_path, pgp="pgp.gk2.secubox.in", web="webmail.gk2.secubox.in", ent=None):
    bin_ = tmp_path / "bin"
    bin_.mkdir(exist_ok=True)
    stub = bin_ / "secubox-domaine"
    stub.write_text(f'#!/bin/sh\ncase "$1" in pgp) echo "{pgp}";; webmail) echo "{web}";; esac\n')
    stub.chmod(0o755)
    stub2 = bin_ / "curl"                                         # jamais le réseau dans les tests
    stub2.write_text("#!/bin/sh\nexit 0\n")
    stub2.chmod(0o755)
    env = {**os.environ, "PATH": f"{bin_}:{os.environ['PATH']}", "SECUBOX_PGP_ANCETRES_ENT": ent or ""}
    stub.write_text(f'#!/bin/sh\ncase "$1" in pgp) echo "{pgp}";; webmail) echo "{web}";; hall) echo "hall.gk2.secubox.in";; esac\n')
    return subprocess.run(["bash", str(SCRIPT), "--imprime"], capture_output=True, text=True, env=env)


def test_le_vhost_est_a_origine_separee_et_n_est_encadrable_que_par_le_webmail(tmp_path):
    r = imprime(tmp_path)
    assert r.returncode == 0 and "server_name pgp.gk2.secubox.in;" in r.stdout
    assert "frame-ancestors https://webmail.gk2.secubox.in https://hall.gk2.secubox.in;" in r.stdout
    assert '{"origines":["https://webmail.gk2.secubox.in"]}' in r.stdout


def test_la_politique_interdit_les_scripts_en_ligne_et_tout_exterieur(tmp_path):
    csp = re.search(r'Content-Security-Policy "([^"]+)"', imprime(tmp_path).stdout).group(1)
    assert "script-src 'self'" in csp and "default-src 'none'" in csp and "connect-src 'self'" in csp
    assert "unsafe-inline" not in csp and "unsafe-eval" not in csp and "*" not in csp


def test_seules_les_routes_necessaires_sont_relayees(tmp_path):
    v = imprime(tmp_path).stdout
    relayees = re.findall(r"location ~ \"?\^(/api/[^\s\"]+)", v)
    assert len(relayees) == 2 and all(r.startswith(("/api/v1/vault/moi/secrets", "/api/v1/openpgp/(annuaire")) for r in relayees)
    # jamais l'administration du Coffre, ni la publication ou le retrait d'une clé, ni l'envoi de messages
    for interdit in ("/api/v1/vault/etat", "/api/v1/vault/ouvrir", "/openpgp/moi", "/openpgp/envoyer", "/openpgp/boite"):
        assert interdit not in v
    assert "limit_except POST" in v and "limit_except GET" in v


def test_sans_domaine_rien_n_est_ecrit(tmp_path):
    r = imprime(tmp_path, pgp="", web="")
    assert r.returncode == 0 and "server_name" not in r.stdout and "rien n'est écrit" in r.stderr


def test_la_page_livre_ses_fichiers_et_le_paquet_les_installe():
    rules = (PKG / "debian" / "rules").read_text()
    for f in ("www/pgp/index.html", "www/pgp/pgp.js", "www/pgp/openpgp.min.js", "sbin/coffre-pgp-vhost"):
        assert f in rules and (PKG / f).is_file()
    html = (PKG / "www" / "pgp" / "index.html").read_text()
    assert "<script>" not in html and "onclick" not in html                      # aucun script en ligne
    assert (PKG / "www" / "pgp" / "LICENSE-openpgpjs.txt").read_text().startswith(" ")   # licence LGPL de la bibliothèque livrée
    assert subprocess.run(["bash", "-n", str(PKG / "debian" / "postinst")]).returncode == 0


def test_toute_expression_a_accolade_est_entre_guillemets_pour_nginx(tmp_path):
    """nginx lit « { » d'une expression non guillemetée comme le début d'un bloc : `nginx -t` la refuse."""
    for ligne in imprime(tmp_path).stdout.splitlines():
        if ligne.strip().startswith("location ~") and "{" in ligne.split("location ~", 1)[1].rsplit("{", 1)[0]:
            assert re.search(r'location ~ "[^"]*\{[^"]*"', ligne), ligne


@pytest.mark.skipif(not (os.path.exists("/usr/sbin/nginx") or __import__("shutil").which("nginx")), reason="nginx absent")
def test_le_vhost_genere_passe_nginx_t(tmp_path):
    """Le vrai juge : nginx lui-même (le test d'accolades ci-dessus a été écrit APRÈS un refus de nginx sur gk2)."""
    nginx = __import__("shutil").which("nginx") or "/usr/sbin/nginx"
    (tmp_path / "vhost.conf").write_text(imprime(tmp_path).stdout.replace("/var/log/nginx/", f"{tmp_path}/"))      # journaux : dossier jetable
    (tmp_path / "nginx.conf").write_text(
        f"pid {tmp_path}/n.pid; error_log {tmp_path}/e.log;\nevents {{}}\nhttp {{\n  access_log off;\n  geo $lan_client {{ default 0; }}\n"
        f"  include {tmp_path}/vhost.conf;\n}}\n")
    r = subprocess.run([nginx, "-t", "-c", str(tmp_path / "nginx.conf"), "-p", str(tmp_path)], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr


def test_la_page_est_encadrable_par_toute_la_chaine_que_le_webmail_accepte(tmp_path):
    """Régression gk2 : le webmail est affiché DANS le Hall ; avec le seul webmail comme ancêtre, le navigateur bloquait la page."""
    ent = "content-security-policy: frame-ancestors 'self' https://hall.gk2.secubox.in https://hall.gk2.net https://billets.gk2.secubox.in"
    csp = re.search(r'Content-Security-Policy "([^"]+)"', imprime(tmp_path, ent=ent).stdout).group(1)
    anc = re.search(r"frame-ancestors ([^;]+);", csp).group(1).split()
    assert anc == ["https://webmail.gk2.secubox.in", "https://hall.gk2.secubox.in", "https://hall.gk2.net", "https://billets.gk2.secubox.in"]


def test_un_ancetre_mal_forme_ou_joker_n_entre_jamais_dans_l_en_tete(tmp_path):
    ent = "content-security-policy: frame-ancestors 'self' * http://clair.example https://ok.example https://x.example;evil https://a b"
    csp = re.search(r'Content-Security-Policy "([^"]+)"', imprime(tmp_path, ent=ent).stdout).group(1)
    anc = re.search(r"frame-ancestors ([^;]+);", csp).group(1).split()
    assert "*" not in anc and "http://clair.example" not in anc and "https://ok.example" in anc and "https://x.example" in anc
