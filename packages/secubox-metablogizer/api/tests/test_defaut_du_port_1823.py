# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: metablogizer — le port 8900 a un défaut explicite (#1823).

Vécu sur gk2 : un site publié sans bloc (ou pas encore) tombait sur le premier
fichier chargé du port, `lldh.gk2-redirect.conf`, laissé à la main, et partait
en 301 vers `lldh.ganimed.fr` — un domaine décommissionné. Un hôte inconnu doit
recevoir un 404, jamais le contenu ni la redirection d'un voisin.
"""

import re

from test_conflits_domaines import aide_simulee, noms_emis, prepare, site

DEFAUT = re.compile(r"^\s*listen\s+0\.0\.0\.0:8900\s+default_server;", re.M)


def test_le_fichier_unifie_porte_le_defaut_du_port(monkeypatch, tmp_path):
    main, enabled = prepare(monkeypatch, tmp_path, [site(tmp_path, "a", "a.example.org")],
                            {"lldh.gk2-redirect.conf":
                             "server {\n    listen 0.0.0.0:8900;\n    server_name lldh.gk2.secubox.in;\n"
                             "    return 301 https://lldh.ganimed.fr$request_uri;\n}\n"})
    ok, _, _ = main.regenerate_nginx_config()
    assert ok
    conf = (enabled / "metablogizer").read_text()
    assert len(DEFAUT.findall(conf)) == 1
    # Le défaut répond 404 et ne revendique aucun nom.
    bloc = conf[conf.index("default_server"):].split("}\n}", 1)[0]
    assert "return 404" in bloc
    assert "server_name" not in bloc
    assert noms_emis(enabled / "metablogizer") == ["a.example.org"]


def test_un_defaut_deja_tenu_ailleurs_n_est_pas_redeclare(monkeypatch, tmp_path):
    """Deux `default_server` sur un même port : `nginx -t` refuserait TOUT."""
    main, enabled = prepare(monkeypatch, tmp_path, [site(tmp_path, "a", "a.example.org")],
                            {"defaut.conf": "server {\n    listen 8900 default_server;\n}\n"})
    ok, _, _ = main.regenerate_nginx_config()
    assert ok
    assert not DEFAUT.search((enabled / "metablogizer").read_text())


def test_le_defaut_d_un_autre_port_ne_compte_pas(monkeypatch, tmp_path):
    main, enabled = prepare(monkeypatch, tmp_path, [site(tmp_path, "a", "a.example.org")],
                            {"webui.conf": "server {\n    listen 0.0.0.0:9080 default_server;\n}\n"})
    ok, _, _ = main.regenerate_nginx_config()
    assert ok
    assert DEFAUT.search((enabled / "metablogizer").read_text())


# ── Rechargement : par l'aide root, et jamais un fichier refusé en place ──

def test_l_installation_passe_par_l_unite_hors_bac_a_sable(monkeypatch, tmp_path):
    """Monté dans l'agrégateur, /etc est en lecture seule, même pour un enfant
    lancé par sudo : vécu sur gk2. Seule une unité systemd en sort."""
    main, enabled = prepare(monkeypatch, tmp_path, [site(tmp_path, "a", "a.example.org")])
    appels = []
    monkeypatch.setattr(main, "run_cmd", aide_simulee(main, enabled / "metablogizer", appels=appels))
    ok, _, _ = main.regenerate_nginx_config()
    assert ok
    assert appels == [["sudo", "-n", "/usr/bin/systemctl", "start", "metablog-nginx.service"]]
    assert (enabled / "metablogizer").read_text().startswith("# publishctl-jeton: ")


def test_un_refus_de_l_aide_fait_un_echec_qui_le_dit(monkeypatch, tmp_path):
    main, enabled = prepare(monkeypatch, tmp_path, [site(tmp_path, "a", "a.example.org")])
    monkeypatch.setattr(main, "run_cmd", aide_simulee(
        main, enabled / "metablogizer", ok=False, detail="nginx -t : [emerg] duplicate default server"))
    ok, n, msg = main.regenerate_nginx_config()
    assert not ok and "duplicate default server" in msg


def test_un_verdict_d_un_autre_appel_n_est_pas_pris(monkeypatch, tmp_path):
    """Le fichier de verdict d'avant (ok) ne fait pas passer un appel raté."""
    import json as _json
    main, enabled = prepare(monkeypatch, tmp_path, [site(tmp_path, "a", "a.example.org")])
    main.NGINX_VERDICT.write_text(_json.dumps({"ok": True, "detail": "vieux", "jeton": "0" * 16}))
    monkeypatch.setattr(main, "run_cmd", lambda cmd, timeout=30: (False, "", "sudo: a password is required"))
    ok, _, msg = main.regenerate_nginx_config()
    assert not ok and "password is required" in msg


# ── Le générateur travaille sur le disque, et l'assistant vérifie ─────────

def test_le_generateur_ignore_un_cache_perime(monkeypatch, tmp_path):
    """Vécu sur gk3 : site créé par l'assistant, liste en cache d'avant, aucun bloc."""
    main, enabled = prepare(monkeypatch, tmp_path, [])
    frais = [site(tmp_path, "neuf", "neuf.example.org")]
    monkeypatch.setattr(main, "_SITES_CACHE", [])            # instantané d'avant
    monkeypatch.setattr(main, "_SITES_CACHE_AT", 10 ** 12)    # « tout frais »
    monkeypatch.setattr(main, "load_sites",
                        lambda: main._SITES_CACHE if main._SITES_CACHE is not None else frais)
    ok, n, _ = main.regenerate_nginx_config()
    assert ok and n == 1
    assert noms_emis(enabled / "metablogizer") == ["neuf.example.org"]


def test_sans_site_le_fichier_est_vide_de_blocs_mais_ecrit(monkeypatch, tmp_path):
    """Dépublier le dernier site doit RETIRER son bloc, pas le laisser servir."""
    main, enabled = prepare(monkeypatch, tmp_path, [])
    (enabled / "metablogizer").write_text("server {\n    server_name ancien.example.org;\n}\n")
    ok, n, _ = main.regenerate_nginx_config()
    assert ok and n == 0
    conf = (enabled / "metablogizer").read_text()
    assert noms_emis(enabled / "metablogizer") == [] and DEFAUT.search(conf)


def test_l_etape_service_verifie_que_le_domaine_a_un_bloc(monkeypatch, tmp_path):
    import routers.publish as rp
    conf = tmp_path / "metablogizer"
    conf.write_text("server {\n    listen 0.0.0.0:8900;\n    server_name autre.example.org;\n}\n")
    monkeypatch.setattr(rp, "NGINX_METABLOGS_CONF", conf)
    monkeypatch.setattr(rp, "regenerer_nginx", lambda: (True, 1, "Published 1 sites"))
    r = rp.publie_vhost("neuf.example.org")
    assert r["ok"] is False and "aucun bloc server" in r["detail"]
    # Un nom qui n'est qu'un SUFFIXE d'un autre ne compte pas.
    conf.write_text("server {\n    server_name xneuf.example.org;\n}\n")
    assert rp.publie_vhost("neuf.example.org")["ok"] is False
    conf.write_text("server {\n    server_name neuf.example.org www.neuf.example.org;\n}\n")
    assert rp.publie_vhost("neuf.example.org")["ok"] is True


# ── Supprimer un site le dépublie d'abord ─────────────────────────────────

def test_supprimer_un_site_le_depublie_d_abord(monkeypatch, tmp_path):
    """Avant : seuls les fichiers du vieux modèle étaient retirés (EROFS dans
    l'agrégateur → 500), et le bloc unifié comme la route restaient."""
    import asyncio
    from api import main
    import routers.pilotage
    racine = tmp_path / "sites"
    (racine / "zz" / "public").mkdir(parents=True)
    monkeypatch.setattr(main, "SITES_ROOT", racine)
    monkeypatch.setattr(main, "_invalidate_sites_cache", lambda: None)
    ordre = []
    monkeypatch.setattr(routers.pilotage, "depublier",
                        lambda d: ordre.append(("depublier", d.name)) or {"ok": True})
    monkeypatch.setattr(main, "_rmtree_force", lambda d: ordre.append(("efface", d.name)))
    r = asyncio.run(main.delete_site("zz"))
    assert r["success"] is True
    assert ordre == [("depublier", "zz"), ("efface", "zz")]
