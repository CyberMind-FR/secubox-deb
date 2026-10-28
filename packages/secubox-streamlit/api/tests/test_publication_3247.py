# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3247 — port automatique, publication déclarative, nom public, environnement d'une appli Streamlit.

`api/publication.py` est exécuté EN ROOT par streamlitctl (`python3 -I`) et importé par l'API pour valider. La chaîne
publiée est celle posée à la main pour couture.gk2.secubox.in le 2026-10-28, rendue générable :
    HAProxy (haproxyctl vhost add <d> nginx_vhosts true) → sbxwaf (secubox-waf-route <d> 9080)
    → nginx :9080 (sites-available/streamlit-<nom>.conf + lien) → conteneur <ip>:<port>
    + [instances.<nom>] et [apps.<dossier>] dans streamlit.toml.
Bancs : fichiers temporaires ; nginx, systemctl, haproxyctl, lxc-attach simulés en tête du PATH ; secubox-waf-route
est le VRAI outil de secubox-core (table pointée par SBX_WAF_ROUTES).
"""
import json
import os
import stat
from pathlib import Path

import pytest

from api import publication as P

REPO = Path(__file__).resolve().parents[4]
WAF_ROUTE = REPO / "packages" / "secubox-core" / "usr" / "sbin" / "secubox-waf-route"


def _exe(chemin: Path, texte: str) -> None:
    chemin.write_text(texte)
    chemin.chmod(chemin.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)


@pytest.fixture
def box(tmp_path, monkeypatch):
    bin_ = tmp_path / "bin"
    bin_.mkdir()
    journal = tmp_path / "appels.log"
    haproxy = tmp_path / "haproxy.toml"
    haproxy.write_text('[vhosts.hall_gk2_secubox_in]\ndomain = "hall.gk2.secubox.in"\nbackend = "x"\n')
    _exe(bin_ / "nginx", f"""#!/bin/bash
echo "nginx $*" >> "{journal}"
if [ -f "{tmp_path}/nginx.echec" ]; then echo "nginx: [emerg] unexpected end of file" >&2; exit 1; fi
exit 0
""")
    _exe(bin_ / "systemctl", f'#!/bin/bash\necho "systemctl $*" >> "{journal}"\nexit 0\n')
    _exe(bin_ / "lxc-attach", f"""#!/bin/bash
echo "lxc-attach $*" >> "{journal}"
if [[ "$*" == *pip3* ]] && [ -f "{tmp_path}/pip.echec" ]; then
  echo "ERROR: No matching distribution found for segno==99" >&2; exit 1
fi
exit 0
""")
    _exe(bin_ / "haproxyctl", f"""#!/bin/bash
echo "haproxyctl $*" >> "{journal}"
if [ "$1" = vhost ] && [ "$2" = remove ] && [ -f "{tmp_path}/haproxy.refus" ]; then
  echo "Drift guard: generated cfg has fewer vhosts/backends than live" >&2; exit 1
fi
if [ "$1" = vhost ] && [ "$2" = add ]; then
  printf '\\n[vhosts.%s]\\ndomain = "%s"\\nbackend = "%s"\\n' "$(printf '%s' "$3" | tr '.-' '__')" "$3" "$4" >> "{haproxy}"
fi
exit 0
""")
    nginx = tmp_path / "nginx"
    (nginx / "sites-available").mkdir(parents=True)
    (nginx / "sites-enabled").mkdir()
    apps = tmp_path / "apps"
    apps.mkdir()
    conf = tmp_path / "streamlit.toml"
    conf.write_text("[main]\nenabled = true\n")
    routes = tmp_path / "haproxy-routes.json"
    routes.write_text(json.dumps({
        "admin.gk2.secubox.in": ["192.168.1.200", 9080],
        "cpf.gk2.secubox.in": ["10.100.0.50", 8523],          # ancienne route DIRECTE vers le conteneur
    }))
    audit = tmp_path / "audit.log"
    monkeypatch.setenv("PATH", f"{bin_}:{os.environ['PATH']}")
    monkeypatch.setenv("SECUBOX_STREAMLIT_ROUTES", str(routes))
    monkeypatch.setenv("SECUBOX_HAPROXY_TOML", str(haproxy))
    monkeypatch.setenv("SECUBOX_STREAMLIT_AUDIT", str(audit))
    monkeypatch.setenv("SECUBOX_STREAMLIT_VERROU", str(tmp_path / "verrou"))
    monkeypatch.setenv("SECUBOX_NGINX_DIR", str(nginx))
    monkeypatch.setenv("SECUBOX_WAF_ROUTE", str(WAF_ROUTE))
    monkeypatch.setenv("SECUBOX_DOMAINE", "gk2.secubox.in")
    monkeypatch.setenv("SECUBOX_STREAMLIT_CT_RACINE", str(tmp_path / "ct"))

    class Box:
        pass
    b = Box()
    b.tmp, b.apps, b.conf, b.routes, b.haproxy, b.audit, b.nginx, b.journal = (
        tmp_path, apps, conf, routes, haproxy, audit, nginx, journal)

    def appli(nom, port=None):
        d = apps / nom
        d.mkdir()
        (d / "app.py").write_text("import streamlit\n")
        if port:
            (d / ".streamlit.toml").write_text(f'port = {port}\nentrypoint = "{nom}/app.py"\n')
    b.appli = appli
    b.appels = lambda: journal.read_text() if journal.exists() else ""
    return b


def run(box, capsys, *args, entree=None):
    rc = P.main(["--conf", str(box.conf), "--apps", str(box.apps), *args], entree=entree)
    out = capsys.readouterr().out.strip().splitlines()
    return rc, (json.loads(out[-1]) if out else {})


def lignes_audit(box):
    if not box.audit.exists():
        return []
    return [json.loads(x) for x in box.audit.read_text().splitlines() if x.strip()]


def section(texte, entete):
    bloc = texte.split(f"[{entete}]\n", 1)[1]
    return bloc.split("\n[", 1)[0]


# ─── Nom public : libellé DNS strict ────────────────────────────────────────

@pytest.mark.parametrize("label", ["atelier", "atelier-partage-1", "a", "x" * 63, "42"])
def test_libelle_dns_valide(label):
    assert P.erreur_label(label) is None


@pytest.mark.parametrize("label", ["", "Atelier", "atelier_1", "-atelier", "atelier-", "a.b", "x" * 64,
                                   "été", "a b", "../x", "a;id"])
def test_libelle_dns_invalide(label):
    assert P.erreur_label(label)


@pytest.mark.parametrize("label", ["admin", "hall", "www", "api", "mail", "git", "waf"])
def test_noms_reserves(label):
    assert P.erreur_label(label) is None and P.label_reserve(label)


@pytest.mark.parametrize("dossier,attendu", [("atelier-partage-1", "atelier-partage-1"),
                                             ("Photo_cloud_streamlit_main", "photo-cloud-streamlit-main"),
                                             ("yijing.v2", "yijing-v2"), ("__x__", "x")])
def test_nom_public_par_defaut_derive_du_dossier(dossier, attendu):
    assert P.label_par_defaut(dossier) == attendu


# ─── Port automatique ──────────────────────────────────────────────────────

def test_port_auto_evite_declares_ecoute_processus_et_routes(box, capsys):
    box.appli("nouvelle")
    box.appli("autre", port=8501)                                   # attribué (fichier de port)
    box.conf.write_text(box.conf.read_text() + "\n[apps.decl]\nport = 8502\n"
                        '\n[instances.vit]\napp = "vitrine"\nport = 8503\ndomain = "vit.gk2.secubox.in"\n')
    routes = json.loads(box.routes.read_text())
    routes["vieux.gk2.secubox.in"] = ["10.100.0.50", 8506]          # route directe restée vers le conteneur
    box.routes.write_text(json.dumps(routes))
    rc, r = run(box, capsys, "port", "nouvelle", "--ecoute", "8504 22", "--processus", "manuelle:8505",
                "--ip-vive", "10.100.0.50")
    assert rc == 0, r
    assert r["port"] == 8507 and r["source"] == "auto"
    assert r["applique"] is False
    assert not (box.apps / "nouvelle" / ".streamlit.toml").exists()   # sans --apply : rien d'écrit


def test_port_auto_applique_persiste_et_declare_l_appli(box, capsys):
    """Constat gk2 : un dépôt ne déclarait pas l'appli ([apps.<nom>]) — `app autostart` la refusait ensuite."""
    box.appli("nouvelle")
    rc, r = run(box, capsys, "port", "nouvelle", "--apply")
    assert rc == 0 and r["port"] == 8501 and r["applique"] is True
    assert "port = 8501" in (box.apps / "nouvelle" / ".streamlit.toml").read_text()
    decl = section(box.conf.read_text(), "apps.nouvelle")
    assert "port = 8501" in decl and "enabled = true" in decl


def test_port_garde_apres_un_nouveau_depot(box, capsys):
    """Un nouveau dépôt efface le dossier (et son .streamlit.toml) : le port déclaré survit et reste le sien."""
    box.appli("ancienne")
    box.conf.write_text(box.conf.read_text() + "\n[apps.ancienne]\nport = 8529\n")
    rc, r = run(box, capsys, "port", "ancienne", "--apply")
    assert rc == 0 and r["port"] == 8529 and r["source"] == "declare"


def test_port_actuel_garde(box, capsys):
    box.appli("ancienne", port=8529)
    rc, r = run(box, capsys, "port", "ancienne", "--ecoute", "8529", "--processus", "ancienne:8529")
    assert rc == 0 and r["port"] == 8529 and r["source"] == "fichier"


def test_port_demande_libre_respecte(box, capsys):
    box.appli("nouvelle")
    rc, r = run(box, capsys, "port", "nouvelle", "--demande", "8555", "--apply")
    assert rc == 0 and r["port"] == 8555 and r["source"] == "demande"
    assert "port = 8555" in (box.apps / "nouvelle" / ".streamlit.toml").read_text()


@pytest.mark.parametrize("prise", ["fichier", "ecoute", "processus", "instance"])
def test_port_demande_pris_refuse_avec_la_cause(box, capsys, prise):
    box.appli("nouvelle")
    args = ["port", "nouvelle", "--demande", "8529", "--apply"]
    if prise == "fichier":
        box.appli("atelier", port=8529)
    elif prise == "ecoute":
        args += ["--ecoute", "8529"]
    elif prise == "processus":
        args += ["--processus", "atelier:8529"]
    else:
        box.conf.write_text(box.conf.read_text() + '\n[instances.at]\napp = "atelier"\nport = 8529\n')
    avant = box.conf.read_text()
    rc, r = run(box, capsys, *args)
    assert rc == 4, r
    assert "8529" in r["error"] and r["ok"] is False
    assert not (box.apps / "nouvelle" / ".streamlit.toml").exists()
    assert box.conf.read_text() == avant


def test_aucun_port_libre(box, capsys):
    box.appli("nouvelle")
    box.conf.write_text(box.conf.read_text() + "\n[ports]\nmin = 8501\nmax = 8502\n")
    rc, r = run(box, capsys, "port", "nouvelle", "--ecoute", "8501 8502")
    assert rc == 5 and "8501" in r["error"] and "8502" in r["error"]


def test_appli_inconnue(box, capsys):
    rc, r = run(box, capsys, "port", "fantome")
    assert rc == 2


# ─── Publication : les quatre maillons + audit ─────────────────────────────

def _publier(box, capsys, appli="atelier-partage-1", nom="atelier", port=8529, *extra):
    return run(box, capsys, "publier", appli, "--nom", nom, "--port", str(port), "--ip-vive", "10.100.0.50",
               "--par", "admin", "--apply", *extra)


def test_publier_pose_nginx_route_haproxy_toml_et_audite(box, capsys):
    box.appli("atelier-partage-1", port=8529)
    rc, r = _publier(box, capsys)
    assert rc == 0, r
    assert r["domaine"] == "atelier.gk2.secubox.in" and r["evenement"] == "publication" and r["applique"]
    # nginx :9080 → conteneur, WebSocket compris ; lien dans sites-enabled.
    dispo = box.nginx / "sites-available" / "streamlit-atelier.conf"
    actif = box.nginx / "sites-enabled" / "streamlit-atelier.conf"
    vhost = dispo.read_text()
    for attendu in ("listen 9080;", "server_name atelier.gk2.secubox.in;", "proxy_pass http://10.100.0.50:8529;",
                    "proxy_set_header Upgrade $http_upgrade;", 'proxy_set_header Connection "upgrade";',
                    "proxy_read_timeout 86400s;"):
        assert attendu in vhost, attendu
    assert "listen 80" not in vhost and "443" not in vhost
    assert actif.is_symlink() and os.readlink(actif) == str(dispo)
    assert "nginx -t" in box.appels() and "systemctl reload nginx" in box.appels()
    # Route sbxwaf → nginx (adresse des voisins du port 9080), jamais vers le conteneur directement.
    routes = json.loads(box.routes.read_text())
    assert routes["atelier.gk2.secubox.in"] == ["192.168.1.200", 9080]
    assert routes["admin.gk2.secubox.in"] == ["192.168.1.200", 9080]          # les autres routes intactes
    # HAProxy déclaratif.
    assert "haproxyctl vhost add atelier.gk2.secubox.in nginx_vhosts true" in box.appels()
    assert "haproxyctl reload" in box.appels()
    # Déclaration : forme de la référence couture.gk2.
    conf = box.conf.read_text()
    inst = section(conf, "instances.atelier")
    for attendu in ('app = "atelier-partage-1"', "port = 8529", 'domain = "atelier.gk2.secubox.in"',
                    "enabled = true", "emancipated = true", "waf_enabled = true", "publication_geree = true"):
        assert attendu in inst, attendu
    assert "waf_bypass" not in conf
    decl = section(conf, "apps.atelier-partage-1")
    assert "autostart = true" in decl and "autostart_publication = true" in decl and "port = 8529" in decl
    assert "systemctl enable streamlit-app@atelier-partage-1.service" in box.appels()
    (ligne,) = lignes_audit(box)
    assert ligne["evenement"] == "publication" and ligne["module"] == "streamlit"
    assert ligne["appli"] == "atelier-partage-1" and ligne["domaine"] == "atelier.gk2.secubox.in"
    assert ligne["cible"] == "10.100.0.50:8529"
    assert ligne["par"] == "admin" and ligne["resultat"] == "applique" and ligne["ts"].endswith("Z")


def test_publier_sans_apply_n_ecrit_rien(box, capsys):
    box.appli("atelier", port=8529)
    avant_conf, avant_routes = box.conf.read_text(), box.routes.read_text()
    rc, r = run(box, capsys, "publier", "atelier", "--nom", "atelier", "--port", "8529", "--ip-vive", "10.100.0.50")
    assert rc == 0 and r["applique"] is False and r["evenement"] == "publication"
    assert box.conf.read_text() == avant_conf and box.routes.read_text() == avant_routes
    assert not list((box.nginx / "sites-enabled").iterdir()) and box.appels() == ""
    assert lignes_audit(box) == []


def test_reglage_autostart_desactive(box, capsys):
    box.appli("atelier", port=8529)
    box.conf.write_text(box.conf.read_text() + "\n[publication]\nautostart = false\n")
    rc, r = _publier(box, capsys, "atelier")
    assert rc == 0, r
    assert "autostart" not in section(box.conf.read_text(), "apps.atelier")
    assert "systemctl enable" not in box.appels()


def test_adresse_du_conteneur(box, capsys):
    """Réglage > adresse vive > voisines (anciennes routes directes des instances)."""
    box.appli("atelier", port=8529)
    box.conf.write_text(box.conf.read_text() + '\n[instances.cpf]\napp = "cineposter"\nport = 8523\n'
                        'domain = "cpf.gk2.secubox.in"\n')
    rc, r = run(box, capsys, "publier", "atelier", "--nom", "atelier", "--port", "8529", "--apply")
    assert rc == 0, r
    assert "proxy_pass http://10.100.0.50:8529;" in (box.nginx / "sites-available" / "streamlit-atelier.conf"
                                                      ).read_text()


def test_sans_adresse_du_conteneur_75(box, capsys):
    box.appli("atelier", port=8529)
    rc, r = run(box, capsys, "publier", "atelier", "--nom", "atelier", "--port", "8529", "--apply")
    assert rc == 75 and "ip_conteneur" in r["error"]


@pytest.mark.parametrize("cas", ["route", "instance", "haproxy", "reserve", "nginx"])
def test_publier_refuse_un_nom_pris_ou_reserve(box, capsys, cas):
    box.appli("atelier", port=8529)
    nom = {"route": "cpf", "instance": "vit", "haproxy": "hall", "reserve": "admin", "nginx": "blog"}[cas]
    if cas == "instance":
        box.conf.write_text(box.conf.read_text() + '\n[instances.vit]\napp = "vitrine"\nport = 8503\n')
    if cas == "nginx":
        (box.nginx / "sites-enabled" / "metablogizer").write_text(
            "server {\n    listen 8900;\n    server_name blog.gk2.secubox.in;\n}\n")
    avant_conf, avant_routes = box.conf.read_text(), box.routes.read_text()
    rc, r = _publier(box, capsys, "atelier", nom)
    assert rc == 4, r
    assert r["error"]
    assert box.conf.read_text() == avant_conf and box.routes.read_text() == avant_routes
    assert box.appels() == "" and lignes_audit(box) == []


def test_publier_refuse_un_libelle_invalide(box, capsys):
    box.appli("atelier", port=8529)
    rc, r = run(box, capsys, "publier", "atelier", "--nom", "Mauvais_Nom", "--port", "8529", "--apply")
    assert rc == 64


def test_nginx_t_en_echec_rien_n_est_publie(box, capsys):
    box.appli("atelier", port=8529)
    (box.tmp / "nginx.echec").touch()
    avant_conf, avant_routes = box.conf.read_text(), box.routes.read_text()
    rc, r = _publier(box, capsys, "atelier")
    assert rc == 1 and "nginx -t" in r["error"]
    assert box.conf.read_text() == avant_conf and box.routes.read_text() == avant_routes
    assert not (box.nginx / "sites-enabled" / "streamlit-atelier.conf").exists()
    assert not (box.nginx / "sites-available" / "streamlit-atelier.conf").exists()


def test_table_illisible_abandon_rien_n_est_ecrit(box, capsys):
    box.appli("atelier", port=8529)
    box.routes.write_text('{"tronque": ')
    avant_conf = box.conf.read_text()
    rc, r = _publier(box, capsys, "atelier")
    assert rc == 1 and "illisible" in r["error"]
    assert box.conf.read_text() == avant_conf and box.routes.read_text() == '{"tronque": '
    assert box.appels() == ""


def test_journal_d_audit_inaccessible_abandon(box, capsys, monkeypatch, tmp_path):
    box.appli("atelier", port=8529)
    monkeypatch.setenv("SECUBOX_STREAMLIT_AUDIT", str(tmp_path / "absent" / "audit.log"))
    avant_conf, avant_routes = box.conf.read_text(), box.routes.read_text()
    rc, r = _publier(box, capsys, "atelier")
    assert rc == 1 and "audit" in r["error"]
    assert box.conf.read_text() == avant_conf and box.routes.read_text() == avant_routes
    assert box.appels() == ""


def test_appli_archivee_refusee(box, capsys):
    box.appli("atelier", port=8529)
    box.conf.write_text(box.conf.read_text() + "\n[apps.atelier]\narchived = true\nenabled = false\n")
    rc, r = _publier(box, capsys, "atelier")
    assert rc == 3 and "archiv" in r["error"]


# ─── Renommage : l'ancien nom retiré, le nouveau posé, par le même chemin ─

def test_renommer_retire_les_quatre_maillons_de_l_ancien_nom(box, capsys):
    box.appli("atelier-partage-1", port=8529)
    assert _publier(box, capsys)[0] == 0
    rc, r = _publier(box, capsys, "atelier-partage-1", "partage")
    assert rc == 0, r
    assert r["evenement"] == "renommage" and r["ancien"]["domaine"] == "atelier.gk2.secubox.in"
    routes = json.loads(box.routes.read_text())
    assert "atelier.gk2.secubox.in" not in routes
    assert routes["partage.gk2.secubox.in"] == ["192.168.1.200", 9080]
    assert not (box.nginx / "sites-enabled" / "streamlit-atelier.conf").exists()
    assert not (box.nginx / "sites-available" / "streamlit-atelier.conf").exists()
    assert "server_name partage.gk2.secubox.in;" in (box.nginx / "sites-available" / "streamlit-partage.conf"
                                                      ).read_text()
    appels = box.appels()
    retrait = appels.index("haproxyctl vhost remove atelier_gk2_secubox_in")
    assert retrait < appels.index("haproxyctl vhost add partage.gk2.secubox.in nginx_vhosts true")
    conf = box.conf.read_text()
    assert "[instances.atelier]" not in conf and "[instances.partage]" in conf
    assert conf.count('app = "atelier-partage-1"') == 1
    renommage = lignes_audit(box)[-1]
    assert renommage["evenement"] == "renommage" and renommage["ancien_domaine"] == "atelier.gk2.secubox.in"
    assert renommage["domaine"] == "partage.gk2.secubox.in" and renommage["par"] == "admin"


def test_renommer_ne_retire_pas_une_route_qui_n_est_plus_la_notre(box, capsys):
    box.appli("atelier-partage-1", port=8529)
    assert _publier(box, capsys)[0] == 0
    routes = json.loads(box.routes.read_text())
    routes["atelier.gk2.secubox.in"] = ["10.0.0.9", 443]               # re-pointée à la main ailleurs
    box.routes.write_text(json.dumps(routes))
    rc, r = _publier(box, capsys, "atelier-partage-1", "partage")
    assert rc == 0, r
    assert json.loads(box.routes.read_text())["atelier.gk2.secubox.in"] == ["10.0.0.9", 443]
    assert any("atelier.gk2.secubox.in" in a for a in r["avertissements"])


def test_adoption_de_la_reference_posee_a_la_main(box, capsys):
    """couture.gk2 (2026-10-28) : fichier nginx ORDINAIRE dans sites-enabled, route, TOML. Republier sous le même
    nom le reprend (fichier généré + lien, copie de l'original hors de sites-enabled) ; renommer le retire."""
    box.appli("atelier-partage-1", port=8529)
    box.conf.write_text(box.conf.read_text() + "\n[apps.atelier-partage-1]\nport = 8529\nenabled = true\n"
                        '\n[instances.couture]\napp = "atelier-partage-1"\nport = 8529\nenabled = true\n'
                        'emancipated = true\ndomain = "couture.gk2.secubox.in"\nwaf_enabled = true\n')
    main_faite = box.nginx / "sites-enabled" / "streamlit-couture.conf"
    main_faite.write_text("server {\n    listen 9080;\n    server_name couture.gk2.secubox.in;\n    location / {\n"
                          "        proxy_pass http://10.100.0.50:8529;\n    }\n}\n")
    routes = json.loads(box.routes.read_text())
    routes["couture.gk2.secubox.in"] = ["192.168.1.200", 9080]
    box.routes.write_text(json.dumps(routes))
    rc, r = run(box, capsys, "publier", "atelier-partage-1", "--port", "8529", "--ip-vive", "10.100.0.50",
                "--apply")
    assert rc == 0, r
    assert r["evenement"] == "mise-a-jour" and r["domaine"] == "couture.gk2.secubox.in"
    assert main_faite.is_symlink()
    assert (box.nginx / "sites-available" / "streamlit-couture.conf.avant-secubox").exists()
    assert not [f for f in (box.nginx / "sites-enabled").iterdir() if "avant" in f.name]
    rc, r = run(box, capsys, "publier", "atelier-partage-1", "--nom", "atelier", "--port", "8529",
                "--ip-vive", "10.100.0.50", "--apply")
    assert rc == 0, r
    assert not main_faite.exists() and "couture.gk2.secubox.in" not in json.loads(box.routes.read_text())
    assert "[instances.couture]" not in box.conf.read_text()


def test_ancienne_route_directe_migree_vers_la_chaine_nginx(box, capsys):
    box.appli("legacy", port=8540)
    box.conf.write_text(box.conf.read_text() + '\n[instances.lldh]\napp = "legacy"\nport = 8523\n'
                        'domain = "lldh.example.fr"\nenabled = true\n')
    routes = json.loads(box.routes.read_text())
    routes["lldh.example.fr"] = ["10.100.0.50", 8523]
    box.routes.write_text(json.dumps(routes))
    rc, r = run(box, capsys, "publier", "legacy", "--port", "8540", "--ip-vive", "10.100.0.50", "--apply")
    assert rc == 0, r
    assert r["evenement"] == "mise-a-jour" and r["domaine"] == "lldh.example.fr"
    assert json.loads(box.routes.read_text())["lldh.example.fr"] == ["192.168.1.200", 9080]
    vhost = (box.nginx / "sites-available" / "streamlit-lldh.conf").read_text()
    assert "server_name lldh.example.fr;" in vhost and "proxy_pass http://10.100.0.50:8540;" in vhost


def test_republier_sans_changement_n_ecrit_ni_n_audite(box, capsys):
    box.appli("atelier-partage-1", port=8529)
    assert _publier(box, capsys)[0] == 0
    n, appels = len(lignes_audit(box)), box.appels()
    rc, r = run(box, capsys, "publier", "atelier-partage-1", "--port", "8529", "--ip-vive", "10.100.0.50",
                "--apply")
    assert rc == 0 and r["evenement"] == "inchange"
    assert len(lignes_audit(box)) == n and box.appels() == appels


def test_publier_sans_nom_une_appli_non_publiee_est_refuse(box, capsys):
    box.appli("atelier", port=8529)
    rc, r = run(box, capsys, "publier", "atelier", "--port", "8529", "--apply")
    assert rc == 3 and "publi" in r["error"]


# ─── Retrait ────────────────────────────────────────────────────────────────

def test_depublier_retire_les_maillons_et_rend_la_veille(box, capsys):
    box.appli("atelier-partage-1", port=8529)
    assert _publier(box, capsys)[0] == 0
    rc, r = run(box, capsys, "depublier", "atelier-partage-1", "--par", "admin", "--apply")
    assert rc == 0, r
    assert "atelier.gk2.secubox.in" not in json.loads(box.routes.read_text())
    assert not (box.nginx / "sites-enabled" / "streamlit-atelier.conf").exists()
    assert "haproxyctl vhost remove atelier_gk2_secubox_in" in box.appels()
    conf = box.conf.read_text()
    assert "[instances.atelier]" not in conf
    decl = section(conf, "apps.atelier-partage-1")
    assert "autostart = false" in decl and "autostart_publication" not in decl
    assert "systemctl disable streamlit-app@atelier-partage-1.service" in box.appels()
    assert lignes_audit(box)[-1]["evenement"] == "depublication"


def test_depublier_garde_un_autostart_voulu_par_l_operateur(box, capsys):
    box.appli("atelier", port=8529)
    box.conf.write_text(box.conf.read_text() + "\n[apps.atelier]\nport = 8529\nautostart = true\n")
    assert _publier(box, capsys, "atelier")[0] == 0
    assert "autostart_publication" not in box.conf.read_text()
    assert run(box, capsys, "depublier", "atelier", "--apply")[0] == 0
    assert "autostart = true" in section(box.conf.read_text(), "apps.atelier")


def test_etat_et_lecture_pour_l_api(box, capsys):
    box.appli("atelier-partage-1", port=8529)
    assert _publier(box, capsys)[0] == 0
    rc, r = run(box, capsys, "etat", "atelier-partage-1")
    assert rc == 0
    attendu = [{"nom_public": "atelier", "domaine": "atelier.gk2.secubox.in", "port": 8529, "enabled": True,
                "geree": True}]
    assert r["publications"] == attendu
    assert P.publications(box.conf.read_text(), "gk2.secubox.in") == {"atelier-partage-1": attendu}
    assert P.reglages(box.conf.read_text())["auto"] is False


def test_conflit_nom_lecture_seule_pour_l_api(box):
    texte = box.conf.read_text()
    routes = json.loads(box.routes.read_text())
    assert "cpf.gk2.secubox.in" in P.conflit_nom("cpf", "cpf.gk2.secubox.in", "x", texte, routes)
    assert P.conflit_nom("libre", "libre.gk2.secubox.in", "x", texte, routes) is None


# ─── Environnement de l'appli (fichier 0600 dans le conteneur) ─────────────

def test_environnement_defini_liste_retire_et_audite(box, capsys):
    box.appli("atelier-partage-1")
    entree = ("AP_ADMIN_PASSWORD_HASH=$2b$12$abcdefghijklmnopqrstuv\nAP_DB_PATH=/var/lib/streamlit-apps/"
              "atelier-partage-1/atelier.db\nAP_PUBLIC_URL=https://couture.gk2.secubox.in\nAP_COOKIE_SECURE=1\n")
    rc, r = run(box, capsys, "env", "atelier-partage-1", "--par", "admin", "--apply", entree=entree)
    assert rc == 0, r
    assert r["cles"] == ["AP_ADMIN_PASSWORD_HASH", "AP_COOKIE_SECURE", "AP_DB_PATH", "AP_PUBLIC_URL"]
    assert r["redemarrage_requis"] is True
    assert "$2b$" not in json.dumps(r)                                  # jamais une valeur en sortie
    f = box.tmp / "ct" / "etc" / "streamlit" / "env" / "atelier-partage-1.env"
    assert stat.S_IMODE(f.stat().st_mode) == 0o600
    assert "AP_ADMIN_PASSWORD_HASH='$2b$12$abcdefghijklmnopqrstuv'" in f.read_text()
    ligne = lignes_audit(box)[-1]
    assert ligne["evenement"] == "environnement" and "AP_DB_PATH" in ligne["cles_definies"]
    assert "$2b$" not in box.audit.read_text()
    rc, r = run(box, capsys, "env", "atelier-partage-1", "--lister")
    assert rc == 0 and r["cles"] == ["AP_ADMIN_PASSWORD_HASH", "AP_COOKIE_SECURE", "AP_DB_PATH", "AP_PUBLIC_URL"]
    rc, r = run(box, capsys, "env", "atelier-partage-1", "--retirer", "AP_COOKIE_SECURE", "--apply", entree="")
    assert rc == 0 and "AP_COOKIE_SECURE" not in r["cles"] and "AP_COOKIE_SECURE" not in f.read_text()


@pytest.mark.parametrize("entree", ["LD_PRELOAD=/tmp/x.so\n", "PATH=/tmp\n", "PYTHONPATH=/tmp\n", "1X=a\n",
                                    "A B=c\n", "SANS_EGAL\n", "A=l'apostrophe\n"])
def test_environnement_refuse(box, capsys, entree):
    box.appli("atelier")
    rc, r = run(box, capsys, "env", "atelier", "--apply", entree=entree)
    assert rc == 64, r
    assert not (box.tmp / "ct").exists()


def test_identifiant_d_instance_hostile_jamais_un_chemin(box, capsys):
    box.appli("atelier", port=8529)
    box.conf.write_text(box.conf.read_text() + '\n[instances.x/../../../etc/cron.d/y]\napp = "atelier"\nport = 8529\n'
                        'domain = "y.gk2.secubox.in"\n')
    avant = box.conf.read_text()
    rc, r = run(box, capsys, "publier", "atelier", "--port", "8529", "--ip-vive", "10.100.0.50", "--apply")
    assert rc == 3, r
    assert box.conf.read_text() == avant and box.appels() == ""
