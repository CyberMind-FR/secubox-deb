# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3247 — le VRAI streamlitctl : port libre, publication, réveil du conteneur, arguments refusés.

Le ctl est la seule surface privilégiée : il voit les ports en écoute DANS le conteneur (lxc-attach, root) et écrit
les fichiers root (streamlit.toml, table de routes sbxwaf, journal d'audit). lxc-info / lxc-start / lxc-attach sont
simulés par des scripts placés en tête du PATH.
"""
import json
import os
import stat
import subprocess
from pathlib import Path

import pytest

ICI = Path(__file__).resolve().parents[2]
CTL = ICI / "sbin" / "streamlitctl"
PUBLICATION_PY = ICI / "api" / "publication.py"
REFUS = 64


def _exe(chemin: Path, texte: str) -> None:
    chemin.write_text(texte)
    chemin.chmod(chemin.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)


@pytest.fixture
def box(tmp_path):
    bin_ = tmp_path / "bin"
    bin_.mkdir()
    eveil = tmp_path / "conteneur.eveille"
    demarre = tmp_path / "unite.demarree"
    journal = tmp_path / "appels.txt"
    # lxc-info : RUNNING si le drapeau existe ; -i rend l'adresse du conteneur.
    _exe(bin_ / "lxc-info", f"""#!/bin/bash
for a in "$@"; do [ "$a" = "-i" ] && {{ echo 10.100.0.50; exit 0; }}; done
if [ -f "{eveil}" ]; then echo "State: RUNNING"; else echo "State: STOPPED"; fi
""")
    _exe(bin_ / "lxc-start", f"""#!/bin/bash
echo "lxc-start $*" >> "{journal}"
touch "{eveil}"
""")
    _exe(bin_ / "lxc-stop", "#!/bin/bash\nexit 0\n")
    # lxc-attach -n <ct> -- <cmd...> : ss (liste ou sonde d'un port), systemctl, ps.
    _exe(bin_ / "lxc-attach", f"""#!/bin/bash
[ -f "{eveil}" ] || exit 1
shift 2; shift
case "$1" in
  systemctl) echo "$*" >> "{journal}"; touch "{demarre}"; exit 0 ;;
  pip3|timeout) echo "$*" >> "{journal}"; exit 0 ;;
  ss)
    if [ "$2" = "-Htln" ]; then
      echo "LISTEN 0 128 0.0.0.0:8501 0.0.0.0:*"
      echo "LISTEN 0 128 [::]:22 [::]:*"
      exit 0
    fi
    if [ -f "{demarre}" ]; then
      port=$(printf '%s' "$3" | grep -oE '[0-9]+$')
      echo "State Recv-Q Send-Q Local Address:Port Peer Address:Port"
      echo "LISTEN 0 128 0.0.0.0:$port 0.0.0.0:*"
    fi
    exit 0 ;;
  *) exit 0 ;;
esac
""")
    _exe(bin_ / "nginx", f'#!/bin/bash\necho "nginx $*" >> "{journal}"\n')
    _exe(bin_ / "systemctl", f'#!/bin/bash\necho "systemctl $*" >> "{journal}"\n')
    _exe(bin_ / "haproxyctl", f'#!/bin/bash\necho "haproxyctl $*" >> "{journal}"\n')
    nginx = tmp_path / "nginx"
    (nginx / "sites-available").mkdir(parents=True)
    (nginx / "sites-enabled").mkdir()
    apps = tmp_path / "apps"
    apps.mkdir()
    lxc = tmp_path / "lxc" / "streamlit"
    (lxc / "rootfs").mkdir(parents=True)
    (lxc / "config").write_text("lxc.net.0.link = br-lxc\nlxc.net.0.ipv4.address = 10.100.0.50/24\n")
    conf = tmp_path / "streamlit.toml"
    conf.write_text("[main]\nenabled = true\n")
    routes = tmp_path / "haproxy-routes.json"
    routes.write_text(json.dumps({"admin.gk2.secubox.in": ["192.168.1.200", 9080]}))
    env = {
        "SECUBOX_NGINX_DIR": str(nginx),
        "SECUBOX_WAF_ROUTE": str(ICI.parents[1] / "packages" / "secubox-core" / "usr" / "sbin" / "secubox-waf-route"),
        "SECUBOX_STREAMLIT_CT_RACINE": str(tmp_path / "ct"),
        "PATH": f"{bin_}:/usr/bin:/bin:/usr/sbin:/sbin",
        "SECUBOX_STREAMLIT_APPS_PATH": str(apps),
        "SECUBOX_STREAMLIT_CONF": str(conf),
        "SECUBOX_STREAMLIT_IDLE_DIR": str(tmp_path / "idle"),
        "SECUBOX_STREAMLIT_LXC_PATH": str(lxc),
        "SECUBOX_STREAMLIT_PUBLICATION_PY": str(PUBLICATION_PY),
        "SECUBOX_STREAMLIT_ROUTES": str(routes),
        "SECUBOX_HAPROXY_TOML": str(tmp_path / "haproxy.toml"),
        "SECUBOX_STREAMLIT_AUDIT": str(tmp_path / "audit.log"),
        "SECUBOX_STREAMLIT_VERROU": str(tmp_path / "verrou"),
        "SECUBOX_DOMAINE": "gk2.secubox.in",
    }

    class B:
        pass
    b = B()
    b.env, b.apps, b.conf, b.routes, b.eveil, b.journal = env, apps, conf, routes, eveil, journal
    b.nginx = nginx
    b.audit = tmp_path / "audit.log"

    def ctl(*args):
        return subprocess.run(["bash", str(CTL), *args], env=env, capture_output=True, text=True, timeout=60)
    b.ctl = ctl

    def appli(nom, port=None):
        d = apps / nom
        d.mkdir()
        (d / "app.py").write_text("import streamlit\n")
        if port:
            (d / ".streamlit.toml").write_text(f'port = {port}\nentrypoint = "{nom}/app.py"\n')
    b.appli = appli
    return b


def _json(r):
    return json.loads(r.stdout.strip().splitlines()[-1])


def test_app_port_choisit_un_port_libre_vu_dans_le_conteneur(box):
    box.eveil.touch()
    box.appli("nouvelle")
    box.conf.write_text(box.conf.read_text() + "\n[apps.decl]\nport = 8502\n")
    r = box.ctl("app", "port", "nouvelle", "--apply")
    assert r.returncode == 0, r.stderr
    sortie = _json(r)
    assert sortie["port"] == 8503 and sortie["source"] == "auto"     # 8501 en écoute, 8502 déclaré
    assert "port = 8503" in (box.apps / "nouvelle" / ".streamlit.toml").read_text()


def test_app_port_explicite_pris_refuse(box):
    box.eveil.touch()
    box.appli("nouvelle")
    r = box.ctl("app", "port", "nouvelle", "8501", "--apply")
    assert r.returncode == 4, r.stderr
    assert "8501" in _json(r)["error"]


def test_app_publish_pose_route_instance_et_audit(box):
    box.eveil.touch()
    box.appli("atelier-partage-1", port=8529)
    r = box.ctl("app", "publish", "atelier-partage-1", "atelier", "--par", "admin", "--apply")
    assert r.returncode == 0, r.stderr + r.stdout
    # sbxwaf → nginx :9080 (adresse des voisins du port), nginx → conteneur (adresse vive rendue par lxc-info -i).
    assert json.loads(box.routes.read_text())["atelier.gk2.secubox.in"] == ["192.168.1.200", 9080]
    vhost = (box.nginx / "sites-available" / "streamlit-atelier.conf").read_text()
    assert "proxy_pass http://10.100.0.50:8529;" in vhost
    assert "[instances.atelier]" in box.conf.read_text()
    ligne = json.loads(box.audit.read_text().splitlines()[-1])
    assert ligne["evenement"] == "publication" and ligne["par"] == "admin"
    r = box.ctl("app", "publish", "atelier-partage-1", "partage", "--par", "admin", "--apply")
    assert r.returncode == 0, r.stderr + r.stdout
    routes = json.loads(box.routes.read_text())
    assert "atelier.gk2.secubox.in" not in routes and routes["partage.gk2.secubox.in"] == ["192.168.1.200", 9080]
    assert not (box.nginx / "sites-enabled" / "streamlit-atelier.conf").exists()
    r = box.ctl("app", "unpublish", "atelier-partage-1", "--par", "admin", "--apply")
    assert r.returncode == 0, r.stderr + r.stdout
    assert "partage.gk2.secubox.in" not in json.loads(box.routes.read_text())


def test_app_env_par_l_entree_standard(box):
    box.eveil.touch()
    box.appli("atelier-partage-1")
    r = subprocess.run(["bash", str(CTL), "app", "env", "atelier-partage-1", "set", "--par", "admin", "--apply"],
                       env=box.env, input="AP_COOKIE_SECURE=1\nAP_DB_PATH=/var/lib/streamlit-apps/x.db\n",
                       capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stderr + r.stdout
    assert _json(r)["cles"] == ["AP_COOKIE_SECURE", "AP_DB_PATH"]
    r = box.ctl("app", "env", "atelier-partage-1", "list")
    assert r.returncode == 0 and _json(r)["cles"] == ["AP_COOKIE_SECURE", "AP_DB_PATH"]
    assert "/var/lib" not in r.stdout


def test_app_start_conteneur_arrete_code_75(box):
    box.appli("foo", port=8510)
    r = box.ctl("app", "start", "foo", "8510")
    assert r.returncode == 75, (r.returncode, r.stderr)
    assert "onteneur" in r.stderr or "Container" in r.stderr


def test_app_start_appli_inconnue_code_2(box):
    box.eveil.touch()
    r = box.ctl("app", "start", "fantome", "8510")
    assert r.returncode == 2, (r.returncode, r.stderr)


def test_app_wake_reveille_le_conteneur_endormi(box):
    box.appli("foo", port=8510)
    r = box.ctl("app", "wake", "foo", "5")
    assert r.returncode == 0, r.stderr
    appels = box.journal.read_text()
    assert "lxc-start" in appels
    assert "systemctl start streamlit-app@foo.service" in appels


@pytest.mark.parametrize("args", [
    ("app", "port", "ok", "80;id"),
    ("app", "port", "../x"),
    ("app", "publish", "ok", "Mauvais_Nom"),
    ("app", "publish", "ok", "a.b"),
    ("app", "publish", "../x", "nom"),
    ("app", "publish", "ok", "nom", "--par", "$(id)"),
    ("app", "publish", "ok", "nom", "--par"),
    ("app", "unpublish", "ok", "x y"),
    ("app", "publication", "a/b"),
    ("app", "env", "ok", "set", "--unset", "A B"),
    ("app", "env", "ok", "set", "AP_X=1"),
    ("app", "env", "ok", "rm"),
])
def test_arguments_hostiles_refuses(box, args):
    r = box.ctl(*args)
    assert r.returncode == REFUS, (args, r.returncode, r.stderr)
    assert "argument refuse" in r.stderr


@pytest.mark.parametrize("args", [
    ("app", "port", "ok"),
    ("app", "port", "ok", "8555", "--apply"),
    ("app", "publish", "ok", "atelier", "--par", "admin", "--apply"),
    ("app", "publish", "ok", "--apply"),
    ("app", "unpublish", "ok", "--par", "admin@gk2.secubox.in", "--apply"),
    ("app", "publication", "ok"),
    ("app", "env", "ok", "list"),
    ("app", "env", "ok", "set", "--unset", "AP_X", "--par", "admin", "--apply"),
])
def test_arguments_legitimes_passent_la_garde(box, args):
    r = box.ctl(*args)
    assert r.returncode != REFUS, (args, r.stderr)
    assert "argument refuse" not in r.stderr


def test_ctl_n_execute_le_module_qu_en_mode_isole():
    texte = CTL.read_text()
    assert 'python3 -I "$PUBLICATION_PY"' in texte


def test_le_module_ne_depend_que_de_la_bibliotheque_standard():
    """Exécuté en root par `python3 -I` : aucun import hors bibliothèque standard (ni secubox_core, ni fastapi)."""
    import ast
    arbre = ast.parse(PUBLICATION_PY.read_text())
    modules = set()
    for n in ast.walk(arbre):
        if isinstance(n, ast.Import):
            modules |= {a.name.split(".")[0] for a in n.names}
        elif isinstance(n, ast.ImportFrom):
            assert n.level == 0, "import relatif interdit"
            modules.add(n.module.split(".")[0])
    import sys
    assert modules <= set(sys.stdlib_module_names), modules - set(sys.stdlib_module_names)


def test_lancement_isole_reel(box):
    """`python3 -I` sur le fichier source : le module tourne sans le dépôt sur le chemin d'import."""
    env = dict(box.env)
    env["PYTHONPATH"] = "/nulle/part"
    box.appli("nouvelle")
    r = subprocess.run(["python3", "-I", str(PUBLICATION_PY), "--conf", str(box.conf), "--apps", str(box.apps),
                        "port", "nouvelle"], env=env, capture_output=True, text=True, timeout=30)
    assert r.returncode == 0, r.stderr
    assert json.loads(r.stdout)["source"] == "auto"
    assert os.environ.get("PYTHONPATH", "") != "/nulle/part"


def test_unite_lit_l_environnement_et_garde_les_donnees_hors_de_l_appli():
    """Constat gk2 : streamlit-launch ne savait passer aucune variable à une appli, et la base d'atelier-partage-1
    vivait dans son dossier, qu'un nouveau dépôt efface. L'unité lit le fichier root 0600 du conteneur (facultatif)
    et donne à l'appli un dossier de données persistant hors de /srv/streamlit/apps."""
    unite = (ICI / "lxc" / "streamlit-app@.service").read_text()
    service = unite.split("[Service]", 1)[1].split("[Install]", 1)[0]
    assert "EnvironmentFile=-/etc/streamlit/env/%i.env" in service
    assert "StateDirectory=streamlit-apps/%i" in service and "StateDirectoryMode=0750" in service
    assert "Environment=STREAMLIT_DATA_DIR=/var/lib/streamlit-apps/%i" in service
    assert "Restart=no" in service


def test_le_ctl_repose_l_unite_dans_un_conteneur_deja_installe():
    texte = CTL.read_text()
    corps = texte.split("cmd_app_start() {", 1)[1].split("\n}\n", 1)[0]
    assert corps.index("_lxc_assets_sync") < corps.index('systemctl start "$(_unit_instance')


def test_boot_ne_demarre_le_conteneur_que_pour_une_appli_publiee(box):
    """Le conteneur arrêté après un redémarrage de gk2 rendait toute appli publiée injoignable. `boot` le démarre
    si une publication l'exige (autostart posé par la publication), et seulement alors : le parc dort (#982)."""
    r = box.ctl("boot")
    assert r.returncode == 0, r.stderr
    assert not box.journal.exists() or "lxc-start" not in box.journal.read_text()
    box.conf.write_text(box.conf.read_text() + "\n[apps.atelier]\nport = 8529\nautostart = true\n"
                        "autostart_publication = true\n")
    r = box.ctl("boot")
    assert r.returncode == 0, r.stderr
    assert "lxc-start" in box.journal.read_text()


def test_unite_de_demarrage_livree_activee_jamais_demarree_a_l_installation():
    unite = (ICI / "debian" / "secubox-streamlit-demarrage.service").read_text()
    assert "ExecStart=/usr/sbin/streamlitctl boot" in unite and "Type=oneshot" in unite
    assert "WantedBy=multi-user.target" in unite and "UMask=0027" in unite
    assert "secubox-streamlit-demarrage.service" in (ICI / "debian" / "secubox-streamlit.install").read_text()
    postinst = (ICI / "debian" / "postinst").read_text()
    assert "systemctl enable secubox-streamlit-demarrage.service" in postinst
    assert "start secubox-streamlit-demarrage" not in postinst and "--now secubox-streamlit-demarrage" not in postinst
    prerm = (ICI / "debian" / "prerm").read_text()
    retrait = prerm.split("remove|deconfigure)", 1)[1].split(";;", 1)[0]
    assert "disable secubox-streamlit-demarrage.service" in retrait
