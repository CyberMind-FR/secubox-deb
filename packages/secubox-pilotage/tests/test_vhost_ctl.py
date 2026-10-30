# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3126 L5 tâche 5 : secubox-pilotage-vhost, ctl root qui pose et retire le vhost admin.<box>.secubox.in d'une box légère.

Lancé sans root sous une racine substituée (SBX_RACINE, honorée parce que l'appelant est le processus lui-même) ; les commandes
externes viennent de SBX_BIN (seulement sous SBX_RACINE). haproxyctl et secubox-waf-route sont les VRAIS scripts du dépôt, sur une
table et un haproxy.toml de test : on vérifie le haproxy.cfg réellement généré, pas la présence d'un mot."""
import json
import os
import re
import stat
import subprocess
from pathlib import Path

import pytest

PKG = Path(__file__).resolve().parents[1]
DEPOT = PKG.parents[1]
CTL = PKG / "sbin" / "secubox-pilotage-vhost"
HAPROXYCTL = DEPOT / "packages/secubox-haproxy/sbin/haproxyctl"
WAF_ROUTE = DEPOT / "packages/secubox-core/usr/sbin/secubox-waf-route"
DOM = "admin.gk5.secubox.in"

TOML = """\
mode = "native"
http_port = 80
https_port = 443
stats_port = 8404
waf_enabled = true
waf_backend_ip = "127.0.0.1"
waf_backend_port = 8085

[vhosts.hall]
domain = "hall.gk2.secubox.in"
backend = "sbxwaf_inspector"
enabled = true
ssl = true
"""


def script(chemin: Path, corps: str):
    chemin.write_text("#!/bin/bash\n" + corps)
    chemin.chmod(0o755)


class Banc:
    def __init__(self, tmp: Path):
        self.r = tmp / "racine"
        self.bin = tmp / "bin"
        self.journal = tmp / "appels.log"
        for d in ("var/log/secubox", "etc/nginx/conf.d", "etc/secubox/waf", "data/haproxy/certs", "var/lib/secubox/pilotage",
                  "haproxy/cfg", "haproxy/cfgd", "haproxy/data"):
            (self.r / d).mkdir(parents=True)
        self.www = self.r / "var/lib/secubox-pilotage-pages/www"
        self.www.mkdir(parents=True)
        os.chmod(self.www.parent, 0o755)
        self.toml = self.r / "etc/secubox/haproxy.toml"
        self.toml.write_text(TOML)
        self.routes = self.r / "etc/secubox/waf/haproxy-routes.json"
        self.routes.write_text(json.dumps({"hall.gk2.secubox.in": ["192.168.1.200", 9080]}))
        (self.r / "data/haproxy/certs/*.gk5.secubox.in.pem").write_text("joker")   # certificat joker du pair déjà là
        self.bin.mkdir()
        log = f'echo "$(basename "$0") $*" >> {self.journal}\n'
        # nginx : « -t -c <enveloppe> » = pré-validation du tampon ; « -t » seul = configuration complète
        script(self.bin / "nginx", log + f"""
if [ "$1 $2" = "-t -c" ]; then [ -e {self.r}/ECHEC_PRE ] && exit 1; grep -q server_name "$(awk '/include/{{print $2}}' "$3" | tr -d ';')" || exit 1; exit 0; fi
if [ "$1" = "-t" ]; then [ -e {self.r}/ECHEC_T ] && exit 1; exit 0; fi
exit 0
""")
        script(self.bin / "systemctl", log + "exit 0\n")
        script(self.bin / "certbot", log + "exit 1\n")
        script(self.bin / "mkdir", 'a=(); for x in "$@"; do [ "$x" = /run/haproxy ] || a+=("$x"); done; exec /bin/mkdir "${a[@]}"\n')
        script(self.bin / "haproxy", "exit 0\n")
        env_h = (f"export SECUBOX_HAPROXY_CONF={self.toml} SECUBOX_HAPROXY_CONFIG_DIR={self.r}/haproxy/cfg "
                 f"HAPROXY_DATA_PATH={self.r}/haproxy/data HAPROXY_EXTRA_CFG_DIR={self.r}/haproxy/cfgd PATH={self.bin}:$PATH\n")
        script(self.bin / "haproxyctl", log + env_h + f"""
case "$1" in
  reload) exit 0 ;;
  generate) bash {HAPROXYCTL} "$@" >/dev/null 2>&1; [ -s {self.r}/haproxy/cfg/haproxy.cfg ] ;;
  # hors root, `vhost add/remove` échouent APRÈS avoir écrit haproxy.toml (chown du cfg régénéré) : le toml fait foi ici
  vhost) bash {HAPROXYCTL} "$@" >/dev/null 2>&1; exit 0 ;;
  *) exec bash {HAPROXYCTL} "$@" ;;
esac
""")
        script(self.bin / "secubox-waf-route", log + f"SBX_WAF_ROUTES={self.routes} exec python3 {WAF_ROUTE} \"$@\"\n")
        script(self.bin / "secubox-pilotage-www", log + f"cat >> {self.r}/www-stdin.log; echo '{{\"ok\": true}}'\n")

    def pages(self, paquet, version, *modules):
        for m in modules:
            d = self.www / paquet / version / m
            d.mkdir(parents=True)
            (d / "index.html").write_text(f"<html>{m}</html>")
        subprocess.run(["chmod", "-R", "go-w", str(self.www.parent)], check=True)   # comme l'extracteur : 0755 / 0644

    def ctl(self, *args, entree=None, env=None):
        e = {"PATH": os.environ["PATH"], "SBX_RACINE": str(self.r), "SBX_BIN": str(self.bin), "SBX_LIB": str(PKG),
             "SUDO_USER": "root"}
        e.update(env or {})
        return subprocess.run([str(CTL), *args], input=entree, capture_output=True, text=True, env=e, timeout=120)

    def conf(self, box="gk5"):
        return self.r / f"etc/nginx/conf.d/secubox-pilotage-admin-{box}.conf"

    def appels(self):
        return self.journal.read_text().splitlines() if self.journal.exists() else []

    def audit(self):
        p = self.r / "var/log/secubox/audit.log"
        return [json.loads(x) for x in p.read_text().splitlines()] if p.exists() else []

    def cfg(self):
        return (self.r / "haproxy/cfg/haproxy.cfg").read_text()


PAGES = json.dumps({"pages": [{"paquet": "secubox-system", "version": "1.4.0"}, {"paquet": "secubox-dns", "version": "2.0"}]})


@pytest.fixture
def banc(tmp_path):
    b = Banc(tmp_path)
    b.pages("secubox-system", "1.4.0", "system")
    b.pages("secubox-dns", "2.0", "dns", "dns-provider")
    return b


def test_poser_le_vhost(banc):
    r = banc.ctl("poser", "--acteur", "alice", "gk5", entree=PAGES)
    assert r.returncode == 0, r.stdout + r.stderr
    out = json.loads(r.stdout)
    assert out["ok"] and out["domaine"] == DOM
    conf = banc.conf().read_text()
    assert f"server_name {DOM};" in conf
    assert "alias /var/lib/secubox-pilotage-pages/www/secubox-dns/2.0/dns-provider/;" in conf
    assert stat.S_IMODE(banc.conf().stat().st_mode) == 0o644
    a = [x for x in banc.audit() if x["evenement"] == "pilotage_vhost_poser"][-1]
    assert a["box"] == "gk5" and a["acteur"] == "alice" and a["resultat"] == "ok" and a["domaine"] == DOM
    assert "systemctl reload nginx" in banc.appels()


def test_pas_de_bypass_waf(banc):
    """Le nom public passe par HAProxy → sbxwaf → nginx : vhost HAProxy vers sbxwaf_inspector (cfg réellement généré), route
    sbxwaf vers le port des vhosts nginx (adresse des voisins), aucun waf_bypass."""
    assert banc.ctl("poser", "gk5", entree=PAGES).returncode == 0
    cfg = banc.cfg()
    acl = re.search(r"acl (\S+) hdr\(host\) -i " + re.escape(DOM), cfg).group(1)
    uses = re.findall(r"use_backend (\S+) if " + re.escape(acl) + r"\b", cfg)
    assert uses and set(uses) == {"sbxwaf_inspector"}
    assert "nginx_vhosts" not in " ".join(uses)
    toml = banc.toml.read_text()
    bloc = toml.split("[vhosts.admin_gk5_secubox_in]", 1)[1].split("\n[", 1)[0]
    assert 'backend = "sbxwaf_inspector"' in bloc and "waf_bypass" not in bloc
    routes = json.loads(banc.routes.read_text())
    assert routes[DOM] == ["192.168.1.200", 9080]
    assert "listen 0.0.0.0:9080;" in banc.conf().read_text()
    assert any(x.startswith("secubox-waf-route admin.gk5.secubox.in 9080") for x in banc.appels())


def test_poser_idempotent(banc):
    assert banc.ctl("poser", "gk5", entree=PAGES).returncode == 0
    n = len(banc.appels())
    r = banc.ctl("poser", "gk5", entree=PAGES)
    assert r.returncode == 0 and json.loads(r.stdout)["deja"] is True
    nouveaux = banc.appels()[n:]
    assert not any(x.startswith(("haproxyctl vhost add", "systemctl reload nginx")) for x in nouveaux)


def test_version_non_extraite_ignoree(banc):
    p = json.dumps({"pages": [{"paquet": "secubox-system", "version": "1.4.0"}, {"paquet": "secubox-dns", "version": "9.9"}]})
    r = banc.ctl("poser", "gk5", entree=p)
    assert r.returncode == 0
    assert json.loads(r.stdout)["absentes"] == ["secubox-dns=9.9"]
    assert "/dns/" not in banc.conf().read_text()


@pytest.mark.parametrize("box", ["GK5", "gk5.evil", "a" * 41, "../x", "", "gk5;rm", "-gk5"])
def test_nom_de_box_invalide_refuse(banc, box):
    r = banc.ctl("poser", box, entree=PAGES)
    assert r.returncode == 2
    assert list((banc.r / "etc/nginx/conf.d").iterdir()) == []
    assert banc.appels() == []


def test_verbe_et_entree_invalides(banc):
    assert banc.ctl("detruire", "gk5").returncode == 2
    for entree in ("pas du json", json.dumps({"pages": [{"paquet": "../x", "version": "1"}]}),
                   json.dumps({"pages": [], "en_trop": 1}), json.dumps({"pages": [{"paquet": "secubox-a", "version": "1", "x": 1}]})):
        assert banc.ctl("poser", "gk5", entree=entree).returncode == 2, entree
    assert banc.appels() == []


def test_rollback_si_nginx_t_echoue(banc):
    assert banc.ctl("poser", "gk5", entree=PAGES).returncode == 0
    avant = banc.conf().read_text()
    (banc.r / "ECHEC_T").touch()
    p = json.dumps({"pages": [{"paquet": "secubox-system", "version": "1.4.0"}]})
    r = banc.ctl("poser", "gk5", entree=p)
    assert r.returncode == 1 and "nginx" in json.loads(r.stdout)["erreur"]
    assert banc.conf().read_text() == avant           # ancienne configuration rétablie
    assert [x.name for x in (banc.r / "etc/nginx/conf.d").iterdir()] == [banc.conf().name]   # aucun résidu
    a = banc.audit()[-1]
    assert a["evenement"] == "pilotage_vhost_poser" and a["resultat"] == "erreur"


def test_rollback_premiere_pose_et_pre_validation(banc):
    (banc.r / "ECHEC_T").touch()
    r = banc.ctl("poser", "gk5", entree=PAGES)
    assert r.returncode == 1 and not banc.conf().exists()
    assert not any(x.startswith("haproxyctl vhost add") for x in banc.appels())   # rien d'exposé
    (banc.r / "ECHEC_T").unlink()
    (banc.r / "ECHEC_PRE").touch()
    n = len(banc.appels())
    r = banc.ctl("poser", "gk5", entree=PAGES)
    assert r.returncode == 1 and not banc.conf().exists()
    assert not any(x.startswith("nginx -t -q") for x in banc.appels()[n:])   # tampon refusé avant tout échange
    assert list((banc.r / "etc/nginx/conf.d").iterdir()) == []


def test_retrait_du_vhost(banc):
    assert banc.ctl("poser", "gk5", entree=PAGES).returncode == 0
    r = banc.ctl("retirer", "--acteur", "alice", "gk5")
    assert r.returncode == 0, r.stdout + r.stderr
    assert not banc.conf().exists()
    assert DOM not in json.loads(banc.routes.read_text())
    assert json.loads(banc.routes.read_text())["hall.gk2.secubox.in"] == ["192.168.1.200", 9080]   # voisins intacts
    assert "admin_gk5_secubox_in" not in banc.toml.read_text()
    assert any(x.startswith("haproxyctl generate --allow-shrink") for x in banc.appels())
    a = banc.audit()[-1]
    assert a["evenement"] == "pilotage_vhost_retirer" and a["box"] == "gk5" and a["resultat"] == "ok"


def test_certificat_absent_certbot_refuse(banc):
    (banc.r / "data/haproxy/certs/*.gk5.secubox.in.pem").unlink()
    r = banc.ctl("poser", "gk5", entree=PAGES)
    assert r.returncode == 1 and "certificat" in json.loads(r.stdout)["erreur"]
    assert any(x.startswith("certbot certonly --webroot") and DOM in x for x in banc.appels())
    assert DOM not in banc.toml.read_text()   # pas de vhost public sans certificat


def test_synchroniser_depuis_le_plan(banc):
    plan = {"boxes": [{"box": "gk5", "pages": [{"paquet": "secubox-system", "version": "1.4.0"}]}]}
    (banc.r / "var/lib/secubox/pilotage/vhosts.json").write_text(json.dumps(plan))
    # un vhost d'une box qui n'est plus dans le plan est retiré
    (banc.r / "data/haproxy/certs/*.gk6.secubox.in.pem").write_text("joker")
    assert banc.ctl("poser", "gk6", entree=PAGES).returncode == 0
    r = banc.ctl("synchroniser")
    assert r.returncode == 0, r.stdout + r.stderr
    assert banc.conf().exists() and not banc.conf("gk6").exists()
    appels = banc.appels()
    assert "secubox-pilotage-www extraire --acteur pilotage secubox-system 1.4.0" in appels
    assert "secubox-pilotage-www purger --acteur pilotage" in appels
    assert json.loads((banc.r / "www-stdin.log").read_text()) == {"en_usage": [{"paquet": "secubox-system", "version": "1.4.0"}]}


def test_plan_lien_ou_invalide_refuse(banc, tmp_path):
    f = banc.r / "var/lib/secubox/pilotage/vhosts.json"
    ailleurs = tmp_path / "ailleurs.json"
    ailleurs.write_text(json.dumps({"boxes": []}))
    f.symlink_to(ailleurs)
    assert banc.ctl("synchroniser").returncode == 1
    f.unlink()
    for plan in ({"boxes": [{"box": "../x", "pages": []}]}, {"boxes": "x"}, {"boxes": [{"box": f"b{i}", "pages": []} for i in range(65)]}):
        f.write_text(json.dumps(plan))
        assert banc.ctl("synchroniser").returncode == 2, plan
    assert banc.appels() == []


def test_sbx_racine_refusee_si_appelant_eleve(banc):
    r = banc.ctl("lister", env={"SUDO_UID": str(os.getuid() + 1)})
    assert r.returncode == 2 and "SBX_RACINE ignorée" in r.stderr


def test_unites_et_paquet():
    rules = (PKG / "debian/rules").read_text()
    assert "sbin/secubox-pilotage-vhost" in rules and "secubox-pilotage-vhost.path" in rules
    u = (PKG / "systemd/secubox-pilotage-vhost.service").read_text()
    assert "ExecStart=/usr/sbin/secubox-pilotage-vhost synchroniser" in u and "Type=oneshot" in u
    p = (PKG / "systemd/secubox-pilotage-vhost.path").read_text()
    assert "PathChanged=/var/lib/secubox/pilotage/vhosts.json" in p
    assert "/run/secubox/auth.sock rw," in (PKG / "apparmor/secubox-pilotage-api").read_text()
