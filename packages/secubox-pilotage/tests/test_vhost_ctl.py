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
import time
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
  vhost) [ "$2" = list ] && exec bash {HAPROXYCTL} vhost list 2>/dev/null; bash {HAPROXYCTL} "$@" >/dev/null 2>&1; exit 0 ;;
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
    assert a["evenement"] == "pilotage_vhost_poser" and a["resultat"] == "echec"


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
    aa = (PKG / "apparmor/secubox-pilotage-api").read_text()
    assert "auth.sock" not in aa                                    # plus de saisie d'identifiants relayée (C1c)
    assert "/var/lib/secubox-pilotage-pages/www/*/*/ r," in aa      # I6 : modules d'un paquet servi, lecture seule
    assert "www-vhost/pilotage-connexion" in rules
    # I4 : relances bornées
    assert "StartLimitIntervalSec=" in u and "StartLimitBurst=" in u
    # R-L5-26 I2 : pas de TriggerLimit (il mettrait le .path en échec définitif) ; l'espacement est dans le ctl
    assert "TriggerLimit" not in p
    # M10 : durcissement du ctl root
    assert "ProtectSystem=strict" in u and "PrivateTmp=yes" in u and "NoNewPrivileges=yes" in u
    rw = " ".join(li.split("=", 1)[1] for li in u.splitlines() if li.startswith("ReadWritePaths="))
    for d in ("/etc/nginx/conf.d", "/var/lib/secubox-pilotage-pages", "/var/log/secubox", "/etc/secubox"):
        assert d in rw.split(), d
    assert "/etc " not in rw + " " and "/var/lib " not in rw + " " and "/usr/share/secubox/www " not in rw + " "


# --- R-L5-25 : noms réservés et marque de propriété (C2), codes retour (I5), certbot amorti et passes espacées (I4) ----------

def registre(banc):
    p = banc.r / "var/lib/secubox-pilotage-pages/registre.json"
    return json.loads(p.read_text()) if p.exists() else None


def ajouter_vhost_etranger(banc, dom, nom="etranger"):
    banc.toml.write_text(banc.toml.read_text() + f'\n[vhosts.{nom}]\ndomain = "{dom}"\nbackend = "nginx_vhosts"\nenabled = true\nssl = true\n')
    t = json.loads(banc.routes.read_text())
    t[dom] = ["192.168.1.200", 9080]
    banc.routes.write_text(json.dumps(t))


def test_box_nommee_comme_un_vhost_existant_refusee(banc):
    ajouter_vhost_etranger(banc, DOM)
    toml, routes = banc.toml.read_text(), banc.routes.read_text()
    r = banc.ctl("poser", "gk5", entree=PAGES)
    assert r.returncode == 1 and "déjà" in json.loads(r.stdout)["erreur"]
    assert banc.toml.read_text() == toml and banc.routes.read_text() == routes and not banc.conf().exists()
    assert not any(x.startswith(("haproxyctl vhost add", "secubox-waf-route", "certbot")) for x in banc.appels())


def test_vhost_nginx_existant_non_pilotage_refuse(banc):
    (banc.r / "etc/nginx/conf.d/autre.conf").write_text(f"server {{ listen 9080; server_name {DOM}; }}\n")
    r = banc.ctl("poser", "gk5", entree=PAGES)
    assert r.returncode == 1 and not banc.conf().exists()


@pytest.mark.parametrize("box", ["www", "api", "admin", "apt", "gk2", "system"])
def test_noms_reserves(banc, box):
    (banc.r / "usr/share/secubox/www/system").mkdir(parents=True)           # module du maître
    r = banc.ctl("poser", box, entree=PAGES, env={"SBX_NOM_MAITRE": "gk2"})
    assert r.returncode == 1 and "réservé" in json.loads(r.stdout)["erreur"]
    assert banc.appels() == []


def test_retrait_ne_touche_jamais_un_vhost_non_marque(banc):
    ajouter_vhost_etranger(banc, DOM)
    toml, routes = banc.toml.read_text(), banc.routes.read_text()
    r = banc.ctl("retirer", "gk5")
    assert r.returncode == 1 and "pilotage" in json.loads(r.stdout)["erreur"]
    assert banc.toml.read_text() == toml and banc.routes.read_text() == routes
    assert not any(x.startswith(("haproxyctl vhost remove", "haproxyctl generate")) for x in banc.appels())


def test_marque_posee_puis_retiree(banc):
    assert banc.ctl("poser", "gk5", entree=PAGES).returncode == 0
    assert DOM in registre(banc)["domaines"]
    assert stat.S_IMODE((banc.r / "var/lib/secubox-pilotage-pages/registre.json").stat().st_mode) == 0o644
    assert banc.ctl("retirer", "gk5").returncode == 0
    assert DOM not in registre(banc)["domaines"]


def test_nom_du_vhost_lu_depuis_haproxyctl(banc):
    assert banc.ctl("poser", "gk5", entree=PAGES).returncode == 0
    # haproxyctl a nommé la table autrement que la convention supposée : le retrait doit suivre l'outil
    banc.toml.write_text(banc.toml.read_text().replace("[vhosts.admin_gk5_secubox_in]", "[vhosts.autre_nom]"))
    assert banc.ctl("retirer", "gk5").returncode == 0
    assert "haproxyctl vhost remove autre_nom" in banc.appels()
    assert DOM not in banc.toml.read_text()


def test_echec_de_vhost_remove_audite_echec(banc):
    assert banc.ctl("poser", "gk5", entree=PAGES).returncode == 0
    script(banc.bin / "haproxyctl", f'echo "haproxyctl $*" >> {banc.journal}\n'
           f'case "$1 $2" in "vhost list") exec env SECUBOX_HAPROXY_CONF={banc.toml} bash {HAPROXYCTL} vhost list ;; esac\nexit 1\n')
    r = banc.ctl("retirer", "gk5")
    assert r.returncode == 1
    assert banc.audit()[-1]["resultat"] == "echec"
    assert DOM in registre(banc)["domaines"]   # toujours marqué : un prochain retrait reprendra


def test_cert_sync_en_echec_refuse(banc):
    (banc.r / "data/haproxy/certs/*.gk5.secubox.in.pem").unlink()
    script(banc.bin / "certbot", f'echo "certbot $*" >> {banc.journal}\nexit 0\n')
    r = banc.ctl("poser", "gk5", entree=PAGES)     # certbot « réussit » mais cert sync ne pose rien (faux haproxyctl hors root)
    assert r.returncode == 1 and "certificat" in json.loads(r.stdout)["erreur"]
    assert banc.audit()[-1]["resultat"] == "echec"


def test_echec_certbot_mis_en_cache(banc):
    (banc.r / "data/haproxy/certs/*.gk5.secubox.in.pem").unlink()
    assert banc.ctl("poser", "gk5", entree=PAGES).returncode == 1
    assert banc.ctl("poser", "gk5", entree=PAGES).returncode == 1
    assert sum(x.startswith("certbot") for x in banc.appels()) == 1       # pas de nouvel essai avant le délai
    banc.ctl("poser", "gk5", entree=PAGES, env={"SBX_MAINTENANT": str(time.time() + 7 * 3600)})
    assert sum(x.startswith("certbot") for x in banc.appels()) == 2


def test_passes_espacees(banc):
    (banc.r / "var/lib/secubox/pilotage/vhosts.json").write_text(json.dumps({"boxes": []}))
    t = time.time()
    assert banc.ctl("synchroniser", env={"SBX_MAINTENANT": str(t)}).returncode == 0
    r = banc.ctl("synchroniser", env={"SBX_MAINTENANT": str(t + 5)})
    assert r.returncode == 0 and json.loads(r.stdout).get("attente_s", 0) >= 50


# --- R-L5-26 ----------------------------------------------------------------------------------------------------------

REG = "var/lib/secubox-pilotage-pages/registre.json"


def test_registre_absent_avec_vhosts_poses_incoherent(banc):
    assert banc.ctl("poser", "gk5", entree=PAGES).returncode == 0
    (banc.r / REG).unlink()
    r = banc.ctl("retirer", "gk5")
    assert r.returncode == 1 and "incohérent" in json.loads(r.stdout)["erreur"]
    assert banc.conf().exists()
    r = banc.ctl("poser", "gk6", entree=PAGES)
    assert r.returncode == 1 and "incohérent" in json.loads(r.stdout)["erreur"]


@pytest.mark.parametrize("cas", ["droits", "proprietaire", "lien"])
def test_registre_etranger_refuse(banc, tmp_path, cas):
    assert banc.ctl("poser", "gk5", entree=PAGES).returncode == 0
    f = banc.r / REG
    env = {}
    if cas == "droits":
        os.chmod(f, 0o666)
    elif cas == "proprietaire":
        env = {"SBX_UID_ATTENDU": str(os.getuid() + 1)}
    else:
        ailleurs = tmp_path / "faux.json"
        ailleurs.write_text(f.read_text())
        f.unlink()
        f.symlink_to(ailleurs)
    r = banc.ctl("retirer", "gk5", env=env)
    assert r.returncode == 1 and "registre" in json.loads(r.stdout)["erreur"]
    assert banc.conf().exists()


def test_dossier_du_registre_inscriptible_refuse(banc):
    os.chmod(banc.r / "var/lib/secubox-pilotage-pages", 0o777)
    r = banc.ctl("poser", "gk5", entree=PAGES)
    assert r.returncode == 1


def test_migration_de_l_ancien_registre(banc):
    ancien = banc.r / "etc/secubox/pilotage-vhosts.json"
    ancien.write_text(json.dumps({"domaines": {DOM: {"box": "gk5"}}, "certbot_echecs": {}, "derniere_passe": 0}))
    os.chmod(ancien, 0o644)
    assert banc.ctl("lister").returncode == 0
    assert not ancien.exists() and DOM in registre(banc)["domaines"]


def test_ancien_registre_inscriptible_non_migre(banc):
    ancien = banc.r / "etc/secubox/pilotage-vhosts.json"
    ancien.write_text(json.dumps({"domaines": {DOM: {"box": "gk5"}}}))
    os.chmod(ancien, 0o666)
    banc.ctl("lister")
    assert registre(banc) is None or DOM not in registre(banc)["domaines"]


def test_haproxy_en_mode_lxc_refuse(banc):
    banc.toml.write_text(banc.toml.read_text().replace('mode = "native"', 'mode = "lxc"'))
    r = banc.ctl("poser", "gk5", entree=PAGES)
    assert r.returncode == 1 and "lxc" in json.loads(r.stdout)["erreur"]
    assert not any(x.startswith(("haproxyctl vhost add", "secubox-waf-route")) for x in banc.appels())


@pytest.mark.parametrize("server_name", ["*.gk5.secubox.in", ".gk5.secubox.in", "admin.gk5.*", "~^admin\\.gk5\\.", "x.y admin.gk5.secubox.in"])
def test_server_name_joker_ou_regex_etranger(banc, server_name):
    (banc.r / "etc/nginx/conf.d/autre.conf").write_text(f"server {{ listen 9080; server_name {server_name}; }}\n")
    r = banc.ctl("poser", "gk5", entree=PAGES)
    assert r.returncode == 1 and not banc.conf().exists(), server_name


def test_nom_public_du_maitre_lu_dans_la_configuration(banc):
    (banc.r / "etc/secubox/secubox.conf").write_text('[global]\ndomain = "gk5.secubox.in"\n')
    r = banc.ctl("poser", "gk5", entree=PAGES, env={"SBX_NOM_MAITRE": "autrehote"})
    assert r.returncode == 1 and "réservé" in json.loads(r.stdout)["erreur"]


def test_certificat_exact_etranger_refuse(banc):
    (banc.r / f"data/haproxy/certs/{DOM}.pem").write_text("cert d'un autre service")
    r = banc.ctl("poser", "gk5", entree=PAGES)
    assert r.returncode == 1 and "déjà" in json.loads(r.stdout)["erreur"]


def test_verrou_libre_pendant_l_espacement(banc):
    """M7 : synchroniser n'attend pas ses 60 s en tenant le verrou (un retrait manuel passe)."""
    (banc.r / "var/lib/secubox/pilotage/vhosts.json").write_text(json.dumps({"boxes": []}))
    t = time.time()
    assert banc.ctl("synchroniser", env={"SBX_MAINTENANT": str(t)}).returncode == 0
    p = subprocess.Popen([str(CTL), "synchroniser"], env={"PATH": os.environ["PATH"], "SBX_RACINE": str(banc.r),
                         "SBX_BIN": str(banc.bin), "SBX_LIB": str(PKG), "SBX_MAINTENANT": str(t + 1), "SBX_ATTENDRE": "1"},
                         stdout=subprocess.PIPE, text=True)
    time.sleep(0.5)
    debut = time.time()
    r = banc.ctl("lister")
    assert r.returncode == 0 and time.time() - debut < 2
    p.kill()
    p.wait()


# --- R-L5-27 : basculement locale (relais-maillage) ⇄ distante (pilotage) ----------------------------------------------

EXCL = "var/lib/secubox-pilotage-pages/exclusions-relais.json"
IP_PAIR = "10.10.0.5"


def relais_factice(banc):
    """secubox-relais-maillage factice : relayer/retirer par les VRAIS haproxyctl (wrapper du banc) et la table des routes."""
    script(banc.bin / "secubox-relais-maillage", f'''echo "secubox-relais-maillage $*" >> {banc.journal}
[ -e {banc.r}/ECHEC_RELAIS_$1 ] && exit 1
case "$1" in
  retirer)
    nom=$({banc.bin}/haproxyctl vhost list | python3 -c 'import json,sys; print(" ".join(v["name"] for v in json.load(sys.stdin)["vhosts"] if v["domain"]==sys.argv[1]))' "$2")
    [ -n "$nom" ] && {banc.bin}/haproxyctl vhost remove "$nom" >/dev/null
    python3 -c 'import json,sys; p=sys.argv[1]; d=json.load(open(p)); d.pop(sys.argv[2],None); json.dump(d,open(p,"w"))' {banc.routes} "$2" ;;
  relayer)
    {banc.bin}/haproxyctl vhost add "$2" sbxwaf_inspector true >/dev/null
    python3 -c 'import json,sys; p=sys.argv[1]; d=json.load(open(p)); d[sys.argv[2]]=[sys.argv[3],int(sys.argv[4])]; json.dump(d,open(p,"w"))' {banc.routes} "$2" "$3" "$4" ;;
esac
''')


def relayer_par_le_maillage(banc, dom=DOM, ip=IP_PAIR):
    banc.toml.write_text(banc.toml.read_text() + f'\n[vhosts.{dom.replace(".", "_").replace("-", "_")}]\ndomain = "{dom}"\n'
                         'backend = "sbxwaf_inspector"\nenabled = true\nssl = true\n')
    t = json.loads(banc.routes.read_text())
    t[dom] = [ip, 9080]
    t["hall.gk5.secubox.in"] = [ip, 9080]          # autre nom de la box : jamais touché
    banc.routes.write_text(json.dumps(t))


def exclusions(banc):
    p = banc.r / EXCL
    return json.loads(p.read_text())["noms"] if p.exists() else []


@pytest.fixture
def relais(banc):
    relais_factice(banc)
    relayer_par_le_maillage(banc)
    return banc


def test_basculement_locale_vers_distante_puis_retour(relais):
    banc = relais
    r = banc.ctl("poser", "--acteur", "alice", "gk5", entree=PAGES)
    assert r.returncode == 0, r.stdout + r.stderr
    routes = json.loads(banc.routes.read_text())
    assert routes[DOM] == ["192.168.1.200", 9080]                 # le nom vise désormais le nginx du maître
    assert routes["hall.gk5.secubox.in"] == [IP_PAIR, 9080]       # les autres noms de la box intacts
    assert banc.toml.read_text().count(f'domain = "{DOM}"') == 1  # jamais deux vhosts pour un nom
    assert exclusions(banc) == [DOM]
    assert f"secubox-relais-maillage retirer {DOM}" in banc.appels()
    reg = registre(banc)["domaines"][DOM]
    assert reg["repris_de"] == "relais-maillage" and reg["route_avant"] == [IP_PAIR, 9080]
    a = [x for x in banc.audit() if x["evenement"] == "pilotage_vhost_basculer"]
    assert a[-1]["sens"] == "distante" and a[-1]["resultat"] == "ok" and a[-1]["acteur"] == "alice"
    # retour : le pilotage rend le nom à relais-maillage
    r = banc.ctl("retirer", "--acteur", "alice", "gk5")
    assert r.returncode == 0, r.stdout + r.stderr
    routes = json.loads(banc.routes.read_text())
    assert routes[DOM] == [IP_PAIR, 9080] and routes["hall.gk5.secubox.in"] == [IP_PAIR, 9080]
    assert exclusions(banc) == [] and not banc.conf().exists()
    assert banc.toml.read_text().count(f'domain = "{DOM}"') == 1
    assert DOM not in registre(banc)["domaines"]
    a = [x for x in banc.audit() if x["evenement"] == "pilotage_vhost_basculer"]
    assert a[-1]["sens"] == "locale" and a[-1]["resultat"] == "ok"


@pytest.mark.parametrize("panne", ["relais_retirer", "nginx", "haproxy_add"])
def test_echec_au_milieu_etat_locale_intact(relais, panne):
    banc = relais
    routes_avant = json.loads(banc.routes.read_text())
    if panne == "relais_retirer":
        (banc.r / "ECHEC_RELAIS_retirer").touch()
    elif panne == "nginx":
        (banc.r / "ECHEC_T").touch()
    else:
        (banc.r / "data/haproxy/certs/*.gk5.secubox.in.pem").unlink()   # certificat impossible après la reprise
    r = banc.ctl("poser", "gk5", entree=PAGES)
    assert r.returncode == 1
    assert json.loads(banc.routes.read_text()) == routes_avant
    assert banc.toml.read_text().count(f'domain = "{DOM}"') == 1
    assert exclusions(banc) == [] and not banc.conf().exists()
    reg = registre(banc)
    assert reg is None or DOM not in reg["domaines"]
    a = [x for x in banc.audit() if x["evenement"] == "pilotage_vhost_basculer"]
    assert any(x["sens"] == "distante" and x["resultat"] == "echec" for x in a)
    if panne != "relais_retirer":   # le relais avait été retiré : son retour est audité
        assert a[-1]["sens"] == "locale" and a[-1]["resultat"] == "ok"


def test_domaine_porte_par_un_tiers_refuse_meme_vers_un_pair(banc):
    relais_factice(banc)
    ajouter_vhost_etranger(banc, DOM)    # vhost manuel vers nginx_vhosts : ni relais-maillage ni pilotage
    r = banc.ctl("poser", "gk5", entree=PAGES)
    assert r.returncode == 1 and "déjà" in json.loads(r.stdout)["erreur"]
    assert not any(x.startswith("secubox-relais-maillage") for x in banc.appels())


def test_route_vers_un_pair_mais_server_nginx_etranger_refuse(relais):
    banc = relais
    (banc.r / "etc/nginx/conf.d/autre.conf").write_text(f"server {{ listen 9080; server_name {DOM}; }}\n")
    assert banc.ctl("poser", "gk5", entree=PAGES).returncode == 1
    assert not any(x.startswith("secubox-relais-maillage") for x in banc.appels())


def test_exclusions_fichier_root(relais):
    banc = relais
    assert banc.ctl("poser", "gk5", entree=PAGES).returncode == 0
    st = (banc.r / EXCL).stat()
    assert stat.S_IMODE(st.st_mode) == 0o644 and st.st_uid == os.getuid()
