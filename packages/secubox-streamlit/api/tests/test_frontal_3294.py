# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3294 — frontaux web permanents hébergés dans le conteneur Streamlit (couture.gk2).

Après le redémarrage de gk2, `streamlitctl boot` ne démarrait le conteneur que pour une appli Streamlit publiée :
le frontal FastAPI d'Atelier Partagé (couture) restait injoignable (502 nginx brute, vhost posé à la main).
"""
import json
import stat
from pathlib import Path

from . import test_ctl_publication_3247 as _base

box = _base.box  # fixture réutilisée (#3247)

COUTURE = ["couture", "--domaine", "couture.gk2.secubox.in", "--cible", "10.100.0.50:8601",
           "--unite", "atelier-partage-web.service", "--sante", "/healthz"]


def _exe(chemin, texte):
    chemin.write_text(texte)
    chemin.chmod(chemin.stat().st_mode | stat.S_IEXEC)


def _attach_unites(box):
    """lxc-attach : `systemctl is-active` répond « inactif » tant que l'unité n'a pas été démarrée."""
    bin_ = box.env["PATH"].split(":")[0]
    actif = box.journal.parent / "unite.active"
    _exe(Path(bin_) / "lxc-attach", f"""#!/bin/bash
[ -f "{box.eveil}" ] || exit 1
shift 2; shift
echo "attach $*" >> "{box.journal}"
if [ "$1" = systemctl ] && [ "$2" = is-system-running ]; then echo running; exit 0; fi
if [ "$1" = systemctl ] && [ "$2" = is-active ]; then [ -f "{actif}" ] && exit 0; exit 3; fi
if [ "$1" = systemctl ] && [ "$2" = start ]; then touch "{actif}"; exit 0; fi
exit 0
""")


def _sortie(r):
    return json.loads(r.stdout.strip().splitlines()[-1])


# ─── boot ────────────────────────────────────────────────────────────────

def test_boot_avec_frontal_demarre_conteneur_puis_unite(box):
    _attach_unites(box)
    box.conf.write_text(box.conf.read_text() + '\n[frontaux.couture]\ndomain = "couture.gk2.secubox.in"\n'
                        'cible = "10.100.0.50:8601"\nunite = "atelier-partage-web.service"\nsante = "/healthz"\n'
                        "enabled = true\n")
    r = box.ctl("boot")
    assert r.returncode == 0, r.stderr
    j = box.journal.read_text()
    assert "lxc-start" in j
    assert "attach systemctl start atelier-partage-web.service" in j


def test_boot_unite_deja_active_n_est_pas_redemarree(box):
    _attach_unites(box)
    (box.journal.parent / "unite.active").touch()
    box.conf.write_text(box.conf.read_text() + '\n[frontaux.couture]\ndomain = "couture.gk2.secubox.in"\n'
                        'cible = "10.100.0.50:8601"\nunite = "atelier-partage-web.service"\nenabled = true\n')
    r = box.ctl("boot")
    assert r.returncode == 0, r.stderr
    assert "systemctl start" not in box.journal.read_text()


def test_boot_sans_frontal_ni_autostart_ne_fait_rien(box):
    _attach_unites(box)
    box.conf.write_text(box.conf.read_text() + '\n[frontaux.couture]\ndomain = "couture.gk2.secubox.in"\n'
                        'cible = "10.100.0.50:8601"\nunite = "atelier-partage-web.service"\nenabled = false\n')
    r = box.ctl("boot")
    assert r.returncode == 0, r.stderr
    assert not box.journal.exists() or "lxc-start" not in box.journal.read_text()


def test_boot_ignore_une_unite_malformee_du_toml(box):
    _attach_unites(box)
    box.conf.write_text(box.conf.read_text() + '\n[frontaux.x]\ndomain = "x.gk2.secubox.in"\n'
                        'cible = "10.100.0.50:8601"\nunite = "--now; reboot"\nenabled = true\n')
    r = box.ctl("boot")
    assert r.returncode == 0, r.stderr
    assert "reboot" not in (box.journal.read_text() if box.journal.exists() else "")


# ─── frontal set : vhost généré ──────────────────────────────────────────

def test_set_genere_le_vhost_avec_pages_d_erreur_et_declare(box):
    r = box.ctl("frontal", "set", *COUTURE, "--par", "gk2", "--apply")
    assert r.returncode == 0, r.stderr + r.stdout
    dispo = box.nginx / "sites-available" / "streamlit-frontal-couture.conf"
    actif = box.nginx / "sites-enabled" / "streamlit-frontal-couture.conf"
    v = dispo.read_text()
    assert actif.is_symlink()
    assert "include snippets/secubox-errorpages.conf;" in v
    assert "proxy_pass http://10.100.0.50:8601;" in v
    assert "server_name couture.gk2.secubox.in;" in v and "listen 9080;" in v
    assert "client_max_body_size 1m;" in v
    for h in ("X-Real-IP $remote_addr", "X-Forwarded-For $proxy_add_x_forwarded_for",
              "X-Forwarded-Proto https", "X-Forwarded-Host $host"):
        assert h in v
    conf = box.conf.read_text()
    assert "[frontaux.couture]" in conf and 'unite = "atelier-partage-web.service"' in conf
    audit = [json.loads(x) for x in box.audit.read_text().splitlines()]
    assert audit[-1]["evenement"] == "frontal-pose" and audit[-1]["par"] == "gk2"
    # Le chemin HAProxy → sbxwaf n'est pas touché.
    assert json.loads(box.routes.read_text()) == {"admin.gk2.secubox.in": ["192.168.1.200", 9080]}
    assert "haproxyctl" not in box.journal.read_text()
    assert "nginx -t" in box.journal.read_text()


def test_set_sans_apply_n_ecrit_rien(box):
    r = box.ctl("frontal", "set", *COUTURE)
    assert r.returncode == 0, r.stderr
    assert _sortie(r)["applique"] is False
    assert not (box.nginx / "sites-available" / "streamlit-frontal-couture.conf").exists()
    assert "frontaux" not in box.conf.read_text()


def test_list_rend_les_frontaux(box):
    box.ctl("frontal", "set", *COUTURE, "--apply")
    r = box.ctl("frontal", "list")
    assert r.returncode == 0, r.stderr
    f = _sortie(r)["frontaux"]
    assert f == [{"nom": "couture", "domaine": "couture.gk2.secubox.in", "cible": "10.100.0.50:8601",
                  "unite": "atelier-partage-web.service", "sante": "/healthz", "enabled": True,
                  "vhost": "conforme"}]


def test_remove_retire_vhost_et_declaration(box):
    box.ctl("frontal", "set", *COUTURE, "--apply")
    r = box.ctl("frontal", "remove", "couture", "--apply")
    assert r.returncode == 0, r.stderr
    assert not (box.nginx / "sites-enabled" / "streamlit-frontal-couture.conf").exists()
    assert not (box.nginx / "sites-available" / "streamlit-frontal-couture.conf").exists()
    assert "frontaux.couture" not in box.conf.read_text()
    assert json.loads(box.audit.read_text().splitlines()[-1])["evenement"] == "frontal-retire"


# ─── validation ──────────────────────────────────────────────────────────

def _remplace(opt, val):
    a = list(COUTURE)
    a[a.index(opt) + 1] = val
    return a


def test_validation_des_entrees(box):
    mauvais = [
        ["Couture"] + COUTURE[1:], ["a" * 41] + COUTURE[1:], ["../x"] + COUTURE[1:],
        _remplace("--domaine", "couture.exemple.org"), _remplace("--domaine", "gk2.secubox.in"),
        _remplace("--cible", "10.100.0.50:80"), _remplace("--cible", "10.100.0.50:70000"),
        _remplace("--cible", "192.168.1.9:8601"), _remplace("--cible", "127.0.0.1:8601"),
        _remplace("--unite", "atelier partage.service"), _remplace("--unite", "x.timer"),
        _remplace("--unite", "-x.service"), _remplace("--sante", "/../etc"), _remplace("--sante", "sante"),
    ]
    for args in mauvais:
        r = box.ctl("frontal", "set", *args, "--apply")
        assert r.returncode != 0, args
    assert not list((box.nginx / "sites-available").iterdir())
    assert "frontaux" not in box.conf.read_text()


def test_option_inconnue_refusee_par_le_ctl(box):
    r = box.ctl("frontal", "set", *COUTURE, "--conf", "/tmp/x")
    assert r.returncode == 64


# ─── reprise du vhost posé à la main ─────────────────────────────────────

MAIN = """server {
    listen 9080;
    server_name couture.gk2.secubox.in;
    location / { proxy_pass http://10.100.0.50:8601; }
}
"""


def _pose_main(box):
    dispo = box.nginx / "sites-available" / "atelier-couture.conf"
    dispo.write_text(MAIN)
    (box.nginx / "sites-enabled" / "atelier-couture.conf").symlink_to(dispo)


def test_vhost_a_la_main_sans_reprise_est_un_conflit(box):
    _pose_main(box)
    r = box.ctl("frontal", "set", *COUTURE, "--apply")
    assert r.returncode != 0
    assert "atelier-couture.conf" in r.stdout + r.stderr
    assert not (box.nginx / "sites-available" / "streamlit-frontal-couture.conf").exists()


def test_reprise_sauvegarde_puis_remplace(box):
    _pose_main(box)
    r = box.ctl("frontal", "set", *COUTURE, "--reprendre", "atelier-couture.conf", "--par", "gk2", "--apply")
    assert r.returncode == 0, r.stderr + r.stdout
    assert not (box.nginx / "sites-enabled" / "atelier-couture.conf").exists()
    assert not (box.nginx / "sites-available" / "atelier-couture.conf").exists()
    sauv = list((box.nginx / "sites-available").glob("atelier-couture.conf.avant-frontal-*"))
    assert len(sauv) == 1 and sauv[0].read_text() == MAIN
    assert (box.nginx / "sites-enabled" / "streamlit-frontal-couture.conf").is_symlink()
    # Un seul rechargement : le remplacement est atomique du point de vue de nginx.
    assert box.journal.read_text().count("systemctl reload nginx") == 1
    a = json.loads(box.audit.read_text().splitlines()[-1])
    assert a["repris"] == "atelier-couture.conf" and a["sauvegarde"].startswith("atelier-couture.conf.avant-frontal-")


def test_reprise_d_un_fichier_qui_ne_sert_pas_le_domaine_refusee(box):
    (box.nginx / "sites-available" / "autre.conf").write_text(MAIN.replace("couture", "autre"))
    (box.nginx / "sites-enabled" / "autre.conf").symlink_to(box.nginx / "sites-available" / "autre.conf")
    r = box.ctl("frontal", "set", *COUTURE, "--reprendre", "autre.conf", "--apply")
    assert r.returncode != 0
    assert (box.nginx / "sites-enabled" / "autre.conf").exists()


def test_nginx_t_en_echec_retour_arriere(box):
    _pose_main(box)
    bin_ = box.env["PATH"].split(":")[0]
    _exe(Path(bin_) / "nginx",
         f'#!/bin/bash\necho "nginx $*" >> "{box.journal}"\n'
         f'[ -e "{box.nginx}/sites-enabled/streamlit-frontal-couture.conf" ] && '
         '{ echo "nginx: [emerg] faux" >&2; exit 1; }\nexit 0\n')
    r = box.ctl("frontal", "set", *COUTURE, "--reprendre", "atelier-couture.conf", "--apply")
    assert r.returncode != 0
    assert (box.nginx / "sites-available" / "atelier-couture.conf").read_text() == MAIN
    assert (box.nginx / "sites-enabled" / "atelier-couture.conf").is_symlink()
    assert not (box.nginx / "sites-enabled" / "streamlit-frontal-couture.conf").exists()
    assert not (box.nginx / "sites-available" / "streamlit-frontal-couture.conf").exists()
    assert "frontaux" not in box.conf.read_text()


# ─── Relecture de sécurité (I1, I2, I3 et mineurs) ───────────────────────

def test_i1_seule_l_adresse_du_conteneur_est_une_cible(box):
    for ip in ("10.100.0.1", "10.100.0.51", "10.100.0.0", "10.100.0.255", "10.100.0.120"):
        r = box.ctl("frontal", "set", *_remplace("--cible", f"{ip}:8601"), "--apply")
        assert r.returncode != 0, ip
    assert "frontaux" not in box.conf.read_text()


def test_i2_domaine_reserve_refuse_meme_avec_reprise(box):
    adm = box.nginx / "sites-available" / "admin.conf"
    adm.write_text(MAIN.replace("couture", "admin"))
    (box.nginx / "sites-enabled" / "admin.conf").symlink_to(adm)
    r = box.ctl("frontal", "set", *_remplace("--domaine", "admin.gk2.secubox.in"), "--reprendre", "admin.conf",
                "--apply")
    assert r.returncode != 0
    assert adm.read_text() == MAIN.replace("couture", "admin")
    assert (box.nginx / "sites-enabled" / "admin.conf").is_symlink()
    assert not box.audit.exists() or "frontal-pose" not in box.audit.read_text()


def test_i2_domaine_route_ailleurs_refuse(box):
    box.routes.write_text(json.dumps({"couture.gk2.secubox.in": ["10.100.0.120", 9000]}))
    r = box.ctl("frontal", "set", *COUTURE, "--apply")
    assert r.returncode != 0 and "frontaux" not in box.conf.read_text()


def test_i2_domaine_haproxy_vers_autre_backend_refuse(box):
    (box.journal.parent / "haproxy.toml").write_text(
        '[vhosts.couture_gk2_secubox_in]\ndomain = "couture.gk2.secubox.in"\nbackend = "mail_backend"\n')
    r = box.ctl("frontal", "set", *COUTURE, "--apply")
    assert r.returncode != 0 and "frontaux" not in box.conf.read_text()


def test_i2_cas_couture_legitime_accepte(box):
    """couture.gk2 est déjà dans haproxy.toml (nginx_vhosts) et routé vers le nginx local :9080 : accepté."""
    box.routes.write_text(json.dumps({"couture.gk2.secubox.in": ["192.168.1.200", 9080]}))
    (box.journal.parent / "haproxy.toml").write_text(
        '[vhosts.couture_gk2_secubox_in]\ndomain = "couture.gk2.secubox.in"\nbackend = "nginx_vhosts"\n')
    _pose_main(box)
    r = box.ctl("frontal", "set", *COUTURE, "--reprendre", "atelier-couture.conf", "--apply")
    assert r.returncode == 0, r.stderr + r.stdout


def _attach_lent(box, pas_prets=3, unite_ok=True):
    bin_ = box.env["PATH"].split(":")[0]
    cpt = box.journal.parent / "essais"
    actif = box.journal.parent / "unite.active"
    _exe(Path(bin_) / "lxc-attach", f"""#!/bin/bash
[ -f "{box.eveil}" ] || exit 1
shift 2; shift
echo "attach $*" >> "{box.journal}"
if [ "$1" = systemctl ] && [ "$2" = is-system-running ]; then
  n=$(cat "{cpt}" 2>/dev/null || echo 0); echo $((n+1)) > "{cpt}"
  [ "$n" -ge {pas_prets} ] && {{ echo running; exit 0; }}
  exit 1
fi
if [ "$1" = systemctl ] && [ "$2" = is-active ]; then [ -f "{actif}" ] && exit 0; exit 3; fi
if [ "$1" = systemctl ] && [ "$2" = start ]; then {"touch " + chr(34) + str(actif) + chr(34) if unite_ok else "true"}; exit 0; fi
exit 0
""")


def _decl(box):
    box.conf.write_text(box.conf.read_text() + '\n[frontaux.couture]\ndomain = "couture.gk2.secubox.in"\n'
                        'cible = "10.100.0.50:8601"\nunite = "atelier-partage-web.service"\nenabled = true\n')


def test_i3_boot_attend_systemd_du_conteneur_puis_audite(box):
    box.env["SECUBOX_STREAMLIT_BOOT_PAUSE"] = "0"
    _attach_lent(box, pas_prets=3)
    _decl(box)
    r = box.ctl("boot")
    assert r.returncode == 0, r.stderr
    j = box.journal.read_text()
    assert j.count("is-system-running") >= 4
    assert j.index("is-system-running") < j.index("systemctl start atelier-partage-web.service")
    a = [json.loads(x) for x in box.audit.read_text().splitlines()]
    assert a[-1]["evenement"] == "frontal-boot" and a[-1]["resultat"] == "actif"


def test_i3_unite_qui_ne_demarre_pas_auditee_sans_bloquer(box):
    box.env["SECUBOX_STREAMLIT_BOOT_PAUSE"] = "0"
    _attach_lent(box, pas_prets=0, unite_ok=False)
    _decl(box)
    r = box.ctl("boot")
    assert r.returncode == 0, r.stderr
    a = [json.loads(x) for x in box.audit.read_text().splitlines()]
    assert a[-1]["evenement"] == "frontal-boot" and a[-1]["resultat"] == "echec"


def test_reprise_d_un_fichier_a_plusieurs_noms_refusee(box):
    dispo = box.nginx / "sites-available" / "atelier-couture.conf"
    dispo.write_text(MAIN.replace("server_name couture.gk2.secubox.in;",
                                  "server_name couture.gk2.secubox.in autre.gk2.secubox.in;"))
    (box.nginx / "sites-enabled" / "atelier-couture.conf").symlink_to(dispo)
    r = box.ctl("frontal", "set", *COUTURE, "--reprendre", "atelier-couture.conf", "--apply")
    assert r.returncode != 0 and dispo.exists()


def test_reprise_d_un_fichier_a_deux_blocs_server_refusee(box):
    dispo = box.nginx / "sites-available" / "atelier-couture.conf"
    dispo.write_text(MAIN + MAIN.replace("couture", "autre"))
    (box.nginx / "sites-enabled" / "atelier-couture.conf").symlink_to(dispo)
    r = box.ctl("frontal", "set", *COUTURE, "--reprendre", "atelier-couture.conf", "--apply")
    assert r.returncode != 0 and dispo.exists()


def test_chiffres_unicode_refuses_par_le_module():
    from api import publication as p
    assert p.erreur_frontal("couture", "couture.gk2.secubox.in", "10.100.0.50:٨٦٠١", "a.service", "",
                            "gk2.secubox.in", "10.100.0.50") is not None


def test_nginx_t_en_echec_est_audite(box):
    bin_ = box.env["PATH"].split(":")[0]
    _exe(Path(bin_) / "nginx", '#!/bin/bash\necho "nginx: [emerg] faux" >&2; exit 1\n')
    r = box.ctl("frontal", "set", *COUTURE, "--apply")
    assert r.returncode != 0
    a = json.loads(box.audit.read_text().splitlines()[-1])
    assert a["evenement"] == "frontal-pose" and a["resultat"] == "echec-nginx"


def test_garde_fou_bash(box):
    for extra in (["--reprendre", "../x.conf"], ["--lxc-config", "/tmp/x"], ["--domaine", "x.gk2.secubox.in"],
                  ["--par"]):
        r = box.ctl("frontal", "set", *COUTURE, *extra)
        assert r.returncode == 64, extra


# ─── Reprise d'une publication Streamlit existante (gk2 : [instances.couture]) ─────────────────

PUB = ('\n[apps.atelier-partage-1]\npath = "streamlit_app.py"\nenabled = true\nautostart = false\n'
       '\n[instances.couture]\napp = "atelier-partage-1"\nport = 8529\nenabled = true\nautostart = true\n'
       'emancipated = true\ndomain = "couture.gk2.secubox.in"\n')


def _gk2(box, backend="nginx_vhosts", route=("192.168.1.200", 9080)):
    box.conf.write_text(box.conf.read_text() + PUB)
    box.routes.write_text(json.dumps({"couture.gk2.secubox.in": list(route)}))
    (box.journal.parent / "haproxy.toml").write_text(
        f'[vhosts.couture_gk2_secubox_in]\ndomain = "couture.gk2.secubox.in"\nbackend = "{backend}"\n')
    _pose_main(box)
    return box.conf.read_text(), box.routes.read_text(), (box.journal.parent / "haproxy.toml").read_text()


REPRISE = ["--reprendre", "atelier-couture.conf", "--reprendre-publication", "atelier-partage-1"]


def test_publication_existante_sans_reprise_refusee(box):
    _gk2(box)
    r = box.ctl("frontal", "set", *COUTURE, "--reprendre", "atelier-couture.conf", "--apply")
    assert r.returncode == 4 and "reprendre-publication" in r.stdout + r.stderr


def test_reprise_de_publication_reussie(box):
    _avant, routes, ha = _gk2(box)
    r = box.ctl("frontal", "set", *COUTURE, *REPRISE, "--par", "gk2", "--apply")
    assert r.returncode == 0, r.stderr + r.stdout
    import tomllib
    c = tomllib.loads(box.conf.read_text())
    inst = c["instances"]["couture"]
    assert inst["enabled"] is False and inst["autostart"] is False and "domain" not in inst
    assert c["apps"]["atelier-partage-1"]["path"] == "streamlit_app.py"          # appli gardée
    assert c["frontaux"]["couture"]["unite"] == "atelier-partage-web.service"
    assert box.routes.read_text() == routes and (box.journal.parent / "haproxy.toml").read_text() == ha
    assert (box.nginx / "sites-enabled" / "streamlit-frontal-couture.conf").is_symlink()
    assert not (box.nginx / "sites-enabled" / "atelier-couture.conf").exists()
    a = json.loads(box.audit.read_text().splitlines()[-1])
    assert a["publication_reprise"] == "atelier-partage-1" and a["instances_reprises"] == ["couture"]


def test_reprise_de_publication_nginx_t_en_echec_tout_intact(box):
    avant, _r, _h = _gk2(box)
    bin_ = box.env["PATH"].split(":")[0]
    _exe(Path(bin_) / "nginx",
         f'#!/bin/bash\n[ -e "{box.nginx}/sites-enabled/streamlit-frontal-couture.conf" ] && '
         '{ echo "nginx: [emerg] faux" >&2; exit 1; }\nexit 0\n')
    r = box.ctl("frontal", "set", *COUTURE, *REPRISE, "--apply")
    assert r.returncode != 0
    assert box.conf.read_text() == avant
    assert (box.nginx / "sites-available" / "atelier-couture.conf").read_text() == MAIN
    assert (box.nginx / "sites-enabled" / "atelier-couture.conf").is_symlink()
    assert not (box.nginx / "sites-available" / "streamlit-frontal-couture.conf").exists()


def test_reprise_de_publication_domaine_different_refusee(box):
    avant, _r, _h = _gk2(box)
    r = box.ctl("frontal", "set", *_remplace("--domaine", "atelier.gk2.secubox.in"),
                "--reprendre-publication", "atelier-partage-1", "--apply")
    assert r.returncode != 0
    assert box.conf.read_text() == avant


def test_reprise_de_publication_haproxy_ou_route_ailleurs_refusee(box):
    for kw in ({"backend": "autre"}, {"route": ("10.100.0.50", 8529)}):
        b = box
        b.conf.write_text("[main]\nenabled = true\n")
        for f in (b.nginx / "sites-enabled").iterdir():
            f.unlink()
        for f in (b.nginx / "sites-available").iterdir():
            f.unlink()
        avant, _r, _h = _gk2(b, **kw)
        r = b.ctl("frontal", "set", *COUTURE, *REPRISE, "--apply")
        assert r.returncode != 0, kw
        assert b.conf.read_text() == avant


def test_reprise_de_publication_exige_route_et_haproxy_presents(box):
    avant, _r, _h = _gk2(box)
    box.routes.write_text("{}")
    r = box.ctl("frontal", "set", *COUTURE, *REPRISE, "--apply")
    assert r.returncode != 0 and box.conf.read_text() == avant


def test_reprise_de_publication_d_une_autre_appli_refusee(box):
    avant, _r, _h = _gk2(box)
    r = box.ctl("frontal", "set", *COUTURE, "--reprendre", "atelier-couture.conf",
                "--reprendre-publication", "autre-appli", "--apply")
    assert r.returncode != 0 and box.conf.read_text() == avant
