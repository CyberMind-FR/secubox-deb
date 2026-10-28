# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3247, relecture de sécurité de la PR #3249 — ce que root lit et écrit dans les dossiers d'applis.

/srv/streamlit/apps appartient à secubox et est monté EN ÉCRITURE dans le conteneur, où toutes les applis tournent
en root : n'importe quelle appli peut y poser un lien ou une FIFO. Root (streamlitctl → api/publication.py) ne doit
donc jamais suivre un lien sous ce dossier, ni s'y bloquer, ni hériter mode ou propriétaire d'un lien ; l'archive
d'une appli est extraite par root SANS rien laisser sortir de son dossier ; le verrou vit dans un dossier root 0700 ;
l'adresse visée par nginx reste dans le sous-réseau du pont du conteneur.
"""
import json
import os
import stat
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

from api import publication as P
from api.tests import test_publication_3247 as banc

# Banc partagé avec test_publication_3247 (fichiers temporaires, nginx/haproxyctl/lxc-attach simulés).
box = banc.box
lignes_audit, run, section = banc.lignes_audit, banc.run, banc.section

PUB = Path(P.__file__)


def cli(box, *args, entree=None, timeout=20):
    """Le module dans un processus SÉPARÉ, comme le ctl l'appelle : un blocage (FIFO) devient un échec borné."""
    r = subprocess.run([sys.executable, "-I", str(PUB), "--conf", str(box.conf), "--apps", str(box.apps), *args],
                       env=dict(os.environ), input=entree, capture_output=True, text=True, timeout=timeout)
    sortie = r.stdout.strip().splitlines()
    return r.returncode, (json.loads(sortie[-1]) if sortie else {}), r.stderr


def secret(box):
    s = box.tmp / "shadow"
    s.write_text("root:$6$sel$empreinte:19000:0:99999:7:::\n")
    s.chmod(0o600)
    return s


# ─── Fichier de port : jamais un lien, jamais une FIFO ─────────────────────

def test_fichier_de_port_lien_vers_un_fichier_root_refuse(box):
    s = secret(box)
    box.appli("piege")
    lien = box.apps / "piege" / ".streamlit.toml"
    lien.symlink_to(s)
    for args in (("port", "piege", "--demande", "8555", "--apply"), ("port", "piege")):
        rc, r, _ = cli(box, *args)
        assert rc == 3, r
        assert "lien" in r["error"]
    assert lien.is_symlink() and s.read_text().startswith("root:") and stat.S_IMODE(s.stat().st_mode) == 0o600


def test_dossier_d_appli_lien_refuse(box):
    ailleurs = box.tmp / "ailleurs"
    ailleurs.mkdir()
    (ailleurs / "app.py").write_text("import streamlit\n")
    (box.apps / "piege").symlink_to(ailleurs)
    rc, r, _ = cli(box, "port", "piege", "--apply")
    assert rc == 3 and "lien" in r["error"], r
    assert sorted(p.name for p in ailleurs.iterdir()) == ["app.py"]


def test_fifo_comme_fichier_de_port_ne_bloque_jamais(box):
    box.appli("piege")
    os.mkfifo(box.apps / "piege" / ".streamlit.toml")
    rc, r, _ = cli(box, "port", "piege", "--apply", timeout=15)
    assert rc == 3, r


def test_fifo_d_une_autre_appli_ignoree_sans_bloquer(box):
    box.appli("autre")
    os.mkfifo(box.apps / "autre" / ".streamlit.toml")
    (box.apps / "lien.py").symlink_to(box.tmp / "nulle-part.py")
    box.appli("nouvelle")
    rc, r, _ = cli(box, "port", "nouvelle", timeout=15)
    assert rc == 0 and r["port"] == 8501, r


def test_ecrire_port_mode_fixe_0644_jamais_herite(box):
    box.appli("a", port=8529)
    f = box.apps / "a" / ".streamlit.toml"
    f.chmod(0o777)
    rc, r, _ = cli(box, "ecrire-port", "a", "--port", "8530", "--entrypoint", "a/app.py", "--sauvegarde",
                   "20261028", "--apply")
    assert rc == 0, r
    assert stat.S_IMODE(f.stat().st_mode) == 0o644
    texte = f.read_text()
    assert "port = 8530" in texte and 'entrypoint = "a/app.py"' in texte and "8529" not in texte
    assert "port = 8529" in (box.apps / "a" / ".streamlit.toml.bak.20261028").read_text()
    (box.apps / "b.py").write_text("import streamlit\n")
    rc, r, _ = cli(box, "ecrire-port", "b", "--port", "8531", "--entrypoint", "b.py", "--apply")
    assert rc == 0, r
    plat = box.apps / ".streamlit-b.toml"
    assert stat.S_IMODE(plat.stat().st_mode) == 0o644 and "port = 8531" in plat.read_text()


def test_ecrire_port_refuse_lien_et_fifo(box):
    s = secret(box)
    box.appli("a")
    (box.apps / "a" / ".streamlit.toml").symlink_to(s)
    rc, r, _ = cli(box, "ecrire-port", "a", "--port", "8530", "--apply")
    assert rc == 3 and s.read_text().startswith("root:")
    box.appli("f")
    os.mkfifo(box.apps / "f" / ".streamlit.toml")
    rc, r, _ = cli(box, "ecrire-port", "f", "--port", "8530", "--apply", timeout=15)
    assert rc == 3


def test_ecrire_atomique_refuse_un_lien(box):
    cible = box.tmp / "cible"
    cible.write_text("intact\n")
    lien = box.tmp / "lien"
    lien.symlink_to(cible)
    with pytest.raises(P.Refus):
        P.ecrire_atomique(lien, "x")
    assert cible.read_text() == "intact\n" and lien.is_symlink()


# ─── Dépôt : extraction par root, rien ne sort du dossier de l'appli ───────

def fabriquer_zip(chemin: Path, entrees):
    with zipfile.ZipFile(chemin, "w") as z:
        for nom, contenu, mode in entrees:
            info = zipfile.ZipInfo(nom)
            if mode is not None:
                info.external_attr = mode << 16
            z.writestr(info, contenu)
    return chemin


def test_depot_extrait_l_appli_dans_son_dossier(box):
    z = fabriquer_zip(box.tmp / "atelier.zip", [("atelier/app.py", "import streamlit\n", None),
                                               ("atelier/pages/1_a.py", "x = 1\n", None)])
    rc, r, err = cli(box, "deposer", str(z), "atelier", "--apply")
    assert rc == 0, (r, err)
    d = box.apps / "atelier"
    assert d.is_dir() and not d.is_symlink()
    assert (d / "app.py").read_text() == "import streamlit\n" and (d / "pages" / "1_a.py").exists()
    assert stat.S_IMODE((d / "app.py").stat().st_mode) == 0o644
    assert not [p for p in box.apps.iterdir() if p.name.startswith(".")]          # ni brouillon ni reste
    assert r["requirements"]["present"] is False


@pytest.mark.parametrize("entree", [
    ("../evil.py", "x", None), ("/abs.py", "x", None), ("a/../../b.py", "x", None), ("C:/x.py", "x", None),
    ("lien", "/etc/shadow", stat.S_IFLNK | 0o777), ("tube", "", stat.S_IFIFO | 0o644),
    ("disque", "", stat.S_IFBLK | 0o600), ("console", "", stat.S_IFCHR | 0o600),
])
def test_depot_refuse_une_entree_hostile(box, entree):
    z = fabriquer_zip(box.tmp / "x.zip", [("app.py", "import streamlit\n", None), entree])
    rc, r, _ = cli(box, "deposer", str(z), "atelier", "--apply")
    assert rc == 64, r
    assert list(box.apps.iterdir()) == []
    assert not (box.tmp / "evil.py").exists() and not (box.tmp / "b.py").exists()


def test_depot_remplace_l_ancienne_version(box):
    box.appli("atelier", port=8529)
    (box.apps / "atelier" / "ancien.py").write_text("x\n")
    z = fabriquer_zip(box.tmp / "x.zip", [("app.py", "import streamlit  # v2\n", None)])
    rc, r, _ = cli(box, "deposer", str(z), "atelier", "--apply")
    assert rc == 0, r
    assert not (box.apps / "atelier" / "ancien.py").exists()
    assert "v2" in (box.apps / "atelier" / "app.py").read_text()
    assert sorted(p.name for p in box.apps.iterdir()) == ["atelier"]


def test_depot_refuse_un_dossier_d_appli_lien(box):
    ailleurs = box.tmp / "ailleurs"
    ailleurs.mkdir()
    (ailleurs / "garde").write_text("x")
    (box.apps / "atelier").symlink_to(ailleurs)
    z = fabriquer_zip(box.tmp / "x.zip", [("app.py", "import streamlit\n", None)])
    rc, r, _ = cli(box, "deposer", str(z), "atelier", "--apply")
    assert rc == 3, r
    assert sorted(p.name for p in ailleurs.iterdir()) == ["garde"]


def test_depot_refuse_un_zip_lien_ou_mal_nomme(box):
    vrai = fabriquer_zip(box.tmp / "vrai.zip", [("app.py", "x\n", None)])
    lien = box.tmp / "lien.zip"
    lien.symlink_to(vrai)
    for chemin in (str(lien), str(box.tmp / "vrai.tar"), "relatif.zip", str(box.tmp / ".." / "x.zip")):
        rc, r, _ = cli(box, "deposer", chemin, "atelier", "--apply")
        assert rc == 64, (chemin, r)
    assert list(box.apps.iterdir()) == []


def test_depot_installe_les_dependances_dans_le_conteneur(box):
    z = fabriquer_zip(box.tmp / "x.zip", [("app.py", "import segno\n", None), ("requirements.txt", "segno\n", None)])
    rc, r, _ = cli(box, "deposer", str(z), "atelier", "--apply")
    assert rc == 0, r
    attendu = f"pip3 install --break-system-packages -r {box.apps}/atelier/requirements.txt"
    assert attendu in box.appels()
    assert r["requirements"] == {"present": True, "installe": True}


def test_depot_echec_des_dependances_visible(box):
    (box.tmp / "pip.echec").touch()
    z = fabriquer_zip(box.tmp / "x.zip", [("app.py", "import segno\n", None), ("requirements.txt", "segno==99\n", None)])
    rc, r, _ = cli(box, "deposer", str(z), "atelier", "--apply")
    assert rc == 6, r
    assert "segno" in r["error"] and "déposée" in r["error"]
    assert (box.apps / "atelier" / "app.py").exists()


# ─── Verrou, adresse du conteneur, ordre du retrait, environnement ────────

def test_verrou_dans_un_dossier_root_0700(box, monkeypatch):
    d = box.tmp / "verrou.d"
    monkeypatch.setenv("SECUBOX_STREAMLIT_VERROU", str(d / "verrou"))
    box.appli("a")
    rc, r, _ = cli(box, "port", "a", "--apply")
    assert rc == 0, r
    assert stat.S_IMODE(d.stat().st_mode) == 0o700
    d.chmod(0o777)
    rc, r, _ = cli(box, "port", "a", "--apply")
    assert rc == 1 and "verrou" in r["error"]


def test_verrou_par_defaut_hors_de_run_lock():
    assert "/run/lock" not in P.VERROU_DEFAUT


def _config_lxc(box):
    c = box.tmp / "lxc.config"
    c.write_text("lxc.net.0.type = veth\nlxc.net.0.link = br-lxc\nlxc.net.0.ipv4.address = 10.100.0.50/24\n")
    return c


def test_adresse_du_conteneur_limitee_au_pont(box):
    box.appli("atelier", port=8529)
    c = _config_lxc(box)
    rc, r, _ = cli(box, "publier", "atelier", "--nom", "atelier", "--port", "8529", "--ip-vive", "192.168.1.77",
                   "--lxc-config", str(c), "--apply")
    assert rc == 75 and "pont" in r["error"], r
    assert not (box.nginx / "sites-available" / "streamlit-atelier.conf").exists()
    rc, r, _ = cli(box, "publier", "atelier", "--nom", "atelier", "--port", "8529", "--ip-vive", "10.100.0.50",
                   "--lxc-config", str(c), "--apply")
    assert rc == 0, r


def test_adresse_reglee_par_l_operateur_hors_du_pont_admise(box):
    box.appli("atelier", port=8529)
    box.conf.write_text(box.conf.read_text() + '\n[publication]\nip_conteneur = "192.168.1.77"\n')
    rc, r, _ = cli(box, "publier", "atelier", "--nom", "atelier", "--port", "8529", "--lxc-config",
                   str(_config_lxc(box)), "--apply")
    assert rc == 0, r
    assert "192.168.1.77:8529" in (box.nginx / "sites-available" / "streamlit-atelier.conf").read_text()


def test_depublier_retire_la_chaine_avant_de_reecrire_le_toml(box, capsys):
    box.appli("atelier", port=8529)
    assert run(box, capsys, "publier", "atelier", "--nom", "atelier", "--port", "8529", "--ip-vive", "10.100.0.50",
               "--apply")[0] == 0
    box.routes.write_text('{"casse": ')
    rc, r = run(box, capsys, "depublier", "atelier", "--apply")
    assert rc == 1
    assert "[instances.atelier]" in box.conf.read_text()                 # la déclaration n'a pas menti


def test_port_auto_compte_les_vhosts_generes(box, capsys):
    (box.nginx / "sites-available" / "streamlit-orphelin.conf").write_text(
        P.vhost_nginx("orphelin", "orphelin", "orphelin.gk2.secubox.in", "10.100.0.50", 8501))
    box.appli("nouvelle")
    rc, r = run(box, capsys, "port", "nouvelle")
    assert rc == 0 and r["port"] == 8502, r


def test_environnement_trop_long_refuse_jamais_tronque(box, capsys):
    box.appli("atelier")
    rc, r, _ = cli(box, "env", "atelier", "--apply", entree="A=" + "x" * 4000 + "\n" + "B=1\n" * 20000)
    assert rc == 64 and "trop" in r["error"], r
    assert not (box.tmp / "ct").exists()


def test_retour_arriere_incomplet_signale(box, monkeypatch):
    casse = box.tmp / "waf-route-casse"
    casse.write_text('#!/bin/bash\nprintf \'{"casse": \' > "$SBX_WAF_ROUTES"\nexit 1\n')
    casse.chmod(0o755)
    monkeypatch.setenv("SECUBOX_WAF_ROUTE", str(casse))
    box.appli("atelier", port=8529)
    rc, r, _ = cli(box, "publier", "atelier", "--nom", "atelier", "--port", "8529", "--ip-vive", "10.100.0.50",
                   "--apply")
    assert rc == 1 and "retour arrière incomplet" in r["error"], r


def test_haproxy_ne_retire_qu_un_vhost_nginx_vhosts(box, capsys):
    box.appli("atelier", port=8529)
    assert run(box, capsys, "publier", "atelier", "--nom", "atelier", "--port", "8529", "--ip-vive", "10.100.0.50",
               "--apply")[0] == 0
    box.haproxy.write_text(box.haproxy.read_text().replace('backend = "nginx_vhosts"', 'backend = "autre_service"'))
    rc, r = run(box, capsys, "depublier", "atelier", "--apply")
    assert rc == 0, r
    assert "haproxyctl vhost remove" not in box.appels()
    assert any("autre_service" in a for a in r["avertissements"])


def test_nginx_retirer_copie_un_fichier_pose_a_la_main(box, capsys):
    box.appli("atelier-partage-1", port=8529)
    box.conf.write_text(box.conf.read_text() + '\n[instances.couture]\napp = "atelier-partage-1"\nport = 8529\n'
                        'domain = "couture.gk2.secubox.in"\n')
    main_faite = box.nginx / "sites-enabled" / "streamlit-couture.conf"
    original = "server {\n    listen 9080;\n    server_name couture.gk2.secubox.in;\n}\n"
    main_faite.write_text(original)
    rc, r = run(box, capsys, "depublier", "atelier-partage-1", "--apply")
    assert rc == 0, r
    assert not main_faite.exists()
    assert (box.nginx / "sites-available" / "streamlit-couture.conf.avant-secubox").read_text() == original


# ─── Retrait des publications historiques cassées (décision du propriétaire) ─

def _gk2(box):
    """Image réduite de gk2 : deux instances cassées (route vers nginx sans vhost ; sans route), une appli déclarée
    avec un domaine, la référence couture posée à la main (chaîne complète), une publication gérée."""
    for a in ("bazi", "basic", "enhance_app", "atelier-partage-1", "geree"):
        box.appli(a, port=None)
    box.conf.write_text(box.conf.read_text()
                        + '\n[instances.pix]\napp = "bazi"\nport = 8511\ndomain = "pix.gk2.secubox.in"\n'
                        + '\n[instances.basic]\napp = "basic"\nport = 8512\ndomain = "basic.gk2.secubox.in"\nenabled = true\n'
                        + '\n[apps.enhance_app]\nport = 8513\ndomain = "enhance-app.gk2.secubox.in"\nautostart = true\n'
                        + '\n[instances.couture]\napp = "atelier-partage-1"\nport = 8529\nemancipated = true\n'
                          'domain = "couture.gk2.secubox.in"\nwaf_enabled = true\n'
                        + '\n[instances.vitrine]\napp = "geree"\nport = 8530\ndomain = "vitrine.gk2.secubox.in"\n'
                          'publication_geree = true\n')
    routes = json.loads(box.routes.read_text())
    routes.update({"pix.gk2.secubox.in": ["192.168.1.200", 9080],
                   "enhance-app.gk2.secubox.in": ["192.168.1.200", 9080],
                   "couture.gk2.secubox.in": ["192.168.1.200", 9080],
                   "vitrine.gk2.secubox.in": ["192.168.1.200", 9080]})
    box.routes.write_text(json.dumps(routes))
    box.haproxy.write_text(box.haproxy.read_text()
                           + '\n[vhosts.pix_gk2_secubox_in]\ndomain = "pix.gk2.secubox.in"\nbackend = "nginx_vhosts"\n'
                           + '\n[vhosts.couture_gk2_secubox_in]\ndomain = "couture.gk2.secubox.in"\n'
                             'backend = "nginx_vhosts"\n')
    (box.nginx / "sites-enabled" / "streamlit-couture.conf").write_text(
        "server {\n    listen 9080;\n    server_name couture.gk2.secubox.in;\n"
        "    location / { proxy_pass http://10.100.0.50:8529; }\n}\n")


def test_depublier_anciennes_a_blanc_ne_touche_a_rien(box, capsys):
    _gk2(box)
    avant = (box.conf.read_text(), box.routes.read_text(), box.haproxy.read_text())
    rc, r = run(box, capsys, "depublier-anciennes")
    assert rc == 0, r
    assert sorted(x["nom"] for x in r["retires"]) == ["basic", "enhance_app", "pix"]
    assert sorted(g["nom"] for g in r["gardes"]) == ["couture", "vitrine"]
    assert r["applique"] is False
    assert avant == (box.conf.read_text(), box.routes.read_text(), box.haproxy.read_text())
    assert box.appels() == "" and lignes_audit(box) == []


def test_depublier_anciennes_retire_les_restes_garde_couture_et_les_applis(box, capsys):
    _gk2(box)
    rc, r = run(box, capsys, "depublier-anciennes", "--par", "admin", "--apply")
    assert rc == 0, r
    routes = json.loads(box.routes.read_text())
    assert "pix.gk2.secubox.in" not in routes and "enhance-app.gk2.secubox.in" not in routes
    assert routes["couture.gk2.secubox.in"] == ["192.168.1.200", 9080]          # couture intacte
    assert routes["vitrine.gk2.secubox.in"] == ["192.168.1.200", 9080]
    assert "haproxyctl vhost remove pix_gk2_secubox_in" in box.appels()
    assert "couture" not in box.appels()
    conf = box.conf.read_text()
    pix = section(conf, "instances.pix")
    assert "enabled = false" in pix and 'domaine_retire = "pix.gk2.secubox.in"' in pix and "\ndomain =" not in pix
    assert 'domain = "couture.gk2.secubox.in"' in section(conf, "instances.couture")
    assert 'domaine_retire = "enhance-app.gk2.secubox.in"' in section(conf, "apps.enhance_app")
    for a in ("bazi", "basic", "enhance_app"):
        assert (box.apps / a / "app.py").exists()                               # les applis restent déposées
    audit = [x for x in lignes_audit(box) if x["evenement"] == "depublication-ancienne"]
    assert sorted(x["nom_public"] for x in audit) == ["basic", "enhance_app", "pix"]
    pubs = P.publications(conf, "gk2.secubox.in")
    assert "bazi" not in pubs and "basic" not in pubs                          # retirées : plus des publications
    assert pubs["atelier-partage-1"][0]["domaine"] == "couture.gk2.secubox.in"
