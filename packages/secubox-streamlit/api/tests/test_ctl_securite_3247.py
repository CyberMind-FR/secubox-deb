# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3247, relecture de sécurité de la PR #3249 — le VRAI streamlitctl sous /srv/streamlit/apps.

Ce dossier est inscriptible par le conteneur, où toutes les applis tournent en root : root (le ctl) n'y suit aucun
lien, ne s'y bloque sur aucune FIFO, n'y extrait aucune archive hors du dossier de l'appli ; le dépôt installe les
dépendances DANS le conteneur et dit son échec.
"""
import os
import subprocess
import zipfile

import pytest

from api.tests import test_ctl_publication_3247 as banc

# Banc partagé (lxc-info / lxc-start / lxc-attach / nginx / haproxyctl simulés, chemins temporaires).
box = banc.box
CTL, ICI, REFUS, _json = banc.CTL, banc.ICI, banc.REFUS, banc._json


def _secret(box):
    s = box.apps.parent / "shadow"
    s.write_text("root:$6$x:1::::::\n")
    s.chmod(0o600)
    return s


def test_ctl_start_n_ecrit_jamais_a_travers_un_lien(box):
    box.eveil.touch()
    s = _secret(box)
    box.appli("foo")
    (box.apps / "foo" / ".streamlit.toml").symlink_to(s)
    r = box.ctl("app", "start", "foo", "8510")
    assert r.returncode == 3, (r.returncode, r.stderr)
    assert s.read_text() == "root:$6$x:1::::::\n" and s.stat().st_mode & 0o777 == 0o600
    assert not box.journal.exists() or "systemctl start" not in box.journal.read_text()


def test_ctl_start_dossier_d_appli_lien_refuse(box):
    box.eveil.touch()
    ailleurs = box.apps.parent / "ailleurs"
    ailleurs.mkdir()
    (ailleurs / "app.py").write_text("import streamlit\n")
    (box.apps / "foo").symlink_to(ailleurs)
    r = box.ctl("app", "start", "foo", "8510")
    assert r.returncode != 0
    assert sorted(p.name for p in ailleurs.iterdir()) == ["app.py"]


def test_ctl_fifo_dans_un_dossier_d_appli_ne_bloque_pas(box):
    box.eveil.touch()
    box.appli("foo")
    os.mkfifo(box.apps / "foo" / ".streamlit.toml")
    r = box.ctl("app", "start", "foo")                    # lecture du port persisté : jamais bloquée
    assert r.returncode == 3, (r.returncode, r.stderr)


def test_ctl_repair_ne_copie_ni_n_ecrit_a_travers_un_lien(box, tmp_path):
    s = _secret(box)
    box.appli("foo")
    (box.apps / "foo" / ".streamlit.toml").symlink_to(s)
    ps = tmp_path / "ps.txt"
    ps.write_text("python3 -m streamlit run foo/app.py --server.port=8599\n")
    env = dict(box.env, SECUBOX_STREAMLIT_PS_SOURCE=str(ps))
    r = subprocess.run(["bash", str(CTL), "app", "repair", "--apply"], env=env, capture_output=True, text=True,
                       timeout=60)
    assert s.read_text() == "root:$6$x:1::::::\n"
    assert not [f for f in (box.apps / "foo").iterdir() if ".bak." in f.name]       # aucune copie du secret
    assert (box.apps / "foo" / ".streamlit.toml").is_symlink(), r.stderr


def _zip(chemin, entrees):
    with zipfile.ZipFile(chemin, "w") as z:
        for nom, contenu in entrees:
            z.writestr(nom, contenu)
    return chemin


def test_ctl_depot_extrait_par_le_module_et_installe_les_dependances(box):
    box.eveil.touch()
    z = _zip(box.apps.parent / "atelier.zip", [("atelier/app.py", "import segno\n"),
                                              ("atelier/requirements.txt", "segno\n")])
    r = box.ctl("app", "deploy", str(z), "atelier")
    assert r.returncode == 0, r.stderr + r.stdout
    assert (box.apps / "atelier" / "app.py").read_text() == "import segno\n"
    assert f"pip3 install --break-system-packages -r {box.apps}/atelier/requirements.txt" in box.journal.read_text()
    texte = CTL.read_text()
    assert "streamlit_extract_" not in texte and "/srv/apps/" not in texte


def test_ctl_depot_hostile_refuse(box):
    z = _zip(box.apps.parent / "x.zip", [("app.py", "x\n"), ("../../evil.py", "x\n")])
    r = box.ctl("app", "deploy", str(z), "atelier")
    assert r.returncode == REFUS, r.stderr
    assert list(box.apps.iterdir()) == []


def test_ctl_depot_dependances_conteneur_arrete_echec_visible(box):
    z = _zip(box.apps.parent / "x.zip", [("app.py", "import segno\n"), ("requirements.txt", "segno\n")])
    r = box.ctl("app", "deploy", str(z), "atelier")
    assert r.returncode == 6, (r.returncode, r.stderr)
    assert "dépendances" in r.stderr and (box.apps / "atelier" / "app.py").exists()


def test_ctl_depublier_anciennes_a_blanc(box):
    box.appli("bazi")
    box.conf.write_text(box.conf.read_text() + '\n[instances.pix]\napp = "bazi"\nport = 8511\n'
                        'domain = "pix.gk2.secubox.in"\n')
    avant = box.conf.read_text()
    r = box.ctl("app", "depublier-anciennes")
    assert r.returncode == 0, r.stderr
    assert [x["nom"] for x in _json(r)["retires"]] == ["pix"] and box.conf.read_text() == avant


def test_ctl_publie_dans_le_sous_reseau_du_pont(box):
    """Le ctl passe sa configuration LXC : l'adresse vive (lxc-info -i) n'est admise que dans le pont."""
    box.eveil.touch()
    box.appli("atelier", port=8529)
    (box.apps.parent / "lxc" / "streamlit" / "config").write_text("lxc.net.0.ipv4.address = 10.200.0.1/24\n")
    r = box.ctl("app", "publish", "atelier", "atelier", "--apply")
    assert r.returncode == 75, (r.returncode, r.stdout)
    assert "pont" in _json(r)["error"]


@pytest.mark.parametrize("args", [
    ("app", "deploy", "/tmp/../etc/x.zip", "a"),
    ("app", "deploy", "relatif.zip", "a"),
    ("app", "deploy", "/tmp/x.tar", "a"),
    ("app", "depublier-anciennes", "--force"),
    ("app", "depublier-anciennes", "--par", "$(id)"),
    ("app", "depublier-anciennes", "--par"),
])
def test_arguments_hostiles_refuses(box, args):
    r = box.ctl(*args)
    assert r.returncode == REFUS, (args, r.returncode, r.stderr)
    assert "argument refuse" in r.stderr


@pytest.mark.parametrize("args", [
    ("app", "depublier-anciennes"),
    ("app", "depublier-anciennes", "--par", "admin", "--apply"),
])
def test_arguments_legitimes_passent_la_garde(box, args):
    r = box.ctl(*args)
    assert r.returncode != REFUS, (args, r.stderr)


def test_aide_et_readme_disent_que_les_applis_tournent_en_root():
    """Relecture #3249 : toutes les applis tournent en root dans le conteneur ; le fichier d'environnement
    n'isole donc rien d'une appli à l'autre. Écrit noir sur blanc dans l'aide et le README."""
    aide = subprocess.run(["bash", str(CTL), "aide"], capture_output=True, text=True, timeout=30).stdout
    readme = (ICI / "README.md").read_text()
    for texte in (aide, readme):
        assert "root" in texte and "isole" in texte


# ─── Seconde relecture (#3249) ──────────────────────────────────────────────

def test_ctl_dossier_des_applis_lien_refuse(box):
    box.eveil.touch()
    vrai = box.apps.parent / "apps-vrai"
    box.apps.rename(vrai)
    box.apps.symlink_to(vrai)
    (vrai / "foo").mkdir()
    (vrai / "foo" / "app.py").write_text("import streamlit\n")
    r = box.ctl("app", "start", "foo", "8510")
    assert r.returncode == 3, (r.returncode, r.stderr)
    assert "lien" in r.stderr
    assert not (vrai / "foo" / ".streamlit.toml").exists()
    assert not box.journal.exists() or "systemctl start" not in box.journal.read_text()


def test_ctl_relaie_la_cause_du_module(box):
    box.eveil.touch()
    s = _secret(box)
    box.appli("foo")
    (box.apps / "foo" / ".streamlit.toml").symlink_to(s)
    r = box.ctl("app", "start", "foo", "8510")
    assert r.returncode == 3
    assert ".streamlit.toml : lien symbolique" in r.stderr                  # la cause réelle, pas un générique
