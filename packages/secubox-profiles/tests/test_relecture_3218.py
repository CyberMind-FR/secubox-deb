# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3218 — correctifs de la relecture de sécurité de la PR #3248.

1. La mise à jour des profils de référence (postinst, en root) écrivait un temporaire dans /etc/secubox/profiles, dossier du
   compte partagé `secubox`, puis le copiait, chmod et chown PAR CHEMIN : un lien substitué suffisait à élever secubox en root,
   à chaque mise à jour. Elle prépare désormais dans un dossier root seul et renomme par descripteur, sans suivre de lien.
2. Une FIFO posée à la place d'un profil bloquait dpkg sans fin (lecture pour l'empreinte).
3. Le sleeper reste hors des profils (livré désactivé, choix de l'opérateur).
4. Le panneau refuse d'appliquer un profil qui coupe sa propre API (proteges_off) : il se couperait pendant la requête.
5. Le postinst ne réactive plus ce que le profil actif coupe (API profiles, minuteries cache-warm@*).
6. Un profil illisible ignoré par minuteurs_geres est journalisé."""
from __future__ import annotations

import importlib.util
import logging
import os
import subprocess
import sys
from pathlib import Path

import pytest

from api import minuteurs
from api.cli import main
from api.state import load_profile

PKG = Path(__file__).resolve().parents[1]
REPO = PKG.parents[1]
SCRIPT = PKG / "scripts" / "maj-references.py"
POSTINST = (PKG / "debian" / "postinst").read_text(encoding="utf-8")


# ── 1 et 2 : mise à jour des profils de référence ────────────────────────────

@pytest.fixture()
def arbre(tmp_path):
    """SOURCE (paquet), PREPA (équivalent de /etc, root seul), CIBLE (/etc/secubox/profiles, au compte partagé)."""
    src, prepa = tmp_path / "share", tmp_path / "etc"
    cible = prepa / "secubox" / "profiles"
    src.mkdir()
    cible.mkdir(parents=True)
    (src / "minimal.toml").write_bytes(b'name = "minimal"\non = ["hub"]\n')
    (src / "lite.toml").write_bytes(b'name = "lite"\non = []\n')
    emp = src / "empreintes-livrees.txt"
    emp.write_text("# commentaire\n", encoding="utf-8")
    return src, prepa, cible, emp


def _lancer(src, prepa, cible, emp, timeout=20):
    env = dict(os.environ, PREPA=str(prepa))
    env.pop("PROPRIO", None)
    return subprocess.run([sys.executable, "-I", str(SCRIPT), str(src), str(cible), str(emp)], env=env,
                          capture_output=True, text=True, timeout=timeout, check=False)


def test_un_lien_pose_a_la_place_d_un_profil_n_est_ni_suivi_ni_ecrit(arbre, tmp_path):
    src, prepa, cible, emp = arbre
    victime = tmp_path / "victime"
    victime.write_text("secret root\n", encoding="utf-8")
    (cible / "minimal.toml").symlink_to(victime)
    r = _lancer(src, prepa, cible, emp)
    assert r.returncode == 0, r.stderr
    assert victime.read_text(encoding="utf-8") == "secret root\n"
    assert (cible / "minimal.toml").is_symlink() and os.readlink(cible / "minimal.toml") == str(victime)
    assert "lien" in r.stderr
    assert (cible / "lite.toml").read_bytes() == (src / "lite.toml").read_bytes()      # les autres profils avancent


def test_un_dossier_cible_remplace_par_un_lien_est_refuse(arbre, tmp_path):
    """/etc/secubox appartient au compte secubox : il peut renommer profiles/ et poser un lien vers un dossier root."""
    src, prepa, cible, emp = arbre
    ailleurs = tmp_path / "dossier-root"
    ailleurs.mkdir()
    cible.rmdir()
    cible.symlink_to(ailleurs)
    r = _lancer(src, prepa, cible, emp)
    assert r.returncode != 0
    assert list(ailleurs.iterdir()) == []


def test_un_lien_pose_a_la_place_d_un_dpkg_dist_n_est_pas_suivi(arbre, tmp_path):
    src, prepa, cible, emp = arbre
    (cible / "minimal.toml").write_bytes(b'name = "minimal"\non = ["a-moi"]\n')        # modifié : référence en .dpkg-dist
    victime = tmp_path / "victime"
    victime.write_text("intact\n", encoding="utf-8")
    (cible / "minimal.toml.dpkg-dist").symlink_to(victime)
    r = _lancer(src, prepa, cible, emp)
    assert r.returncode == 0, r.stderr
    assert victime.read_text(encoding="utf-8") == "intact\n"
    # Le lien est REMPLACÉ par un renommage (jamais écrit au travers) : la référence est bien posée.
    assert not (cible / "minimal.toml.dpkg-dist").is_symlink()
    assert (cible / "minimal.toml.dpkg-dist").read_bytes() == (src / "minimal.toml").read_bytes()


def test_une_fifo_a_la_place_d_un_profil_ne_bloque_pas_dpkg(arbre):
    src, prepa, cible, emp = arbre
    os.mkfifo(cible / "minimal.toml")
    r = _lancer(src, prepa, cible, emp, timeout=20)          # avant : sha256sum < fifo attendait un écrivain, sans fin
    assert r.returncode == 0, r.stderr
    assert "pas un fichier ordinaire" in r.stderr
    assert (cible / "lite.toml").is_file()


def test_rien_n_est_prepare_dans_le_dossier_du_compte_partage(arbre, monkeypatch):
    """Chaque fichier est CRÉÉ dans un dossier temporaire root seul (0700) sous PREPA, puis renommé : jamais dans la cible."""
    src, prepa, cible, emp = arbre
    spec = importlib.util.spec_from_file_location("maj_references", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    crees, vrai_open = [], os.open

    def espion(chemin, drapeaux, mode=0o777, *, dir_fd=None):
        if drapeaux & os.O_CREAT:
            dossier = os.readlink(f"/proc/self/fd/{dir_fd}") if dir_fd is not None else os.path.dirname(chemin)
            crees.append((dossier, os.stat(dossier).st_mode & 0o777))
        return vrai_open(chemin, drapeaux, mode, dir_fd=dir_fd)

    monkeypatch.setattr(mod.os, "open", espion)
    assert mod.maj(src, cible, emp, prepa=prepa, proprio=None) == 0
    assert crees and all(Path(d).parent == prepa and Path(d) != cible and m == 0o700 for d, m in crees), crees
    assert [p.name for p in prepa.iterdir()] == ["secubox"]                      # le dossier de préparation est retiré
    assert (cible / "minimal.toml").stat().st_mode & 0o777 == 0o644


def test_une_copie_livree_non_modifiee_est_remplacee_et_une_copie_modifiee_gardee(arbre):
    src, prepa, cible, emp = arbre
    ancien = b'name = "minimal"\non = ["dpi"]\n'
    import hashlib
    emp.write_text(f"{hashlib.sha256(ancien).hexdigest()}  minimal.toml\n", encoding="utf-8")
    (cible / "minimal.toml").write_bytes(ancien)
    (cible / "lite.toml").write_bytes(b'name = "lite"\non = ["a-moi"]\n')
    r = _lancer(src, prepa, cible, emp)
    assert r.returncode == 0, r.stderr
    assert (cible / "minimal.toml").read_bytes() == (src / "minimal.toml").read_bytes()
    assert b"a-moi" in (cible / "lite.toml").read_bytes()
    assert (cible / "lite.toml.dpkg-dist").read_bytes() == (src / "lite.toml").read_bytes()


def test_le_postinst_appelle_la_version_python_isolee():
    assert "python3 -I /usr/lib/secubox/profiles/maj-references.py" in POSTINST
    assert "maj-references.sh" not in POSTINST
    install = (PKG / "debian" / "install").read_text(encoding="utf-8")
    assert "scripts/maj-references.py" in install and "maj-references.sh" not in install


# ── 3 : le sleeper reste hors des profils ────────────────────────────────────

def test_le_sleeper_n_est_dans_aucun_profil_de_reference():
    for p in sorted((PKG / "profiles").glob("*.toml")):
        assert "sleeper" not in load_profile(p).on, p.name


# ── 4 : le panneau n'applique pas un profil qui coupe sa propre API ──────────

def test_le_panneau_refuse_d_appliquer_un_profil_qui_coupe_son_api(tmp_path, monkeypatch):
    sys.path.insert(0, str(REPO / "common"))
    import api.web as web
    from fastapi.testclient import TestClient
    (tmp_path / "modules.d").mkdir()
    prof = tmp_path / "profiles"
    prof.mkdir()
    (prof / "minimal.toml").write_text('name = "minimal"\nlabel = "m"\non = []\nproteges_off = ["profiles"]\n')
    (prof / "lite.toml").write_text('name = "lite"\nlabel = "l"\non = []\n')
    (prof / "active").write_text("lite\n")
    monkeypatch.setenv("SECUBOX_PROFILES_ROOT", str(tmp_path))
    appels = []
    monkeypatch.setattr(web, "_ctl_run", lambda argv, **kw: appels.append(argv))
    c = TestClient(web.app)
    c.app.dependency_overrides[web.require_jwt] = lambda: {"sub": "admin"}
    try:
        r = c.post("/api/v1/profiles/apply", json={"profile": "minimal"})
    finally:
        c.app.dependency_overrides.clear()
    assert r.status_code == 409
    assert "secubox-profilectl apply --profile minimal --yes" in r.json()["detail"]
    assert appels == [] and (prof / "active").read_text() == "lite\n"


# ── 5 : le postinst ne réactive pas ce que le profil actif coupe ─────────────

@pytest.fixture()
def racine(tmp_path):
    prof = tmp_path / "profiles"
    prof.mkdir()
    (prof / "minimal.toml").write_text('name = "minimal"\nlabel = "m"\non = []\nproteges_off = ["profiles"]\n'
                                       'minuteurs_off = ["cache-warm@jitsi", "netstats"]\n')
    (prof / "lite.toml").write_text('name = "lite"\nlabel = "l"\non = []\n')
    return tmp_path


@pytest.mark.parametrize("unite, attendu", [
    ("secubox-profiles.service", 0), ("secubox-cache-warm@jitsi.timer", 0), ("secubox-netstats.timer", 0),
    ("secubox-cache-warm@metacatalog.timer", 1), ("secubox-hub.service", 1), ("secubox-netstats.service", 1)])
def test_coupe_dit_si_le_profil_actif_coupe_l_unite(racine, unite, attendu):
    (racine / "profiles" / "active").write_text("minimal\n")
    assert main(["--root", str(racine), "coupe", unite]) == attendu


def test_coupe_sans_profil_actif_ou_avec_un_autre_profil_ne_coupe_rien(racine):
    assert main(["--root", str(racine), "coupe", "secubox-profiles.service"]) == 1
    (racine / "profiles" / "active").write_text("lite\n")
    assert main(["--root", str(racine), "coupe", "secubox-profiles.service"]) == 1


@pytest.mark.parametrize("unite", ["../x.timer", "secubox-profiles", "secubox-a b.service", "nginx.service"])
def test_coupe_refuse_un_nom_d_unite_invalide(racine, unite):
    (racine / "profiles" / "active").write_text("minimal\n")
    assert main(["--root", str(racine), "coupe", unite]) == 2


def test_le_postinst_ne_reactive_ni_l_api_ni_les_minuteries_coupees():
    bloc = POSTINST[POSTINST.index("for _m in metacatalog jitsi"):POSTINST.index("secubox-waker (ref #896")]
    assert 'secubox-profilectl coupe "secubox-cache-warm@${_m}.timer"' in bloc
    assert "secubox-profilectl coupe secubox-profiles.service" in bloc
    # enable/restart de l'API seulement dans la branche « non coupée » du test.
    branche = bloc[bloc.index("secubox-profilectl coupe secubox-profiles.service"):]
    assert branche.index("else") < branche.index("systemctl enable secubox-profiles.service")


# ── 6 : un profil illisible ignoré est journalisé ────────────────────────────

def test_un_profil_illisible_ignore_est_journalise(tmp_path, caplog):
    (tmp_path / "casse.toml").write_text("name = ", encoding="utf-8")
    (tmp_path / "bon.toml").write_text('name = "bon"\non = []\nminuteurs_off = ["netstats"]\n', encoding="utf-8")
    with caplog.at_level(logging.WARNING):
        assert minuteurs.minuteurs_geres(tmp_path) == {"netstats"}
    assert any("casse.toml" in r.getMessage() for r in caplog.records)
