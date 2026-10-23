# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3072 — destination et chemin LXC configurables (/etc/secubox/backup.toml), restauration par root seulement.

gk2 : la racine (eMMC) est à 91 %, /data a 400 Go ; les conteneurs sont dans /data/lxc, pas /srv/lxc ; l'API lançait
`tar -xzf` sous `secubox` (échec) et une archive en clair appartient à `secubox` : ne jamais la faire extraire par sudoers."""
import importlib.machinery
import importlib.util
import io
import sys
import tarfile
from pathlib import Path

import pytest
from fastapi import HTTPException

RACINE = Path(__file__).resolve().parents[1]
API = RACINE / "api"
CTL = RACINE / "sbin" / "backupctl"
SUDOERS = RACINE / "debian" / "secubox-backup.sudoers"


def _chiffrement():
    spec = importlib.util.spec_from_file_location("chiffrement_t3072", API / "chiffrement.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def _ctl(monkeypatch, conf=None, **env):
    monkeypatch.setenv("SECUBOX_BACKUP_LIB", str(API))
    monkeypatch.setenv("SECUBOX_BACKUP_CONF", str(conf or "/nonexistent/backup.toml"))
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    sys.modules.pop("chiffrement", None)
    sys.path.insert(0, str(API))
    loader = importlib.machinery.SourceFileLoader("backupctl_t3072", str(CTL))
    spec = importlib.util.spec_from_loader("backupctl_t3072", loader)
    m = importlib.util.module_from_spec(spec)
    loader.exec_module(m)
    return m


# ── configuration ──────────────────────────────────────────────────────────────

def test_sans_fichier_les_valeurs_historiques(tmp_path):
    c = _chiffrement()
    p = c.parametres(tmp_path / "absent.toml")
    assert p["path"] == "/srv/backups" and p["lxc_path"] == "/srv/lxc"
    assert "/var/lib/secubox" in p["service_paths"]


def test_le_toml_deplace_la_destination_et_les_conteneurs(tmp_path):
    f = tmp_path / "backup.toml"
    f.write_text('[backup]\npath = "/data/secubox-backups/"\nlxc_path = "/data/lxc"\nservice_paths = ["/var/lib/secubox"]\n')
    p = _chiffrement().parametres(f)
    assert p["path"] == "/data/secubox-backups" and p["lxc_path"] == "/data/lxc"
    assert p["service_paths"] == ["/var/lib/secubox"]


@pytest.mark.parametrize("contenu", [
    '[backup]\npath = "relatif/chemin"\n', '[backup]\npath = "/data/../etc"\n', '[backup]\npath = 5\n',
    '[backup]\nservice_paths = []\n', '[backup]\nservice_paths = ["relatif"]\n', 'pas du toml [[[',
])
def test_valeur_invalide_ignoree_sans_planter(tmp_path, contenu):
    f = tmp_path / "b.toml"
    f.write_text(contenu)
    p = _chiffrement().parametres(f)
    assert p["path"] == "/srv/backups" and p["lxc_path"] == "/srv/lxc"
    assert p["service_paths"][0] == "/var/lib/secubox"


def test_le_ctl_lit_le_toml_et_l_environnement_prime(tmp_path, monkeypatch):
    f = tmp_path / "b.toml"
    f.write_text('[backup]\npath = "/data/sb"\nlxc_path = "/data/lxc"\n')
    m = _ctl(monkeypatch, f)
    assert str(m.RACINE) == "/data/sb" and str(m.LXC_PATH) == "/data/lxc"
    m = _ctl(monkeypatch, f, SECUBOX_BACKUP_PATH="/tmp/x")
    assert str(m.RACINE) == "/tmp/x"


def test_l_api_lit_le_meme_toml(tmp_path, monkeypatch):
    f = tmp_path / "b.toml"
    f.write_text('[backup]\npath = "/data/sb"\nlxc_path = "/data/lxc"\n')
    monkeypatch.setenv("SECUBOX_BACKUP_CONF", str(f))
    spec = importlib.util.spec_from_file_location("backup_main_3072", API / "main.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    assert str(m.BACKUP_PATH) == "/data/sb" and str(m.LXC_PATH) == "/data/lxc"


# ── restauration par root ──────────────────────────────────────────────────────

def _archive(chemin: Path, nom_interne: str, contenu: bytes = b"x"):
    chemin.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(chemin, "w:gz") as t:
        i = tarfile.TarInfo(nom_interne)
        i.size = len(contenu)
        t.addfile(i, io.BytesIO(contenu))


def test_restaurer_accepte_une_archive_en_clair_et_la_conserve(tmp_path, monkeypatch):
    m = _ctl(monkeypatch, SECUBOX_BACKUP_PATH=str(tmp_path / "sb"))
    arc = tmp_path / "sb" / "config" / "config-1.tar.gz"
    _archive(arc, "fichier.txt", b"bonjour")
    cible = tmp_path / "cible"
    cible.mkdir()
    assert m.restaurer([str(arc), "-C", str(cible)]) == 0
    assert (cible / "fichier.txt").read_bytes() == b"bonjour"
    assert arc.exists()                      # l'archive d'origine n'est jamais détruite


def test_restaurer_refuse_un_format_inconnu(tmp_path, monkeypatch):
    m = _ctl(monkeypatch, SECUBOX_BACKUP_PATH=str(tmp_path / "sb"))
    f = tmp_path / "sb" / "config" / "x.zip"
    f.parent.mkdir(parents=True)
    f.write_text("z")
    with pytest.raises(SystemExit):
        m.restaurer([str(f)])


def test_restaurer_une_archive_de_conteneur_va_dans_lxc(tmp_path, monkeypatch):
    lxc = tmp_path / "lxc"
    lxc.mkdir()
    m = _ctl(monkeypatch, SECUBOX_BACKUP_PATH=str(tmp_path / "sb"), SECUBOX_BACKUP_LXC=str(lxc))
    arc = tmp_path / "sb" / "containers" / "web-1.tar.gz"
    _archive(arc, "web/config", b"lxc")
    assert m.restaurer([str(arc)]) == 0
    assert (lxc / "web" / "config").read_bytes() == b"lxc"


def test_restaurer_conteneur_remplace_et_garde_l_ancien_si_l_archive_est_mauvaise(tmp_path, monkeypatch):
    lxc = tmp_path / "lxc"
    (lxc / "web").mkdir(parents=True)
    (lxc / "web" / "config").write_text("ancien")
    m = _ctl(monkeypatch, SECUBOX_BACKUP_PATH=str(tmp_path / "sb"), SECUBOX_BACKUP_LXC=str(lxc))
    mauvaise = tmp_path / "sb" / "containers" / "web-bad.tar.gz"
    _archive(mauvaise, "autre/config")                # ne contient pas web/config
    assert m.restaurer_conteneur("web", str(mauvaise)) != 0
    assert (lxc / "web" / "config").read_text() == "ancien"
    bonne = tmp_path / "sb" / "containers" / "web-ok.tar.gz"
    _archive(bonne, "web/config", b"nouveau")
    assert m.restaurer_conteneur("web", str(bonne)) == 0
    assert (lxc / "web" / "config").read_bytes() == b"nouveau"
    assert not [p for p in lxc.iterdir() if p.name.startswith(".restaure")]


def test_restaurer_conteneur_refuse_un_nom_ou_une_archive_hors_conteneurs(tmp_path, monkeypatch):
    m = _ctl(monkeypatch, SECUBOX_BACKUP_PATH=str(tmp_path / "sb"), SECUBOX_BACKUP_LXC=str(tmp_path))
    with pytest.raises(SystemExit):
        m.restaurer_conteneur("../etc", "x.tar.gz")
    cfg = tmp_path / "sb" / "config" / "c.tar.gz"
    _archive(cfg, "a")
    with pytest.raises(SystemExit):
        m.restaurer_conteneur("web", str(cfg))


# ── l'API ne restaure plus rien ────────────────────────────────────────────────

def _api(tmp_path, monkeypatch):
    spec = importlib.util.spec_from_file_location("backup_main_3072b", API / "main.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    monkeypatch.setattr(m, "BACKUP_PATH", tmp_path / "srv")
    monkeypatch.setattr(m, "LXC_PATH", tmp_path / "lxc")
    return m


@pytest.mark.asyncio
async def test_api_restore_clair_renvoie_409_et_ne_lance_aucun_tar(tmp_path, monkeypatch):
    m = _api(tmp_path, monkeypatch)
    _archive(tmp_path / "srv" / "config" / "config-1.tar.gz", "a")
    appels = []
    monkeypatch.setattr(m, "run_cmd", lambda *a, **k: appels.append(a) or (True, "", ""))
    with pytest.raises(HTTPException) as e:
        await m.restore_backup(m.RestoreRequest(file="config-1.tar.gz", dry_run=False), {"sub": "a"})
    assert e.value.status_code == 409 and "backupctl restaurer config-1.tar.gz" in e.value.detail["commande"]
    assert not [a for a in appels if "-xzf" in a[0]]


@pytest.mark.asyncio
async def test_api_restore_refuse_un_nom_avec_chemin(tmp_path, monkeypatch):
    m = _api(tmp_path, monkeypatch)
    with pytest.raises(HTTPException) as e:
        await m.restore_backup(m.RestoreRequest(file="../../etc/passwd", dry_run=False), {"sub": "a"})
    assert e.value.status_code == 422


@pytest.mark.asyncio
async def test_api_container_restore_409_sans_toucher_au_conteneur(tmp_path, monkeypatch):
    m = _api(tmp_path, monkeypatch)
    (tmp_path / "lxc" / "web").mkdir(parents=True)
    _archive(tmp_path / "srv" / "containers" / "web-1.tar.gz", "web/config")
    appels = []
    monkeypatch.setattr(m, "run_cmd", lambda *a, **k: appels.append(a) or (True, "", ""))
    with pytest.raises(HTTPException) as e:
        await m.restore_container(m.ContainerRestore(name="web", file="web-1.tar.gz"), {"sub": "a"})
    assert e.value.status_code == 409 and "restaurer-conteneur web web-1.tar.gz" in e.value.detail["commande"]
    assert appels == [] and (tmp_path / "lxc" / "web").exists()


def test_le_sudoers_n_accorde_aucune_restauration():
    assert "restaurer" not in SUDOERS.read_text().replace("# ", "").split("secubox ALL")[1]
