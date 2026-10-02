# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Sauvegardes chiffrées par défaut (#1903) : GPG réel, échec fermé, droits restreints."""
import importlib.util
import json
import os
import shutil
import stat
import subprocess
import tempfile
from pathlib import Path

import pytest

API = Path(__file__).resolve().parents[1] / "api"
spec = importlib.util.spec_from_file_location("chiffrement_t", API / "chiffrement.py")
c = importlib.util.module_from_spec(spec)
spec.loader.exec_module(c)
MAIN = (API / "main.py").read_text()

gpg_ok = pytest.mark.skipif(not shutil.which("gpg"), reason="gpg absent")


@pytest.fixture
def trousseau(monkeypatch):
    home = tempfile.mkdtemp(prefix="g", dir="/tmp")
    os.chmod(home, 0o700)
    monkeypatch.setenv("GNUPGHOME", home)
    subprocess.run(["gpg", "--batch", "--pinentry-mode", "loopback", "--passphrase", "", "--quick-gen-key",
                    "sauve <sauve@exemple.invalid>", "default", "default", "never"], capture_output=True, check=True)
    yield "sauve@exemple.invalid"
    subprocess.run(["gpgconf", "--kill", "gpg-agent"], capture_output=True)
    shutil.rmtree(home, ignore_errors=True)


def _archive(tmp_path, contenu=b"etc/secubox/secrets/mqtt: motdepasse-secret\n"):
    f = tmp_path / "config-20261003-000000.tar.gz"
    f.write_bytes(contenu)
    return f


@gpg_ok
def test_chiffre_puis_dechiffre_et_le_clair_disparait(tmp_path, trousseau):
    f = _archive(tmp_path)
    chiffre = c.chiffrer(f, trousseau)
    assert chiffre.name.endswith(".tar.gz.age") and not f.exists()          # plus de clair
    assert b"motdepasse-secret" not in chiffre.read_bytes()                  # illisible
    assert stat.S_IMODE(chiffre.stat().st_mode) == 0o640
    clair = c.dechiffrer(chiffre)
    assert clair.read_bytes() == b"etc/secubox/secrets/mqtt: motdepasse-secret\n"
    c.detruire_clair(clair)
    assert not clair.exists() and not clair.parent.exists()


def test_sans_destinataire_la_sauvegarde_echoue_et_aucun_clair_ne_reste(tmp_path, monkeypatch):
    monkeypatch.setattr(c, "CONFIG", tmp_path / "absent.json")
    f = _archive(tmp_path)
    with pytest.raises(c.ErreurChiffrement):
        c.chiffrer(f)
    assert not f.exists()                                                    # jamais d'archive en clair par omission


def test_echec_de_l_outil_detruit_le_clair(tmp_path):
    f = _archive(tmp_path)

    class R:
        returncode, stderr = 1, "boom"
    with pytest.raises(c.ErreurChiffrement):
        c.chiffrer(f, "age1xyz", run=lambda *a, **k: R())
    assert not f.exists() and not Path(str(f) + ".age").exists()


def test_cle_privee_illisible_se_lit_absente(tmp_path):
    ferme = tmp_path / "ferme"
    ferme.mkdir()
    (ferme / "cle").write_text("x")
    ferme.chmod(0)                                          # dossier non traversable, comme secrets/ pour l'API
    try:
        assert c.existe(ferme / "cle") in (True, False)     # jamais d'exception (root la voit, un autre non)
    finally:
        ferme.chmod(0o700)


def test_destinataire_lu_dans_la_config(tmp_path, monkeypatch):
    cfg = tmp_path / "c.json"
    cfg.write_text(json.dumps({"recipient": " age1abc "}))
    monkeypatch.setattr(c, "CONFIG", cfg)
    assert c.destinataire() == "age1abc"
    cfg.write_text("{pas du json")
    assert c.destinataire() is None


def test_commande_age_ou_gpg_selon_le_destinataire(tmp_path):
    assert c.commande_chiffrer(Path("a"), Path("a.age"), "age1abc")[:3] == ["age", "-r", "age1abc"]
    assert c.commande_chiffrer(Path("a"), Path("a.age"), "moi@x")[0] == "gpg"


def test_restreint_dossier_0750_fichiers_0640_non_recursif(tmp_path):
    d = tmp_path / "config"
    (d / "sous").mkdir(parents=True)
    f = d / "a.tar.gz"
    f.write_text("x")
    g = d / "sous" / "b.tar.gz"
    g.write_text("y")
    for p in (d, f, g):
        os.chmod(p, 0o777 if p.is_dir() else 0o666)
    assert c.restreint(d) >= 2
    assert stat.S_IMODE(d.stat().st_mode) == 0o750 and stat.S_IMODE(f.stat().st_mode) == 0o640
    assert stat.S_IMODE(g.stat().st_mode) == 0o666                           # plus profond : intact


def test_archives_en_clair_listees(tmp_path):
    (tmp_path / "a.tar.gz").write_text("x")
    (tmp_path / "b.tar.gz.age").write_text("x")
    (tmp_path / "notes.txt").write_text("x")
    assert [f.name for f in c.en_clair(tmp_path)] == ["a.tar.gz"]


def test_defauts_chiffres_dans_l_api():
    for modele in ("class BackupCreate", "class ContainerBackup", "class ScheduleConfig"):
        bloc = MAIN[MAIN.index(modele):MAIN.index(modele) + 400]
        assert "encrypt: bool = True" in bloc, modele
    assert "chiffrement.chiffrer(a, req.encrypt_recipient)" in MAIN
    assert "encrypt_recipient and created_files" not in MAIN                 # l'ancien « chiffre si un destinataire »
    assert "backupctl restaurer" in MAIN                                     # restauration d'un .age : message clair


@gpg_ok
def test_dechiffrer_n_ecrase_jamais_l_archive_en_clair_d_origine(tmp_path, trousseau):
    """Régression (#1903) : le déchiffré allait au nom d'origine, puis le nettoyage supprimait le clair."""
    f = _archive(tmp_path)
    original = f.read_bytes()
    chiffre = Path(str(f) + ".age")
    subprocess.run(c.commande_chiffrer(f, chiffre, trousseau), check=True, capture_output=True)   # clair conservé
    assert f.exists()
    clair = c.dechiffrer(chiffre)
    assert clair != f and clair.read_bytes() == original        # fichier temporaire distinct
    c.detruire_clair(clair)
    assert f.exists() and f.read_bytes() == original            # l'original est intact


def test_la_verification_compare_deux_fichiers_distincts():
    ctl = (API.parent / "sbin" / "backupctl").read_text()
    assert "c.detruire_clair(verif)" in ctl and "_memes_octets(verif, f)" in ctl
    assert "verif.read_bytes() == f.read_bytes()" not in ctl      # l'ancienne comparaison d'un fichier à lui-même


# ── Chemins de l'interface : /create et /container/backup (#1903, 2e passe) ────────

def _charge_api(tmp_path, monkeypatch):
    """main.py importé, sauvegardes redirigées vers tmp_path, tar et chiffrement simulés."""
    import sys
    sys.path.insert(0, str(API.parent))
    for nom in ("secubox_core.auth",):
        pass
    spec2 = importlib.util.spec_from_file_location("backup_main_t", API / "main.py")
    m = importlib.util.module_from_spec(spec2)
    spec2.loader.exec_module(m)
    monkeypatch.setattr(m, "BACKUP_PATH", tmp_path / "srv")
    return m


def test_create_chiffre_par_defaut_et_ne_laisse_aucun_clair(tmp_path, monkeypatch):
    import asyncio
    m = _charge_api(tmp_path, monkeypatch)
    monkeypatch.setattr(m, "CONFIG_PATHS", [str(tmp_path)])
    (tmp_path / "secret").write_text("motdepasse-secret")

    def faux_tar(cmd, timeout=300):
        Path(cmd[2]).write_bytes(b"CLAIR motdepasse-secret")
        return True, "", ""
    monkeypatch.setattr(m, "run_cmd", faux_tar)
    monkeypatch.setattr(m.chiffrement, "destinataire", lambda: "age1abc")

    class R:
        returncode, stderr = 0, ""

    def faux_run(cmd, **k):
        dest = Path(cmd[cmd.index("-o") + 1])
        dest.write_bytes(b"CHIFFRE")
        return R()
    monkeypatch.setattr(m.chiffrement.subprocess, "run", faux_run)
    req = m.BackupCreate(type="config")            # aucun champ encrypt : le défaut s'applique
    assert req.encrypt is True
    res = asyncio.run(m.create_backup(req, user={"sub": "t"}))
    assert res["code"] == 0 and ".age" in res["output"]
    restes = list((tmp_path / "srv" / "config").iterdir())
    assert [f.suffix for f in restes] == [".age"]  # plus aucune archive en clair
    assert b"CLAIR" not in restes[0].read_bytes()


def test_create_sans_destinataire_est_un_echec_pas_un_succes_en_clair(tmp_path, monkeypatch):
    import asyncio
    m = _charge_api(tmp_path, monkeypatch)
    monkeypatch.setattr(m, "CONFIG_PATHS", [str(tmp_path)])
    monkeypatch.setattr(m, "run_cmd", lambda cmd, timeout=300: (Path(cmd[2]).write_bytes(b"CLAIR") or True, "", ""))
    monkeypatch.setattr(m.chiffrement, "destinataire", lambda: None)
    res = asyncio.run(m.create_backup(m.BackupCreate(type="config"), user={"sub": "t"}))
    assert res["code"] == 1                         # jamais « code 0 » pour une sauvegarde qui n'existe pas
    assert list((tmp_path / "srv" / "config").iterdir()) == []      # et rien en clair ne reste


def test_choix_explicite_de_ne_pas_chiffrer_est_signale(tmp_path, monkeypatch):
    import asyncio
    m = _charge_api(tmp_path, monkeypatch)
    monkeypatch.setattr(m, "CONFIG_PATHS", [str(tmp_path)])
    monkeypatch.setattr(m, "run_cmd", lambda cmd, timeout=300: (Path(cmd[2]).write_bytes(b"CLAIR") or True, "", ""))
    res = asyncio.run(m.create_backup(m.BackupCreate(type="config", encrypt=False), user={"sub": "t"}))
    assert res["code"] == 0 and "NON CHIFFRÉE" in res["output"]
    f = next((tmp_path / "srv" / "config").iterdir())
    assert stat.S_IMODE(f.stat().st_mode) == 0o640  # même en clair : jamais 0666


def test_liste_marque_les_archives_chiffrees(tmp_path, monkeypatch):
    m = _charge_api(tmp_path, monkeypatch)
    d = tmp_path / "srv" / "config"
    d.mkdir(parents=True)
    (d / "a.tar.gz").write_text("x")
    (d / "b.tar.gz.age").write_text("x")
    etat = {b["file"]: b["encrypted"] for b in m.list_backups("config")}
    assert etat == {"a.tar.gz": False, "b.tar.gz.age": True}


def test_interface_a_la_case_et_l_etat_du_chiffrement():
    html = (API.parent / "www" / "backup" / "index.html").read_text()
    assert 'id="chiffrer" checked' in html                       # cochée par défaut
    assert "JSON.stringify({ type, encrypt })" in html and "JSON.stringify({ name, encrypt })" in html
    assert "loadEncryption()" in html and "backupctl restaurer" in html
    assert "SANS" not in html or "EN CLAIR" in html              # l'opt-out demande une confirmation explicite
