# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3064 — l'archive est créée par `backupctl archiver` (root, sudoers à argv exact), pas par l'API (`secubox`).

Constat gk2 : « Config backup failed: tar: /etc/secubox/secrets: Cannot open: Permission denied » (et ~60 fichiers de
/etc/secubox, /etc/nginx, /etc/wireguard). L'API tournait sous `secubox`, `NoNewPrivileges=true`, sans sudoers, et lançait
`tar -czf … /etc/secubox …` elle-même ; idem pour les conteneurs (lxc-stop/start) et les données de services."""
import importlib.machinery
import importlib.util
import json
import re
import stat
import subprocess
import sys
from pathlib import Path

import pytest

RACINE = Path(__file__).resolve().parents[1]
API = RACINE / "api"
CTL = RACINE / "sbin" / "backupctl"
SUDOERS = RACINE / "debian" / "secubox-backup.sudoers"
UNITE = RACINE / "debian" / "secubox-backup.service"
RULES = RACINE / "debian" / "rules"
POSTINST = RACINE / "debian" / "postinst"


def _ctl(monkeypatch):
    monkeypatch.setenv("SECUBOX_BACKUP_LIB", str(API))
    sys.path.insert(0, str(API))
    loader = importlib.machinery.SourceFileLoader("backupctl_t", str(CTL))
    spec = importlib.util.spec_from_loader("backupctl_t", loader)
    m = importlib.util.module_from_spec(spec)
    loader.exec_module(m)
    return m


def _api(tmp_path, monkeypatch):
    spec = importlib.util.spec_from_file_location("backup_main_3064", API / "main.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    monkeypatch.setattr(m, "BACKUP_PATH", tmp_path / "srv")
    return m


# ── ctl : création de l'archive ────────────────────────────────────────────────

def test_archiver_config_cree_une_archive_chiffree_sans_clair(tmp_path, monkeypatch):
    m = _ctl(monkeypatch)
    (tmp_path / "etc").mkdir()
    (tmp_path / "etc" / "secret").write_text("motdepasse-secret")
    monkeypatch.setattr(m.c, "destinataire", lambda: "age1abc")

    class R:
        returncode, stderr = 0, ""

    def faux_run(cmd, **k):
        if cmd[0] == "age":
            Path(cmd[cmd.index("-o") + 1]).write_bytes(b"CHIFFRE")
            return R()
        return subprocess.run(cmd, **k)
    monkeypatch.setattr(m.c.subprocess, "run", faux_run)
    r = m.archiver("config", None, True, racine=tmp_path / "srv", chemins=[str(tmp_path / "etc")], proprietaire=False)
    assert r["ok"] is True and r["chiffre"] is True and r["fichier"].endswith(".tar.gz.age")
    fichiers = list((tmp_path / "srv" / "config").iterdir())
    assert [f.name for f in fichiers] == [r["fichier"]], "plus aucune archive en clair"
    assert b"motdepasse" not in fichiers[0].read_bytes()
    assert stat.S_IMODE(fichiers[0].stat().st_mode) == 0o640


def test_archiver_sans_destinataire_echoue_et_ne_laisse_rien_en_clair(tmp_path, monkeypatch):
    m = _ctl(monkeypatch)
    (tmp_path / "etc").mkdir()
    (tmp_path / "etc" / "f").write_text("x")
    monkeypatch.setattr(m.c, "destinataire", lambda: None)
    r = m.archiver("config", None, True, racine=tmp_path / "srv", chemins=[str(tmp_path / "etc")], proprietaire=False)
    assert r["ok"] is False and "destinataire" in r["erreur"]
    assert list((tmp_path / "srv" / "config").iterdir()) == []


def test_archiver_en_clair_est_un_choix_explicite_en_0640(tmp_path, monkeypatch):
    m = _ctl(monkeypatch)
    (tmp_path / "etc").mkdir()
    (tmp_path / "etc" / "f").write_text("x")
    r = m.archiver("services", None, False, racine=tmp_path / "srv", chemins=[str(tmp_path / "etc")], proprietaire=False)
    assert r["ok"] is True and r["chiffre"] is False and r["fichier"].endswith(".tar.gz")
    assert stat.S_IMODE((tmp_path / "srv" / "services" / r["fichier"]).stat().st_mode) == 0o640


def test_archiver_un_chemin_illisible_est_un_echec_explicite_pas_une_archive_tronquee(tmp_path, monkeypatch):
    m = _ctl(monkeypatch)
    r = m.archiver("config", None, False, racine=tmp_path / "srv", chemins=[str(tmp_path / "absent")], proprietaire=False)
    assert r["ok"] is False and "rien à sauvegarder" in r["erreur"]


def test_archiver_conteneur_redemarre_toujours_ce_qu_il_a_arrete(tmp_path, monkeypatch):
    m = _ctl(monkeypatch)
    lxc = tmp_path / "lxc"
    (lxc / "web").mkdir(parents=True)
    (lxc / "web" / "config").write_text("lxc.uts.name = web")
    monkeypatch.setattr(m, "LXC_PATH", lxc)
    appels = []

    class R:
        def __init__(self, rc=0, out=""):
            self.returncode, self.stdout, self.stderr = rc, out, ""

    def faux_run(cmd, **k):
        appels.append(cmd[0])
        if cmd[0] == "lxc-info":
            return R(0, "State: RUNNING")
        return R(0)

    class TarEchoue:                                    # tar passe par Popen (surveillance de l'espace disque)
        returncode, stderr = 2, None

        def __init__(self, *a, **k):
            appels.append("tar")

        def poll(self):
            return 2

        def wait(self, timeout=None):
            return 2

    class Large:
        free = 10 * 1024 * 1024 * 1024
    r = m.archiver("conteneur", "web", False, racine=tmp_path / "srv", run=faux_run, proprietaire=False,
                   popen=TarEchoue, libre=lambda p: Large)
    assert r["ok"] is False
    assert "lxc-stop" in appels and "lxc-start" in appels, "un conteneur arrêté pour la sauvegarde est relancé même si tar échoue"
    assert list((tmp_path / "srv" / "containers").iterdir()) == []


def test_archiver_refuse_un_nom_de_conteneur_hors_alphabet(tmp_path, monkeypatch):
    m = _ctl(monkeypatch)
    for nom in ("../etc", "a b", "", "x;rm"):
        r = m.archiver("conteneur", nom, False, racine=tmp_path / "srv", proprietaire=False)
        assert r["ok"] is False and "nom" in r["erreur"]


def test_le_ctl_ne_connait_que_les_verbes_declares(monkeypatch, capsys):
    m = _ctl(monkeypatch)
    for argv in (["archiver"], ["archiver", "boom", "chiffre"], ["archiver", "config"], ["archiver", "config", "peut-etre"]):
        monkeypatch.setattr(sys, "argv", ["backupctl", *argv])
        assert m.main() == 2


# ── sudoers, unité, paquet ─────────────────────────────────────────────────────

def test_le_sudoers_accorde_les_verbes_exacts_et_pas_la_restauration():
    s = SUDOERS.read_text()
    regles = "\n".join(x for x in s.splitlines() if x.strip() and not x.lstrip().startswith("#"))
    for k in ("config", "services"):
        for mode in ("chiffre", "clair"):
            assert f"/usr/sbin/backupctl archiver {k} {mode}" in regles
    assert "/usr/sbin/backupctl archiver conteneur [A-Za-z0-9._-]* chiffre" in regles
    assert "/usr/sbin/backupctl archiver conteneur [A-Za-z0-9._-]* clair" in regles
    assert "restaurer" not in regles and "init-key" not in regles and "chiffrer-existantes" not in regles
    assert not re.search(r"backupctl\s*(,|$)", regles, re.M), "jamais le ctl nu"
    assert "Defaults!/usr/sbin/backupctl !requiretty" in s


def test_l_unite_laisse_passer_sudo():
    service = UNITE.read_text().split("[Service]", 1)[1]
    assert "NoNewPrivileges=true" not in service, "sudo vers le ctl serait neutralisé"
    assert "User=secubox" in service


def test_le_paquet_installe_le_sudoers_et_le_valide():
    r = RULES.read_text()
    assert "debian/secubox-backup.sudoers" in r and "etc/sudoers.d/secubox-backup" in r
    assert "visudo -cf /etc/sudoers.d/secubox-backup" in POSTINST.read_text()


# ── API : plus aucun tar ni lxc-* lancé par l'utilisateur secubox ──────────────

def test_l_api_ne_lance_plus_tar_de_creation_ni_lxc():
    a = (API / "main.py").read_text()
    assert '["tar", "-czf"' not in a, "la création d'archive est au ctl root"
    assert '"lxc-stop"' not in a.split("def lxc_running")[0] and a.count('"lxc-stop"') <= 1   # restauration seulement
    assert "backupctl" in a and '"archiver"' in a


def test_create_delegue_au_ctl_et_rend_le_nom_de_l_archive(tmp_path, monkeypatch):
    import asyncio
    m = _api(tmp_path, monkeypatch)
    appels = []

    def faux(kind, encrypt, nom=None, timeout=900):
        appels.append((kind, encrypt, nom))
        return True, f"{kind}-20261023-000000.tar.gz.age"
    monkeypatch.setattr(m, "_archiver", faux)
    monkeypatch.setattr(m, "LXC_PATH", tmp_path / "pas-de-lxc")
    res = asyncio.run(m.create_backup(m.BackupCreate(type="full"), user={"sub": "t"}))
    assert [a[0] for a in appels] == ["config", "services"] and all(a[1] is True for a in appels)
    assert res["code"] == 0 and "config-20261023-000000.tar.gz.age" in res["output"]


def test_create_un_echec_du_ctl_est_un_echec_pas_un_code_zero(tmp_path, monkeypatch):
    import asyncio
    m = _api(tmp_path, monkeypatch)
    monkeypatch.setattr(m, "_archiver", lambda kind, encrypt, nom=None, timeout=900: (False, "tar: /etc/secubox/secrets: Permission denied"))
    res = asyncio.run(m.create_backup(m.BackupCreate(type="config"), user={"sub": "t"}))
    assert res["code"] == 1 and "Permission denied" in res["output"] and "NON créée" in res["output"]


def test_create_refuse_un_destinataire_choisi_par_l_appelant(tmp_path, monkeypatch):
    import asyncio

    from fastapi import HTTPException
    m = _api(tmp_path, monkeypatch)
    monkeypatch.setattr(m, "_archiver", lambda *a, **k: (True, "x"))
    with pytest.raises(HTTPException) as e:
        asyncio.run(m.create_backup(m.BackupCreate(type="config", encrypt_recipient="age1autre"), user={"sub": "t"}))
    assert e.value.status_code == 422


def test_archiver_cote_api_construit_l_argv_exact_du_sudoers(tmp_path, monkeypatch):
    m = _api(tmp_path, monkeypatch)
    vus = []

    def faux_run(cmd, timeout=300):
        vus.append(cmd)
        return True, json.dumps({"ok": True, "fichier": "a.tar.gz.age", "chiffre": True}), ""
    monkeypatch.setattr(m, "run_cmd", faux_run)
    assert m._archiver("config", True) == (True, "a.tar.gz.age")
    assert m._archiver("conteneur", False, nom="web")[0] is True
    assert vus[0] == ["sudo", "-n", "/usr/sbin/backupctl", "archiver", "config", "chiffre"]
    assert vus[1] == ["sudo", "-n", "/usr/sbin/backupctl", "archiver", "conteneur", "web", "clair"]
    ok, msg = m._archiver("conteneur", True, nom="../x")
    assert ok is False and "nom" in msg and len(vus) == 2, "un nom invalide ne part jamais vers sudo"


# ── garde d'espace disque : une sauvegarde ne remplit JAMAIS le disque de la box ──

def test_archiver_refuse_de_commencer_sans_la_reserve_d_espace(tmp_path, monkeypatch):
    m = _ctl(monkeypatch)
    (tmp_path / "etc").mkdir()
    (tmp_path / "etc" / "f").write_text("x")
    lance = []

    class U:
        free = 100 * 1024 * 1024                      # 100 Mo libres, réserve 1 Go

    r = m.archiver("config", None, False, racine=tmp_path / "srv", chemins=[str(tmp_path / "etc")],
                   proprietaire=False, libre=lambda p: U, popen=lambda *a, **k: lance.append(a))
    assert r["ok"] is False and "espace disque" in r["erreur"]
    assert lance == [], "tar n'est même pas lancé"
    assert list((tmp_path / "srv" / "config").iterdir()) == []


def test_archiver_interrompt_tar_et_supprime_le_partiel_quand_le_disque_se_remplit(tmp_path, monkeypatch):
    m = _ctl(monkeypatch)
    (tmp_path / "etc").mkdir()
    (tmp_path / "etc" / "f").write_text("x")
    mo = 1024 * 1024
    libres = iter([2048 * mo, 2048 * mo, 100 * mo, 100 * mo])    # assez au départ, puis le disque se remplit

    class U:
        def __init__(self, free):
            self.free = free

    class FauxTar:
        def __init__(self, cmd, **k):
            self.archive = Path(cmd[2])
            self.archive.write_bytes(b"x" * 1000)       # l'archive partielle existe
            self.tue, self.returncode = False, None

        def poll(self):
            return self.returncode

        def kill(self):
            self.tue, self.returncode = True, -9

        def wait(self, timeout=None):
            return self.returncode

        def communicate(self):
            return "", ""
    faux = {}

    def popen(cmd, **k):
        faux["p"] = FauxTar(cmd, **k)
        return faux["p"]
    r = m.archiver("config", None, False, racine=tmp_path / "srv", chemins=[str(tmp_path / "etc")], proprietaire=False,
                   libre=lambda p: U(next(libres)), popen=popen, intervalle=0)
    assert r["ok"] is False and "espace disque" in r["erreur"]
    assert faux["p"].tue is True
    assert list((tmp_path / "srv" / "config").iterdir()) == [], "l'archive partielle est supprimée"
