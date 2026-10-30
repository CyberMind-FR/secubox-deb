# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Correction 1 de la relecture de sécurité du moteur en couches (ref #3290)."""
import json
import logging
import os
import pwd
import re
import subprocess
import sys
import time
from pathlib import Path

import pytest

PKG = Path(__file__).resolve().parents[1]
REPO = PKG.parents[1]
sys.path.insert(0, str(PKG / "usr" / "lib" / "secubox-led-heartbeat"))

import ledcouches as lc  # noqa: E402

MOI = pwd.getpwuid(os.getuid()).pw_name


def jauge(p, **kw):
    return lc.SourceJaugeJson("v", {"chemin": str(p), "cle": "a", "seuils": [1, 2, 3],
                                     "fraicheur_max": 0, "proprietaires": [MOI], **kw})


# ---------- 1. ouverture sûre ----------

def test_json_lien_symbolique_refuse(tmp_path):
    vrai = tmp_path / "vrai.json"
    vrai.write_text(json.dumps({"a": 5}))
    lien = tmp_path / "lien.json"
    lien.symlink_to(vrai)
    assert jauge(vrai).lire(0) == 3
    assert jauge(lien).lire(0) is None


def test_json_fifo_ne_bloque_pas(tmp_path):
    f = tmp_path / "fifo"
    os.mkfifo(f)
    t = time.monotonic()
    assert jauge(f).lire(0) is None
    assert time.monotonic() - t < 1


def test_json_enorme_refuse(tmp_path):
    p = tmp_path / "gros.json"
    p.write_text('{"a": 5, "b": "' + "x" * (lc.TAILLE_MAX_JSON + 10) + '"}')
    assert jauge(p).lire(0) is None


def test_json_proprietaire_inattendu_refuse(tmp_path):
    if os.getuid() == 0:
        pytest.skip("propriétaire root")
    p = tmp_path / "m.json"
    p.write_text(json.dumps({"a": 5}))
    assert jauge(p, proprietaires=["root"]).lire(0) is None


def test_json_inscriptible_par_tous_refuse(tmp_path):
    p = tmp_path / "m.json"
    p.write_text(json.dumps({"a": 5}))
    os.chmod(p, 0o666)
    assert jauge(p).lire(0) is None


# ---------- 2 et 3. JSON piégé : jamais de plantage, jamais vert ----------

@pytest.mark.parametrize("contenu", [
    "[" * 100000 + "]" * 100000,                 # RecursionError
    '{"a": ' + "9" * 400 + "}",                   # OverflowError au float()
    '{"a": NaN}', '{"a": Infinity}', '{"a": -Infinity}', '{"a": 1e400}',
    '{"a": "texte"}', '{"a": [1]}', '{"a": null}', "[1, 2]", '"nu"',
])
def test_json_piege_inconnu(tmp_path, contenu):
    p = tmp_path / "m.json"
    p.write_text(contenu)
    assert jauge(p).lire(0) is None
    c = lc.SourceCompteurJson("c", {"chemin": str(p), "cle": "a", "seuils": [1, 2, 3],
                                    "fraicheur_max": 0, "proprietaires": [MOI]})
    assert c.lire(0) is None and c.lire(60) is None


def test_cle_non_texte_inconnu(tmp_path):
    p = tmp_path / "m.json"
    p.write_text(json.dumps({"a": 5}))
    assert jauge(p, cle=5).lire(0) is None


def test_alertes_pieges(tmp_path):
    p = tmp_path / "alerts.json"
    for contenu in ["[" * 100000 + "]" * 100000, '{"alerts": 5}', '"x"', "[1, null]"]:
        p.write_text(contenu)
        s = lc.SourceAlertes("alertes", {"chemin": str(p), "seuils": [1, 3, 10],
                                         "fraicheur_max": 0, "vivant": "",
                                         "proprietaires": [MOI]})
        r = s.lire(0)
        assert r is None or r == 0


# ---------- 4. alertes : fraîcheur et SOC vivant ----------

def test_alertes_fraicheur_par_defaut():
    assert lc.SOURCES_DEFAUT["alertes"]["fraicheur_max"] > 0
    assert lc.SOURCES_DEFAUT["alertes"]["vivant"]


def test_alertes_soc_mort_inconnu(tmp_path):
    p = tmp_path / "alerts.json"
    p.write_text("[]")
    vivant = tmp_path / "soc.sock"
    s = lc.SourceAlertes("alertes", {"chemin": str(p), "seuils": [1, 3, 10],
                                     "vivant": str(vivant), "proprietaires": [MOI]})
    assert s.lire(0) is None
    vivant.write_text("")
    assert s.lire(1) == 0


def test_alertes_perimees_inconnu(tmp_path):
    p = tmp_path / "alerts.json"
    p.write_text("[]")
    os.utime(p, (1, 1))
    s = lc.SourceAlertes("alertes", {"chemin": str(p), "seuils": [1, 3, 10],
                                     "fraicheur_max": 3600, "vivant": "",
                                     "proprietaires": [MOI]})
    assert s.lire(0) is None


def test_horodatage_interne_prime_sur_mtime(tmp_path):
    p = tmp_path / "m.json"
    p.write_text(json.dumps({"a": 5, "timestamp_epoch": int(time.time())}))
    os.utime(p, (1, 1))
    assert jauge(p, fraicheur_max=300).lire(0) == 3
    p.write_text(json.dumps({"a": 5, "timestamp_epoch": 1}))
    assert jauge(p, fraicheur_max=300).lire(0) is None


# ---------- 5. validation de config par types ----------

@pytest.mark.parametrize("toml", [
    'couleurs = 5\n',
    'sources = "x"\n',
    '[sources.cpu]\ntype = ["cpu"]\n',
    '[sources.cpu]\ntype = { a = 1 }\n',
    '[sources.attaques]\nchemin = 5\n',
    '[sources.attaques]\ncle = ["waf"]\n',
    '[sources.attaques]\nfraicheur_max = "x"\n',
    '[sources.attaques]\nproprietaires = "root"\n',
    'moteur = 3\n',
    'couche = 3\n',
    'couche = [1, "x"]\n',
    '[[couche]]\nnom = ["x"]\nsources = ["cpu"]\nleds = "1"\n',
])
def test_config_types_invalides_defauts(tmp_path, caplog, toml):
    caplog.set_level(logging.WARNING)
    p = tmp_path / "leds.toml"
    p.write_text(toml)
    cfg = lc.charger_config(p)
    assert cfg.couches
    assert cfg.debit_max == lc.DEFAUT_DEBIT
    for s in cfg.sources.values():
        assert isinstance(s.chemin, Path) and isinstance(s.cle, str)
    assert [r for r in caplog.records if r.name == "secubox-led"]


def test_debit_max_borne_a_50(tmp_path):
    p = tmp_path / "leds.toml"
    p.write_text("[moteur]\ndebit_max = 80\n")
    assert lc.charger_config(p).debit_max == lc.DEFAUT_DEBIT
    p.write_text("[moteur]\ndebit_max = 50\n")
    assert lc.charger_config(p).debit_max == 50


def test_config_inscriptible_par_autrui_refusee(tmp_path, caplog):
    caplog.set_level(logging.WARNING)
    p = tmp_path / "leds.toml"
    p.write_text("[moteur]\ndebit_max = 7\n")
    os.chmod(p, 0o666)
    cfg = lc.charger_config(p, exiger_root=True)
    assert cfg.debit_max == lc.DEFAUT_DEBIT
    assert any("inscriptible" in r.getMessage() or "propriétaire" in r.getMessage()
               for r in caplog.records)


# ---------- minor : espacement minimal ----------

def test_espacement_minimal_entre_ecritures():
    pauses, ecr = [], []

    class E:
        def ecrire(self, c, v):
            ecr.append(c)
    r = lc.Rendu(E(), debit_max=50, horloge=lambda: 0.0, pause=pauses.append)
    r.afficher([(1, 2, 3)] * 3)
    assert len(ecr) == 9
    assert len([p for p in pauses if p >= 0.01]) >= 8


# ---------- 7. reprise sans systemd-run ----------

def test_reprise_par_code_de_sortie_et_on_failure():
    src = (PKG / "usr/lib/secubox-led-heartbeat/ledcouches.py").read_text()
    assert "systemd-run" not in src and "subprocess" not in src
    assert lc.CODE_REPRISE == 75
    unite = (PKG / "systemd/secubox-led-pulse.service").read_text()
    assert "OnFailure=secubox-led-reprise.service" in unite
    assert "RestartPreventExitStatus=75" in unite
    rep = (PKG / "systemd/secubox-led-reprise.service").read_text()
    assert "ExecStart=/usr/sbin/secubox-led-reset" in rep
    assert "StartLimitBurst=1" in rep and "StartLimitIntervalSec=600" in rep
    rules = (PKG / "debian/rules").read_text()
    assert "secubox-led-reprise.service" in rules
    reset = (PKG / "usr/sbin/secubox-led-reset").read_text()
    assert "reset-failed secubox-led-pulse" in reset


def test_servir_sort_en_75_apres_erreurs(tmp_path, monkeypatch):
    base = tmp_path / "leds"
    for i in (1, 2, 3):
        for c in lc.COULEURS:
            d = base / f"{c}:led{i}"
            d.mkdir(parents=True)
            (d / "brightness").mkdir()           # écriture impossible : IsADirectoryError
            (d / "trigger").write_text("")
    cfg = lc.charger_config(None)
    cfg.base = str(base)
    monkeypatch.setattr(lc.time, "sleep", lambda d: None)
    assert lc.servir(cfg) == lc.CODE_REPRISE


# ---------- 6. unité et AppArmor ----------

def test_unite_durcie():
    u = (PKG / "systemd/secubox-led-pulse.service").read_text()
    for opt in ("UMask=0027", "RestrictSUIDSGID=yes", "ProtectKernelLogs=yes",
                "RestrictNamespaces=yes", "PrivateDevices=yes", "NoNewPrivileges=yes",
                "ProtectSystem=strict", "ProtectHome=yes", "PrivateTmp=yes",
                "ProtectControlGroups=yes", "LockPersonality=yes", "AppArmorProfile="):
        assert opt in u, opt
    assert re.search(r"^MemoryMax=\d+M$", u, re.M)


def test_exception_root_ecrite_dans_rules_code():
    regles = (REPO / ".claude/RULES-CODE.md").read_text()
    lignes = [li for li in regles.splitlines() if "secubox-led-pulse.service" in li]
    assert lignes and "ProtectKernelTunables" in lignes[0] and "test_couches_correction1_3290" in lignes[0]


def test_profil_apparmor():
    prof = (PKG / "apparmor/secubox-led-pulse").read_text()
    assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in prof
    assert "/usr/sbin/secubox-led-pulse" in prof
    assert re.search(r"/sys/devices/\S*leds/\S*brightness\S* r?w,", prof)
    assert "deny /etc/secubox/secrets/** r," in prof
    assert " ix," not in prof.replace("python3* rix", "")   # aucun autre exécutable
    assert "/var/cache/secubox/metrics-cache.json r," in prof
    rules = (PKG / "debian/rules").read_text()
    assert "etc/apparmor.d/secubox-led-pulse" in rules
    post = (PKG / "debian/postinst").read_text()
    assert "apparmor_parser -r /etc/apparmor.d/secubox-led-pulse" in post
    assert "chown root:root /etc/secubox/leds.toml" in post and "chmod 0644 /etc/secubox/leds.toml" in post


# ---------- 8. demo : trap ----------

def _faux_env(tmp_path, stop_rc=0, pulse_corps="exit 0", actif=True):
    b = tmp_path / "bin"
    b.mkdir()
    journal = tmp_path / "journal"
    (b / "systemctl").write_text(
        f'#!/bin/sh\necho "systemctl $*" >> {journal}\n'
        f'case "$*" in *is-active*) exit {0 if actif else 3};; stop*) exit {stop_rc};; esac\nexit 0\n')
    (b / "pulse").write_text(f'#!/bin/sh\necho "pulse $*" >> {journal}\n{pulse_corps}\n')
    for f in b.iterdir():
        f.chmod(0o755)
    env = dict(os.environ, PATH=f"{b}:{os.environ['PATH']}", SECUBOX_TEST="1",
               SECUBOX_LED_PULSE=str(b / "pulse"))
    return env, journal


SCRIPT = str(PKG / "usr/sbin/secubox-led")


@pytest.mark.skipif(os.getuid() == 0, reason="variables de test refusées en root")
def test_demo_relance_le_service(tmp_path):
    env, j = _faux_env(tmp_path)
    r = subprocess.run(["bash", SCRIPT, "demo", "mono"], env=env, capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    log = j.read_text()
    assert "systemctl stop secubox-led-pulse.service" in log
    assert log.strip().endswith("systemctl start secubox-led-pulse.service")


@pytest.mark.skipif(os.getuid() == 0, reason="variables de test refusées en root")
def test_demo_tuee_relance_quand_meme(tmp_path):
    env, j = _faux_env(tmp_path, pulse_corps="kill -TERM $PPID; sleep 5")
    subprocess.run(["bash", SCRIPT, "demo", "mono"], env=env, capture_output=True, timeout=10)
    assert j.read_text().strip().endswith("systemctl start secubox-led-pulse.service")


@pytest.mark.skipif(os.getuid() == 0, reason="variables de test refusées en root")
def test_demo_stop_echoue_pas_de_second_ecrivain(tmp_path):
    env, j = _faux_env(tmp_path, stop_rc=1)
    r = subprocess.run(["bash", SCRIPT, "demo", "mono"], env=env, capture_output=True, text=True)
    assert r.returncode != 0
    log = j.read_text()
    assert "pulse demo" not in log
    assert log.strip().endswith("systemctl start secubox-led-pulse.service")


@pytest.mark.skipif(os.getuid() == 0, reason="variables de test refusées en root")
def test_demo_service_inactif_non_relance(tmp_path):
    env, j = _faux_env(tmp_path, actif=False)
    subprocess.run(["bash", SCRIPT, "demo", "mono"], env=env, capture_output=True)
    assert "systemctl start" not in j.read_text()


def test_demo_python_eteint_sur_sigterm():
    src = (PKG / "usr/lib/secubox-led-heartbeat/ledcouches.py").read_text()
    assert "signal.SIGHUP" in src
