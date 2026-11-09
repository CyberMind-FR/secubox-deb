# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""Bouton « Réparer » de la page Santé (#3628) : secubox-reparerctl avec un systemctl et un dpkg factices."""
from __future__ import annotations

import json
import os
import stat
import subprocess
from pathlib import Path

CTL = Path(__file__).resolve().parents[1] / "sbin" / "secubox-reparerctl"

# systemctl factice : l'état de chaque unité vit dans $FAUX/<unite>.etat (« LoadState ActiveState SubState Result ») ;
# chaque appel est noté dans $FAUX/appels. `start` passe l'unité à l'état écrit dans $FAUX/<unite>.apres.
FAUX_SYSTEMCTL = r"""#!/usr/bin/env bash
echo "$*" >> "$FAUX/appels"
case "$1" in
  show) prop=$3; unite=${@: -1}
        f="$FAUX/$unite.etat"; [ -f "$f" ] || { case $prop in LoadState) echo not-found;; *) echo inactive;; esac; exit 0; }
        read -r l a s r < "$f"
        case $prop in LoadState) echo "$l";; ActiveState) echo "$a";; SubState) echo "$s";; Result) echo "$r";; esac ;;
  reset-failed) unite=${@: -1}; read -r l a s r < "$FAUX/$unite.etat"; echo "$l inactive dead success" > "$FAUX/$unite.etat" ;;
  start) unite=${@: -1}; [ -f "$FAUX/$unite.apres" ] && cp "$FAUX/$unite.apres" "$FAUX/$unite.etat" ;;
esac
exit 0
"""

FAUX_DPKG = r"""#!/usr/bin/env bash
echo "dpkg $*" >> "$FAUX/appels"
case "$*" in
  --audit) [ -f "$FAUX/dpkg-casse" ] && echo "secubox-premier-pas  half-configured" ;;
  *--configure*) rm -f "$FAUX/dpkg-casse"; exit "${DPKG_RC:-0}" ;;
esac
exit 0
"""


def _exe(p: Path, texte: str) -> None:
    p.write_text(texte)
    p.chmod(p.stat().st_mode | stat.S_IXUSR)


def _env(tmp: Path) -> dict:
    faux = tmp / "faux"
    faux.mkdir(exist_ok=True)
    _exe(faux / "systemctl", FAUX_SYSTEMCTL)
    _exe(faux / "dpkg", FAUX_DPKG)
    (tmp / "spool").mkdir(exist_ok=True)
    (tmp / "updates").mkdir(exist_ok=True)
    env = dict(os.environ)
    env.update({
        "FAUX": str(faux),
        "SECUBOX_REPARER_SYSTEMCTL": str(faux / "systemctl"),
        "SECUBOX_REPARER_DPKG": str(faux / "dpkg"),
        "SECUBOX_REPARER_SPOOL": str(tmp / "spool"),
        "SECUBOX_REPARER_ETAT": str(tmp / "etat" / "reparer.json"),
        "SECUBOX_REPARER_JOURNAL": str(tmp / "reparer.log"),
        "SECUBOX_AUDIT_LOG": str(tmp / "audit.log"),
        "SECUBOX_REPARER_VERROU": str(tmp / "verrou"),
        "SECUBOX_REPARER_DPKG_UPDATES": str(tmp / "updates"),
        "SECUBOX_REPARER_ATTENTE_S": "2",
        "SECUBOX_REPARER_PAS_S": "1",
    })
    return env


def _unite(tmp: Path, nom: str, etat: str, apres: str | None = None) -> None:
    (tmp / "faux" / f"secubox-{nom}.service.etat").write_text(etat + "\n")
    if apres:
        (tmp / "faux" / f"secubox-{nom}.service.apres").write_text(apres + "\n")


def _run(env, *args):
    return subprocess.run(["bash", str(CTL), *args], env=env, capture_output=True, text=True, timeout=60)


def _etat(tmp: Path) -> dict:
    return json.loads((tmp / "etat" / "reparer.json").read_text())


def _appels(tmp: Path) -> str:
    p = tmp / "faux" / "appels"
    return p.read_text() if p.exists() else ""


def _audit(tmp: Path) -> list:
    p = tmp / "audit.log"
    return [json.loads(ligne) for ligne in p.read_text().splitlines()] if p.exists() else []


def test_unite_en_panne_relancee_et_auditee(tmp_path):
    env = _env(tmp_path)
    _unite(tmp_path, "majauto", "loaded failed failed exit-code", apres="loaded active running success")
    r = _run(env, "reparer", "majauto", "gk2")
    assert r.returncode == 0, r.stdout + r.stderr
    e = _etat(tmp_path)["modules"]["majauto"]
    assert e["ok"] is True and e["phase"] == "fini"
    appels = _appels(tmp_path)
    assert "reset-failed -- secubox-majauto.service" in appels
    assert "start --no-block -- secubox-majauto.service" in appels
    assert "--configure" not in appels            # dpkg sain : rien à reprendre
    a = _audit(tmp_path)
    assert len(a) == 1 and a[0]["event"] == "sante_reparation" and a[0]["acteur"] == "gk2" and a[0]["ok"] is True


def test_dpkg_interrompu_termine_avant_la_relance(tmp_path):
    env = _env(tmp_path)
    (tmp_path / "faux" / "dpkg-casse").write_text("")
    _unite(tmp_path, "majauto", "loaded failed failed exit-code", apres="loaded active running success")
    r = _run(env, "reparer", "majauto", "gk2")
    assert r.returncode == 0, r.stdout + r.stderr
    appels = _appels(tmp_path).splitlines()
    i_conf = next(i for i, ligne in enumerate(appels) if "--configure -a" in ligne)
    i_start = next(i for i, ligne in enumerate(appels) if ligne.startswith("start"))
    assert i_conf < i_start
    assert "dpkg : configuration terminée" in _etat(tmp_path)["modules"]["majauto"]["etapes"]


def test_dpkg_en_echec_ne_relance_pas(tmp_path):
    env = _env(tmp_path)
    env["DPKG_RC"] = "1"
    (tmp_path / "updates" / "0001").write_text("")
    _unite(tmp_path, "majauto", "loaded failed failed exit-code", apres="loaded active running success")
    r = _run(env, "reparer", "majauto", "gk2")
    assert r.returncode == 1
    assert not [ligne for ligne in _appels(tmp_path).splitlines() if ligne.startswith(("start", "reset-failed"))]
    assert _etat(tmp_path)["modules"]["majauto"]["ok"] is False
    assert _audit(tmp_path)[0]["ok"] is False


def test_service_sain_jamais_relance(tmp_path):
    env = _env(tmp_path)
    _unite(tmp_path, "hub", "loaded active running success")
    r = _run(env, "reparer", "hub", "gk2")
    assert r.returncode == 1
    appels = _appels(tmp_path)
    assert "start" not in appels and "reset-failed" not in appels
    assert "pas en panne" in _etat(tmp_path)["modules"]["hub"]["message"]


def test_unite_inconnue_et_identifiant_invalide(tmp_path):
    env = _env(tmp_path)
    assert _run(env, "reparer", "inexistant", "gk2").returncode == 1
    for mauvais in ("../etc", "Hub", "a b", "-x", "", "x" * 70):
        r = _run(env, "reparer", mauvais, "gk2")
        assert r.returncode == 2, mauvais
    assert "start" not in _appels(tmp_path)


def test_retombe_en_panne(tmp_path):
    env = _env(tmp_path)
    _unite(tmp_path, "mail", "loaded failed failed exit-code", apres="loaded failed failed exit-code")
    r = _run(env, "reparer", "mail", "gk2")
    assert r.returncode == 1
    assert "retombe en panne" in _etat(tmp_path)["modules"]["mail"]["message"]


def test_tache_ponctuelle_terminee(tmp_path):
    env = _env(tmp_path)
    _unite(tmp_path, "majauto", "loaded failed failed exit-code", apres="loaded inactive dead success")
    r = _run(env, "reparer", "majauto", "gk2")
    assert r.returncode == 0, r.stdout + r.stderr
    assert "sans erreur" in _etat(tmp_path)["modules"]["majauto"]["message"]


def test_tache_longue_en_cours(tmp_path):
    env = _env(tmp_path)
    _unite(tmp_path, "majauto", "loaded failed failed exit-code", apres="loaded activating start success")
    r = _run(env, "reparer", "majauto", "gk2")
    assert r.returncode == 0
    assert "en cours" in _etat(tmp_path)["modules"]["majauto"]["message"]


def test_process_ops_draine_et_assainit(tmp_path):
    env = _env(tmp_path)
    _unite(tmp_path, "majauto", "loaded failed failed exit-code", apres="loaded active running success")
    spool = tmp_path / "spool"
    (spool / "1-majauto.demande").write_text("reparer majauto gk2;rm$(id)\n")
    (spool / "2-x.demande").write_text("shell rm -rf /\n")
    cible = tmp_path / "cible"
    cible.write_text("reparer majauto lien\n")
    (spool / "3-lien.demande").symlink_to(cible)
    r = _run(env, "process-ops")
    assert r.returncode == 0
    assert json.loads(r.stdout)["traitees"] == 1
    assert not list(spool.iterdir())
    assert cible.exists()                          # le lien est retiré, sa cible jamais lue ni touchée
    a = _audit(tmp_path)
    assert len(a) == 1 and a[0]["acteur"] == "gk2rmid"


def test_audit_ne_suit_pas_un_lien(tmp_path):
    env = _env(tmp_path)
    victime = tmp_path / "victime"
    victime.write_text("intact\n")
    (tmp_path / "audit.log").symlink_to(victime)
    _unite(tmp_path, "majauto", "loaded failed failed exit-code", apres="loaded active running success")
    _run(env, "reparer", "majauto", "gk2")
    assert victime.read_text() == "intact\n"
