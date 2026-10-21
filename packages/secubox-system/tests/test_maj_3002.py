# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3002 — mises à jour apt : l'API (secubox, servie par l'agrégateur) dépose une demande, l'unité root la draine.

« E: Could not open lock file /var/lib/dpkg/lock-frontend … are you root? » : apt-get ne se lance plus depuis l'API.
"""
import importlib.util
import json
import os
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

SYSTEM = Path(__file__).resolve().parents[1]
CTL = SYSTEM / "sbin" / "secubox-majctl"
sys.path.insert(0, str(SYSTEM.parents[1] / "common"))

APT = r'''#!/usr/bin/env bash
# doublure d'apt-get : journalise l'appel, simule une liste, applique si demande
echo "$*" >> "$APT_JOURNAL"
case " $* " in
  *" update "*) [ -f "$APT_PANNE" ] && { echo "E: Impossible de récupérer http://depot/InRelease" >&2; exit 100; }; echo "Hit:1 http://depot trixie InRelease"; exit 0 ;;
  *" -s upgrade "*) if [ -f "$APT_FAIT" ]; then echo "Reading package lists..."; else printf 'Reading package lists...\nInst secubox-hub [1.10.2] (1.11.0 apt.secubox.in:trixie [all])\nInst libssl3t64 [3.5.1] (3.5.2 Debian:13.7/stable [arm64])\nConf secubox-hub (1.11.0)\n'; fi; exit 0 ;;
  *" upgrade "*) echo "Setting up secubox-hub (1.11.0) ..."; touch "$APT_FAIT"; exit 0 ;;
esac
exit 2
'''


@pytest.fixture
def env(tmp_path):
    bin_ = tmp_path / "bin"
    bin_.mkdir()
    (bin_ / "apt-get").write_text(APT)
    (bin_ / "apt-get").chmod(0o755)
    (tmp_path / "spool").mkdir()
    return {"PATH": f"{bin_}:" + os.environ.get("PATH", "/usr/bin:/bin"), "HOME": str(tmp_path),
            "SECUBOX_MAJ_ETAT": str(tmp_path / "etat" / "maj.json"), "SECUBOX_MAJ_SPOOL": str(tmp_path / "spool"),
            "SECUBOX_MAJ_JOURNAL": str(tmp_path / "maj.log"), "SECUBOX_MAJ_VERROU": str(tmp_path / "maj.lock"),
            "APT_JOURNAL": str(tmp_path / "apt.calls"), "APT_PANNE": str(tmp_path / "panne"), "APT_FAIT": str(tmp_path / "fait")}


def ctl(env, *args):
    p = subprocess.run(["bash", str(CTL), *args], capture_output=True, text=True, env=env, timeout=60)
    return p.returncode, p.stdout


def etat(env):
    return json.loads(Path(env["SECUBOX_MAJ_ETAT"]).read_text())


# ── le ctl ──────────────────────────────────────────────────────────────────
def test_verifier_fait_update_puis_simule_et_ecrit_l_etat(env):
    rc, out = ctl(env, "verifier")
    assert rc == 0 and json.loads(out)["ok"]
    e = etat(env)
    assert e["phase"] == "idle" and e["derniere"] == "verifier" and e["ok"] is True
    assert e["paquets"] == ["secubox-hub", "libssl3t64"] and e["count"] == 2 and e["fin"] >= e["debut"] > 0
    appels = Path(env["APT_JOURNAL"]).read_text()
    assert "update" in appels and "-s upgrade" in appels and "DPkg::Lock::Timeout" in appels
    assert oct(Path(env["SECUBOX_MAJ_ETAT"]).stat().st_mode & 0o777) == "0o644"       # lisible par l'API (autre compte)


def test_verifier_en_panne_dit_pourquoi(env):
    Path(env["APT_PANNE"]).touch()
    rc, out = ctl(env, "verifier")
    assert rc != 0 and json.loads(out)["ok"] is False
    e = etat(env)
    assert e["ok"] is False and "InRelease" in e["erreur"] and e["phase"] == "idle"


def test_appliquer_fait_upgrade_sans_dist_upgrade_ni_autoremove(env):
    rc, out = ctl(env, "appliquer")
    assert rc == 0 and json.loads(out)["appliques"] == 2
    e = etat(env)
    assert e["derniere"] == "appliquer" and e["ok"] is True and e["appliques"] == 2 and e["count"] == 0
    appels = Path(env["APT_JOURNAL"]).read_text()
    assert "upgrade -y" in appels and "force-confold" in appels
    assert "dist-upgrade" not in appels and "autoremove" not in appels and "full-upgrade" not in appels
    assert "Setting up secubox-hub" in Path(env["SECUBOX_MAJ_JOURNAL"]).read_text()


def test_process_ops_draine_le_spool_et_retire_les_demandes_avant_d_agir(env):
    sp = Path(env["SECUBOX_MAJ_SPOOL"])
    (sp / "1-verifier.demande").write_text("verifier\n")
    (sp / "2-bidon.demande").write_text("rm -rf /\n")
    rc, out = ctl(env, "process-ops")
    assert rc == 0 and json.loads(out)["traitees"] == 1
    assert list(sp.iterdir()) == [] and etat(env)["derniere"] == "verifier"
    assert "ignoree" in Path(env["SECUBOX_MAJ_JOURNAL"]).read_text()


def test_le_ctl_n_est_pas_dans_un_sudoers_et_les_unites_sont_livrees():
    assert not list(SYSTEM.glob("debian/*sudoers*")) or "majctl" not in "".join(p.read_text() for p in SYSTEM.glob("debian/*sudoers*"))
    path = (SYSTEM / "systemd" / "secubox-maj.path").read_text()
    svc = (SYSTEM / "systemd" / "secubox-maj.service").read_text()
    assert "DirectoryNotEmpty=/run/secubox/system/maj" in path and "Unit=secubox-maj.service" in path
    assert "Type=oneshot" in svc and "User=" not in svc and "secubox-majctl process-ops" in svc
    rules = (SYSTEM / "debian" / "rules").read_text()
    assert "secubox-maj.path" in rules and "secubox-majctl" in rules and "tmpfiles.d/secubox-system.conf" in rules
    assert "dh_installsystemd" in rules and "secubox-maj.path" in rules.rsplit("dh_installsystemd", 1)[1]
    assert "/run/secubox/system/maj" in (SYSTEM / "tmpfiles.d" / "secubox-system.conf").read_text()


# ── l'API ───────────────────────────────────────────────────────────────────
def charge_api(tmp_path, monkeypatch, attente="5"):
    monkeypatch.setenv("SECUBOX_MAJ_SPOOL", str(tmp_path / "spool"))
    monkeypatch.setenv("SECUBOX_MAJ_ETAT", str(tmp_path / "maj.json"))
    monkeypatch.setenv("SECUBOX_MAJ_ATTENTE_S", attente)
    spec = importlib.util.spec_from_file_location("api_systeme_3002", SYSTEM / "api" / "main.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def faux_ctl(tmp_path, verbe, ok=True, delai=0.5):
    """Joue le rôle de l'unité root : consomme la demande puis écrit l'état."""
    def run():
        sp = tmp_path / "spool"
        for _ in range(100):
            d = list(sp.glob("*.demande")) if sp.exists() else []
            if d:
                assert d[0].read_text().strip() == verbe
                d[0].unlink()
                break
            time.sleep(0.05)
        time.sleep(delai)
        (tmp_path / "maj.json").write_text(json.dumps({"phase": "idle", "derniere": verbe, "ok": ok, "debut": int(time.time()) - 1,
                                                       "fin": int(time.time()), "erreur": None if ok else "E: dépôt injoignable",
                                                       "paquets": ["secubox-hub"], "count": 1, "appliques": 0}))
    t = threading.Thread(target=run, daemon=True)
    t.start()
    return t


def test_check_updates_depose_une_demande_et_lit_le_resultat_du_ctl(tmp_path, monkeypatch):
    api = charge_api(tmp_path, monkeypatch)
    appels = []
    monkeypatch.setattr(api.subprocess, "run", lambda *a, **k: appels.append(a) or (_ for _ in ()).throw(AssertionError("apt depuis l'API")))
    t = faux_ctl(tmp_path, "verifier")
    r = api.check_updates(user={"sub": "admin"})
    t.join()
    assert r["packages"] == ["secubox-hub"] and r["count"] == 1 and appels == []


def test_check_updates_sans_unite_root_repond_504_explicite(tmp_path, monkeypatch):
    api = charge_api(tmp_path, monkeypatch, attente="2")
    from fastapi import HTTPException
    with pytest.raises(HTTPException) as ex:
        api.check_updates(user={"sub": "admin"})
    assert ex.value.status_code == 504 and "secubox-maj.path" in ex.value.detail
    assert list((tmp_path / "spool").glob("*.demande"))        # la demande attend l'unité


def test_check_updates_remonte_l_echec_d_apt(tmp_path, monkeypatch):
    api = charge_api(tmp_path, monkeypatch)
    from fastapi import HTTPException
    faux_ctl(tmp_path, "verifier", ok=False)
    with pytest.raises(HTTPException) as ex:
        api.check_updates(user={"sub": "admin"})
    assert ex.value.status_code == 502 and "injoignable" in ex.value.detail


def test_apply_updates_lance_en_arriere_plan_et_refuse_le_doublon(tmp_path, monkeypatch):
    api = charge_api(tmp_path, monkeypatch)
    r = api.apply_updates(user={"sub": "admin"})
    assert r["success"] and r["suivi"] == "/maj_status"
    d = list((tmp_path / "spool").glob("*.demande"))
    assert len(d) == 1 and d[0].read_text().strip() == "appliquer"
    (tmp_path / "maj.json").write_text(json.dumps({"phase": "appliquer", "derniere": "appliquer", "ok": False, "debut": int(time.time()),
                                                   "fin": 0, "erreur": None, "paquets": [], "count": 0, "appliques": 0}))
    from fastapi import HTTPException
    with pytest.raises(HTTPException) as ex:
        api.apply_updates(user={"sub": "admin"})
    assert ex.value.status_code == 409
    s = api.maj_status(user={"sub": "admin"})
    assert s["en_cours"] is True and s["phase"] == "appliquer"


def test_l_api_ne_lance_plus_apt_elle_meme():
    src = (SYSTEM / "api" / "main.py").read_text(encoding="utf-8")
    assert '"apt-get"' not in src and "'apt-get'" not in src and '"apt"' not in src


def test_la_page_suit_la_mise_a_niveau():
    page = (SYSTEM / "www" / "system" / "index.html").read_text(encoding="utf-8")
    assert "'/maj_status'" in page and "'/check_updates'" in page and "'/apply_updates'" in page and "en_cours" in page
