# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3182 — meetctl : relevé de l'activité, réunions, en direct, clôture d'une réunion, audit des décisions."""
import json
import sqlite3

from conftest import _ecrire_exec, run_ctl, run_ctl_rc
from test_activite import GANDALF, REELLES, SALLE


def _preparer(tmp_path, journal=(), comptes=None, salles=None):
    (tmp_path / "journal.jsonl").write_text("\n".join(journal) + ("\n" if journal else ""))
    psql = tmp_path / "psql"
    psql.mkdir(exist_ok=True)
    if comptes is not None:
        (psql / "comptes").write_text(comptes)
    if salles is not None:
        (psql / "salles").write_text(salles)


def _activite_simulee(tmp_path):
    """Un faux activite.py : note son argv, rend un JSON d'accord (aucun appel réseau dans ces tests)."""
    faux = tmp_path / "activite-faux.py"
    _ecrire_exec(faux, f'''#!/usr/bin/env python3
import json, sys
open("{tmp_path}/activite-appels", "a").write(" ".join(sys.argv[1:]) + "\\n")
print(json.dumps({{"success": True, "argv": sys.argv[1:]}}))
''')
    return {"SECUBOX_MEET_ACTIVITE_PY": str(faux)}


def test_collecte_de_bout_en_bout_curseur_et_pseudos(tmp_path):
    _preparer(tmp_path, REELLES, comptes=f"{GANDALF}\x1fgandalf\x1e")
    d = json.loads(run_ctl(tmp_path, "activite-collecte"))
    assert d["success"] is True and d["evenements"] == 4
    cx = sqlite3.connect(tmp_path / "activite" / "activite.db")
    assert cx.execute("SELECT COUNT(*) FROM sessions").fetchone()[0] == 2
    assert cx.execute("SELECT pseudo FROM comptes").fetchone()[0] == "gandalf"
    appels = (tmp_path / "urls").read_text()
    assert "journalctl -u livekit -o json --no-pager --since -30 days" in appels      # premier relevé : 30 jours
    assert "psql -d meet -A -t -F" in appels and "meet_user" in appels
    run_ctl(tmp_path, "activite-collecte")
    assert "--after-cursor s=b100;i=3be" in (tmp_path / "urls").read_text()        # ensuite : après le dernier curseur


def test_collecte_conteneur_absent(tmp_path):
    rc, out = run_ctl_rc(tmp_path, "activite-collecte", rootfs=False)
    assert rc == 1 and json.loads(out)["success"] is False


def test_reunions_transmet_les_salles_de_meet(tmp_path):
    _preparer(tmp_path, salles=f"{SALLE}\x1fgii\x1fgii\x1fpublic\x1fgandalf\x1f1\x1f2\x1e")
    env = _activite_simulee(tmp_path)
    d = json.loads(run_ctl(tmp_path, "reunions", env_extra=env))
    assert d["argv"][0] == "reunions" and "--url" in d["argv"] and "http://10.100.0.195:7880" in d["argv"]
    assert "meet_room" in (tmp_path / "urls").read_text()


def test_en_direct(tmp_path):
    env = _activite_simulee(tmp_path)
    assert json.loads(run_ctl(tmp_path, "en-direct", env_extra=env))["argv"][0] == "en-direct"


def test_clore_audite_la_decision(tmp_path):
    env = _activite_simulee(tmp_path)
    d = json.loads(run_ctl(tmp_path, "clore", SALLE, env_extra=env))
    assert d["success"] is True and ["--salle", SALLE] == d["argv"][d["argv"].index("--salle"):d["argv"].index("--salle") + 2]
    ligne = json.loads((tmp_path / "audit.log").read_text().splitlines()[-1])
    assert ligne["module"] == "meet" and ligne["action"] == "clore" and SALLE in ligne["detail"]


def test_clore_refuse_un_nom_invalide_ou_des_arguments_en_trop(tmp_path):
    env = _activite_simulee(tmp_path)
    for args in (["../../etc"], [SALLE, "--autre"], []):
        rc, out = run_ctl_rc(tmp_path, "clore", *args, env_extra=env)
        assert rc == 1 and json.loads(out)["success"] is False
    assert not (tmp_path / "activite-appels").exists() and not (tmp_path / "audit.log").exists()


def test_media_expose_audite_ouverture_et_fermeture(tmp_path):
    (tmp_path / "meet.nft").write_text("table inet secubox-meet {}\n")
    run_ctl(tmp_path, "media-expose", "--apply", nft_ok=True)
    run_ctl(tmp_path, "media-expose", "--revoke", nft_ok=True)
    actions = [json.loads(l)["action"] for l in (tmp_path / "audit.log").read_text().splitlines()]
    assert actions == ["media-expose-ouvrir", "media-expose-fermer"]
