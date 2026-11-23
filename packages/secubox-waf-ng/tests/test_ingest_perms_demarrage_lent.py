# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""Le groupe de la socket d'ingestion doit tenir même si actord met des minutes à démarrer (reconstruction du graphe).

Incident 2026-10-05 : actord a mis ~4 min à ouvrir sa socket ; le script ne cherchait que 12 s, la socket est restée au groupe
`secubox`, sbxwaf n'a plus pu y écrire et l'ingestion est restée muette près de deux jours (carte Sécurité : 0 événement / j).
"""
import os
import stat
import subprocess
import textwrap
from pathlib import Path

PKG = Path(__file__).resolve().parents[1]
SCRIPT = PKG / "sbin" / "secubox-actord-ingest-perms"
UNITE = PKG / "systemd" / "secubox-actord-ingest.service"


def test_l_unite_laisse_assez_de_temps_pour_un_demarrage_lent():
    t = [l for l in UNITE.read_text().splitlines() if l.startswith("TimeoutStartSec=")]
    assert t and int(t[0].split("=")[1].rstrip("s")) >= 600


def test_le_script_attend_une_socket_en_ecoute_et_pas_seulement_un_fichier():
    texte = SCRIPT.read_text()
    assert "ss -xl" in texte, "un fichier de socket périmé n'est pas une socket en écoute"
    assert "FENETRE=24" not in texte


def test_le_script_pose_le_groupe_apres_une_attente(tmp_path):
    """Faux `ss`, `chgrp`, `stat` : la socket n'est « en écoute » qu'au 3e tour ; le groupe doit alors être posé."""
    bin_ = tmp_path / "bin"
    bin_.mkdir()
    etat = tmp_path / "n"
    etat.write_text("0")
    sock = tmp_path / "actord.sock"
    sock.write_text("")
    groupe = tmp_path / "groupe"
    groupe.write_text("secubox")

    def faux(nom, corps):
        p = bin_ / nom
        p.write_text("#!/bin/sh\n" + textwrap.dedent(corps))
        p.chmod(0o755)

    faux("ss", f'n=$(cat {etat}); n=$((n+1)); echo $n > {etat}\n[ "$n" -ge 3 ] && echo "u_str LISTEN 0 1024 {sock} 1 * 0"\nexit 0\n')
    faux("chgrp", f'echo "$1" > {groupe}\n')
    faux("chmod", "exit 0\n")
    faux("sleep", "exit 0\n")
    faux("stat", f'case "$*" in *"%G"*) cat {groupe};; esac\n')
    env = {**os.environ, "PATH": f"{bin_}:{os.environ['PATH']}"}
    # [ -S ] exige une vraie socket : on la crée
    sock.unlink()
    import socket as so
    s = so.socket(so.AF_UNIX)
    s.bind(str(sock))
    try:
        r = subprocess.run(["sh", str(SCRIPT), str(sock), "actord-ingest"], capture_output=True, text=True, env=env, timeout=30)
    finally:
        s.close()
    assert r.returncode == 0 and "posé" in r.stdout and "NON posé" not in r.stdout, r.stdout + r.stderr
    assert groupe.read_text().strip() == "actord-ingest"


# ── #3880 : garde périodique (actord a mis 18 min à ouvrir sa socket le 22/11 : attente dépassée, ingestion muette 25 h) ──
def _banc_garde(tmp_path, ecoute: bool, groupe_initial: str, chgrp_tient: bool = True):
    import socket as so
    bin_ = tmp_path / "bin"
    bin_.mkdir()
    sock = tmp_path / "actord.sock"
    groupe = tmp_path / "groupe"
    groupe.write_text(groupe_initial)
    appels = tmp_path / "appels"

    def faux(nom, corps):
        p = bin_ / nom
        p.write_text("#!/bin/sh\n" + textwrap.dedent(corps))
        p.chmod(0o755)
    faux("ss", f'echo ss >> {appels}\n' + (f'echo "u_str LISTEN 0 1024 {sock} 1 * 0"\n' if ecoute else "") + "exit 0\n")
    faux("chgrp", (f'echo "$1" > {groupe}\n' if chgrp_tient else "exit 1\n"))
    faux("chmod", "exit 0\n")
    faux("sleep", f"echo sleep >> {appels}\nexit 0\n")
    faux("stat", f'case "$*" in *"%G"*) cat {groupe};; esac\n')
    s = so.socket(so.AF_UNIX)
    s.bind(str(sock))
    env = {**os.environ, "PATH": f"{bin_}:{os.environ['PATH']}"}
    try:
        r = subprocess.run(["sh", str(SCRIPT), str(sock), "actord-ingest", "garde"], capture_output=True, text=True, env=env, timeout=10)
    finally:
        s.close()
    return r, groupe.read_text().strip(), (appels.read_text() if appels.exists() else "")


def test_garde_repose_le_groupe_sans_attendre(tmp_path):
    r, g, appels = _banc_garde(tmp_path, ecoute=True, groupe_initial="secubox")
    assert r.returncode == 0 and g == "actord-ingest" and "rétablie" in r.stdout
    assert "sleep" not in appels                         # aucune attente en mode garde


def test_garde_ne_touche_rien_si_deja_bon_ou_pas_en_ecoute(tmp_path):
    (tmp_path / "a").mkdir()
    r, g, _ = _banc_garde(tmp_path / "a", ecoute=True, groupe_initial="actord-ingest")
    assert r.returncode == 0 and r.stdout == "" and g == "actord-ingest"
    (tmp_path / "b").mkdir()
    r, g, _ = _banc_garde(tmp_path / "b", ecoute=False, groupe_initial="secubox")
    assert r.returncode == 0 and g == "secubox"          # pas encore en écoute : l'unité de démarrage s'en occupe


def test_garde_echoue_bruyamment_si_le_groupe_ne_tient_pas(tmp_path):
    r, g, _ = _banc_garde(tmp_path, ecoute=True, groupe_initial="secubox", chgrp_tient=False)
    assert r.returncode == 1 and "muette" in r.stderr


def test_minuterie_de_garde_installee():
    ici = SCRIPT.parents[1]
    svc = (ici / "systemd" / "secubox-actord-ingest-garde.service").read_text()
    tmr = (ici / "systemd" / "secubox-actord-ingest-garde.timer").read_text()
    assert "secubox-actord-ingest-perms /run/secubox/actord.sock actord-ingest garde" in svc and "Type=oneshot" in svc
    assert "OnUnitActiveSec=5min" in tmr and "WantedBy=timers.target" in tmr
    assert "secubox-actord-ingest-garde.timer" in (ici / "debian" / "rules").read_text()
