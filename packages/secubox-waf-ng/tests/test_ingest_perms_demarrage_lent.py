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
