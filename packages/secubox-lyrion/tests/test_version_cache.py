# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Cache de version et `version-status` (#993).

`check-upgrade` sort vers le reseau. Appele depuis le chemin de requete du
panneau, il le prendrait en otage a chaque affichage et le rendrait dependant
d'une panne DNS ou d'un depot lent. Le minuteur quotidien ecrit le cache, le
panneau le lit.

Regle qui compte le plus : un echec reseau ne doit JAMAIS etre memorise comme
« a jour ». Ecrire latest=current apres un echec ferait disparaitre une mise a
jour disponible du panneau, en silence — le pire mode de defaillance pour une
fonction dont le seul role est de signaler.
"""
import json
import subprocess
from pathlib import Path

CTL = Path(__file__).resolve().parents[1] / "sbin" / "lyrionctl"


def _run(args, env):
    return subprocess.run(["bash", str(CTL)] + args,
                          capture_output=True, text=True, env=env, timeout=60)


def _env(tmp_path, cache):
    return {
        "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
        "SECUBOX_LYRION_VERSION_CACHE": str(cache),
        "HOME": str(tmp_path),
    }


def test_version_status_without_cache_reports_unknown_latest(tmp_path):
    """Sans cache, on annonce qu'on ne sait pas — plutot que de pretendre etre
    a jour."""
    cache = tmp_path / "version.json"
    r = _run(["version-status"], _env(tmp_path, cache))
    assert r.returncode == 0, r.stderr
    d = json.loads(r.stdout)
    assert d["latest"] is None
    assert d["available"] is False
    assert d["cached"] is False


def test_version_status_reads_the_cache_without_network(tmp_path):
    cache = tmp_path / "version.json"
    cache.write_text(json.dumps({"current": "9.1.0", "latest": "9.1.1",
                                 "available": True, "checked_at": "2026-08-06T05:00:00+02:00"}))
    r = _run(["version-status"], _env(tmp_path, cache))
    d = json.loads(r.stdout)
    assert d["latest"] == "9.1.1"
    assert d["cached"] is True
    assert d["checked_at"].startswith("2026-08-06")


def test_current_is_reread_live_not_taken_from_the_cache(tmp_path):
    """Le cache peut dater d'AVANT un upgrade. Afficher une version courante
    obsolete apres coup serait pire que ne rien afficher : l'utilisateur
    croirait sa mise a jour perdue."""
    src = CTL.read_text()
    i = src.index("cmd_version_status")
    window = src[i:i + 1400]
    assert 'd["current"] = cur' in window, (
        "current doit etre relu en direct, pas repris du cache"
    )


def test_a_failed_lookup_is_never_cached(tmp_path):
    """La garde la plus importante du fichier."""
    src = CTL.read_text()
    i = src.index("cmd_check_upgrade")
    window = src[i:i + 1600]
    assert 'if [ -n "$latest" ]; then' in window, (
        "le cache ne doit etre ecrit que si la version distante a ete obtenue"
    )


def test_current_falls_back_to_cache_when_live_read_is_unavailable(tmp_path):
    """L'API tourne en `secubox` et ne peut pas interroger la LXC : la lecture
    live de la version installee y revient VIDE. Sans repli, le panneau
    afficherait une version courante vide — constate sur la board.

    L'ordre est donc : live d'abord (il peut refleter un upgrade que le cache
    ignore), cache ensuite, jamais le blanc."""
    src = CTL.read_text()
    i = src.index("cmd_version_status")
    window = src[i:i + 1800]
    assert 'd["current"] = cur or d.get("current") or ""' in window, (
        "current doit se replier sur le cache quand la lecture live echoue"
    )


def test_action_endpoints_require_a_token(tmp_path):
    """`upgrade` redemarre le serveur de musique et coupe toute lecture en
    cours. Le reste de cette API est volontairement sans jeton — decision
    anterieure du module, protegee par la porte LAN de nginx — mais une action
    de cette portee ne doit pas etre declenchable par le seul fait d'etre sur
    le reseau local.

    Constate en verifiant : POST /api/v1/lyrion/check-upgrade repondait 200
    sans aucun jeton, la ou l'equivalent PeerTube repondait 401."""
    api = Path(__file__).resolve().parents[1] / "api" / "main.py"
    src = api.read_text()
    for verb in ("check-upgrade", "upgrade"):
        i = src.index(f'@app.post("/{verb}")')
        sig = src[i:i + 240]
        assert "Depends(require_jwt)" in sig, f"/{verb} doit exiger un jeton"
