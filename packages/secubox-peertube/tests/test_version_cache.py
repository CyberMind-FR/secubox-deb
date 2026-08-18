# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""PeerTube — cache de version et `version-status` (#993).

Meme dispositif que Lyrion, pour la meme raison : `check-upgrade` interroge
l'API GitHub. Appele dans le chemin de requete du panneau, il le rendrait
dependant d'une limite de debit GitHub ou d'une panne DNS, a chaque affichage.

La garde qui compte : un echec reseau ne doit JAMAIS etre memorise comme « a
jour ». Ecrire latest=current apres un echec ferait disparaitre une mise a jour
disponible, en silence — le pire mode de defaillance pour une fonction dont le
seul role est de signaler.
"""
import json
import subprocess
from pathlib import Path

CTL = Path(__file__).resolve().parents[1] / "sbin" / "peertubectl"


def _run(args, env):
    return subprocess.run(["bash", str(CTL)] + args,
                          capture_output=True, text=True, env=env, timeout=60)


def _env(tmp_path, cache):
    return {
        "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
        "SECUBOX_PEERTUBE_VERSION_CACHE": str(cache),
        "HOME": str(tmp_path),
    }


def test_version_status_without_cache_says_unknown(tmp_path):
    """Sans cache, on annonce qu'on ne sait pas — plutot que de pretendre etre
    a jour."""
    cache = tmp_path / "version.json"
    r = _run(["version-status"], _env(tmp_path, cache))
    assert r.returncode == 0, r.stderr
    d = json.loads(r.stdout)
    assert d["latest"] is None
    assert d["available"] is False
    assert d["cached"] is False


def test_version_status_reads_the_cache(tmp_path):
    cache = tmp_path / "version.json"
    cache.write_text(json.dumps({"current": "8.2.2", "latest": "8.2.3",
                                 "available": True,
                                 "checked_at": "2026-08-06T04:50:00+02:00"}))
    r = _run(["version-status"], _env(tmp_path, cache))
    d = json.loads(r.stdout)
    assert d["latest"] == "8.2.3"
    assert d["cached"] is True
    assert d["available"] is True


def test_a_failed_lookup_is_never_cached(tmp_path):
    src = CTL.read_text()
    i = src.index("cmd_check_upgrade")
    window = src[i:i + 2000]
    assert 'if [ -n "$latest" ]; then' in window, (
        "le cache ne doit etre ecrit que si la version distante a ete obtenue"
    )


def test_current_falls_back_to_cache(tmp_path):
    """L'API tourne en `secubox` et ne peut pas interroger la LXC : la lecture
    live revient vide. Sans repli, le panneau afficherait un champ vide —
    constate sur Lyrion avant correction."""
    src = CTL.read_text()
    i = src.index("cmd_version_status")
    window = src[i:i + 1600]
    assert 'd["current"] = cur or d.get("current") or ""' in window


def test_upgrade_is_never_triggered_by_the_timer(tmp_path):
    """Le minuteur sert a SAVOIR. Un upgrade PeerTube migre la base et
    reconstruit : il reste declenche par l'operateur."""
    unit = Path(__file__).resolve().parents[1] / "debian" / "secubox-peertube-version-check.service"
    body = unit.read_text()
    assert "check-upgrade" in body
    assert "peertubectl upgrade" not in body, (
        "le minuteur ne doit jamais appliquer une mise a jour"
    )
