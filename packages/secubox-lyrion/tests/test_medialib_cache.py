# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""medialib detect — cache, verrou, balayage borne (#993).

Sur la board, 7 `find` concurrents ont ete observes sur un disque USB de
931 Go, sur 4 coeurs deja charges : le panneau interroge l'endpoint en boucle
et chaque appel relançait un balayage complet. Tant que la fonctionnalite
etait cassee (elle l'etait), le defaut restait invisible.
"""
import re
import subprocess
from pathlib import Path

CTL = Path(__file__).resolve().parents[1] / "sbin" / "lyrionctl"


def _func(name):
    src = CTL.read_text()
    start = src.index(f"{name}() {{")
    return src[start:src.index("\n}\n", start)]


def test_ctl_is_syntactically_valid():
    assert subprocess.run(["bash", "-n", str(CTL)]).returncode == 0


def test_detect_serves_a_cache():
    """La composition d'un support ne change pas d'une seconde a l'autre."""
    fn = _func("medialib_detect")
    assert "MEDIALIB_CACHE" in fn and "ttl" in fn
    assert "cat \"$cache\"" in fn


def test_detect_holds_an_exclusive_lock():
    """Deux appels simultanes ne doivent jamais lancer deux balayages."""
    fn = _func("medialib_detect")
    assert "flock" in fn, "sans verrou, les scans s'empilent"
    assert re.search(r"flock -w", fn), \
        "le verrou doit ATTENDRE : l'appelant veut le resultat, pas une erreur"


def test_detect_rechecks_the_cache_after_taking_the_lock():
    """Sinon N appelants bloques relancent N balayages a la suite.

    C'est le piege classique du verrou : chacun obtient le verrou a son tour
    et rescanne, alors que le premier vient d'ecrire le cache."""
    fn = _func("medialib_detect")
    after = fn[fn.index("flock -w"):]
    assert "_cache_fresh" in after, \
        "le cache doit etre re-verifie APRES obtention du verrou"


def test_scan_is_time_bounded():
    """`head -n 5000` borne le NOMBRE de resultats, pas la duree de la marche.

    Sur 931 Go en USB, la marche prend des minutes meme sans resultat."""
    fn = _func("_medialib_audio_count")
    assert "timeout" in fn, "le balayage doit etre borne dans le temps"
    assert fn.index("timeout") < fn.index("find"), \
        "le timeout doit encadrer le find"


def test_no_scan_when_saturated_and_no_cache():
    """Mieux vaut une reponse honnete qu'un balayage de plus."""
    fn = _func("medialib_detect")
    assert '"stale":true' in fn


def test_scan_still_runs_when_the_cache_is_unwritable():
    """Renvoyer « rien trouve » parce qu'on n'a pas pu ecrire un verrou est un
    mensonge — et c'est indiscernable d'un support vide cote panneau."""
    fn = _func("medialib_detect")
    assert "else" in fn and fn.count("_medialib_detect_scan") >= 2, \
        "un balayage sans cache doit rester possible"
    tail = fn[fn.index("PAS DE VERROU"):]
    assert "_medialib_detect_scan" in tail
