# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2028 — des cookies que YouTube refuse (HTTP 403 sur les données vidéo) ne doivent pas faire
échouer les vidéos PUBLIQUES, qui n'en ont pas besoin : le moteur retente sans cookies et marque
les cookies périmés. Constaté sur gk2 : toute la radio écartée par un cookies.txt déposé le jour même."""
import asyncio
import os
import pathlib
import sys
import tempfile

os.environ.setdefault("YTSAS_DOWNLOAD_DIR", tempfile.mkdtemp())
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "lxc" / "app"))
from engine import Engine  # noqa: E402

FAUX = r'''#!/bin/sh
# Faux yt-dlp : refuse (403) tout appel portant --cookies, sert sinon un fichier.
out=""; cookies=0
while [ $# -gt 0 ]; do
  [ "$1" = "-o" ] && out="$2"
  [ "$1" = "--cookies" ] && cookies=1
  shift
done
echo "$cookies" >> "$(dirname "$0")/appels"
if [ "$cookies" = "1" ]; then
  echo "ERROR: unable to download video data: HTTP Error 403: Forbidden" >&2
  exit 1
fi
f=$(echo "$out" | sed "s/%(id)s/abc/; s/%(ext)s/mp4/")
echo x > "$f"
echo "[download] 100% of 1KiB"
exit 0
'''


class FauxLibrary:
    def __init__(self):
        self.complets = []

    def set_complete(self, vid, ok, path=None):
        self.complets.append((vid, ok, path))


def _moteur(tmp_path, avec_cookies):
    faux = tmp_path / "yt-dlp"
    faux.write_text(FAUX)
    faux.chmod(0o755)
    cookies = tmp_path / "cookies.txt"
    if avec_cookies:
        cookies.write_text("# Netscape HTTP Cookie File\n")
    lib = FauxLibrary()
    eng = Engine(str(tmp_path / "dl"), lib, str(cookies), ytdlp_bin=str(faux))
    eng.jobs["abc"] = {"status": "downloading", "progress": 0.0}
    (tmp_path / "dl" / "abc").mkdir(parents=True)
    return eng, lib


def _telecharger(eng, tmp_path):
    asyncio.run(eng._download("abc", "https://www.youtube.com/watch?v=abc", str(tmp_path / "dl" / "abc")))


def _appels(tmp_path):
    f = tmp_path / "appels"
    return f.read_text().split() if f.exists() else []


def test_403_avec_cookies_retente_sans_cookies(tmp_path):
    eng, lib = _moteur(tmp_path, avec_cookies=True)
    _telecharger(eng, tmp_path)
    assert _appels(tmp_path) == ["1", "0"]          # d'abord avec, puis sans
    assert eng.jobs["abc"]["status"] == "complete"
    assert lib.complets and lib.complets[0][0] == "abc"
    assert eng.cookies_stale is True                # les cookies sont signalés périmés


def test_sans_cookies_aucun_repli_inutile(tmp_path):
    eng, lib = _moteur(tmp_path, avec_cookies=False)
    _telecharger(eng, tmp_path)
    assert _appels(tmp_path) == ["0"]
    assert eng.jobs["abc"]["status"] == "complete"
    assert eng.cookies_stale is False


def test_un_vrai_403_sans_cookies_reste_une_erreur(tmp_path):
    # Si même l'essai sans cookies échoue, l'erreur reste visible (pas de boucle).
    eng, lib = _moteur(tmp_path, avec_cookies=False)
    (tmp_path / "yt-dlp").write_text('#!/bin/sh\necho "ERROR: unable to download video data: HTTP Error 403: Forbidden" >&2\nexit 1\n')
    _telecharger(eng, tmp_path)
    assert eng.jobs["abc"]["status"] == "error" and "403" in eng.jobs["abc"]["error"]
