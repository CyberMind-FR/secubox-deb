# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Task 13 (#4058) : capture d'admin masquée, contrôle OCR bloquant, validation visuelle.

Sans Playwright/chromium ni tesseract sur le poste, la prise de vue et l'OCR sont remplacés par des faux : le faux
navigateur « rend » la page factice en ne gardant que le texte hors des sélecteurs masqués.
"""
import asyncio
import html
import re

import pytest
from PIL import Image, PngImagePlugin

from emissions.capture import capturer, captures_validees, enregistrer_capture, lire_masques, valider_capture

PAGE = ('<div class="ip">10.1.2.3</div><pre>journal 10.9.9.9</pre>'
        '<p>Dernier visiteur : 192.0.2.7</p><p>Bans du jour : 1 204</p>')
NOMS = ["gk0", "gk2"]


def faux_navigateur(page):
    async def nav(url, zone, selecteurs, sortie):
        # masquage simulé : les éléments dont la balise ou la classe figure dans les sélecteurs disparaissent
        n, visible = 0, page
        for s in selecteurs:
            m = re.fullmatch(r"([a-z]+)|\.([\w-]+)", s)
            if not m:
                continue
            motif = (rf"<{m[1]}\b[^>]*>.*?</{m[1]}>" if m[1]
                     else rf'<(\w+) class="{re.escape(m[2])}">.*?</\1>')
            visible, k = re.subn(motif, "", visible)
            n += k
        texte = html.unescape(re.sub(r"<[^>]+>", " ", visible))
        meta = PngImagePlugin.PngInfo()
        meta.add_text("dessine", texte)
        Image.new("RGB", (64, 32), "white").save(sortie, pnginfo=meta)
        return n
    return nav


def faux_ocr(chemin):
    return Image.open(chemin).text["dessine"]


def _capturer(tmp_path, page, url="http://127.0.0.1:9000/admin"):
    return asyncio.run(capturer(url, "#principal", tmp_path / "b/c1.png", navigateur=faux_navigateur(page),
                                ocr=faux_ocr, noms_internes=NOMS))


def test_capture_refusee_si_ocr(tmp_path):
    r = _capturer(tmp_path, PAGE)
    assert r["masques"] == 2                       # .ip et pre masqués
    assert r["etat"] == "refusee"
    assert {"ou": "image:c1.png", "motif": "ipv4"} in r["controle"]
    enregistrer_capture(tmp_path / "b", "c1", r)
    with pytest.raises(ValueError):
        valider_capture(tmp_path / "b", "c1", True)
    assert captures_validees(tmp_path / "b") == []


def test_capture_propre_a_valider(tmp_path):
    r = _capturer(tmp_path, PAGE.replace("192.0.2.7", "un robot"))
    assert r["etat"] == "a_valider" and r["controle"] == []
    enregistrer_capture(tmp_path / "b", "c1", r)
    assert captures_validees(tmp_path / "b") == []          # rien sans l'accord du propriétaire
    assert valider_capture(tmp_path / "b", "c1", True) == "validee"
    assert captures_validees(tmp_path / "b") == ["c1.png"]


def test_url_hors_liste_refusee(tmp_path):
    for url in ("https://exemple.org/admin", "http://user@127.0.0.1/admin", "file:///etc/passwd",
                "http://127.0.0.1.exemple.org/"):
        with pytest.raises(ValueError):
            _capturer(tmp_path, PAGE, url)
    assert not (tmp_path / "b/c1.png").exists()


def test_masques_toml():
    m = lire_masques()
    assert "127.0.0.1" in m["hotes"] and "pre" in m["selecteurs"] and ".ip" in m["selecteurs"]
