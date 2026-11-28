# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Task 12 (#4058) : balayage final bloquant (textes et images par OCR).

Sans tesseract sur le poste, l'OCR est remplacé par un faux qui lit le texte dessiné, rangé dans un bloc tEXt du
PNG ; le même test tourne avec le vrai tesseract quand il est présent.
"""
import shutil

import pytest
from PIL import Image, ImageDraw, ImageFont, PngImagePlugin

from emissions.balayage import balayer, lire_noms_internes

NOMS = ["gk0", "gk2", ".lan"]


def _png(chemin, texte):
    img = Image.new("RGB", (900, 200), "white")
    try:
        police = ImageFont.truetype("DejaVuSans.ttf", 64)
    except OSError:
        police = ImageFont.load_default()
    ImageDraw.Draw(img).text((20, 60), texte, fill="black", font=police)
    meta = PngImagePlugin.PngInfo()
    meta.add_text("dessine", texte)
    img.save(chemin, pnginfo=meta)
    return chemin


def faux_ocr(chemin):
    return Image.open(chemin).text["dessine"]


OCRS = [faux_ocr] + ([None] if shutil.which("tesseract") else [])


@pytest.mark.parametrize("ocr", OCRS, ids=lambda o: "faux" if o else "tesseract")
def test_balayage_bloque_ip_dans_png(tmp_path, ocr):
    img = _png(tmp_path / "diapo-01.png", "Source 192.0.2.7")
    r = balayer(["Titre propre"], [img], NOMS, ocr=ocr)
    assert {"ou": "image:diapo-01.png", "motif": "ipv4"} in r
    assert all("192.0.2.7" not in str(x) for x in r)   # jamais recopié


def test_texte_propre_vide(tmp_path):
    img = _png(tmp_path / "d.png", "1 204 bans en 3 vagues")
    textes = ["La campagne compte 1 204 bans le 24/11 à 06:00:00.", "Version 1.2.3 du moteur.",
              "Opérateur OVH, 61 %."]
    assert balayer(textes, [img], NOMS, ocr=faux_ocr) == []


def test_motifs_textes():
    textes = ["vu depuis 2001:db8::1", "sur gk2 ce matin", "le poste nas.lan", "jeton eyJhbGciOiJIUzI1NiJ9",
              "clé " + "a1" * 20, "ip 10.0.0.1"]
    r = balayer(textes, [], NOMS)
    assert [x["motif"] for x in r] == ["ipv6", "nom_interne", "nom_interne", "jeton", "jeton", "ipv4"]


def test_ocr_echec_bloque(tmp_path):
    abime = tmp_path / "abime.png"
    abime.write_bytes(b"pas une image")

    def ocr_qui_casse(_):
        raise RuntimeError("illisible")

    assert balayer([], [abime], NOMS, ocr=ocr_qui_casse) == [{"ou": "image:abime.png", "motif": "ocr_echec"}]


def test_noms_internes_fichier(tmp_path):
    f = tmp_path / "noms.txt"
    f.write_text("# noms\ngk3\n.intra  # domaine\n\n")
    assert lire_noms_internes(f) == ["gk3", ".intra"]
    assert "gk0" in lire_noms_internes(tmp_path / "absent.txt")
