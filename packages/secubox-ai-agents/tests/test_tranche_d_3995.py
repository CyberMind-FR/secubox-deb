# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Tranche D (#3995) : filtre de contenu, file de création, image reçue ; vision et génération RÉELLES quand présentes."""
import base64
import json
import os
import subprocess
import time
from pathlib import Path

import pytest

pytest.importorskip("openjarvis", reason="OpenJarvis absent : tests à lancer avec /opt/secubox-ai-agents/venv/bin/python (README)")

from conftest import MOTEUR, PAQUET  # noqa: E402

# PNG 1×1 réel (blanc)
PNG = base64.b64decode("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAIAAACQd1PeAAAADElEQVR4nGP4//8/AAX+Av4N70a4AAAAAElFTkSuQmCC")
SD = Path.home() / "poc-secubox-ai/sdcpp/build/bin/sd-cli"
SD15 = Path.home() / "AI/models/sd/checkpoints/stable-diffusion-v1-5-pruned-emaonly-Q8_0.gguf"


def test_filtre_par_defaut():
    from agents.creation import filtrer
    assert filtrer("un phare breton au coucher du soleil, aquarelle") is None
    assert filtrer("un menu de restaurant") is None                      # « nu » en mot entier seulement
    for p in ("une femme nue", "NSFW anime", "scène gore", "portrait de Emmanuel Macron", "drapeau nazi"):
        assert filtrer(p) is not None, p


def test_file_journal_sans_texte_et_annulation(tmp_path):
    from agents.creation import Creations
    c = Creations(tmp_path)
    with pytest.raises(PermissionError):
        c.demander("une femme nue", "sd15", 512)
    d = c.demander("un chat roux sur un toit", "sd15", 512, negatif="flou")
    assert d["etat"] == "en_attente" and (tmp_path / "file" / f"{d['id']}.json").is_file()
    with pytest.raises(ValueError):
        c.demander("un chat", "sd15", 1024)                                # SD 1.5 : 512 seulement
    journal = (tmp_path / "journal.jsonl").read_text()
    assert "chat roux" not in journal and "femme" not in journal           # jamais le texte de la demande
    assert [json.loads(ligne)["evenement"] for ligne in journal.splitlines()] == ["refus", "demande"]
    assert c.annuler(d["id"]) and not c.annuler(d["id"])
    assert c.lister()[0]["etat"] == "echec"
    assert c.fichier("../../etc/passwd") is None


def test_image_reconnue_par_ses_octets(tmp_path):
    from agents import vision
    octets, ext, mime = vision.decoder(base64.b64encode(PNG).decode())
    assert (ext, mime) == ("png", "image/png")
    for mauvais in (base64.b64encode(b"<svg></svg>").decode(), "pas du base64 !"):
        with pytest.raises(ValueError):
            vision.decoder(mauvais)
    ident = vision.garder(tmp_path, octets, ext)
    f = tmp_path / "images" / f"{ident}.png"
    assert f.read_bytes() == PNG and oct(f.stat().st_mode & 0o777) == "0o600"


def test_unites_sans_lien_avec_poc_llama():
    for nom in ("secubox-ai-images-gk0.service", "secubox-ai-eval-moteur-gk0.service", "secubox-ai-agents-gk0.service"):
        lignes = [x for x in (PAQUET / "systemd" / nom).read_text().splitlines() if not x.startswith("#")]
        assert not [x for x in lignes if "poc-llama" in x], nom
    t = (PAQUET / "systemd/secubox-ai-images-gk0.service").read_text().splitlines()
    assert "RestrictAddressFamilies=AF_UNIX" in t and "NoNewPrivileges=yes" in t


def _vision():
    from agents.vision import vision_disponible
    return Path(MOTEUR).is_socket() and vision_disponible(MOTEUR)


@pytest.mark.skipif(not _vision(), reason="moteur sans projecteur vision : test réel impossible ici")
def test_vision_reelle_lit_le_texte(client, tmp_path):
    # Image réelle : texte rendu par Pillow (Python du système) ; sans lui, test sauté.
    img = tmp_path / "t.png"
    code = ("import sys; from PIL import Image, ImageDraw, ImageFont;"
            "f = ImageFont.truetype('/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf', 44);"
            "im = Image.new('RGB', (520, 120), 'white'); ImageDraw.Draw(im).text((20, 30), 'SECUBOX 2026', fill='black', font=f);"
            "im.save(sys.argv[1])")
    if subprocess.run(["/usr/bin/python3", "-I", "-c", code, str(img)], capture_output=True).returncode != 0:
        pytest.skip("Pillow ou la police DejaVu absents pour fabriquer l'image de test")
    r = client.post("/image", json={"image": base64.b64encode(img.read_bytes()).decode(), "action": "lire"})
    assert r.status_code == 200
    texte = "".join(json.loads(x[6:]).get("morceau", "") for x in r.text.splitlines() if x.startswith("data: "))
    assert "SECUBOX" in texte.upper() and "2026" in texte, texte


@pytest.mark.skipif(not (SD.is_file() and SD15.is_file()), reason="stable-diffusion.cpp ou SD 1.5 absent")
def test_creation_reelle_sd15(tmp_path):
    """Le vrai travailleur, sur une file temporaire : une image 512, puis l'arrêt propre remet la suivante en file."""
    racine = tmp_path / "images"
    env = {**os.environ, "SECUBOX_AI_IMAGES_RACINE": str(racine)}
    from agents.creation import Creations
    c = Creations(racine)
    d = c.demander("un phare sur une falaise, peinture à l'huile", "sd15", 512, graine=42)
    p = subprocess.Popen(["/usr/bin/python3", "-I", str(PAQUET / "sbin/secubox-ai-images")], env=env)
    try:
        fin = time.time() + 900
        while time.time() < fin and not (racine / "fait" / f"{d['id']}.png").exists():
            assert not list((racine / "echec").glob("*.json")), "génération en échec"
            time.sleep(3)
        png = racine / "fait" / f"{d['id']}.png"
        assert png.is_file() and png.read_bytes()[:8] == b"\x89PNG\r\n\x1a\n"
        fiche = json.loads((racine / "fait" / f"{d['id']}.json").read_text())
        assert fiche["duree_s"] > 0 and fiche["peripherique"] in ("nvidia", "cpu")
        # Arrêt propre en pleine génération : la demande revient dans la file.
        d2 = c.demander("une forêt sous la neige", "sd15", 512, graine=7)
        time.sleep(8)
        p.terminate()
        p.wait(60)
        assert (racine / "file" / f"{d2['id']}.json").is_file()
    finally:
        if p.poll() is None:
            p.kill()
