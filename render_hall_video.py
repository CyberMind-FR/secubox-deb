#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""
Générateur vidéo 100% fidèle pour SECUBOX HALL
Moteur : FFmpeg natif + PIL (Zéro dépendance MoviePy / Zéro ImageMagick)
"""

import os
import glob
import subprocess
from PIL import Image, ImageDraw, ImageFont

SCREENSHOTS_DIR = "docs/hall-inspection/screenshots"
BUILD_DIR = "build_video"
OUTPUT_FILE = "secubox-entrez-dans-le-hall.mp4"

os.makedirs(BUILD_DIR, exist_ok=True)

def find_font(size):
    candidates = [
        "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
        "/usr/share/fonts/truetype/liberation/LiberationSans-Bold.ttf",
        "/usr/share/fonts/truetype/ubuntu/Ubuntu-B.ttf"
    ]
    for p in candidates:
        if os.path.exists(p):
            return ImageFont.truetype(p, size)
    return ImageFont.load_default()

def create_title_image(text, filename, size=(1920, 1080), fontsize=42, color=(200, 168, 75)):
    img = Image.new("RGB", size, (10, 12, 16))
    draw = ImageDraw.Draw(img)
    font = find_font(fontsize)
    
    # Dessin multi-lignes centré
    lines = text.split("\n")
    total_height = sum(draw.textbbox((0, 0), line, font=font)[3] - draw.textbbox((0, 0), line, font=font)[1] + 20 for line in lines)
    y = (size[1] - total_height) // 2
    
    for line in lines:
        if line.strip():
            bbox = draw.textbbox((0, 0), line, font=font)
            w = bbox[2] - bbox[0]
            h = bbox[3] - bbox[1]
            x = (size[0] - w) // 2
            draw.text((x, y), line, fill=color, font=font)
            y += h + 20
        else:
            y += 30

    out_path = os.path.join(BUILD_DIR, filename)
    img.save(out_path)
    return out_path

def resolve_screenshot(pattern):
    candidates = sorted(glob.glob(os.path.join(SCREENSHOTS_DIR, f"*{pattern}*")))
    if candidates:
        return candidates[0]
    all_pngs = sorted(glob.glob(os.path.join(SCREENSHOTS_DIR, "*.png")))
    return all_pngs[0] if all_pngs else None

def prepare_image(src_path, filename):
    """Met à l'échelle et rogne en 1920x1080 sans déformer l'UI."""
    out_path = os.path.join(BUILD_DIR, filename)
    if not src_path or not os.path.exists(src_path):
        return create_title_image(f"[SOURCE: {filename}]", filename)
        
    pil_img = Image.open(src_path).convert("RGB")
    scale = max(1920 / pil_img.width, 1080 / pil_img.height)
    new_w, new_h = int(pil_img.width * scale), int(pil_img.height * scale)
    pil_img = pil_img.resize((new_w, new_h), Image.Resampling.LANCZOS)
    
    # Crop centré
    x = (new_w - 1920) // 2
    y = (new_h - 1080) // 2
    pil_img = pil_img.crop((x, y, x + 1920, y + 1080))
    pil_img.save(out_path)
    return out_path

def render_segment(img_path, duration_sec, out_segment, zoom=True):
    fps = 60
    total_frames = int(duration_sec * fps)
    
    if zoom:
        # Effet zoom 2.5D propre via zoompan FFmpeg
        vf = (
            f"zoompan=z='min(zoom+0.0004,1.06)':d={total_frames}:x='iw/2-(iw/zoom/2)':y='ih/2-(ih/zoom/2)':s=1920x1080:fps={fps},"
            f"format=yuv420p"
        )
    else:
        vf = f"fps={fps},format=yuv420p"

    cmd = [
        "ffmpeg", "-y",
        "-loop", "1",
        "-t", str(duration_sec),
        "-i", img_path,
        "-vf", vf,
        "-c:v", "libx264",
        "-preset", "fast",
        "-crf", "18",
        out_segment
    ]
    subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)

def main():
    print("[1/4] Préparation des visuels exacts depuis docs/hall-inspection/screenshots/...")
    
    # 1. Images de titres & captures
    t_intro = create_title_image("VOUS VOULEZ VOIR CE QU'IL Y A DANS UNE SECUBOX ?\n\nENTREZ.", "img_00_intro.png", fontsize=38)
    
    img_bienvenue = prepare_image(resolve_screenshot("bienvenue"), "img_01_bienvenue.png")
    img_accueil = prepare_image(resolve_screenshot("accueil"), "img_02_accueil.png")
    img_radio = prepare_image(resolve_screenshot("radio"), "img_03_radio.png")
    img_metanews = prepare_image(resolve_screenshot("metanews") or resolve_screenshot("flux"), "img_04_metanews.png")
    img_parc = prepare_image(resolve_screenshot("tout-le-parc") or resolve_screenshot("pleine-page"), "img_05_parc.png")
    img_surf = prepare_image(resolve_screenshot("surf"), "img_06_surf.png")
    img_acces = prepare_image(resolve_screenshot("acces"), "img_07_acces.png")
    img_erreurs = prepare_image(resolve_screenshot("erreur") or resolve_screenshot("401"), "img_08_erreurs.png")
    
    t_outro = create_title_image("SECUBOX\n\nENTREZ.  EXPLOREZ.  TESTEZ.", "img_09_outro.png", fontsize=46)

    timeline = [
        (t_intro, 5.0, False),
        (img_bienvenue, 7.0, True),
        (img_accueil, 10.0, True),
        (img_radio, 10.0, True),
        (img_metanews, 11.0, True),
        (img_parc, 12.0, True),
        (img_surf, 10.0, True),
        (img_acces, 10.0, True),
        (img_erreurs, 7.0, True),
        (t_outro, 8.0, False),
    ]

    print("[2/4] Encodage des segments vidéo en 1080p60 (avec zoom optique)...")
    concat_list = os.path.join(BUILD_DIR, "concat.txt")
    with open(concat_list, "w") as f:
        for idx, (img_path, duration, zoom) in enumerate(timeline):
            seg_name = os.path.join(BUILD_DIR, f"seg_{idx:02d}.mp4")
            print(f"  -> Segment {idx+1}/{len(timeline)} ({duration}s) : {os.path.basename(img_path)}")
            render_segment(img_path, duration, seg_name, zoom=zoom)
            f.write(f"file '{os.path.abspath(seg_name)}'\n")

    print("[3/4] Vérification de la voix-off...")
    voice_file = "voiceover.mp3"
    if not os.path.exists(voice_file):
        script_text = (
            "Alors n'écoutez pas ce que je vous raconte. Entrez. "
            "Voici le Hall. Pas une page remplie de liens. "
            "Un bureau où les services de la box deviennent des cartes vivantes. "
            "Vous pouvez écouter, regarder, consulter, discuter. "
            "Et certaines cartes vivent réellement en temps réel. "
            "Actualités, podcasts, vidéos, forums, messagerie, contenus. "
            "Le visiteur peut déjà explorer une partie du système sans compte. "
            "Et derrière cette interface, il y a le parc. "
            "Cent treize modules, organisés en six familles. "
            "Même le navigateur peut passer par la box. "
            "Le Hall devient alors une porte vers le Web relayé. "
            "Et si vous voulez aller plus loin, vous demandez un accès. "
            "Certaines fonctions restent derrière une session. "
            "Et non, tout n'est pas parfait. C'est aussi pour ça qu'on vous montre le vrai Hall. "
            "SecuBox. Une petite boîte. Un vrai système. Entrez, explorez, testez."
        )
        cmd_tts = f'edge-tts --voice fr-FR-HenriNeural --text "{script_text}" --write-media {voice_file}'
        subprocess.run(cmd_tts, shell=True, check=False)

    print("[4/4] Concaténation finale et mixage audio...")
    cmd_final = [
        "ffmpeg", "-y",
        "-f", "concat", "-safe", "0", "-i", concat_list
    ]
    if os.path.exists(voice_file):
        cmd_final += [
            "-i", voice_file,
            "-c:v", "copy",
            "-c:a", "aac",
            "-b:a", "192k",
            "-shortest",
            OUTPUT_FILE
        ]
    else:
        cmd_final += ["-c:v", "copy", OUTPUT_FILE]

    subprocess.run(cmd_final, check=True)
    print(f"\n[✓] VIDÉO TERMINÉE AVEC SUCCÈS : {OUTPUT_FILE}")

if __name__ == "__main__":
    main()