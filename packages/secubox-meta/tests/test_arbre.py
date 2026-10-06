# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""L'arbre des métapaquets (#1397) : cohérent, couvrant, et le control à jour."""
import importlib.util
import os
import subprocess
import sys

ICI = os.path.dirname(os.path.abspath(__file__))
RACINE = os.path.dirname(ICI)
spec = importlib.util.spec_from_file_location("gen_meta", os.path.join(RACINE, "gen-meta.py"))
gm = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gm)


def _etat():
    depot = gm.paquets_du_depot(exclure_source="secubox-meta")
    noeuds, hors = gm.lit_arbre()
    return depot, noeuds, hors


def test_arbre_valide_et_couvrant():
    depot, noeuds, hors = _etat()
    assert gm.valide(noeuds, hors, depot) == []


def test_control_genere_a_jour():
    r = subprocess.run([sys.executable, os.path.join(RACINE, "gen-meta.py"), "--check"],
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stderr


def test_deux_racines_imbriquees():
    _, noeuds, _ = _etat()
    m = {n["meta"]: n for n in noeuds}
    assert {n["meta"] for n in noeuds if n["niveau"] == "racine"} == {"sbxos", "secubox"}
    assert "secubox" in m["sbxos"]["requiert"]            # le Hall pose la box
    assert "secubox-service-hall" in m["sbxos"]["requiert"]


def test_le_courrier_absorbe_ses_trois_anciens_paquets():
    depot, noeuds, hors = _etat()
    r = gm.resolu(noeuds, hors, depot)
    assert set(r["paquets"]["secubox-mail"]["absorbe"]) >= {
        "secubox-mail-lxc", "secubox-webmail", "secubox-webmail-lxc"}


def test_refus():
    depot, noeuds, hors = _etat()
    import copy
    # arm64 seul en Depends
    n2 = copy.deepcopy(noeuds)
    svc = next(n for n in n2 if n["meta"] == "secubox-service-assistant")
    svc["suggere"].remove("secubox-zia-llm"); svc["requiert"].append("secubox-zia-llm")
    assert any("arm64" in e for e in gm.valide(n2, hors, depot))
    # cycle
    n3 = copy.deepcopy(noeuds)
    next(n for n in n3 if n["meta"] == "secubox-fonction-socle")["recommande"].append("secubox")
    assert any(e.startswith("cycle") for e in gm.valide(n3, hors, depot))
    # module neuf oublié
    d2 = dict(depot); d2["secubox-neuf"] = dict(depot["secubox-mail"], transitionnel=False)
    assert any("secubox-neuf" in e for e in gm.valide(noeuds, hors, d2))
    # transitionnel rangé
    n4 = copy.deepcopy(noeuds)
    next(n for n in n4 if n["meta"] == "secubox-service-mail")["recommande"].append("secubox-webmail")
    assert any("transitionnel" in e for e in gm.valide(n4, [h for h in hors if h != "secubox-webmail"], depot))


# ── LE HALL ENTIER (#1577) ─────────────────────────────────────────────────
# `apt install sbxos` doit poser tout module qui a une carte dans le Hall :
# Lyrion, Mastodon, Torrent, YTSaS, Zigbee et Mood n'étaient que suggérés, et
# une box neuve montrait un Hall troué. Chaque entrée FEATURED du Hall doit
# mener à un paquet atteint par requiert/recommande depuis sbxos.

import re  # noqa: E402

HALL = os.path.join(RACINE, "..", "secubox-webos", "www", "hall", "index.html")

# Entrée du Hall → paquet qui la sert, quand le nom ne suffit pas.
PAQUET_DE = {
    "securite": "secubox-waf", "acteurs": "secubox-waf-ng",
    "contenu": "secubox-droplet", "depot": "secubox-droplet",
    "cloud": "secubox-nextcloud", "nextcloud-super": "secubox-nextcloud",
    "forums": "secubox-bbs",
    "activite": "secubox-sbxid", "comptes": "secubox-sbxid", "acces": "secubox-sbxid",
    "sbxos": "secubox-sbxos", "surfviewer": "secubox-webos", "mood": "sbxos-audio-mood",
    # Le Coffre : la carte d'admin (/vault/) et « Mon coffre » (/coffre/) sont deux pages du MÊME
    # paquet, secubox-vault ; le défaut « secubox-<id> » désignait des paquets qui n'existent pas.
    "coffre": "secubox-vault", "mon-coffre": "secubox-vault",
    # La carte « Voix » (dire, dicter) est servie par secubox-voice ; « secubox-voix » n'existe pas.
    "voix": "secubox-voice",
}

# Cartes dont le paquet ne peut PAS être requis par sbxos : il n'existe qu'en amd64, et un requiert
# le rendrait non installable sur une box arm64. Il reste suggéré (VoiceStudio vit sur gk3, #1917).
SUGGERE_SEULEMENT = {"voicestudio": "secubox-voicestudio"}


def _installe_par_sbxos(noeuds):
    m = {n["meta"]: n for n in noeuds}
    vus = set()

    def va(x):
        for lien in ("requiert", "recommande"):
            for c in m.get(x, {}).get(lien, []):
                if c not in vus:
                    vus.add(c)
                    va(c)
    va("sbxos")
    return vus


def test_sbxos_pose_tout_le_hall():
    _, noeuds, _ = _etat()
    pose = _installe_par_sbxos(noeuds)
    texte = open(HALL, encoding="utf-8").read()
    ids = re.findall(r'\{id:"([a-z0-9-]+)",\s*label:"', texte)
    assert len(ids) >= 25, "liste du Hall introuvable"
    manquants = []
    for i in sorted(set(ids)):
        p = PAQUET_DE.get(i, f"secubox-{i}")
        if SUGGERE_SEULEMENT.get(i) == p:
            continue
        if p not in pose:
            manquants.append(f"{i} → {p}")
    assert not manquants, "cartes du Hall que sbxos n'installe pas : " + ", ".join(manquants)


def test_le_hub_vivant_est_dans_l_arbre_pas_hors_arbre():
    """#2050 : secubox-hub générait le menu du Hall mais était classé « remplacé »."""
    depot, noeuds, hors = _etat()
    assert "secubox-hub" not in hors
    hall = next(n for n in noeuds if n.get("meta") == "secubox-service-hall")
    assert "secubox-hub" in hall["requiert"]
