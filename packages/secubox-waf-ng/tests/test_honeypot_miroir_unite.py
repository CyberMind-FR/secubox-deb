# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""Le drop-in du leurre redéfinit TOUTE la ligne de commande de sbxwaf : il doit rester le miroir de l'unité.

Incident 2026-10-07 : un drapeau (--actor-ban) et un délai (--upstream-timeout 1h) ajoutés à l'unité n'avaient aucun effet sur une box
où le leurre était armé, parce que le drop-in recopié gardait l'ancienne liste. Aucune erreur, aucun signe : le changement n'existait pas.
"""
import re
from pathlib import Path

PKG = Path(__file__).resolve().parents[1]


def _drapeaux(texte):
    # ExecStart= ... jusqu'à la première ligne qui ne continue pas
    m = re.search(r"^ExecStart=/usr/sbin/sbxwaf\b(.*?)(?:\n(?!\s)|\Z)", texte, re.S | re.M)
    bloc = re.sub(r"\\\n", " ", m.group(1))
    out, mots = {}, bloc.split()
    i = 0
    while i < len(mots):
        if mots[i].startswith("--"):
            val = mots[i + 1] if i + 1 < len(mots) and not mots[i + 1].startswith("--") else ""
            out[mots[i]] = val
            i += 2 if val else 1
        else:
            i += 1
    return out


def test_le_dropin_du_leurre_reprend_chaque_drapeau_de_l_unite_avec_la_meme_valeur():
    unite = _drapeaux((PKG / "systemd" / "secubox-waf-ng.service").read_text())
    leurre = _drapeaux((PKG / "conf" / "honeypot.conf").read_text())
    manquants = {k: v for k, v in unite.items() if leurre.get(k, None) != v}
    assert not manquants, f"le modèle du leurre a dérivé de l'unité : {manquants}"


def test_le_leurre_n_ajoute_que_ses_propres_drapeaux():
    unite = _drapeaux((PKG / "systemd" / "secubox-waf-ng.service").read_text())
    leurre = _drapeaux((PKG / "conf" / "honeypot.conf").read_text())
    en_plus = set(leurre) - set(unite)
    assert en_plus <= {"--honeypot", "--honeypot-secret", "--leurre-ban"}, en_plus


def test_rotation_en_propose_et_verdict_differe():
    """#3919 : le détecteur de rotation observe ; `auto` est une décision du propriétaire, dans les deux fichiers à la fois."""
    for f in (PKG / "systemd" / "secubox-waf-ng.service", PKG / "conf" / "honeypot.conf", PKG / "conf" / "actor-intelligence-simulation.conf.example"):
        d = _drapeaux(f.read_text())
        assert d.get("--rotation") == "propose" and d.get("--rotation-verdict") == "differe", f.name


def test_un_seul_processus_porte_le_detecteur_de_rotation():
    """Ailleurs, la page et ses ressources seraient vues par des processus différents (verrou du binaire en plus)."""
    porteurs = [f.name for f in (PKG / "systemd").iterdir() if "--rotation" in f.read_text()]
    assert porteurs == ["secubox-waf-ng.service"], porteurs
