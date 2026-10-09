# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2192 (box) : rapport final — construit sans secret, affiché à l'écran, diffusé à l'infrastructure sans jamais arrêter le parcours."""
import json
import os
import sys
from pathlib import Path

import pytest

ICI = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ICI))
sys.path.insert(0, str(ICI.parent / "secubox-premier-pas"))
from autoload_agent import client as C, moteur as M, rapport as R  # noqa: E402
from test_moteur_2187 import monde, moteur, FauxExecuteur, FauxEnroleur, TUNNEL  # noqa: E402,F401  (fixtures)

RAP = {"client": "client-042", "profil": "lite", "paquets": ["secubox-core", "secubox-ad-guard"], "domaine": "client042.secubox.in", "comptes": ["admin"],
       "tunnel_adresse": "10.64.0.2/32", "debut": 1_800_000_000, "fin": 1_800_000_900, "etapes": ["reponses", "cle"]}


def test_le_texte_dit_l_essentiel_sans_secret_ni_adresse_de_tunnel():
    t = R.texte(RAP)
    assert "prêt" in t and "client042.secubox.in" in t and "Lite" in t and "15 minutes" in t and "secubox-ad-guard" in t
    assert "10.64.0.2" not in t and "argon2" not in t and "gk2_" not in t


def test_le_texte_borne_la_liste_des_paquets():
    t = R.texte({**RAP, "paquets": [f"secubox-p{i}" for i in range(300)]})
    assert t.count("secubox-p") <= 40 and "300 paquets" in t


def test_l_ecran_ecrit_le_message_d_accueil_si_le_dossier_existe(tmp_path):
    R.ecrire_issue(RAP, tmp_path)
    f = tmp_path / "50-secubox-autoload.issue"
    assert f.is_file() and "prêt" in f.read_text() and oct(f.stat().st_mode & 0o777) == "0o644"
    R.ecrire_issue(RAP, tmp_path / "absent")                                   # dossier absent : rien, sans erreur
    assert not (tmp_path / "absent").exists()


def test_le_client_poste_le_rapport_dans_le_tunnel():
    vus = []

    class Faux:
        def __call__(self, requete, timeout=None, context=None):
            vus.append((requete.get_method(), requete.full_url, json.loads(requete.data)))

            class Rep:
                status = 200

                def read(self, n=-1):
                    return b'{"ok": true, "envoye": true}'

                def __enter__(self):
                    return self

                def __exit__(self, *a):
                    return False
            return Rep()
    assert C.ClientInfra(ouvrir=Faux()).rapport(RAP) is True
    assert vus[0][:2] == ("POST", "http://10.64.0.1:8470/rapport") and vus[0][2] == RAP


def test_le_parcours_construit_diffuse_et_ecrit_un_rapport_complet(monde):
    diffuses = []
    m = M.Moteur(monde.cfg, executeur=monde.ex, enroleur=monde.en, valideur=lambda p: True, diffuseur=diffuses.append)
    assert m.run().ok
    rap = diffuses[0]
    assert rap["client"] == "client-042" and rap["profil"] == "lite" and rap["domaine"] == "client042.secubox.in" and rap["comptes"] == ["admin"]
    assert rap["paquets"] == ["secubox-core", "secubox-ad-guard", "secubox-lite"] and rap["tunnel_adresse"] == "10.64.0.2/32"
    assert rap["fin"] >= rap["debut"] > 0 and rap["etapes"] == list(M.ETAPES)
    assert json.loads(monde.cfg.rapport.read_text()) == rap
    assert set(rap) == {"client", "profil", "paquets", "domaine", "comptes", "tunnel_adresse", "debut", "fin", "etapes"}        # exactement ce que l'infrastructure accepte
    brut = monde.cfg.rapport.read_text()
    assert "a" * 32 not in brut and "argon2" not in brut and "autoload-jeton" not in brut


def test_une_diffusion_en_panne_n_arrete_pas_le_parcours_et_le_rapport_reste_sur_la_box(monde):
    def casse(rap):
        raise OSError("tunnel coupé")
    assert M.Moteur(monde.cfg, executeur=monde.ex, enroleur=monde.en, valideur=lambda p: True, diffuseur=casse).run().ok
    assert monde.cfg.rapport.is_file()


def test_la_cli_affiche_le_dernier_rapport(tmp_path):
    import subprocess
    (tmp_path / "rapport.json").write_text(json.dumps(RAP))
    env = dict(os.environ, SECUBOX_AUTOLOAD_AGENT_DOSSIER=str(tmp_path))
    r = subprocess.run([sys.executable, str(ICI / "sbin" / "autoload-agentctl"), "rapport"], capture_output=True, text=True, env=env)
    assert r.returncode == 0 and "client042.secubox.in" in r.stdout
    vide = subprocess.run([sys.executable, str(ICI / "sbin" / "autoload-agentctl"), "rapport"], capture_output=True, text=True, env=dict(env, SECUBOX_AUTOLOAD_AGENT_DOSSIER=str(tmp_path / "vide")))
    assert vide.returncode == 1 and "aucun rapport" in vide.stderr
