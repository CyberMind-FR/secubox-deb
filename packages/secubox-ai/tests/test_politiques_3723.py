# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Politiques de réponse (#3723, V2 § 10.2) : double tampon (ombre, validation, bascule), fichier invalide = politique
précédente gardée + audit `politiques-invalides` borné, catalogue fermé, plafonds au plus ceux de gk2, défauts figés."""
import os
import tomllib
from datetime import timedelta
from pathlib import Path

import pytest

from veille import politiques, riposte
from test_veille_correlation_3721 import T0

PAQUET = Path(__file__).resolve().parents[1]
EXEMPLE = PAQUET / "conf" / "politiques.toml.example"
EXEMPLE_RIPOSTE = PAQUET / "conf" / "riposte.toml.example"
GESTES = ("ban", "ban_bloc", "prolonger", "limiter", "leurre", "partager", "unban")
PLAFONDS_GK2 = {"ban": (60, 400), "ban_bloc": (5, 20), "prolonger": (30, 100), "limiter": (60, 400),
                "leurre": (30, 200), "partager": (30, 200)}


class Audits(list):
    def __call__(self, evenement, details):
        self.append((evenement, details))


def _tampon():
    return politiques.Tampon(proprietaire=os.getuid())


def _ecrire(chemin, texte):
    chemin.write_text(texte, encoding="utf-8")
    os.chmod(chemin, 0o644)


def test_exemple_defauts_figes():
    p = politiques.valider(tomllib.loads(EXEMPLE.read_text(encoding="utf-8")))
    assert p.mode == "hybride" and p.refuser_inconnu is True and p.expiration_min == 120
    assert set(p.gestes) == set(GESTES)
    assert all(g.actif and g.auto for g in p.gestes.values())
    assert p.automatique_suspendu is False
    for geste, (heure, jour) in PLAFONDS_GK2.items():
        assert (p.plafonds[geste]["heure"], p.plafonds[geste]["jour"]) == (heure, jour)
    assert politiques.PLAFONDS_GK2 == {g: {"heure": h, "jour": j} for g, (h, j) in PLAFONDS_GK2.items()}


def test_plafonds_identiques_au_source_de_gk2():
    """PLAFONDS_GK2 relu dans gestes_ia.py (PLAFONDS_PAR_GESTE) : gk3 ne peut pas croire à un plafond plus haut."""
    import ast
    source = PAQUET.parents[0] / "secubox-waf-ng" / "composants" / "waf" / "api" / "gestes_ia.py"
    arbre = ast.parse(source.read_text(encoding="utf-8"))
    valeurs = {}
    for n in arbre.body:
        if isinstance(n, ast.Assign) and getattr(n.targets[0], "id", None) == "PLAFONDS":
            plafonds_blocs = ast.literal_eval(n.value)
        if isinstance(n, ast.Assign) and getattr(n.targets[0], "id", None) == "PLAFONDS_PAR_GESTE":
            for k, v in zip(n.value.keys, n.value.values):
                valeurs[k.value] = {}
                for ck, cv in zip(v.keys, v.values):
                    if isinstance(cv, ast.Subscript):       # ban_bloc : renvoie à PLAFONDS["auto_*"]
                        valeurs[k.value][ck.value] = plafonds_blocs[cv.slice.value]
                    else:
                        valeurs[k.value][ck.value] = ast.literal_eval(cv)
    assert valeurs == politiques.PLAFONDS_GK2


def test_toml_invalide_garde_precedente(tmp_path):
    chemin = tmp_path / "politiques.toml"
    _ecrire(chemin, EXEMPLE.read_text(encoding="utf-8"))
    t, audits = _tampon(), Audits()
    p1 = t.charger(chemin, auditer=audits, maintenant=T0)
    assert p1.mode == "hybride" and t.active is p1 and audits == []
    _ecrire(chemin, "version = 1\n[defauts\nmode = ")                          # TOML cassé
    assert t.charger(chemin, auditer=audits, maintenant=T0 + timedelta(seconds=60)) is p1
    assert [e for e, _ in audits] == ["politiques-invalides"] and audits[0][1]["motif"] == "toml"
    # même fichier invalide à la passe suivante : pas un audit par passe
    assert t.charger(chemin, auditer=audits, maintenant=T0 + timedelta(seconds=120)) is p1
    assert len(audits) == 1
    # autre contenu invalide (plafond au-delà de gk2) : nouvel audit, précédente toujours gardée
    _ecrire(chemin, EXEMPLE.read_text(encoding="utf-8").replace("heure = 60", "heure = 61", 1))
    assert t.charger(chemin, auditer=audits, maintenant=T0 + timedelta(seconds=180)) is p1
    assert len(audits) == 2 and audits[1][1]["motif"] == "schema"
    # fichier absent : précédente gardée, dit une fois
    chemin.unlink()
    assert t.charger(chemin, auditer=audits, maintenant=T0 + timedelta(seconds=240)) is p1
    assert audits[-1][1]["motif"] == "absent"
    # retour d'un fichier valide : bascule
    _ecrire(chemin, EXEMPLE.read_text(encoding="utf-8").replace("expiration_min = 120", "expiration_min = 60"))
    p2 = t.charger(chemin, auditer=audits, maintenant=T0 + timedelta(seconds=300))
    assert p2 is not p1 and p2.expiration_min == 60 and t.active is p2


def test_sans_politique_valide_rien_d_office(tmp_path):
    """Au démarrage sans fichier valide : politique fermée (observation, automatique suspendu), jamais des défauts
    permissifs inventés."""
    t = _tampon()
    p = t.charger(tmp_path / "absent.toml", auditer=Audits(), maintenant=T0)
    assert p.mode == "observation" and p.automatique_suspendu is True and not p.gestes


def test_fichier_inscriptible_ou_lien_refuse(tmp_path):
    vrai = tmp_path / "vrai.toml"
    _ecrire(vrai, EXEMPLE.read_text(encoding="utf-8"))
    lien = tmp_path / "lien.toml"
    lien.symlink_to(vrai)
    audits = Audits()
    assert _tampon().charger(lien, auditer=audits, maintenant=T0).mode == "observation"
    os.chmod(vrai, 0o666)
    assert _tampon().charger(vrai, auditer=audits, maintenant=T0).mode == "observation"
    assert politiques.Tampon(proprietaire=os.getuid() + 1).charger(
        tmp_path / "vrai.toml", auditer=audits, maintenant=T0).mode == "observation"


def test_geste_inconnu_refuse():
    base = tomllib.loads(EXEMPLE.read_text(encoding="utf-8"))
    inconnu = {**base, "gestes": {**base["gestes"], "scan_retour": {"actif": True, "auto": True}}}
    with pytest.raises(politiques.PolitiqueInvalide):
        politiques.valider(inconnu)
    sans_refus = {**base, "defauts": {**base["defauts"], "refuser_inconnu": False}}
    with pytest.raises(politiques.PolitiqueInvalide):
        politiques.valider(sans_refus)
    champ = {**base, "gestes": {**base["gestes"], "ban": {"actif": True, "auto": True, "cible": "0.0.0.0/0"}}}
    with pytest.raises(politiques.PolitiqueInvalide):
        politiques.valider(champ)
    p = politiques.valider(base)
    assert not p.admet("scan_retour") and not p.admet("rediriger_trafic") and p.admet("ban")
    inactif = {**base, "gestes": {**base["gestes"], "limiter": {"actif": False, "auto": True}}}
    assert not politiques.valider(inactif).admet("limiter")


def test_plafond_au_dela_de_gk2_ou_geste_sans_plafond_refuse():
    base = tomllib.loads(EXEMPLE.read_text(encoding="utf-8"))
    for geste, champ, valeur in (("ban_bloc", "jour", 21), ("leurre", "heure", 31), ("partager", "jour", -1)):
        p = {**base, "plafonds": {**base["plafonds"], geste: {**base["plafonds"][geste], champ: valeur}}}
        with pytest.raises(politiques.PolitiqueInvalide):
            politiques.valider(p)
    plus_bas = {**base, "plafonds": {**base["plafonds"], "ban": {"heure": 10, "jour": 50}}}
    assert politiques.valider(plus_bas).plafonds["ban"] == {"heure": 10, "jour": 50}


def test_riposte_toml_exemple_et_bornes(tmp_path):
    s = riposte.valider_seuils(tomllib.loads(EXEMPLE_RIPOSTE.read_text(encoding="utf-8")))
    assert (s.n2_tentatives, s.n3_tentatives, s.calme_s) == (20, 100, 21600)
    assert s == riposte.SEUILS
    with pytest.raises(ValueError):
        riposte.valider_seuils({"version": 1, "seuils": {"n2_tentatives": 200, "n3_tentatives": 100}})
    chemin = tmp_path / "riposte.toml"
    _ecrire(chemin, "version = 1\n[seuils]\nn2_tentatives = 0\n")
    assert riposte.charger_seuils(chemin, proprietaire=os.getuid()) == riposte.SEUILS     # invalide : défauts


def test_postinst_depose_sans_ecraser_et_apparmor_lit():
    post = (PAQUET / "debian" / "postinst").read_text(encoding="utf-8")
    for nom in ("politiques.toml", "riposte.toml"):
        assert (f'if [ ! -e /etc/secubox/ai/{nom} ] && [ -f /usr/share/secubox/ai/{nom}.example ]; then') in post
        assert (f"install -m 0644 -o root -g root /usr/share/secubox/ai/{nom}.example /etc/secubox/ai/{nom}") in post
    regles = (PAQUET / "debian" / "rules").read_text(encoding="utf-8")
    assert "conf/politiques.toml.example" in regles and "conf/riposte.toml.example" in regles
    profil = (PAQUET / "apparmor" / "secubox-ai-veille").read_text(encoding="utf-8")
    assert "/etc/secubox/ai/politiques.toml r," in profil and "/etc/secubox/ai/riposte.toml r," in profil
