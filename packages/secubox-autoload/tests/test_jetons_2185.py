# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2185 : jetons clients — usage unique, expiration, révocation, statut d'abonnement, audit sans valeur, refus uniforme."""
import json
import os
import sqlite3
import stat
import subprocess
import sys
import threading
from pathlib import Path

import pytest

ICI = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ICI))
from autoload import jetons as J  # noqa: E402

CLE_A = "A" * 43 + "="
CLE_B = "B" * 43 + "="
T0 = 1_800_000_000


class Horloge:
    def __init__(self, t=T0):
        self.t = t

    def __call__(self):
        return self.t


@pytest.fixture
def reg(tmp_path):
    h = Horloge()
    r = J.Registre(tmp_path / "var" / "jetons.db", tmp_path / "audit.log", horloge=h)
    r.h = h
    return r


def audit(reg):
    p = reg.audit_chemin
    return [json.loads(l) for l in p.read_text().splitlines()] if p.exists() else []


def test_emission_donne_une_valeur_de_128_bits_et_ne_la_garde_pas(reg, tmp_path):
    e = reg.emettre("client-042", "lite", lot="lot-1")
    assert len(e.valeur) == 32 and int(e.valeur, 16) >= 0
    brut = (tmp_path / "var" / "jetons.db").read_bytes()
    assert e.valeur.encode() not in brut                                # seule l'empreinte est stockée
    assert e.expire_le == T0 + J.DUREE_DEFAUT_S


def test_deux_emissions_donnent_deux_valeurs_distinctes(reg):
    assert reg.emettre("c1", "lite").valeur != reg.emettre("c1", "lite").valeur


def test_reclamation_a_usage_unique(reg):
    e = reg.emettre("client-042", "isp", lot="lot-1")
    r = reg.reclamer(e.valeur, CLE_A)
    assert (r.client, r.profil, r.lot) == ("client-042", "isp", "lot-1")
    with pytest.raises(J.JetonRefuse):
        reg.reclamer(e.valeur, CLE_B)                                   # rejoué : refusé, et la clé d'origine reste
    ligne = [j for j in reg.lister() if j["id"] == r.id][0]
    assert ligne["etat"] == "reclame" and ligne["cle_pub"] == CLE_A


def test_jeton_expire_refuse(reg):
    e = reg.emettre("c1", "lite", duree_s=3600)
    reg.h.t += 3601
    with pytest.raises(J.JetonRefuse):
        reg.reclamer(e.valeur, CLE_A)


def test_jeton_revoque_refuse(reg):
    e = reg.emettre("c1", "lite")
    reg.revoquer(e.id, "perdu")
    with pytest.raises(J.JetonRefuse):
        reg.reclamer(e.valeur, CLE_A)


def test_revocation_d_un_lot(reg):
    a, b, c = reg.emettre("c1", "lite", lot="l"), reg.emettre("c2", "lite", lot="l"), reg.emettre("c3", "lite", lot="autre")
    assert reg.revoquer_lot("l", "fabrication défectueuse") == 2
    for x in (a, b):
        with pytest.raises(J.JetonRefuse):
            reg.reclamer(x.valeur, CLE_A)
    assert reg.reclamer(c.valeur, CLE_A).client == "c3"


def test_revoquer_un_jeton_deja_reclame_rend_la_cle_a_retirer(reg):
    e = reg.emettre("c1", "lite")
    reg.reclamer(e.valeur, CLE_A)
    assert reg.revoquer(e.id, "box volée") == CLE_A                     # #2189 retire ce pair WireGuard


def test_abonnement_suspendu_bloque_la_reclamation_et_la_livraison(reg):
    e = reg.emettre("c1", "lite")
    assert reg.fixer_abonnement("c1", "suspendu") == 1
    with pytest.raises(J.JetonRefuse):
        reg.reclamer(e.valeur, CLE_A)
    reg.fixer_abonnement("c1", "actif")
    reg.reclamer(e.valeur, CLE_A)
    assert reg.livraison_autorisee(CLE_A) is True
    reg.fixer_abonnement("c1", "suspendu")
    assert reg.livraison_autorisee(CLE_A) is False                      # nouvelles livraisons arrêtées, la box garde ses fonctions
    assert reg.livraison_autorisee(CLE_B) is False                      # clé inconnue : refusée


def test_refus_uniforme_inconnu_expire_deja_pris_revoque(reg):
    e1, e2, e3 = reg.emettre("c1", "lite"), reg.emettre("c2", "lite", duree_s=1), reg.emettre("c3", "lite")
    reg.reclamer(e1.valeur, CLE_A)
    reg.revoquer(e3.id, "x")
    reg.h.t += 10
    messages = set()
    for v in (e1.valeur, e2.valeur, e3.valeur, "0" * 32, "pas-un-jeton", "", "é" * 40):
        with pytest.raises(J.JetonRefuse) as ex:
            reg.reclamer(v, CLE_B)
        messages.add(str(ex.value))
    assert messages == {"jeton refusé"}                                  # rien n'apprend à un tiers pourquoi


def test_l_audit_dit_la_vraie_raison_sans_jamais_ecrire_la_valeur(reg):
    e = reg.emettre("c1", "lite")
    reg.reclamer(e.valeur, CLE_A)
    with pytest.raises(J.JetonRefuse):
        reg.reclamer(e.valeur, CLE_B)
    with pytest.raises(J.JetonRefuse):
        reg.reclamer("f" * 32, CLE_B)
    lignes = audit(reg)
    actions = [l["action"] for l in lignes]
    assert actions == ["jeton-emis", "jeton-reclame", "jeton-refus", "jeton-refus"]
    assert "déjà réclamé" in lignes[2]["detail"] and "inconnu" in lignes[3]["detail"]
    assert e.valeur not in reg.audit_chemin.read_text()
    assert all(l["module"] == "autoload" for l in lignes)


def test_cle_publique_wireguard_invalide_refusee_sans_consommer_le_jeton(reg):
    e = reg.emettre("c1", "lite")
    for mauvaise in ("", "court", "A" * 44, "A" * 43 + "x", "é" * 44, None):
        with pytest.raises(J.JetonRefuse):
            reg.reclamer(e.valeur, mauvaise)
    assert reg.reclamer(e.valeur, CLE_A).client == "c1"                  # intact


def test_une_meme_cle_ne_peut_pas_porter_deux_jetons(reg):
    reg.reclamer(reg.emettre("c1", "lite").valeur, CLE_A)
    with pytest.raises(J.JetonRefuse):
        reg.reclamer(reg.emettre("c2", "lite").valeur, CLE_A)


@pytest.mark.parametrize("champ,valeur", [("client", "Client Majuscule"), ("client", ""), ("client", "a" * 41), ("profil", "../x"), ("profil", ""),
                                           ("lot", "L O T"), ("serie", "x")])
def test_champs_d_emission_valides(reg, champ, valeur):
    args = {"client": "c1", "profil": "lite", "lot": None, "serie": None}
    args[champ] = valeur
    with pytest.raises(ValueError):
        reg.emettre(args["client"], args["profil"], lot=args["lot"], serie=args["serie"])


def test_duree_hors_bornes_refusee(reg):
    for d in (0, -5, J.DUREE_MAX_S + 1):
        with pytest.raises(ValueError):
            reg.emettre("c1", "lite", duree_s=d)


def test_reclamation_par_numero_de_serie_preenregistre(reg):
    reg.preenregistrer("SBX-0001-AB", "client-042", "isp", lot="l")
    r = reg.reclamer_par_serie("SBX-0001-AB", CLE_A)
    assert (r.client, r.profil) == ("client-042", "isp")
    with pytest.raises(J.JetonRefuse):
        reg.reclamer_par_serie("SBX-0001-AB", CLE_B)                    # une série ne se réclame qu'une fois
    with pytest.raises(J.JetonRefuse):
        reg.reclamer_par_serie("SBX-INCONNU-99", CLE_B)


def test_reclamation_concurrente_un_seul_gagnant(tmp_path):
    h = Horloge()
    e = J.Registre(tmp_path / "j.db", tmp_path / "a.log", horloge=h).emettre("c1", "lite")
    gagnants, refus = [], []

    def tenter(cle):
        try:
            gagnants.append(J.Registre(tmp_path / "j.db", tmp_path / "a.log", horloge=h).reclamer(e.valeur, cle))
        except J.JetonRefuse:
            refus.append(cle)
    cles = [chr(65 + i) * 43 + "=" for i in range(8)]
    ts = [threading.Thread(target=tenter, args=(c,)) for c in cles]
    [t.start() for t in ts]
    [t.join() for t in ts]
    assert len(gagnants) == 1 and len(refus) == 7


def test_le_stockage_est_prive(reg, tmp_path):
    reg.emettre("c1", "lite")
    db = tmp_path / "var" / "jetons.db"
    assert stat.S_IMODE(db.stat().st_mode) == 0o600
    assert stat.S_IMODE(db.parent.stat().st_mode) & 0o007 == 0                   # 0750 : aucun accès pour les autres comptes


def test_la_liste_ne_revele_jamais_la_valeur_ni_l_empreinte(reg):
    e = reg.emettre("c1", "lite")
    texte = json.dumps(reg.lister())
    assert e.valeur not in texte and "empreinte" not in texte


def test_injection_sql_sans_effet(reg):
    for v in ("' OR '1'='1", "x'; DROP TABLE jetons;--", "%", "_" * 32):
        with pytest.raises(J.JetonRefuse):
            reg.reclamer(v, CLE_A)
    reg.emettre("c1", "lite")
    assert len(reg.lister()) == 1


def test_cli_emettre_lister_revoquer(tmp_path):
    env = dict(os.environ, SECUBOX_AUTOLOAD_DB=str(tmp_path / "c.db"), SECUBOX_AUTOLOAD_AUDIT=str(tmp_path / "c.log"))
    ctl = str(ICI / "sbin" / "autoloadctl")

    def run(*a):
        return subprocess.run([sys.executable, ctl, *a], capture_output=True, text=True, env=env)
    e = run("emettre", "--client", "client-042", "--profil", "lite", "--lot", "l1")
    assert e.returncode == 0 and len(e.stdout.strip().splitlines()[-1]) == 32
    valeur = e.stdout.strip().splitlines()[-1]
    liste = run("lister", "--json")
    assert json.loads(liste.stdout)[0]["etat"] == "emis" and valeur not in liste.stdout
    assert run("revoquer", "--lot", "l1", "--motif", "test").returncode == 0
    assert json.loads(run("lister", "--json").stdout)[0]["etat"] == "revoque"
    assert run("emettre", "--client", "BAD NAME", "--profil", "lite").returncode == 2
