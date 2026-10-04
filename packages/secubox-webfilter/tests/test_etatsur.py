# SPDX-License-Identifier: LicenseRef-CMSD-1.0
"""Le contrôleur root lit et écrit dans un dossier que contrôle un compte non root : ouverture sans suivre de lien, propriétaire vérifié,
opérations RELATIVES au descripteur (relecture de sécurité #1962, phase 2)."""
import os
import stat

import pytest

from webfilter import etatsur, zones


def test_ouvre_un_vrai_dossier_et_lit_ce_qui_existe(tmp_path):
    (tmp_path / "config.json").write_text("{}")
    e = etatsur.EtatSur(tmp_path)
    try:
        assert e.lire("config.json", 100) == b"{}" and e.lire("absent.json", 100) is None
    finally:
        e.fermer()


def test_refuse_un_lien_symbolique_a_la_place_du_dossier(tmp_path):
    reel = tmp_path / "reel"
    reel.mkdir()
    (tmp_path / "lien").symlink_to(reel)
    with pytest.raises(etatsur.ErreurEtat):
        etatsur.EtatSur(tmp_path / "lien")


def test_refuse_un_dossier_inscriptible_par_d_autres(tmp_path):
    d = tmp_path / "ouvert"
    d.mkdir()
    os.chmod(d, 0o777)
    with pytest.raises(etatsur.ErreurEtat):
        etatsur.EtatSur(d)


def test_refuse_un_mauvais_proprietaire(tmp_path):
    with pytest.raises(etatsur.ErreurEtat):
        etatsur.EtatSur(tmp_path, proprietaire_uid=os.getuid() + 1)
    etatsur.EtatSur(tmp_path, proprietaire_uid=os.getuid()).fermer()


def test_lire_refuse_lien_fifo_et_fichier_enorme(tmp_path):
    (tmp_path / "cible").write_text("secret")
    (tmp_path / "lien.json").symlink_to(tmp_path / "cible")
    os.mkfifo(tmp_path / "fifo.json")
    (tmp_path / "gros.json").write_text("x" * 5000)
    e = etatsur.EtatSur(tmp_path)
    try:
        for nom in ("lien.json", "fifo.json", "gros.json"):
            with pytest.raises(etatsur.ErreurEtat):
                e.lire(nom, 1000)
    finally:
        e.fermer()


def test_ecrire_est_atomique_sans_residu_et_sans_suivre_un_lien(tmp_path):
    cible = tmp_path / "hors-dossier.txt"
    cible.write_text("intact")
    (tmp_path / "resultat.json").symlink_to(cible)                      # le compte non root a posé un lien à la place de la cible
    e = etatsur.EtatSur(tmp_path)
    try:
        e.ecrire("resultat.json", b'{"ok": 1}', 0o640)
    finally:
        e.fermer()
    assert cible.read_text() == "intact"                                # le lien a été REMPLACÉ, jamais suivi
    assert not (tmp_path / "resultat.json").is_symlink() and (tmp_path / "resultat.json").read_bytes() == b'{"ok": 1}'
    assert stat.S_IMODE((tmp_path / "resultat.json").stat().st_mode) == 0o640
    assert sorted(p.name for p in tmp_path.iterdir()) == ["hors-dossier.txt", "resultat.json"]


def test_supprimer_et_tolerance_a_l_absence(tmp_path):
    (tmp_path / "x.demande").write_text("")
    e = etatsur.EtatSur(tmp_path)
    try:
        e.supprimer("x.demande")
        e.supprimer("x.demande")
        assert not (tmp_path / "x.demande").exists()
    finally:
        e.fermer()


# ── zones : lecture relative au descripteur, sources du catalogue seulement, budget global ────────────────────────────────────────
def etat_avec(tmp_path, fichiers):
    (tmp_path / "listes" / "jeux").mkdir(parents=True)
    for nom, texte in fichiers.items():
        (tmp_path / "listes" / "jeux" / nom).write_text(texte)
    return etatsur.EtatSur(tmp_path)


def test_charger_sur_ne_lit_que_les_sources_du_catalogue(tmp_path):
    e = etat_avec(tmp_path, {"s1.lst": "a.example.com\n", "ancienne.lst": "orpheline.example.org\n"})
    try:
        assert zones.charger_sur(e, "jeux", ["s1"], etatsur.Budget(10_000)) == ["a.example.com"]
    finally:
        e.fermer()


def test_charger_sur_revalide_les_lignes(tmp_path):
    e = etat_avec(tmp_path, {"s1.lst": 'ok.example.com\nbad".com\n; local-zone: "."\n'})
    try:
        assert zones.charger_sur(e, "jeux", ["s1"], etatsur.Budget(10_000)) == ["ok.example.com"]
    finally:
        e.fermer()


def test_charger_sur_refuse_un_dossier_de_listes_ou_de_categorie_en_lien(tmp_path):
    reel = tmp_path / "ailleurs"
    (reel / "jeux").mkdir(parents=True)
    (reel / "jeux" / "s1.lst").write_text("vole.example.com\n")
    (tmp_path / "listes").symlink_to(reel)
    e = etatsur.EtatSur(tmp_path)
    try:
        with pytest.raises(etatsur.ErreurEtat):
            zones.charger_sur(e, "jeux", ["s1"], etatsur.Budget(10_000))
    finally:
        e.fermer()
    (tmp_path / "listes").unlink()
    (tmp_path / "listes").mkdir()
    (tmp_path / "listes" / "jeux").symlink_to(reel / "jeux")
    e = etatsur.EtatSur(tmp_path)
    try:
        with pytest.raises(etatsur.ErreurEtat):
            zones.charger_sur(e, "jeux", ["s1"], etatsur.Budget(10_000))
    finally:
        e.fermer()


def test_charger_sur_ignore_lien_fifo_et_fichier_enorme(tmp_path, monkeypatch):
    e = etat_avec(tmp_path, {"s1.lst": "ok.example.com\n", "s3.lst": "x" * 500})
    (tmp_path / "ext.txt").write_text("lien.example.com\n")
    (tmp_path / "listes" / "jeux" / "s2.lst").symlink_to(tmp_path / "ext.txt")
    os.mkfifo(tmp_path / "listes" / "jeux" / "s4.lst")
    monkeypatch.setattr(zones, "MAX_LST_OCTETS", 100)
    try:
        assert zones.charger_sur(e, "jeux", ["s1", "s2", "s3", "s4"], etatsur.Budget(10_000)) == ["ok.example.com"]
    finally:
        e.fermer()


def test_budget_global_d_octets(tmp_path):
    e = etat_avec(tmp_path, {"s1.lst": "a.example.com\n" * 100})
    try:
        with pytest.raises(etatsur.ErreurEtat):
            zones.charger_sur(e, "jeux", ["s1"], etatsur.Budget(50))
    finally:
        e.fermer()


def test_categorie_absente_ou_hostile(tmp_path):
    e = etatsur.EtatSur(tmp_path)
    try:
        assert zones.charger_sur(e, "jeux", ["s1"], etatsur.Budget(1000)) == [] and zones.charger_sur(e, "../x", ["s1"], etatsur.Budget(1000)) == []
    finally:
        e.fermer()
