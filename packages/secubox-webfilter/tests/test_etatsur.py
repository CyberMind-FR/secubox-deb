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


# #3172 : config.json réécrit par root en 0600 dans le dossier du service — l'API ne le lisait plus. Le contrôleur root le rend au service,
# sans jamais suivre un lien que le compte du service aurait posé (systemd-tmpfiles refuse ce chemin : « unsafe path transition »).
@pytest.fixture
def repris(tmp_path, monkeypatch):
    """Le compte courant joue root (propriétaire du fichier), le service est un autre uid ; fchown est noté, pas exécuté (tests non root)."""
    monkeypatch.setattr(etatsur, "UID_ROOT", os.getuid())
    appels = []
    monkeypatch.setattr(etatsur.os, "fchown", lambda fd, uid, gid: appels.append((uid, gid)))
    e = etatsur.EtatSur(tmp_path)
    e.uid, e.gid = os.getuid() + 1, os.getgid() + 1
    yield tmp_path, e, appels
    e.fermer()


def test_un_fichier_de_root_est_rendu_au_service_en_0600_3172(repris):
    d, e, appels = repris
    (d / "config.json").write_text("{}")
    os.chmod(d / "config.json", 0o644)
    assert e.rendre_au_service("config.json", 0o600) is True
    assert appels == [(e.uid, e.gid)] and stat.S_IMODE(os.stat(d / "config.json").st_mode) == 0o600


def test_rien_a_faire_si_absent_ou_deja_au_service_3172(repris):
    d, e, appels = repris
    assert e.rendre_au_service("config.json", 0o600) is False
    (d / "config.json").write_text("{}")
    e.uid = os.getuid()
    assert e.rendre_au_service("config.json", 0o600) is False and appels == []


def test_un_lien_symbolique_ou_un_lien_dur_n_est_jamais_repris_3172(repris):
    d, e, appels = repris
    (d / "cible").write_text("secret")
    os.chmod(d / "cible", 0o644)
    (d / "config.json").symlink_to(d / "cible")
    with pytest.raises(etatsur.ErreurEtat):
        e.rendre_au_service("config.json", 0o600)
    (d / "config.json").unlink()
    os.link(d / "cible", d / "config.json")                                              # lien dur : un autre nom pour un autre fichier
    with pytest.raises(etatsur.ErreurEtat):
        e.rendre_au_service("config.json", 0o600)
    assert appels == [] and stat.S_IMODE(os.stat(d / "cible").st_mode) == 0o644


def test_un_autre_proprietaire_que_root_n_est_pas_repris_3172(repris, monkeypatch):
    d, e, appels = repris
    (d / "config.json").write_text("{}")
    monkeypatch.setattr(etatsur, "UID_ROOT", os.getuid() + 7)
    with pytest.raises(etatsur.ErreurEtat):
        e.rendre_au_service("config.json", 0o600)
    assert appels == []


def test_un_echec_du_changement_de_proprietaire_devient_un_refus_3172(repris, monkeypatch):
    """Relecture #3172 : une PermissionError de fchown faisait avorter toute l'application, sans résultat ni audit."""
    d, e, _ = repris
    (d / "config.json").write_text("{}")

    def refuse(fd, uid, gid):
        raise PermissionError(1, "Operation not permitted")
    monkeypatch.setattr(etatsur.os, "fchown", refuse)
    with pytest.raises(etatsur.ErreurEtat, match="reprise impossible"):
        e.rendre_au_service("config.json", 0o600)
