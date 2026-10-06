# SPDX-License-Identifier: LicenseRef-CMSD-1.0
"""Contrôleur root : corrections de la relecture de sécurité de la phase 2 (#1962)."""
# ruff: noqa: F811, F401  (la fixture `banc` est importée de test_ctl)
import json
import os
import shutil

from tests.test_ctl import Faux, banc, config, dropin, ecrire_config, lancer  # noqa: F401  (banc : fixture partagée)
from webfilter import ctl

TOUT_OBSERVE = {"adulte": "observe", "jeux": "observe", "phishing": "observe"}


def test_la_demande_est_consommee_des_le_debut_et_une_demande_tardive_n_est_pas_perdue(banc):
    ecrire_config(banc, config())
    (banc / "etat" / "appliquer.demande").write_text("")

    class Espion(Faux):
        def voisins(self):                                              # appelé PENDANT l'application
            assert not (banc / "etat" / "appliquer.demande").exists()
            (banc / "etat" / "appliquer.demande").write_text("")        # une nouvelle demande arrive en cours d'exécution
            return super().voisins()
    lancer(banc, Espion())
    assert (banc / "etat" / "appliquer.demande").exists()               # pas effacée à la fin : l'unité .path la reprendra


def test_json_tres_imbrique_refuse_sans_planter(banc):
    (banc / "etat" / "config.json").write_text("[" * 200000)
    r = lancer(banc, Faux())
    assert r["statut"] == "refuse" and not dropin(banc).exists()


def test_dossier_d_etat_en_lien_symbolique_refuse(banc):
    (banc / "lien").symlink_to(banc / "etat")
    s = Faux()
    r = ctl.appliquer(banc / "lien", banc / "racine", dropin(banc), banc / "w.toml", systeme=s)
    assert r["statut"] == "refuse" and "dossier d'état" in r["message"] and s.appels == [] and str(banc) not in r["message"]


def test_dossier_d_etat_d_un_mauvais_proprietaire_refuse(banc):
    ecrire_config(banc, config())

    class Autre(Faux):
        def uid_service(self):
            return os.getuid() + 1
    r = lancer(banc, Autre())
    assert r["statut"] == "refuse" and "propriétaire" in r["message"] and not dropin(banc).exists()


def test_une_liste_orpheline_ne_bloque_pas(banc):
    (banc / "etat" / "listes" / "jeux" / "ancienne-source.lst").write_text("orpheline.example.net\n")      # source retirée du catalogue
    ecrire_config(banc, config())
    lancer(banc, Faux())
    t = dropin(banc).read_text()
    assert "bet.example.org" in t and "orpheline.example.net" not in t


def test_dossier_listes_en_lien_refuse(banc):
    ailleurs = banc / "ailleurs"
    ailleurs.mkdir()
    shutil.rmtree(banc / "etat" / "listes")
    (banc / "etat" / "listes").symlink_to(ailleurs)
    ecrire_config(banc, config())
    r = lancer(banc, Faux())
    assert r["statut"] == "refuse" and not dropin(banc).exists()


def test_budget_global_d_octets_des_listes(banc, monkeypatch):
    ecrire_config(banc, config())
    monkeypatch.setattr(ctl, "BUDGET_OCTETS", 10)
    r = lancer(banc, Faux())
    assert r["statut"] == "refuse" and "budget" in r["message"]


def test_aucun_blocage_n_ecrit_rien_dans_unbound(banc):
    ecrire_config(banc, config(TOUT_OBSERVE))
    s = Faux()
    r = lancer(banc, s)
    assert r["statut"] == "inchange" and s.appels == [] and not dropin(banc).exists() and not any(a == "application" for a, _ in s.audits)
    c = json.loads((banc / "etat" / "carte.json").read_text()) if (banc / "etat" / "carte.json").exists() else {}
    assert c.get("adresses", {}) == {}


def test_plus_aucun_blocage_retire_le_dropin_et_recharge(banc):
    ecrire_config(banc, config())
    lancer(banc, Faux())
    assert dropin(banc).exists()
    ecrire_config(banc, config(TOUT_OBSERVE))
    s = Faux()
    r = lancer(banc, s)
    assert r["statut"] == "applique" and "aucun blocage" in r["message"] and not dropin(banc).exists() and s.appels == ["checkconf", "reload"]
    assert ("changement", "profil enfants jeux block->observe") in s.audits


def test_retrait_refuse_par_le_controle_restaure_le_dropin(banc):
    ecrire_config(banc, config())
    lancer(banc, Faux())
    avant = dropin(banc).read_bytes()
    ecrire_config(banc, config(TOUT_OBSERVE))
    r = lancer(banc, Faux(checkconf_ok=False))
    assert r["statut"] == "refuse" and dropin(banc).read_bytes() == avant


# ── 0.2.1 : essai réel du 2026-10-04 ─────────────────────────────────────────────────────────────────────────────────────────────
def test_categorie_en_block_sans_aucune_liste_est_refusee(banc):
    for f in (banc / "etat" / "listes" / "jeux").glob("*.lst"):
        f.unlink()                                                      # comme après une mise à jour 0.1.0 → 0.2.0 : aucune liste brute avant la prochaine synchronisation
    ecrire_config(banc, config())
    s = Faux()
    r = lancer(banc, s)
    assert r["statut"] == "refuse" and "jeux" in r["message"] and "synchronisation" in r["message"].lower()
    assert not dropin(banc).exists() and s.appels == []                 # rien n'est écrit, rien n'est rechargé : jamais « appliqué » avec 0 zone


def test_categorie_en_block_avec_liste_vide_est_refusee(banc):
    (banc / "etat" / "listes" / "jeux" / "hagezi-gambling-medium.lst").write_text("# rien de valide\n")
    ecrire_config(banc, config())
    assert lancer(banc, Faux())["statut"] == "refuse"


def test_une_categorie_observe_sans_liste_n_empeche_rien(banc):
    for f in (banc / "etat" / "listes" / "jeux").glob("*.lst"):
        f.unlink()
    ecrire_config(banc, config({"adulte": "block", "jeux": "observe", "phishing": "observe"}))
    r = lancer(banc, Faux())
    assert r["statut"] == "applique"                                     # seule une catégorie en BLOCK exige une liste


# ── constaté sur gk2 et gk3 (04:00) : chmod refusé par AppArmor sur un dossier déjà en 0700 ─────────────────────────

def test_un_dossier_racine_deja_en_0700_n_est_pas_rechmode(banc, monkeypatch):
    """Le profil AppArmor n'accorde pas `w` sur le dossier lui-même (seulement sur son contenu) : un chmod, même sans effet,
    y est refusé (EACCES) et faisait échouer l'unité à chaque passage. Déjà en 0700, il n'y a rien à faire."""
    ecrire_config(banc, config())
    os.chmod(banc / "racine", 0o700)

    def refuse(chemin, mode):
        raise PermissionError(13, "Permission denied", str(chemin))
    monkeypatch.setattr(ctl.os, "chmod", refuse)
    r = lancer(banc, Faux())
    assert r["statut"] != "erreur"


def test_un_dossier_racine_trop_ouvert_est_toujours_resserre(banc):
    ecrire_config(banc, config())
    os.chmod(banc / "racine", 0o755)
    lancer(banc, Faux())
    assert (banc / "racine").stat().st_mode & 0o777 == 0o700


def test_le_profil_apparmor_autorise_le_dossier_racine_lui_meme():
    from pathlib import Path
    profil = (Path(__file__).resolve().parents[1] / "apparmor" / "secubox-webfilter").read_text()
    bloc = profil[profil.index("/usr/sbin/secubox-webfilter-ctl {"):]
    assert "/var/lib/secubox-webfilter-ctl/ rw," in bloc


def test_le_profil_du_controleur_laisse_unbound_checkconf_et_ip_resoudre_leurs_utilisateurs():
    """Constaté sur gk2 : sous le profil, unbound-checkconf ne pouvait lire ni /etc/passwd ni /etc/nsswitch.conf (« user 'unbound'
    does not exist »), et ip /usr/share/iproute2/group. Le contrôleur refusait donc toute configuration."""
    from pathlib import Path
    profil = (Path(__file__).resolve().parents[1] / "apparmor" / "secubox-webfilter").read_text()
    bloc = profil[profil.index("/usr/sbin/secubox-webfilter-ctl {"):]
    assert "#include <abstractions/nameservice>" in bloc
    assert "/usr/share/iproute2/** r," in bloc
