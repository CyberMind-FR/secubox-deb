# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3581 — reload en double tampon : écrit à côté, relu et validé, remplacé atomiquement, relancé, sondé ; sinon l'ancien
settings.yml revient (y compris quand la relance échoue après le remplacement). Chaque issue est une ligne d'audit.
Conteneur simulé (aucun lxc-attach)."""
import io
import json
import subprocess

import pytest

from sbx_searxng import config as C

SETTINGS = "/etc/searxng/settings.yml"
ANCIEN = "# ancien\nuse_default_settings: true\n"


class Conteneur:
    """Système de fichiers du conteneur en mémoire ; journal des opérations."""

    def __init__(self, fichiers=None, corrompre=False, echec_relance=False, echec_ecriture=False):
        self.f = dict(fichiers or {})
        self.ops, self.corrompre, self.echec_ecriture = [], corrompre, echec_ecriture
        # echec_relance : True (toujours), un entier (les n premières), ou une exception à lever.
        self.echec_relance = echec_relance

    def lire(self, chemin):
        return self.f.get(chemin)

    def ecrire(self, chemin, contenu, mode="0644"):
        self.ops.append(("ecrire", chemin))
        if self.echec_ecriture:
            raise subprocess.TimeoutExpired(["lxc-attach"], 30)
        self.f[chemin] = contenu[: len(contenu) // 3] if self.corrompre and chemin.endswith(".nouveau") else contenu

    def renommer(self, source, cible):
        self.ops.append(("renommer", source, cible))
        self.f[cible] = self.f.pop(source)

    def supprimer(self, chemin):
        self.ops.append(("supprimer", chemin))
        self.f.pop(chemin, None)

    def relancer(self):
        self.ops.append(("relancer",))
        e = self.echec_relance
        if isinstance(e, BaseException):
            raise e
        if e is True or (isinstance(e, int) and not isinstance(e, bool) and e > 0):
            if not isinstance(e, bool):
                self.echec_relance = e - 1
            raise subprocess.CalledProcessError(1, ["systemctl"])


class Audit(list):
    def __call__(self, evenement, details):
        self.append((evenement, details))


def test_applique(ctl, cfg):
    ct, audit = Conteneur({SETTINGS: ANCIEN}), Audit()
    code, sortie = ctl.appliquer_settings(cfg, ct, sante=lambda: True, acteur="alice", audit_fn=audit)
    assert code == 0 and sortie["issue"] == "applique"
    assert C.valider_settings(ct.f[SETTINGS], cfg)
    assert ct.f[SETTINGS + ".precedent"] == ANCIEN and SETTINGS + ".nouveau" not in ct.f
    # Ordre du double tampon : à côté, relu (lire), sauvegarde de l'ancien, remplacement atomique, relance.
    assert ct.ops == [("ecrire", SETTINGS + ".nouveau"), ("ecrire", SETTINGS + ".precedent"),
                      ("renommer", SETTINGS + ".nouveau", SETTINGS), ("relancer",)]
    assert audit == [("reload", {"issue": "applique", "acteur": "alice", "sha256": sortie["sha256"]})]


def test_validation_en_echec_ancien_fichier_garde(ctl, cfg):
    ct, audit = Conteneur({SETTINGS: ANCIEN}, corrompre=True), Audit()
    code, sortie = ctl.appliquer_settings(cfg, ct, sante=lambda: True, audit_fn=audit)
    assert code == 3 and sortie["issue"] == "refuse"
    assert ct.f[SETTINGS] == ANCIEN and SETTINGS + ".nouveau" not in ct.f
    assert ("relancer",) not in ct.ops and not any(o[0] == "renommer" for o in ct.ops)
    assert audit[0][0] == "reload" and audit[0][1]["issue"] == "refuse" and audit[0][1]["detail"]


def test_searxng_muet_retour_arriere(ctl, cfg):
    reponses = iter([False, True])                 # muet avec le nouveau fichier, répond avec l'ancien
    ct, audit = Conteneur({SETTINGS: ANCIEN}), Audit()
    code, sortie = ctl.appliquer_settings(cfg, ct, sante=lambda: next(reponses), audit_fn=audit)
    assert code == 3 and sortie["issue"] == "retour-arriere" and sortie["retabli"] is True
    assert ct.f[SETTINGS] == ANCIEN
    assert [o for o in ct.ops if o[0] == "relancer"] == [("relancer",), ("relancer",)]
    assert [a[1]["issue"] for a in audit] == ["retour-arriere"]


def test_premier_passage_sans_ancien_fichier(ctl, cfg):
    ct, audit = Conteneur(), Audit()
    code, sortie = ctl.appliquer_settings(cfg, ct, sante=lambda: False, audit_fn=audit)
    assert code == 3 and sortie["issue"] == "echec" and "aucun ancien" in sortie["detail"]
    assert audit[0][1]["issue"] == "echec"


def test_relance_en_echec_apres_remplacement_ancien_fichier_remis(ctl, cfg):
    # La relance échoue toujours (même celle du retour arrière) : l'ancien settings.yml est quand même remis.
    ct, audit = Conteneur({SETTINGS: ANCIEN}, echec_relance=True), Audit()
    code, sortie = ctl.appliquer_settings(cfg, ct, sante=lambda: True, audit_fn=audit)
    assert ct.f[SETTINGS] == ANCIEN
    assert code == 3 and sortie["issue"] == "retour-arriere" and sortie["retabli"] is False
    assert "relance" in sortie["detail"] and [a[1]["issue"] for a in audit] == ["retour-arriere"]


@pytest.mark.parametrize("exc", [subprocess.TimeoutExpired(["lxc-attach"], 90), RuntimeError("inattendue")])
def test_relance_en_echec_puis_retablie(ctl, cfg, exc):
    # Délai dépassé (ou toute autre erreur) à la relance avec le nouveau fichier : même chemin que la sonde muette.
    ct, audit = Conteneur({SETTINGS: ANCIEN}), Audit()
    appels = []

    def relancer():
        appels.append(1)
        ct.ops.append(("relancer",))
        if len(appels) == 1:
            raise exc
    ct.relancer = relancer
    code, sortie = ctl.appliquer_settings(cfg, ct, sante=lambda: True, audit_fn=audit)
    assert ct.f[SETTINGS] == ANCIEN and len(appels) == 2
    assert code == 3 and sortie["issue"] == "retour-arriere" and sortie["retabli"] is True
    assert audit == [("reload", sortie)]


def test_sonde_qui_leve_apres_remplacement_defait(ctl, cfg):
    ct, audit = Conteneur({SETTINGS: ANCIEN}), Audit()
    etats = iter([ValueError("sonde"), True])

    def sante():
        e = next(etats)
        if isinstance(e, BaseException):
            raise e
        return e
    code, sortie = ctl.appliquer_settings(cfg, ct, sante=sante, audit_fn=audit)
    assert (code, sortie["issue"], sortie["retabli"], ct.f[SETTINGS]) == (3, "retour-arriere", True, ANCIEN)


def test_echec_avant_remplacement_rien_ne_change(ctl, cfg):
    ct, audit = Conteneur({SETTINGS: ANCIEN}, echec_ecriture=True), Audit()
    code, sortie = ctl.appliquer_settings(cfg, ct, sante=lambda: True, audit_fn=audit)
    assert code == 1 and sortie["issue"] == "echec" and audit[0][1]["issue"] == "echec"
    assert ct.f[SETTINGS] == ANCIEN and ("relancer",) not in ct.ops and not any(o[0] == "renommer" for o in ct.ops)


def test_erreur_imprevue_avant_remplacement_propagee(ctl, cfg):
    ct = Conteneur({SETTINGS: ANCIEN})
    ct.lire = lambda chemin: (_ for _ in ()).throw(KeyError("bogue"))
    with pytest.raises(KeyError):
        ctl.appliquer_settings(cfg, ct, sante=lambda: True, audit_fn=Audit())


def test_install_n_ecrit_rien_si_identique(ctl, cfg):
    texte = C.rendre_yaml(C.generer_settings(cfg))
    ct, audit = Conteneur({SETTINGS: texte}), Audit()
    code, sortie = ctl.appliquer_settings(cfg, ct, sante=lambda: True, relancer_si_identique=False, audit_fn=audit)
    assert (code, sortie["issue"], ct.ops, audit) == (0, "inchange", [], [])


def test_audit_ligne_json_en_ajout_seul(ctl, tmp_path):
    f = tmp_path / "audit.log"
    f.write_text('{"avant": 1}\n')
    ctl.audit("reload", {"issue": "applique", "acteur": "alice"}, chemin=f)
    lignes = f.read_text().splitlines()
    assert lignes[0] == '{"avant": 1}'
    d = json.loads(lignes[1])
    assert d["type"] == "searxng" and d["evenement"] == "reload" and d["issue"] == "applique" and d["ts"].endswith("+00:00")


def test_acteur_lu_sur_l_entree_standard_et_valide(ctl):
    assert ctl.lire_acteur(io.StringIO('{"acteur": "alice"}')) == "alice"
    for mauvais in ('{"acteur": "a b"}', '{"acteur": "x;reboot"}', "pas du json", "", '["alice"]'):
        assert ctl.lire_acteur(io.StringIO(mauvais)) == "?"


def test_reload_avec_configuration_refusee_audite(ctl, tmp_path, monkeypatch, capsys):
    toml = tmp_path / "searxng.toml"
    toml.write_text('[searxng]\nport = 1\n')
    audit = Audit()
    monkeypatch.setattr(ctl, "CONFIG", str(toml))
    monkeypatch.setattr(ctl, "audit", audit)
    assert ctl.main(["reload", "--json"]) == 3
    assert audit[0][1]["issue"] == "refuse"
    assert json.loads(capsys.readouterr().out)["issue"] == "refuse"


def test_usage_strict(ctl):
    assert ctl.main(["reload", "--force"]) == 2
    assert ctl.main(["detruire"]) == 2
