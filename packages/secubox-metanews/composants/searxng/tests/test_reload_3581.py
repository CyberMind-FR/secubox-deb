# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3581 — reload en double tampon : écrit à côté, relu et validé, remplacé atomiquement, relancé, sondé ; sinon l'ancien
settings.yml revient (y compris quand la relance échoue après le remplacement). Chaque issue est une ligne d'audit.
Conteneur simulé (aucun lxc-attach). Demandes de l'API : dépôt par fichier, revalidées par le contrôleur root."""
import json
import os
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


def test_reload_avec_configuration_refusee_audite(ctl, tmp_path, monkeypatch, capsys):
    toml = tmp_path / "searxng.toml"
    toml.write_text('[searxng]\nport = 1\n')
    toml.chmod(0o640)
    audit = Audit()
    monkeypatch.setattr(ctl, "CONFIG", str(toml))
    monkeypatch.setattr(ctl, "PROPRIETAIRE_CONFIG", os.getuid())
    monkeypatch.setattr(ctl, "audit", audit)
    assert ctl.main(["reload", "--json"]) == 3
    assert audit[0][1]["issue"] == "refuse"
    assert json.loads(capsys.readouterr().out)["issue"] == "refuse"


def test_usage_strict(ctl):
    assert ctl.main(["reload", "--force"]) == 2
    assert ctl.main(["reload", "--acteur-stdin"]) == 2          # plus de passage par sudo
    assert ctl.main(["status", "--demandes"]) == 2
    assert ctl.main(["detruire"]) == 2


# ── TOML lu par le contrôleur root : propriétaire root, ni groupe ni autres en écriture, jamais un lien ──

def test_toml_du_controleur_protege(ctl, tmp_path, monkeypatch):
    toml = tmp_path / "searxng.toml"
    toml.write_text('[searxng]\nport = 8888\n')
    toml.chmod(0o640)
    monkeypatch.setattr(ctl, "CONFIG", str(toml))
    monkeypatch.setattr(ctl, "PROPRIETAIRE_CONFIG", os.getuid())
    assert ctl.charger_config()["searxng"]["port"] == 8888
    for mode in (0o660, 0o646, 0o666):
        toml.chmod(mode)
        with pytest.raises(ctl.C.ConfigInvalide, match="inscriptible"):
            ctl.charger_config()
    toml.chmod(0o640)
    monkeypatch.setattr(ctl, "PROPRIETAIRE_CONFIG", os.getuid() + 1)
    with pytest.raises(ctl.C.ConfigInvalide, match="root"):
        ctl.charger_config()
    monkeypatch.setattr(ctl, "PROPRIETAIRE_CONFIG", os.getuid())
    lien = tmp_path / "lien.toml"
    lien.symlink_to(toml)
    monkeypatch.setattr(ctl, "CONFIG", str(lien))
    with pytest.raises(ctl.C.ConfigInvalide, match="illisible"):
        ctl.charger_config()
    monkeypatch.setattr(ctl, "CONFIG", str(tmp_path / "absent.toml"))
    assert ctl.charger_config()["lxc"]["ip"] == "10.100.0.85"                   # absent = défauts
    assert "PROPRIETAIRE_CONFIG = 0\n" in (ctl.__file__ and open(ctl.__file__, encoding="utf-8").read())


# ── Demandes de l'API (secubox-searxng-reload.path → searxngctl reload --demandes) ──

@pytest.fixture
def depot(ctl, tmp_path, monkeypatch):
    d, r = tmp_path / "searxng-reload", tmp_path / "searxng-reload-resultats"
    monkeypatch.setattr(ctl, "DEMANDES", d)
    monkeypatch.setattr(ctl, "RESULTATS", r)
    monkeypatch.setattr(ctl, "_identites", lambda: (os.getuid(), os.getuid(), os.getgid()))
    monkeypatch.setattr(ctl.os, "geteuid", lambda: 0)
    audit = Audit()
    monkeypatch.setattr(ctl, "audit", lambda ev, det, chemin=None: audit(ev, det))
    reloads = []

    def reload(cfg, acteur):
        reloads.append(acteur)
        return 0, {"issue": "applique", "acteur": acteur, "sha256": "ab"}
    monkeypatch.setattr(ctl, "executer_reload", reload)
    ctl.preparer_depot()
    return d, r, audit, reloads


def _deposer(d, ident, contenu):
    f = d / f"{ident}.demande"
    f.write_bytes(contenu if isinstance(contenu, bytes) else json.dumps(contenu).encode())
    return f


def test_depot_prepare_et_liens_ecartes(ctl, depot, tmp_path):
    d, r, audit, _ = depot
    assert d.stat().st_mode & 0o7777 == 0o1770 and r.stat().st_mode & 0o7777 == 0o750
    # Un lien posé à la place du dépôt est écarté, jamais suivi ; le dossier est recréé.
    cible = tmp_path / "ailleurs"
    cible.mkdir()
    d.rmdir()
    d.symlink_to(cible)
    ctl.preparer_depot()
    assert d.is_dir() and not d.is_symlink() and d.stat().st_mode & 0o7777 == 0o1770
    assert list(cible.iterdir()) == [] and any(x.name.startswith(".searxng-reload.ecarte-") for x in tmp_path.iterdir())
    assert audit[-1][1]["issue"] == "ecarte"


def test_une_demande_valide_par_passage(ctl, depot, cfg):
    d, r, audit, reloads = depot
    _deposer(d, "0" * 16, {"acteur": "alice"})
    _deposer(d, "1" * 16, {"acteur": "bob"})
    (d / ".tmp.2222222222222222").write_text("{")              # en cours d'écriture par l'API : laissé
    (d / "inattendu.txt").write_text("x")                      # nom inattendu : retiré
    (d / ("3" * 16 + ".demande")).mkdir()                      # dossier sous un nom de demande : mis de côté
    (d / ("3" * 16 + ".demande") / "x").write_text("x")
    assert ctl.traiter_demandes(cfg) == 0
    assert reloads == ["alice"]
    assert json.loads((r / ("0" * 16 + ".json")).read_text()) == {
        "code": 0, "resultat": {"issue": "applique", "acteur": "alice", "sha256": "ab"}}
    assert (r / ("0" * 16 + ".json")).stat().st_mode & 0o777 == 0o640
    assert sorted(x.name for x in d.iterdir() if not x.name.startswith(".ecarte.")) == [
        ".tmp.2222222222222222", "1" * 16 + ".demande"]
    assert any(x.name.startswith(".ecarte.3333") and x.is_dir() for x in d.iterdir())   # hors de *.demande
    assert ctl.traiter_demandes(cfg) == 0                      # l'unité .path relance : la suivante
    assert reloads == ["alice", "bob"] and not list(d.glob("*.demande"))


@pytest.mark.parametrize("contenu,motif", [
    (b"pas du json", "JSON invalide"), (b"\xff\xfe", "JSON invalide"), ({"acteur": "a b"}, "acteur refusé"),
    ({"acteur": "x;reboot"}, "acteur refusé"), ({"acteur": "alice\n"}, "acteur refusé"), ({"acteur": 3}, "acteur refusé"),
    ({"acteur": "alice", "verbe": "install"}, "attendu"), (["alice"], "attendu"), ({}, "attendu"),
    (json.dumps({"acteur": "a" * 64, "x": " " * 600}).encode(), "trop grande")])
def test_demande_refusee_sans_reload(ctl, depot, cfg, contenu, motif):
    d, r, audit, reloads = depot
    _deposer(d, "a" * 16, contenu)
    assert ctl.traiter_demandes(cfg) == 0
    assert reloads == [] and not list(d.glob("*.demande"))
    res = json.loads((r / ("a" * 16 + ".json")).read_text())
    assert res["code"] == 2 and res["resultat"]["issue"] == "refuse" and motif in res["resultat"]["detail"]
    assert audit[-1][1]["issue"] == "refuse"


def test_demande_lien_fifo_liens_multiples_ou_autre_proprietaire(ctl, depot, cfg, tmp_path, monkeypatch):
    d, r, _, reloads = depot
    secret = tmp_path / "secret"
    secret.write_text(json.dumps({"acteur": "alice"}))
    (d / ("b" * 16 + ".demande")).symlink_to(secret)
    os.mkfifo(d / ("c" * 16 + ".demande"))
    os.link(_deposer(d, "d" * 16, {"acteur": "alice"}), tmp_path / "second-lien")
    for _ in range(3):
        ctl.traiter_demandes(cfg)
    assert reloads == [] and secret.exists()
    motifs = {f.name[:1]: json.loads(f.read_text())["resultat"]["detail"] for f in r.glob("*.json")}
    assert "illisible" in motifs["b"] and "ordinaire" in motifs["c"] and "liens multiples" in motifs["d"]
    monkeypatch.setattr(ctl, "_identites", lambda: (os.getuid(), os.getuid() + 1, os.getgid()))
    _deposer(d, "e" * 16, {"acteur": "alice"})
    ctl.traiter_demandes(cfg)
    assert reloads == [] and "propriétaire" in json.loads((r / ("e" * 16 + ".json")).read_text())["resultat"]["detail"]


def test_configuration_refusee_chaque_demande_le_sait(ctl, depot, tmp_path, monkeypatch):
    d, r, audit, reloads = depot
    toml = tmp_path / "searxng.toml"
    toml.write_text('[searxng]\nport = 1\n')
    toml.chmod(0o640)
    monkeypatch.setattr(ctl, "CONFIG", str(toml))
    monkeypatch.setattr(ctl, "PROPRIETAIRE_CONFIG", os.getuid())
    _deposer(d, "f" * 16, {"acteur": "alice"})
    assert ctl.main(["reload", "--demandes"]) == 0
    res = json.loads((r / ("f" * 16 + ".json")).read_text())
    assert reloads == [] and res["code"] == 3 and res["resultat"]["issue"] == "refuse" and res["resultat"]["acteur"] == "alice"
    assert audit[-1][1]["issue"] == "refuse"


def test_resultats_et_temporaires_perimes_purges(ctl, depot, cfg):
    d, r, _, _ = depot
    vieux_res, vieux_tmp, frais = r / ("9" * 16 + ".json"), d / ".tmp.9999999999999999", d / ".tmp.8888888888888888"
    for f in (vieux_res, vieux_tmp, frais):
        f.write_text("{}")
    for f in (vieux_res, vieux_tmp):
        os.utime(f, (1, 1))
    ctl.traiter_demandes(cfg)
    assert not vieux_res.exists() and not vieux_tmp.exists() and frais.exists()


def test_executer_reload_conteneur_arrete_et_occupe(ctl, cfg, tmp_path, monkeypatch):
    audit = Audit()
    monkeypatch.setattr(ctl, "audit", lambda ev, det, chemin=None: audit(ev, det))
    monkeypatch.setattr(ctl, "ETAT_ROOT", tmp_path / "etat")
    monkeypatch.setattr(ctl.Conteneur, "etat", lambda self: "stopped")
    code, sortie = ctl.executer_reload(cfg, "alice")
    assert (code, sortie["issue"], sortie["acteur"]) == (4, "conteneur-arrete", "alice") and audit[-1][1] == sortie
    with ctl.Verrou(tmp_path / "etat" / "verrou"):
        assert ctl.executer_reload(cfg, "alice")[0] == 5
