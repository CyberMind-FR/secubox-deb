# SPDX-License-Identifier: LicenseRef-CMSD-1.0
"""Contrôleur root : application des vues, retour arrière, audit, résultat et carte (#1962, phase 2)."""
import fcntl
import json
import os
import stat
from pathlib import Path

import pytest

from webfilter import ctl

RACINE = Path(__file__).resolve().parent.parent
CONF = (RACINE / "conf" / "webfilter.toml").read_text()
MAC = "aa:bb:cc:dd:ee:01"


class Faux(ctl.Systeme):
    def __init__(self, voisins=None, adguard="", box=(), checkconf_ok=True, reloads_en_echec=0):
        self._v, self._a, self._b = voisins if voisins is not None else {MAC: ["192.168.1.50"]}, adguard, set(box)
        self.checkconf_ok, self.reloads_en_echec = checkconf_ok, reloads_en_echec
        self.appels, self.audits = [], []

    def verifier_unbound(self):
        self.appels.append("checkconf")
        return self.checkconf_ok, "" if self.checkconf_ok else "unbound-checkconf: erreur simulée"

    def recharger_unbound(self):
        self.appels.append("reload")
        if self.reloads_en_echec > 0:
            self.reloads_en_echec -= 1
            raise ctl.ErreurCtl("unbound-control reload a échoué : simulé")

    def adguard_texte(self):
        return self._a

    def voisins(self):
        return self._v

    def adresses_box(self):
        return self._b

    def audit(self, action, detail=""):
        self.audits.append((action, detail))


def config(modes_enfants=None, appareils=None):
    return {"version": 5, "profils": {
        "defaut": {"categories": {"adulte": "observe", "jeux": "observe", "phishing": "observe"}, "autorise": []},
        "enfants": {"categories": modes_enfants or {"adulte": "observe", "jeux": "block", "phishing": "observe"}, "autorise": []}},
        "appareils": appareils if appareils is not None else {MAC: {"nom": "Tablette", "profil": "enfants", "exceptions": {}}}}


@pytest.fixture
def banc(tmp_path):
    (tmp_path / "etat" / "listes" / "jeux").mkdir(parents=True)
    (tmp_path / "etat" / "listes" / "jeux" / "hagezi-gambling-medium.lst").write_text("bet.example.org\ncasino.example.net\n")
    (tmp_path / "racine").mkdir()
    (tmp_path / "u").mkdir()
    os.chmod(tmp_path / "etat", 0o700)                                  # comme en production (tmpfiles) : le contrôleur refuse un dossier ouvert au groupe
    toml = tmp_path / "w.toml"
    toml.write_text(CONF.replace("lan = []", 'lan = ["192.168.1.0/24", "2a01:db8::/64"]')
                    .replace("zones_max = 1500000", "zones_max = 1000"))
    return tmp_path


def ecrire_config(banc, cfg):
    (banc / "etat" / "config.json").write_text(json.dumps(cfg))


def lancer(banc, systeme, **k):
    return ctl.appliquer(banc / "etat", banc / "racine", banc / "u" / "93-secubox-webfilter.conf", banc / "w.toml", systeme=systeme, **k)


def dropin(banc):
    return banc / "u" / "93-secubox-webfilter.conf"


def test_premiere_application(banc):
    ecrire_config(banc, config())
    s = Faux()
    r = lancer(banc, s)
    assert r["statut"] == "applique" and r["zones"] == 2 and r["version"] == 5 and s.appels == ["checkconf", "reload"]
    assert "access-control-view: 192.168.1.50/32 wf-" in dropin(banc).read_text()
    assert json.loads((banc / "etat" / "resultat.json").read_text())["statut"] == "applique"
    assert any(a == "application" and "zones=2" in d for a, d in s.audits)


def test_application_identique_ne_recharge_pas(banc):
    ecrire_config(banc, config())
    lancer(banc, Faux())
    s = Faux()
    r = lancer(banc, s)
    assert r["statut"] == "inchange" and s.appels == [] and not any(a == "application" for a, _ in s.audits)
    assert json.loads((banc / "etat" / "resultat.json").read_text())["statut"] == "inchange"


def test_bascule_observe_vers_block_est_auditee(banc):
    ecrire_config(banc, config({"adulte": "observe", "jeux": "observe", "phishing": "observe"}))
    lancer(banc, Faux())
    ecrire_config(banc, config())
    s = Faux()
    lancer(banc, s)
    assert ("changement", "profil enfants jeux observe->block") in s.audits and "reload" in s.appels


def test_appareil_reassigne_est_audite(banc):
    ecrire_config(banc, config(appareils={MAC: {"nom": "T", "profil": "defaut", "exceptions": {}}}))
    lancer(banc, Faux())
    ecrire_config(banc, config())
    s = Faux()
    lancer(banc, s)
    assert ("changement", f"appareil {MAC} profil defaut->enfants") in s.audits


def test_controle_refuse_restaure_l_ancien_fichier(banc):
    ecrire_config(banc, config({"adulte": "block", "jeux": "observe", "phishing": "observe"}))
    lancer(banc, Faux())
    avant = dropin(banc).read_bytes()
    ecrire_config(banc, config())
    s = Faux(checkconf_ok=False)
    r = lancer(banc, s)
    assert r["statut"] == "refuse" and "erreur simulée" in r["message"] and dropin(banc).read_bytes() == avant
    assert "reload" not in s.appels and s.audits[-1][0] == "refuse"


def test_premiere_application_refusee_ne_laisse_rien(banc):
    ecrire_config(banc, config())
    assert lancer(banc, Faux(checkconf_ok=False))["statut"] == "refuse" and not dropin(banc).exists()


def test_rechargement_en_echec_restaure_et_recharge_l_ancien_etat(banc):
    ecrire_config(banc, config({"adulte": "block", "jeux": "observe", "phishing": "observe"}))
    lancer(banc, Faux())
    avant = dropin(banc).read_bytes()
    ecrire_config(banc, config())
    s = Faux(reloads_en_echec=1)
    r = lancer(banc, s)
    assert r["statut"] == "erreur" and dropin(banc).read_bytes() == avant
    assert s.appels == ["checkconf", "reload", "reload"] and s.audits[-1][0] == "rechargement-echoue"


def test_restauration_incomplete_est_dite(banc, monkeypatch):
    ecrire_config(banc, config({"adulte": "block", "jeux": "observe", "phishing": "observe"}))
    lancer(banc, Faux())
    ecrire_config(banc, config())
    reel = ctl._ecrire_atomique

    def capricieux(chemin, texte, mode=0o644):
        if capricieux.restauration:
            raise OSError("disque plein")
        return reel(chemin, texte, mode)
    capricieux.restauration = False
    s = Faux(checkconf_ok=False)
    ancien = s.verifier_unbound
    s.verifier_unbound = lambda: (setattr(capricieux, "restauration", True), ancien())[1]
    monkeypatch.setattr(ctl, "_ecrire_atomique", capricieux)
    r = lancer(banc, s)
    assert r["statut"] == "erreur" and "INCOMPLÈTE" in r["message"]


@pytest.mark.parametrize("contenu", ["pas du json", "[1, 2]", "null", '{"inconnu": 1}', json.dumps({"profils": {"defaut": {"categories": {"x": "block"}}}}),
                                     "x" * (1024 * 1024 + 10)])
def test_config_hostile_refusee_sans_toucher_au_dropin(banc, contenu):
    ecrire_config(banc, config({"adulte": "block", "jeux": "observe", "phishing": "observe"}))
    lancer(banc, Faux())
    avant = dropin(banc).read_bytes()
    (banc / "etat" / "config.json").write_text(contenu)
    r = lancer(banc, Faux())
    assert r["statut"] == "refuse" and dropin(banc).read_bytes() == avant and str(banc) not in r["message"]


def test_config_absente_n_est_pas_une_erreur_et_ne_fait_aucun_bruit(banc):
    s = Faux()
    r = lancer(banc, s)
    assert r["statut"] == "inchange" and s.appels == [] and s.audits == [] and not dropin(banc).exists()


def test_config_lien_symbolique_ou_non_regulier_refusee(banc):
    cible = banc / "secret.txt"
    cible.write_text(json.dumps(config()))
    (banc / "etat" / "config.json").symlink_to(cible)
    assert lancer(banc, Faux())["statut"] == "refuse"
    (banc / "etat" / "config.json").unlink()
    os.mkfifo(banc / "etat" / "config.json")
    assert lancer(banc, Faux())["statut"] == "refuse"


def test_budget_de_zones_refuse(banc):
    (banc / "etat" / "listes" / "jeux" / "hagezi-gambling-medium.lst").write_text("".join(f"d{i}.example.org\n" for i in range(1500)))      # 1 500 zones > zones_max = 1 000
    ecrire_config(banc, config())
    r = lancer(banc, Faux())
    assert r["statut"] == "refuse" and "budget" in r["message"] and not dropin(banc).exists()


def test_verrou_deja_tenu(banc):
    ecrire_config(banc, config())
    fd = os.open(banc / "racine" / "verrou", os.O_CREAT | os.O_RDWR, 0o600)
    fcntl.flock(fd, fcntl.LOCK_EX)
    try:
        s = Faux()
        r = lancer(banc, s)
        assert r["statut"] == "refuse" and "déjà en cours" in r["message"] and s.appels == []
    finally:
        os.close(fd)


def test_carte_des_adresses_et_du_profil_par_defaut(banc):
    ecrire_config(banc, config())
    lancer(banc, Faux())
    c = json.loads((banc / "etat" / "carte.json").read_text())
    a = c["adresses"]["192.168.1.50"]
    assert a["mac"] == MAC and a["profil"] == "enfants" and a["modes"]["jeux"] == "block" and a["vue"].startswith("wf-")
    assert c["defaut"]["reseaux"] == ["192.168.1.0/24", "2a01:db8::/64"] and c["defaut"]["modes"]["jeux"] == "observe"


def test_appareil_d_adguard_est_exclu_et_signale(banc):
    ecrire_config(banc, config())
    r = lancer(banc, Faux(adguard="server:\n    access-control-view: 192.168.1.50/32 sbx-tv-auto-tv-banc\n"))
    assert "192.168.1.50/32 wf-" not in dropin(banc).read_text()
    assert json.loads((banc / "etat" / "resultat.json").read_text())["exclus"] == {MAC: "geree par ad-guard"} and r["statut"] == "applique"


def test_droits_des_fichiers(banc):
    ecrire_config(banc, config())
    lancer(banc, Faux())
    assert stat.S_IMODE(dropin(banc).stat().st_mode) == 0o644
    for f in ("resultat.json", "carte.json"):
        assert stat.S_IMODE((banc / "etat" / f).stat().st_mode) == 0o640
    assert sorted(p.name for p in (banc / "u").iterdir()) == ["93-secubox-webfilter.conf"]      # aucun résidu temporaire


def test_statut_en_ligne_de_commande(banc, capsys):
    assert ctl.principal(["--etat", str(banc / "etat"), "status"]) == 1
    ecrire_config(banc, config())
    lancer(banc, Faux())
    assert ctl.principal(["--etat", str(banc / "etat"), "status"]) == 0
    assert json.loads(capsys.readouterr().out)["statut"] == "applique"
