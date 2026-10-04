# SPDX-License-Identifier: LicenseRef-CMSD-1.0
"""Pose, validation, retour arrière, rechargement conditionnel et audit (#1938)."""
import tomllib
from pathlib import Path

import pytest

from dns_lan import appliquer, config

RACINE = Path(__file__).resolve().parent.parent
FIXTURES = RACINE / "tests" / "fixtures" / "gk2"


class Faux:
    """Système simulé : enregistre ce qui est demandé."""
    def __init__(self, checkconf_ok=True):
        self.checkconf_ok = checkconf_ok
        self.appels = []
        self.audits = []

    def verifier_unbound(self):
        self.appels.append("checkconf")
        return self.checkconf_ok, "" if self.checkconf_ok else "unbound-checkconf: erreur simulée"

    def recharger_unbound(self):
        self.appels.append("reload-unbound")

    def recharger_reseau(self):
        self.appels.append("reload-reseau")

    def audit(self, action, detail=""):
        self.audits.append((action, detail))


@pytest.fixture
def cfg(tmp_path):
    brut = tomllib.loads((RACINE / "conf" / "dns-lan.toml").read_text())
    brut["unbound"] = {"dossier": str(tmp_path / "unbound.conf.d")}
    brut["ipv6"]["dropin_reseau"] = str(tmp_path / "reseau" / "50-secubox-ipv6-stable.conf")
    (tmp_path / "unbound.conf.d").mkdir()
    (tmp_path / "reseau").mkdir()
    return config.valider(brut)


def poser_etat_gk2(cfg):
    """Pose sur le disque les fichiers exacts capturés sur gk2 (sans l'en-tête généré)."""
    d = Path(cfg["dossier"])
    for nom in ("96-secubox-lan.conf", "96-secubox-lan-ipv6.conf", "96-secubox-gk2-local.conf", "98-secubox-voicestudio-lan.conf"):
        (d / nom).write_text((FIXTURES / nom).read_text())
    Path(cfg["ipv6"]["dropin_reseau"]).write_text((FIXTURES / "50-secubox-ipv6-stable.conf").read_text())


def test_premiere_pose_ecrit_valide_recharge(cfg):
    s = Faux()
    r = appliquer.generer(cfg, s)
    assert len(r["ecrits"]) == 5 and r["recharge_unbound"] and r["recharge_reseau"]
    assert s.appels == ["checkconf", "reload-unbound", "reload-reseau"]
    assert (Path(cfg["dossier"]) / "96-secubox-lan.conf").read_text().startswith("# SPDX-License-Identifier")


def test_etat_gk2_existant_aucun_rechargement(cfg):
    """Mise à jour sur gk2 : seuls les commentaires changent, le DNS ne doit PAS être rechargé."""
    poser_etat_gk2(cfg)
    s = Faux()
    r = appliquer.generer(cfg, s)
    assert r["recharge_unbound"] is False and r["recharge_reseau"] is False
    assert "reload-unbound" not in s.appels and "reload-reseau" not in s.appels
    assert len(r["ecrits"]) == 5        # les commentaires (en-tête généré) sont mis à jour


def test_idempotence(cfg):
    appliquer.generer(cfg, Faux())
    s = Faux()
    r = appliquer.generer(cfg, s)
    assert r["ecrits"] == [] and s.appels == [] and s.audits == []


def test_changement_effectif_recharge_unbound_seulement(cfg):
    appliquer.generer(cfg, Faux())
    cfg2 = dict(cfg, hote=[{"nom": "voicestudio.gk3.secubox.in", "adresse": "192.168.1.10", "ttl": 300}])
    s = Faux()
    r = appliquer.generer(cfg2, s)
    assert r["recharge_unbound"] and not r["recharge_reseau"]
    assert s.appels == ["checkconf", "reload-unbound"]


def test_checkconf_echoue_restaure_et_ne_recharge_pas(cfg):
    poser_etat_gk2(cfg)
    avant = {p.name: p.read_text() for p in Path(cfg["dossier"]).iterdir()}
    avant_reseau = Path(cfg["ipv6"]["dropin_reseau"]).read_text()
    cfg2 = dict(cfg, lan={"interface": "192.168.1.201", "acces": ["192.168.0.0/16"]})
    s = Faux(checkconf_ok=False)
    with pytest.raises(appliquer.ErreurApplication) as e:
        appliquer.generer(cfg2, s)
    assert "erreur simulée" in str(e.value)
    assert {p.name: p.read_text() for p in Path(cfg["dossier"]).iterdir()} == avant
    assert Path(cfg["ipv6"]["dropin_reseau"]).read_text() == avant_reseau
    assert not any(a.startswith("reload") for a in s.appels)
    assert s.audits[-1][0] == "generate-refuse"


def test_premiere_pose_echouee_ne_laisse_rien(cfg):
    s = Faux(checkconf_ok=False)
    with pytest.raises(appliquer.ErreurApplication):
        appliquer.generer(cfg, s)
    assert list(Path(cfg["dossier"]).iterdir()) == [] and list(Path(cfg["ipv6"]["dropin_reseau"]).parent.iterdir()) == []


def test_audit_une_ligne_par_application_effective(cfg):
    s = Faux()
    appliquer.generer(cfg, s)
    assert [a for a, _ in s.audits] == ["generate"]
    assert "ecrits=5" in s.audits[0][1] and "unbound=recharge" in s.audits[0][1]


def test_fichier_ecrit_avec_droits_644_sans_residu(cfg):
    appliquer.generer(cfg, Faux())
    for p in list(Path(cfg["dossier"]).iterdir()) + list(Path(cfg["ipv6"]["dropin_reseau"]).parent.iterdir()):
        assert oct(p.stat().st_mode & 0o777) == "0o644", p
        assert ".tmp" not in p.name and not p.name.endswith(".bak"), p


def test_derive_signale_ecart_effectif_seulement(cfg):
    poser_etat_gk2(cfg)
    assert appliquer.deriver(cfg) == []                       # état gk2 identique en lignes effectives
    (Path(cfg["dossier"]) / "96-secubox-lan.conf").write_text("server:\n    interface: 192.168.1.77\n")
    assert [Path(p).name for p in appliquer.deriver(cfg)] == ["96-secubox-lan.conf"]
    Path(cfg["ipv6"]["dropin_reseau"]).unlink()
    assert {Path(p).name for p in appliquer.deriver(cfg)} == {"96-secubox-lan.conf", "50-secubox-ipv6-stable.conf"}
