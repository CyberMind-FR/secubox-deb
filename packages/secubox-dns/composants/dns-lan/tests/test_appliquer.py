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
        if getattr(self, "reload_echoue", False):
            raise appliquer.ErreurApplication("unbound-control reload a échoué : simulé")

    def redemarrer_unbound(self):
        self.appels.append("redemarrer-unbound")

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
    c = config.valider(brut, confiner=False)
    c["_verrou"] = tmp_path / "dns-lan.lock"
    return c


def poser_etat_gk2(cfg):
    """Pose sur le disque les fichiers exacts capturés sur gk2 (sans l'en-tête généré)."""
    d = Path(cfg["dossier"])
    for nom in ("96-secubox-lan.conf", "96-secubox-lan-ipv6.conf", "96-secubox-gk2-local.conf", "98-secubox-voicestudio-lan.conf"):
        (d / nom).write_text((FIXTURES / nom).read_text())
    Path(cfg["ipv6"]["dropin_reseau"]).write_text((FIXTURES / "50-secubox-ipv6-stable.conf").read_text())


def test_premiere_pose_ecrit_valide_recharge(cfg):
    s = Faux()
    r = appliquer.generer(cfg, s, verrou=cfg["_verrou"])
    assert len(r["ecrits"]) == 5 and r["recharge_unbound"] and r["recharge_reseau"]
    assert s.appels == ["checkconf", "redemarrer-unbound", "reload-reseau"]      # première pose : écoutes nouvelles, donc redémarrage
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
    assert "ecrits=5" in s.audits[0][1] and "unbound=redémarre" in s.audits[0][1]


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


# ── relecture de sécurité #1938 ───────────────────────────────────────────────────────────────────────────────────────────────────
def gen(cfg, s):
    return appliquer.generer(cfg, s, verrou=cfg["_verrou"])


def test_checkconf_timeout_restaure(cfg, monkeypatch):
    poser_etat_gk2(cfg)
    avant = {p.name: p.read_text() for p in Path(cfg["dossier"]).iterdir()}
    import subprocess

    def boum(*a, **k):
        raise subprocess.TimeoutExpired("unbound-checkconf", 60)
    import secubox_unbound
    monkeypatch.setattr(secubox_unbound.subprocess, "run", boum)     # la commande vit désormais dans la bibliothèque commune
    cfg2 = dict(cfg, lan={"interface": "192.168.1.201", "acces": ["192.168.0.0/16"]})
    s = appliquer.Systeme()
    s.audit = lambda a, d="": None
    with pytest.raises(appliquer.ErreurApplication):
        gen(cfg2, s)
    assert {p.name: p.read_text() for p in Path(cfg["dossier"]).iterdir()} == avant


def test_restauration_qui_echoue_continue_et_le_dit(cfg, monkeypatch):
    poser_etat_gk2(cfg)
    cfg2 = dict(cfg, lan={"interface": "192.168.1.201", "acces": ["192.168.0.0/16"]}, hote=[{"nom": "voicestudio.gk3.secubox.in", "adresse": "192.168.1.10", "ttl": 300}])
    s = Faux(checkconf_ok=False)
    reel = appliquer._ecrire_atomique
    etat = {"restauration": False}

    def capricieux(chemin, texte):
        if etat["restauration"] and chemin.name == "96-secubox-lan.conf":
            raise OSError("disque plein")
        reel(chemin, texte)
    ancien_verifier = s.verifier_unbound

    def verifier():
        etat["restauration"] = True                              # tout ce qui suit la validation est une restauration
        return ancien_verifier()
    s.verifier_unbound = verifier
    monkeypatch.setattr(appliquer, "_ecrire_atomique", capricieux)
    with pytest.raises(appliquer.ErreurApplication) as e:
        gen(cfg2, s)
    assert "96-secubox-lan.conf" in str(e.value)
    assert s.audits[-1][0] == "generate-echec-restauration" and "96-secubox-lan.conf" in s.audits[-1][1]
    # les autres fichiers ont quand même été restaurés
    assert (Path(cfg["dossier"]) / "98-secubox-voicestudio-lan.conf").read_text() == (FIXTURES / "98-secubox-voicestudio-lan.conf").read_text()


def test_echec_du_rechargement_restaure_et_audite(cfg):
    poser_etat_gk2(cfg)
    avant = (Path(cfg["dossier"]) / "96-secubox-lan.conf").read_text()
    cfg2 = dict(cfg, lan={"interface": "192.168.1.200", "acces": ["192.168.0.0/16", "10.0.0.0/8"]})
    s = Faux()
    s.reload_echoue = True
    with pytest.raises(appliquer.ErreurApplication):
        gen(cfg2, s)
    assert (Path(cfg["dossier"]) / "96-secubox-lan.conf").read_text() == avant
    assert s.audits[-1][0] == "generate-rechargement-echoue"


def test_nouvelle_ecoute_redemarre_au_lieu_de_recharger(cfg):
    """`unbound-control reload` ne rouvre pas les sockets d'écoute : une nouvelle ligne `interface:` exige un redémarrage."""
    gen(cfg, Faux())
    s = Faux()
    r = gen(dict(cfg, lan={"interface": "192.168.1.201", "acces": ["192.168.0.0/16"]}), s)
    assert r["recharge_unbound"] and s.appels == ["checkconf", "redemarrer-unbound"]
    s2 = Faux()
    gen(dict(cfg, lan={"interface": "192.168.1.201", "acces": ["192.168.0.0/16", "10.0.0.0/8"]}), s2)
    assert s2.appels == ["checkconf", "reload-unbound"]                 # contrôle d'accès seul : le rechargement suffit


def test_section_retiree_supprime_le_fichier_genere_seulement(cfg):
    gen(cfg, Faux())
    d = Path(cfg["dossier"])
    (d / "99-a-la-main.conf").write_text("server:\n")
    sans_hote = {k: v for k, v in cfg.items() if k != "hote"}
    assert [Path(x).name for x in appliquer.deriver(sans_hote)] == ["98-secubox-voicestudio-lan.conf"]
    s = Faux()
    r = gen(sans_hote, s)
    assert not (d / "98-secubox-voicestudio-lan.conf").exists() and (d / "99-a-la-main.conf").exists()
    assert r["recharge_unbound"] and "reload-unbound" in s.appels
    assert appliquer.deriver(sans_hote) == []


def test_fichier_pose_a_la_main_jamais_supprime(cfg):
    d = Path(cfg["dossier"])
    (d / "98-secubox-voicestudio-lan.conf").write_text("server:\n    local-zone: \"x.\" static\n")      # sans la marque générée
    sans_hote = {k: v for k, v in cfg.items() if k != "hote"}
    gen(sans_hote, Faux())
    assert (d / "98-secubox-voicestudio-lan.conf").exists()


def test_verrou_exclusif(tmp_path):
    chemin = tmp_path / "v.lock"
    with appliquer.verrou_exclusif(chemin):
        with pytest.raises(appliquer.ErreurApplication):
            with appliquer.verrou_exclusif(chemin, attendre=False):
                pass
    with appliquer.verrou_exclusif(chemin, attendre=False):          # libéré à la sortie
        pass


def test_cible_lien_symbolique_refusee(cfg, tmp_path):
    cible = tmp_path / "ailleurs.conf"
    cible.write_text("server:\n")
    (Path(cfg["dossier"]) / "96-secubox-lan.conf").symlink_to(cible)
    with pytest.raises(appliquer.ErreurApplication):
        gen(cfg, Faux())
    assert cible.read_text() == "server:\n"


def test_audit_inaccessible_previent_sur_stderr(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(appliquer, "AUDIT", tmp_path / "absent" / "audit.log")
    appliquer.Systeme().audit("generate", "x")
    assert "audit" in capsys.readouterr().err.lower()


def test_binaires_en_chemin_absolu_sans_variable_d_environnement():
    import inspect

    import secubox_unbound
    for c in (secubox_unbound.CHECKCONF, secubox_unbound.CONTROL, secubox_unbound.SYSTEMCTL, appliquer.NETWORKCTL):
        assert c.startswith("/")
    assert "os.environ" not in inspect.getsource(appliquer) and "os.environ" not in inspect.getsource(secubox_unbound)


def test_dossiers_crees_en_0755_et_tous_retires_au_retour_arriere(cfg, tmp_path):
    profond = tmp_path / "a" / "b" / "c.network.d"
    cfg2 = dict(cfg, ipv6=dict(cfg["ipv6"], dropin_reseau=str(profond / "50.conf")))
    s = Faux(checkconf_ok=False)
    with pytest.raises(appliquer.ErreurApplication):
        gen(cfg2, s)
    assert not (tmp_path / "a").exists()
    gen(cfg2, Faux())
    assert oct((tmp_path / "a" / "b").stat().st_mode & 0o777) == "0o755"
