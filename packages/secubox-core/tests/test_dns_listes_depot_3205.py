# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3205 — dépôt des sources, transaction sur plusieurs fichiers, application par secubox-dns-listes.

Les générateurs (webfilter, adblock, adult) déposent leur rendu inchangé comme SOURCE ; un seul service compile, pose
92-secubox-listes.conf et retire les anciens fichiers en UNE transaction : une vérification, un rechargement, et au
moindre échec TOUT est remis octet pour octet. Un ancien fichier trouvé dans unbound.conf.d est adopté comme source."""
import json
import os
import re
import signal
import stat
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "common"))
import secubox_unbound as U  # noqa: E402
from secubox_unbound import depot as D  # noqa: E402

ADBLOCK = 'server:\n    local-zone: "ads.example." always_nxdomain\n    local-zone: "a.ads.example." always_nxdomain\n'
ADULT = 'server:\n    local-zone: "porn.example." always_nxdomain\n'
ACL = "server:\n    access-control: 192.168.0.0/16 allow\n"


class Faux(U.SystemeUnbound):
    MODULE = "test"

    def __init__(self, verif=(True, ""), recharge_ok=True):
        self.verif, self.recharge_ok, self.appels = verif, recharge_ok, []

    def verifier_unbound(self):
        self.appels.append("verifier")
        return self.verif

    def recharger_unbound(self):
        self.appels.append("recharger")
        if not self.recharge_ok:
            raise self.ERREUR("reload a échoué")

    def audit(self, action, detail=""):
        self.appels.append(("audit", action))
        self.dernier_audit = detail


@pytest.fixture
def lieux(tmp_path):
    conf = tmp_path / "unbound.conf.d"
    conf.mkdir()
    (conf / "10-acl.conf").write_text(ACL)
    return {"sources": tmp_path / "sources", "conf_d": conf, "etat": tmp_path / "etat.json",
            "reglages": tmp_path / "dns-listes.toml", "verrou": tmp_path / "verrou"}


def _appliquer(lieux, s=None):
    return D.appliquer(systeme=s or Faux(), **lieux)


# ── transaction sur plusieurs fichiers ───────────────────────────────────────

def test_poser_vues_ecrit_retire_verifie_une_fois_recharge_une_fois(tmp_path):
    a, b = tmp_path / "a.conf", tmp_path / "b.conf"
    b.write_text("vieux")
    s = Faux()
    assert U.poser_vues({a: "neuf", b: None}, s) == "applique"
    assert a.read_text() == "neuf" and not b.exists() and s.appels == ["verifier", "recharger"]


def test_poser_vues_identique_ne_touche_rien(tmp_path):
    a = tmp_path / "a.conf"
    a.write_text("x")
    s = Faux()
    assert U.poser_vues({a: "x", tmp_path / "absent.conf": None}, s) == "inchange" and s.appels == []


@pytest.mark.parametrize("faux", [Faux(verif=(False, "erreur ligne 3")), Faux(recharge_ok=False)])
def test_poser_vues_un_echec_remet_tout_octet_pour_octet(tmp_path, faux):
    a, b, c = tmp_path / "a.conf", tmp_path / "b.conf", tmp_path / "c.conf"
    a.write_bytes(b"ancien a\x00")
    b.write_text("ancien b")
    with pytest.raises(U.ErreurUnbound):
        U.poser_vues({a: "neuf a", b: None, c: "neuf c"}, faux)
    assert a.read_bytes() == b"ancien a\x00" and b.read_text() == "ancien b" and not c.exists()


def test_poser_vues_forcer_verifie_et_recharge_meme_identique(tmp_path):
    """Après une transaction interrompue (processus tué), les fichiers sont déjà basculés mais jamais vérifiés."""
    a = tmp_path / "a.conf"
    a.write_text("x")
    s = Faux()
    assert U.poser_vues({a: "x"}, s, forcer=True) == "applique" and s.appels == ["verifier", "recharger"]


def test_une_restauration_qui_echoue_est_dite(tmp_path, monkeypatch):
    """Disque plein pendant la remise en place : l'état sur disque est mélangé, il faut le dire (et l'auditer)."""
    a = tmp_path / "a.conf"
    a.write_text("ancien")
    reel = U._restaurer

    def plein(chemin, ancien):
        if chemin == a:
            raise OSError(28, "No space left on device")
        return reel(chemin, ancien)
    monkeypatch.setattr(U, "_restaurer", plein)
    s = Faux(verif=(False, "refus"))
    with pytest.raises(U.ErreurUnbound, match="INCOMPLET"):
        U.poser_vues({a: "neuf", tmp_path / "b.conf": "b"}, s)
    assert ("audit", "restauration-echouee") in s.appels and not (tmp_path / "b.conf").exists()


def test_un_second_rechargement_qui_echoue_est_dit(tmp_path):
    a = tmp_path / "a.conf"
    a.write_text("ancien")
    with pytest.raises(U.ErreurUnbound, match="second rechargement"):
        U.poser_vues({a: "neuf"}, Faux(recharge_ok=False))
    assert a.read_text() == "ancien"


def test_un_arret_pendant_la_verification_remet_tout(tmp_path):
    """SIGTERM devient SystemExit (secubox-dns-listes) : la remise en place a lieu avant que le processus ne sorte."""
    a = tmp_path / "a.conf"
    a.write_text("ancien")

    class Arrete(Faux):
        def verifier_unbound(self):
            raise SystemExit(143)
    with pytest.raises(SystemExit):
        U.poser_vues({a: "neuf"}, Arrete())
    assert a.read_text() == "ancien"


# ── dépôt des sources par les générateurs ────────────────────────────────────

def test_deposer_et_retirer_une_source(tmp_path):
    src = tmp_path / "sources"
    assert D.deposer_source("95-secubox-adblock.conf", ADBLOCK, src) == "depose"
    assert D.deposer_source("95-secubox-adblock.conf", ADBLOCK, src) == "inchange"
    assert (src / "95-secubox-adblock.conf").read_text() == ADBLOCK
    assert D.retirer_source("95-secubox-adblock.conf", src) == "retire"
    assert D.retirer_source("95-secubox-adblock.conf", src) == "absent"


@pytest.mark.parametrize("nom", ["../etc/passwd", "97-autre.conf", "95-secubox-adblock.conf/x", ""])
def test_seules_les_sources_connues(tmp_path, nom):
    with pytest.raises(D.ErreurDepot):
        D.deposer_source(nom, ADBLOCK, tmp_path / "sources")


def test_l_arbre_est_hors_du_dossier_du_compte_partage():
    """/var/lib/secubox appartient au compte secubox : il pourrait renommer un sous-dossier root et le remplacer
    (relecture #3205). L'arbre des listes est à part, comme /var/lib/secubox-webfilter-ctl."""
    for chemin in (D.SOURCES, D.ETAT, D.VERROU):
        assert str(chemin).startswith("/var/lib/secubox-dns-listes/"), chemin


def test_un_dossier_des_sources_lien_symbolique_est_refuse(tmp_path):
    ailleurs = tmp_path / "ailleurs"
    ailleurs.mkdir()
    (tmp_path / "sources").symlink_to(ailleurs)
    with pytest.raises(D.ErreurDepot, match="dossier"):
        D.deposer_source("95-secubox-adblock.conf", ADBLOCK, tmp_path / "sources")
    assert list(ailleurs.iterdir()) == []


@pytest.mark.parametrize("lequel", ["sources", "parent"])
def test_un_dossier_ouvert_au_groupe_est_refuse(tmp_path, lequel):
    parent = tmp_path / "arbre"
    src = parent / "sources"
    src.mkdir(parents=True)
    os.chmod(src if lequel == "sources" else parent, 0o775)
    with pytest.raises(D.ErreurDepot, match="dossier"):
        D.deposer_source("95-secubox-adblock.conf", ADBLOCK, src)


def test_le_dossier_des_sources_est_cree_ferme(tmp_path):
    D.deposer_source("95-secubox-adblock.conf", ADBLOCK, tmp_path / "sources")
    assert stat.S_IMODE((tmp_path / "sources").stat().st_mode) & 0o022 == 0


def test_une_source_n_est_pas_ecrite_a_travers_un_lien(tmp_path):
    src = tmp_path / "sources"
    src.mkdir()
    (src / "95-secubox-adblock.conf").symlink_to(tmp_path / "ailleurs")
    with pytest.raises(D.ErreurDepot):
        D.deposer_source("95-secubox-adblock.conf", ADBLOCK, src)
    assert not (tmp_path / "ailleurs").exists()


# ── application ──────────────────────────────────────────────────────────────

def test_compile_pose_92_et_retire_les_anciens(lieux):
    D.deposer_source("95-secubox-adblock.conf", ADBLOCK, lieux["sources"])
    (lieux["conf_d"] / "96-secubox-adult.conf").write_text(ADULT)              # ancien fichier : adopté
    r = _appliquer(lieux)
    conf = lieux["conf_d"]
    assert r["etat"] == "applique" and r["mode"] == "compile"
    texte = (conf / "92-secubox-listes.conf").read_text()
    assert '"ads.example."' in texte and '"porn.example."' in texte and '"a.ads.example."' not in texte
    assert not (conf / "95-secubox-adblock.conf").exists() and not (conf / "96-secubox-adult.conf").exists()
    assert (lieux["sources"] / "96-secubox-adult.conf").read_text() == ADULT
    etat = json.loads(lieux["etat"].read_text())
    assert etat["etat"] == "applique" and etat["stats"]["emis"] == 2 and "erreur" not in etat


def test_un_ancien_fichier_reecrit_par_un_generateur_non_mis_a_jour_est_readopte(lieux):
    D.deposer_source("96-secubox-adult.conf", ADULT, lieux["sources"])
    _appliquer(lieux)
    plus_recent = ADULT + '    local-zone: "neuf.example." always_nxdomain\n'
    (lieux["conf_d"] / "96-secubox-adult.conf").write_text(plus_recent)
    assert _appliquer(lieux)["etat"] == "applique"
    assert '"neuf.example."' in (lieux["conf_d"] / "92-secubox-listes.conf").read_text()
    assert not (lieux["conf_d"] / "96-secubox-adult.conf").exists()


def test_rien_de_neuf_rien_n_est_recharge(lieux):
    D.deposer_source("95-secubox-adblock.conf", ADBLOCK, lieux["sources"])
    _appliquer(lieux)
    s = Faux()
    assert _appliquer(lieux, s)["etat"] == "inchange" and "recharger" not in s.appels


def test_mode_direct_remet_les_fichiers_tels_quels(lieux):
    D.deposer_source("95-secubox-adblock.conf", ADBLOCK, lieux["sources"])
    _appliquer(lieux)
    lieux["reglages"].write_text('mode = "direct"\n')
    r = _appliquer(lieux)
    assert r["mode"] == "direct" and r["etat"] == "applique"
    assert (lieux["conf_d"] / "95-secubox-adblock.conf").read_text() == ADBLOCK
    assert not (lieux["conf_d"] / "92-secubox-listes.conf").exists()


def test_une_source_illisible_ne_touche_a_rien(lieux):
    D.deposer_source("95-secubox-adblock.conf", 'server:\n    local-data: "x. A 1.2.3.4"\n', lieux["sources"])
    (lieux["conf_d"] / "92-secubox-listes.conf").write_text("ancien")
    s = Faux()
    r = _appliquer(lieux, s)
    assert r["etat"] == "erreur" and "local-data" in r["erreur"]
    assert "verifier" not in s.appels and "recharger" not in s.appels and ("audit", "listes-erreur") in s.appels
    assert (lieux["conf_d"] / "92-secubox-listes.conf").read_text() == "ancien"
    assert json.loads(lieux["etat"].read_text())["etat"] == "erreur"


def test_une_configuration_refusee_est_annoncee_et_rien_ne_change(lieux):
    (lieux["conf_d"] / "95-secubox-adblock.conf").write_text(ADBLOCK)
    r = _appliquer(lieux, Faux(verif=(False, "ligne 4 : erreur")))
    assert r["etat"] == "erreur" and "ligne 4" in r["erreur"]
    assert (lieux["conf_d"] / "95-secubox-adblock.conf").read_text() == ADBLOCK      # remis
    assert not (lieux["conf_d"] / "92-secubox-listes.conf").exists()


def test_sans_unbound_rien_a_faire(tmp_path):
    r = D.appliquer(systeme=Faux(), sources=tmp_path / "s", conf_d=tmp_path / "absent", etat=tmp_path / "e.json",
                    reglages=tmp_path / "r.toml", verrou=tmp_path / "v")
    assert r["etat"] == "sans-unbound"


def test_sans_aucune_source_92_retire(lieux):
    D.deposer_source("95-secubox-adblock.conf", ADBLOCK, lieux["sources"])
    _appliquer(lieux)
    D.retirer_source("95-secubox-adblock.conf", lieux["sources"])
    assert _appliquer(lieux)["etat"] == "applique"
    assert not (lieux["conf_d"] / "92-secubox-listes.conf").exists()


# ── ne recompiler que si une entrée a changé (le .path surveille AUSSI unbound.conf.d) ──────────────────────────

@pytest.fixture
def compilations(monkeypatch):
    vrai, appels = D.listes.compiler, []

    def compter(sources, contexte):
        appels.append(sorted(p.name for p in sources))
        return vrai(sources, contexte)
    monkeypatch.setattr(D.listes, "compiler", compter)
    return appels


def test_rien_de_neuf_ne_recompile_pas(lieux, compilations):
    D.deposer_source("95-secubox-adblock.conf", ADBLOCK, lieux["sources"])
    _appliquer(lieux)
    s = Faux()
    r = _appliquer(lieux, s)
    assert r["etat"] == "inchange" and len(compilations) == 1 and s.appels == []
    assert r["stats"]["emis"] == 1                                            # le relevé de la dernière compilation reste lisible


def test_un_contexte_qui_ne_decide_rien_ne_recompile_pas(lieux, compilations):
    D.deposer_source("95-secubox-adblock.conf", ADBLOCK, lieux["sources"])
    _appliquer(lieux)
    (lieux["conf_d"] / "60-noms.conf").write_text('server:\n    local-data: "box.lan. A 192.168.1.1"\n')
    assert _appliquer(lieux)["etat"] == "inchange" and len(compilations) == 1


def test_un_reseau_nouveau_dans_le_contexte_recompile(lieux, compilations):
    """Une vue TV ou un réseau ajouté après la compilation : ses adresses ne porteraient aucune étiquette du 92."""
    D.deposer_source("95-secubox-adblock.conf", ADBLOCK, lieux["sources"])
    _appliquer(lieux)
    (lieux["conf_d"] / "94-tv.conf").write_text("server:\n    access-control-view: 192.168.1.95/32 tv\nview:\n    name: \"tv\"\n")
    _appliquer(lieux)
    assert len(compilations) == 2


def test_une_source_deposee_pendant_la_compilation_est_reprise(lieux, monkeypatch):
    """systemd ne relance pas une unité déjà active : un dépôt arrivé pendant la compilation serait perdu jusqu'au lendemain."""
    vrai, appels = D.listes.compiler, []

    def compiler(sources, contexte):
        appels.append(1)
        if len(appels) == 1:
            D.deposer_source("96-secubox-adult.conf", ADULT, lieux["sources"])
        return vrai(sources, contexte)
    monkeypatch.setattr(D.listes, "compiler", compiler)
    D.deposer_source("95-secubox-adblock.conf", ADBLOCK, lieux["sources"])
    r = _appliquer(lieux)
    assert len(appels) == 2 and r["etat"] == "applique" and r["passes"] == 2
    assert '"porn.example."' in (lieux["conf_d"] / "92-secubox-listes.conf").read_text()


def test_un_echec_n_est_pas_retente_sur_les_memes_entrees(lieux, compilations):
    """La remise en place après un échec écrit dans unbound.conf.d, que le .path surveille : sans cette garde, deux minutes
    de compilation en boucle."""
    (lieux["conf_d"] / "95-secubox-adblock.conf").write_text(ADBLOCK)
    assert D.appliquer(systeme=Faux(verif=(False, "x")), maintenant=lambda: 1000.0, **lieux)["etat"] == "erreur"
    s = Faux()
    r = D.appliquer(systeme=s, maintenant=lambda: 1000.0 + D.REESSAI_S - 1, **lieux)
    assert r["etat"] == "erreur" and len(compilations) == 1 and s.appels == []


def test_un_echec_ancien_est_retente(lieux, compilations):
    (lieux["conf_d"] / "95-secubox-adblock.conf").write_text(ADBLOCK)
    D.appliquer(systeme=Faux(verif=(False, "x")), maintenant=lambda: 1000.0, **lieux)
    r = D.appliquer(systeme=Faux(), maintenant=lambda: 1000.0 + D.REESSAI_S + 1, **lieux)
    assert r["etat"] == "applique" and len(compilations) == 2


def test_une_nouvelle_version_du_compilateur_recompile(lieux, compilations, monkeypatch, tmp_path):
    code = tmp_path / "listes.py"
    code.write_text("v1")
    monkeypatch.setattr(D, "_CODE", (code,))
    D.deposer_source("95-secubox-adblock.conf", ADBLOCK, lieux["sources"])
    _appliquer(lieux)
    code.write_text("v2, plus longue")
    _appliquer(lieux)
    assert len(compilations) == 2


def test_une_source_deposee_apres_la_derniere_passe_n_est_pas_perdue(lieux, monkeypatch):
    """Relecture #3205 : la signature notée doit être celle de ce qui a été COMPILÉ. Notée après coup, un dépôt arrivé
    pendant la dernière passe passait pour « déjà appliqué » au passage suivant."""
    vrai, appels = D.listes.compiler, []

    def compiler(sources, contexte):
        appels.append(1)
        n = len(appels)
        res = vrai(sources, contexte)                               # sources déjà lues...
        if n <= D.PASSES_MAX:                                       # ... un dépôt arrive pendant CHAQUE passe du premier passage
            D.deposer_source("96-secubox-adult.conf", ADULT + f'    local-zone: "n{n}.example." always_nxdomain\n', lieux["sources"])
        return res
    monkeypatch.setattr(D.listes, "compiler", compiler)
    D.deposer_source("95-secubox-adblock.conf", ADBLOCK, lieux["sources"])
    r = _appliquer(lieux)
    assert r["passes"] == D.PASSES_MAX and len(appels) == D.PASSES_MAX
    r = _appliquer(lieux)
    assert len(appels) == D.PASSES_MAX + 1 and r["etat"] == "applique"
    assert f'"n{D.PASSES_MAX}.example."' in (lieux["conf_d"] / "92-secubox-listes.conf").read_text()


def test_une_source_corrective_deposee_pendant_un_echec_est_reprise(lieux, monkeypatch):
    vrai, appels = D.listes.compiler, []

    def compiler(sources, contexte):
        appels.append(1)
        if len(appels) == 1:
            D.deposer_source("95-secubox-adblock.conf", ADBLOCK, lieux["sources"])      # la correction arrive pendant la passe
            raise D.listes.ErreurListes("95-secubox-adblock.conf:2 : ligne non reconnue (local-zone)")
        return vrai(sources, contexte)
    monkeypatch.setattr(D.listes, "compiler", compiler)
    D.deposer_source("95-secubox-adblock.conf", "server:\n", lieux["sources"])
    assert D.appliquer(systeme=Faux(), maintenant=lambda: 1000.0, **lieux)["etat"] == "erreur"
    assert D.appliquer(systeme=Faux(), maintenant=lambda: 1010.0, **lieux)["etat"] == "applique" and len(appels) == 2


def test_l_etat_est_en_cours_pendant_la_passe(lieux, monkeypatch):
    vrai, vus = D.listes.compiler, []

    def compiler(sources, contexte):
        vus.append(json.loads(lieux["etat"].read_text())["etat"])
        return vrai(sources, contexte)
    monkeypatch.setattr(D.listes, "compiler", compiler)
    D.deposer_source("95-secubox-adblock.conf", ADBLOCK, lieux["sources"])
    _appliquer(lieux)
    assert vus == ["en-cours"]


def test_une_passe_interrompue_est_verifiee_et_rechargee(lieux):
    """Processus tué (OOM, délai) après la bascule : au passage suivant, les fichiers sont identiques mais n'ont jamais
    été vérifiés ni chargés."""
    D.deposer_source("95-secubox-adblock.conf", ADBLOCK, lieux["sources"])
    _appliquer(lieux)
    e = json.loads(lieux["etat"].read_text())
    lieux["etat"].write_text(json.dumps({**e, "etat": "en-cours"}))
    s = Faux()
    r = _appliquer(lieux, s)
    assert r["etat"] == "applique" and s.appels[:2] == ["verifier", "recharger"]


def test_un_echec_court_circuite_garde_sa_date_et_rafraichit_t(lieux):
    (lieux["conf_d"] / "95-secubox-adblock.conf").write_text(ADBLOCK)
    D.appliquer(systeme=Faux(verif=(False, "x")), maintenant=lambda: 1000.0, **lieux)
    r = D.appliquer(systeme=Faux(), maintenant=lambda: 1010.0, **lieux)
    assert r["etat"] == "erreur" and r["t"] == 1010 and r["t_echec"] == 1000


def test_le_verrou_est_prive(lieux):
    _appliquer(lieux)
    assert stat.S_IMODE(lieux["verrou"].stat().st_mode) == 0o600


def test_un_verrou_lien_symbolique_est_refuse(lieux, tmp_path):
    (tmp_path / "cible").write_text("")
    lieux["verrou"].symlink_to(tmp_path / "cible")
    assert _appliquer(lieux)["etat"] == "erreur"


def test_les_fichiers_caches_ne_sont_pas_du_contexte(lieux):
    """Unbound n'inclut pas « .sbx-restaure-*.conf » (restauration interrompue) : le compilateur non plus."""
    (lieux["conf_d"] / ".sbx-restaure-10.conf").write_text("server:\n    access-control: 10.0.0.0/8 allow\n")
    assert [p.name for p in D.fichiers_contexte(lieux["conf_d"])] == ["10-acl.conf"]


def test_le_mode_direct_ne_recopie_pas_une_source_invalide(lieux):
    lieux["reglages"].write_text('mode = "direct"\n')
    D.deposer_source("95-secubox-adblock.conf", 'server:\n    local-data: "x. A 1.2.3.4"\n', lieux["sources"])
    r = _appliquer(lieux)
    assert r["etat"] == "erreur" and not (lieux["conf_d"] / "95-secubox-adblock.conf").exists()


def test_un_toml_illisible_est_signale(tmp_path, capsys):
    (tmp_path / "r.toml").write_text("mode = = \n")
    assert D.lire_mode(tmp_path / "r.toml") == "compile" and "illisible" in capsys.readouterr().err


# ── le rechargement n'est réussi que quand Unbound répond de nouveau (#2969) ─────────────────────────────────────

def _commandes(monkeypatch, statuts):
    appels, reponses = [], iter(statuts)

    def commande(args, delai):
        appels.append(args[-1])
        return (True, "ok") if args[-1] == "reload" else next(reponses)
    monkeypatch.setattr(U, "commande", commande)
    monkeypatch.setattr(D, "commande", commande)
    monkeypatch.setattr(D.time, "sleep", lambda s: None)
    return appels


def test_le_rechargement_attend_qu_unbound_reponde(monkeypatch):
    appels = _commandes(monkeypatch, [(False, "refusé"), (False, "refusé"), (True, "is running")])
    D.SystemeListes().recharger_unbound()
    assert appels == ["reload", "status", "status", "status"]


def test_un_unbound_qui_ne_repond_plus_est_une_erreur(monkeypatch):
    _commandes(monkeypatch, [(False, "refusé")] * 1000)
    s = D.SystemeListes()
    s.ATTENTE_S = 0
    with pytest.raises(U.ErreurUnbound, match="ne répond plus"):
        s.recharger_unbound()


# ── empaquetage ──────────────────────────────────────────────────────────────

PAQUET = Path(__file__).resolve().parents[1]


def _unite(nom):
    out = {}
    for ligne in (PAQUET / "systemd" / nom).read_text().splitlines():
        if "=" in ligne and not ligne.startswith("#"):
            k, v = ligne.split("=", 1)
            out.setdefault(k.strip(), []).append(v.strip())
    return out


def test_service_root_durci_et_exception_ecrite():
    """RULES-CODE § 10 : root est une EXCEPTION (écrire /etc/unbound, unbound-control), écrite avec sa raison et ce test."""
    u = _unite("secubox-dns-listes.service")
    for cle, val in {"NoNewPrivileges": "yes", "ProtectSystem": "strict", "ProtectHome": "yes", "PrivateTmp": "yes",
                     "ProtectKernelTunables": "yes", "ProtectControlGroups": "yes", "RestrictSUIDSGID": "yes",
                     "LockPersonality": "yes", "Type": "oneshot", "Nice": "10", "IOSchedulingClass": "idle",
                     "ProtectKernelModules": "yes", "ProtectKernelLogs": "yes", "RestrictNamespaces": "yes",
                     "RestrictRealtime": "yes", "SystemCallArchitectures": "native", "UMask": "0027",
                     "CapabilityBoundingSet": "CAP_DAC_OVERRIDE", "IPAddressDeny": "any", "IPAddressAllow": "localhost",
                     "RestrictAddressFamilies": "AF_UNIX AF_NETLINK AF_INET AF_INET6", "MemoryMax": "2G"}.items():
        assert u.get(cle) == [val], cle
    assert "User" not in u
    assert set(u["ReadWritePaths"][0].split()) == {"/etc/unbound/unbound.conf.d", "/var/lib/secubox-dns-listes",
                                                    "-/var/log/secubox/audit.log"}
    assert int(u["TimeoutStartSec"][0].removesuffix("min")) >= 60          # 3 passes × (compilation + checkconf 10 min + attente)
    regles = (PAQUET.parents[1] / ".claude" / "RULES-CODE.md").read_text()
    assert "secubox-dns-listes.service" in regles and "test_service_root_durci_et_exception_ecrite" in regles


def test_le_declencheur_surveille_les_sources_et_le_contexte():
    """Le service écrit dans unbound.conf.d : c'est l'empreinte des entrées (test_rien_de_neuf_ne_recompile_pas) qui arrête
    le redéclenchement, et une limite de démarrages large garde le .path actif."""
    p = _unite("secubox-dns-listes.path")
    assert p["PathChanged"] == ["/var/lib/secubox-dns-listes/sources", "/etc/unbound/unbound.conf.d"] and "PathExists" not in p
    assert "MakeDirectory" not in p                         # créerait /etc/unbound/unbound.conf.d sur une box sans Unbound
    assert p["Unit"] == ["secubox-dns-listes.service"]
    u = _unite("secubox-dns-listes.service")
    assert int(u["StartLimitBurst"][0]) >= 20


def test_profil_apparmor_n_ecrit_que_ses_fichiers():
    profil = (PAQUET / "apparmor" / "secubox-dns-listes").read_text()
    regles_seules = [ligne.split("#")[0].strip().rstrip(",") for ligne in profil.splitlines()]
    ecrits = {r.split()[0] for r in regles_seules if r.startswith("/") and r.split()[-1] in ("rw", "rwk", "w")}
    assert ecrits == {"/var/lib/secubox-dns-listes/", "/var/lib/secubox-dns-listes/**", "/run/unbound.ctl",
                      "/var/log/secubox/audit.log", "/etc/unbound/unbound.conf.d/92-secubox-listes.conf",
                      "/etc/unbound/unbound.conf.d/93-secubox-webfilter.conf",
                      "/etc/unbound/unbound.conf.d/95-secubox-adblock.conf",
                      "/etc/unbound/unbound.conf.d/96-secubox-adult.conf", "/etc/unbound/unbound.conf.d/.sbx-*"}
    regles = "\n".join(ligne for ligne in profil.splitlines() if not ligne.strip().startswith("#"))
    assert "deny /etc/secubox/secrets/** r," in regles and "sudo" not in regles and "/bin/sh" not in regles
    # dac_override SEULE : audit.log appartient à secubox (0640) ; constaté sur gk1, sans elle l'audit était perdu.
    assert re.findall(r"capability\s+(\S+),", regles) == ["dac_override"] and "#include <abstractions/openssl>" in profil


def test_paquet_installe_et_postinst_ne_bloque_pas_apt():
    regles = (PAQUET / "debian" / "rules").read_text()
    for f in ("sbin/secubox-dns-listes", "systemd/secubox-dns-listes.service", "systemd/secubox-dns-listes.path",
              "systemd/secubox-dns-listes.timer", "apparmor/secubox-dns-listes"):
        assert f in regles, f
    postinst = (PAQUET / "debian" / "postinst").read_text()
    assert "install -d -m 0755 -o root -g root /var/lib/secubox-dns-listes /var/lib/secubox-dns-listes/sources" in postinst
    assert "rm -rf /var/lib/secubox/dns-listes" in postinst                       # l'ancien arbre (1.8.0) est repris puis retiré
    assert "apparmor_parser -r /etc/apparmor.d/secubox-dns-listes" in postinst
    assert "systemctl start --no-block secubox-dns-listes.service" in postinst
    assert postinst.index("apparmor_parser -r /etc/apparmor.d/secubox-dns-listes") < postinst.index("--no-block secubox-dns-listes")


def test_sigterm_devient_une_sortie_qui_remet_tout():
    """Python ne remet rien en place sur SIGTERM (délai systemd) : la commande le transforme en SystemExit."""
    import importlib.machinery
    import importlib.util
    loader = importlib.machinery.SourceFileLoader("dns_listes_cmd", str(PAQUET / "sbin" / "secubox-dns-listes"))
    spec = importlib.util.spec_from_loader("dns_listes_cmd", loader)
    m = importlib.util.module_from_spec(spec)
    loader.exec_module(m)
    avant = signal.getsignal(signal.SIGTERM)
    try:
        m.main(["etat"])
        assert signal.getsignal(signal.SIGTERM) is m._terminer
        with pytest.raises(SystemExit):
            m._terminer(signal.SIGTERM, None)
    finally:
        signal.signal(signal.SIGTERM, avant)
