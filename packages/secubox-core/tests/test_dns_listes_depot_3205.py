# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3205 — dépôt des sources, transaction sur plusieurs fichiers, application par secubox-dns-listes.

Les générateurs (webfilter, adblock, adult) déposent leur rendu inchangé comme SOURCE ; un seul service compile, pose
92-secubox-listes.conf et retire les anciens fichiers en UNE transaction : une vérification, un rechargement, et au
moindre échec TOUT est remis octet pour octet. Un ancien fichier trouvé dans unbound.conf.d est adopté comme source."""
import json
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
                     "LockPersonality": "yes", "Type": "oneshot", "Nice": "10", "IOSchedulingClass": "idle"}.items():
        assert u.get(cle) == [val], cle
    assert "User" not in u
    regles = (PAQUET.parents[1] / ".claude" / "RULES-CODE.md").read_text()
    assert "secubox-dns-listes.service" in regles and "test_service_root_durci_et_exception_ecrite" in regles


def test_le_declencheur_ne_surveille_pas_ce_que_le_service_ecrit():
    p = _unite("secubox-dns-listes.path")
    assert p["PathChanged"] == ["/var/lib/secubox/dns-listes/sources"] and "PathExists" not in p
    assert p["Unit"] == ["secubox-dns-listes.service"]


def test_profil_apparmor_n_ecrit_que_ses_fichiers():
    profil = (PAQUET / "apparmor" / "secubox-dns-listes").read_text()
    ecrits = {ligne.split()[0] for ligne in profil.splitlines()
              if ligne.strip().startswith("/") and ligne.rstrip(",").split()[-1] in ("rw", "rwk", "w")}
    assert ecrits == {"/var/lib/secubox/dns-listes/", "/var/lib/secubox/dns-listes/**", "/run/lock/secubox-dns-listes.lock",
                      "/var/log/secubox/audit.log", "/etc/unbound/unbound.conf.d/92-secubox-listes.conf",
                      "/etc/unbound/unbound.conf.d/93-secubox-webfilter.conf",
                      "/etc/unbound/unbound.conf.d/95-secubox-adblock.conf",
                      "/etc/unbound/unbound.conf.d/96-secubox-adult.conf", "/etc/unbound/unbound.conf.d/.sbx-*"}
    regles = "\n".join(ligne for ligne in profil.splitlines() if not ligne.strip().startswith("#"))
    assert "deny /etc/secubox/secrets/** r," in regles and "sudo" not in regles and "/bin/sh" not in regles


def test_paquet_installe_et_postinst_ne_bloque_pas_apt():
    regles = (PAQUET / "debian" / "rules").read_text()
    for f in ("sbin/secubox-dns-listes", "systemd/secubox-dns-listes.service", "systemd/secubox-dns-listes.path",
              "systemd/secubox-dns-listes.timer", "apparmor/secubox-dns-listes"):
        assert f in regles, f
    postinst = (PAQUET / "debian" / "postinst").read_text()
    assert "apparmor_parser -r /etc/apparmor.d/secubox-dns-listes" in postinst
    assert "systemctl start --no-block secubox-dns-listes.service" in postinst
    assert postinst.index("apparmor_parser -r /etc/apparmor.d/secubox-dns-listes") < postinst.index("--no-block secubox-dns-listes")
