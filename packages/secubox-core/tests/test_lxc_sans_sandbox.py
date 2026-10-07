# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""secubox-lxc-sans-sandbox — remet en marche un service dont le bac à sable systemd ne se monte plus dans un conteneur sans
privilèges (AppArmor refuse le montage : 226/NAMESPACE, constaté le 2026-10-05 sur redis, apache2…)."""
import importlib.machinery
import importlib.util
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "usr" / "sbin" / "secubox-lxc-sans-sandbox"


def charger():
    chargeur = importlib.machinery.SourceFileLoader("sanssandbox", str(SCRIPT))
    spec = importlib.util.spec_from_loader("sanssandbox", chargeur)
    m = importlib.util.module_from_spec(spec)
    chargeur.exec_module(m)
    return m


class Faux:
    """Remplace lxc-attach : mémorise les appels et le contenu du fichier écrit."""
    def __init__(self, en_marche=True, actif=True):
        self.appels, self.ecrits, self.en_marche, self.actif = [], [], en_marche, actif

    def __call__(self, conteneur, argv, entree=None):
        self.appels.append((conteneur, list(argv)))
        if entree is not None:
            self.ecrits.append((conteneur, list(argv), entree))
        if argv[:2] == ["systemctl", "is-active"]:
            return 0 if self.actif else 3
        return 0


def test_le_surcharge_coupe_toutes_les_protections():
    m = charger()
    t = m.surcharge()
    for d in ("PrivateDevices=false", "PrivateTmp=false", "PrivateUsers=false", "ProtectSystem=false", "ProtectHome=false",
              "ProtectKernelTunables=false", "ProtectControlGroups=false", "RestrictNamespaces=false", "ReadWritePaths=",
              "InaccessiblePaths=", "TemporaryFileSystem="):
        assert d in t
    assert t.startswith("[Service]")


@pytest.mark.parametrize("mauvais", ["", "redis; rm -rf /", "a b", "../x", "x\n", "$(id)", "a" * 90])
def test_un_nom_de_service_douteux_est_refuse(mauvais):
    m = charger()
    assert not m.nom_valide(mauvais)


@pytest.mark.parametrize("bon", ["redis-server", "apache2", "postfix@-", "php8.2-fpm", "systemd-resolved"])
def test_les_noms_de_service_usuels_sont_acceptes(bon):
    assert charger().nom_valide(bon)


def test_un_nom_de_conteneur_douteux_est_refuse():
    m = charger()
    assert m.nom_valide("peertube") and not m.nom_valide("a/b") and not m.nom_valide("-x")


def test_reparer_pose_la_surcharge_recharge_puis_demarre():
    m = charger()
    f = Faux()
    assert m.reparer("peertube", ["redis-server"], f) == 0
    ecrit = [e for e in f.ecrits if "10-lxc-sans-sandbox.conf" in " ".join(e[1])]
    assert ecrit and "PrivateTmp=false" in ecrit[0][2]
    cmds = [a[1] for a in f.appels]
    assert ["systemctl", "daemon-reload"] in cmds
    assert any(c[:2] == ["systemctl", "reset-failed"] for c in cmds)
    assert ["systemctl", "enable", "--now", "redis-server"] in cmds
    assert all(c == "peertube" for c, _ in f.appels)


def test_reparer_signale_un_service_qui_ne_demarre_pas():
    m = charger()
    f = Faux(actif=False)
    assert m.reparer("peertube", ["redis-server"], f) != 0


def test_reparer_ne_touche_a_rien_avec_un_nom_douteux():
    m = charger()
    f = Faux()
    assert m.reparer("peertube", ["redis; id"], f) != 0
    assert f.appels == []


def test_la_commande_ne_modifie_jamais_l_hote():
    src = SCRIPT.read_text()
    assert "/etc/systemd/system" in src and "lxc-attach" in src
    for interdit in ("shell=True", "os.system", "eval("):
        assert interdit not in src
