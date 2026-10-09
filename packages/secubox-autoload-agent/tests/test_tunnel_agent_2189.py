# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2189 (box) : clé générée sur la box, configuration sortante seulement, entrées du réseau validées avant d'écrire quoi que ce soit."""
import stat
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from autoload_agent import tunnel as T  # noqa: E402

PUB_SERVEUR = "S" * 43 + "="
BON = {"endpoint": "admin.gk2.secubox.in:51830", "serveur_cle_pub": PUB_SERVEUR, "adresse": "10.64.0.2/32", "hub": "10.64.0.1/32"}


class Faux:
    """Exécuteur injecté : enregistre les commandes, rend ce qu'on lui dit."""
    def __init__(self, sorties=None, rc=0):
        self.appels, self.sorties, self.rc = [], sorties or {}, rc

    def __call__(self, argv, **kw):
        self.appels.append((argv, kw))

        class R:
            pass
        r = R()
        r.returncode = self.rc
        r.stdout = self.sorties.get(argv[1] if len(argv) > 1 else argv[0], "")
        r.stderr = "erreur" if self.rc else ""
        return r


def test_la_cle_est_generee_sur_la_box_en_0600_et_reutilisee(tmp_path):
    ex = Faux({"genkey": "PRIVEE" + "p" * 37 + "=\n", "pubkey": "P" * 43 + "=\n"})
    cle = tmp_path / "secrets" / "autoload-wg.key"
    pub = T.assurer_cle(cle, executeur=ex)
    assert pub == "P" * 43 + "=" and stat.S_IMODE(cle.stat().st_mode) == 0o600
    assert stat.S_IMODE(cle.parent.stat().st_mode) & 0o077 == 0
    n = len(ex.appels)
    assert T.assurer_cle(cle, executeur=ex) == pub                        # existante : jamais régénérée (la box ne change pas d'identité)
    assert [a[0][1] for a in ex.appels[n:]] == ["pubkey"]


def test_la_cle_privee_ne_passe_jamais_en_argument(tmp_path):
    ex = Faux({"genkey": "K" * 43 + "=\n", "pubkey": "P" * 43 + "=\n"})
    T.assurer_cle(tmp_path / "k", executeur=ex)
    for argv, _ in ex.appels:
        assert "K" * 43 not in " ".join(argv)


def test_conf_sortante_seulement(tmp_path):
    conf = T.rendre_conf(BON, Path("/etc/secubox/secrets/autoload-wg.key"))
    assert "ListenPort" not in conf                                        # aucun port entrant côté client
    assert "PrivateKey" not in conf and "wg set %i private-key /etc/secubox/secrets/autoload-wg.key" in conf
    assert "AllowedIPs = 10.64.0.1/32" in conf and "PersistentKeepalive = 25" in conf
    assert "Endpoint = admin.gk2.secubox.in:51830" in conf and "Address = 10.64.0.2/32" in conf
    assert "0.0.0.0/0" not in conf                                         # jamais de route par défaut vers l'infrastructure


@pytest.mark.parametrize("champ,valeur", [
    ("endpoint", "evil.com:51830"), ("endpoint", "admin.gk2.secubox.in"), ("endpoint", "admin.gk2.secubox.in:0"),
    ("endpoint", "admin.gk2.secubox.in:51830\nPostUp = rm -rf /"), ("endpoint", "1.2.3.4:51830"),
    ("serveur_cle_pub", "court"), ("serveur_cle_pub", "S" * 43 + "=\nPostUp=x"),
    ("adresse", "192.168.1.5/32"), ("adresse", "10.64.0.2/16"), ("adresse", "10.64.0.2/32\nPostUp=x"), ("adresse", "10.64.0.1/32"),
    ("hub", "10.64.0.9/32"), ("hub", "0.0.0.0/0"),
])
def test_une_reponse_hostile_est_refusee_avant_toute_ecriture(tmp_path, champ, valeur):
    mauvais = dict(BON, **{champ: valeur})
    with pytest.raises(T.TunnelInvalide):
        T.rendre_conf(mauvais, Path("/etc/secubox/secrets/k"))


def test_champ_manquant_ou_inconnu_refuse():
    with pytest.raises(T.TunnelInvalide):
        T.rendre_conf({k: v for k, v in BON.items() if k != "hub"}, Path("/k"))
    with pytest.raises(T.TunnelInvalide):
        T.rendre_conf(dict(BON, extra="x"), Path("/k"))


def test_monter_ecrit_en_0600_et_active_l_unite(tmp_path):
    ex = Faux()
    conf = tmp_path / "wireguard" / "wg-autoload.conf"
    T.monter(BON, tmp_path / "k", conf, executeur=ex)
    assert stat.S_IMODE(conf.stat().st_mode) == 0o600
    cmds = [a[0] for a in ex.appels]
    assert ["systemctl", "enable", "--now", "wg-quick@wg-autoload.service"] in cmds
    assert all(isinstance(a[0], list) and a[1].get("timeout") for a in ex.appels)


def test_monter_qui_echoue_ne_laisse_pas_une_conf_a_moitie(tmp_path):
    conf = tmp_path / "wg-autoload.conf"
    with pytest.raises(T.TunnelInvalide):
        T.monter(dict(BON, endpoint="evil.com:1"), tmp_path / "k", conf, executeur=Faux())
    assert not conf.exists()
    with pytest.raises(T.TunnelErreur):
        T.monter(BON, tmp_path / "k", conf, executeur=Faux(rc=1))
    assert not conf.exists()                                               # activation refusée : on retire ce qu'on a posé
