# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2189 (infrastructure) : plage 10.64.0.0/16, attribution d'adresses idempotente, configuration du hub, retrait des pairs révoqués."""
import ipaddress
import stat
import sys
import threading
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from autoload import jetons as J, tunnel as T  # noqa: E402

CLE_A, CLE_B, CLE_C = "A" * 43 + "=", "B" * 43 + "=", "C" * 43 + "="
HUB_CLE = "H" * 43 + "="


@pytest.fixture
def pairs(tmp_path):
    return T.Pairs(tmp_path / "var" / "jetons.db")


def test_la_plage_est_distincte_des_autres_tunnels_secubox():
    plage = ipaddress.ip_network(T.RESEAU)
    for autre in ("10.10.0.0/24", "10.11.0.0/24", "10.20.0.0/24", "10.30.0.0/24", "10.99.0.0/24", "10.100.0.0/24"):
        assert not plage.overlaps(ipaddress.ip_network(autre)), autre
    assert ipaddress.ip_address(T.HUB) in plage and T.PORT_UDP == 51830


def test_attribution_sequentielle_et_idempotente(pairs):
    a = pairs.attribuer(CLE_A)
    b = pairs.attribuer(CLE_B)
    assert a == "10.64.0.2" and b == "10.64.0.3"
    assert pairs.attribuer(CLE_A) == a                                   # la même clé garde son adresse
    assert T.HUB not in (a, b)


def test_l_adresse_d_une_cle_retiree_n_est_pas_reutilisee(pairs):
    a = pairs.attribuer(CLE_A)
    pairs.retirer(CLE_A)
    assert pairs.attribuer(CLE_B) != a
    with pytest.raises(ValueError):
        pairs.attribuer(CLE_A)                                           # une clé retirée ne revient pas sans nouveau jeton
    assert [p["cle_pub"] for p in pairs.actifs()] == [CLE_B]


def test_attributions_concurrentes_sans_doublon(tmp_path):
    base = tmp_path / "j.db"
    T.Pairs(base)
    sortie = []

    def tache(i):
        sortie.append(T.Pairs(base).attribuer(chr(65 + i) * 43 + "="))
    ts = [threading.Thread(target=tache, args=(i,)) for i in range(12)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    assert len(set(sortie)) == 12


@pytest.mark.parametrize("cle", ["", "court", "A" * 44, "A" * 43 + "x", None, "é" * 44])
def test_cle_invalide_refusee(pairs, cle):
    with pytest.raises(ValueError):
        pairs.attribuer(cle)


def test_plage_epuisee_refuse_proprement(pairs, monkeypatch):
    monkeypatch.setattr(T, "RESEAU", "10.64.0.0/30")                      # hub .1, une seule adresse cliente (.2)
    pairs.attribuer(CLE_A)
    with pytest.raises(T.PlageEpuisee):
        pairs.attribuer(CLE_B)


def test_conf_du_hub_ne_contient_pas_la_cle_privee_et_liste_les_pairs_actifs(pairs):
    pairs.attribuer(CLE_A)
    pairs.attribuer(CLE_B)
    pairs.retirer(CLE_B)
    conf = T.rendre_hub(pairs.actifs(), Path("/etc/secubox/secrets/autoload-hub.key"))
    assert "ListenPort = 51830" in conf and "Address = 10.64.0.1/16" in conf
    assert "PrivateKey" not in conf and "private-key /etc/secubox/secrets/autoload-hub.key" in conf
    assert f"PublicKey = {CLE_A}" in conf and "AllowedIPs = 10.64.0.2/32" in conf
    assert CLE_B not in conf


def test_les_pairs_sont_isoles_entre_eux(pairs):
    pairs.attribuer(CLE_A)
    conf = T.rendre_hub(pairs.actifs(), Path("/etc/secubox/secrets/h.key"))
    assert "10.64.0.0/16" not in conf.split("[Peer]")[1]                  # un pair n'a jamais plus que sa propre adresse


def test_gabarit_remis_a_la_box(pairs):
    adresse = pairs.attribuer(CLE_A)
    g = T.gabarit_box(adresse, HUB_CLE)
    assert g == {"endpoint": f"{T.INFRA}:{T.PORT_UDP}", "serveur_cle_pub": HUB_CLE, "adresse": "10.64.0.2/32", "hub": "10.64.0.1/32"}


def test_synchronisation_ecrit_la_conf_en_0600_et_appelle_wg(pairs, tmp_path):
    pairs.attribuer(CLE_A)
    appels = []

    def executeur(argv, **kw):
        appels.append(argv)

        class R:
            returncode, stdout, stderr = 0, "", ""
        return R()
    conf = tmp_path / "wg" / "wg-autoload.conf"
    T.synchroniser(pairs, conf, Path("/etc/secubox/secrets/h.key"), executeur=executeur)
    assert stat.S_IMODE(conf.stat().st_mode) == 0o600 and f"PublicKey = {CLE_A}" in conf.read_text()
    assert appels and all(isinstance(a, list) for a in appels) and any("syncconf" in a for a in appels)


def test_synchronisation_qui_echoue_laisse_l_ancienne_conf(pairs, tmp_path):
    conf = tmp_path / "wg-autoload.conf"
    conf.write_text("ANCIENNE")
    pairs.attribuer(CLE_A)

    def echec(argv, **kw):
        class R:
            returncode, stdout, stderr = 1, "", "boom"
        return R()
    with pytest.raises(T.TunnelErreur):
        T.synchroniser(pairs, conf, Path("/etc/secubox/secrets/h.key"), executeur=echec)
    assert conf.read_text() == "ANCIENNE"


def test_revoquer_un_jeton_reclame_retire_le_pair(tmp_path):
    reg = J.Registre(tmp_path / "j.db", tmp_path / "a.log")
    p = T.Pairs(tmp_path / "j.db")
    e = reg.emettre("c1", "lite")
    reg.reclamer(e.valeur, CLE_A)
    p.attribuer(CLE_A)
    cle = reg.revoquer(e.id, "volée")
    p.retirer(cle)
    assert p.actifs() == []
