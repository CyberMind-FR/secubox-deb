# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

from pathlib import Path
CONF = Path(__file__).resolve().parents[1] / "conf"
def test_dnsport_moved_off_avahi_5353():
    torrc = (CONF / "torrc-toolbox-egress.conf").read_text()
    assert "DNSPort 127.0.0.1:9053" in torrc
    assert "5353" not in torrc          # avahi owns 5353
def test_nft_redirect_targets_9053():
    nft = (CONF / "nft-toolbox-tor.nft").read_text()
    assert "redirect to :9053" in nft
    assert ":5353" not in nft
def test_unbound_onion_forward_zone_valid():
    conf = (CONF / "48-secubox-onion.conf").read_text()
    assert 'name: "onion."' in conf
    assert "forward-addr: 127.0.0.1@9053" in conf


SCRIPT = Path(__file__).resolve().parents[1] / "sbin" / "secubox-toolbox-tor-reconcile"


def test_pas_de_doublon_forward_zone_onion_avec_torctl():
    # secubox-tor (torctl) pose déjà secubox-onion-forward.conf, qui déclare la même zone `onion.`
    # vers le même DNSPort : un second forward-zone fait écrire « duplicate forward zone onion. ignored »
    # à Unbound au démarrage (#2018). Le script doit s'effacer devant lui et retirer son propre fichier.
    texte = SCRIPT.read_text()
    assert "secubox-onion-forward.conf" in texte
    garde = texte.index("secubox-onion-forward.conf", texte.index("UNBOUND_ONION_DST="))
    assert 'rm -f "$UNBOUND_ONION_DST"' in texte[garde:garde + 600]
