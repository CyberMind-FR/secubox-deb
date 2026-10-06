# SPDX-License-Identifier: LicenseRef-CMSD-1.0
"""Entrées hostiles ou dangereuses : rien ne doit atteindre un fichier de configuration (relecture de sécurité #1938)."""
import pytest

from dns_lan import config

BASE_IPV6 = {"stable": "2001:db8::200/64", "interfaces": ["2001:db8::200"], "acces": ["2001:db8::/64"],
             "dropin_reseau": "/etc/systemd/network/10-netplan-eth2.network.d/50-secubox-ipv6-stable.conf"}


@pytest.mark.parametrize("brut", [
    {"lan": {"interface": "::1%x\nserver:\n    access-control: 0.0.0.0/0 allow", "acces": ["10.0.0.0/8"]}},
    {"lan": {"interface": "fe80::1%eth0", "acces": ["10.0.0.0/8"]}},
    {"lan": {"interface": "10.0.0.1", "acces": ["10.0.0.0/8"], "x": 1}},
    {"ipv6": dict(BASE_IPV6, stable="2001:db8::200%x\n[Network]\nDNS=6.6.6.6/64")},
    {"ipv6": dict(BASE_IPV6, stable="2001:db8::200/６４")},
    {"ipv6": dict(BASE_IPV6, interfaces=["2001:db8::1%lo"])},
    {"vue_locale": {"zone": "gk2.secubox.in", "adresse": "fe80::1%eth0\nserver:"}},
    {"hote": [{"nom": "a.b", "adresse": "::1%x", "ttl": 60}]},
])
def test_identifiant_de_zone_et_controles_refuses(brut):
    with pytest.raises(config.ErreurConfig):
        config.valider(brut)


@pytest.mark.parametrize("brut", [
    {"lan": {"interface": "0.0.0.0", "acces": ["10.0.0.0/8"]}},
    {"lan": {"interface": "::", "acces": ["10.0.0.0/8"]}},
    {"lan": {"interface": "10.0.0.1", "acces": ["0.0.0.0/0"]}},
    {"lan": {"interface": "10.0.0.1", "acces": ["8.0.0.0/7"]}},
    {"ipv6": dict(BASE_IPV6, acces=["::/0"])},
    {"ipv6": dict(BASE_IPV6, acces=["2000::/3"])},
])
def test_pas_de_resolveur_ouvert(brut):
    with pytest.raises(config.ErreurConfig):
        config.valider(brut)


@pytest.mark.parametrize("brut", [
    {"unbound": {"dossier": "/etc/sudoers.d"}},
    {"unbound": {"dossier": "/"}},
    {"ipv6": dict(BASE_IPV6, dropin_reseau="/etc/unbound/unbound.conf")},
    {"ipv6": dict(BASE_IPV6, dropin_reseau="/etc/nginx/nginx.conf")},
    {"ipv6": dict(BASE_IPV6, dropin_reseau="/etc/systemd/network/x.conf")},
    {"ipv6": dict(BASE_IPV6, dropin_reseau="/etc/systemd/network/a.network.d/../../b.conf")},
])
def test_chemins_confines(brut):
    with pytest.raises(config.ErreurConfig):
        config.valider(brut)


def test_chemins_valides_acceptes():
    c = config.valider({"unbound": {"dossier": "/etc/unbound/unbound.conf.d"}, "ipv6": BASE_IPV6})
    assert c["dossier"] == "/etc/unbound/unbound.conf.d"


def test_collision_de_chemins_refusee():
    with pytest.raises(config.ErreurConfig):
        config.valider({"unbound": {"dossier": "/x/u"}, "ipv6": dict(BASE_IPV6, dropin_reseau="/x/u/96-secubox-lan.conf")}, confiner=False)


def test_hote_sous_la_vue_locale_signale():
    with pytest.raises(config.ErreurConfig):
        config.valider({"vue_locale": {"zone": "gk2.secubox.in", "adresse": "10.0.0.1"},
                        "hote": [{"nom": "a.gk2.secubox.in", "adresse": "10.0.0.2", "ttl": 60}]})


def test_nul_et_retour_chariot_dans_un_chemin():
    for chemin in ("/etc/unbound/unbound.conf.d\x00", "/etc/unbound/unbound.conf.d\r"):
        with pytest.raises(config.ErreurConfig):
            config.valider({"unbound": {"dossier": chemin}}, confiner=False)
