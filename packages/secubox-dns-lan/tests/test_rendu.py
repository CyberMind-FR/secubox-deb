# SPDX-License-Identifier: LicenseRef-CMSD-1.0
"""Le rendu du TOML de gk2 doit avoir les mêmes lignes EFFECTIVES (hors commentaires) que les fichiers capturés sur la box (#1938)."""
import tomllib
from pathlib import Path

import pytest

from dns_lan import config, rendu

RACINE = Path(__file__).resolve().parent.parent
FIXTURES = RACINE / "tests" / "fixtures" / "gk2"


def effectives(texte: str) -> list[str]:
    return [x.strip() for x in texte.splitlines() if x.strip() and not x.strip().startswith("#")]


@pytest.fixture
def cfg():
    return config.valider(tomllib.loads((RACINE / "conf" / "dns-lan.toml").read_text()))


@pytest.mark.parametrize("nom", ["96-secubox-lan.conf", "96-secubox-lan-ipv6.conf", "96-secubox-gk2-local.conf",
                                 "98-secubox-voicestudio-lan.conf", "50-secubox-ipv6-stable.conf"])
def test_rendu_identique_a_gk2(cfg, nom):
    fichiers = {Path(p).name: t for p, t in rendu.rendre(cfg).items()}
    assert nom in fichiers, f"{nom} non produit : {sorted(fichiers)}"
    assert effectives(fichiers[nom]) == effectives((FIXTURES / nom).read_text())


def test_chaque_fichier_porte_en_tete_et_marque_genere(cfg):
    for chemin, texte in rendu.rendre(cfg).items():
        assert texte.startswith("# SPDX-License-Identifier: LicenseRef-CMSD-1.0"), chemin
        assert "GÉNÉRÉ par secubox-dns-lan" in texte, chemin


def test_section_absente_aucun_fichier():
    c = config.valider({"lan": {"interface": "10.0.0.1", "acces": ["10.0.0.0/8"]}})
    noms = [Path(p).name for p in rendu.rendre(c)]
    assert noms == ["96-secubox-lan.conf"]


@pytest.mark.parametrize("brut", [
    {"lan": {"interface": "pas-une-ip", "acces": ["10.0.0.0/8"]}},
    {"lan": {"interface": "10.0.0.1", "acces": ["10.0.0.0/99"]}},
    {"lan": {"interface": "10.0.0.1", "acces": []}},
    {"lan": {"interface": "10.0.0.1\nserver: x", "acces": ["10.0.0.0/8"]}},
    {"ipv6": {"stable": "2001:db8::200", "interfaces": [], "acces": ["2001:db8::/64"], "dropin_reseau": "/etc/systemd/network/x.conf"}},
    {"ipv6": {"stable": "2001:db8::200/64", "interfaces": ["::1"], "acces": ["2001:db8::/64"], "dropin_reseau": "relatif.conf"}},
    {"vue_locale": {"zone": "a b.c", "adresse": "10.0.0.1"}},
    {"vue_locale": {"zone": "gk2.secubox.in", "adresse": "10.0.0.999"}},
    {"hote": [{"nom": "x.y", "adresse": "10.0.0.1", "ttl": 0}]},
    {"hote": [{"nom": "x.y\"; local-zone: \".", "adresse": "10.0.0.1", "ttl": 300}]},
    {"unbound": {"dossier": "relatif"}},
])
def test_entrees_invalides_refusees(brut):
    with pytest.raises(config.ErreurConfig):
        config.valider(brut)


def test_ipv6_accepte_dans_hote():
    c = config.valider({"hote": [{"nom": "nas.lan.example", "adresse": "fd00::5", "ttl": 60}]})
    texte = next(iter(rendu.rendre(c).values()))
    assert 'local-data: "nas.lan.example. 60 IN AAAA fd00::5"' in texte
