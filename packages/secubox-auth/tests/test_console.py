# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Console locale du kiosque (#1695) : seul le kiosque, par son port, entre sans
authentification. Chaque refus ci-dessous est une porte qu'on a fermée."""
import ipaddress
from pathlib import Path

import pytest

from api import console

KIOSQUE, AUTRE, NGINX = 1000, 1001, 33
ENTETE = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"


def _v4(ip: str, port: int) -> str:
    return ipaddress.IPv4Address(ip).packed[::-1].hex().upper() + f":{port:04X}"


def _v6(ip: str, port: int) -> str:
    b = ipaddress.IPv6Address(ip).packed
    return "".join(b[i:i + 4][::-1].hex().upper() for i in range(0, 16, 4)) + f":{port:04X}"


def _ligne(i: int, local: str, distant: str, uid: int, etat: str = "01") -> str:
    return f"   {i}: {local} {distant} {etat} 00000000:00000000 00:00000000 00000000  {uid}        0 {1000 + i} 1 0000000000000000 20 4 0 10 -1\n"


@pytest.fixture
def proc(tmp_path: Path) -> Path:
    """Un /proc où le kiosque est connecté au port console depuis 127.0.0.1:54321,
    et un autre compte depuis 127.0.0.1:54400."""
    net = tmp_path / "net"
    net.mkdir()
    (net / "tcp").write_text(ENTETE + "".join([
        # bout serveur (nginx) : ne doit jamais compter
        _ligne(0, _v4("127.0.0.1", 9078), _v4("127.0.0.1", 54321), NGINX),
        # bout client du kiosque
        _ligne(1, _v4("127.0.0.1", 54321), _v4("127.0.0.1", 9078), KIOSQUE),
        # un autre compte local, sur le même port console
        _ligne(2, _v4("127.0.0.1", 54400), _v4("127.0.0.1", 9078), AUTRE),
        # le kiosque vers le port ordinaire du Hall
        _ligne(3, _v4("127.0.0.1", 54500), _v4("127.0.0.1", 9080), KIOSQUE),
        # une connexion du kiosque qui se ferme (TIME_WAIT)
        _ligne(4, _v4("127.0.0.1", 54600), _v4("127.0.0.1", 9078), KIOSQUE, etat="06"),
    ]))
    (net / "tcp6").write_text(ENTETE + _ligne(0, _v6("::1", 54700), _v6("::1", 9078), KIOSQUE))
    return tmp_path


@pytest.fixture
def secret(tmp_path: Path) -> Path:
    p = tmp_path / "console.key"
    p.write_text("s3cret-de-nginx\n")
    return p


def _refus(proc, secret, **kw):
    base = dict(secret_fourni="s3cret-de-nginx", paire="127.0.0.1:54321", hote="hall.localhost",
                origine=None, cfg={}, uid=KIOSQUE, chemin_secret=secret, proc=proc)
    base.update(kw)
    return console.refus(**base)


def test_le_kiosque_par_le_port_console_entre(proc, secret):
    assert _refus(proc, secret) is None
    assert _refus(proc, secret, origine="http://hall.localhost:9078") is None


def test_ipv6_boucle_locale(proc, secret):
    assert _refus(proc, secret, paire="::1:54700") is None


def test_un_autre_compte_local_est_refuse(proc, secret):
    assert _refus(proc, secret, paire="127.0.0.1:54400") == "connexion étrangère au kiosque"


def test_le_bout_serveur_ne_compte_pas(proc, secret):
    # La paire du bout nginx (9078 → 54321) appartient à nginx, pas au kiosque.
    assert _refus(proc, secret, paire="127.0.0.1:9078") == "connexion étrangère au kiosque"


def test_le_kiosque_sur_le_port_ordinaire_est_refuse(proc, secret):
    assert _refus(proc, secret, paire="127.0.0.1:54500") == "connexion étrangère au kiosque"


def test_connexion_fermee_refusee(proc, secret):
    assert _refus(proc, secret, paire="127.0.0.1:54600") == "connexion étrangère au kiosque"


def test_adresse_non_locale_refusee(proc, secret):
    assert _refus(proc, secret, paire="192.168.1.20:54321") == "connexion étrangère au kiosque"


def test_paire_illisible_refusee(proc, secret):
    for p in ("", "127.0.0.1", "abc:def", "127.0.0.1:0", "127.0.0.1:70000"):
        assert _refus(proc, secret, paire=p) == "connexion étrangère au kiosque"


def test_sans_le_secret_de_nginx_refuse(proc, secret):
    # Appel direct au socket de l'agrégateur (0666) avec la paire du kiosque,
    # lisible par tous dans /proc : c'est précisément ce que le secret ferme.
    assert _refus(proc, secret, secret_fourni="") == "demande hors du port console"
    assert _refus(proc, secret, secret_fourni="devine") == "demande hors du port console"
    assert _refus(proc, secret, chemin_secret=secret.parent / "absent") == "demande hors du port console"


def test_rebond_dns_et_autre_hote_refuses(proc, secret):
    assert _refus(proc, secret, hote="evil.example") == "hôte refusé"
    assert _refus(proc, secret, hote="hall.evil.example") == "hôte refusé"
    assert _refus(proc, secret, hote="hall.localhost:9078") is None


def test_l_administration_est_une_origine_de_la_console(proc, secret):
    assert _refus(proc, secret, hote="admin.localhost") is None
    assert _refus(proc, secret, hote="admin.localhost", origine="http://admin.localhost:9078") is None
    # …mais chacune avec SA propre origine.
    assert _refus(proc, secret, hote="admin.localhost", origine="http://hall.localhost:9078") == "origine refusée"


def test_origine_etrangere_refusee(proc, secret):
    assert _refus(proc, secret, origine="https://surf-exemple.gk2.secubox.in") == "origine refusée"
    assert _refus(proc, secret, origine="http://hall.localhost:9080") == "origine refusée"


def test_pas_de_kiosque_pas_de_console(proc, secret):
    assert "pas de kiosque" in _refus(proc, secret, uid=None)


def test_console_desactivee(proc, secret):
    assert "désactivée" in _refus(proc, secret, cfg={"actif": False})


def test_reglages_par_defaut():
    assert console.reglages(None) == {"actif": True, "compte": "console"}
    assert console.reglages({"compte": "  "}) == {"actif": True, "compte": "console"}
    assert console.reglages({"compte": "kiosque-admin", "actif": True})["compte"] == "kiosque-admin"
