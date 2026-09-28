# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""La sortie du relais ne mène qu'à l'extérieur (#1609).

Aucun test ne touche le réseau : le résolveur est simulé, et la couche réseau
d'origine de httpcore est remplacée par une fausse, qui note à quelle adresse
on lui demande de se connecter et répond une réponse HTTP écrite d'avance.
"""
import asyncio
import os
import socket
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

os.environ.setdefault("SECUBOX_TOR_SOCKS", "127.0.0.1:9050")   # pas de sonde
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import httpx  # noqa: E402

from surf import egress  # noqa: E402

PUBLIQUE = "93.184.216.34"
BOX_V6 = "2a0c:5a80:1:2::200"
VOISIN_V6 = "2a0c:5a80:1:2::77"


class Resolveur:
    """getaddrinfo simulé : un nom → des adresses ; un littéral → lui-même."""

    def __init__(self, table=None, suites=None):
        self.table = table or {}
        self.suites = suites or {}      # nom → [réponse 1, réponse 2, …]
        self.appels = []

    def __call__(self, hote, port, family=0, type=0, proto=0, flags=0):
        self.appels.append(hote)
        if hote in self.suites:
            adresses = self.suites[hote].pop(0)
        elif hote in self.table:
            adresses = self.table[hote]
        else:
            try:
                socket.inet_pton(socket.AF_INET6 if ":" in hote else socket.AF_INET, hote)
                adresses = [hote]
            except OSError:
                raise socket.gaierror(socket.EAI_NONAME, "Name or service not known")
        return [((socket.AF_INET6 if ":" in a else socket.AF_INET),
                 socket.SOCK_STREAM, 6, "", (a, port)) for a in adresses]


def _reponse(code=200, entetes=(), corps=b"ok"):
    lignes = [f"HTTP/1.1 {code} X", f"Content-Length: {len(corps)}"]
    lignes += [f"{k}: {v}" for k, v in entetes]
    return ("\r\n".join(lignes) + "\r\n\r\n").encode() + corps


class _Flux:
    def __init__(self, reseau, ip):
        self.reseau, self.ip, self.lu = reseau, ip, False

    def _lire(self):
        if self.lu:
            return b""
        self.lu = True
        return self.reseau.reponses.get(self.ip, _reponse())

    def _ecrire(self, octets):
        self.reseau.ecrit.append(bytes(octets))

    def _tls(self, server_hostname):
        self.reseau.sni.append(server_hostname)
        return self

    def get_extra_info(self, info):
        return None


class _FluxAsync(_Flux):
    async def read(self, max_bytes, timeout=None):
        return self._lire()

    async def write(self, buffer, timeout=None):
        self._ecrire(buffer)

    async def aclose(self):
        pass

    async def start_tls(self, ssl_context, server_hostname=None, timeout=None):
        return self._tls(server_hostname)


class _FluxSync(_Flux):
    def read(self, max_bytes, timeout=None):
        return self._lire()

    def write(self, buffer, timeout=None):
        self._ecrire(buffer)

    def close(self):
        pass

    def start_tls(self, ssl_context, server_hostname=None, timeout=None):
        return self._tls(server_hostname)


class FauxReseau:
    """Couche réseau factice : note les connexions, répond d'avance."""

    def __init__(self, reponses=None):
        self.reponses = reponses or {}
        self.connexions, self.ecrit, self.sni = [], [], []

    async def connect_tcp(self, host, port, timeout=None, local_address=None, **kw):
        self.connexions.append((host, port))
        return _FluxAsync(self, host)

    async def sleep(self, seconds):
        pass


class FauxReseauSync(FauxReseau):
    def connect_tcp(self, host, port, timeout=None, local_address=None, **kw):
        self.connexions.append((host, port))
        return _FluxSync(self, host)

    def sleep(self, seconds):
        pass


def _client_async(reseau):
    cli = egress.client_async("direct")
    cli._transport._pool._network_backend._interne = reseau
    return cli


def _get(url, reseau, **kw):
    async def go():
        async with _client_async(reseau) as cli:
            return await cli.get(url, **kw)
    return asyncio.run(go())


class Base(unittest.TestCase):

    def setUp(self):
        self.resolveur = Resolveur({
            "exemple.test": [PUBLIQUE],
            "nas.exemple.test": ["192.168.1.50"],
            "mixte.exemple.test": [PUBLIQUE, "10.100.0.1"],
            "voisin.exemple.test": [VOISIN_V6],
            "box.exemple.test": [BOX_V6],
        })
        propres = (frozenset({egress.ipaddress.ip_address(BOX_V6)}),
                   (egress.ipaddress.ip_network("2a0c:5a80:1:2::/64"),))
        self._patches = [
            mock.patch.object(egress, "_resoudre", self.resolveur),
            mock.patch.object(egress, "_adresses_de_la_box", lambda: propres),
            mock.patch.object(egress, "CONFIG", Path("/nonexistent/egress.toml")),
        ]
        for p in self._patches:
            p.start()

    def tearDown(self):
        for p in reversed(self._patches):
            p.stop()

    def assertRefuse(self, url, reseau=None, **kw):
        reseau = reseau or FauxReseau()
        with self.assertRaises(httpx.ConnectError) as ctx:
            _get(url, reseau, **kw)
        refus = egress.refus_de(ctx.exception)
        self.assertIsNotNone(refus, f"{url} : échec qui n'est pas un refus")
        return refus, reseau


class AdressesInternes(Base):

    def test_boucle_locale_ipv4_refusee(self):
        refus, reseau = self.assertRefuse("http://127.0.0.1/")
        self.assertEqual(refus.raison, "boucle locale")
        self.assertEqual(reseau.connexions, [])

    def test_conteneurs_de_la_box_refuses(self):
        refus, reseau = self.assertRefuse("http://10.100.0.1/")
        self.assertEqual(reseau.connexions, [])

    def test_boucle_locale_ipv6_refusee(self):
        refus, reseau = self.assertRefuse("http://[::1]/")
        self.assertEqual(reseau.connexions, [])

    def test_nom_resolu_vers_le_lan_refuse(self):
        refus, reseau = self.assertRefuse("http://nas.exemple.test/")
        self.assertEqual(refus.adresse, "192.168.1.50")
        self.assertEqual(refus.raison, "réseau privé")
        self.assertEqual(reseau.connexions, [])

    def test_une_seule_adresse_interne_suffit_a_refuser(self):
        refus, reseau = self.assertRefuse("https://mixte.exemple.test/")
        self.assertEqual(refus.adresse, "10.100.0.1")
        self.assertEqual(reseau.connexions, [])

    def test_adresse_de_la_box_refusee_meme_publique(self):
        refus, _ = self.assertRefuse("http://box.exemple.test/")
        self.assertEqual(refus.raison, "adresse de la box")

    def test_reseau_attenant_de_la_box_refuse(self):
        refus, _ = self.assertRefuse("http://voisin.exemple.test/")
        self.assertEqual(refus.raison, "réseau local de la box")

    def test_nom_de_la_box_refuse_sans_resolution(self):
        refus, _ = self.assertRefuse("https://hall.gk2.secubox.in/")
        self.assertEqual(refus.raison, "service de la box")
        self.assertNotIn("hall.gk2.secubox.in", self.resolveur.appels)

    def test_localhost_refuse_sans_resolution(self):
        self.assertRefuse("http://localhost:8080/")
        self.assertRefuse("http://app.localhost/")
        self.assertEqual(self.resolveur.appels, [])

    def test_redirection_vers_la_boucle_locale_refusee(self):
        reseau = FauxReseau({PUBLIQUE: _reponse(302, [("Location", "http://127.0.0.1/admin")])})
        refus, _ = self.assertRefuse("http://exemple.test/", reseau, follow_redirects=True)
        self.assertEqual(refus.raison, "boucle locale")
        self.assertEqual(reseau.connexions, [(PUBLIQUE, 80)])

    def test_adresse_publique_configuree_refusee(self):
        with tempfile.TemporaryDirectory() as t:
            conf = Path(t) / "egress.toml"
            conf.write_text(f'refuse = ["{PUBLIQUE}/32", "pas-une-adresse"]\n')
            with mock.patch.object(egress, "CONFIG", conf):
                refus, _ = self.assertRefuse("http://exemple.test/")
        self.assertEqual(refus.raison, "refusée par la configuration")


class Classement(Base):

    def test_plages_refusees(self):
        for ip in ("0.0.0.0", "10.0.0.1", "100.64.0.1", "169.254.169.254",
                   "172.16.0.1", "192.168.1.200", "224.0.0.251", "240.0.0.1",
                   "255.255.255.255", "::", "::1", "fc00::1", "fd12::1",
                   "fe80::1", "ff02::1", "::ffff:127.0.0.1", "::ffff:10.100.0.1",
                   "2002:c0a8:1c8::1", "64:ff9b::7f00:1", "2001:db8::1"):
            self.assertIsNotNone(egress.raison_refus(ip), ip)

    def test_adresses_publiques_admises(self):
        for ip in (PUBLIQUE, "2a00:1450:4007:80c::200e"):
            self.assertIsNone(egress.raison_refus(ip), ip)

    def test_nom_introuvable_nest_pas_un_refus(self):
        with self.assertRaises(httpx.ConnectError) as ctx:
            _get("http://inconnu.exemple.test/", FauxReseau())
        self.assertIsNone(egress.refus_de(ctx.exception))


class SortieAdmise(Base):

    def test_adresse_publique_admise_et_connexion_a_l_adresse_verifiee(self):
        reseau = FauxReseau()
        r = _get("http://exemple.test/page", reseau)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(reseau.connexions, [(PUBLIQUE, 80)])
        requete = b"".join(reseau.ecrit)
        self.assertIn(b"Host: exemple.test", requete)
        self.assertNotIn(PUBLIQUE.encode(), requete)

    def test_sni_et_certificat_gardent_le_nom(self):
        reseau = FauxReseau()
        r = _get("https://exemple.test/", reseau)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(reseau.connexions, [(PUBLIQUE, 443)])
        self.assertEqual(reseau.sni, ["exemple.test"])

    def test_une_seule_resolution_par_connexion(self):
        self.resolveur.suites["change.exemple.test"] = [[PUBLIQUE], ["127.0.0.1"]]
        reseau = FauxReseau()
        r = _get("http://change.exemple.test/", reseau)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(self.resolveur.appels.count("change.exemple.test"), 1)
        self.assertEqual(reseau.connexions, [(PUBLIQUE, 80)])


class Harnais(Base):

    def test_client_synchrone_garde(self):
        reseau = FauxReseauSync()
        with egress.client_pour("127.0.0.1", "direct") as cli:
            cli._transport._pool._network_backend._interne = reseau
            with self.assertRaises(httpx.ConnectError) as ctx:
                cli.get("http://127.0.0.1/")
            self.assertIsNotNone(egress.refus_de(ctx.exception))
            self.assertEqual(cli.get("http://exemple.test/").status_code, 200)
        self.assertEqual(reseau.connexions, [(PUBLIQUE, 80)])

    def test_sans_couche_reseau_pas_de_client(self):
        with self.assertRaises(RuntimeError):
            egress._arme(object())


class AdressesDeLaBox(unittest.TestCase):
    """Les adresses de la box se lisent sur ses interfaces, `ip` absent compris."""

    def _lire(self, sortie_ip=None, if_inet6=""):
        with tempfile.TemporaryDirectory() as t:
            f = Path(t) / "if_inet6"
            f.write_text(if_inet6)
            run = (mock.Mock(return_value=mock.Mock(stdout=sortie_ip))
                   if sortie_ip is not None else mock.Mock(side_effect=OSError))
            with mock.patch.object(egress.subprocess, "run", run), \
                 mock.patch.object(egress, "_IF_INET6", f), \
                 mock.patch.object(egress.socket, "getaddrinfo", side_effect=OSError), \
                 mock.patch.object(egress, "_ip_locale", return_value=None), \
                 mock.patch.dict(egress._propres, {"t": -1e9}):
                return egress._adresses_de_la_box()

    def test_lues_par_ip(self):
        sortie = ('[{"ifname":"eth2","addr_info":[{"family":"inet6",'
                  '"local":"2a0c:5a80:1:2::200","prefixlen":64}]}]')
        adresses, reseaux = self._lire(sortie_ip=sortie)
        self.assertIn(egress.ipaddress.ip_address("2a0c:5a80:1:2::200"), adresses)
        self.assertIn(egress.ipaddress.ip_network("2a0c:5a80:1:2::/64"), reseaux)

    def test_lues_sans_netlink(self):
        adresses, reseaux = self._lire(
            if_inet6="2a0c5a80000100020000000000000200 03 40 00 00     eth2\n")
        self.assertIn(egress.ipaddress.ip_address("2a0c:5a80:1:2::200"), adresses)
        self.assertIn(egress.ipaddress.ip_network("2a0c:5a80:1:2::/64"), reseaux)


class _FauxTunnel(httpx.AsyncBaseTransport):
    def __init__(self):
        self.vus = []

    async def handle_async_request(self, request):
        self.vus.append(request.url.host)
        return httpx.Response(200, request=request)


class ModeTor(Base):

    def _get(self, url):
        tunnel = _FauxTunnel()

        async def go():
            async with httpx.AsyncClient(transport=egress._TorGardeAsync(tunnel)) as cli:
                return await cli.get(url)
        return asyncio.run(go()), tunnel

    def test_litteral_interne_refuse_sans_tunnel(self):
        for url in ("http://127.0.0.1/", "http://[::1]/", "http://10.100.0.1/",
                    "http://localhost/"):
            with self.assertRaises(httpx.ConnectError) as ctx:
                self._get(url)
            self.assertIsNotNone(egress.refus_de(ctx.exception), url)

    def test_onion_passe_par_le_tunnel_sans_resolution_locale(self):
        onion = "a" * 56 + ".onion"
        r, tunnel = self._get(f"http://{onion}/")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(tunnel.vus, [onion])
        self.assertEqual(self.resolveur.appels, [])


class Relais(Base):
    """Le serveur répond 403, sans sortir, pour une origine qui vise la box."""

    def _appel(self, hote):
        from surf import serveur
        reseau = FauxReseau()
        envoye = []

        async def recoit():
            return {"type": "http.request", "body": b"", "more_body": False}

        async def envoie(msg):
            envoye.append(msg)

        async def go():
            # Le client du relais, fabriqué par egress, sur la couche factice.
            serveur._clients["direct"] = _client_async(reseau)
            try:
                await serveur.app(scope, recoit, envoie)
            finally:
                await serveur._clients.pop("direct").aclose()

        scope = {"type": "http", "method": "GET", "path": "/", "raw_path": b"/",
                 "query_string": b"", "headers": [(b"host", hote.encode())]}
        with mock.patch.object(serveur.jarre, "entete", lambda *a: ""):
            asyncio.run(go())
        self.assertEqual(reseau.connexions, [])
        return envoye[0]["status"], envoye[1]["body"]

    def test_origine_vers_la_boucle_locale_refusee(self):
        code, corps = self._appel("surf-127-0-0-1.gk2.secubox.in")
        self.assertEqual(code, 403)
        self.assertIn("le relais ne l'ouvre pas".encode(), corps)

    def test_origine_vers_les_conteneurs_refusee(self):
        code, _ = self._appel("surf-10-100-0-1.gk2.secubox.in")
        self.assertEqual(code, 403)

    def test_origine_vers_un_service_de_la_box_refusee(self):
        code, _ = self._appel("surf-hall-gk2-secubox-in.gk2.secubox.in")
        self.assertEqual(code, 403)


if __name__ == "__main__":
    unittest.main()
