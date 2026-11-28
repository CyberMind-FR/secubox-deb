# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Task 10 (#4058) : voix par réplique, reprise idempotente — contre un FAUX worker Voice Studio sur socket Unix
(le vrai worker GPU #4057 n'est pas prêt)."""
import asyncio
import contextlib
import hashlib
import json

import pytest

from emissions.gpu import VerrouGPU
from emissions.voix import MoteurVoix, dire_tout, nom_fichier

REPLIQUES = [{"rang": 0, "voix": 1, "texte": "Bonjour, voici la semaine."},
             {"rang": 1, "voix": 2, "texte": "La campagne totalise 1 204 bans.", "statut": "verifiee"},
             {"rang": 2, "voix": 1, "texte": "Un chiffre inventé : 9 999.", "statut": "retiree"},
             {"rang": 3, "voix": 2, "texte": "Et la suite ?", "statut": "ia_seule"}]


class FauxWorker:
    """Contrat OpenAI `POST /v1/audio/speech` ; rend « ID3 » + empreinte de (texte, voix)."""

    def __init__(self, sock, echec=False):
        self.sock, self.echec, self.requetes, self.serveur = str(sock), echec, [], None

    async def _client(self, r, w):
        tete = await r.readuntil(b"\r\n\r\n")
        lignes = tete.decode().split("\r\n")
        h = {k.lower(): v.strip() for k, v in (x.split(":", 1) for x in lignes[1:] if ":" in x)}
        corps = await r.readexactly(int(h.get("content-length", "0")))
        self.requetes.append({"ligne": lignes[0], "auth": h.get("authorization"), "json": json.loads(corps or b"{}")})
        if self.echec:
            rep, code = b"panne", b"500 Internal Server Error"
        else:
            j = self.requetes[-1]["json"]
            rep, code = b"ID3" + hashlib.sha256((j["input"] + j["voice"]).encode()).digest(), b"200 OK"
        w.write(b"HTTP/1.1 " + code + b"\r\nContent-Type: audio/mpeg\r\nContent-Length: "
                + str(len(rep)).encode() + b"\r\nConnection: close\r\n\r\n" + rep)
        await w.drain()
        w.close()

    async def __aenter__(self):
        self.serveur = await asyncio.start_unix_server(self._client, path=self.sock)
        return self

    async def __aexit__(self, *a):
        self.serveur.close()
        await self.serveur.wait_closed()


class Compteur:
    def __init__(self):
        self.arrets = self.relances = 0

    async def arreter(self):
        self.arrets += 1

    async def relancer(self):
        self.relances += 1


@pytest.fixture
def banc(tmp_path):
    c = Compteur()
    verrou = VerrouGPU(tmp_path / "run" / "voix.verrou", c.arreter, c.relancer)
    worker = FauxWorker(tmp_path / "w.sock")
    moteur = MoteurVoix("http://worker", cle=lambda: "cle-worker", uds=str(tmp_path / "w.sock"))
    return tmp_path / "brouillon", c, verrou, worker, moteur


def test_premier_passage_retiree_jamais_dite(banc):
    br, c, verrou, worker, moteur = banc

    async def go():
        async with worker:
            return await dire_tout(br, REPLIQUES, moteur=moteur, verrou=verrou)
    chemins = asyncio.run(go())
    assert [p.name.split("-")[0] for p in chemins] == ["0", "1", "3"]          # la retirée n'est jamais dite
    assert all(p.read_bytes().startswith(b"ID3") for p in chemins)
    assert len(worker.requetes) == 3 and (c.arrets, c.relances) == (1, 1)       # un seul passage sous le verrou
    assert [r["json"]["voice"] for r in worker.requetes] == ["nova", "onyx", "onyx"]
    assert all(r["ligne"].startswith("POST /v1/audio/speech") and r["auth"] == "Bearer cle-worker"
               for r in worker.requetes)
    assert chemins[1].name == nom_fichier(REPLIQUES[1], "onyx") and chemins[1].parent == br / "voix"
    assert not (br / "run").exists() and not verrou.fichier.exists()


def test_reprise_idempotente(banc):
    br, c, verrou, worker, moteur = banc

    async def go():
        async with worker:
            await dire_tout(br, REPLIQUES, moteur=moteur, verrou=verrou)
            n = len(worker.requetes)
            again = await dire_tout(br, REPLIQUES, moteur=moteur, verrou=verrou)
            return n, again
    n, again = asyncio.run(go())
    assert len(worker.requetes) == n                                            # zéro requête au second appel
    assert (c.arrets, c.relances) == (1, 1)                                     # Gemma pas suspendu pour rien
    assert len(again) == 3


def test_modifier_ne_refait_que_sa_voix(banc):
    br, c, verrou, worker, moteur = banc
    modifiees = [dict(r) for r in REPLIQUES]
    modifiees[1]["texte"] = "La campagne totalise 1 205 bans."

    async def go():
        async with worker:
            await dire_tout(br, REPLIQUES, moteur=moteur, verrou=verrou)
            n = len(worker.requetes)
            await dire_tout(br, modifiees, moteur=moteur, verrou=verrou)
            return n
    n = asyncio.run(go())
    assert len(worker.requetes) == n + 1
    assert worker.requetes[-1]["json"]["input"] == "La campagne totalise 1 205 bans."
    assert sorted(p.name.split("-")[0] for p in (br / "voix").glob("*.mp3")) == ["0", "1", "3"]   # ancienne voix 1 ôtée


def test_echec_worker_relance_gemma(banc):
    br, c, verrou, _, moteur = banc
    worker = FauxWorker(moteur.uds, echec=True)

    async def go():
        async with worker:
            await dire_tout(br, REPLIQUES, moteur=moteur, verrou=verrou)
    with pytest.raises(RuntimeError):
        asyncio.run(go())
    assert (c.arrets, c.relances) == (1, 1) and not verrou.fichier.exists()
    assert not list((br / "voix").glob("*.mp3"))                               # rien de partiel


def test_voix_reglables_et_validation(banc):
    br, c, verrou, worker, moteur = banc

    async def go():
        async with worker:
            return await dire_tout(br, REPLIQUES[:2], {1: "alloy", 2: "echo"}, moteur=moteur, verrou=verrou)
    asyncio.run(go())
    assert [r["json"]["voice"] for r in worker.requetes] == ["alloy", "echo"]
    for mauvaise in ({"rang": 0, "voix": 3, "texte": "x"}, {"rang": 0, "voix": 1, "texte": "  "},
                     {"rang": -1, "voix": 1, "texte": "x"}):
        with pytest.raises(ValueError):
            asyncio.run(dire_tout(br, [mauvaise], moteur=moteur, verrou=verrou))
    assert (c.arrets, c.relances) == (1, 1)                                     # validation AVANT le verrou
    with contextlib.suppress(FileNotFoundError):
        assert not verrou.fichier.exists()


def test_voix_cpu_ne_suspend_pas_gemma(banc, tmp_path):
    """voix_gpu = false (CUDA en panne) : aucun verrou posé, Gemma jamais arrêté ; voix_gpu = true : le verrou réel."""
    from emissions import gpu
    br, c, verrou, worker, moteur = banc
    v = gpu.selon_reglage(False, tmp_path / "v.verrou")

    async def go():
        async with worker:
            return await dire_tout(br, REPLIQUES, moteur=moteur, verrou=v)
    assert len(asyncio.run(go())) == 3
    assert not (tmp_path / "v.verrou").exists() and (c.arrets, c.relances) == (0, 0)
    assert isinstance(gpu.selon_reglage(True, tmp_path / "v.verrou"), VerrouGPU)
    assert asyncio.run(v.reparer()) is False


def test_cle_absente_aucun_entete(tmp_path):
    """Le Voice Studio local de gk0 (127.0.0.1:3910) ne demande pas de clé : fichier absent → pas d'en-tête."""
    from emissions.voix import WORKER, cle_fichier
    assert WORKER.endswith(":3910") or WORKER.startswith("http")
    worker = FauxWorker(tmp_path / "w.sock")
    m = MoteurVoix("http://worker", cle=cle_fichier(tmp_path / "absente"), uds=str(tmp_path / "w.sock"))

    async def go():
        async with worker:
            return await m.dire("Bonjour.", "nova")
    assert asyncio.run(go()).startswith(b"ID3")
    assert worker.requetes[0]["auth"] is None
