# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Task 7 (#4058) : consigne, dialogue V1/V2, vérification réplique par réplique — contre un FAUX LLM sur socket Unix."""
import asyncio
import json

from emissions.dialogue import GABARIT, associer_diapos, decouper, dites, ecrire, verifier_repliques
from emissions.consigne import consigne

DOSSIER = {"sujet": {"genre": "campagne", "id": "c1", "nom": "Essai"},
           "chiffres": {"bans_90j": 1204, "adresses_90j": 87}, "tendances": []}


def test_consigne_regles_et_faits():
    c = consigne([{"nom": "Essai", "genre": "campagne"}], [{"texte": "Nouvelle vague de Essai.", "marquant": True}],
                 GABARIT.read_text(encoding="utf-8"))
    assert "Nouvelle vague de Essai." in c and "V1:" in c and "V2:" in c
    for regle in ("hébergeur", "État", "bannissements", "publicitaire"):
        assert regle in c


def test_decouper_v1_v2():
    sortie = "Voici le dialogue.\nV1: Bonjour.\n**V2 :** La campagne Essai compte 1 204 bans.\nsuite de la phrase.\n\nV1: Et ensuite ?"
    r = decouper(sortie)
    assert [x["voix"] for x in r] == [1, 2, 1]
    assert [x["rang"] for x in r] == [0, 1, 2]
    assert r[1]["texte"] == "La campagne Essai compte 1 204 bans. suite de la phrase."


def test_retiree_jamais_dite():
    r = verifier_repliques([{"rang": 0, "voix": 1, "texte": "La campagne Essai compte 1 204 bans."},
                            {"rang": 1, "voix": 2, "texte": "La campagne Essai compte 9 999 bans."}], DOSSIER)
    assert r[0]["statut"] == "verifiee" and r[0]["marque"] == "✓"
    assert r[1]["statut"] == "retiree" and r[1]["marque"] == "✗" and r[1]["motifs"]
    assert [x["rang"] for x in dites(r)] == [0]


def test_question_admise():
    r = verifier_repliques([{"rang": 0, "voix": 1, "texte": "Et qu'est-ce que cela change pour nous ?"}], DOSSIER)
    assert r[0]["statut"] == "verifiee"


def test_hypothese_signalee():
    r = verifier_repliques([{"rang": 0, "voix": 1, "texte": "La campagne Essai compte probablement 1 204 bans."}],
                           DOSSIER)
    assert r[0]["statut"] == "ia_seule" and r[0]["marque"] == "⚠"


def test_associer_diapos_sans_retiree():
    reps = [{"rang": 0, "voix": 1, "texte": "1 204 bans.", "statut": "verifiee"},
            {"rang": 1, "voix": 2, "texte": "87 adresses.", "statut": "retiree"}]
    graphs = [{"id": "g1", "chiffres": ["1204"], "termes": []}, {"id": "g2", "chiffres": ["87"], "termes": []}]
    assert associer_diapos(reps, graphs) == {0: "g1"}


def test_ecrire_faux_llm(tmp_path):
    sock = tmp_path / "llm.sock"
    recu = {}

    async def client(r, w):
        tete = await r.readuntil(b"\r\n\r\n")
        n = int([x for x in tete.split(b"\r\n") if x.lower().startswith(b"content-length")][0].split(b":")[1])
        recu.update(json.loads(await r.readexactly(n)))
        corps = json.dumps({"choices": [{"message": {"content": "V1: Bonjour.\nV2: Salut."}}]}).encode()
        w.write(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n" % len(corps) + corps)
        await w.drain()
        w.close()

    async def go():
        srv = await asyncio.start_unix_server(client, path=str(sock))
        async with srv:
            return await ecrire("consigne", socket=str(sock))
    assert asyncio.run(go()) == "V1: Bonjour.\nV2: Salut."
    assert recu["messages"][-1]["content"] == "consigne"


def test_supposition_non_ancree_signalee():
    # essai réel du 28/11 : « Cela suggère …, probablement … » sans chiffre passait ✓
    r = verifier_repliques([{"rang": 0, "voix": 2, "texte": "Cela suggère probablement une adaptation du pare-feu."}],
                           DOSSIER)
    assert r[0]["statut"] == "ia_seule"
