# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Tranche A (#3986) : garde, refus par défaut, minage absent, flux réel, conversations, mémoire Rust."""
import json
import os
import subprocess
import sys

import pytest

pytest.importorskip("openjarvis", reason="OpenJarvis absent : tests à lancer avec /opt/secubox-ai-agents/venv/bin/python (README)")

from conftest import PAQUET, moteur_present

UNITE = PAQUET / "systemd/secubox-ai-agents-gk0.service"
OUTILS_INTERDITS = [ligne.strip() for ligne in (PAQUET / "outils-retires.txt").read_text().splitlines()
                    if ligne.strip() and not ligne.startswith("#")]


def _evenements(reponse) -> list[dict]:
    return [json.loads(ligne[6:]) for ligne in reponse.text.splitlines() if ligne.startswith("data: ")]


# --- garde ------------------------------------------------------------------------------------------------

def test_sans_jeton_ou_mauvais_jeton_401(client):
    assert client.get("/health").status_code == 200   # seule route publique
    for entete in ({}, {"Authorization": "Bearer faux"}, {"Authorization": "Basic x"}):
        c = client.__class__(client.app)
        with c:
            r = c.get("/status", headers=entete)
            assert r.status_code == 401
            assert c.post("/chat", json={"message": "x"}, headers=entete).status_code == 401
            assert c.get("/conversations", headers=entete).status_code == 401
            assert c.get("/memoire/assistant?q=x", headers=entete).status_code == 401


# --- refus par défaut, aucun outil, minage absent ------------------------------------------------------

def test_aucun_outil_et_politique_en_refus(client):
    import agents.app as m
    # Tranche C : trois outils de LECTURE, et eux seuls (#3990).
    assert m.OUTILS == ("web_search", "memory_search", "digest_collect")
    for cap in ("code:execute", "file:write", "file:read", "network:fetch", "system:admin", "tool:invoke"):
        assert m.POLITIQUE.check("assistant", cap) is False
    s = client.get("/status").json()
    assert s["outils"] == list(m.OUTILS) and s["politique"] == "refus par défaut"
    if not sys.prefix.startswith("/opt/secubox-ai-agents"):
        pytest.skip("modules d'outils interdits : vérifiés dans le venv livré seulement (ils y sont supprimés)")
    charges = [k for k in sys.modules if k.startswith("openjarvis.tools.") and k.split(".")[-1] in OUTILS_INTERDITS]
    assert charges == []
    import importlib.util
    assert [n for n in OUTILS_INTERDITS if importlib.util.find_spec(f"openjarvis.tools.{n}")] == []
    assert importlib.util.find_spec("openjarvis.sandbox") is None


def test_minage_jamais_importe_et_absent_du_venv_dedie():
    """Interpréteur neuf : importer l'application ne charge aucun module de minage ni le serveur d'OpenJarvis.
    Dans le venv livré (/opt), `openjarvis.mining` n'existe plus du tout."""
    code = ("import sys; sys.path.insert(0, sys.argv[1]); import os;"
            "os.environ.update(SECUBOX_AI_AGENTS_GARDE='jeton-local');"
            "import agents.moteur, agents.stockage, agents.garde, agents.outils, agents.travaux;"
            "import openjarvis.security.capabilities;"
            "bad=[k for k in sys.modules if 'mining' in k or 'pearl' in k.lower() or k.startswith('openjarvis.server')"
            " or k.startswith('openjarvis.cli') or k in ('posthog','telegram','datasets')]; print(bad)")
    r = subprocess.run([sys.executable, "-I", "-c", code, str(PAQUET)], capture_output=True, text=True, timeout=120,
                       env={**os.environ, "OPENJARVIS_NO_UPDATE_CHECK": "1"})
    assert r.returncode == 0, r.stderr
    assert r.stdout.strip() == "[]"
    if sys.prefix.startswith("/opt/secubox-ai-agents"):
        r = subprocess.run([sys.executable, "-I", "-c", "import openjarvis.mining"], capture_output=True)
        assert r.returncode != 0


def test_requete_fts_sans_syntaxe():
    from agents.stockage import requete_fts
    assert requete_fts('NEAR(a b) OR "x" * -- ; pare-feu') == "near pare feu"
    assert requete_fts("a b") == ""


# --- mémoire (extension Rust réelle) -------------------------------------------------------------------

def test_memoire_par_agent_rust(client):
    import openjarvis._rust_bridge as rb
    assert rb.RUST_AVAILABLE
    r = client.post("/memoire/veille", json={"titre": "Consigne gk2", "texte": "Le port SSH de gk2 est 2222."})
    assert r.status_code == 200
    assert client.post("/memoire/assistant", json={"texte": "Recette du pain."}).status_code == 200
    v = client.get("/memoire/veille", params={"q": "quel port SSH ?"}).json()
    assert v["documents"] == 1 and v["resultats"][0]["titre"] == "Consigne gk2"
    a = client.get("/memoire/assistant", params={"q": "port SSH"}).json()
    assert a["resultats"] == []          # mémoire de l'autre agent : rien ne fuit
    assert client.post("/memoire/Mauvais Nom", json={"texte": "x"}).status_code in (404, 422)
    assert client.post("/memoire/veille", json={"texte": "x", "inconnu": 1}).status_code == 422


# --- conversation réelle ------------------------------------------------------------------------------

moteur = pytest.mark.skipif(not moteur_present(), reason="llama-server absent : test réel impossible ici")


@moteur
def test_flux_reel_conversation_et_memoire(client):
    client.post("/memoire/assistant", json={"titre": "Nom du chat", "texte": "Le chat du propriétaire s'appelle Zéphyr."})
    r = client.post("/chat", json={"message": "Comment s'appelle le chat du propriétaire ? Réponds en un mot.",
                                   "max_tokens": 32, "temperature": 0})
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/event-stream")
    ev = _evenements(r)
    conv = ev[0]["conversation"]
    assert ev[0]["sources"] and ev[0]["sources"][0]["titre"] == "Nom du chat"
    texte = "".join(e.get("morceau", "") for e in ev)
    assert "zéphyr" in texte.lower() or "zephyr" in texte.lower(), texte
    fin = ev[-1]
    assert fin["fin"] and fin["morceaux"] > 0 and fin["premier_s"] is not None

    # Deuxième tour, même conversation, sans mémoire : l'historique suffit.
    r2 = client.post("/chat", json={"message": "Répète ce nom, en un mot.", "conversation": conv,
                                    "memoire": False, "max_tokens": 16, "temperature": 0})
    t2 = "".join(e.get("morceau", "") for e in _evenements(r2))
    assert "zéphyr" in t2.lower() or "zephyr" in t2.lower(), t2

    lst = client.get("/conversations").json()["conversations"]
    assert [c["id"] for c in lst] == [conv] and lst[0]["messages"] == 4
    msgs = client.get(f"/conversations/{conv}").json()["messages"]
    assert [m["role"] for m in msgs] == ["user", "assistant", "user", "assistant"]
    assert client.delete(f"/conversations/{conv}").status_code == 200
    assert client.get(f"/conversations/{conv}").status_code == 404
    assert client.get("/conversations/zzzz").status_code == 404


def test_messages_un_systeme_et_roles_alternes():
    """Gabarit Gemma 3 : un seul message système, rôles alternés (HTTP 400 sinon, vu sur le vrai moteur)."""
    from types import SimpleNamespace as N

    from agents.app import construire_messages
    hist = [N(role="assistant", content="orphelin"), N(role="user", content="q1"), N(role="user", content="q1 bis"),
            N(role="assistant", content="r1")]
    m = construire_messages(hist, "q2", [{"titre": "t", "source": "note", "texte": "x"}])
    roles = [str(getattr(x.role, "value", x.role)) for x in m]
    assert roles == ["system", "user", "assistant", "user"]
    assert "q1\n\nq1 bis" == m[1].content and "[1] t" in m[0].content
