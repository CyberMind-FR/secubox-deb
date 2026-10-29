# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3126 L2 tâche 6 (R-L2-35) — câblage de Rejoindre : le service du maître (sans sudo, NoNewPrivileges) obtient le code par
la socket de l'assistant `secubox-pilotage-invite` (activé par socket, compte `secubox`, celui des jetons de secubox-p2p) qui
lance `sbx-mesh-invite --code --nom <nom> --json` ; noms du maillage ; chaîne complète canal → suivi → file de la box."""
import asyncio
import importlib.machinery
import importlib.util
import io
import json
import socket
import threading
from pathlib import Path

import httpx
import pytest

from secubox_core import auth

from pilotage import renommage as R
from pilotage.identite import noms_du_maillage
from outils import GK5, Horloge
from test_renommage import Res, code_maillage

ICI = Path(__file__).resolve().parents[1]
CODE = code_maillage()


def serveur(chemin, reponse: bytes, recus: list):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.bind(str(chemin))
    s.listen(1)

    def boucle():
        cx, _ = s.accept()
        with cx:
            recus.append(cx.makefile("rb").readline())
            cx.sendall(reponse)
        s.close()
    threading.Thread(target=boucle, daemon=True).start()


def test_lanceur_assistant_par_socket(tmp_path):
    recus = []
    serveur(tmp_path / "i.sock", (json.dumps({"code": CODE, "nom": "gk9", "expire": 1}) + "\n").encode(), recus)
    assert R.emettre_code_par(R.lanceur_assistant(tmp_path / "i.sock"))("gk9") == CODE
    assert recus == [b"gk9\n"]                       # seul le nom passe ; l'argv est fixé par l'assistant


def test_lanceur_assistant_en_echec(tmp_path):
    serveur(tmp_path / "i.sock", b"", [])            # l'assistant ferme sans rien rendre : échec de sbx-mesh-invite
    with pytest.raises(R.ErreurRejoindre):
        R.emettre_code_par(R.lanceur_assistant(tmp_path / "i.sock"))("gk9")
    with pytest.raises(R.ErreurRejoindre):           # socket absente
        R.emettre_code_par(R.lanceur_assistant(tmp_path / "absente.sock"))("gk9")
    # un argv autre que celui de sbx-mesh-invite --code --nom <nom> --json n'est jamais transmis
    r = R.lanceur_assistant(tmp_path / "absente.sock")(["/bin/sh", "-c", "id"], timeout=1)
    assert r.returncode != 0


JOURNAL = {}


@pytest.fixture(autouse=True)
def journal_de_test(tmp_path):
    """L'assistant audite dans un journal existant (il ne le crée jamais) : par défaut, celui du test."""
    JOURNAL["chemin"] = tmp_path / "audit-test.log"
    JOURNAL["chemin"].write_text("")
    yield
    JOURNAL.clear()


def charger_assistant():
    chemin = ICI / "sbin" / "secubox-pilotage-invite"
    chargeur = importlib.machinery.SourceFileLoader("assistant_invite", str(chemin))
    spec = importlib.util.spec_from_loader("assistant_invite", chargeur)
    m = importlib.util.module_from_spec(spec)
    chargeur.exec_module(m)
    if JOURNAL.get("chemin"):
        m.AUDIT = JOURNAL["chemin"]
    return m


def test_assistant_lance_sbx_mesh_invite_pour_un_nom_valide(tmp_path):
    a = charger_assistant()
    appels = []

    def lanceur(argv, **k):
        appels.append((argv, k))
        return Res(json.dumps({"code": CODE, "nom": "gk9", "expire": 1}) + "\n", 0, "")
    sortie = io.BytesIO()
    assert a.main(io.BytesIO(b"gk9\n"), sortie, lanceur=lanceur, dossier=tmp_path) == 0
    assert appels[0][0] == ["/usr/bin/sbx-mesh-invite", "--code", "--nom", "gk9", "--ttl", "600", "--json"]   # M1 : 10 min figées
    assert appels[0][1]["timeout"] and appels[0][1]["stdin"] is not None
    assert json.loads(sortie.getvalue())["code"] == CODE


@pytest.mark.parametrize("entree", [b"", b"\n", b"GK9\n", b"gk9 --flash\n", b"-gk9\n", b"a" * 64 + b"\n", b"gk9", b"x" * 500])
def test_assistant_refuse_un_nom_invalide(entree, tmp_path):
    a = charger_assistant()
    appels, sortie = [], io.BytesIO()
    assert a.main(io.BytesIO(entree), sortie, lanceur=lambda argv, **k: appels.append(argv), dossier=tmp_path) != 0
    assert appels == [] and sortie.getvalue() == b""


def test_assistant_echec_ne_rend_rien(capsys, tmp_path):
    a = charger_assistant()
    sortie = io.BytesIO()
    assert a.main(io.BytesIO(b"gk9\n"), sortie, lanceur=lambda argv, **k: Res("sbxmesh1.secret", 1, "détail"), dossier=tmp_path) != 0
    assert sortie.getvalue() == b"" and "sbxmesh1" not in capsys.readouterr().err


def test_noms_du_maillage(tmp_path):
    peers = tmp_path / "peers.json"
    peers.write_text(json.dumps({"peers": [
        {"name": "gk2", "mesh_ip": "10.10.0.2", "fingerprint": "f", "joined_via": "code"},
        {"name": "ombre", "mesh_ip": "10.10.0.7"},                                    # découverte mDNS non enrôlée : ignorée
    ]}))
    noms = noms_du_maillage(peers, hote=lambda: "maitre.local")
    assert noms == {"gk2", "maitre"}
    assert noms_du_maillage(tmp_path / "absent.json", hote=lambda: "maitre") == {"maitre"}


@pytest.mark.asyncio
async def test_chaine_complete_canal_suivi_rejoindre(tmp_path):
    from api.asgi import assembler
    from pilotage.files import Files
    from pilotage.inventaire import Inventaire
    from pilotage.stockage import StockageSqlite
    h = Horloge()
    s, f, lignes, emis = StockageSqlite(tmp_path / "p", horloge=h), Files(), [], []

    def emettre(nom):
        emis.append(nom)
        return CODE
    admin, canal = assembler(s, f, Inventaire(f, s, horloge=h), lambda ev, ch: lignes.append((ev, ch)),
                             lambda a: GK5 if a == GK5.adresse else None, h, emettre=emettre, noms_pris=set)
    admin.dependency_overrides[auth.require_jwt] = lambda: {"sub": "alice"}
    ent = {"X-Real-IP": GK5.adresse, "X-SecuBox-Pilotage-Tunnel": "1"}
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=admin), base_url="http://a") as a, \
            httpx.AsyncClient(transport=httpx.ASGITransport(app=canal), base_url="http://c", headers=ent) as c:
        await c.post("/canal/v1/bonjour", json={"agent_version": "0.2.0", "boot_id": "b", "modele": []})
        t = asyncio.create_task(a.post("/boxes/gk5/actions/renommer", json={"args": {"nom": "gk9"}, "confirmation": "gk5"}))
        (rq,) = (await c.get("/canal/v1/requetes", params={"attente": 2})).json()
        await c.post("/canal/v1/reponses", json=[{"msg_id": rq["msg_id"], "type": "OPERATE_RESP",
                                                  "body": {"etat": "accepte", "job": "j1", "raison": ""}}])
        assert (await t).json()["job"] == "j1"
        done = {"type": "NOTIFY", "body": {"event": {"type": "X_SECUBOX_OperationDone", "job": "j1", "rc": 0, "resume": "renommer : succès",
                                                     "ts": 5}}}
        assert (await c.post("/canal/v1/notifs", json=[done, done])).json() == {"ignore": 0}
        (rj,) = (await c.get("/canal/v1/requetes", params={"attente": 2})).json()
        assert rj["body"] == {"command": "Device.X_SECUBOX_Maillage.Rejoindre()", "args": {"code": CODE}}
        ops = (await a.get("/operations", params={"nom": "gk5"})).json()
    assert emis == ["gk9"] and ops[0]["resultat"] == "succes"
    assert [ch for ev, ch in lignes if ev == "pilotage_action_resultat"][0]["rc"] == 0
    assert CODE not in json.dumps(lignes)



def test_assistant_plafonne_les_emissions_par_heure(tmp_path):
    """M1 : au plus 20 codes par heure (compteur dans master-link) ; au-delà, sbx-mesh-invite n'est pas lancé."""
    a = charger_assistant()
    t, appels = [100_000.0], []

    def lanceur(argv, **k):
        appels.append(argv)
        return Res(json.dumps({"code": CODE, "nom": "gk9", "expire": 1}) + "\n", 0, "")
    for _ in range(20):
        assert a.main(io.BytesIO(b"gk9\n"), io.BytesIO(), lanceur=lanceur, dossier=tmp_path, horloge=lambda: t[0]) == 0
    sortie = io.BytesIO()
    assert a.main(io.BytesIO(b"gk9\n"), sortie, lanceur=lanceur, dossier=tmp_path, horloge=lambda: t[0]) != 0
    assert len(appels) == 20 and sortie.getvalue() == b""
    t[0] += 3601                                                      # une heure plus tard : de nouveau permis
    assert a.main(io.BytesIO(b"gk9\n"), io.BytesIO(), lanceur=lanceur, dossier=tmp_path, horloge=lambda: t[0]) == 0
    compteur = tmp_path / "pilotage-emissions.json"
    assert compteur.exists() and (compteur.stat().st_mode & 0o777) == 0o600
    assert CODE not in compteur.read_text()


def test_assistant_compteur_illisible_ou_lien_refuse(tmp_path):
    a = charger_assistant()
    (tmp_path / "ailleurs").write_text("[]")
    (tmp_path / "pilotage-emissions.json").symlink_to(tmp_path / "ailleurs")
    appels = []
    assert a.main(io.BytesIO(b"gk9\n"), io.BytesIO(), lanceur=lambda argv, **k: appels.append(argv), dossier=tmp_path) != 0
    assert appels == []


def test_assistant_audite_l_emission_sans_le_code(tmp_path):
    """Sous le profil (audit.log en ajout seul), l'audit de sbx-mesh-invite (open « a » = O_CREAT) est refusé : l'assistant
    écrit lui-même la ligne, sans O_CREAT, et ne rend pas le code si l'audit échoue (fermé par défaut)."""
    a = charger_assistant()
    journal = tmp_path / "audit.log"
    journal.write_text("")

    def lanceur(argv, **k):
        return Res(json.dumps({"code": CODE, "nom": "gk9", "expire": 1}) + "\n", 0, "")
    sortie = io.BytesIO()
    assert a.main(io.BytesIO(b"gk9\n"), sortie, lanceur=lanceur, dossier=tmp_path, audit=journal) == 0
    (ligne,) = [json.loads(x) for x in journal.read_text().splitlines()]
    assert ligne["module"] == "pilotage" and ligne["action"] == "pilotage_code_emis" and ligne["nom"] == "gk9" and ligne["ttl"] == 600
    assert CODE not in journal.read_text()
    sortie = io.BytesIO()
    assert a.main(io.BytesIO(b"gk9\n"), sortie, lanceur=lanceur, dossier=tmp_path, audit=tmp_path / "absent.log") != 0
    assert sortie.getvalue() == b"" and not (tmp_path / "absent.log").exists()
