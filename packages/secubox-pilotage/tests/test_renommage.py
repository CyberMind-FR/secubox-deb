# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3126 L2 tâche 5 (D3) — côté maître : après le X_SECUBOX_OperationDone réussi d'un Renommer, un code de jonction
lié au NOUVEAU nom (`sbx-mesh-invite --code --nom <nouveau>`) part vers la box par
Device.X_SECUBOX_Maillage.Rejoindre() {"code"} ; le code ne transite que par la file de la box (le tunnel) : jamais
dans un journal, l'audit ou une erreur. Le câblage dans l'API du contrôleur (table des opérations) est la tâche 6."""
import asyncio
import base64
import hashlib
import json
import logging

import pytest

from pilotage.files import Files
from pilotage.identite import Box
from pilotage import renommage as R

BOX = Box("gk4", "10.10.0.5", "maillage", None, None)
CLIENTE = Box("client-1", "10.64.0.9", "autoload", "c1", "actif")


def code_maillage(jeton="ab" * 32):
    charge = base64.urlsafe_b64encode(json.dumps({"a": "192.168.1.1", "t": jeton}, separators=(",", ":")).encode())
    charge = charge.decode().rstrip("=")
    return f"sbxmesh1.{charge}.{hashlib.sha256(charge.encode()).hexdigest()[:4]}"


class Res:
    def __init__(self, out="", rc=0, err=""):
        self.stdout, self.stderr, self.returncode = out, err, rc


def faux_invite(appels, code, nom=None, rc=0):
    def run(argv, **k):
        appels.append((list(argv), k))
        sortie = json.dumps({"code": code, "nom": nom if nom is not None else argv[argv.index("--nom") + 1],
                             "expire": 1}) + "\n"
        return Res(sortie, rc, "sbx-mesh-invite : audit non écrit" if rc else "")
    return run


def test_emettre_code_par_sbx_mesh_invite():
    code, appels = code_maillage(), []
    assert R.emettre_code("gk5", lanceur=faux_invite(appels, code)) == code
    [(argv, k)] = appels
    assert argv == ["/usr/bin/sbx-mesh-invite", "--code", "--nom", "gk5", "--json"]
    assert k.get("timeout") and k.get("capture_output") and k.get("stdin") is not None


def test_emettre_code_refus_sans_recopier_la_sortie():
    code = code_maillage()
    for nom in ("GK5", "-gk5", "a" * 64, "gk5;reboot", ""):
        appels = []
        with pytest.raises(R.ErreurRejoindre):
            R.emettre_code(nom, lanceur=faux_invite(appels, code))
        assert appels == []
    for lanceur in (faux_invite([], code, rc=1), faux_invite([], code + "0"), faux_invite([], code, nom="gk9"),
                    lambda argv, **k: Res("pas du json " + code), lambda argv, **k: (_ for _ in ()).throw(OSError())):
        with pytest.raises(R.ErreurRejoindre) as e:
            R.emettre_code("gk5", lanceur=lanceur)
        assert code not in str(e.value) and "sbxmesh1" not in str(e.value)


def test_apres_renommer_le_code_part_par_rejoindre():
    code = code_maillage()
    audits = []

    async def cas():
        f = Files()
        fut = await R.envoyer_rejoindre(f, BOX, {"action": "renommer", "args": {"nom": "gk5"}}, {"rc": 0},
                                        emettre=lambda nom: code, audit=lambda ev, ch: audits.append((ev, ch)))
        assert fut is not None
        [rq] = await f.attendre_requetes(BOX.cle, 1)
        assert rq["type"] == "OPERATE"
        assert rq["body"] == {"command": "Device.X_SECUBOX_Maillage.Rejoindre()", "args": {"code": code}}
        return rq["msg_id"]
    msg_id = asyncio.run(cas())
    assert audits == [("pilotage_rejoindre_envoye", {"box": "gk4", "nouveau": "gk5", "msg_id": msg_id})]


def test_rien_a_envoyer_hors_renommage_reussi_au_maillage():
    appels = []

    def emettre(nom):
        appels.append(nom)
        return code_maillage()

    async def cas():
        f = Files()
        for box, op, fin in ((BOX, {"action": "renommer", "args": {"nom": "gk5"}}, {"rc": 1}),
                             (BOX, {"action": "renommer", "args": {"nom": "gk5"}}, {"rc": None}),
                             (BOX, {"action": "reboot", "args": {}}, {"rc": 0}),
                             (BOX, {"action": "renommer", "args": {"nom": "GK5"}}, {"rc": 0}),
                             (CLIENTE, {"action": "renommer", "args": {"nom": "gk5"}}, {"rc": 0})):
            assert await R.envoyer_rejoindre(f, box, op, fin, emettre=emettre, audit=lambda *a: None) is None
        return f.en_attente(BOX.cle) + f.en_attente(CLIENTE.cle)
    assert asyncio.run(cas()) == 0 and appels == []


def test_code_jamais_journalise(caplog, tmp_path):
    """Le code ne transite que dans la file de la box : ni journal (tous niveaux), ni audit, ni message d'erreur."""
    jeton = "f00dcafe" * 8
    code = code_maillage(jeton)
    journal = tmp_path / "audit.log"
    journal.write_text("")
    from pilotage.audit import journal as fabrique
    audit = fabrique(journal)
    caplog.set_level(logging.DEBUG)
    messages = []

    async def cas():
        f = Files(max_par_box=1)
        op = {"action": "renommer", "args": {"nom": "gk5"}}
        await R.envoyer_rejoindre(f, BOX, op, {"rc": 0}, emettre=R.emettre_code_par(faux_invite([], code)), audit=audit)
        # file pleine, sbx-mesh-invite en échec, sortie incohérente : chaque échec est dit sans le code
        for emettre in (R.emettre_code_par(faux_invite([], code)), R.emettre_code_par(faux_invite([], code, rc=1)),
                        R.emettre_code_par(lambda argv, **k: Res("bruit " + code))):
            try:
                await R.envoyer_rejoindre(f, BOX, op, {"rc": 0}, emettre=emettre, audit=audit)
            except R.ErreurRejoindre as e:
                messages.append(str(e))
    asyncio.run(cas())
    assert len(messages) == 3
    traces = caplog.text + journal.read_text() + "\n".join(messages)
    for morceau in (code, jeton, code.split(".")[1][:24]):
        assert morceau not in traces
    assert "pilotage_rejoindre_envoye" in journal.read_text()
