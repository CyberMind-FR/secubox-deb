# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3206 — secubox-dns-joker : verbe étroit, sortie JSON, codes, audit sans clé d'API."""
import importlib.machinery
import importlib.util
import json
from pathlib import Path

from test_joker_3206 import GANDI, Faux

CLI = Path(__file__).resolve().parents[1] / "sbin" / "secubox-dns-joker"


def _cli():
    chargeur = importlib.machinery.SourceFileLoader("secubox_dns_joker", str(CLI))
    spec = importlib.util.spec_from_loader("secubox_dns_joker", chargeur)
    mod = importlib.util.module_from_spec(spec)
    chargeur.exec_module(mod)
    return mod


def _lancer(capsys, argv, faux):
    audits = []

    def charger():
        # le faux refuse par RuntimeError, comme le vrai par HTTPException : c'est l'erreur fournisseur déclarée
        return ([("df97", faux)], lambda nom, ip: (nom, ip), lambda action, d: audits.append((action, d)),
                (RuntimeError,))

    code = _cli().main(argv, charger=charger)
    return code, json.loads(capsys.readouterr().out), audits


def test_usage(capsys):
    for argv in ([], ["assurer", "gk4.secubox.in", "82.67.100.75"],
                 ["creer", "gk4.secubox.in", "82.67.100.75", "secubox.in"]):
        code, sortie, audits = _lancer(capsys, argv, Faux(["secubox.in"]))
        assert code == 2 and "usage" in sortie["erreur"] and audits == []


def test_cree_et_audite(capsys):
    code, sortie, audits = _lancer(capsys, ["assurer", "gk4.secubox.in", "82.67.100.75", "secubox.in"],
                                   Faux(["secubox.in"], {"secubox.in": list(GANDI)}))
    assert code == 0 and sortie["etat"] == "cree" and sortie["nom"] == "*.gk4"
    assert audits[0][0] == "record_created" and audits[0][1]["name"] == "*.gk4"


def test_inchange_sans_audit(capsys):
    code, sortie, audits = _lancer(capsys, ["assurer", "gk3.secubox.in", "82.67.100.75", "secubox.in"],
                                   Faux(["secubox.in"], {"secubox.in": list(GANDI)}))
    assert code == 0 and sortie["etat"] == "inchange" and audits == []


def test_refus_code_3_et_audite(capsys):
    code, sortie, audits = _lancer(capsys, ["assurer", "gk4.secubox.in", "192.168.1.200", "secubox.in"],
                                   Faux(["secubox.in"], {"secubox.in": list(GANDI)}))
    assert code == 3 and "publique" in sortie["erreur"]
    assert audits[0][0] == "joker_refuse"


def test_echec_fournisseur_code_1(capsys):
    code, sortie, audits = _lancer(capsys, ["assurer", "gk4.secubox.in", "82.67.100.75", "secubox.in"],
                                   Faux(["secubox.in"], {"secubox.in": list(GANDI)}, refuse=True))
    assert code == 1 and "409" in sortie["erreur"] and audits[0][0] == "joker_echec"


def test_erreur_imprevue_code_1_et_auditee(capsys):
    class Casse(Faux):
        async def list_records(self, zone):
            raise KeyError("rrset_name")

    code, sortie, audits = _lancer(capsys, ["assurer", "gk4.secubox.in", "82.67.100.75", "secubox.in"],
                                   Casse(["secubox.in"]))
    assert code == 1 and "KeyError" in sortie["erreur"] and audits[0][0] == "joker_echec"


def test_seuls_les_fournisseurs_gandi_actifs(tmp_path, monkeypatch):
    """Revue #3206 : un fournisseur désactivé ne doit jamais être écrit, et le joker ne connaît que Gandi (Route53 et
    Cloudflare nomment autrement les enregistrements : « jamais écrasé » n'y serait pas tenu)."""
    cli = _cli()
    retenus = cli.fournisseurs_retenus([
        {"id": "a", "provider": "gandi", "enabled": True, "credentials": {}},
        {"id": "b", "provider": "gandi", "enabled": False, "credentials": {}},
        {"id": "c", "provider": "cloudflare", "enabled": True, "credentials": {}},
        {"id": "d", "provider": "gandi", "credentials": {}},
    ])
    assert [p["id"] for p in retenus] == ["a", "d"]
