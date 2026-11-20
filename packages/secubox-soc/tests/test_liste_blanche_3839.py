# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3839 — liste blanche de SADE : ajout et retrait audités (page, API require_jwt, ligne de commande), jamais une
entrée système retirée, jamais un réseau trop large ; l'exécuteur automatique et l'approbation la respectent."""
# ruff: noqa: F811 — les fixtures pytest importées sont « redéfinies » par les paramètres des tests (faux positif).
import json
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_defense_approbation import isole, client, ADMIN  # noqa: E402,F401
from api import defense, defense_etat, liste_blanche  # noqa: E402

PAGE = (Path(__file__).resolve().parents[1] / "www" / "soc" / "defense.html").read_text(encoding="utf-8")


def _audit():
    try:
        return Path(os.environ["SECUBOX_AUDIT_LOG"]).read_text(encoding="utf-8")
    except OSError:
        return ""


def _lignes(action):
    return [json.loads(x) for x in _audit().splitlines() if x.strip() and json.loads(x).get("action") == action]


def test_ajout_normalise_et_audite(isole):
    assert defense_etat.ajouter_liste_blanche("82.67.100.75", "foyer", "gerald") == "82.67.100.75/32"
    assert defense_etat.ajouter_liste_blanche("2a01:e0a:dec:c4e0::1/64", "foyer v6", "gerald") == "2a01:e0a:dec:c4e0::/64"
    a = _lignes("sade-liste-blanche-ajout")
    assert {"module": "soc", "operateur": "gerald", "cidr": "82.67.100.75/32", "motif": "foyer"}.items() <= a[0].items()
    lb = {e["cidr"]: e for e in defense_etat.liste_blanche()}
    assert lb["82.67.100.75/32"]["supprimable"] is True and lb["10.0.0.0/8"]["supprimable"] is False


@pytest.mark.parametrize("cidr,cause", [("", "cidr_illisible"), ("pas-une-ip", "cidr_illisible"),
                                         ("0.0.0.0/0", "cidr_trop_large"), ("82.0.0.0/8", "cidr_trop_large"),
                                         ("82.67.0.0/23", "cidr_trop_large"), ("2a01::/16", "cidr_trop_large"),
                                         ("2a01:e0a::/32", "cidr_trop_large"), ("::ffff:82.67.100.0/120", "cidr_illisible"),
                                         ("2002:5243:644b::/48", "cidr_illisible"), ("64:ff9b::/96", "cidr_illisible")])
def test_reseau_refuse(isole, cidr, cause):
    with pytest.raises(ValueError, match=cause):
        defense_etat.ajouter_liste_blanche(cidr, "x", "gerald")
    assert "sade-liste-blanche-ajout" not in _audit()


def test_bornes_admises(isole):
    assert defense_etat.ajouter_liste_blanche("82.67.100.0/24", "x", "gerald") == "82.67.100.0/24"
    assert defense_etat.ajouter_liste_blanche("2a01:e0a:dec::/48", "x", "gerald") == "2a01:e0a:dec::/48"


def test_motif_sans_caractere_invisible(isole):
    for m in ("foyer\u202eraeyof", "a\u200bb"):
        with pytest.raises(ValueError, match="motif_invalide"):
            defense_etat.ajouter_liste_blanche("203.0.113.9", m, "gerald")


def test_doublon_motif_et_systeme(isole):
    defense_etat.ajouter_liste_blanche("203.0.113.7/32", "x", "gerald")
    with pytest.raises(ValueError, match="deja_presente"):
        defense_etat.ajouter_liste_blanche("203.0.113.7", "y", "gerald")
    with pytest.raises(ValueError, match="motif_invalide"):
        defense_etat.ajouter_liste_blanche("203.0.113.8", "a\nb", "gerald")
    with pytest.raises(ValueError, match="cidr_trop_large"):
        defense_etat.ajouter_liste_blanche("10.0.0.0/8", "x", "gerald")
    with pytest.raises(PermissionError):
        defense_etat.retirer_liste_blanche("10.0.0.0/8", "gerald")
    with pytest.raises(KeyError):
        defense_etat.retirer_liste_blanche("198.51.100.0/24", "gerald")
    assert defense_etat.retirer_liste_blanche("203.0.113.7/32", "gerald") == "203.0.113.7/32"
    assert _lignes("sade-liste-blanche-retrait")[-1]["cidr"] == "203.0.113.7/32"


def test_audit_en_echec_rien_ajoute(isole, monkeypatch):
    def ko(_):
        raise defense_etat.AuditIndisponible("x")
    monkeypatch.setattr(defense_etat, "ecrire_audit", ko)
    with pytest.raises(defense_etat.AuditIndisponible):
        defense_etat.ajouter_liste_blanche("203.0.113.7", "x", "gerald")
    assert "203.0.113.7/32" not in {e["cidr"] for e in defense_etat.liste_blanche()}


def test_api_ajout_retrait(isole, client):
    r = client.post("/defense/liste-blanche", json={"cidr": "82.67.100.75", "motif": "foyer"}, headers=ADMIN)
    assert r.status_code == 200 and r.json() == {"cidr": "82.67.100.75/32"}
    assert client.post("/defense/liste-blanche", json={"cidr": "82.67.100.75", "motif": "foyer"},
                       headers=ADMIN).json()["cause"] == "deja_presente"
    assert client.post("/defense/liste-blanche", json={"cidr": "1.0.0.0/8", "motif": "x"}, headers=ADMIN).status_code == 400
    assert client.post("/defense/liste-blanche/retirer", json={"cidr": "10.0.0.0/8"}, headers=ADMIN).status_code == 403
    assert client.post("/defense/liste-blanche/retirer", json={"cidr": "82.67.100.75/32"}, headers=ADMIN).status_code == 200


def test_api_reservee_a_l_administrateur(isole):
    from fastapi.testclient import TestClient
    from api import main
    r = TestClient(main.app).post("/defense/liste-blanche", json={"cidr": "82.67.100.75", "motif": "x"})
    assert r.status_code in (401, 403)


def test_adresse_ajoutee_protegee(isole):
    defense_etat.ajouter_liste_blanche("82.67.100.75", "foyer", "gerald")
    proteges, _illisibles, _ = defense._proteges({}, [])
    assert defense._adresse_interdite("82.67.100.75", proteges) is True
    assert defense._adresse_interdite("82.67.100.76", proteges) is False


def test_cli(isole, monkeypatch, capsys, tmp_path):
    monkeypatch.setattr(os, "geteuid", lambda: 1000)
    uid = tmp_path / "loginuid"
    uid.write_text(str(os.getuid()))
    monkeypatch.setattr(liste_blanche, "LOGINUID", str(uid))
    monkeypatch.setenv("SUDO_USER", "forge")          # jamais lu : l'identité vient du loginuid
    import pwd
    assert liste_blanche.main(["ajouter", "82.67.100.75", "foyer"]) == 0
    assert _lignes("sade-liste-blanche-ajout")[-1]["operateur"] == "cli:" + pwd.getpwuid(os.getuid()).pw_name
    assert liste_blanche.main(["lister"]) == 0 and "82.67.100.75/32\tfoyer\tajout" in capsys.readouterr().out
    assert liste_blanche.main(["retirer", "10.0.0.0/8"]) == 1
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    assert liste_blanche.main(["lister"]) == 2


def test_page_formulaire_admin_et_echappement():
    assert "'/liste-blanche'" in PAGE and "'/liste-blanche/retirer'" in PAGE
    assert "rendSeuils(r[5], r[6].ok && r[6].d && r[6].d.admin === true)" in PAGE
    assert "data-lbr=\"' + esc(e.cidr) + '\"" in PAGE and "esc(lbNote)" in PAGE
    assert "confirmer le retrait" in PAGE and "Confirmer l\\'ajout" in PAGE
    assert 'value="\' + esc(lbSaisie.cidr) + \'"' in PAGE
