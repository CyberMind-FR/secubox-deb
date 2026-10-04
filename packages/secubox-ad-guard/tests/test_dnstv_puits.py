# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#1959 : état étendu (MAC, origine, puits, mode par défaut…) et vue `auto` qui GARDE le puits de production (`view-first: yes`)."""
import pytest

from api import dnstv


def etat(**kw):
    c = {"ip": "192.168.1.95", "nom": "TV banc", "mode": "auto"}
    c.update(kw)
    return {"actif": True, "clients": [c]}


def bloc_auto(sortie):
    return sortie.split('name: "sbx-tv-auto-tv-banc"')[1].split("view:")[0]


def test_vue_auto_avec_puits_complet_par_defaut():
    out = dnstv.rendre_unbound(etat(), {}, {"tv-banc": ["videos-pub.ftv-publicite.fr"]})
    b = bloc_auto(out)
    assert "view-first: yes" in b and 'local-zone: "." transparent' not in b
    assert 'local-zone: "videos-pub.ftv-publicite.fr." always_nxdomain' in b


def test_puits_faux_rend_l_ancien_comportement_transparent():
    b = bloc_auto(dnstv.rendre_unbound(etat(puits=False), {}, {}))
    assert 'local-zone: "." transparent' in b and "view-first" not in b


def test_observe_et_block_restent_transparents():
    out = dnstv.rendre_unbound(etat(mode="block"), {"a.example": "advertising"}, None)
    bloc = out.split('name: "sbx-tv-block"')[1].split("view:")[0]
    assert bloc.count('local-zone: "." transparent') == 1
    assert 'name: "sbx-tv-observe"' in out and 'local-zone: "." transparent' in out.split('name: "sbx-tv-observe"')[1].split("view:")[0]


def test_champs_revalides():
    base = dict(ip="192.168.1.95", nom="TV 4e95", mode="auto")
    c = dnstv.valider_etat({"actif": True, "clients": [dict(base, mac="38:07:16:93:4e:95", origine="auto", ajoute=1800000000, preuve="fwmrm.net x12")]})["clients"][0]
    assert c["mac"] == "38:07:16:93:4e:95" and c["origine"] == "auto" and c["ajoute"] == 1800000000 and c["preuve"] == "fwmrm.net x12"
    for mauvais in (dict(base, mac="00:00:00:00:00:00"), dict(base, mac="38:07:16:93:4E:95"), dict(base, mac='x"; reboot'), dict(base, origine="root"),
                    dict(base, puits="oui"), dict(base, ajoute=-1), dict(base, preuve="x" * 500), dict(base, mac=12)):
        with pytest.raises(dnstv.ErreurTV):
            dnstv.valider_etat({"actif": True, "clients": [mauvais]})


def test_defauts_racine_et_anciens_etats_inchanges():
    e = dnstv.valider_etat({"actif": True, "clients": [{"ip": "192.168.1.95", "nom": "TV", "mode": "observe"}]})
    assert e["mode_defaut"] == "auto" and e["ajout_auto"] is False and e["ignores"] == []
    assert e["clients"][0] == {"ip": "192.168.1.95", "nom": "TV", "mode": "observe"}      # aucun champ ajouté tant qu'il est à sa valeur par défaut
    for mauvais in ({"mode_defaut": "inconnu"}, {"ajout_auto": "oui"}, {"ignores": ["pas-une-mac"]}, {"ignores": ["38:07:16:93:4e:95"] * 65},
                    {"ignores": "38:07:16:93:4e:95"}):
        with pytest.raises(dnstv.ErreurTV):
            dnstv.valider_etat({"actif": True, "clients": [], **mauvais})


def test_ignores_dedoublonnes():
    e = dnstv.valider_etat({"actif": True, "clients": [], "ignores": ["38:07:16:93:4e:95", "38:07:16:93:4e:95"]})
    assert e["ignores"] == ["38:07:16:93:4e:95"]


def test_meme_nom_meme_puits_et_meme_mode():
    cs = [{"ip": "192.168.1.95", "nom": "TV", "mode": "auto"}, {"ip": "2a01::1", "nom": "TV", "mode": "auto", "puits": False}]
    with pytest.raises(dnstv.ErreurTV):
        dnstv.valider_etat({"actif": True, "clients": cs})


def test_etat_par_defaut_porte_les_nouveaux_champs():
    assert dnstv.ETAT_DEFAUT["mode_defaut"] == "auto" and dnstv.ETAT_DEFAUT["ajout_auto"] is False and dnstv.ETAT_DEFAUT["ignores"] == []


def test_un_changement_de_puits_declenche_un_rechargement_complet(monkeypatch, tmp_path):
    """Les vues changent : l'application à chaud ne suffit pas, le contrôleur doit recharger Unbound."""
    from test_dnstv_auto_rendu import charger_ctl, faux
    faux(tmp_path, "checkconf")
    ctl = faux(tmp_path, "unbound-control")
    mod = charger_ctl(monkeypatch, tmp_path, ctl)
    dnstv.ecrire_etat(etat(), tmp_path)
    mod.appliquer()
    (tmp_path / "unbound-control.log").unlink(missing_ok=True)
    dnstv.ecrire_etat(etat(puits=False), tmp_path)
    assert mod.regles_appliquer() == 0
    assert "reload" in (tmp_path / "unbound-control.log").read_text()
    assert 'local-zone: "." transparent' in bloc_auto((tmp_path / "94.conf").read_text())
