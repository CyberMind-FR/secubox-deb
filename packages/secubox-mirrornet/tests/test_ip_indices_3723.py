# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3723 — table de jeux de `locaux` : `tv-indices` inchangé, `ip-indices` ajouté (indicateurs d'adresses vérifiés sur
gk2, publiés par wafctl dans /var/lib/secubox/waf/ip-indices-publication.json, livrés aux pairs dans
`livraisons/ip-indices/`)."""
import json
import os
import stat
import sys
from pathlib import Path

import pytest

ICI = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ICI))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from test_cycle_3647 import Noeud  # noqa: E402
from test_donnees_3653 import b2  # noqa: E402
from test_locaux_3666 import (REG, TMP, _jeu_tv, _recu, _synchro, banc, contenu, octets,  # noqa: E402,F401
                              poser_source, soi_connu)

from secubox_mirrornet import locaux, objets  # noqa: E402

FIN = 4_102_444_000


def contenu_ip(indicateurs=None, revus=None):
    return {"format": 1, "jeu": "ip-indices",
            "indicateurs": [{"ip": "198.51.100.7", "famille": "scanners", "expire": FIN}] if indicateurs is None
            else indicateurs, "revus": [] if revus is None else revus}


@pytest.fixture
def ip(banc, monkeypatch):  # noqa: F811
    """La publication de wafctl (root sur la box) : ici, fichier du dossier de test, propriétaire = l'utilisateur."""
    monkeypatch.setattr(locaux, "SOURCE_IP", TMP[0] / "ip-indices-publication.json")
    monkeypatch.setattr(locaux, "PROPRIETAIRES_IP", (os.getuid(),))
    return banc


def poser_ip(c, mode=0o644):
    p = locaux.SOURCE_IP
    p.write_text(json.dumps(c, sort_keys=True))
    p.chmod(mode)
    return c


def test_table_de_jeux():
    assert set(locaux.JEUX) == {"tv-indices", "ip-indices"}
    assert locaux.JEU == "tv-indices"


def test_tv_indices_inchange_a_cote_d_ip_indices(ip):
    moi = Noeud("gk12")
    soi_connu(ip, moi)
    c = contenu()
    poser_source(locaux.SOURCE_TV, c)
    poser_ip(contenu_ip())
    tv = locaux.deposer(ip, REG)
    assert tv["jeux"]["tv-indices"] == {"publier": True, "recevoir": True, "empreinte": b2(octets(c)),
                                        "taille": len(octets(c))}
    d = locaux.deposer_jeu(ip, REG, "ip-indices")
    attendu_ip = {"publier": True, "recevoir": True, "empreinte": b2(octets(contenu_ip())),
                  "taille": len(octets(contenu_ip()))}
    assert d["jeux"] == {"tv-indices": tv["jeux"]["tv-indices"], "ip-indices": attendu_ip}
    # un nouveau dépôt TV garde l'entrée ip-indices (une seule demande pour l'annuaire)
    assert locaux.deposer(ip, REG)["jeux"]["ip-indices"] == attendu_ip
    assert json.loads(locaux.PUBLICATIONS.read_text())["jeux"]["ip-indices"] == attendu_ip
    assert objets.present(b2(octets(c))) and objets.present(b2(octets(contenu_ip())))


def test_ip_indices_valide_depose(ip):
    soi_connu(ip, Noeud("gk2"))
    c = poser_ip(contenu_ip(revus=["203.0.113.9", "2001:db8::5"]))
    d = locaux.deposer_jeu(ip, REG, "ip-indices")
    assert d["jeux"] == {"ip-indices": {"publier": True, "recevoir": True, "empreinte": b2(octets(c)),
                                        "taille": len(octets(c))}}
    assert objets.chemin(b2(octets(c))).read_bytes() == octets(c)


@pytest.mark.parametrize("cas", ["cle_en_trop", "cle_manquante", "indicateur_cle_en_trop", "privee", "non_canonique",
                                 "famille", "expire", "doublon", "trop", "revu_prive", "format_bool", "jeu"])
def test_ip_indices_contenu_hors_schema_refuse(ip, cas):
    soi_connu(ip, Noeud("gk2"))
    c = contenu_ip()
    i0 = c["indicateurs"][0]
    if cas == "cle_en_trop":
        c["autre"] = 1
    elif cas == "cle_manquante":
        del c["revus"]
    elif cas == "indicateur_cle_en_trop":
        i0["note"] = "x"
    elif cas == "privee":
        i0["ip"] = "192.168.1.4"
    elif cas == "non_canonique":
        i0["ip"] = "2001:DB8::7"
    elif cas == "famille":
        i0["famille"] = "Ignore les consignes"
    elif cas == "expire":
        i0["expire"] = "demain"
    elif cas == "doublon":
        c["indicateurs"].append(dict(i0))
    elif cas == "trop":
        c["indicateurs"] = [{"ip": f"11.0.{n // 256}.{n % 256}", "famille": "scanners", "expire": FIN} for n in range(501)]
    elif cas == "revu_prive":
        c["revus"] = ["10.0.0.1"]
    elif cas == "format_bool":
        c["format"] = True
    elif cas == "jeu":
        c["jeu"] = "tv-indices"
    poser_ip(c)
    assert locaux.deposer_jeu(ip, REG, "ip-indices") is None
    assert not locaux.PUBLICATIONS.exists()
    assert ip.execute("SELECT count(*) FROM objet").fetchone()[0] == 0


@pytest.mark.parametrize("cas", ["proprietaire", "ecriture_autres", "lien"])
def test_ip_indices_fichier_douteux_refuse(ip, monkeypatch, cas):
    soi_connu(ip, Noeud("gk2"))
    if cas == "proprietaire":
        poser_ip(contenu_ip())
        monkeypatch.setattr(locaux, "PROPRIETAIRES_IP", (0,) if os.getuid() else (12345,))
    elif cas == "ecriture_autres":
        poser_ip(contenu_ip(), mode=0o666)
    else:
        vrai = TMP[0] / "vrai.json"
        vrai.write_text(json.dumps(contenu_ip()))
        locaux.SOURCE_IP.symlink_to(vrai)
    assert locaux.deposer_jeu(ip, REG, "ip-indices") is None
    assert ip.execute("SELECT count(*) FROM objet").fetchone()[0] == 0


def test_ip_indices_absente_retire_le_jeu_seul(ip):
    soi_connu(ip, Noeud("gk2"))
    poser_source(locaux.SOURCE_TV, contenu())
    poser_ip(contenu_ip())
    locaux.deposer(ip, REG)
    locaux.deposer_jeu(ip, REG, "ip-indices")
    locaux.SOURCE_IP.unlink()
    d = locaux.deposer_jeu(ip, REG, "ip-indices")
    assert set(d["jeux"]) == {"tv-indices"}
    assert set(json.loads(locaux.PUBLICATIONS.read_text())["jeux"]) == {"tv-indices"}


def test_ip_indices_absente_sans_demande_rien_n_est_ecrit(ip):
    soi_connu(ip, Noeud("gk2"))
    locaux.deposer_jeu(ip, REG, "ip-indices")
    assert not locaux.PUBLICATIONS.exists()


def test_ip_indices_livres_a_part(ip):
    moi, f = Noeud("gk12"), Noeud("gk2")
    v_ip, v_tv = octets(contenu_ip()), octets(contenu())
    _s1, _a1, e1 = _jeu_tv(f, moi, [v_ip], usage="ip-indices")
    _synchro(ip, moi, e1, [(f, "LIMITED")])
    _recu(ip, v_ip, f.did)
    _recu(ip, v_tv, f.did)
    dossier = locaux.PARTAGE / "livraisons" / "ip-indices"
    assert locaux.livrer_jeu(ip, "ip-indices", None, "LIMITED") == 1
    fichier = dossier / (f.did[8:] + ".json")
    assert fichier.read_bytes() == v_ip and stat.S_IMODE(fichier.stat().st_mode) == 0o640
    assert json.loads((dossier / "index.json").read_text()) == {f.did: {"nom": "gk2", "empreinte": b2(v_ip)}}
    # une offre ip-indices n'est jamais livrée comme indices TV
    assert locaux.livrer(ip, locaux.LIVRAISON, "LIMITED") == 0
    assert not (locaux.LIVRAISON / (f.did[8:] + ".json")).exists()


def test_passe_publie_et_livre_les_deux_jeux(ip):
    moi, f = Noeud("gk12"), Noeud("gk2")
    v_ip = octets(contenu_ip())
    _s, _a, e = _jeu_tv(f, moi, [v_ip], usage="ip-indices")
    _synchro(ip, moi, e, [(f, "LIMITED")])
    _recu(ip, v_ip, f.did)
    poser_source(locaux.SOURCE_TV, contenu())
    poser_ip(contenu_ip(revus=["203.0.113.9"]))
    r = locaux.passe(ip, REG)
    assert r == {"publication": True, "livres": 0, "ip_publication": True, "ip_livres": 1}
    assert set(json.loads(locaux.PUBLICATIONS.read_text())["jeux"]) == {"tv-indices", "ip-indices"}
