# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: metablogizer — le domaine d'un site, calcul unique (#1012).

Le defaut corrige ici s'est manifeste sur `aletheia.gk2.secubox.in`, qui
rendait le contenu de MAGIC·CHESS·360 : la publication ecrivait
`server_name aletheia.local`, nginx n'associait ce bloc a aucune requete, et
servait donc le premier bloc venu — en 200, sans rien signaler.

Le calcul etait duplique a CINQ endroits et un seul etait juste : celui de
l'affichage. L'interface affirmait donc le bon domaine pendant que nginx en
portait un autre, ce qui a rendu le defaut invisible.
"""

import json


import sites_scan
from sites_scan import DEFAULT_DOMAIN_SUFFIX, domaine_du_site


def site(tmp_path, nom, config=None):
    d = tmp_path / nom
    (d / "public").mkdir(parents=True)
    if config is not None:
        (d / "site.json").write_text(json.dumps(config))
    return d


def test_sans_site_json_le_domaine_porte_le_suffixe_reel(tmp_path):
    # LE CAS D'ALETHEIA, releve verbatim sur gk2 : le repertoire ne contenait
    # que `public/`, aucun `site.json`. L'ancien chemin de publication rendait
    # alors `aletheia.local`.
    assert domaine_du_site(site(tmp_path, "aletheia")) == \
        "aletheia" + DEFAULT_DOMAIN_SUFFIX


def test_jamais_de_local_quel_que_soit_le_chemin(tmp_path):
    # La regle qui compte. Un `.local` ne peut plus sortir de ce calcul :
    # c'est precisement ce que nginx ne sait pas associer.
    for cfg in (None, {}, {"domain": ""}, {"domain": "   "},
                {"domain": "aletheia.local"}):
        d = site(tmp_path / str(id(cfg)), "aletheia", cfg)
        assert not domaine_du_site(d).endswith(".local"), f"cfg={cfg}"


def test_un_domaine_explicite_fait_foi_meme_hors_du_board(tmp_path):
    # Une soixantaine de sites servent sous maegia.tv ou ganimed.fr. Leur
    # imposer le suffixe du board les casserait tous.
    d = site(tmp_path, "chess", {"domain": "chess.ganimed.fr"})
    assert domaine_du_site(d) == "chess.ganimed.fr"


def test_un_local_herite_garde_son_sous_domaine(tmp_path):
    # `want` sert sous `wanted.` : reecrire a partir du NOM DU REPERTOIRE
    # perdrait ce choix. Seul le suffixe est remplace.
    d = site(tmp_path, "want", {"domain": "wanted.local"})
    assert domaine_du_site(d) == "wanted" + DEFAULT_DOMAIN_SUFFIX


def test_le_suffixe_est_retire_en_fin_pas_partout(tmp_path):
    # `replace` reecrivait TOUTES les occurrences : un domaine portant
    # `.local` ailleurs qu'en fin voyait son etiquette interne mutilee.
    d = site(tmp_path, "x", {"domain": "a.local.b.local"})
    assert domaine_du_site(d) == "a.local.b" + DEFAULT_DOMAIN_SUFFIX


def test_un_site_json_illisible_n_empeche_pas_la_publication(tmp_path):
    # Un JSON casse ne doit pas faire retomber sur `.local` — ni lever.
    d = site(tmp_path, "casse")
    (d / "site.json").write_text("{ ceci n'est pas du json")
    assert domaine_du_site(d) == "casse" + DEFAULT_DOMAIN_SUFFIX


def test_l_affichage_et_la_publication_donnent_LE_MEME_domaine(tmp_path):
    # LE TEST QUI COMPTE VRAIMENT. Le defaut n'etait pas qu'un chemin soit
    # faux : c'est que deux chemins repondaient DIFFEREMMENT, l'un montre a
    # l'operateur et l'autre ecrit dans nginx. Tant qu'ils s'accordent, une
    # erreur reste visible.
    for nom, cfg in (("aletheia", None), ("want", {"domain": "wanted.local"}),
                     ("chess", {"domain": "chess.ganimed.fr"}), ("nu", {})):
        racine = tmp_path / nom
        d = site(racine, nom, cfg)
        vus = sites_scan.scan_sites(racine, tmp_path / "absent.conf")
        assert vus, f"{nom} n'a pas ete scanne"
        assert vus[0]["domain"] == domaine_du_site(d), (
            f"{nom}: affichage={vus[0]['domain']} publication={domaine_du_site(d)}")


def test_le_vhost_publie_ne_reclame_jamais_le_port_80():
    """Le vhost généré ne doit JAMAIS demander `listen 80`.

    Sur une board SecuBox, HAProxy détient `0.0.0.0:80`. Un vhost qui le
    réclame empêche nginx de démarrer — `bind() to 0.0.0.0:80 failed (98:
    Address already in use)` — et TOUS les vhosts de l'hôte tombent avec lui.

    Le défaut restait invisible tant que nginx n'était que RECHARGÉ : un
    rechargement ne rebind pas, le master conservait donc un port pris avant
    HAProxy. Il n'a éclaté qu'au premier redémarrage franc, longtemps après la
    publication fautive — d'où un lien de cause à effet indéchiffrable.

    Le test lit la SOURCE comme TEXTE plutôt que d'importer le module :
    `main` charge /etc/secubox/secubox.conf à l'import, illisible hors board.

    Il ne vise QUE `publish_site`. Le module porte un second gabarit, dans
    l'export ZIP, où `listen 80` + `listen 443 ssl` est correct : ce bundle
    est destiné à une AUTRE machine, où nginx est seul en frontal. Interdire
    le port 80 partout casserait un export parfaitement valide.

    Les commentaires sont retirés — celui qui explique ce piège cite
    `listen 80` et ferait sinon échouer le test qu'il documente.
    """
    from pathlib import Path as _P

    src = (_P(__file__).resolve().parent.parent / "main.py").read_text()
    debut = src.index("async def publish_site(")
    fin = src.index("async def unpublish_site(", debut)
    corps = "\n".join(l for l in src[debut:fin].splitlines()
                      if not l.lstrip().startswith("#"))
    assert "listen 80;" not in corps, "le vhost publié réclame le port 80"
    assert "listen {BASE_PORT};" in corps, \
        "le vhost publié doit écouter sur le port du module"
