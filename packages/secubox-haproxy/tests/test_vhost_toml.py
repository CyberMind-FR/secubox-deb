# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: haproxyctl — édition du haproxy.toml (#1015).

Trois défauts, tous relevés sur le fichier vivant de gk2 :

  - `vhost add` appendait sans regarder l'existant → deux tables pour le même
    domaine, deux ACL identiques dans le cfg généré ;
  - `vhost add` insérait son argument `ssl` verbatim → `ssl = ssl`, qui n'est
    pas du TOML ;
  - `vhost remove` supprimait jusqu'à l'en-tête SUIVANT inclus → la section
    d'après était décapitée et ses clés devenaient orphelines.

Le fichier de production n'était de ce fait pas du TOML valide, et l'API du
module, qui le charge avec `tomllib`, échouait — pendant que le générateur, qui
le lit avec `grep`/`sed`, continuait sans rien signaler.
"""

import subprocess
import tomllib
from pathlib import Path

import pytest

RACINE = Path(__file__).resolve().parent.parent
CTL = RACINE / "sbin" / "haproxyctl"

SAIN = """\
[global]
maxconn = 2048

[vhosts.a_exemple_fr]
domain = "a.exemple.fr"
backend = "mitmproxy_inspector"
ssl = false
ssl_redirect = true
enabled = true

[vhosts.b_exemple_fr]
domain = "b.exemple.fr"
backend = "nginx_vhosts"
ssl = true
ssl_redirect = true
enabled = true
waf_bypass = true
"""


def ctl(conf, *args):
    """Lance haproxyctl sur une config temporaire, sans toucher au systeme."""
    r = subprocess.run(
        ["bash", str(CTL), *args],
        env={"PATH": "/usr/bin:/bin", "SECUBOX_HAPROXY_CONF": str(conf),
             "HOME": "/tmp"},
        capture_output=True, text=True)
    return r


@pytest.fixture
def conf(tmp_path):
    c = tmp_path / "haproxy.toml"
    c.write_text(SAIN)
    return c


# ── Le verbe de reparation ────────────────────────────────────────────────

def test_une_config_saine_est_declaree_saine(conf):
    r = ctl(conf, "config-repair")
    assert "configuration saine" in r.stdout, r.stdout + r.stderr


def test_le_booleen_invalide_est_signale_puis_corrige(conf):
    # LE CAS DE GK2 : `ssl = ssl`, produit par `vhost add <d> <b> ssl`.
    conf.write_text(SAIN + '\n[vhosts.c_exemple_fr]\ndomain = "c.exemple.fr"\n'
                           'backend = "nginx_vhosts"\nssl = ssl\nenabled = true\n')
    with pytest.raises(tomllib.TOMLDecodeError):
        tomllib.loads(conf.read_text())

    vu = ctl(conf, "config-repair")
    assert "booleen invalide" in vu.stdout, vu.stdout + vu.stderr
    # SANS --write, RIEN N'EST TOUCHE : on ne reecrit pas la configuration d'un
    # frontal en production par simple consultation.
    with pytest.raises(tomllib.TOMLDecodeError):
        tomllib.loads(conf.read_text())

    ctl(conf, "config-repair", "--write")
    d = tomllib.loads(conf.read_text())
    assert d["vhosts"]["c_exemple_fr"]["ssl"] is False


def test_la_reparation_preserve_le_comportement(conf):
    # `ssl = ssl` est lu comme FALSE par le generateur (`grep -q 'true'`).
    # Le normaliser vers `false` ne change donc rien au trafic — vers `true`,
    # si, et cela exposerait un vhost sans certificat.
    conf.write_text(SAIN.replace("ssl = false", "ssl = ssl", 1))
    ctl(conf, "config-repair", "--write")
    d = tomllib.loads(conf.read_text())
    assert d["vhosts"]["a_exemple_fr"]["ssl"] is False


def test_la_table_en_double_est_repliee_sur_la_premiere(conf):
    # On garde la PREMIERE : c'est celle que le generateur rencontre d'abord,
    # donc celle dont le comportement est deja observe en production.
    conf.write_text(SAIN + '\n[vhosts.a_exemple_fr]\ndomain = "a.exemple.fr"\n'
                           'backend = "AUTRE"\nssl = true\nenabled = true\n')
    ctl(conf, "config-repair", "--write")
    d = tomllib.loads(conf.read_text())
    assert d["vhosts"]["a_exemple_fr"]["backend"] == "mitmproxy_inspector"


def test_la_reparation_laisse_une_sauvegarde(conf, tmp_path):
    # La configuration d'un frontal ne se remplace pas sans filet.
    conf.write_text(SAIN.replace("ssl = false", "ssl = ssl", 1))
    ctl(conf, "config-repair", "--write")
    assert list(tmp_path.glob("haproxy.toml.avant-reparation-*")), \
        "aucune sauvegarde avant reecriture"


# ── Ajout et suppression ──────────────────────────────────────────────────

def test_ajouter_deux_fois_ne_cree_pas_deux_tables(conf):
    # LE DEFAUT D'ORIGINE : `aletheia` declare deux fois, d'ou deux ACL
    # identiques dans le cfg genere.
    ctl(conf, "vhost", "add", "c.exemple.fr", "nginx_vhosts", "false")
    ctl(conf, "vhost", "add", "c.exemple.fr", "nginx_vhosts", "false")
    assert conf.read_text().count("[vhosts.c_exemple_fr]") == 1
    tomllib.loads(conf.read_text())


def test_un_ssl_non_booleen_est_refuse_pas_ecrit(conf):
    # Ecrire l'argument verbatim produisait `ssl = ssl` — pas du TOML.
    r = ctl(conf, "vhost", "add", "d.exemple.fr", "nginx_vhosts", "peut-etre")
    assert r.returncode != 0, "un ssl absurde a ete accepte"
    assert "d_exemple_fr" not in conf.read_text()
    tomllib.loads(conf.read_text())


def test_supprimer_un_vhost_ne_decapite_pas_le_suivant(conf):
    # LE PIEGE DE LA PLAGE sed : `/^\\[a\\]/,/^\\[/d` supprime jusqu'a l'en-tete
    # d'apres INCLUS. La section suivante perdait son en-tete et ses cles
    # etaient absorbees par la precedente — en silence.
    ctl(conf, "vhost", "remove", "a_exemple_fr")
    texte = conf.read_text()
    assert "[vhosts.a_exemple_fr]" not in texte
    assert "[vhosts.b_exemple_fr]" in texte, "la section suivante a ete decapitee"
    d = tomllib.loads(texte)
    assert d["vhosts"]["b_exemple_fr"]["backend"] == "nginx_vhosts"
    # Et la cle que le paquet ne gere pas doit survivre : la perdre
    # desactiverait en silence une exception WAF declaree par l'operateur.
    assert d["vhosts"]["b_exemple_fr"]["waf_bypass"] is True


def test_mettre_a_jour_un_vhost_preserve_ses_cles_non_gerees(conf):
    # `waf_bypass` est la seule exception WAF sanctionnee : la perdre a la
    # mise a jour d'un vhost la desactiverait sans que personne ne le voie.
    ctl(conf, "vhost", "add", "b.exemple.fr", "mitmproxy_inspector", "true")
    d = tomllib.loads(conf.read_text())
    assert d["vhosts"]["b_exemple_fr"]["backend"] == "mitmproxy_inspector"
    assert d["vhosts"]["b_exemple_fr"]["waf_bypass"] is True
