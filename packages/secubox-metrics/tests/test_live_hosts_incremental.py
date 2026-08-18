# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Lecture incrementale des journaux nginx par live_hosts (#1045).

Le defaut corrige : 87 journaux, 12 Mo, relus et re-analyses chaque minute — un
`strptime` par ligne — pour ne retenir que 60 minutes et n en afficher que cinq
hotes.

Ces tests figent le comportement incrementale ET les situations ou il pourrait
PERDRE des lignes, ce que la relecture integrale ne pouvait pas provoquer.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from api.live_hosts import LiveHostsAggregator


def _ligne(quand: datetime, chemin: str = "/") -> str:
    # Format nginx combined : la date entre crochets est ce que TS_RE cherche.
    return ('1.2.3.4 - - [%s] "GET %s HTTP/1.1" 200 12 "-" "curl"\n'
            % (quand.strftime("%d/%b/%Y:%H:%M:%S +0000"), chemin))


def _agg(tmp_path, fenetre=60):
    return LiveHostsAggregator({"enabled": True, "log_dir": str(tmp_path),
                                "window_minutes": fenetre, "top_n": 5})


def _ecrire(f, lignes, mode="a"):
    with open(f, mode, encoding="utf-8") as fh:
        for l in lignes:
            fh.write(l)


def test_les_lignes_neuves_seules_sont_relues(tmp_path):
    """Le coeur de la correction."""
    f = tmp_path / "a.fr_access.log"
    maintenant = datetime.now(timezone.utc)
    _ecrire(f, [_ligne(maintenant)], "w")
    agg = _agg(tmp_path)
    counts, total = agg._read_nginx_hosts()
    assert counts["a.fr"] == 1 and total == 1
    pos1 = agg._pos[str(f)][2]
    assert pos1 == f.stat().st_size

    _ecrire(f, [_ligne(maintenant), _ligne(maintenant)])
    counts, total = agg._read_nginx_hosts()
    # Les trois sont comptees, alors que la premiere n a PAS ete relue.
    assert counts["a.fr"] == 3 and total == 3
    assert agg._pos[str(f)][2] == f.stat().st_size > pos1


def test_sans_ligne_neuve_le_compte_ne_bouge_pas(tmp_path):
    f = tmp_path / "a.fr_access.log"
    _ecrire(f, [_ligne(datetime.now(timezone.utc))], "w")
    agg = _agg(tmp_path)
    agg._read_nginx_hosts()
    avant = agg._pos[str(f)][2]
    counts, total = agg._read_nginx_hosts()
    assert counts["a.fr"] == 1 and total == 1
    assert agg._pos[str(f)][2] == avant


def test_la_fenetre_glissante_oublie_le_passe(tmp_path):
    """La purge par minute remplace la relecture : une entree sortie de la
    fenetre doit disparaitre du compte SANS qu on relise le fichier."""
    f = tmp_path / "a.fr_access.log"
    maintenant = datetime.now(timezone.utc)
    _ecrire(f, [_ligne(maintenant - timedelta(minutes=90)),
                _ligne(maintenant)], "w")
    agg = _agg(tmp_path, fenetre=60)
    counts, total = agg._read_nginx_hosts()
    assert counts["a.fr"] == 1, "une entree hors fenetre a ete comptee"
    assert total == 1


def test_un_hote_devenu_vide_sort_du_resultat(tmp_path):
    f = tmp_path / "a.fr_access.log"
    maintenant = datetime.now(timezone.utc)
    _ecrire(f, [_ligne(maintenant - timedelta(minutes=3))], "w")
    agg = _agg(tmp_path, fenetre=5)
    assert agg._read_nginx_hosts()[0]["a.fr"] == 1
    # On rétrécit la fenetre : l entree en sort, l hote doit disparaitre.
    agg.cfg["window_minutes"] = 1
    counts, total = agg._read_nginx_hosts()
    assert "a.fr" not in counts and total == 0
    assert "a.fr" not in agg._minutes, "le seau vide reste en memoire"


def test_une_ligne_partielle_nest_pas_perdue(tmp_path):
    """nginx ecrit pendant qu on lit. Consommer une ligne tronquee la rendrait
    illisible ET impossible a relire — donc perdue."""
    f = tmp_path / "a.fr_access.log"
    maintenant = datetime.now(timezone.utc)
    _ecrire(f, [_ligne(maintenant)], "w")
    agg = _agg(tmp_path)
    assert agg._read_nginx_hosts()[0]["a.fr"] == 1
    entiere = _ligne(maintenant, "/tard")
    _ecrire(f, [entiere[:30]])                      # moitie de ligne
    assert agg._read_nginx_hosts()[0]["a.fr"] == 1  # pas encore visible
    _ecrire(f, [entiere[30:]])                      # nginx termine
    assert agg._read_nginx_hosts()[0]["a.fr"] == 2  # rien n a ete perdu


def test_la_rotation_repart_du_debut(tmp_path):
    f = tmp_path / "a.fr_access.log"
    maintenant = datetime.now(timezone.utc)
    _ecrire(f, [_ligne(maintenant)], "w")
    agg = _agg(tmp_path)
    agg._read_nginx_hosts()
    f.rename(tmp_path / "a.fr_access.log.1")        # logrotate
    _ecrire(f, [_ligne(maintenant)], "w")
    counts, _ = agg._read_nginx_hosts()
    # La ligne du fichier neuf s ajoute a celles deja comptees dans la fenetre :
    # la rotation ne doit ni tout perdre, ni tout recompter.
    assert counts["a.fr"] == 2


def test_un_journal_disparu_ne_laisse_pas_de_position(tmp_path):
    f = tmp_path / "a.fr_access.log"
    _ecrire(f, [_ligne(datetime.now(timezone.utc))], "w")
    agg = _agg(tmp_path)
    agg._read_nginx_hosts()
    assert str(f) in agg._pos
    f.unlink()
    agg._read_nginx_hosts()
    assert str(f) not in agg._pos, "la position d un journal disparu subsiste"


def test_plusieurs_hotes_sont_comptes_separement(tmp_path):
    maintenant = datetime.now(timezone.utc)
    _ecrire(tmp_path / "a.fr_access.log", [_ligne(maintenant)] * 2, "w")
    _ecrire(tmp_path / "b.fr_access.log", [_ligne(maintenant)] * 5, "w")
    counts, total = _agg(tmp_path)._read_nginx_hosts()
    assert counts["a.fr"] == 2 and counts["b.fr"] == 5 and total == 7
