# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: secubox-waf-ng :: relais nginx vers sbx-actord (ref #1608)
CyberMind — https://cybermind.fr

sbx-actord sert deux vues par le même socket (voir cmd/sbx-actord/vue.go) :

  - l'arbre préfixé /api/v1/actor/… ne sert que la vue RÉDUITE ;
  - la RACINE sert la vue COMPLÈTE seulement avec `X-Sbx-Vue: complete`.

La règle tient donc à la FORME des relais nginx, dans tout le dépôt :

  1. un relais de lecture conserve le préfixe /api/v1/actor/ (arbre réduit) ;
  2. le vhost d'administration actor.gk2 ne relaie pas vers actor.sock : il
     passe par l'agrégateur (garde « administrateur réel », #1581), seul à
     poser `X-Sbx-Vue: complete`, et vide l'en-tête du visiteur ;
  3. aucun fichier nginx ne pose `X-Sbx-Vue complete`.

La garde de l'agrégateur est testée dans secubox-aggregator.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent            # packages/secubox-waf-ng
REPO = ROOT.parent.parent
VHOST_ADMIN = ROOT / "nginx" / "actor.gk2.secubox.in.conf"
SOCKET = "/run/secubox/actor.sock"
PREFIXE = "/api/v1/actor/"


def _sans_commentaires(texte: str) -> str:
    return "\n".join(l.split("#", 1)[0] for l in texte.splitlines())


def _locations(texte: str):
    """(motif de la location, corps) pour chaque bloc location, blocs imbriqués
    (limit_except) compris dans le corps."""
    t = _sans_commentaires(texte)
    for m in re.finditer(r"\blocation\s+([^{]*?)\s*\{", t):
        profondeur, i = 1, m.end()
        while i < len(t) and profondeur:
            profondeur += {"{": 1, "}": -1}.get(t[i], 0)
            i += 1
        yield m.group(1).strip(), t[m.end():i - 1]


def _fichiers_nginx():
    for base in (REPO / "packages", REPO / "common"):
        for p in base.rglob("*"):
            if not p.is_file() or any(x in p.parts for x in (".git", "vendor", "node_modules", "tests")):
                continue
            if p.suffix == ".conf" or ".conf." in p.name or p.name.endswith((".vhost", ".tmpl")):
                yield p


def _relais_actor():
    """(fichier, motif, corps, uri) pour chaque proxy_pass vers actor.sock.
    uri = partie URI du proxy_pass, None s'il n'en a pas (URI transmise telle quelle)."""
    for f in _fichiers_nginx():
        try:
            texte = f.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        if SOCKET not in texte:
            continue
        for motif, corps in _locations(texte):
            for pp in re.findall(r"proxy_pass\s+([^;]+);", corps):
                pp = pp.strip()
                if SOCKET not in pp:
                    continue
                reste = pp.split(SOCKET, 1)[1]
                uri = reste[1:] if reste.startswith(":") else None
                yield f, motif, corps, uri


def _motif_prefixe(motif: str) -> bool:
    """La location ne capte-t-elle que des chemins sous /api/v1/actor/ ?"""
    mots = motif.split()
    if mots and mots[0] in ("=", "^~"):
        mots = mots[1:]
    if mots and mots[0] in ("~", "~*"):
        return mots[1].startswith("^" + PREFIXE)
    return bool(mots) and mots[0].startswith(PREFIXE)


def _pose_complete(corps: str) -> bool:
    return re.search(r"proxy_set_header\s+X-Sbx-Vue\s+\"?complete\"?\s*;", corps, re.I) is not None


RELAIS = list(_relais_actor())


def test_le_relais_du_hall_est_trouve():
    assert "hall.vhost.conf" in {f.name for f, *_ in RELAIS}


@pytest.mark.parametrize("f,motif,corps,uri", RELAIS,
                         ids=[f"{f.parent.parent.name}:{m}" for f, m, _, _ in RELAIS])
def test_relais_de_lecture_conserve_le_prefixe(f, motif, corps, uri):
    if uri is None:
        # Pas d'URI : nginx transmet le chemin tel quel, qui doit être préfixé.
        assert _motif_prefixe(motif), f"{f}: location {motif} hors de {PREFIXE}"
    else:
        assert uri.startswith(PREFIXE), f"{f}: location {motif} retire le préfixe ({uri})"
    assert not _pose_complete(corps), f"{f}: location {motif} pose X-Sbx-Vue complete"


def _api_vhost_admin():
    blocs = [(m, c) for m, c in _locations(VHOST_ADMIN.read_text(encoding="utf-8"))
             if m == PREFIXE]
    assert len(blocs) == 1
    return blocs[0][1]


def test_vhost_admin_passe_par_la_garde_de_l_agregateur():
    corps = _api_vhost_admin()
    assert SOCKET not in corps
    pp = re.findall(r"proxy_pass\s+([^;]+);", corps)
    assert pp == ["http://unix:/run/secubox/aggregator.sock:/api/v1/actor/"]
    assert re.search(r'proxy_set_header\s+X-Sbx-Vue\s+"";', corps)
    assert not _pose_complete(corps)
    assert re.search(r"limit_except\s+GET\s*\{\s*deny\s+all;\s*\}", corps)


def test_vhost_admin_reste_filtre_au_lan():
    texte = _sans_commentaires(VHOST_ADMIN.read_text(encoding="utf-8"))
    assert "include /etc/nginx/snippets/exposure/actor.gk2.secubox.in.conf;" in texte


def test_aucun_fichier_nginx_ne_pose_la_vue_complete():
    for f in _fichiers_nginx():
        try:
            texte = _sans_commentaires(f.read_text(encoding="utf-8"))
        except (UnicodeDecodeError, OSError):
            continue
        assert not re.search(r"X-Sbx-Vue\s+\"?complete", texte, re.I), f
