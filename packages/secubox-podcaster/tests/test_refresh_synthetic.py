"""Rafraichissement des flux synthetiques (#1005).

Plus aucun episode telecharge depuis le 2026-07-25. Quatre flux sur cinq ne
sont pas des sources HTTP mais des conteneurs crees localement
(`youtube:<serie>`, `audiobook:<titre>`) ; le rafraichisseur les passait a un
client HTTP, qui les refusait a chaque cycle.
"""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _src(name):
    return (ROOT / "api" / name).read_text()


def test_refresher_skips_non_http_feeds():
    """Un conteneur local n'est pas une URL : l'appeler en HTTP echoue a chaque
    cycle et masque les vrais problemes dans le journal."""
    s = _src("main.py")
    body = s[s.index("async def _refresher"):]
    assert 'url.startswith(("http://", "https://"))' in body


def test_importer_records_the_source_url():
    """Sans `site`, un flux youtube: est un cul-de-sac : son url propre n'est
    qu'un slug de serie, rien a re-interroger."""
    s = _src("importer.py")
    assert '"site": url' in s, "l'URL source doit etre enregistree"


def test_import_skips_known_entries_before_downloading():
    """L'insertion est idempotente, mais le TELECHARGEMENT a lieu avant : sans
    ce saut, un reimport retelechargerait la serie entiere — ce qui interdisait
    tout rafraichissement automatique."""
    s = _src("importer.py")
    loop = s[s.index("for i, e in enumerate(entries)"):]
    skip = loop.index('if f"yt:{vid}" in known')
    dl = loop.index("_download(")
    assert skip < dl, "le saut doit preceder le telechargement"


def test_missing_source_is_reported_once_not_looped():
    """Un flux importe avant ce correctif n'a pas de source : le dire une fois
    vaut mieux qu'echouer a chaque cycle."""
    s = _src("main.py")
    body = s[s.index("async def _refresh_synthetic"):]
    assert "log.info" in body and "reimportez-le une fois" in body
    assert "log.error" not in body.split("if importer.JOB")[0], \
        "une source absente n'est pas une erreur, c'est un etat connu"


def test_only_one_import_at_a_time():
    """L'import est lourd (yt-dlp) : deux en parallele saturent la board."""
    s = _src("main.py")
    body = s[s.index("async def _refresh_synthetic"):]
    assert 'importer.JOB.get("running")' in body


def test_every_run_import_call_matches_the_signature():
    """TOUS les appels, pas le premier.

    Un appel a la mauvaise arite passe le controle syntaxique et echoue au
    PREMIER CYCLE — une heure apres le deploiement, quand plus personne ne
    regarde. Le premier jet de ce correctif passait trois arguments a
    run_import qui en prend quatre.

    Deux pieges rencontres en ecrivant ce test, tous deux le rendaient
    complaisant :

      - une expression reguliere `[^)]*` s'arrete a la parenthese de
        `str(MEDIA)` et compte deux arguments au lieu de quatre ;
      - main.py contient DEUX appels a run_import (l'endpoint manuel, deja
        correct, et le reimport automatique). S'arreter au premier revient a
        valider un appel qu'on n'a pas ecrit — la mutation passait.

    Les deux cotes sont donc lus par analyse syntaxique, et TOUS les appels
    sont verifies. L'import direct est impossible ici : le module depend de
    secubox_core, absent de l'environnement de test."""
    import ast

    fn = next(n for n in ast.walk(ast.parse(_src("importer.py")))
              if isinstance(n, ast.FunctionDef) and n.name == "run_import")
    required = [a.arg for a in fn.args.args][:len(fn.args.args) - len(fn.args.defaults)]

    calls = []
    for node in ast.walk(ast.parse(_src("main.py"))):
        if not isinstance(node, ast.Call):
            continue
        f = node.func
        if isinstance(f, ast.Attribute) and f.attr == "to_thread" and node.args:
            a0 = node.args[0]
            if isinstance(a0, ast.Attribute) and a0.attr == "run_import":
                calls.append(node)
    assert calls, "aucun appel a run_import trouve"
    for node in calls:
        passed = node.args[1:]
        assert len(passed) == len(required), (
            f"ligne {node.lineno}: run_import attend {len(required)} arguments "
            f"{required}, l'appel en passe {len(passed)}")
