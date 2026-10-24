# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3117 : aucun vhost nginx livré ne porte un nom propre à gk2 dans `server_name`.

gk2 est UNE box. Un paquet qui livre `server_name x.gk2.secubox.in` publie les
noms de gk2 sur toutes les boxes qui l'installent. Le service d'une box se
nomme par un joker `<x>.*` (les noms exacts de gk2 restent couverts par lui).

Fichiers balayés (sources livrées) : `packages/*/nginx/**`,
`packages/*/conf/*.nginx.conf`, `packages/*/composants/*/nginx/**`, et
`packages/*/deploy/*nginx*.conf` (billets y range son vhost). Sont
exclus les arbres de construction `packages/<pkg>/debian/<pkg>/` et les
`*.example`.
"""
import re
from pathlib import Path

RACINE = Path(__file__).resolve().parent.parent
PACKAGES = RACINE / "packages"

# LISTE D'EXCEPTIONS — UNIQUEMENT ce qui n'a pas pu être corrigé sans risque.
# Chaque entrée : chemin relatif à packages/ → raison. Vide à ce jour : tous
# les vhosts livrés ont été neutralisés par #3117.
EXCEPTIONS: dict[str, str] = {}

_RE_SERVER_NAME = re.compile(r"\bserver_name\s+([^;]*);", re.S)


def _sans_commentaires(texte: str) -> str:
    return "\n".join(ligne.split("#", 1)[0] for ligne in texte.splitlines())


def _fichiers_livres():
    motifs = ("*/nginx/**/*", "*/conf/*.nginx.conf", "*/composants/*/nginx/**/*",
              "*/deploy/*nginx*.conf")
    vus = set()
    for motif in motifs:
        for f in PACKAGES.glob(motif):
            if not f.is_file() or f in vus or f.name.endswith(".example"):
                continue
            rel = f.relative_to(PACKAGES)
            # Arbre de construction dh : packages/<pkg>/debian/<pkg>/…
            if len(rel.parts) > 2 and rel.parts[1] == "debian":
                continue
            vus.add(f)
            yield f


def _noms_gk2(f: Path) -> list[str]:
    try:
        texte = f.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return []
    fautifs = []
    for m in _RE_SERVER_NAME.finditer(_sans_commentaires(texte)):
        fautifs += [n for n in m.group(1).split() if "gk2" in n.lower()]
    return fautifs


def test_la_garde_voit_les_vhosts():
    noms = {f.relative_to(PACKAGES).as_posix() for f in _fichiers_livres()}
    assert "secubox-hub/nginx/webui.conf" in noms
    assert "secubox-gitea/conf/gitea.nginx.conf" in noms
    assert "secubox-ytsas/composants/torrent/nginx/torrent.conf" in noms
    assert "secubox-billets/deploy/nginx.conf" in noms


def test_aucun_server_name_de_gk2():
    fautes = {}
    for f in _fichiers_livres():
        rel = f.relative_to(PACKAGES).as_posix()
        noms = _noms_gk2(f)
        if noms and rel not in EXCEPTIONS:
            fautes[rel] = noms
    assert not fautes, f"server_name propres à gk2 livrés (#3117) : {fautes}"


def test_les_exceptions_sont_encore_justifiees():
    # Une exception corrigée doit quitter la liste, sinon elle couvrirait une régression.
    perimees = [r for r in EXCEPTIONS if not _noms_gk2(PACKAGES / r)]
    assert not perimees, f"exceptions devenues inutiles : {perimees}"


def test_la_garde_attrape_un_nom_de_gk2(tmp_path):
    f = tmp_path / "v.conf"
    f.write_text("server {\n  # server_name x.gk2.secubox.in;\n  server_name\n    a.*\n    b.gk2.secubox.in;\n}\n")
    assert _noms_gk2(f) == ["b.gk2.secubox.in"]
