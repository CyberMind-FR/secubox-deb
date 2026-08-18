# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Le générateur doit émettre lui-même le routage ACME HTTP-01 (#986).

Avant ce correctif, l'ACL `is_acme_challenge`, sa règle `use_backend` et le
backend `acme_challenge` n'existaient QUE dans le `haproxy.cfg` vivant de la
board, ajoutés à la main. Conséquences enchaînées, toutes observées :

  - Une régénération réussie les aurait supprimés en silence. Le symptôme ne
    serait apparu qu'au renouvellement suivant des certificats, des semaines
    plus tard, sous la forme d'une expiration — le pire délai de détection
    possible.
  - C'est précisément pour ça que la garde anti-dérive (#626) refusait de
    régénérer : le vivant contenait un backend absent des sources. Elle a
    fonctionné, mais son effet de bord est que **toute** modification
    déclarative de `haproxy.toml` est restée inerte pendant six jours sans que
    rien n'échoue bruyamment.

Ces tests lisent le script livré plutôt que d'exécuter `generate` : celui-ci
exige un binaire haproxy pour sa validation `-c`, un socket d'état et une
arborescence /etc complète. Ce qui doit être verrouillé ici est le contenu que
le générateur ÉMET, et il est lisible statiquement.
"""
import re
from pathlib import Path

CTL = Path(__file__).resolve().parents[1] / "sbin" / "haproxyctl"


def _src() -> str:
    return CTL.read_text(encoding="utf-8")


def test_generator_emits_the_acme_acl_and_route():
    src = _src()
    assert "acl is_acme_challenge path_beg /.well-known/acme-challenge/" in src, (
        "l'ACL du défi ACME doit être émise par le générateur, pas ajoutée à la main"
    )
    assert "use_backend acme_challenge if is_acme_challenge" in src


def test_generator_emits_the_acme_backend():
    """Une règle `use_backend` sans backend correspondant rend la configuration
    invalide : `haproxy -c` la rejette et la génération échoue entièrement.
    Les deux moitiés doivent donc voyager ensemble."""
    src = _src()
    assert re.search(r"^backend acme_challenge$", src, re.M), (
        "le backend acme_challenge doit être émis avec la règle qui le référence"
    )
    assert "server acme1 127.0.0.1:${acme_port}" in src


def test_acme_route_precedes_the_vhost_rules():
    """L'ordre est la substance du correctif, pas un détail de style.

    Un défi ACME arrive sur le domaine du certificat demandé. Si une règle de
    vhost pour ce même domaine est évaluée d'abord, elle capte le défi et
    l'envoie au service applicatif, qui répond 404 — le renouvellement échoue
    alors que le routage a l'air correct."""
    src = _src()
    acme = src.index("use_backend acme_challenge if is_acme_challenge")
    vhost_loop = src.index("# Add ACLs and use_backend rules for vhosts")
    assert acme < vhost_loop, (
        "le routage ACME doit être émis AVANT la boucle des vhosts, sinon un "
        "vhost homonyme capte le défi"
    )


def test_acme_port_is_configurable_with_a_default():
    """Le port n'est pas figé : il est lu dans haproxy.toml, avec 8880 comme
    valeur par défaut — celle qui était câblée à la main sur la board, pour que
    la génération reproduise l'existant sans configuration supplémentaire."""
    src = _src()
    assert "acme_port" in src
    assert "acme_port=8880" in src.replace(" ", "")


# ─────────────────────────────────────────────────────────────────────
# ssl_redirect (#988) — declare partout, lu nulle part jusqu'ici
# ─────────────────────────────────────────────────────────────────────

def test_generator_reads_ssl_redirect():
    """`vhost add` ecrivait `ssl_redirect = true` dans chaque bloc et le
    generateur ne l'a jamais lu : 18 vhosts le declaraient, zero redirection
    etait produite. Un operateur relisant haproxy.toml croyait legitimement
    que ses vhosts redirigeaient."""
    src = _src()
    assert "redirect scheme https code 301" in src, (
        "le generateur doit emettre la redirection que ssl_redirect declare"
    )
    assert "grep -E '^ssl_redirect" in src, (
        "ssl_redirect doit etre LU depuis la section du vhost, pas seulement ecrit"
    )


def test_ssl_redirect_never_captures_acme_challenges():
    """L'exclusion la plus importante du fichier.

    HAProxy evalue les regles `redirect` AVANT `use_backend`. Sans
    `!is_acme_challenge`, la redirection prendrait le pas sur le routage ACME
    emis en tete de frontend : les defis Let's Encrypt partiraient en HTTPS et
    le renouvellement echouerait — la panne meme que #986 vient de reparer,
    reintroduite par la porte d'a cote."""
    src = _src()
    line = [l for l in src.splitlines() if "redirect scheme https code 301" in l]
    assert line, "regle de redirection absente"
    for l in line:
        assert "!is_acme_challenge" in l, (
            "la redirection doit exclure les defis ACME : " + l.strip()
        )


def test_ssl_redirect_requires_ssl():
    """Rediriger vers HTTPS un vhost sans certificat enverrait le visiteur sur
    une page injoignable. La condition porte sur les deux drapeaux."""
    src = _src()
    i = src.index("redirect scheme https code 301")
    window = src[max(0, i - 400):i]
    assert '"$ssl_redirect" = "1"' in window and '"$ssl" = "1"' in window, (
        "la redirection doit exiger ssl ET ssl_redirect"
    )
