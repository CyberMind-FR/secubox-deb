# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: secubox-mail — le panneau mutilé, et le lien qui ment (#1014).

Deux défauts signalés ensemble par l'utilisateur : « le lien dans la webui
admin du mail est localhost, le webui est incomplet ou non fonctionnel ».

Ils n'avaient qu'un point commun — être passés inaperçus parce que la page
affichait quelque chose plutôt que rien.
"""

import pathlib

RACINE = pathlib.Path(__file__).resolve().parents[2]

PANNEAU = RACINE / "www" / "mail" / "index.html"


# ── 1. Le panneau mutilé par une permission ───────────────────────────────

def test_un_repertoire_illisible_ne_fait_pas_tomber_la_sonde(tmp_path, monkeypatch):
    """LE CAS RELEVÉ SUR GK2, à l'identique.

    `/data/lxc/mail` est en `drwxrwx--- 100000:100000` : la racine mappée du
    conteneur. Le panneau tourne sous `secubox` et ne peut pas y entrer. Un
    `stat` sur `<conteneur>/rootfs` y lève `PermissionError` — et comme rien
    ne la rattrapait, l'exception remontait jusqu'à faire tomber l'endpoint
    `/status` ENTIER, qui est la source principale de la page.

    Ce n'était pas un cas limite mais le cas nominal.
    """
    from api import main

    lxc = tmp_path / "lxc"
    (lxc / "mail" / "rootfs").mkdir(parents=True)
    # 0o000 : ni lecture ni traversée, comme un conteneur non privilégié vu
    # depuis le compte du panneau.
    (lxc / "mail").chmod(0o000)
    monkeypatch.setattr(main, "LXC_PATH", lxc)
    try:
        assert main.lxc_exists("mail") is True, \
            "un conteneur installé mais non traversable est rendu absent"
    finally:
        (lxc / "mail").chmod(0o755)


def test_un_conteneur_absent_est_bien_rendu_absent(tmp_path, monkeypatch):
    # La garde ne doit pas répondre « installé » à tout : sans elle, le
    # panneau annoncerait un serveur mail sur une board qui n'en a pas.
    from api import main

    lxc = tmp_path / "lxc"
    lxc.mkdir()
    monkeypatch.setattr(main, "LXC_PATH", lxc)
    assert main.lxc_exists("mail") is False


def test_la_sonde_ne_leve_jamais(tmp_path, monkeypatch):
    # Savoir si un conteneur est installé ne vaut jamais de perdre le reste de
    # la page : aucune erreur système ne doit pouvoir remonter d'ici.
    from api import main

    monkeypatch.setattr(main, "LXC_PATH", tmp_path / "chemin" / "inexistant")
    assert main.lxc_exists("mail") is False


# ── 2. Le lien qui affichait une adresse et en visitait une autre ─────────

def test_l_api_n_annonce_jamais_localhost():
    """`localhost` est consommé par le NAVIGATEUR de l'opérateur.

    Il y désigne la machine de l'opérateur, jamais la board : cette valeur ne
    peut structurellement jamais convenir.
    """
    source = (RACINE / "api" / "main.py").read_text()
    corps = "\n".join(l for l in source.splitlines()
                      if not l.lstrip().startswith("#"))
    assert '"local_url": f"http://localhost:' not in corps, \
        "l'API annonce encore localhost comme adresse de webmail"


def test_le_lien_webmail_mene_ou_il_dit():
    """Le défaut exact signalé : le lien AFFICHAIT l'adresse publique et
    NAVIGUAIT vers `local_url`. On lit une adresse, on en visite une autre —
    et rien ne signale l'écart, puisque le texte est correct."""
    html = PANNEAU.read_text()
    assert "document.getElementById('webmail-url').href = webmailUrl;" in html, \
        "le lien webmail ne pointe pas sur l'adresse qu'il affiche"
    assert "webmail-url').href = d.webmail?.local_url" not in html, \
        "le lien webmail navigue encore vers l'adresse locale"


def test_les_deux_liens_partagent_LA_MEME_adresse():
    # Deux calculs séparés pour la même destination finissent par diverger —
    # c'est ainsi que l'un des deux s'est mis à pointer sur localhost.
    html = PANNEAU.read_text()
    # On compte les AFFECTATIONS de lien, pas la declaration de la variable —
    # sans quoi le `const` la ferait passer a trois et le test mentirait.
    assert html.count(".href = webmailUrl;") == 2, \
        "les deux liens webmail ne partagent plus le même calcul"
