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


# ── 3. Domaine des adresses ≠ domaine des noms de service ────────────────

def test_le_domaine_des_adresses_vient_de_ce_qui_est_servi(tmp_path, monkeypatch):
    """Sur gk2, le déclaratif dit `gk2.secubox.in` et Postfix sert
    `secubox.in`. Les adresses annoncées sous le premier n'existent pas.

    On lit donc `vmailbox`, la table des boîtes réelles."""
    from api import main

    cfg = tmp_path / "config"
    cfg.mkdir()
    (cfg / "vmailbox").write_text("gk2@secubox.in secubox.in/gk2/Maildir/\n")
    monkeypatch.setattr(main, "DATA_PATH", tmp_path)
    monkeypatch.setattr(main, "DOMAIN", "gk2.secubox.in")
    assert main._domaine_des_adresses() == "secubox.in"


def test_sans_table_lisible_on_retombe_sur_le_declare(tmp_path, monkeypatch):
    # Mieux vaut une valeur discutable qu'une page vide : l'absence de table
    # ne doit ni lever ni rendre une chaîne creuse.
    from api import main

    monkeypatch.setattr(main, "DATA_PATH", tmp_path / "absent")
    monkeypatch.setattr(main, "DOMAIN", "gk2.secubox.in")
    assert main._domaine_des_adresses() == "gk2.secubox.in"


def test_les_commentaires_de_la_table_sont_ignores(tmp_path, monkeypatch):
    # Une table commentée en tête ferait sinon dériver le domaine vers ce que
    # dit un commentaire — donc vers n'importe quoi.
    from api import main

    cfg = tmp_path / "config"
    cfg.mkdir()
    (cfg / "vmailbox").write_text(
        "# ancien@exemple.invalid ne doit pas compter\n"
        "\n"
        "gk2@secubox.in secubox.in/gk2/Maildir/\n")
    monkeypatch.setattr(main, "DATA_PATH", tmp_path)
    monkeypatch.setattr(main, "DOMAIN", "gk2.secubox.in")
    assert main._domaine_des_adresses() == "secubox.in"


def test_l_autoconfiguration_annonce_le_domaine_des_adresses():
    """Thunderbird cherche la fiche par le domaine de l'adresse saisie :
    annoncer le domaine de service la rend introuvable, donc inutile."""
    source = (RACINE / "api" / "main.py").read_text()
    assert '<emailProvider id="{MAIL_DOMAIN}">' in source
    assert '<domain>{MAIL_DOMAIN}</domain>' in source
    assert '<emailProvider id="{DOMAIN}">' not in source


def test_roundcube_recoit_un_username_domain():
    """Sans lui, saisir « gk2 » envoie « gk2 » à Dovecot, qui ne connaît que
    « gk2@secubox.in » — la connexion échoue et le webmail paraît cassé."""
    install = (RACINE / "lib" / "mail" / "install.sh").read_text()
    assert "username_domain" in install, \
        "le gabarit Roundcube ne pose pas username_domain"
    mailctl = (RACINE / "sbin" / "mailctl").read_text()
    assert "webmail-config)" in mailctl, \
        "aucun verbe ne reconcilie un conteneur deja installe"
