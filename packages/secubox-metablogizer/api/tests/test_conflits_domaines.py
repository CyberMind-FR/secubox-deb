# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: metablogizer — les conflits de `server_name` (#1016).

Sept `conflicting server name ... ignored` au chargement de nginx sur gk2.

Le mal n'est pas le doublon : c'est qu'il est **muet**. nginx garde le premier
bloc charge — donc, en pratique, l'ordre alphabetique des noms de fichiers — et
ignore le reste sans rien dire. Le panneau affichait deux sites publies alors
qu'un seul repondait, exactement comme en #1012 ou l'interface affirmait le bon
domaine pendant que nginx en portait un autre.

Et ce hasard portait a consequence : `ganimed.fr.conf`, maintenu a la main,
contient le point ACME et la redirection `www` que le bloc genere n'a pas. Il ne
l'emporte que parce que « g » vient avant « m ».
"""

import pathlib
import re

RACINE = pathlib.Path(__file__).resolve().parents[2]


def prepare(monkeypatch, tmp_path, sites, autres_vhosts=None):
    """Monte un faux /etc/nginx/sites-enabled et un jeu de sites."""
    from api import main

    enabled = tmp_path / "sites-enabled"
    enabled.mkdir()
    for nom, contenu in (autres_vhosts or {}).items():
        (enabled / nom).write_text(contenu)

    monkeypatch.setattr(main, "NGINX_ENABLED_DIR", enabled)
    monkeypatch.setattr(main, "NGINX_METABLOGS_CONF", enabled / "metablogizer")
    monkeypatch.setattr(main, "load_sites", lambda: sites)
    monkeypatch.setattr(main, "_invalidate_sites_cache", lambda: None)
    monkeypatch.setattr(main, "run_cmd", lambda *a, **k: (True, "", ""))
    return main, enabled


def site(tmp_path, nom, domaine):
    d = tmp_path / "sites" / nom
    (d / "public").mkdir(parents=True)
    (d / "public" / "index.html").write_text("<html><body>x</body></html>")
    return {"name": nom, "domain": domaine, "directory": str(d), "size": "4.0K"}


def noms_emis(conf):
    return re.findall(r"^\s*server_name\s+([^;]+);", conf.read_text(), re.M)


def test_un_domaine_deja_servi_ailleurs_n_est_pas_redeclare(monkeypatch, tmp_path):
    """LE CAS DE `ganimed.fr`. Un fichier maintenu a la main porte une
    intention — ici le point ACME et la redirection `www`. Le bloc genere n'est
    qu'un defaut : il cede, explicitement, au lieu de dependre de l'ordre
    alphabetique des fichiers."""
    s = [site(tmp_path, "ganimed", "ganimed.fr")]
    main, enabled = prepare(monkeypatch, tmp_path, s, {
        "ganimed.fr.conf": "server {\n  server_name ganimed.fr;\n}\n"})
    ok, n, msg = main.regenerate_nginx_config()
    assert ok
    assert "ganimed.fr" not in noms_emis(enabled / "metablogizer")
    assert "ganimed.fr.conf" in msg, f"l'ecart n'est pas dit : {msg}"


def test_deux_sites_sur_le_meme_domaine_n_en_emettent_qu_un(monkeypatch, tmp_path):
    # LE CAS DE `tdah` / `rtdah` et `zem` / `zemialos`.
    s = [site(tmp_path, "tdah", "tdah.gk2.secubox.in"),
         site(tmp_path, "rtdah", "tdah.gk2.secubox.in")]
    main, enabled = prepare(monkeypatch, tmp_path, s)
    ok, n, msg = main.regenerate_nginx_config()
    assert ok
    assert noms_emis(enabled / "metablogizer").count("tdah.gk2.secubox.in") == 1
    assert n == 1, f"compte publie faux : {n}"


def test_l_ecart_est_DIT_jamais_avale(monkeypatch, tmp_path):
    # LA REGLE QUI COMPTE. Un doublon signale se corrige ; un doublon muet ne
    # se voit jamais. C'est exactement ce que nginx faisait.
    s = [site(tmp_path, "zem", "zem.gk2.secubox.in"),
         site(tmp_path, "zemialos", "zem.gk2.secubox.in")]
    main, enabled = prepare(monkeypatch, tmp_path, s)
    ok, n, msg = main.regenerate_nginx_config()
    assert "ecarte" in msg, f"aucun ecart signale : {msg}"
    assert "zemialos" in msg


def test_les_sites_sans_conflit_sont_tous_emis(monkeypatch, tmp_path):
    # La garde ne doit pas manger ce qui va bien : sur gk2 elle s'applique a 7
    # domaines sur 171.
    s = [site(tmp_path, f"s{i}", f"s{i}.gk2.secubox.in") for i in range(5)]
    main, enabled = prepare(monkeypatch, tmp_path, s)
    ok, n, msg = main.regenerate_nginx_config()
    assert n == 5
    assert len(noms_emis(enabled / "metablogizer")) == 5


def test_le_fichier_genere_ne_se_compare_pas_a_lui_meme(monkeypatch, tmp_path):
    """Sans cette exclusion, le SECOND passage verrait ses propres blocs comme
    « deja servis ailleurs » et effacerait tout le site — une regeneration
    idempotente deviendrait une suppression."""
    s = [site(tmp_path, "a", "a.gk2.secubox.in")]
    main, enabled = prepare(monkeypatch, tmp_path, s)
    main.regenerate_nginx_config()
    ok, n, msg = main.regenerate_nginx_config()
    assert n == 1, f"le deuxieme passage a efface le site : {msg}"
    assert "a.gk2.secubox.in" in noms_emis(enabled / "metablogizer")


def test_un_repertoire_illisible_ne_casse_pas_la_generation(monkeypatch, tmp_path):
    # Le pire cas doit rester le comportement d'avant, pas une page blanche.
    from api import main

    monkeypatch.setattr(main, "NGINX_ENABLED_DIR", tmp_path / "inexistant")
    assert main.domaines_deja_servis() == {}


# ── A egalite, l'intention l'emporte sur le defaut ────────────────────────

def test_un_domaine_declare_l_emporte_sur_un_domaine_herite(monkeypatch, tmp_path):
    """LE CAS DE `zem` / `zemialos`.

    `zemialos` ECRIT `zem.gk2.secubox.in` dans son site.json et porte un
    index.html ; `zem` ne fait qu'HERITER du nom de son repertoire et n'a pas
    d'index. C'est pourtant `zem` qui gagnait — par ordre de scan — et le
    domaine repondait 403.

    Un domaine ecrit est une intention ; un domaine herite n'est qu'un defaut.
    """
    import json

    from api import main

    zem = tmp_path / "sites" / "zem"
    (zem / "public").mkdir(parents=True)
    zemialos = tmp_path / "sites" / "zemialos"
    (zemialos / "public").mkdir(parents=True)
    (zemialos / "public" / "index.html").write_text("<html>zemialos</html>")
    (zemialos / "site.json").write_text(json.dumps({"domain": "zem.gk2.secubox.in"}))

    s = [{"name": "zem", "domain": "zem.gk2.secubox.in",
          "directory": str(zem), "size": "4.0K"},
         {"name": "zemialos", "domain": "zem.gk2.secubox.in",
          "directory": str(zemialos), "size": "1.1M"}]
    main, enabled = prepare(monkeypatch, tmp_path, s)
    ok, n, msg = main.regenerate_nginx_config()
    assert ok
    conf = (enabled / "metablogizer").read_text()
    assert "zemialos" in conf, "le site qui DECLARE le domaine a ete ecarte"
    assert "zem (zem.gk2.secubox.in)" in msg, f"l'ecart n'est pas dit : {msg}"


def test_deux_declarations_egales_restent_signalees(monkeypatch, tmp_path):
    """LE CAS DE `tdah` / `rtdah` : les deux ECRIVENT le meme domaine.

    C'est une vraie egalite — le choix appartient a l'operateur. Le code ne
    doit pas la trancher en douce, seulement la rendre visible.
    """
    import json

    from api import main

    s = []
    for nom in ("tdah", "rtdah"):
        d = tmp_path / "sites" / nom
        (d / "public").mkdir(parents=True)
        (d / "public" / "index.html").write_text("<html>x</html>")
        (d / "site.json").write_text(json.dumps({"domain": "tdah.gk2.secubox.in"}))
        s.append({"name": nom, "domain": "tdah.gk2.secubox.in",
                  "directory": str(d), "size": "2.9M"})
    main, enabled = prepare(monkeypatch, tmp_path, s)
    ok, n, msg = main.regenerate_nginx_config()
    assert n == 1
    assert "ecarte" in msg and "tdah" in msg
