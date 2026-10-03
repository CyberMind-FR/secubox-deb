# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""SecuBox-Deb :: haproxyctl generate — tests de non-regression bout en bout.

On EXECUTE reellement `haproxyctl generate` sur un haproxy.toml temoin, avec un
faux binaire `haproxy` qui valide tout, et l'on regarde ce qui sort — le cfg ET
le flux d'erreur. Les deux pannes couvertes ici etaient invisibles a une simple
relecture du script :

1. Les commentaires francais du generateur citent la configuration entre
   accents graves. Emis dans un heredoc NON QUOTE, ces accents etaient des
   substitutions de commandes : bash executait `defaults`, `set-timeout`,
   `timeout server 30s`... l'operateur voyait une volee de « command not found »
   et croyait `generate` casse, et les commentaires sortaient eventres.
2. L'extraction d'une table TOML retranchait sa derniere ligne. Pour la
   DERNIERE table du fichier, cette ligne n'etait pas l'en-tete suivant mais
   une vraie directive : le dernier backend sortait sans un seul serveur.
"""
import os
import shutil
import subprocess
from pathlib import Path

import pytest

CTL = Path(__file__).resolve().parents[1] / "sbin" / "haproxyctl"

TOML_TEMOIN = """\
mode = "native"
http_port = 80
https_port = 443
stats_port = 8404
waf_enabled = true
waf_backend_ip = "127.0.0.1"
waf_backend_port = 8085

[vhosts.hall]
domain = "hall.gk2.secubox.in"
backend = "nginx_vhosts"
enabled = true
ssl = true
cadrable = true

# DERNIERE table du fichier : c'est elle que l'ancienne extraction decapitait.
[backends.metablog]
mode = "http"
balance = "roundrobin"
servers = ["127.0.0.1:9091", "127.0.0.1:9092"]
"""


@pytest.fixture(scope="module")
def generation(tmp_path_factory):
    """Lance `haproxyctl generate` et rend (cfg genere, stdout, stderr)."""
    if not shutil.which("bash"):
        pytest.skip("bash absent")
    base = tmp_path_factory.mktemp("haproxyctl")
    (base / "conf").mkdir()
    (base / "cfg").mkdir()
    (base / "cfgd").mkdir()
    (base / "bin").mkdir()

    toml = base / "conf" / "haproxy.toml"
    toml.write_text(TOML_TEMOIN, encoding="utf-8")

    # `haproxy -c` valide tout : on teste le GENERATEUR, pas HAProxy, et le
    # binaire n'est pas installe sur une machine de developpement.
    faux = base / "bin" / "haproxy"
    faux.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    faux.chmod(0o755)

    env = dict(os.environ)
    env.update(
        PATH=f"{base / 'bin'}{os.pathsep}{env.get('PATH', '')}",
        SECUBOX_HAPROXY_CONF=str(toml),
        SECUBOX_HAPROXY_CONFIG_DIR=str(base / "cfg"),
        HAPROXY_DATA_PATH=str(base / "data"),
        HAPROXY_EXTRA_CFG_DIR=str(base / "cfgd"),
    )
    p = subprocess.run(
        ["bash", str(CTL), "generate"],
        env=env, capture_output=True, text=True, timeout=120,
    )
    assert p.returncode == 0, f"generate a echoue :\n{p.stdout}\n{p.stderr}"
    cfg = (base / "cfg" / "haproxy.cfg").read_text(encoding="utf-8")
    return cfg, p.stdout, p.stderr


def test_generate_n_emet_aucune_erreur_bash(generation):
    """Le flux d'erreur doit etre vierge de diagnostics bash.

    « command not found » / « syntax error » sur stderr, c'est bash qui execute
    un morceau de commentaire, pas HAProxy qui se plaint."""
    _, _, err = generation
    for bruit in ("command not found", "syntax error", "unexpected end of file"):
        assert bruit not in err, f"erreur bash pendant generate : {err}"


def test_les_commentaires_gardent_leurs_accents_graves(generation):
    """Les citations de directives doivent arriver INTACTES dans le cfg.

    Elles etaient interpretees comme des substitutions de commandes : le texte
    entre accents disparaissait, et le commentaire devenait incomprehensible
    (« La section  porte , et c'est bien »)."""
    cfg, _, _ = generation
    for cite in ("`$scheme`", "`set-header`", "`defaults`", "`set-timeout client`"):
        assert cite in cfg, f"citation mangee par le heredoc : {cite}"


def test_la_derniere_table_toml_garde_sa_derniere_ligne(generation):
    """Le dernier backend declare doit sortir AVEC ses serveurs.

    Un backend sans serveur repond 503 sur tout son trafic — la panne etait
    silencieuse, le cfg restant parfaitement valide pour `haproxy -c`."""
    cfg, _, _ = generation
    corps = cfg.split("backend metablog", 1)
    assert len(corps) == 2, "backend metablog absent du cfg genere"
    bloc = corps[1].split("\nbackend ", 1)[0]
    assert "server srv0 127.0.0.1:9091 check" in bloc
    assert "server srv1 127.0.0.1:9092 check" in bloc


def test_le_vhost_est_route_vers_l_inspection(generation):
    """Garde-fou de charte : waf_enabled sans waf_bypass ⇒ sbxwaf_inspector."""
    cfg, _, _ = generation
    assert "use_backend sbxwaf_inspector if host_hall" in cfg


# ── VoiceStudio (#1917) : des délais LONGS, et seulement pour lui ─────────────────────────────────────────────────
def _backend_inspecteur(cfg: str) -> str:
    debut = cfg.index("\nbackend sbxwaf_inspector")        # en début de ligne : « use_backend sbxwaf_inspector » en contient aussi
    return cfg[debut:cfg.index("\nbackend ", debut + 10)]


def test_la_synthese_vocale_n_est_plus_coupee_a_30_secondes(generation):
    """Vu en production : « Synthèse : HTTP 504 » — HAProxy abandonnait à 30 s, le moteur continuait de travailler."""
    bloc = _backend_inspecteur(generation[0])
    assert "acl est_voix_longue path_beg /api/v1/voicestudio/essai/ /api/v1/voicestudio/usager/dire /api/v1/voicestudio/usager/transcrire" in bloc
    assert "http-request set-timeout server 10m if est_voix_longue" in bloc


def test_le_domaine_du_studio_natif_a_un_delai_d_une_heure(generation):
    bloc = _backend_inspecteur(generation[0])
    assert "acl est_studio_natif hdr_beg(host) -i voicestudio." in bloc
    assert "http-request set-timeout server 1h if est_studio_natif" in bloc


def test_les_delais_longs_restent_des_exceptions_les_30_secondes_protegent_le_reste(generation):
    cfg, _, _ = generation
    assert "timeout server 30s" in cfg                                           # la protection générale est intacte
    bloc = _backend_inspecteur(cfg)
    # exactement trois exceptions : dépôts de fichiers, voix, studio — rien de plus
    assert bloc.count("set-timeout server") == 3
    for interdit in ("path_beg /api/v1/ ", "path_beg / ", "hdr_beg(host) -i hall", "hdr_beg(host) -i admin"):
        assert interdit not in bloc


def test_les_commentaires_voicestudio_n_ont_pas_ete_executes_par_bash(generation):
    """Les commentaires du générateur sont dans un heredoc non quoté : un accent grave y deviendrait une commande."""
    cfg, _, err = generation
    assert "command not found" not in err
    assert "VOIX ET STUDIO (VoiceStudio, #1917)" in cfg and "Chemins et prefixe de domaine EXACTS" in cfg


def test_le_backend_nginx_direct_porte_aussi_le_delai_du_studio_natif(generation):
    """Acces LAN direct a la box (sans WAF) : meme heure de delai, sinon le studio reste coupe a 30 s."""
    cfg = generation[0]
    debut = cfg.index("\nbackend nginx_vhosts")
    bloc = cfg[debut:cfg.index("\nbackend ", debut + 10) if "\nbackend " in cfg[debut + 10:] else len(cfg)]
    assert "acl est_studio_natif hdr_beg(host) -i voicestudio." in bloc and "set-timeout server 1h if est_studio_natif" in bloc
    assert bloc.count("set-timeout server") == 1
