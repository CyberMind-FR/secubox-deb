# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Tests de scripts/verifie-relais-hall.py — le gabarit des relais du Hall
(#1609, #1608).

Deux familles : le vhost du dépôt doit passer (c'est la règle vivante), et
chaque règle doit échouer sur un cas construit exprès (sans quoi un
vérificateur qui ne regarde rien passerait aussi).
"""

from __future__ import annotations

import importlib.util
import shutil
import sys
import textwrap
from pathlib import Path

import pytest

_SCRIPT = Path(__file__).resolve().parents[1] / "verifie-relais-hall.py"
_spec = importlib.util.spec_from_file_location("verifie_relais_hall", _SCRIPT)
assert _spec and _spec.loader
vrh = importlib.util.module_from_spec(_spec)
sys.modules["verifie_relais_hall"] = vrh
_spec.loader.exec_module(vrh)

RACINE = Path(__file__).resolve().parents[2]
VHOST = RACINE / "packages" / "secubox-webos" / "nginx" / "hall.vhost.conf"

# En-têtes d'origine du gabarit, à coller dans les cas construits.
ORIGINE = """
        proxy_set_header X-SecuBox-LAN   $lan_client;
        proxy_set_header X-Real-IP       $remote_addr;
        proxy_set_header X-Forwarded-For $remote_addr;
"""


REPLI_API = """
location /api/ {
    return 404;
}"""


def serveur(*locations: str, niveau_serveur: str = "", repli: str = REPLI_API) -> str:
    corps = "\n".join(textwrap.dedent(l) for l in locations + (repli,))
    return f"server {{\n    listen 9080;\n{niveau_serveur}\n{corps}\n}}\n"


def constats(texte: str, tmp_path: Path, racine: Path = RACINE):
    f = tmp_path / "hall.conf"
    f.write_text(texte)
    _, c = vrh.analyse_fichier(f, racine)
    return c


def regles(liste) -> list:
    return sorted({c.regle for c in liste})


# ── Le vhost du dépôt ────────────────────────────────────────────────────────

def test_vhost_du_depot_suit_le_gabarit():
    tous, c = vrh.analyse_fichier(VHOST, RACINE)
    assert not c, "\n".join(f"{x.ligne} {x.location} [{x.regle}] {x.message}" for x in c)


def test_vhost_du_depot_a_bien_des_relais_a_verifier():
    """Un vérificateur qui ne reconnaît rien passe pour de mauvaises raisons."""
    tous, _ = vrh.analyse_fichier(VHOST, RACINE)
    assert len(tous) >= 25
    assert sum(1 for r in tous if r.lecture) >= 10
    modules = {vrh.module_de(r) for r in tous}
    assert {"actor", "dpi", "freeboxtv", "zigbee", "lyrion", "radio", "acces"} <= modules


def test_vhost_du_depot_relais_actor_exigent_la_session_sauf_stats():
    tous, _ = vrh.analyse_fichier(VHOST, RACINE)
    actor = [r for r in tous if vrh.module_de(r) == "actor"]
    assert actor
    for r in actor:
        assert r.entete("X-Sbx-Vue") == "reduite"
        a_session = any(True for _ in r.location.enfants("auth_request"))
        assert a_session == (r.motif != "/api/v1/actor/stats"), r.libelle()


@pytest.mark.parametrize("uri", [
    "/api/v1/actor/evidence/ACT-0040", "/api/v1/actor/feedback/ACT-0040",
    "/api/v1/zigbee/backups", "/api/v1/zigbee/access",
    "/api/v1/dpi/sessions", "/api/v1/lyrion/rescan",
])
def test_vhost_du_depot_ne_relaie_pas_les_chemins_d_administration(uri):
    tous, _ = vrh.analyse_fichier(VHOST, RACINE)
    assert not [r.libelle() for r in tous if not r.interne and vrh.correspond(r, uri)]


@pytest.mark.parametrize("uri", [
    "/api/v1/actor/stats", "/api/v1/actor/actors", "/api/v1/actor/actors/ACT-0040",
    "/api/v1/actor/campaigns", "/api/v1/dpi/stats", "/api/v1/dpi/clients",
    "/api/v1/freeboxtv/channels", "/api/v1/freeboxtv/hls/201/live.m3u8",
    "/api/v1/freeboxtv/hls/201/live12.ts", "/api/v1/zigbee/devices",
    "/api/v1/zigbee/devices/LIGHT-BIBLI/set", "/api/v1/lyrion/players",
    "/api/v1/lyrion/now-playing", "/api/v1/lyrion/player/aa:bb/action/play",
    "/api/v1/lyrion/player/aa:bb/volume",
])
def test_vhost_du_depot_relaie_les_chemins_des_cartes(uri):
    tous, _ = vrh.analyse_fichier(VHOST, RACINE)
    assert [r for r in tous if vrh.correspond(r, uri)], uri


# ── A : verdict LAN ──────────────────────────────────────────────────────────

def test_cas_conforme(tmp_path):
    texte = serveur(f"""
    location = /api/v1/demo/etat {{
        # relais: lecture
        limit_except GET {{ deny all; }}
        proxy_pass http://unix:/run/secubox/demo.sock:/etat;
        {ORIGINE}
        proxy_set_header Host $host;
    }}""")
    assert constats(texte, tmp_path) == []


def test_location_sans_verdict_lan(tmp_path):
    texte = serveur("""
    location /api/v1/demo/ {
        proxy_pass http://unix:/run/secubox/demo.sock:/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $remote_addr;
    }""")
    c = constats(texte, tmp_path)
    assert regles(c) == ["A"]
    assert "X-SecuBox-LAN" in c[0].message and c[0].location == "location /api/v1/demo/"


def test_verdict_du_serveur_non_herite_des_qu_un_entete_est_pose(tmp_path):
    """La règle de nginx : un seul proxy_set_header dans le location, et celui
    du serveur ne s'applique plus."""
    niveau = """    proxy_set_header X-SecuBox-LAN   $lan_client;
    proxy_set_header X-Real-IP       $remote_addr;
    proxy_set_header X-Forwarded-For $remote_addr;"""
    perd = serveur("""
    location /api/v1/demo/ {
        proxy_pass http://unix:/run/secubox/demo.sock:/;
        proxy_set_header Host $host;
    }""", niveau_serveur=niveau)
    assert "A" in regles(constats(perd, tmp_path))
    herite = serveur("""
    location /api/v1/demo/ {
        proxy_pass http://unix:/run/secubox/demo.sock:/;
    }""", niveau_serveur=niveau)
    assert constats(herite, tmp_path) == []


def test_verdict_lan_recopie_du_client_refuse(tmp_path):
    texte = serveur("""
    location /api/v1/demo/ {
        proxy_pass http://unix:/run/secubox/demo.sock:/;
        proxy_set_header X-SecuBox-LAN   $http_x_secubox_lan;
        proxy_set_header X-Real-IP       $remote_addr;
        proxy_set_header X-Forwarded-For $remote_addr;
    }""")
    assert regles(constats(texte, tmp_path)) == ["A"]


def test_location_interne_de_verification_suit_aussi_le_gabarit(tmp_path):
    texte = serveur("""
    location = /__verif {
        internal;
        proxy_pass http://unix:/run/secubox/aggregator.sock:/api/v1/auth/auth/verify;
    }""")
    assert "A" in regles(constats(texte, tmp_path))


def test_snippet_du_depot_ne_suffit_pas(tmp_path):
    """secubox-proxy.conf du dépôt ne porte pas la ligne du verdict (le postinst
    de secubox-core l'ajoute, sous condition) et ajoute l'adresse à la chaîne
    du client : un relais du Hall ne peut pas s'en remettre à lui."""
    texte = serveur("""
    location = /api/v1/demo/etat {
        proxy_pass http://unix:/run/secubox/demo.sock:/etat;
        include /etc/nginx/snippets/secubox-proxy.conf;
    }""")
    c = constats(texte, tmp_path)
    assert "A" in regles(c)
    assert any("X-Forwarded-For" in x.message for x in c)


def test_snippet_relu_compte_pour_ses_entetes(tmp_path):
    racine = tmp_path / "depot"
    (racine / "common" / "nginx").mkdir(parents=True)
    (racine / "common" / "nginx" / "secubox-proxy.conf").write_text(ORIGINE)
    texte = serveur("""
    location = /api/v1/demo/etat {
        proxy_pass http://unix:/run/secubox/demo.sock:/etat;
        include /etc/nginx/snippets/secubox-proxy.conf;
    }""")
    assert constats(texte, tmp_path, racine=racine) == []


def test_include_inconnu_ne_compte_pour_rien(tmp_path):
    texte = serveur(f"""
    location = /api/v1/demo/etat {{
        proxy_pass http://unix:/run/secubox/demo.sock:/etat;
        {ORIGINE}
        include /etc/nginx/snippets/autre-chose.conf;
    }}""")
    c = constats(texte, tmp_path)
    assert regles(c) == ["A"] and "autre-chose.conf" in c[0].message


# ── B : en-têtes de confiance ────────────────────────────────────────────────

def test_adresse_du_client_ajoutee_a_la_chaine_refusee(tmp_path):
    texte = serveur("""
    location /api/v1/demo/ {
        proxy_pass http://unix:/run/secubox/demo.sock:/;
        proxy_set_header X-SecuBox-LAN   $lan_client;
        proxy_set_header X-Real-IP       $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }""")
    c = constats(texte, tmp_path)
    assert regles(c) == ["B"] and "X-Forwarded-For" in c[0].message


def test_identite_radio_non_videe(tmp_path):
    texte = serveur(f"""
    location ~ ^/api/v1/radio/(current|chat)$ {{
        rewrite ^ $uri break;  proxy_pass http://unix:/run/secubox/radio.sock;
        {ORIGINE}
        proxy_set_header X-Sbx-User-Id "";
    }}""")
    c = constats(texte, tmp_path)
    assert regles(c) == ["B"]
    assert {m for x in c for m in ("X-Sbx-User", "X-Sbx-Role") if m in x.message} == {
        "X-Sbx-User", "X-Sbx-Role"}


def test_identite_radio_videe_conforme(tmp_path):
    texte = serveur(f"""
    location ~ ^/api/v1/radio/(current|chat)$ {{
        rewrite ^ $uri break;  proxy_pass http://unix:/run/secubox/radio.sock;
        {ORIGINE}
        proxy_set_header X-Sbx-User-Id "";
        proxy_set_header X-Sbx-User    "";
        proxy_set_header X-Sbx-Role    "";
    }}""")
    assert constats(texte, tmp_path) == []


def test_identite_posee_depuis_la_session_admise(tmp_path):
    """Posée après auth_request (variable serveur) : c'est le relais qui parle."""
    texte = serveur(f"""
    location = /api/v1/bbs/sbx/auto {{
        auth_request /__verif;
        auth_request_set $membre $upstream_http_remote_user;
        rewrite ^ $uri break;  proxy_pass http://unix:/run/secubox/bbs.sock;
        {ORIGINE}
        proxy_set_header X-Sbx-Membre     $membre;
        proxy_set_header X-Sbx-Compte-Bbs "";
        proxy_set_header X-Sbx-Profil     "";
    }}""")
    assert constats(texte, tmp_path) == []


def test_vue_actor_absente_ou_choisie_par_le_client(tmp_path):
    base = """
    location = /api/v1/actor/stats {{
        rewrite ^ $uri break;  proxy_pass http://unix:/run/secubox/actor.sock;
        {origine}
        {vue}
    }}"""
    sans = serveur(base.format(origine=ORIGINE, vue=""))
    assert regles(constats(sans, tmp_path)) == ["B"]
    client = serveur(base.format(origine=ORIGINE,
                                 vue="proxy_set_header X-Sbx-Vue $http_x_sbx_vue;"))
    assert regles(constats(client, tmp_path)) == ["B"]
    bonne = serveur(base.format(origine=ORIGINE, vue="proxy_set_header X-Sbx-Vue reduite;"))
    assert constats(bonne, tmp_path) == []


def test_module_de_l_agregateur_reconnu_par_son_chemin(tmp_path):
    texte = serveur(f"""
    location /api/v1/acces/session/ {{
        proxy_pass http://unix:/run/secubox/aggregator.sock:/api/v1/acces/session/;
        {ORIGINE}
    }}""")
    c = constats(texte, tmp_path)
    assert regles(c) == ["B"]
    assert all("« acces »" in x.message for x in c)


def test_module_derriere_nginx_local_reconnu_par_son_hote(tmp_path):
    texte = serveur(f"""
    location ~ ^/pt/(client)(/|$) {{
        rewrite ^ $uri break;  proxy_pass http://nginx_local;
        proxy_set_header Host peertube.gk2.secubox.in;
        {ORIGINE}
    }}""")
    c = constats(texte, tmp_path)
    assert regles(c) == ["B"] and "X-Sbx-Peertube-User" in c[0].message


# ── C : relais de lecture ────────────────────────────────────────────────────

def test_relais_lecture_par_prefixe(tmp_path):
    texte = serveur(f"""
    location /api/v1/demo/ {{
        # relais: lecture
        limit_except GET {{ deny all; }}
        proxy_pass http://unix:/run/secubox/demo.sock:/;
        {ORIGINE}
    }}""")
    c = constats(texte, tmp_path)
    assert regles(c) == ["C"] and "préfixe" in c[0].message


def test_relais_lecture_sans_limit_except(tmp_path):
    texte = serveur(f"""
    location = /api/v1/demo/etat {{
        # relais: lecture
        proxy_pass http://unix:/run/secubox/demo.sock:/etat;
        {ORIGINE}
    }}""")
    c = constats(texte, tmp_path)
    assert regles(c) == ["C"] and "limit_except" in c[0].message


def test_relais_lecture_qui_admet_une_ecriture(tmp_path):
    texte = serveur(f"""
    location = /api/v1/demo/etat {{
        # relais: lecture
        limit_except GET POST {{ deny all; }}
        proxy_pass http://unix:/run/secubox/demo.sock:/etat;
        {ORIGINE}
    }}""")
    assert regles(constats(texte, tmp_path)) == ["C"]


def test_relais_lecture_limit_except_sans_deny(tmp_path):
    texte = serveur(f"""
    location = /api/v1/demo/etat {{
        # relais: lecture
        limit_except GET {{ allow 192.168.1.0/24; }}
        proxy_pass http://unix:/run/secubox/demo.sock:/etat;
        {ORIGINE}
    }}""")
    c = constats(texte, tmp_path)
    assert regles(c) == ["C"] and "deny all" in c[0].message


@pytest.mark.parametrize("motif", [
    "^/api/v1/demo/(a|b)(/|$)",       # suffixe ouvert
    "^/api/v1/demo/.*$",              # joker
    "/api/v1/demo/(a|b)$",            # début non ancré
    "^/api/v1/demo/.+/etat$",         # joker entre segments
])
def test_relais_lecture_regex_non_ancree(tmp_path, motif):
    texte = serveur(f"""
    location ~ {motif} {{
        # relais: lecture
        limit_except GET {{ deny all; }}
        rewrite ^ $uri break;  proxy_pass http://unix:/run/secubox/demo.sock;
        {ORIGINE}
    }}""")
    assert regles(constats(texte, tmp_path)) == ["C"]


def test_relais_lecture_regex_ancree_conforme(tmp_path):
    texte = serveur(f"""
    location ~ ^/api/v1/demo/(a|b|objets/[A-Za-z0-9_-]+)$ {{
        # relais: lecture
        limit_except GET {{ deny all; }}
        rewrite ^/api/v1/demo/(.*)$ /$1 break;
        rewrite ^ $uri break;  proxy_pass http://unix:/run/secubox/demo.sock;
        {ORIGINE}
    }}""")
    assert constats(texte, tmp_path) == []


def test_relais_lecture_sans_adresse_reelle(tmp_path):
    texte = serveur("""
    location = /api/v1/demo/etat {
        # relais: lecture
        limit_except GET { deny all; }
        proxy_pass http://unix:/run/secubox/demo.sock:/etat;
        proxy_set_header X-SecuBox-LAN   $lan_client;
        proxy_set_header X-Real-IP       "";
        proxy_set_header X-Forwarded-For $remote_addr;
    }""")
    c = constats(texte, tmp_path)
    assert regles(c) == ["C"] and "X-Real-IP" in c[0].message


def test_marqueur_mal_orthographie(tmp_path):
    texte = serveur(f"""
    location = /api/v1/demo/etat {{
        # relais: lectrue
        proxy_pass http://unix:/run/secubox/demo.sock:/etat;
        {ORIGINE}
    }}""")
    c = constats(texte, tmp_path)
    assert regles(c) == ["C"] and "lectrue" in c[0].message


def test_marqueur_hors_du_bloc_ne_compte_pas(tmp_path):
    """Le marqueur vit DANS le bloc : au-dessus, il se confondrait avec les
    commentaires du location précédent."""
    texte = serveur(f"""
    # relais: lecture
    location /api/v1/demo/ {{
        proxy_pass http://unix:/run/secubox/demo.sock:/;
        {ORIGINE}
    }}""")
    tous, c = vrh.analyse_fichier(_ecrit(tmp_path, texte), RACINE)
    assert c == [] and not tous[0].lecture


# ── D : décisions du Hall ────────────────────────────────────────────────────

def test_verrou_lan_absent_sur_un_module_local(tmp_path):
    texte = serveur(f"""
    location = /api/v1/zigbee/devices {{
        proxy_pass http://unix:/run/secubox/zigbee.sock:/devices;
        {ORIGINE}
    }}""")
    c = constats(texte, tmp_path)
    assert regles(c) == ["D"] and "lan_client" in c[0].message


def test_verrou_lan_present(tmp_path):
    texte = serveur(f"""
    location = /api/v1/zigbee/devices {{
        if ($lan_client = 0) {{ return 403; }}
        proxy_pass http://unix:/run/secubox/zigbee.sock:/devices;
        {ORIGINE}
    }}""")
    assert constats(texte, tmp_path) == []


def test_actor_sans_session(tmp_path):
    texte = serveur(f"""
    location = /api/v1/actor/actors {{
        rewrite ^ $uri break;  proxy_pass http://unix:/run/secubox/actor.sock;
        {ORIGINE}
        proxy_set_header X-Sbx-Vue reduite;
    }}""")
    c = constats(texte, tmp_path)
    assert regles(c) == ["D"] and "auth_request" in c[0].message


def test_actor_session_vers_une_verification_inconnue(tmp_path):
    texte = serveur(f"""
    location = /api/v1/actor/actors {{
        auth_request /ailleurs;
        rewrite ^ $uri break;  proxy_pass http://unix:/run/secubox/actor.sock;
        {ORIGINE}
        proxy_set_header X-Sbx-Vue reduite;
    }}""")
    assert regles(constats(texte, tmp_path)) == ["D"]


def test_actor_session_verifiee_par_l_agregateur(tmp_path):
    texte = serveur(f"""
    location = /api/v1/actor/actors {{
        auth_request /__verif;
        rewrite ^ $uri break;  proxy_pass http://unix:/run/secubox/actor.sock;
        {ORIGINE}
        proxy_set_header X-Sbx-Vue reduite;
    }}""", f"""
    location = /__verif {{
        internal;
        proxy_pass http://unix:/run/secubox/aggregator.sock:/api/v1/auth/auth/verify;
        {ORIGINE}
    }}""")
    assert constats(texte, tmp_path) == []


def test_prefixe_qui_ouvre_un_chemin_d_administration(tmp_path):
    texte = serveur(f"""
    location /api/v1/zigbee/ {{
        if ($lan_client = 0) {{ return 403; }}
        proxy_pass http://unix:/run/secubox/zigbee.sock:/;
        {ORIGINE}
    }}""")
    c = constats(texte, tmp_path)
    assert regles(c) == ["D"]
    assert any("/api/v1/zigbee/backups" in x.message for x in c)


RELAIS_API = f"""
location = /api/v1/demo/etat {{
    proxy_pass http://unix:/run/secubox/demo.sock:/etat;
    {ORIGINE}
}}"""


def test_api_non_relayee_sans_repli_404(tmp_path):
    c = constats(serveur(RELAIS_API, repli=""), tmp_path)
    assert regles(c) == ["D"] and c[0].location == "server" and "/api/" in c[0].message


def test_repli_api_en_priorite_absolue_refuse(tmp_path):
    """`^~` couperait la recherche des expressions régulières : tous les
    relais en regex sous /api/ tomberaient dans le repli."""
    repli = """
location ^~ /api/ {
    return 404;
}"""
    assert regles(constats(serveur(RELAIS_API, repli=repli), tmp_path)) == ["D"]


def test_repli_api_present(tmp_path):
    assert constats(serveur(RELAIS_API), tmp_path) == []


# ── Lecture du fichier ───────────────────────────────────────────────────────

def _ecrit(tmp_path: Path, texte: str) -> Path:
    f = tmp_path / "hall.conf"
    f.write_text(texte)
    return f


def test_commentaires_et_guillemets_ne_trompent_pas_l_analyse(tmp_path):
    texte = serveur(f"""
    location = /api/v1/demo/etat {{  # un commentaire avec {{ et ; et }}
        # relais: lecture
        limit_except GET {{ deny all; }}
        add_header X-Note "texte ; avec {{ accolades }} et # dièse" always;
        proxy_pass http://unix:/run/secubox/demo.sock:/etat;
        {ORIGINE}
        set $x "${{remote_addr}}";
    }}""")
    tous, c = vrh.analyse_fichier(_ecrit(tmp_path, texte), RACINE)
    assert c == [] and len(tous) == 1 and tous[0].lecture


def test_location_imbrique_herite_des_entetes_du_parent(tmp_path):
    texte = serveur(f"""
    location /api/v1/demo/ {{
        {ORIGINE}
        location = /api/v1/demo/etat {{
            proxy_pass http://unix:/run/secubox/demo.sock:/etat;
        }}
    }}""")
    tous, c = vrh.analyse_fichier(_ecrit(tmp_path, texte), RACINE)
    assert c == [] and [r.motif for r in tous] == ["/api/v1/demo/etat"]


@pytest.mark.parametrize("texte", [
    "server {\n location / {\n proxy_pass http://x;\n}\n",       # bloc non refermé
    "server {\n}\n}\n",                                           # accolade en trop
    'server {\n add_header X "non refermé;\n}\n',                 # guillemet
])
def test_fichier_mal_forme(tmp_path, texte):
    with pytest.raises(vrh.ErreurAnalyse):
        vrh.analyse_fichier(_ecrit(tmp_path, texte), RACINE)


# ── Ligne de commande ────────────────────────────────────────────────────────

def test_cli_code_0_sur_le_depot(capsys):
    assert vrh.main(["--racine", str(RACINE)]) == 0
    assert "conformes au gabarit" in capsys.readouterr().out


def test_cli_code_1_et_message_par_location(tmp_path, capsys):
    f = _ecrit(tmp_path, serveur("""
    location /api/v1/demo/ {
        proxy_pass http://unix:/run/secubox/demo.sock:/;
        proxy_set_header Host $host;
    }"""))
    assert vrh.main(["--vhost", str(f), "--racine", str(RACINE)]) == 1
    sortie = capsys.readouterr().out
    ligne = 1 + f.read_text().split("\n").index("location /api/v1/demo/ {")
    assert f"hall.conf:{ligne}  location /api/v1/demo/" in sortie
    assert "[A]" in sortie and "écart(s)" in sortie


def test_cli_code_2_si_illisible(tmp_path, capsys):
    f = _ecrit(tmp_path, "server {\n")
    assert vrh.main(["--vhost", str(f)]) == 2


# ── Syntaxe nginx ────────────────────────────────────────────────────────────

_NGINX = shutil.which("nginx") or (Path("/usr/sbin/nginx").exists() and "/usr/sbin/nginx")


@pytest.mark.skipif(not _NGINX, reason="nginx absent : la CI l'installe")
def test_syntaxe_nginx_du_vhost_du_depot():
    ok, sortie = vrh.verifie_syntaxe(VHOST, exiger=True)
    assert ok, sortie


@pytest.mark.skipif(not _NGINX, reason="nginx absent : la CI l'installe")
def test_syntaxe_nginx_refuse_une_directive_mal_formee(tmp_path):
    f = _ecrit(tmp_path, serveur("""
    location = /x {
        proxy_set_header X-Seul;
        proxy_pass http://unix:/run/secubox/demo.sock:/x;
    }"""))
    ok, sortie = vrh.verifie_syntaxe(f, exiger=True)
    assert ok is False and "proxy_set_header" in sortie


# ── U : l'amont reçoit l'URI normalisée ─────────────────────────────────────

def _lecture_exacte(pp: str, avant: str = "") -> str:
    return serveur(f"""
    location = /api/v1/demo/etat {{
        # relais: lecture
        limit_except GET {{ deny all; }}
        {avant}
        proxy_pass {pp};
        {ORIGINE}
    }}""")


def test_proxy_pass_sans_uri_signale(tmp_path):
    c = constats(_lecture_exacte("http://unix:/run/secubox/demo.sock"), tmp_path)
    assert regles(c) == ["U"]


def test_proxy_pass_http_sans_uri_signale(tmp_path):
    c = constats(_lecture_exacte("http://10.0.0.9:8080"), tmp_path)
    assert regles(c) == ["U"]


@pytest.mark.parametrize("pp", ["http://unix:/run/secubox/demo.sock:/etat",
                                "http://10.0.0.9:8080/etat"])
def test_proxy_pass_avec_uri_conforme(tmp_path, pp):
    assert constats(_lecture_exacte(pp), tmp_path) == []


def test_rewrite_break_normalise_conforme(tmp_path):
    texte = _lecture_exacte("http://unix:/run/secubox/demo.sock", "rewrite ^ $uri break;")
    assert constats(texte, tmp_path) == []


def test_rewrite_sans_break_ne_suffit_pas(tmp_path):
    texte = _lecture_exacte("http://unix:/run/secubox/demo.sock", "rewrite ^ $uri last;")
    assert "U" in regles(constats(texte, tmp_path))


def test_verrou_if_apres_rewrite_signale(tmp_path):
    texte = _lecture_exacte("http://unix:/run/secubox/demo.sock",
                            "rewrite ^ $uri break;\n if ($lan_client = 0) { return 403; }")
    c = constats(texte, tmp_path)
    assert regles(c) == ["U"] and "if" in c[0].message


def test_vhost_du_depot_transmet_toujours_l_uri_normalisee():
    relais, _ = vrh.analyse_fichier(VHOST, RACINE)
    for r in relais:
        assert vrh._proxy_pass_avec_uri(r.proxy_pass) or vrh._reecrit_en_break(r), r.libelle()
