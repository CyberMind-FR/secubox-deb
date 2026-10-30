# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3126 L5 tâche 7 — profil léger « distante » : minimal sans front web d'administration, piloté par le maître.

Ni nginx d'administration, ni portal, ni haproxy, ni annuaire, ni assist (R-L5-28) ; modules Python dans UN groupe
`secubox-group@distante` avec veille ; agrégateur en relais pur ; agent et relais du pilotage actifs ; nginx réduit à
la page d'état locale (gabarit `etat`, LAN seulement)."""
import re
from pathlib import Path

import pytest

from api import front_web
from api.state import StateError, load_profile, parse_profile

RACINE = Path(__file__).resolve().parents[1]
DISTANTE = load_profile(RACINE / "profiles" / "distante.toml")
MINIMAL = load_profile(RACINE / "profiles" / "minimal.toml")
GROUPE = [m.split("#")[0].strip() for m in (RACINE / "groups" / "distante.conf").read_text().splitlines()]
GROUPE = [m for m in GROUPE if m]
DROPIN = (RACINE / "groups" / "secubox-group@distante.service.d" / "distante.conf").read_text()
GABARIT = (RACINE / "nginx" / "etat.conf").read_text()
ETAT_GO = (RACINE.parent / "secubox-pilotage-agent" / "internal" / "etat" / "etat.go").read_text()


def _code(txt):
    return "\n".join(ligne for ligne in txt.splitlines() if not ligne.lstrip().startswith("#"))


def test_profil_leger_sans_front_web():
    assert DISTANTE.name == "distante"
    assert DISTANTE.front_web == "etat" and DISTANTE.agregateur == "relais"
    for mid in ("portal", "haproxy", "waf", "waf-ng", "hub", "waker", "kiosk", "console", "webos", "profiles", "metrics"):
        assert mid not in DISTANTE.on, mid
    for mid in ("core", "auth", "aggregator", "pilotage-agent", "pilotage-relais", "group@distante", "p2p"):
        assert mid in DISTANTE.on, mid
    # Les autres profils gardent leur front web (aucune clé).
    assert MINIMAL.front_web is None and MINIMAL.agregateur is None


def test_profil_sans_annuaire_ni_assist():
    """R-L5-28 : ni annuaire ni assistance sur la box légère ; leurs menus sont masqués."""
    assert not ({"annuaire", "assist", "groupe-declares"} & DISTANTE.on)
    assert {"annuaire", "assist"} <= DISTANTE.menu_off


def test_profil_garde_les_fonctions_du_boitier_de_garde():
    """Le boîtier de garde reste : ce que minimal sert, sauf le front web, l'annuaire et ce qui passe dans le groupe."""
    for mid in ("dns-guard", "ad-guard", "hub", "hardening", "wireguard"):
        assert mid in GROUPE, mid
    for mid in ("webfilter", "webfilter-feed", "nac", "freebox", "ipv6guard", "system", "meshname"):
        assert mid in DISTANTE.on, mid
    attendus = (MINIMAL.on - {"annuaire", "groupe-declares", "waker", "users"} - set(GROUPE)) | {
        "pilotage-agent", "pilotage-relais", "group@distante"}
    assert DISTANTE.on == attendus


def test_groupe_unique_sans_double_socket():
    """Un module du groupe n'a pas aussi son unité dans le profil (deux serveurs sur la même socket : un module mort)."""
    assert GROUPE and len(GROUPE) == len(set(GROUPE))
    assert not (set(GROUPE) & DISTANTE.on)
    # Jamais un module à socket dédiée (root, polkit, compte propre) : il n'a rien à faire sous le compte secubox.
    for mid in ("system", "nac", "admin", "netdiag", "webfilter", "freebox", "ipv6guard", "pilotage", "auth", "p2p"):
        assert mid not in GROUPE, mid


def test_groupe_en_veille():
    code = _code(DROPIN)
    lignes = [ligne for ligne in code.splitlines() if ligne.startswith("ExecStart=")]
    assert lignes[0] == "ExecStart="  # remise à zéro de l'ExecStart du gabarit (sinon deux commandes)
    cmd = lignes[1]
    assert cmd.startswith("ExecStart=/usr/sbin/secubox-groupd --fichier /usr/share/secubox/profiles/groups/distante.conf ")
    veille = float(re.search(r"--veille (\d+)", cmd).group(1))
    assert veille >= 60
    opt_in = re.search(r"--veille-modules (\S+)", cmd).group(1).split(",")
    assert set(opt_in) <= set(GROUPE) and set(opt_in) == {"hub", "hardening"}
    # Les fonctions du boîtier (filtrage DNS, publicités, tunnel) ne s'endorment jamais.
    assert not ({"dns-guard", "ad-guard", "wireguard"} & set(opt_in))


def test_gabarit_etat_lan_seulement():
    code = _code(GABARIT)
    allows = re.findall(r"^\s*allow\s+(\S+);", code, re.M)
    assert set(allows) == {"127.0.0.1", "::1", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7", "fe80::/10"}
    assert re.search(r"^\s*deny\s+all;", code, re.M)
    # Une seule page, aucun relais vers une API.
    for interdit in ("proxy_pass", "fastcgi_pass", "uwsgi_pass", "scgi_pass", "grpc_pass", "/api/", "autoindex on", "ssi on"):
        assert interdit not in code, interdit
    assert re.findall(r"^\s*location\s+(.*?)\s*\{", code, re.M) == ["= /etat", "= /", "/"]
    assert "alias /run/secubox/pilotage/etat.html;" in code
    assert re.search(r"location / \{\s*return 404;", code)


def test_gabarit_etat_entetes_de_securite():
    code = _code(GABARIT)
    empreinte = re.search(r'EmpreinteStyle = "(sha256-[^"]+)"', ETAT_GO).group(1)
    csp = re.search(r'add_header Content-Security-Policy "([^"]+)" always;', code).group(1)
    assert csp.startswith("default-src 'none';")
    assert f"style-src '{empreinte}'" in csp
    for d in ("frame-ancestors 'none'", "base-uri 'none'", "form-action 'none'"):
        assert d in csp, d
    for h in ('add_header X-Content-Type-Options "nosniff" always;', 'add_header X-Frame-Options "DENY" always;',
              'add_header Referrer-Policy "no-referrer" always;', 'add_header Cache-Control "no-store" always;'):
        assert h in code, h
    assert "server_tokens off;" in code


def test_cles_de_profil_validees(tmp_path):
    with pytest.raises(StateError):
        parse_profile('name = "x"\non = ["core"]\nfront_web = "admin"\n', tmp_path / "x.toml")
    with pytest.raises(StateError):
        parse_profile('name = "x"\non = ["core"]\nagregateur = "tout"\n', tmp_path / "x.toml")


# --- front_web : installation et retour arrière du front web réduit ---

def _box(tmp_path, nginx_ok=True):
    r = tmp_path / "racine"
    se, sa = r / "etc/nginx/sites-enabled", r / "etc/nginx/sites-available"
    se.mkdir(parents=True)
    sa.mkdir(parents=True)
    (sa / "secubox").write_text("server { listen 80; }\n")
    (se / "secubox").symlink_to("../sites-available/secubox")
    (se / "webui.conf").write_text("server { listen 8080; }\n")
    (r / "etc/secubox").mkdir(parents=True)
    (r / "etc/secubox/aggregator.toml").write_text('modules = ["hub", "users"]\n')
    appels = []

    def run(argv):
        appels.append(argv)
        if argv[:2] == ["nginx", "-t"]:
            return (0 if nginx_ok else 1), ("" if nginx_ok else "emerg")
        return 0, ""
    return r, appels, run


def test_front_web_installe_l_etat_et_le_relais_pur(tmp_path):
    r, appels, run = _box(tmp_path)
    res = front_web.appliquer(DISTANTE, racine=r, gabarit=RACINE / "nginx" / "etat.conf", run=run)
    assert res["ok"] and res["action"] == "alleger"
    se = r / "etc/nginx/sites-enabled"
    assert sorted(p.name for p in se.iterdir()) == ["secubox-etat"]
    assert (se / "secubox-etat").is_symlink()
    assert (r / "etc/nginx/sites-available/secubox-etat").read_text() == GABARIT
    assert "modules = []" in (r / "etc/secubox/aggregator.toml").read_text()
    assert ["nginx", "-t"] in appels
    assert ["systemctl", "try-restart", "secubox-aggregator.service"] in appels
    # Idempotent : un second apply ne déplace rien de plus et garde la sauvegarde d'origine.
    res = front_web.appliquer(DISTANTE, racine=r, gabarit=RACINE / "nginx" / "etat.conf", run=run)
    assert res["ok"]
    sauve = r / front_web.ETAT_REL
    assert (sauve / "aggregator.toml").read_text() == 'modules = ["hub", "users"]\n'


def test_front_web_retour_arriere_par_un_autre_profil(tmp_path):
    r, appels, run = _box(tmp_path)
    front_web.appliquer(DISTANTE, racine=r, gabarit=RACINE / "nginx" / "etat.conf", run=run)
    res = front_web.appliquer(MINIMAL, racine=r, gabarit=RACINE / "nginx" / "etat.conf", run=run)
    assert res["ok"] and res["action"] == "retablir"
    se = r / "etc/nginx/sites-enabled"
    assert sorted(p.name for p in se.iterdir()) == ["secubox", "webui.conf"]
    assert (se / "secubox").is_symlink() and not (se / "webui.conf").is_symlink()
    assert (r / "etc/secubox/aggregator.toml").read_text() == 'modules = ["hub", "users"]\n'
    assert not (r / front_web.ETAT_REL).exists()
    # Sans allègement en cours, un profil ordinaire ne touche à rien.
    n = len(appels)
    assert front_web.appliquer(MINIMAL, racine=r, gabarit=RACINE / "nginx" / "etat.conf", run=run)["action"] == "rien"
    assert len(appels) == n


def test_front_web_nginx_invalide_tout_est_rendu(tmp_path):
    r, appels, run = _box(tmp_path, nginx_ok=False)
    res = front_web.appliquer(DISTANTE, racine=r, gabarit=RACINE / "nginx" / "etat.conf", run=run)
    assert not res["ok"]
    se = r / "etc/nginx/sites-enabled"
    assert sorted(p.name for p in se.iterdir()) == ["secubox", "webui.conf"]
    assert (r / "etc/secubox/aggregator.toml").read_text() == 'modules = ["hub", "users"]\n'
    assert not (r / front_web.ETAT_REL).exists()
    assert ["systemctl", "try-restart", "secubox-aggregator.service"] not in appels


def test_paquet_installe_profil_groupe_et_gabarit():
    inst = (RACINE / "debian" / "install").read_text()
    assert "profiles/*.toml" in inst
    assert re.search(r"^groups/distante\.conf\s+usr/share/secubox/profiles/groups/$", inst, re.M)
    assert re.search(r"^nginx/etat\.conf\s+usr/share/secubox/profiles/nginx/$", inst, re.M)
    rules = (RACINE / "debian" / "rules").read_text()
    assert "secubox-group@distante.service.d" in rules


def _apply(tmp_path, monkeypatch, statut, profil_toml):
    import api.apply as ap
    import api.cli as cli
    from api.apply import ApplyReport
    from api.observe import Actual
    monkeypatch.setattr(cli, "_running_as_root", lambda: True)
    root = tmp_path / "etc"
    (root / "modules.d").mkdir(parents=True)
    (root / "profiles").mkdir(parents=True)
    (root / "profiles" / "distante.toml").write_text(profil_toml)
    monkeypatch.setattr(cli, "_observe_all", lambda mans, routes: {})
    monkeypatch.setattr(ap, "apply_plan", lambda *a, **k: ApplyReport(status=statut, changed=[]))
    vus, audits = [], []
    monkeypatch.setattr(front_web, "appliquer", lambda prof, **k: vus.append(prof) or {"ok": True, "action": "alleger"})
    monkeypatch.setattr(cli, "_audit_front_web", lambda res, prof: audits.append((res, prof.name if prof else None)))
    rc = cli.main(["--root", str(root), "apply", "--profile", "distante", "--yes", "--json"])
    return rc, vus, audits


def test_apply_pose_le_front_web_apres_un_apply_reussi(tmp_path, monkeypatch):
    rc, vus, audits = _apply(tmp_path, monkeypatch, "applied", (RACINE / "profiles" / "distante.toml").read_text())
    assert rc == 0 and len(vus) == 1 and vus[0].front_web == "etat"
    assert audits == [({"ok": True, "action": "alleger"}, "distante")]


def test_apply_en_echec_ne_touche_pas_au_front_web(tmp_path, monkeypatch):
    rc, vus, audits = _apply(tmp_path, monkeypatch, "rolled_back", (RACINE / "profiles" / "distante.toml").read_text())
    assert rc == 2 and vus == [] and audits == []
