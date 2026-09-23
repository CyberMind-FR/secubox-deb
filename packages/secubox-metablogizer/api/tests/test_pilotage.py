# packages/secubox-metablogizer/api/tests/test_pilotage.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Poste de pilotage (#1322) : un verdict par maillon, un geste par route.

Les tests portent sur la LOGIQUE (fonctions pures ou à dépendances
substituées), pas sur le transport HTTP : le TestClient dépend de la version
d'httpx du poste, la logique non.
"""
import json
import subprocess
from pathlib import Path

import pytest

import routers.pilotage as rp


@pytest.fixture
def site(tmp_path, monkeypatch):
    """Un site `wall` avec index.html, un nginx unifié et une table de routes."""
    root = tmp_path / "sites"
    d = root / "wall" / "public"
    d.mkdir(parents=True)
    (d / "index.html").write_text("<h1>wall</h1>")
    (root / "wall" / "site.json").write_text(json.dumps({"name": "wall", "domain": "wall.gk2.net"}))
    nginx = tmp_path / "metablogizer"
    nginx.write_text(f"server {{\n    root {root / 'wall' / 'public'};\n}}\n")
    routes = tmp_path / "haproxy-routes.json"
    routes.write_text(json.dumps({"wall.gk2.net": ["192.168.1.200", 8900]}))
    monkeypatch.setattr(rp, "SITES_ROOT", root)
    monkeypatch.setattr(rp, "NGINX_METABLOGS_CONF", nginx)
    monkeypatch.setattr(rp, "NGINX_ENABLED_DIR", tmp_path / "enabled")
    monkeypatch.setattr(rp, "NGINX_VHOST_DIR", tmp_path / "available")
    monkeypatch.setattr(rp, "WAF_ROUTES_FILE", routes)
    monkeypatch.setattr(rp, "CERTS_DIRS", (tmp_path / "le", tmp_path / "hap", tmp_path / "data"))
    return root / "wall"


def _dns(reponses):
    """Substitut de `_resoudre` : {(nom, type): (adresses, erreur)}."""
    return lambda nom, rrtype: reponses.get((nom, rrtype), ([], None))


# ── DNS ──────────────────────────────────────────────────────────────────

def test_dns_nxdomain_est_nomme_comme_cause(monkeypatch):
    monkeypatch.setattr(rp, "_resoudre", _dns({
        ("wall.gk2.net", "A"): ([], "nxdomain"),
        (rp.DOMAINE_REFERENCE, "A"): (["82.67.100.75"], None),
    }))
    m = rp.maillon_dns("wall.gk2.net")
    assert m["ok"] is False and m["nxdomain"] is True
    assert "NXDOMAIN" in m["detail"] and "registrar" in m["detail"]


def test_dns_qui_resout_ailleurs_que_la_box_est_un_echec(monkeypatch):
    monkeypatch.setattr(rp, "_resoudre", _dns({
        ("wall.gk2.net", "A"): (["1.2.3.4"], None),
        (rp.DOMAINE_REFERENCE, "A"): (["82.67.100.75"], None),
    }))
    m = rp.maillon_dns("wall.gk2.net")
    assert m["ok"] is False
    assert "1.2.3.4" in m["detail"] and "82.67.100.75" in m["detail"]


def test_dns_qui_resout_vers_la_box_est_bon(monkeypatch):
    monkeypatch.setattr(rp, "_resoudre", _dns({
        ("wall.gk2.net", "A"): (["82.67.100.75"], None),
        (rp.DOMAINE_REFERENCE, "A"): (["82.67.100.75"], None),
    }))
    assert rp.maillon_dns("wall.gk2.net")["ok"] is True


def test_dns_sans_reference_connue_se_contente_de_resoudre(monkeypatch):
    """Si la référence elle-même ne résout pas (coupure), on ne blâme pas le site."""
    monkeypatch.setattr(rp, "_resoudre", _dns({("wall.gk2.net", "A"): (["82.67.100.75"], None)}))
    assert rp.maillon_dns("wall.gk2.net")["ok"] is True


# ── Certificat ───────────────────────────────────────────────────────────

def _cert_autosigne(chemin: Path, cn: str, jours: int) -> None:
    chemin.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "/dev/null",
                    "-out", str(chemin), "-days", str(jours), "-subj", f"/CN={cn}",
                    "-addext", f"subjectAltName=DNS:{cn}"],
                   check=True, capture_output=True)


def test_cert_absent(site):
    m = rp.maillon_cert("wall.gk2.net")
    assert m == {"ok": False, "existe": False, "wildcard": False, "detail": "aucun certificat pour ce nom"}


def test_cert_dedie_lu_avec_expiration_et_san(site, tmp_path):
    _cert_autosigne(tmp_path / "hap" / "wall.gk2.net.pem", "wall.gk2.net", 90)
    m = rp.maillon_cert("wall.gk2.net")
    assert m["ok"] and m["existe"] and m["wildcard"] is False
    assert "wall.gk2.net" in m["san"]
    assert 85 <= m["jours_restants"] <= 90
    assert "expire le" in m["detail"]


def test_cert_wildcard_couvre_un_sous_domaine_gk2(site, tmp_path):
    _cert_autosigne(tmp_path / "data" / f"*{rp.DEFAULT_DOMAIN_SUFFIX}.pem", f"*{rp.DEFAULT_DOMAIN_SUFFIX}", 60)
    m = rp.maillon_cert(f"coin{rp.DEFAULT_DOMAIN_SUFFIX}")
    assert m["ok"] and m["wildcard"] is True


def test_cert_expire_est_un_echec_explicite(site, tmp_path):
    # openssl refuse -days négatif : on antidate via -not_before/-not_after (openssl ≥ 3.0)
    chemin = tmp_path / "hap" / "wall.gk2.net.pem"
    chemin.parent.mkdir(parents=True)
    r = subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "/dev/null",
                        "-out", str(chemin), "-subj", "/CN=wall.gk2.net",
                        "-not_before", "20200101000000Z", "-not_after", "20200102000000Z"],
                       capture_output=True)
    if r.returncode != 0:
        pytest.skip("openssl sans -not_after")
    m = rp.maillon_cert("wall.gk2.net")
    assert m["ok"] is False and "EXPIRÉ" in m["detail"]


# ── Chaîne complète ──────────────────────────────────────────────────────

def test_chaine_rend_six_maillons_et_l_exposition(site, monkeypatch):
    monkeypatch.setattr(rp, "_resoudre", _dns({
        ("wall.gk2.net", "A"): (["82.67.100.75"], None),
        (rp.DOMAINE_REFERENCE, "A"): (["82.67.100.75"], None),
    }))
    c = rp.chaine_du_site(site)
    assert set(c["maillons"]) == {"contenu", "domaine", "vhost", "route", "dns", "cert"}
    assert c["domain"] == "wall.gk2.net"
    assert c["maillons"]["contenu"]["ok"] and c["maillons"]["vhost"]["ok"] and c["maillons"]["route"]["ok"]
    assert c["maillons"]["dns"]["ok"] and not c["maillons"]["cert"]["ok"]
    assert c["exposition"] == "wan"
    assert c["published"] is True          # servi, et rien ne dit le contraire
    assert c["intention"] is None          # site.json ne porte pas encore la clé
    assert c["ok"] is False                # il manque le certificat


def test_chaine_lan_quand_la_route_manque(site, monkeypatch):
    monkeypatch.setattr(rp, "_resoudre", _dns({}))
    rp.WAF_ROUTES_FILE.write_text("{}")
    c = rp.chaine_du_site(site)
    assert c["exposition"] == "lan" and c["maillons"]["route"]["ok"] is False
    assert "LAN" in c["maillons"]["route"]["detail"]


def test_chaine_depublie_meme_si_le_bloc_traine(site, monkeypatch):
    """`published` = servi ET voulu : un site.json à false l'emporte sur un bloc
    encore présent (le générateur n'a pas encore retourné)."""
    monkeypatch.setattr(rp, "_resoudre", _dns({}))
    (site / "site.json").write_text(json.dumps({"name": "wall", "domain": "wall.gk2.net", "published": False}))
    c = rp.chaine_du_site(site)
    assert c["published"] is False and c["intention"] is False


# ── Gestes ───────────────────────────────────────────────────────────────

@pytest.fixture
def gestes(site, monkeypatch):
    """Générateur et publishctl substitués ; on trace les appels."""
    appels = []
    monkeypatch.setattr(rp, "_resoudre", _dns({}))

    def regen():
        appels.append(("regen",))
        # Le générateur honore l'intention : bloc présent ssi published != False
        cfg = json.loads((site / "site.json").read_text())
        rp.NGINX_METABLOGS_CONF.write_text("" if cfg.get("published") is False
                                           else f"server {{ root {site / 'public'}; }}\n")
        return True, 1, "Published 1 sites"
    monkeypatch.setattr(rp, "regenerer_nginx", regen)

    def publishctl(verb, *args):
        appels.append((verb,) + args)
        routes = rp.lire_routes_waf()
        if verb == "waf-route":
            routes[args[0]] = ["192.168.1.200", int(args[1])]
        elif verb == "vhost-del":
            routes.pop(args[0], None)
        rp.WAF_ROUTES_FILE.write_text(json.dumps(routes))
        return {"ok": True, "detail": verb}
    monkeypatch.setattr(rp, "_sudo_publishctl", publishctl)
    monkeypatch.setattr(rp, "apply_route", lambda domain, port=8900: {
        "route_ok": publishctl("vhost-add", domain)["ok"] and publishctl("waf-route", domain, str(port))["ok"]})
    return appels


def test_depublier_retire_intention_bloc_et_route(site, gestes):
    r = rp.depublier(site)
    assert r["ok"] is True
    assert json.loads((site / "site.json").read_text())["published"] is False
    assert rp.NGINX_METABLOGS_CONF.read_text() == ""
    assert "wall.gk2.net" not in rp.lire_routes_waf()
    assert ("vhost-del", "wall.gk2.net") in gestes
    assert r["chaine"]["published"] is False and r["chaine"]["exposition"] == "lan"


def test_publier_remet_intention_bloc_et_route(site, gestes):
    rp.depublier(site)
    gestes.clear()
    r = rp.publier(site)
    assert r["ok"] is True
    assert json.loads((site / "site.json").read_text())["published"] is True
    assert rp.NGINX_METABLOGS_CONF.read_text() != ""
    assert rp.lire_routes_waf()["wall.gk2.net"] == ["192.168.1.200", 8900]
    assert r["chaine"]["published"] is True and r["chaine"]["exposition"] == "wan"


def test_publier_ne_force_pas_le_wan_sur_un_site_deja_expose(site, gestes):
    """La route existe déjà : publier ne la réécrit pas (l'exposition est un
    réglage à part, piloté par `exposer`)."""
    rp.publier(site)
    assert not any(a[0] == "waf-route" for a in gestes)


def test_publier_purge_le_vestige_par_site(site, gestes):
    """Un `<nom>.conf` du modèle un-fichier-par-site double le bloc unifié : il
    part avec la publication, sans quoi le générateur s'efface devant lui."""
    rp.NGINX_ENABLED_DIR.mkdir()
    rp.NGINX_VHOST_DIR.mkdir()
    (rp.NGINX_VHOST_DIR / "wall.conf").write_text("server {}")
    (rp.NGINX_ENABLED_DIR / "wall.conf").symlink_to(rp.NGINX_VHOST_DIR / "wall.conf")
    r = rp.publier(site)
    assert r["etapes"]["vestige"]["purge"] is True
    assert not (rp.NGINX_ENABLED_DIR / "wall.conf").exists()
    assert not (rp.NGINX_VHOST_DIR / "wall.conf").exists()


def test_exposition_lan_puis_wan(site, gestes):
    assert rp.maillon_route("wall.gk2.net")["ok"]
    rp._sudo_publishctl("vhost-del", "wall.gk2.net")
    assert rp.maillon_route("wall.gk2.net")["ok"] is False
    assert rp.apply_route("wall.gk2.net", 8900)["route_ok"]
    assert rp.maillon_route("wall.gk2.net")["cible"] == ["192.168.1.200", 8900]


def test_vestige_par_site_est_signale_dans_le_verdict_vhost(site):
    rp.NGINX_ENABLED_DIR.mkdir()
    (rp.NGINX_ENABLED_DIR / "wall.conf").write_text("server {}")
    assert rp.maillon_vhost(site)["vestige_par_site"] is True
