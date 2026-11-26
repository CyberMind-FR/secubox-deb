# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3974 : sites PHP détectés — wafctl php-sites réel sur de faux fichiers, puis vue et routes de l'API."""
import json
import re
import shutil
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from .test_modes_3741 import c  # noqa: F401 — fixture de l'API (faux ctl)

ICI = Path(__file__).resolve().parents[1]
ACCES = '{h} 203.0.113.{n} - - [26/Nov/2026:09:00:00 +0100] "{m} {p} HTTP/1.1" {s} {o} "-" "Mozilla/5.0"\n'


class _Origine(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        self.send_response(200)
        if self.headers.get("Host") == "wiki.ex.fr":
            self.send_header("X-Powered-By", "PHP/8.2.20")
        if self.headers.get("Host") == "forum.ex.fr":
            self.send_header("Set-Cookie", "PHPSESSID=abc; path=/")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *a):
        pass


@pytest.fixture
def origine():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Origine)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield srv.server_address[1]
    srv.shutdown()


@pytest.fixture
def ctl(tmp_path, origine):
    (tmp_path / "audit.log").touch()
    vp = json.loads((ICI / "config" / "vhost_profiles.json").read_text())
    vp["vhosts"] = {"nc.ex.fr": "nextcloud"}
    vp["php_hotes"] = list(vp["php_hotes"]) + ["^ancien\\.ex\\.fr$", "^.*$"]      # anciens choix (#3741)
    (tmp_path / "vp.json").write_text(json.dumps(vp))
    mort = ["127.0.0.1", 9]                                                         # port fermé : sonde sans réponse
    routes = {h: mort for h in ("nc.ex.fr", "boutique.ex.fr", "spa.ex.fr", "blog.ex.fr", "ancien.ex.fr")}
    routes.update({"wiki.ex.fr": ["127.0.0.1", origine], "forum.ex.fr": ["127.0.0.1", origine],
                   "10.55.0.1": mort, "255.gk2.ex.fr": mort})
    (tmp_path / "routes.json").write_text(json.dumps(routes))
    lignes = [ACCES.format(h="boutique.ex.fr", n=1, m="GET", p="/index.php?id=3", s=200, o=5120),
              ACCES.format(h="boutique.ex.fr", n=2, m="POST", p="/panier.php", s=200, o=800),
              ACCES.format(h="boutique.ex.fr", n=3, m="GET", p="/", s=200, o=4000),
              # attrape-tout : même taille que « / » pour tout chemin
              ACCES.format(h="spa.ex.fr", n=4, m="GET", p="/", s=200, o=1234),
              ACCES.format(h="spa.ex.fr", n=5, m="GET", p="/wp-login.php", s=200, o=1234),
              ACCES.format(h="spa.ex.fr", n=6, m="GET", p="/xmlrpc.php", s=200, o=1234),
              # sondes en 404 : pas une preuve
              ACCES.format(h="blog.ex.fr", n=7, m="GET", p="/shell.php", s=404, o=150),
              ACCES.format(h="blog.ex.fr", n=8, m="GET", p="/admin.php", s=404, o=150),
              # non servi
              ACCES.format(h="ailleurs.ex.fr", n=9, m="GET", p="/a.php", s=200, o=10),
              ACCES.format(h="ailleurs.ex.fr", n=9, m="GET", p="/b.php", s=200, o=10)]
    (tmp_path / "hosts.log").write_text("".join(lignes))
    s = (ICI / "scripts" / "wafctl").read_text()
    for var, val in (("PROFILS_VHOST", tmp_path / "vp.json"), ("ROUTES_HAPROXY", tmp_path / "routes.json"),
                     ("AUDIT_SECUBOX", tmp_path / "audit.log"), ("PHP_SITES", tmp_path / "php-sites.json"),
                     ("WAF_PHP_SITES", ICI / "scripts" / "waf-php-sites"),
                     ("JOURNAL_HOTES_NGINX", tmp_path / "hosts.log")):
        s = re.sub(rf'^{var}=.*$', f'{var}="{val}"', s, count=1, flags=re.M)
    (tmp_path / "wafctl").write_text(s)

    def lance(*args, entree=None):
        corps = json.dumps(entree).encode() if entree is not None else b""
        r = subprocess.run(["bash", str(tmp_path / "wafctl"), *args], input=corps, capture_output=True, timeout=60,
                           check=False)
        return r.returncode, json.loads(r.stdout.decode().strip().splitlines()[-1])
    lance.dossier = tmp_path
    lance.profils = lambda: json.loads((tmp_path / "vp.json").read_text())["php_hotes"]
    lance.audits = lambda: [json.loads(x) for x in (tmp_path / "audit.log").read_text().splitlines()]
    return lance


def test_lister_avant_migration_n_ecrit_rien(ctl):
    rc, d = ctl("php-sites", "lister")
    assert rc == 0 and d["present"] is False and list(d["etat"]["forcer"]) == ["ancien.ex.fr"]
    assert "10.55.0.1" not in d["routes"] and "255.gk2.ex.fr" not in d["routes"]       # jamais d'adresse ni de numéro
    assert not (ctl.dossier / "php-sites.json").exists() and ctl.audits() == []


def test_detecter_preuves_et_motifs(ctl):
    avant = ctl.profils()
    rc, d = ctl("php-sites", "detecter")
    assert rc == 0
    etat = json.loads((ctl.dossier / "php-sites.json").read_text())
    det = etat["detectes"]
    assert det["nc.ex.fr"]["type"] == "appli" and "nextcloud" in det["nc.ex.fr"]["preuve"]
    assert det["boutique.ex.fr"]["type"] == "fichier" and "servi en 2xx (2 fois)" in det["boutique.ex.fr"]["preuve"]
    assert "?" not in det["boutique.ex.fr"]["preuve"]                                  # jamais la chaîne de requête
    assert det["wiki.ex.fr"] == {**det["wiki.ex.fr"], "type": "entete", "preuve": "X-Powered-By: PHP/8.2.20"}
    assert det["forum.ex.fr"]["preuve"] == "cookie PHPSESSID"
    for h in ("spa.ex.fr", "blog.ex.fr", "ailleurs.ex.fr"):                             # attrape-tout, 404, non servi
        assert h not in det
    apres = ctl.profils()
    assert [m for m in avant if m not in ("^ancien\\.ex\\.fr$",)] == apres[:len(avant) - 1]   # gardés, ^.*$ compris
    for h in ("ancien", "boutique", "wiki", "forum", "nc"):
        assert f"^{h}\\.ex\\.fr$" in apres
    a = ctl.audits()
    assert len(a) == 1 and a[0]["action"] == "waf-php-sites" and "migration" in a[0]["detail"]
    rc, _ = ctl("php-sites", "detecter")                                               # rien de neuf : pas d'audit
    assert rc == 0 and len(ctl.audits()) == 1


def test_exceptions_forcer_exclure_et_refus(ctl):
    ctl("php-sites", "detecter")
    rc, d = ctl("php-sites", "ecrire", entree={"acteur": "admin", "forcer": ["ancien.ex.fr", "blog.ex.fr"],
                                               "exclure": ["wiki.ex.fr"]})
    assert rc == 0, d
    p = ctl.profils()
    assert "^blog\\.ex\\.fr$" in p and "^wiki\\.ex\\.fr$" not in p
    assert d["etat"]["exclure"]["wiki.ex.fr"]["par"] == "admin"
    rc, d = ctl("php-sites", "detecter")                                               # la détection ne réarme pas
    assert "^wiki\\.ex\\.fr$" not in ctl.profils()
    refus = [{"exclure": ["nc.ex.fr"]},                                                # couvert par le service
             {"forcer": ["inconnu.ex.fr"]},                                            # non servi
             {"forcer": ["a;b"]}, {"forcer": ["blog.ex.fr"], "exclure": ["blog.ex.fr"]}, {}]
    for e in refus:
        rc, d = ctl("php-sites", "ecrire", entree={"acteur": "admin", **e})
        assert rc == 2, e
    assert [x["result"] for x in ctl.audits()][-5:] == ["refus"] * 5


def test_retrait_tout_couvrir_et_retour_arriere(ctl):
    origine = ctl.profils()
    ctl("php-sites", "detecter")
    rc, d = ctl("php-sites", "ecrire", entree={"acteur": "admin", "retirer_tout_couvrir": True})
    assert rc == 0 and "^.*$" not in ctl.profils() and "^(nc|nextcloud|cloud)\\." in ctl.profils()
    rc, d = ctl("php-hotes", "ecrire", entree={"hotes": []})                           # ancien verbe : refusé
    assert rc == 3
    rc, d = ctl("php-sites", "retablir")
    assert rc == 0 and ctl.profils() == origine and not (ctl.dossier / "php-sites.json").exists()
    assert list(ctl.dossier.glob("php-sites.json.retabli-*"))
    rc, d = ctl("php-sites", "retablir")
    assert rc == 4


def test_routes_illisibles_rien_n_est_retire(ctl):
    ctl("php-sites", "detecter")
    avant = ctl.profils()
    (ctl.dossier / "routes.json").write_text("{cassé")
    rc, _ = ctl("php-sites", "detecter")
    assert rc == 0 and ctl.profils() == avant


# ── API ──────────────────────────────────────────────────────────────────

LISTER = {"ok": True, "present": True, "routes": ["nc.ex.fr", "boutique.ex.fr", "blog.ex.fr", "www.ex.fr", "cloud.ex.fr"],
          "profils_vhosts": {"nc.ex.fr": "nextcloud"}, "php_services": ["nextcloud"],
          "php_hotes": ["^(nc|nextcloud|cloud)\\.", "^.*$", "^boutique\\.ex\\.fr$", "^vieux\\.ex\\.fr$"],
          "explicites": ["boutique.ex.fr", "vieux.ex.fr"],
          "etat": {"version": 1, "derniere_detection": "2026-11-26T09:00:00Z",
                   "detectes": {"nc.ex.fr": {"type": "appli", "preuve": "appli nextcloud (module installé)"},
                                "boutique.ex.fr": {"type": "fichier", "preuve": "/index.php servi en 2xx (2 fois)"},
                                "parti.ex.fr": {"type": "fichier", "preuve": "x"}},
                   "forcer": {"vieux.ex.fr": {"par": "migration"}}, "exclure": {}}}


def test_api_vue_sans_liste_brute(c):  # noqa: F811
    c.ctl.reponses[("wafctl", "php-sites", "lister")] = (0, LISTER)
    v = c.get("/php-sites").json()
    assert [d["hote"] for d in v["detectes"]] == ["boutique.ex.fr", "nc.ex.fr"]          # « parti » non servi : caché
    assert {d["hote"]: d["couvert"] for d in v["detectes"]} == {"boutique.ex.fr": "site", "nc.ex.fr": "service"}
    assert v["forcer"][0] == {"hote": "vieux.ex.fr", "le": None, "par": "migration", "servi": False, "couvert": "site"}
    # blog, www : autres ; cloud : couvert par le motif livré ^(nc|…)\. ; ^.*$ hérité signalé, pas compté comme PHP
    assert v["autres"] == 2 and v["tout_couvrir_herite"] is True
    assert v["motifs_livres"] == ["^(nc|nextcloud|cloud)\\."]


def test_api_ecritures_exactes(c):  # noqa: F811
    c.ctl.reponses[("wafctl", "php-sites", "lister")] = (0, LISTER)
    c.ctl.reponses[("wafctl", "php-sites", "ecrire")] = (0, LISTER)
    r = c.post("/php-sites", json={"forcer": ["Blog.ex.fr"], "exclure": []})
    assert r.status_code == 200 and r.json()["detectes"]
    assert (["sudo", "-n", "/usr/sbin/wafctl", "php-sites", "ecrire"],
            {"acteur": "admin", "forcer": ["blog.ex.fr"], "exclure": []}) in c.ctl.appels
    assert c.post("/php-sites", json={"forcer": ["a;b"]}).status_code == 422
    assert c.post("/php-sites", json={}).status_code == 422
    assert c.post("/php-sites", json={"tous": True}).status_code == 422                  # plus de tout-ou-rien
    r = c.post("/php-sites/detecter")
    assert r.status_code == 200 and (["sudo", "-n", "/usr/sbin/wafctl", "php-sites", "detecter"], {}) in c.ctl.appels
    c.ctl.reponses[("wafctl", "php-sites", "ecrire")] = (2, {"ok": False, "erreur": "exclure : nc.ex.fr reste couvert"})
    r = c.post("/php-sites", json={"exclure": ["nc.ex.fr"]})
    assert r.status_code == 422 and "reste couvert" in r.json()["detail"]["erreur"]
    actions = [json.loads(x)["action"] for x in c.audit.read_text().splitlines()]
    assert actions.count("waf-php-sites") >= 5


def test_paquet_installe_le_detecteur():
    rules = (ICI.parents[1] / "debian" / "rules").read_text()
    assert "composants/waf/scripts/waf-php-sites debian/secubox-waf-ng/usr/lib/secubox/waf/waf-php-sites" in rules
    assert "wafctl php-sites detecter" in (ICI.parents[1] / "debian" / "postinst").read_text()
