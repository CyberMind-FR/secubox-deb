# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3824 — le nom public d'une box ne sert que le dé et sa santé ; le relais des autres chemins vers l'ancienne cible
(sur gk2 : l'API admin) est une option FERMÉE par défaut, ouverte ou fermée par l'administrateur, auditée.

Vérifié : le vhost rendu servi par un VRAI nginx dans les deux modes, la montée depuis 1.21.0 (gk2 finit fermé), le
verbe `secubox-noeud relais` (réglage atomique, nginx -t et retour arrière, garde du mot de passe par défaut, audit),
le dépôt des demandes (`prepare`/`traite`), les unités, et le passage de secubox-webos au cœur (#3883 : vhost de webos
repris, migration une fois de [noeud] et de l'état). L'API est celle de secubox-system (ses tests : test_api_noeud_3883)."""
import http.server
import json
import os
import re
import shutil
import socket
import stat
import subprocess
import threading
import time
from pathlib import Path

import pytest
from banc_noeud import DOM, HALL, PAGE, PKG, RACINE, audits, box_noeud, charger, conf, get, port_libre  # noqa: F401

CIBLE = ["192.168.1.200", 8000]
EYE_REMOTE = """# Eye Remote API - Expose APIs on port 8000
server {
    listen 192.168.1.200:8000;
    listen 127.0.0.1:8000;
    server_name _;
    location /api/v1/metrics { proxy_pass http://unix:/run/secubox/metrics.sock; }
    location /api/v1/admin/ { rewrite ^/api/v1/admin/(.*)$ /$1 break; proxy_pass http://unix:/run/secubox/admin.sock; }
    location /api/v1/health { return 200 '{"status": "ok"}'; }
    location / { return 404 '{"detail": "Not Found"}'; }
}
"""
# Un fichier de réglages avec une autre table et un commentaire posés à la main : ils doivent survivre (c'était le
# webos.toml de gk2 avant #3883 ; noeud.toml garde la même règle : seule la clé change).
TOML_GK2 = ("[webos]\nenabled = true\nregistry_enabled = true\n"
            "# Coque « vue maître » du Hall (#2996), activée le 2026-10-21\nhall_v2 = true\n")


def gk2_repris(m, toml=TOML_GK2):
    """La box après 1.21.0 sur gk2 : route reprise, ancienne cible :8000 (eye-remote-api), réglages posés."""
    t = json.loads(Path(m.ROUTES).read_text())
    t[DOM] = CIBLE
    Path(m.ROUTES).write_text(json.dumps(t))
    (m.racine / "etc/nginx/sites-enabled/eye-remote-api").write_text(EYE_REMOTE)
    if toml is not None:
        Path(m.REGLAGES).write_text(toml)
        os.chmod(m.REGLAGES, 0o644)
    m.sonde = 404
    assert m.appliquer() == 0


# ── Montée depuis 1.21.0 : gk2 finit FERMÉ ───────────────────────────────────────────────────────────────────

def test_montee_depuis_1_21_0_ferme_le_relais(box):
    # le vhost de 1.21.0 tel qu'il est sur gk2 : tout le reste relayé à :8000
    gk2_repris(box)
    ancien = box.rendre(DOM, tuple(CIBLE), True, relais=True)
    Path(box.CONF).write_text(ancien)
    assert "location / {\n        proxy_pass http://192.168.1.200:8000;" in ancien
    box.appels.clear()
    assert box.appliquer() == 0                                  # ce que fait le postinst de 1.21.1
    c = conf(box)
    assert "location / {\n        return 404;" in c
    assert "location = /api/v1/health {\n        proxy_pass http://192.168.1.200:8000;" in c and c.count("proxy_pass") == 1
    assert ["systemctl", "reload", "nginx"] in box.appels
    a = audits(box)[-1]
    assert a["action"] == "vhost" and a["result"] == "regenere" and "fermé" in a["detail"]
    assert box.relais_voulu() is False
    assert Path(box.REGLAGES).read_text() == TOML_GK2            # le réglage n'est pas écrit : défaut = fermé


@pytest.mark.parametrize("toml", [None, "", "[noeud]\naccueil = true\n", "[noeud]\nrelais_api = \"true\"\n",
                                  "[noeud]\nrelais_api = 1\n", "{illisible"])
def test_tout_sauf_true_laisse_ferme(box, toml):
    if toml is not None:
        Path(box.REGLAGES).write_text(toml)
    assert box.relais_voulu() is False


# ── Le verbe `relais` ────────────────────────────────────────────────────────────────────────────────────────

def test_ouvrir_puis_fermer_audite_et_reglage_garde(box):
    gk2_repris(box)
    box.appels.clear()
    assert box.relais("activer", "admin") == 0
    texte = Path(box.REGLAGES).read_text()
    assert texte.startswith(TOML_GK2) and texte.endswith("[noeud]\nrelais_api = true\n")
    assert stat.S_IMODE(os.stat(box.REGLAGES).st_mode) == 0o644
    c = conf(box)
    assert "location / {\n        proxy_pass http://192.168.1.200:8000;" in c and "return 404;" not in c
    assert ["nginx", "-t"] in box.appels and ["systemctl", "reload", "nginx"] in box.appels
    assert not any(a[0] in ("secubox-waf-route", "haproxyctl") for a in box.appels)   # ni route ni HAProxy touchées
    a = audits(box)[-1]
    assert (a["action"], a["result"]) == ("relais_api", "ouvert")
    assert "par admin" in a["detail"] and "192.168.1.200:8000" in a["detail"] and "/api/v1/admin/" in a["detail"]
    e = box.etat_relais()
    assert e["relais_api"] and e["relais_actif"] and e["cible"] == "192.168.1.200:8000"
    assert e["chemins_cible"] == ["/api/v1/metrics", "/api/v1/admin/", "/api/v1/health", "/"]
    assert e["source_chemins"].endswith("sites-enabled/eye-remote-api")
    # un passage d'`appliquer` (montée suivante) GARDE le choix de l'administrateur
    assert box.appliquer() == 0 and conf(box) == c
    # fermer
    assert box.relais("desactiver", "admin") == 0
    assert Path(box.REGLAGES).read_text().endswith("[noeud]\nrelais_api = false\n")
    assert "location / {\n        return 404;" in conf(box)
    a = audits(box)[-1]
    assert (a["action"], a["result"]) == ("relais_api", "ferme") and "par admin" in a["detail"]
    assert box.etat_relais()["relais_actif"] is False


def test_ouvrir_refuse_tant_que_le_mot_de_passe_par_defaut(box, monkeypatch):
    gk2_repris(box)
    avant, c = Path(box.REGLAGES).read_text(), conf(box)
    monkeypatch.setattr(box, "mot_de_passe_change", lambda: False)
    assert box.relais("activer", "admin") == 3
    assert Path(box.REGLAGES).read_text() == avant and conf(box) == c
    a = audits(box)[-1]
    assert (a["action"], a["result"]) == ("relais_api", "refus") and "#3401" in a["detail"]
    assert box.relais("desactiver", "admin") == 0                # fermer reste toujours possible


def test_nginx_refuse_le_reglage_est_remis(box):
    gk2_repris(box)
    avant, c = Path(box.REGLAGES).read_text(), conf(box)
    box.nginx_ok = False
    assert box.relais("activer", "admin") == 1
    assert Path(box.REGLAGES).read_text() == avant and conf(box) == c
    a = audits(box)[-1]
    assert (a["action"], a["result"]) == ("relais_api", "echec") and "réglage remis" in a["detail"]


def test_reglage_toml_invalide_jamais_reecrit(box):
    gk2_repris(box, toml="[webos\nenabled = true\n")
    assert box.relais("activer", "admin") == 1
    assert Path(box.REGLAGES).read_text() == "[webos\nenabled = true\n"
    assert audits(box)[-1]["result"] == "echec"


def test_reglage_lien_jamais_suivi(box, tmp_path):
    autre = tmp_path / "ailleurs.toml"
    autre.write_text("[webos]\nenabled = true\n")
    os.symlink(autre, box.REGLAGES)
    assert box.ecrire_reglage_relais(True) is None
    assert autre.read_text() == "[webos]\nenabled = true\n" and os.path.islink(box.REGLAGES)


@pytest.mark.parametrize("avant,apres", [
    ("", "[noeud]\nrelais_api = true\n"),
    ("[webos]\nenabled = true\n", "[webos]\nenabled = true\n\n[noeud]\nrelais_api = true\n"),
    ("[noeud]\naccueil = true\n", "[noeud]\nrelais_api = true\naccueil = true\n"),
    ("[noeud]  # nom\naccueil = true\nrelais_api = false\n[autre]\nx = 1\n",
     "[noeud]  # nom\naccueil = true\nrelais_api = true\n[autre]\nx = 1\n"),
    ("[noeud]\n[autre]\nrelais_api = false\n", "[noeud]\nrelais_api = true\n[autre]\nrelais_api = false\n"),
])
def test_reecriture_ne_touche_que_la_cle(avant, apres):
    assert charger().reglage_avec_relais(avant, True) == apres


def test_cli_usage_et_root(box, capsys):
    assert box.main(["secubox-noeud", "relais"]) == 2
    assert box.main(["secubox-noeud", "relais", "ouvrir"]) == 2
    assert box.main(["secubox-noeud", "relais", "activer", "a", "b"]) == 2
    if os.geteuid() != 0:
        assert box.main(["secubox-noeud", "relais", "activer"]) == 1    # root requis (R vide)
        assert "root requis" in capsys.readouterr().err


# ── Dépôt des demandes de l'API ──────────────────────────────────────────────────────────────────────────────

@pytest.fixture
def depot(box, monkeypatch):
    monkeypatch.setattr(box, "R", str(box.racine))             # pas de chown hors root
    (box.racine / "run/secubox").mkdir(parents=True)
    monkeypatch.setattr(box, "DEMANDES", str(box.racine / "run/secubox/noeud"))
    monkeypatch.setattr(box, "RESULTATS", str(box.racine / "run/secubox/noeud-resultats"))
    return box


def test_prepare_modes_et_lien_retire(depot, tmp_path):
    cible = tmp_path / "piege"
    cible.mkdir()
    os.symlink(cible, depot.DEMANDES)
    assert depot.prepare() == 0
    assert not os.path.islink(depot.DEMANDES)
    assert stat.S_IMODE(os.lstat(depot.DEMANDES).st_mode) == 0o1770
    assert stat.S_IMODE(os.lstat(depot.RESULTATS).st_mode) == 0o750
    assert list(cible.iterdir()) == []


def test_traite_demandes_valides_et_hostiles(depot, tmp_path):
    gk2_repris(depot)
    depot.prepare()
    d = Path(depot.DEMANDES)
    (d / "0123456789abcdef.demande").write_text(json.dumps({"geste": "activer", "acteur": "admin"}))
    (d / "fedcba9876543210.demande").write_text(json.dumps({"geste": "etat", "acteur": "admin"}))
    (d / "aaaaaaaaaaaaaaaa.demande").write_text(json.dumps({"geste": "rm -rf", "acteur": "admin"}))
    (d / "bbbbbbbbbbbbbbbb.demande").write_text(json.dumps({"geste": "activer", "acteur": "x;y"}))
    (d / "cccccccccccccccc.demande").write_text("x" * 600)
    secret = tmp_path / "secret"
    secret.write_text('{"geste": "activer"}')
    os.symlink(secret, d / "dddddddddddddddd.demande")
    (d / "pas-un-nom").write_text("{}")
    (d / ".tmp.eeeeeeeeeeeeeeee").write_text("{}")
    (d / ".tmp.ffffffffffffffff").write_text("{}")
    os.utime(d / ".tmp.ffffffffffffffff", (time.time() - 120, time.time() - 120))   # abandonnée : retirée
    assert depot.traite() == 0
    res = {p.stem: json.loads(p.read_text()) for p in Path(depot.RESULTATS).glob("*.json")}
    assert res["0123456789abcdef"]["code"] == 0 and res["0123456789abcdef"]["etat"]["relais_actif"] is True
    assert res["fedcba9876543210"]["code"] == 0
    for ident in ("aaaaaaaaaaaaaaaa", "bbbbbbbbbbbbbbbb", "cccccccccccccccc", "dddddddddddddddd"):
        assert res[ident]["code"] == 2 and "etat" not in res[ident], ident
    assert sorted(os.listdir(d)) == [".tmp.eeeeeeeeeeeeeeee"]       # tout traité ou retiré, sauf l'écriture en cours
    assert secret.exists()
    assert all(stat.S_IMODE(p.stat().st_mode) == 0o640 for p in Path(depot.RESULTATS).glob("*.json"))
    assert [a["detail"] for a in audits(depot) if a["action"] == "relais_api"][-1].endswith(
        "(/api/v1/metrics, /api/v1/admin/, /api/v1/health, /)")


# ── Le vhost rendu, servi par un vrai nginx, dans les deux modes ─────────────────────────────────────────────

class _Cible(http.server.BaseHTTPRequestHandler):
    """L'ancienne cible (eye-remote-api) : santé, API admin, 404 JSON ailleurs."""
    def do_GET(self):
        corps = {"/api/v1/health": b'{"status": "ok"}', "/api/v1/admin/status": b'{"admin": true}'}.get(self.path)
        self.send_response(200 if corps else 404)
        self.send_header("Content-Type", "application/json")
        self.send_header("X-Hote-Recu", self.headers.get("Host", ""))
        self.end_headers()
        self.wfile.write(corps or b'{"detail": "Not Found"}')

    def log_message(self, *a):
        pass


@pytest.mark.skipif(not shutil.which("nginx"), reason="nginx absent")
@pytest.mark.parametrize("relais", [False, True])
def test_vrai_nginx_ferme_par_defaut_relaye_si_ouvert(tmp_path, relais):
    m = charger()
    www = tmp_path / "www"
    (www / "noeud").mkdir(parents=True)
    shutil.copy(PAGE, www / "noeud" / "index.html")
    shutil.copy(HALL / "sbx-dice.js", www / "noeud" / "sbx-dice.js")     # livré par secubox-core (#3883)
    shutil.copytree(HALL / "dice", www / "noeud" / "dice")
    m.WWW, m.PORT = str(www), port_libre()
    serveur = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Cible)
    threading.Thread(target=serveur.serve_forever, daemon=True).start()
    (tmp_path / "logs").mkdir()
    (tmp_path / "noeud.conf").write_text(m.rendre(DOM, ("127.0.0.1", serveur.server_address[1]), False, relais))
    (tmp_path / "nginx.conf").write_text(
        f"pid {tmp_path}/nginx.pid;\nerror_log {tmp_path}/logs/error.log;\nevents {{}}\n"
        f"http {{\n include /etc/nginx/mime.types;\n access_log off;\n client_body_temp_path {tmp_path}/cb;\n"
        f" proxy_temp_path {tmp_path}/px;\n fastcgi_temp_path {tmp_path}/fc;\n uwsgi_temp_path {tmp_path}/uw;\n"
        f" scgi_temp_path {tmp_path}/sc;\n include {tmp_path}/noeud.conf;\n}}\n")
    base = ["nginx", "-p", str(tmp_path), "-c", str(tmp_path / "nginx.conf"), "-e", str(tmp_path / "logs/error.log")]
    subprocess.run(base + ["-t"], check=True, timeout=30, capture_output=True)
    subprocess.run(base, check=True, timeout=30, capture_output=True)
    try:
        url = f"http://127.0.0.1:{m.PORT}"
        for _ in range(50):
            try:
                socket.create_connection(("127.0.0.1", m.PORT), timeout=0.2).close()
                break
            except OSError:
                time.sleep(0.05)
        code, h, corps = get(url + "/", DOM)
        assert code == 200 and b"<sbx-dice" in corps
        assert get(url + "/_noeud/sbx-dice.js", DOM)[0] == 200
        code, h, corps = get(url + "/api/v1/health", DOM)
        assert code == 200 and json.loads(corps) == {"status": "ok"} and h["X-Hote-Recu"] == DOM
        code, h, corps = get(url + "/api/v1/admin/status", DOM)
        if relais:
            assert code == 200 and json.loads(corps) == {"admin": True} and h["X-Hote-Recu"] == DOM
        else:
            assert code == 404 and "X-Hote-Recu" not in h and b"admin" not in corps
        for chemin in ("/api/v1/metrics", "/api/v1/admin/", "/api/v1/healthz", "/api/v1/health/x", "/x"):
            code, h, corps = get(url + chemin, DOM)
            assert code == 404, chemin
            assert ("X-Hote-Recu" in h) is relais, chemin                # 404 de la cible (ouvert) ou d'ici (fermé)
    finally:
        subprocess.run(base + ["-s", "stop"], check=False, timeout=30, capture_output=True)
        serveur.shutdown()


# ── Paquet ───────────────────────────────────────────────────────────────────────────────────────────────────

def test_unites_paquet_et_exception_ecrite():
    path = (PKG / "systemd/secubox-noeud.path").read_text()
    unite = (PKG / "systemd/secubox-noeud.service").read_text()
    m = charger()
    assert "DirectoryNotEmpty=/run/secubox/noeud\n" in path and m.DEMANDES == "/run/secubox/noeud"
    assert "Unit=secubox-noeud.service" in path and m.RESULTATS == "/run/secubox/noeud-resultats"
    assert m.MODULE == "noeud" and m.REGLAGES == "/etc/secubox/noeud.toml" and m.ETAT_DIR == "/var/lib/secubox-noeud"
    for ligne in ("Type=oneshot", "ExecStartPre=+/usr/sbin/secubox-noeud prepare", "ExecStart=/usr/sbin/secubox-noeud traite",
                  "Environment=SBX_NOEUD_UNITE=1", "UMask=0027", "NoNewPrivileges=true", "ProtectSystem=strict",
                  "ProtectHome=true", "PrivateTmp=true", "ProtectKernelTunables=true", "ProtectControlGroups=true",
                  "RestrictSUIDSGID=true", "LockPersonality=true", "IPAddressDeny=any", "RestrictAddressFamilies=AF_UNIX",
                  "CapabilityBoundingSet=CAP_DAC_OVERRIDE CAP_DAC_READ_SEARCH CAP_CHOWN CAP_FOWNER",
                  "WantedBy=multi-user.target"):
        assert ligne in unite, ligne
    rw = re.search(r"^ReadWritePaths=(.+)$", unite, re.M).group(1).split()
    assert rw == ["/etc/secubox", "/etc/nginx/conf.d", "/var/log/secubox", "-/run/secubox/noeud",
                  "-/run/secubox/noeud-resultats"]
    rules = (PKG / "debian/rules").read_text()
    assert "systemd/secubox-noeud.path debian/secubox-core/usr/lib/systemd/system/secubox-noeud.path" in rules
    assert "systemd/secubox-noeud.service debian/secubox-core/usr/lib/systemd/system/secubox-noeud.service" in rules
    postinst = (PKG / "debian/postinst").read_text()
    # migration, puis appliquer et prepare, puis l'activation (deb-systemd-helper), le tout avant #DEBHELPER#
    i = [postinst.index(x) for x in ("! -e /etc/secubox/noeud.toml", "mv /var/lib/secubox-webos-noeud /var/lib/secubox-noeud",
                                     "/usr/sbin/secubox-noeud appliquer", "/usr/sbin/secubox-noeud prepare",
                                     "for _u in secubox-noeud.path secubox-noeud.service", "systemctl start secubox-noeud.path",
                                     "#DEBHELPER#")]
    assert i == sorted(i)
    assert "systemctl stop secubox-noeud.path secubox-noeud.service" in (PKG / "debian/prerm").read_text()
    postrm = (PKG / "debian/postrm").read_text()
    assert "deb-systemd-helper purge secubox-noeud.path secubox-noeud.service" in postrm
    control = (PKG / "debian/control").read_text()
    assert "Breaks: secubox-metrics (<< 1.12.9~), secubox-defaults (<< 1.0.3~), secubox-webos (<< 1.21.3~)" in control
    assert "Replaces: secubox-metrics (<< 1.12.9~), secubox-defaults (<< 1.0.3~), secubox-webos (<< 1.21.3~)" in control
    assert "relais_api = false" in (PKG / "etc/noeud.toml.example").read_text()
    regles = (RACINE / ".claude/RULES-CODE.md").read_text()
    ligne = next(x for x in regles.splitlines() if "secubox-noeud.service" in x)
    assert "§ 10" in ligne and "secubox-core/tests/test_relais_noeud_3824.py::test_unites_paquet_et_exception_ecrite" in ligne
    assert "webos-noeud.service" not in regles
    script = (PKG / "sbin/secubox-noeud").read_text()
    assert "shell=True" not in script and "waf_bypass" not in script and "sudo " not in script


# ── Passage de secubox-webos au cœur (#3883) ─────────────────────────────────────────────────────────────────

def test_vhost_pose_par_webos_reconnu_regenere_et_retirable(box):
    """Sur gk2, le vhost en place porte l'en-tête de webos-noeud : il est le nôtre, jamais « l'existant qui gagne »."""
    box.appliquer()
    nouveau = conf(box)
    ancien = nouveau.replace(box.ENTETE, box.ENTETE_WEBOS).replace("/www/noeud/sbx-dice.js", "/www/hall/sbx-dice.js") \
        .replace("/www/noeud/dice/", "/www/hall/dice/")
    assert ancien.startswith("# GÉNÉRÉ par /usr/sbin/webos-noeud (secubox-webos, #3821)")
    Path(box.CONF).write_text(ancien)
    assert box.noms_explicites(DOM) == []                      # notre fichier n'est jamais compté comme explicite
    assert box.etat_relais()["vhost"] is True
    box.appels.clear()
    assert box.appliquer() == 0 and conf(box) == nouveau       # réécrit au nouvel en-tête, le dé lu sous www/noeud
    assert ["systemctl", "reload", "nginx"] in box.appels
    Path(box.CONF).write_text(ancien)
    assert box.regenerer() is True and conf(box) == nouveau
    Path(box.CONF).write_text(ancien)
    assert box.retirer_conf() is True and conf(box) is None


def _migration(racine: Path) -> str:
    """Le bloc python du postinst qui crée noeud.toml, sur une racine d'essai."""
    texte = (PKG / "debian/postinst").read_text()
    code = texte.split("<<'MIGRATION'", 1)[1].split("\n", 1)[1].split("\nMIGRATION\n", 1)[0]
    assert code.count("/etc/secubox") >= 3
    return code.replace("/etc/secubox", str(racine / "etc/secubox"))


@pytest.mark.parametrize("webos,attendu", [
    (None, {"accueil": True, "relais_api": False}),                                   # box sans webos : défauts
    ("[webos]\nenabled = true\n", {"accueil": True, "relais_api": False}),
    ("[webos]\nenabled = true\n[noeud]\naccueil = true\nrelais_api = true\n", {"accueil": True, "relais_api": True}),
    ("[noeud]\naccueil = false\n", {"accueil": False, "relais_api": False}),
    ("[noeud]\nrelais_api = \"true\"\nautre = 1\n", {"accueil": True, "relais_api": False}),  # pas un booléen : défaut
    ("{illisible", {"accueil": True, "relais_api": False}),
])
def test_postinst_migre_noeud_toml_une_fois(tmp_path, webos, attendu):
    import subprocess
    import sys
    import tomllib
    (tmp_path / "etc/secubox").mkdir(parents=True)
    if webos is not None:
        (tmp_path / "etc/secubox/webos.toml").write_text(webos)
    subprocess.run([sys.executable, "-I", "-c", _migration(tmp_path)], check=True, timeout=30, capture_output=True)
    cree = tmp_path / "etc/secubox/noeud.toml"
    assert tomllib.loads(cree.read_text()) == {"noeud": attendu}
    assert stat.S_IMODE(cree.stat().st_mode) == 0o644
    assert sorted(p.name for p in (tmp_path / "etc/secubox").iterdir()) == sorted(
        ["noeud.toml"] + (["webos.toml"] if webos is not None else []))          # aucun fichier temporaire laissé
    if webos is not None:
        assert (tmp_path / "etc/secubox/webos.toml").read_text() == webos         # webos.toml jamais modifié
    # le réglage créé est celui que lit secubox-noeud, et la bascule le réécrit
    m = charger()
    m.REGLAGES = str(cree)
    assert m.accueil_voulu() is attendu["accueil"] and m.relais_voulu() is attendu["relais_api"]
    assert tomllib.loads(m.reglage_avec_relais(cree.read_text(), True))["noeud"]["relais_api"] is True
    # deuxième passage : un noeud.toml existant n'est jamais écrasé (le postinst ne lance le bloc que s'il est absent)
    cree.write_text("[noeud]\nrelais_api = true\n")
    r = subprocess.run([sys.executable, "-I", "-c", _migration(tmp_path)], timeout=30, capture_output=True)
    assert r.returncode != 0 and cree.read_text() == "[noeud]\nrelais_api = true\n"


def test_postinst_garde_de_la_migration():
    postinst = (PKG / "debian/postinst").read_text()
    assert "if [ ! -e /etc/secubox/noeud.toml ] && [ ! -L /etc/secubox/noeud.toml ]; then" in postinst
    bloc = postinst[postinst.index("if [ -d /var/lib/secubox-webos-noeud ]"):postinst.index("mv /var/lib/secubox-webos-noeud")]
    for garde in ("[ ! -L /var/lib/secubox-webos-noeud ]", '"$(stat -c %u /var/lib/secubox-webos-noeud)" = 0',
                  "[ ! -e /var/lib/secubox-noeud ]", "[ ! -L /var/lib/secubox-noeud ]"):
        assert garde in bloc, garde
