# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Direct (live) et purge des rediffusions (#3890).

`peertubectl direct activer|etat` et `peertubectl rediffusions purger
[--simuler]` contre une API PeerTube SIMULÉE (serveur HTTP local) : le vrai
peertubectl, le vrai curl, le vrai jq — seul PeerTube est factice.
"""
import copy
import json
import re
import subprocess
import threading
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import pytest

PKG = Path(__file__).resolve().parents[1]
CTL = PKG / "sbin" / "peertubectl"
MOT_DE_PASSE = "mdp-admin-ne-jamais-afficher"
JETON = "jeton-simule-0123456789"


def _date(jours):
    t = datetime.now(timezone.utc) - timedelta(days=jours)
    return t.strftime("%Y-%m-%dT%H:%M:%S.123Z")


def _uuid(n):
    return f"00000000-0000-4000-8000-{n:012d}"


CONFIG_INITIALE = {
    "instance": {"name": "gk1"},
    "transcoding": {"enabled": True, "webVideos": {"enabled": False}, "hls": {"enabled": True}},
    "live": {
        "enabled": False, "allowReplay": False, "latencySetting": {"enabled": True},
        "maxDuration": -1, "maxInstanceLives": 20, "maxUserLives": 3,
        "transcoding": {"enabled": True, "threads": 2, "profile": "default",
                        "resolutions": {"720p": True}, "alwaysTranscodeOriginalResolution": True,
                        "remoteRunners": {"enabled": False}, "fps": {"max": 60}},
        "dvr": {"maxWindow": 3600},
    },
    "defaults": {"live": {"saveReplay": False}},
}


class Etat:
    def __init__(self):
        self.config = copy.deepcopy(CONFIG_INITIALE)
        self.puts = []
        self.listes = []          # [{id, displayName, privacy}]
        self.elements = {}        # id liste -> [uuid]
        self.videos = []          # [{uuid, name, isLive, publishedAt}]
        self.sessions = {}        # uuid -> session (rediffusion)
        self.supprimees = []
        self.creations = []
        self.panne = None         # motif de chemin qui rend 500
        self.vus_auth = []
        self.relu_en_direct = set()  # uuid listés hors direct, mais en direct à la relecture
        self.sans_total = False      # « À garder » rendue sans .total
        self.total_en_plus = 0       # .total annoncé > éléments réellement rendus
        self.ajout_tardif = None     # uuid ajouté à « À garder » après la 1re lecture
        self.lectures_gardes = 0
        self.revocations = 0


def _serveur(etat):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _rep(self, code, corps=None):
            b = b"" if corps is None else json.dumps(corps).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)

        def _corps(self):
            n = int(self.headers.get("Content-Length") or 0)
            return self.rfile.read(n) if n else b""

        def _traite(self, meth):
            u = urlparse(self.path)
            p, q = u.path, parse_qs(u.query)
            corps = self._corps()
            if etat.panne and re.search(etat.panne, p) and meth == "GET":
                return self._rep(500, {"error": "panne simulée"})
            if p == "/api/v1/oauth-clients/local":
                return self._rep(200, {"client_id": "cid", "client_secret": "csec"})
            if p == "/api/v1/users/revoke-token" and meth == "POST":
                if self.headers.get("Authorization") == f"Bearer {JETON}":
                    etat.revocations += 1
                return self._rep(200, {})
            if p == "/api/v1/users/token" and meth == "POST":
                ok = MOT_DE_PASSE.encode() in corps
                return self._rep(200 if ok else 400, {"access_token": JETON} if ok else {})
            etat.vus_auth.append(self.headers.get("Authorization"))
            if self.headers.get("Authorization") != f"Bearer {JETON}":
                return self._rep(401, {"error": "auth"})
            if p == "/api/v1/config/custom":
                if meth == "GET":
                    return self._rep(200, etat.config)
                if meth == "PUT":
                    b = json.loads(corps)
                    etat.puts.append(b)
                    etat.config = b
                    return self._rep(200, b)
            if p == "/api/v1/accounts/root/video-playlists" and meth == "GET":
                return self._rep(200, {"total": len(etat.listes), "data": etat.listes})
            if p == "/api/v1/video-playlists" and meth == "POST":
                etat.creations.append(corps.decode("utf-8", "replace"))
                nid = 100 + len(etat.listes)
                nom = "À garder" if "À garder".encode() in corps else "?"
                etat.listes.append({"id": nid, "displayName": nom, "privacy": {"id": 3}})
                etat.elements[nid] = []
                return self._rep(200, {"videoPlaylist": {"id": nid}})
            m = re.fullmatch(r"/api/v1/video-playlists/(\d+)/videos", p)
            if m and meth == "GET":
                lid = int(m.group(1))
                start = int(q.get("start", ["0"])[0])
                count = min(int(q.get("count", ["15"])[0]), 100)
                if start == 0:
                    etat.lectures_gardes += 1
                    if etat.ajout_tardif and etat.lectures_gardes == 2:
                        etat.elements[lid].append(etat.ajout_tardif)
                uu = etat.elements.get(lid, [])
                data = [{"id": i, "position": i, "video": {"uuid": x}} for i, x in enumerate(uu)]
                data.append({"id": 999999, "position": 999999, "video": None})   # élément indisponible
                rep = {"data": data[start:start + count]}
                if not etat.sans_total:
                    rep["total"] = len(data) + etat.total_en_plus
                return self._rep(200, rep)
            if p == "/api/v1/videos" and meth == "GET":
                start = int(q.get("start", ["0"])[0])
                count = int(q.get("count", ["15"])[0])
                assert "privacyOneOf" in q and q.get("isLocal") == ["true"]
                # Le filtre isLive du serveur est volontairement ignoré : le
                # client doit écarter un direct en cours de lui-même.
                return self._rep(200, {"total": len(etat.videos),
                                       "data": etat.videos[start:start + count]})
            m = re.fullmatch(r"/api/v1/videos/([0-9a-f-]{36})/live-session", p)
            if m and meth == "GET":
                s = etat.sessions.get(m.group(1))
                return self._rep(200, s) if s else self._rep(404, {"detail": "No live replay found"})
            m = re.fullmatch(r"/api/v1/videos/([0-9a-f-]{36})", p)
            if m:
                v = next((v for v in etat.videos if v["uuid"] == m.group(1)), None)
                if v is None:
                    return self._rep(404, {})
                if meth == "GET":
                    return self._rep(200, dict(v, isLive=v["uuid"] in etat.relu_en_direct or v["isLive"]))
                if meth == "DELETE":
                    etat.supprimees.append(m.group(1))
                    etat.videos.remove(v)
                    return self._rep(204)
            return self._rep(404, {"error": f"inconnu {meth} {p}"})

        def do_GET(self):
            self._traite("GET")

        def do_POST(self):
            self._traite("POST")

        def do_PUT(self):
            self._traite("PUT")

        def do_DELETE(self):
            self._traite("DELETE")

    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


@pytest.fixture
def pt(tmp_path):
    etat = Etat()
    srv = _serveur(etat)
    secret = tmp_path / "peertube-admin"
    secret.write_text(MOT_DE_PASSE + "\n")
    secret.chmod(0o600)
    toml = tmp_path / "peertube.toml"
    toml.write_text(
        "[lxc]\nname = \"peertube\"\nip = \"127.0.0.1\"\n"
        f"path = \"{tmp_path / 'lxc'}\"\n"
        f"[peertube]\nhttp_port = {srv.server_address[1]}\n"
        "[exposure]\npublic_hostname = \"peertube.test\"\n"
        "[direct]\njours_conservation = 7\n")
    audit = tmp_path / "audit.log"
    (tmp_path / "lxc" / "peertube").mkdir(parents=True)
    (tmp_path / "lxc" / "peertube" / "config").write_text("lxc.uts.name = peertube\n")
    env = {
        "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
        "HOME": str(tmp_path),
        "SECUBOX_PEERTUBE_CONFIG": str(toml),
        "SECUBOX_PEERTUBE_ADMIN_SECRET": str(secret),
        "SECUBOX_AUDIT_LOG": str(audit),
    }

    def run(*args):
        r = subprocess.run(["bash", str(CTL), *args], capture_output=True, text=True,
                           env=env, timeout=120)
        # Jamais de secret à l'écran ni dans l'audit.
        for txt in (r.stdout, r.stderr, audit.read_text() if audit.exists() else ""):
            assert MOT_DE_PASSE not in txt and JETON not in txt
        return r

    etat.run = run
    etat.audit = audit
    etat.toml = toml
    etat.lxc = tmp_path / "lxc" / "peertube"
    yield etat
    srv.shutdown()


def _audit(etat):
    if not etat.audit.exists():
        return []
    return [json.loads(x) for x in etat.audit.read_text().splitlines() if x.strip()]


# ── direct activer / etat ────────────────────────────────────────────────

def test_activer_ne_change_que_la_section_live(pt):
    r = pt.run("direct", "activer")
    assert r.returncode == 0, r.stderr
    assert len(pt.puts) == 1
    envoye = pt.puts[0]
    avant = copy.deepcopy(CONFIG_INITIALE)
    # Tout ce qui n'est pas .live est rendu à l'identique.
    assert {k: v for k, v in envoye.items() if k != "live"} == \
           {k: v for k, v in avant.items() if k != "live"}
    live = envoye["live"]
    assert live["enabled"] is True and live["allowReplay"] is True
    assert live["transcoding"]["enabled"] is False
    assert live["maxDuration"] == 6 * 3600 * 1000      # millisecondes
    assert live["maxInstanceLives"] == 2 and live["maxUserLives"] == 1
    # Le reste de .live intact (DVR, latence, profil du transcodage).
    assert live["dvr"] == avant["live"]["dvr"]
    assert live["latencySetting"] == avant["live"]["latencySetting"]
    assert live["transcoding"]["resolutions"] == avant["live"]["transcoding"]["resolutions"]
    a = [x for x in _audit(pt) if x["action"] == "direct-activer"]
    assert a and a[-1]["resultat"] == "applique" and a[-1]["module"] == "peertube"


def test_activer_cree_la_liste_a_garder_privee_une_seule_fois(pt):
    assert pt.run("direct", "activer").returncode == 0
    assert len(pt.creations) == 1
    c = pt.creations[0]
    assert "À garder" in c and 'name="privacy"' in c and "\r\n3\r\n" in c
    # Idempotent : ni second PUT, ni seconde liste.
    r = pt.run("direct", "activer")
    assert r.returncode == 0, r.stderr
    assert len(pt.puts) == 1 and len(pt.creations) == 1
    assert "déjà réglé" in r.stdout


def test_activer_refuse_sans_transcodage_des_videos(pt):
    # PeerTube rendrait 400 (allowReplay exige transcoding.enabled) : rien n'est écrit.
    pt.config["transcoding"]["enabled"] = False
    r = pt.run("direct", "activer")
    assert r.returncode != 0
    assert pt.puts == [] and pt.creations == []


def test_etat_en_json(pt):
    pt.run("direct", "activer")
    r = pt.run("direct", "etat")
    assert r.returncode == 0, r.stderr
    d = json.loads(r.stdout)
    assert d["live"]["enabled"] is True and d["live"]["transcoding"]["enabled"] is False
    assert d["liste_a_garder"] is True and d["jours_conservation"] == 7
    assert len(pt.puts) == 1          # etat n'écrit rien


# ── rediffusions purger ──────────────────────────────────────────────────

def _peupler(pt, garder_id=100):
    pt.listes.append({"id": garder_id, "displayName": "À garder", "privacy": {"id": 3}})
    pt.listes.append({"id": 101, "displayName": "À garder plus tard", "privacy": {"id": 3}})
    V = pt.videos
    titre_long = 'Direct "du soir" — ' + "x" * 100

    def video(n, jours, titre, live=False):
        V.append({"uuid": _uuid(n), "name": titre, "isLive": live, "publishedAt": _date(jours)})

    def session(n, fin_jours):
        pt.sessions[_uuid(n)] = {"id": n, "startDate": _date((fin_jours or 0) + 0.1),
                                 "endDate": None if fin_jours is None else _date(fin_jours),
                                 "replayVideo": {"uuid": _uuid(n)}}

    # (n, âge de publication en jours, titre, isLive, fin de session : jours / None / absente)
    SANS = object()
    for n, jours, titre, live, fin in (
        (1, 10, "rediffusion vieille", False, 10),             # effacée
        (2, 10, "rediffusion gardée", False, 10),              # dans « À garder »
        (3, 3, "rediffusion récente", False, 3),               # < 7 jours
        (4, 30, "téléversée", False, SANS),                    # 404 live-session
        (5, 30, "direct en cours", True, 25),                  # isLive (session passée finie)
        (6, 10, "direct permanent fini il y a 2 j", False, 2),
        (7, 20, titre_long, False, 20),                        # effacée, titre tronqué
        (8, 12, "session sans fin", False, None),              # endDate absent
        (9, 15, "redevenu direct à la relecture", False, 15),  # isLive à GET /videos/{id}
    ):
        video(n, jours, titre, live)
        if fin is not SANS:
            session(n, fin)
    pt.relu_en_direct.add(_uuid(9))
    pt.elements[garder_id] = [_uuid(2)]
    pt.elements[101] = [_uuid(1)]                                  # autre liste : ne protège pas


def test_purge_efface_seulement_les_vieilles_rediffusions_non_gardees(pt):
    _peupler(pt)
    r = pt.run("rediffusions", "purger")
    assert r.returncode == 0, r.stderr
    assert sorted(pt.supprimees) == [_uuid(1), _uuid(7)]
    out = json.loads(r.stdout.strip().splitlines()[-1])
    assert out["simulation"] is False and out["traitees"] == 2
    lignes = [x for x in _audit(pt)
              if x["action"] == "rediffusion-supprimee" and x["resultat"] == "supprimee"]
    assert {x["uuid"] for x in lignes} == {_uuid(1), _uuid(7)}
    for x in lignes:
        assert x["resultat"] == "supprimee" and x["module"] == "peertube"
        assert len(x["titre"]) <= 60 and x["age_jours"] >= 7
    l7 = next(x for x in lignes if x["uuid"] == _uuid(7))
    assert l7["titre"].startswith('Direct "du soir"') and l7["age_jours"] in (19, 20)


def test_simuler_n_efface_rien(pt):
    _peupler(pt)
    r = pt.run("rediffusions", "purger", "--simuler")
    assert r.returncode == 0, r.stderr
    assert pt.supprimees == []
    assert _uuid(1) in r.stdout and _uuid(7) in r.stdout
    assert _uuid(2) not in r.stdout.replace(json.dumps(_uuid(2)), "")
    out = json.loads(r.stdout.strip().splitlines()[-1])
    assert out["simulation"] is True and len(out["rediffusions"]) == 2
    assert not [x for x in _audit(pt) if x["action"] == "rediffusion-supprimee"]


@pytest.mark.parametrize("panne", [
    r"/live-session$",                 # session de direct
    r"/video-playlists/\d+/videos$",   # liste « À garder »
    r"^/api/v1/videos$",               # liste des vidéos
    r"/accounts/root/video-playlists", # listes du compte
])
def test_echec_api_n_efface_rien(pt, panne):
    _peupler(pt)
    pt.panne = panne
    r = pt.run("rediffusions", "purger")
    assert r.returncode != 0
    assert pt.supprimees == []


def test_sans_liste_a_garder_rien_n_est_efface(pt):
    _peupler(pt)
    pt.listes = [x for x in pt.listes if x["displayName"] != "À garder"]
    r = pt.run("rediffusions", "purger")
    assert r.returncode != 0 and pt.supprimees == []


def test_jours_conservation_reglable(pt, tmp_path):
    _peupler(pt)
    toml = tmp_path / "peertube.toml"
    toml.write_text(toml.read_text().replace("jours_conservation = 7", "jours_conservation = 15"))
    r = pt.run("rediffusions", "purger")
    assert r.returncode == 0, r.stderr
    assert pt.supprimees == [_uuid(7)]


def test_jours_conservation_invalide_refuse(pt, tmp_path):
    _peupler(pt)
    toml = tmp_path / "peertube.toml"
    toml.write_text(toml.read_text().replace("jours_conservation = 7", "jours_conservation = 0"))
    assert pt.run("rediffusions", "purger").returncode != 0
    assert pt.supprimees == []


def test_option_inconnue_refusee(pt):
    assert pt.run("rediffusions", "purger", "--force").returncode != 0
    assert pt.run("rediffusions").returncode != 0
    assert pt.run("direct", "eteindre").returncode != 0


# ── unités et paquet ─────────────────────────────────────────────────────

def test_unites_minuterie_et_postinst():
    svc = (PKG / "debian" / "secubox-peertube-rediffusions.service").read_text()
    tim = (PKG / "debian" / "secubox-peertube-rediffusions.timer").read_text()
    assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in svc and "SPDX" in tim
    assert "Type=oneshot" in svc
    assert "ExecStart=/usr/sbin/peertubectl rediffusions purger --minuterie" in svc.splitlines()
    for d in ("IPAddressDeny=any", "IPAddressAllow=10.100.0.120/32",
              "SystemCallFilter=@system-service"):
        assert d in svc.splitlines(), d
    assert "#3894" in svc
    for d in ("User=secubox", "NoNewPrivileges=yes", "ProtectSystem=strict",
              "ReadWritePaths=/var/log/secubox", "ProtectHome=yes", "PrivateTmp=yes",
              "ProtectKernelTunables=yes", "ProtectControlGroups=yes",
              "RestrictSUIDSGID=yes", "LockPersonality=yes", "UMask=0027"):
        assert d in svc.splitlines(), d
    assert "--simuler" not in svc
    assert "OnCalendar=" in tim and "Persistent=true" in tim and "WantedBy=timers.target" in tim
    rules = (PKG / "debian" / "rules").read_text()
    assert "debian/secubox-peertube-rediffusions.service" in rules
    assert "debian/secubox-peertube-rediffusions.timer" in rules
    post = (PKG / "debian" / "postinst").read_text()
    assert "deb-systemd-helper enable secubox-peertube-rediffusions.timer" in post
    assert "deb-systemd-invoke start secubox-peertube-rediffusions.timer" in post
    assert post.index("rediffusions.timer") < post.index("#DEBHELPER#")
    assert "systemctl stop secubox-peertube-rediffusions.service" in (PKG / "debian" / "prerm").read_text()
    ctrl = (PKG / "debian" / "control").read_text()
    assert re.search(r"\bjq\b", ctrl) and re.search(r"\bcurl\b", ctrl)
    assert "[direct]" in (PKG / "conf" / "peertube.toml.example").read_text()
    assert "jours_conservation      = 7" in (PKG / "conf" / "peertube.toml.example").read_text()


def test_save_config_garde_la_section_direct(tmp_path, monkeypatch):
    from api import main as m
    f = tmp_path / "peertube.toml"
    f.write_text("[lxc]\nname = \"peertube\"\n[direct]\njours_conservation = 9\n")
    monkeypatch.setattr(m, "CONFIG_FILE", f)
    cfg = m.get_config()
    assert cfg["jours_conservation"] == 9
    m.save_config(cfg)
    assert "[direct]" in f.read_text() and "jours_conservation = 9" in f.read_text()


# ── corrections de la relecture (#3890) ──────────────────────────────────

def test_jeton_revoque_en_fin_de_passe(pt):
    _peupler(pt)
    assert pt.run("rediffusions", "purger", "--simuler").returncode == 0
    assert pt.revocations == 1
    pt.panne = r"/live-session$"
    assert pt.run("rediffusions", "purger").returncode != 0
    assert pt.revocations == 2                     # aussi après une erreur


def test_minuterie_sans_conteneur_rien_a_faire(pt):
    _peupler(pt)
    (pt.lxc / "config").unlink()
    r = pt.run("rediffusions", "purger", "--minuterie")
    assert r.returncode == 0, r.stderr
    assert "rien à faire" in r.stdout
    assert pt.supprimees == [] and _audit(pt) == [] and pt.vus_auth == []


def test_minuterie_sans_liste_rien_a_faire_mais_refus_a_la_main(pt):
    _peupler(pt)
    pt.listes = [x for x in pt.listes if x["displayName"] != "À garder"]
    r = pt.run("rediffusions", "purger", "--minuterie")
    assert r.returncode == 0, r.stderr
    assert "rien à faire" in r.stdout and _audit(pt) == [] and pt.supprimees == []
    assert pt.run("rediffusions", "purger").returncode != 0


def test_minuterie_erreur_api_sort_en_echec(pt):
    _peupler(pt)
    pt.panne = r"^/api/v1/videos$"
    r = pt.run("rediffusions", "purger", "--minuterie")
    assert r.returncode != 0 and pt.supprimees == []


def test_minuterie_purge_normalement(pt):
    _peupler(pt)
    r = pt.run("rediffusions", "purger", "--minuterie")
    assert r.returncode == 0, r.stderr
    assert sorted(pt.supprimees) == [_uuid(1), _uuid(7)]


def test_a_garder_plus_de_100_elements_lus_en_entier(pt):
    _peupler(pt)
    # La vidéo 1 (effaçable) est en position 150 : seule une lecture paginée la sauve.
    pt.elements[100] = [_uuid(5000 + i) for i in range(149)] + [_uuid(1), _uuid(2)]
    r = pt.run("rediffusions", "purger")
    assert r.returncode == 0, r.stderr
    assert pt.supprimees == [_uuid(7)]


@pytest.mark.parametrize("defaut", ["sans_total", "total_en_plus"])
def test_a_garder_lecture_incomplete_rien_n_est_efface(pt, defaut):
    _peupler(pt)
    if defaut == "sans_total":
        pt.sans_total = True
    else:
        pt.total_en_plus = 5
    r = pt.run("rediffusions", "purger")
    assert r.returncode != 0
    assert pt.supprimees == []
    assert not [x for x in _audit(pt) if x["action"] == "rediffusion-supprimee"]


def test_ajoutee_a_garder_entre_temps_non_effacee(pt):
    _peupler(pt)
    pt.ajout_tardif = _uuid(7)          # ajoutée après la première lecture
    r = pt.run("rediffusions", "purger")
    assert r.returncode == 0, r.stderr
    assert pt.supprimees == [_uuid(1)]
    assert "gardée entre-temps" in r.stdout


def test_audit_intention_avant_resultat(pt):
    _peupler(pt)
    assert pt.run("rediffusions", "purger").returncode == 0
    lignes = [(x["uuid"], x["resultat"]) for x in _audit(pt) if x["action"] == "rediffusion-supprimee"]
    for u in (_uuid(1), _uuid(7)):
        assert lignes.index((u, "intention")) < lignes.index((u, "supprimee"))


@pytest.mark.parametrize("args", [(), ("--simuler",)])
def test_titres_sans_caracteres_de_controle(pt, args):
    _peupler(pt)
    pt.videos[0]["name"] = "pi\x1b[31mège\nfausse ligne\r\x07"
    r = pt.run("rediffusions", "purger", *args)
    assert r.returncode == 0, r.stderr
    sortie = r.stdout + r.stderr + (pt.audit.read_text() if pt.audit.exists() else "")
    sortie_sans_couleurs = re.sub(r"\x1b\[[0-9;]*m", "", sortie.replace("\x1b[0;32m", "").replace("\x1b[0m", ""))
    assert "\x1b[31m" not in sortie and "\x07" not in sortie and "\r" not in sortie
    assert "fausse ligne" in sortie_sans_couleurs
    assert not any(ligne.startswith("fausse ligne") for ligne in sortie.splitlines())


def test_entiers_en_base_10(pt):
    _peupler(pt)
    t = pt.toml.read_text().replace("jours_conservation = 7", "jours_conservation = \"08\"")
    pt.toml.write_text(t + "duree_max_heures = 08\ndirects_max_instance = 02\n")
    r = pt.run("rediffusions", "purger", "--simuler")
    assert r.returncode == 0, r.stderr
    out = json.loads(r.stdout.strip().splitlines()[-1])
    assert out["jours_conservation"] == 8
    assert {x["uuid"] for x in out["rediffusions"]} == {_uuid(1), _uuid(7)}
    r = pt.run("direct", "activer")
    assert r.returncode == 0, r.stderr
    assert pt.puts[-1]["live"]["maxDuration"] == 8 * 3600 * 1000
    assert pt.puts[-1]["live"]["maxInstanceLives"] == 2


def _postinst_dropin(tmp_path, ip_toml):
    post = (PKG / "debian" / "postinst").read_text()
    debut = post.index("    _dropin=")
    fin = post.index("    fi\n", debut) + len("    fi\n")
    bloc = post[debut:fin]
    dropin = tmp_path / "etc" / "10-ip-lxc.conf"
    toml = tmp_path / "pt.toml"
    toml.write_text(f'[lxc]\nname = "peertube"\nip   = "{ip_toml}"  # commentaire\n')
    bloc = bloc.replace("/etc/systemd/system/secubox-peertube-rediffusions.service.d/10-ip-lxc.conf",
                        str(dropin)).replace("/etc/secubox/peertube.toml", str(toml))
    subprocess.run(["sh", "-c", bloc], check=True, timeout=10, capture_output=True, text=True)
    return dropin


def test_postinst_drop_in_ip_du_conteneur(tmp_path):
    d = _postinst_dropin(tmp_path, "10.100.0.130")
    lignes = d.read_text().splitlines()
    assert lignes[-2:] == ["IPAddressAllow=", "IPAddressAllow=10.100.0.130/32"]
    d = _postinst_dropin(tmp_path, "10.100.0.120")      # adresse par défaut : pas de drop-in
    assert not d.exists()
    d = _postinst_dropin(tmp_path, "pas-une-ip")
    assert not d.exists()
