# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: secubox-dpi — ce que la fusion aff481735 avait effacé (#1775)

La fusion du 2026-08-17 a remis dans api/main.py une version de juin : /exfil
servait de nouveau la seule fenêtre live (sans bloc `engine`), /media_types
et tout le tampon média (/media/buffer, /media/replay, /media/thumb) avaient
disparu — la page www/dpi/index.html les appelait toujours, dans le vide.

Ces tests fixent :
  - la GARDE DE PAGE : chaque route que la page appelle existe dans l'API ;
  - /exfil : cumul + fenêtre live + vivacité du moteur ;
  - le tampon média : relecture réservée à l'admin réel, auditée, jamais
    servie sans trace, jamais servie avec un Content-Type exécutable ;
  - ce que la restauration ne devait PAS défaire (lecture gardée #1256,
    contrôle de service retiré avec netifyd).
"""
import inspect
import json
import re
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # api importable
from fastapi.testclient import TestClient  # noqa: E402
from secubox_core.auth import ENTETE_LAN, require_jwt  # noqa: E402
from api import main as m  # noqa: E402

PAGE = Path(__file__).resolve().parents[1] / "www" / "dpi" / "index.html"

LIVE_ID = "aabbccdd1122"
LIVE_SESSION = "aabbccdd11223344"
MANIFEST_ID = "aaaa11112222"
MANIFEST_SESSION = "aaaa1111222233334444"


# ── Garde de page ───────────────────────────────────────────────────────────
def _norme(chemin: str) -> str:
    """/media/replay/{rec_id} et /media/replay/{} se comparent à l'identique."""
    return re.sub(r"\{[^}]*\}", "{}", chemin.split("?", 1)[0])


def _appels_de_la_page() -> set:
    """(méthode, chemin normalisé) de chaque appel à /api/v1/dpi de la page."""
    html = PAGE.read_text(encoding="utf-8")
    appels = set()
    for chemin, methode in re.findall(r"\bapi\(\s*'([^']+)'(?:\s*,\s*'([A-Z]+)')?", html):
        appels.add((methode or "GET", _norme(chemin)))
    for chemin in re.findall(r"\bapiAuthed\(\s*API\s*\+\s*'([^']+)'", html):
        appels.add(("GET", _norme(chemin)))
    for chemin in re.findall(r"\bpostJwt\(\s*API\s*\+\s*'([^']+)'", html):
        appels.add(("POST", _norme(chemin)))
    # URL construite : API + '/media/replay/' + encodeURIComponent(id) → GET.
    for chemin in re.findall(r"API\s*\+\s*'([^']+/)'\s*\+\s*encodeURIComponent", html):
        appels.add(("GET", _norme(chemin) + "{}"))
    # Rien ne doit échapper aux motifs ci-dessus : toute concaténation
    # « API + '…' » de la page doit avoir été reconnue.
    reconnus = {c for _, c in appels}
    for chemin in re.findall(r"API\s*\+\s*'([^']+)'", html):
        c = _norme(chemin)
        assert c in reconnus or c + "{}" in reconnus, \
            f"appel non reconnu par la garde de page : {chemin!r} — étendre _appels_de_la_page"
    return appels


def _routes_de_l_api() -> set:
    """(méthode, chemin normalisé) de chaque route servie. Lu dans le schéma
    OpenAPI plutôt que dans `app.routes` : depuis FastAPI 0.14x, un routeur
    inclus y reste un nœud opaque (_IncludedRouter) au lieu d'être aplati."""
    routes = set()
    for chemin, ops in m.app.openapi()["paths"].items():
        for methode in ops:
            routes.add((methode.upper(), _norme(chemin)))
    return routes


def test_la_garde_de_page_voit_les_appels_attendus():
    """Garde de la garde : si les motifs cessent de reconnaître la page, le
    test suivant passerait à vide."""
    appels = _appels_de_la_page()
    for attendu in [("GET", "/exfil"), ("GET", "/media_types"), ("GET", "/history"),
                    ("GET", "/media/buffer"), ("GET", "/media/replay/{}"),
                    ("POST", "/rules/accept"), ("GET", "/suggestions")]:
        assert attendu in appels, attendu


@pytest.mark.parametrize("appel", sorted(_appels_de_la_page()), ids=lambda a: f"{a[0]} {a[1]}")
def test_chaque_route_appelee_par_la_page_existe(appel):
    assert appel in _routes_de_l_api(), f"la page appelle {appel[0]} {appel[1]}, absente de l'API"


# ── /exfil : cumul + fenêtre live + moteur ──────────────────────────────────
def _collector(tmp_path, monkeypatch, cumul=None, etat=None):
    c, s = tmp_path / "cumulative.json", tmp_path / "state.json"
    if cumul is not None:
        c.write_text(json.dumps(cumul))
    if etat is not None:
        s.write_text(json.dumps(etat))
    monkeypatch.setattr(m, "COLLECTOR_CUMUL", c, raising=False)
    monkeypatch.setattr(m, "COLLECTOR_STATE", s, raising=False)


def test_exfil_terminaux_du_cumul_flux_de_la_fenetre_live(tmp_path, monkeypatch):
    now = int(time.time())
    _collector(tmp_path, monkeypatch,
               cumul={"generated_at": now - 5, "alert_count": 1,
                      "devices": [{"device": "d1", "flows": 7, "services": []}],
                      "alerts": [{"kind": "new_cloud", "device": "d1"}],
                      "active_flows": [{"dst": "périmé"}]},
               etat={"generated_at": now - 30, "devices": [],
                     "active_flows": [{"dst": "live.example", "up_bytes": 1}]})
    body = TestClient(m.app).get("/exfil").json()
    # Les terminaux viennent du CUMUL, pas de la fenêtre live vide.
    assert [d["device"] for d in body["devices"]] == ["d1"]
    assert body["alert_count"] == 1
    # La fenêtre live superpose ses flux actifs.
    assert body["active_flows"] == [{"dst": "live.example", "up_bytes": 1}]
    eng = body["engine"]
    assert eng["alive"] is True
    assert eng["service"] == "secubox-dpi-flowcap"
    assert 25 <= eng["last_window_s"] <= 60
    assert "note" not in body


def test_exfil_moteur_idle_quand_la_fenetre_est_vieille(tmp_path, monkeypatch):
    _collector(tmp_path, monkeypatch, cumul={"devices": []},
               etat={"generated_at": int(time.time()) - 1000, "active_flows": []})
    body = TestClient(m.app).get("/exfil").json()
    assert body["engine"]["alive"] is False
    assert body["engine"]["last_window_s"] >= 1000
    assert body["devices"] == [] and "note" in body


def test_exfil_fail_empty_sans_aucun_fichier(tmp_path, monkeypatch):
    _collector(tmp_path, monkeypatch)
    r = TestClient(m.app).get("/exfil")
    assert r.status_code == 200
    body = r.json()
    assert body["devices"] == [] and body["active_flows"] == []
    assert body["engine"] == {"name": "ndpiReader · R3 exfil",
                              "service": "secubox-dpi-flowcap",
                              "alive": False, "last_window_s": None}


# ── Ce que la restauration ne devait pas défaire ────────────────────────────
@pytest.mark.parametrize("chemin", ["/exfil", "/history", "/media_types"])
def test_lecture_gardee_hors_lan_sans_jeton(chemin):
    """#1256 : lecture de tableau de bord = jeton, ou LAN en mode armé."""
    r = TestClient(m.app).get(chemin, headers={ENTETE_LAN: "0"})
    assert r.status_code == 401


@pytest.mark.parametrize("nom", ["exfil_state", "exfil_history", "media_types",
                                 "realtime", "block_rules", "add_block_rule",
                                 "delete_block_rule", "media_buffer_list",
                                 "media_replay", "media_thumb"])
def test_les_handlers_a_io_bloquante_sont_des_def(nom):
    """#808 : un `async def` qui lit un fichier fige la boucle de l'agrégateur."""
    fn = getattr(m, nom)
    assert not inspect.iscoroutinefunction(fn), f"{nom} doit être un def"


@pytest.fixture
def admin(monkeypatch):
    """Session d'administrateur réel (root, du registre du conftest)."""
    monkeypatch.setitem(m.app.dependency_overrides, require_jwt, lambda: {"sub": "root"})


@pytest.mark.parametrize("chemin", ["/restart", "/start", "/stop"])
def test_controle_de_service_reste_retire(admin, chemin):
    """5c8d5b34b : le contrôle de service legacy est retiré exprès."""
    assert TestClient(m.app).post(chemin).json() == {"success": False, "retired": True}


# ── Tampon média : accès, audit, types servis ───────────────────────────────
def _seed(tmp_path, monkeypatch, host="cdn.example", ctype="video/mp4",
          kind="video", ext="mp4", contenu=b"hello"):
    rec = {"id": LIVE_ID, "session_id": LIVE_SESSION, "first_ts": 2, "last_ts": 2,
           "mac_hash": "m1", "host": host, "url": "https://cdn.example/v",
           "direction": "down", "kind": kind, "ctype": ctype, "bytes": len(contenu),
           "segments": 0, "truncated": False, "buffer_ref": LIVE_SESSION,
           "expired": False}
    (tmp_path / "media-buffer.jsonl").write_text(json.dumps(rec) + "\n")
    (tmp_path / LIVE_SESSION).mkdir()
    (tmp_path / LIVE_SESSION / f"object-0.{ext}").write_bytes(contenu)
    monkeypatch.setattr(m, "MEDIA_BUFFER_ROOT", str(tmp_path), raising=False)


@pytest.mark.parametrize("chemin", ["/media/buffer", f"/media/replay/{LIVE_ID}",
                                    f"/media/thumb/{LIVE_ID}"])
def test_tampon_media_sans_jeton_401(tmp_path, monkeypatch, chemin):
    """Le mode tableau de bord LAN n'ouvre PAS le tampon média."""
    _seed(tmp_path, monkeypatch)
    assert TestClient(m.app).get(chemin).status_code == 401


@pytest.mark.parametrize("porteur", [
    {"sub": "bob"},                              # simple usager
    {"sub": "bob", "role": "admin"},             # revendication non vérifiée
    {"sub": "sbx-0123456789abcdef", "role": "admin"},  # session d'appareil
])
def test_relecture_refusee_a_qui_n_est_pas_admin_reel(tmp_path, monkeypatch,
                                                      registre_et_audit, porteur):
    """Même si la garde amont laissait passer (dépendance remplacée ici), la
    garde du tampon refuse — et rien n'est journalisé ni servi."""
    _seed(tmp_path, monkeypatch)
    monkeypatch.setitem(m.app.dependency_overrides, require_jwt, lambda: dict(porteur))
    c = TestClient(m.app)
    assert c.get(f"/media/replay/{LIVE_ID}").status_code == 403
    assert c.get(f"/media/thumb/{LIVE_ID}").status_code == 403
    assert c.get("/media/buffer").json() == {"items": [], "count": 0}
    assert not registre_et_audit.exists()


def test_relecture_admin_servie_et_auditee(tmp_path, monkeypatch, admin, registre_et_audit):
    _seed(tmp_path, monkeypatch)
    c = TestClient(m.app)
    assert c.get("/media/buffer").json()["count"] == 1
    r = c.get(f"/media/replay/{LIVE_ID}",
              headers={"X-Forwarded-For": "6.6.6.6, 203.0.113.9"})
    assert r.status_code == 200 and r.content == b"hello"
    assert r.headers["content-type"].startswith("video/mp4")
    assert r.headers["x-content-type-options"] == "nosniff"
    lignes = registre_et_audit.read_text().splitlines()
    assert len(lignes) == 1
    assert " media-replay sub=root " in lignes[0]
    assert f"rec_id={LIVE_ID}" in lignes[0] and "host=cdn.example" in lignes[0]
    # Adresse lue depuis la DROITE de X-Forwarded-For (#1753), pas la forgée.
    assert lignes[0].endswith("ip=203.0.113.9")


def test_pas_de_relecture_sans_trace(tmp_path, monkeypatch, admin):
    """Journal d'audit non inscriptible → 503, aucun octet servi."""
    _seed(tmp_path, monkeypatch)
    dossier = tmp_path / "pas-un-fichier"
    dossier.mkdir()
    monkeypatch.setattr(m, "AUDIT_LOG", str(dossier), raising=False)
    r = TestClient(m.app).get(f"/media/replay/{LIVE_ID}")
    assert r.status_code == 503
    assert b"hello" not in r.content


def test_hote_capture_ne_forge_pas_de_ligne_d_audit(tmp_path, monkeypatch, admin,
                                                    registre_et_audit):
    _seed(tmp_path, monkeypatch, host="evil.example\n2026-01-01T00:00:00 media-replay sub=admin")
    assert TestClient(m.app).get(f"/media/replay/{LIVE_ID}").status_code == 200
    lignes = registre_et_audit.read_text().splitlines()
    assert len(lignes) == 1 and lignes[0].count("media-replay") == 2  # 2e = dans host, neutralisé
    assert "sub=root" in lignes[0]


@pytest.mark.parametrize("ctype,attendu", [
    ("text/html", "application/octet-stream"),
    ("image/svg+xml", "application/octet-stream"),
    ("application/dash+xml", "application/octet-stream"),
    ("video/mp4\r\nSet-Cookie: x=1", "application/octet-stream"),
    ("", "application/octet-stream"),
    ("video/mp4; codecs=avc1", "video/mp4"),
    ("AUDIO/MPEG", "audio/mpeg"),
    ("application/vnd.apple.mpegurl", "application/vnd.apple.mpegurl"),
])
def test_type_capture_jamais_executable(tmp_path, monkeypatch, ctype, attendu):
    """Un Content-Type capturé (donc choisi par un tiers) ne doit jamais faire
    rendre du HTML/SVG sur l'origine d'administration."""
    _seed(tmp_path, monkeypatch, ctype=ctype, kind="file", ext="bin",
          contenu=b"<script>alert(1)</script>")
    resp = m.media_replay(LIVE_ID, request=None, user={"sub": "root"})
    assert resp.media_type == attendu
    assert resp.headers["x-content-type-options"] == "nosniff"


def test_manifeste_audite_une_seule_fois(tmp_path, monkeypatch, admin, registre_et_audit):
    rec = {"id": MANIFEST_ID, "session_id": MANIFEST_SESSION, "first_ts": 3, "last_ts": 3,
           "mac_hash": "m1", "host": "h", "url": "https://h/hls/index.m3u8",
           "direction": "down", "kind": "manifest",
           "ctype": "application/vnd.apple.mpegurl", "bytes": 5, "segments": 0,
           "truncated": False, "buffer_ref": MANIFEST_SESSION, "expired": False}
    (tmp_path / "media-buffer.jsonl").write_text(json.dumps(rec) + "\n")
    (tmp_path / MANIFEST_SESSION).mkdir()
    (tmp_path / MANIFEST_SESSION / "object-0.m3u8").write_text(
        "#EXTM3U\n#EXTINF:6.0,\nseg0.ts\n#EXT-X-ENDLIST\n")
    monkeypatch.setattr(m, "MEDIA_BUFFER_ROOT", str(tmp_path), raising=False)
    r = TestClient(m.app).get(f"/media/replay/{MANIFEST_ID}")
    assert r.status_code == 200
    assert "hls-reassembled" in r.headers["x-secubox-media"]
    assert len(registre_et_audit.read_text().splitlines()) == 1


@pytest.mark.parametrize("chemin", ["/usage", "/suggestions", "/sessions", "/clients", "/countries"])
def test_panneaux_lives_ne_levent_plus(chemin, monkeypatch):
    """#1775 : une seconde `_sbxdpi_get(path)` écrasait `_sbxdpi_get(path,
    default)` — ces cinq routes levaient TypeError (500), les panneaux
    Apprentissage, Sessions et Pays restaient vides sans erreur visible."""
    from secubox_core.auth import require_jwt, require_lecture
    m.app.dependency_overrides[require_jwt] = lambda: {"sub": "root"}
    m.app.dependency_overrides[require_lecture] = lambda: {"sub": "root"}
    monkeypatch.setattr(m, "DPI_LIVE_SOCK", "/nonexistent/dpi-live.sock")
    try:
        r = TestClient(m.app).get(chemin)
    finally:
        m.app.dependency_overrides.clear()
    assert r.status_code != 500, (chemin, r.text[:200])
