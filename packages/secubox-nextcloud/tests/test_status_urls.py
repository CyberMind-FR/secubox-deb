# SPDX-License-Identifier: LicenseRef-CMSD-1.0
"""/status, /connections, /storage — sur l'architecture actuelle (#1757).

Réalignés : la conception d'avant (cache à la requête `_cached`,
`ctl status --json` sur le chemin de /status, `container_reachable`,
`public_url`) est partie avec l'orage d'occ (2ad3c001a). La marche se juge
par la sonde de port ; les champs lents viennent du rafraîchisseur de fond,
et aucune requête ne lance le helper."""
import importlib
import socket
import threading

from fastapi.testclient import TestClient


def _load(monkeypatch):
    import api.main as m
    importlib.reload(m)
    from secubox_core.auth import require_jwt
    m.app.dependency_overrides[require_jwt] = lambda: {"sub": "admin"}
    return m


def _espion(monkeypatch, m, reponse=(True, "", "")):
    """Enregistre les appels au helper faits HORS du rafraîchisseur de fond."""
    appels = []

    def faux(cmd, timeout=30, stdin=None):
        if threading.current_thread().name != "nc-cache":
            appels.append(list(cmd))
        return reponse
    monkeypatch.setattr(m, "run_cmd", faux)
    return appels


def test_ctl_routes_through_sudo_nextcloudctl(monkeypatch):
    m = _load(monkeypatch)
    seen = {}

    def fake_run(cmd, timeout=30, stdin=None):
        seen["cmd"] = cmd
        return True, "RUNNING", ""

    monkeypatch.setattr(m, "run_cmd", fake_run)
    m.ctl(["status", "--json"])
    assert seen["cmd"][:3] == ["sudo", "-n", "/usr/sbin/nextcloudctl"]
    assert seen["cmd"][3:] == ["status", "--json"]


def test_status_running_and_reachable(monkeypatch):
    m = _load(monkeypatch)
    appels = _espion(monkeypatch, m)
    monkeypatch.setattr(m, "lxc_running", lambda: True)
    monkeypatch.setattr(m, "lxc_installed", lambda: True)
    monkeypatch.setattr(m, "_nc_cache", {"version": "29.0.1", "user_count": 3,
                                         "disk_used": "11G", "storage": {}, "ts": 1})
    r = TestClient(m.app).get("/status")
    assert r.status_code == 200
    b = r.json()
    assert b["running"] is True and b["reachable"] is True
    assert b["version"] == "29.0.1" and b["user_count"] == 3
    # real URL, never localhost
    assert b["web_url"].startswith("https://") and "localhost" not in b["web_url"]
    assert appels == []


def test_status_stopped_is_not_reachable(monkeypatch):
    m = _load(monkeypatch)
    _espion(monkeypatch, m)
    monkeypatch.setattr(m, "lxc_running", lambda: False)
    monkeypatch.setattr(m, "lxc_installed", lambda: True)
    monkeypatch.setattr(m, "_nc_cache", {"version": "29.0.1", "user_count": 3,
                                         "disk_used": "11G", "storage": {}, "ts": 1})
    b = TestClient(m.app).get("/status").json()
    assert b["running"] is False and b["reachable"] is False
    assert b["version"] == "" and b["user_count"] == 0


def test_status_never_runs_the_helper(monkeypatch):
    # Remplace test_status_is_cached_and_invalidated : /status est interrogé
    # en boucle par la page ; il ne lance JAMAIS le helper (chaque occ prend
    # des secondes, et leur entassement a mis la machine à genoux). Il lit le
    # cache que le rafraîchisseur de fond remplit.
    m = _load(monkeypatch)
    appels = _espion(monkeypatch, m, (True, '{"running":true}', ""))
    monkeypatch.setattr(m, "lxc_running", lambda: True)
    monkeypatch.setattr(m, "lxc_installed", lambda: True)
    c = TestClient(m.app)
    for _ in range(3):
        assert c.get("/status").status_code == 200
    assert appels == []


def test_connections_uses_real_vhost(monkeypatch):
    # le domaine vient de la configuration (conftest : nc.gk2.secubox.in)
    m = _load(monkeypatch)
    b = TestClient(m.app).get("/connections").json()
    assert b["base_url"] == "https://nc.gk2.secubox.in"
    assert b["webdav"].startswith("https://nc.gk2.secubox.in/remote.php/dav/files/")
    assert "localhost" not in b["base_url"]


def test_reachable_probe_is_failsafe(monkeypatch):
    m = _load(monkeypatch)

    def boom(*a, **k):
        raise socket.timeout("nope")

    monkeypatch.setattr(socket, "create_connection", boom)
    assert m._port_open("10.100.0.21", 80) is False  # never raises
    assert m.lxc_running() is False


def test_storage_reports_real_usage(monkeypatch):
    # /storage sert la dernière mesure du rafraîchisseur, sans appel au helper
    m = _load(monkeypatch)
    appels = _espion(monkeypatch, m)
    monkeypatch.setattr(m, "_nc_cache", {
        "version": "29.0.1", "user_count": 1, "disk_used": "11G", "ts": 1,
        "storage": {"used": "12G", "total": "100G", "used_pct": 12, "data": "11G", "ts": 5}})
    r = TestClient(m.app).get("/storage")
    assert r.status_code == 200
    b = r.json()
    assert b["used_pct"] == 12
    assert b["used"] == "12G" and b["total"] == "100G" and b["data"] == "11G"
    assert appels == []


def test_storage_is_failsafe_on_ctl_error(monkeypatch):
    m = _load(monkeypatch)
    monkeypatch.setattr(m, "ctl", lambda *a, **k: (False, "", "boom"))
    assert m._mesurer_stockage() is None  # une mesure ratée n'écrase rien
    monkeypatch.setattr(m, "_nc_cache", {"version": "", "user_count": 0, "disk_used": "0",
                                         "storage": {}, "ts": 0})
    r = TestClient(m.app).get("/storage")
    assert r.status_code == 200
    b = r.json()
    assert b["used_pct"] == 0 and b["ts"] == 0
