import importlib
def _load(monkeypatch):
    import api.main as m; importlib.reload(m)
    from secubox_core.auth import require_jwt
    m.app.dependency_overrides[require_jwt] = lambda: {"sub": "admin"}
    return m

def test_local_targets_are_owned(monkeypatch):
    m = _load(monkeypatch)
    assert m._is_local_or_owned("192.168.1.10") is True
    assert m._is_local_or_owned("10.0.0.5") is True
    assert m._is_local_or_owned("nc.gk2.secubox.in") is True   # box-owned suffix

def test_external_targets_not_owned(monkeypatch):
    m = _load(monkeypatch)
    assert m._is_local_or_owned("scanme.nmap.org") is False
    assert m._is_local_or_owned("8.8.8.8") is False
