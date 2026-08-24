# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# #1173 : les endpoints du socle (#1169) exposes au panel admin mail.
import pathlib, sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))
from fastapi.testclient import TestClient  # noqa: E402
from api.main import app  # noqa: E402
from secubox_core.auth import require_jwt  # noqa: E402

app.dependency_overrides[require_jwt] = lambda: {"sub": "test"}
client = TestClient(app)


def test_socle_routes_registered():
    paths = {getattr(r, "path", "") for r in app.routes}
    for p in ("/socle/status", "/maildir/reconcile", "/sieve/enable",
              "/sieve/status", "/antivirus/status", "/antivirus/{action}",
              "/ssl/renew"):
        assert p in paths, f"route {p} absente"


def test_antivirus_action_invalide_est_400():
    # action bogus -> 400 AVANT tout appel a mailctl (pas d'effet de bord)
    r = client.post("/antivirus/bogus")
    assert r.status_code == 400
