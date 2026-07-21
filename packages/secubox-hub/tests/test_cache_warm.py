import asyncio
import importlib
import sys
from pathlib import Path

import pytest

# Import the hub app module.
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "api"))
main = importlib.import_module("main")


def _reset_cache():
    main._cache["services"] = {}
    main._cache["last_refresh"] = 0
    main._cache["health_batch"] = None
    main._cache["health_batch_ts"] = 0


def test_ensure_services_warm_refreshes_when_cold(monkeypatch):
    _reset_cache()
    calls = {"n": 0}

    def fake_refresh():
        calls["n"] += 1
        main._cache["services"]["secubox-x"] = {"name": "secubox-x", "active": True, "socket": False}

    monkeypatch.setattr(main, "_refresh_services_cache", fake_refresh)
    asyncio.run(main._ensure_services_warm())
    assert calls["n"] == 1
    assert main._cache["last_refresh"] > 0


def test_ensure_services_warm_skips_when_fresh(monkeypatch):
    _reset_cache()
    main._cache["last_refresh"] = main.time.time()
    calls = {"n": 0}
    monkeypatch.setattr(main, "_refresh_services_cache", lambda: calls.__setitem__("n", calls["n"] + 1))
    asyncio.run(main._ensure_services_warm())
    assert calls["n"] == 0


def test_refresh_health_batch_parses_units(monkeypatch):
    _reset_cache()

    class R:
        stdout = (
            "secubox-hub.service loaded active running Hub\n"
            "secubox-dpi.service loaded active exited DPI\n"
            "secubox-cdn.service loaded failed failed CDN\n"
        )

    monkeypatch.setattr(main.subprocess, "run", lambda *a, **k: R())
    # No sockets present for these in the test env.
    main._refresh_health_batch()
    hb = main._cache["health_batch"]
    assert hb["modules"]["hub"]["status"] == "ok"
    assert hb["modules"]["dpi"]["status"] == "warn"
    assert hb["modules"]["cdn"]["status"] == "error"
    assert main._cache["health_batch_ts"] > 0


def test_refresh_health_batch_reports_sleepable_as_asleep_not_warn(monkeypatch):
    # A module in the sleepable-modules.json export (eager/on-demand,
    # scale-to-zero ref #896) that's inactive/dead is EXPECTED — it's
    # asleep, not down. Must stay in the "ok" bucket, never "warn"/"error".
    _reset_cache()

    class R:
        stdout = (
            "secubox-peertube.service loaded inactive dead PeerTube\n"
            "secubox-otherapp.service loaded inactive dead OtherApp\n"
        )

    monkeypatch.setattr(main.subprocess, "run", lambda *a, **k: R())
    monkeypatch.setattr(main, "_load_sleepable_modules", lambda: {"peertube"})
    main._refresh_health_batch()
    hb = main._cache["health_batch"]
    assert hb["modules"]["peertube"]["status"] == "ok"
    assert hb["modules"]["peertube"]["msg"] == "Asleep (on-demand)"
    # A module NOT in the sleepable set with the same inactive/dead state
    # keeps today's behavior (an unexpected stop is still a "warn").
    assert hb["modules"]["otherapp"]["status"] == "warn"


def test_refresh_health_batch_failed_beats_sleepable(monkeypatch):
    # A crash (failed) is a real alarm even for a sleepable module —
    # intentional sleep goes through disable+stop, never "failed".
    _reset_cache()

    class R:
        stdout = "secubox-peertube.service loaded failed failed PeerTube\n"

    monkeypatch.setattr(main.subprocess, "run", lambda *a, **k: R())
    monkeypatch.setattr(main, "_load_sleepable_modules", lambda: {"peertube"})
    main._refresh_health_batch()
    hb = main._cache["health_batch"]
    assert hb["modules"]["peertube"]["status"] == "error"


def test_health_batch_serves_cache_without_subprocess(monkeypatch):
    _reset_cache()
    main._cache["health_batch"] = {"modules": {"hub": {"status": "ok", "msg": "Running"}}, "count": 1}
    main._cache["health_batch_ts"] = main.time.time()

    def boom(*a, **k):
        raise AssertionError("subprocess must NOT be called when cache is warm")

    monkeypatch.setattr(main.subprocess, "run", boom)
    out = asyncio.run(main.public_health_batch())
    assert out["count"] == 1
    assert out["modules"]["hub"]["status"] == "ok"


def test_health_batch_cold_miss_builds_once(monkeypatch):
    _reset_cache()

    class R:
        stdout = "secubox-hub.service loaded active running Hub\n"

    calls = {"n": 0}

    def fake_run(*a, **k):
        calls["n"] += 1
        return R()

    monkeypatch.setattr(main.subprocess, "run", fake_run)
    out = asyncio.run(main.public_health_batch())
    assert out["count"] >= 1
    assert calls["n"] == 1
