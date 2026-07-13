# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: secubox-nac — tests for the lazy init path (#817 whole-branch
fix C1): under the aggregator's in-process mount, `@app.on_event("startup")`
never fires, so `_do_init()` (idempotent) + the HTTP middleware must bring
the store/collector up on the first request.
"""


def _reset(main, tmp_path, monkeypatch):
    """Point the module at throwaway paths and reset the init flags so a
    test drives a clean lazy-init from scratch."""
    monkeypatch.setattr(main, "DEVICES_DB_PATH", str(tmp_path / "d.db"))
    monkeypatch.setattr(main, "MACGUARD_DEVICES_JSON", str(tmp_path / "absent-mg.json"))
    monkeypatch.setattr(main, "DEVICEINTEL_DEVICES_JSON", str(tmp_path / "absent-di.json"))
    monkeypatch.setattr(main, "IOTGUARD_DEVICES_DB", str(tmp_path / "absent-iot.db"))
    monkeypatch.setattr(main, "store", None)
    monkeypatch.setattr(main, "collector", None)
    monkeypatch.setattr(main, "oui_map", None)
    monkeypatch.setattr(main, "_initialized", False)
    monkeypatch.setattr(main, "_collector_started", False)
    monkeypatch.setattr(main, "_monitoring_task", None)
    monkeypatch.setattr(main, "_main_loop", None)


def test_do_init_builds_store_and_is_idempotent(tmp_path, monkeypatch):
    import api.main as main
    _reset(main, tmp_path, monkeypatch)

    assert main.store is None
    main._do_init()
    assert main.store is not None
    assert main.collector is not None
    assert main._initialized is True

    first_store = main.store
    first_collector = main.collector
    main._do_init()  # second call is a no-op
    assert main.store is first_store
    assert main.collector is first_collector


def test_middleware_inits_and_starts_collector(tmp_path, monkeypatch):
    """Driving the HTTP middleware once (as the aggregator would on the
    first request) must `_do_init()` AND start the collector task on the
    loop thread — the whole feature is inert without this."""
    import asyncio
    import api.main as main
    import api.collector as C

    _reset(main, tmp_path, monkeypatch)
    # keep the started collector cycle cheap and side-effect free
    monkeypatch.setattr(C, "discover", lambda **k: [])

    class _Req:
        pass

    async def _call_next(_req):
        class _Resp:
            pass
        return _Resp()

    async def drive():
        assert main.store is None and main._collector_started is False
        await main._lazy_init_middleware(_Req(), _call_next)
        assert main.store is not None
        assert main._collector_started is True
        assert main._monitoring_task is not None
        assert main._main_loop is asyncio.get_running_loop()
        # cancel the collector task the middleware started
        main._monitoring_task.cancel()
        try:
            await main._monitoring_task
        except asyncio.CancelledError:
            pass

    asyncio.run(drive())
