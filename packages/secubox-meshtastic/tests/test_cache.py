# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
import json

def test_update_then_get_roundtrips_and_persists(tmp_path):
    from api.cache import StateCache
    c = StateCache(tmp_path / "state.json")
    c.update({"radio": "present", "nodes": []})
    assert c.get()["radio"] == "present"
    assert json.loads((tmp_path / "state.json").read_text())["radio"] == "present"

def test_cold_get_reads_file(tmp_path):
    from api.cache import StateCache
    (tmp_path / "state.json").write_text('{"radio":"present","nodes":[1]}')
    assert StateCache(tmp_path / "state.json").get()["nodes"] == [1]

def test_cold_get_no_file_is_radio_absent(tmp_path):
    from api.cache import StateCache
    assert StateCache(tmp_path / "state.json").get()["radio"] == "absent"

def test_refresh_thread_calls_producer(tmp_path):
    import threading, time
    from api.cache import StateCache
    c = StateCache(tmp_path / "state.json")
    stop = threading.Event()
    c.start_refresh(lambda: {"radio": "present", "n": 1}, interval=0.01, stop=stop)
    time.sleep(0.05); stop.set()
    assert c.get()["n"] == 1

def test_get_returns_deep_copy_not_live_reference(tmp_path):
    from api.cache import StateCache
    c = StateCache(tmp_path / "state.json")
    c.update({"radio": "present", "nodes": [{"id": 1}]})
    got = c.get()
    got["nodes"].append({"id": 2})       # mutate the returned copy
    assert c.get()["nodes"] == [{"id": 1}]   # cache uncorrupted
