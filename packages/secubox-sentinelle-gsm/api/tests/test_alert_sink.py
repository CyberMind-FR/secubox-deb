# packages/secubox-sentinelle-gsm/api/tests/test_alert_sink.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0

import asyncio
import json
import pytest
from sentinelle_gsm.alert_sink import Alert, AlertSink


@pytest.fixture
def sink(tmp_path):
    return AlertSink(tmp_path / "alerts.db")


def test_write_and_list_roundtrip(sink):
    a = Alert(cell_id="208-01-100-12345", arfcn=124, score=85, reason="cipher_downgrade")
    written = sink.write(a)
    assert written.id > 0
    history = sink.list()
    assert len(history) == 1
    assert history[0].cell_id == "208-01-100-12345"
    assert history[0].score == 85


def test_plaintext_imsi_in_reason_is_refused(sink):
    """Privacy invariant: never accept plaintext IMSI in any field."""
    a = Alert(cell_id="208-01-100-12345", arfcn=124, score=85,
              reason="caught IMSI 208201234567890")  # 15 digits = IMSI
    with pytest.raises(ValueError, match="plaintext-IMSI"):
        sink.write(a)


def test_hmac_in_subscriber_hash_is_accepted(sink):
    """Hashed identifier (typical 32-hex chars) must pass the guard."""
    a = Alert(cell_id="208-01-100-12345", arfcn=124, score=85,
              reason="paging targets a trusted IMSI",
              subscriber_hash="a1b2c3d4e5f6deadbeef00112233445566778899aabbccddeeff0011",
              trusted_label="Gerald iPhone")
    written = sink.write(a)
    assert written.subscriber_hash.startswith("a1b2")


@pytest.mark.asyncio
async def test_subscribe_receives_new_alerts(sink):
    q = sink.subscribe()
    try:
        sink.write(Alert(cell_id="208-01-100-99999", arfcn=12, score=72, reason="ghost_bts"))
        got = await asyncio.wait_for(q.get(), timeout=1.0)
        assert got.cell_id == "208-01-100-99999"
        assert got.score == 72
    finally:
        sink.unsubscribe(q)


@pytest.mark.asyncio
async def test_stream_emits_subscribed_then_alert(sink):
    """First SSE chunk is the `: subscribed` comment (forces EventSource
    open), then the next chunk is the alert event."""
    gen = sink.stream()
    # First chunk must be the immediate subscribed comment so the
    # browser transitions EventSource readyState CONNECTING → OPEN
    # even when the alert queue is empty.
    first = await asyncio.wait_for(gen.__anext__(), timeout=1.0)
    assert first == ": subscribed\n\n"

    # Now write an alert and consume the next chunk — it should be the
    # alert event in proper SSE format.
    sink.write(Alert(cell_id="208-01-100-77777", arfcn=88, score=91, reason="identity_request_abuse"))
    chunk = await asyncio.wait_for(gen.__anext__(), timeout=1.0)
    assert chunk.startswith("event: alert\n")
    data_line = next(l for l in chunk.split("\n") if l.startswith("data: "))
    payload = json.loads(data_line[len("data: "):])
    assert payload["cell_id"] == "208-01-100-77777"
    await gen.aclose()
