"""Unit tests for CookieAuditAggregator + Classifier."""
import asyncio
import json
from pathlib import Path

import pytest

from cookie_audit import (
    CookieAuditAggregator,
    Classifier,
    classify_cookie,
)


CFG_BASE = {
    "enabled": True,
    "max_ingest_age_hours": 24,
}


def _write_ledger(tmp_path, records):
    p = tmp_path / "server.jsonl"
    with p.open("w") as f:
        for r in records:
            f.write(json.dumps(r) + "\n")
    return p


def test_classify_strictly_necessary():
    cls = Classifier({
        "strictly_necessary": [r"^PHPSESSID$", r"^sess(ion)?id$", r"^csrftoken$"],
        "analytics": [r"^_ga", r"^_pk_"],
        "marketing": [r"^_fbp$", r"^_gcl_"],
        "functional": [r"^lang$", r"^theme$"],
    })
    assert cls.classify("PHPSESSID") == "strictly_necessary"
    assert cls.classify("_ga") == "analytics"
    assert cls.classify("_ga_ABC123") == "analytics"
    assert cls.classify("_fbp") == "marketing"
    assert cls.classify("lang") == "functional"
    assert cls.classify("randomname") == "unclassified"


def test_classify_first_match_wins_in_category_order():
    cls = Classifier({
        "strictly_necessary": [r"^x"],
        "analytics": [r"^x_analytic"],
        "functional": [],
        "marketing": [],
    })
    # x_analytic matches both, but strictly_necessary is checked first.
    assert cls.classify("x_analytic") == "strictly_necessary"


def test_classify_cookie_helper():
    rules = {"analytics": [r"^_ga"], "strictly_necessary": [], "functional": [], "marketing": []}
    assert classify_cookie("_ga", rules) == "analytics"
    assert classify_cookie("zoo", rules) == "unclassified"


def test_aggregator_reconciles_server_and_browser(tmp_path):
    ledger = _write_ledger(tmp_path, [
        {"ts": "2026-05-16T10:00:00+00:00", "vhost": "foo.example.com",
         "name": "PHPSESSID", "value_hash": "abc", "secure": True,
         "httponly": True, "samesite": "Lax", "domain": None,
         "path": "/", "max_age": None, "expires": None},
        {"ts": "2026-05-16T10:00:01+00:00", "vhost": "foo.example.com",
         "name": "lang", "value_hash": "def", "secure": False,
         "httponly": False, "samesite": None, "domain": None,
         "path": "/", "max_age": None, "expires": None},
    ])
    ingest_dir = tmp_path / "ingest"
    ingest_dir.mkdir()
    (ingest_dir / "foo.example.com.jsonl").write_text(
        json.dumps({"ts": "2026-05-16T10:00:05+00:00",
                    "host": "foo.example.com", "path": "/",
                    "cookies": [
                        {"name": "PHPSESSID", "value_hash": "abc"},
                        {"name": "_ga", "value_hash": "ghi"},
                        {"name": "lang", "value_hash": "def"},
                    ]}) + "\n"
    )
    agg = CookieAuditAggregator(
        dict(CFG_BASE,
             ledger_path=str(ledger),
             ingest_dir=str(ingest_dir),
             classifier={
                 "strictly_necessary": [r"^PHPSESSID$"],
                 "analytics": [r"^_ga"],
                 "functional": [r"^lang$"],
                 "marketing": [],
             }),
        cache_path=tmp_path / "cookie-audit.json",
    )
    out = asyncio.run(agg.refresh_once())
    assert out["enabled"] is True
    hosts = {h["vhost"]: h for h in out["hosts"]}
    assert "foo.example.com" in hosts
    foo = hosts["foo.example.com"]
    by_name = {c["name"]: c for c in foo["cookies"]}
    assert by_name["PHPSESSID"]["source"] == "both"
    assert by_name["PHPSESSID"]["category"] == "strictly_necessary"
    assert by_name["PHPSESSID"]["rgpd_violation"] is False
    assert by_name["lang"]["source"] == "both"
    assert by_name["lang"]["category"] == "functional"
    # _ga is in the browser but never in the server ledger -> JS-set + analytics
    assert by_name["_ga"]["source"] == "js"
    assert by_name["_ga"]["category"] == "analytics"
    assert by_name["_ga"]["rgpd_violation"] is True
    assert foo["violation_count"] == 1
    # Summary rolls up
    assert out["summary"]["host_count"] == 1
    assert out["summary"]["violation_count"] == 1
    assert out["summary"]["hosts_with_violations"] == 1


def test_aggregator_http_only_cookie_source(tmp_path):
    """Server-only cookie (e.g. HttpOnly) -> source='http', no violation."""
    ledger = _write_ledger(tmp_path, [
        {"ts": "2026-05-16T10:00:00+00:00", "vhost": "secure.example.com",
         "name": "session_token", "value_hash": "xyz", "secure": True,
         "httponly": True, "samesite": "Strict", "domain": None,
         "path": "/", "max_age": None, "expires": None},
    ])
    ingest_dir = tmp_path / "ingest"
    ingest_dir.mkdir()
    agg = CookieAuditAggregator(
        dict(CFG_BASE,
             ledger_path=str(ledger),
             ingest_dir=str(ingest_dir),
             classifier={"strictly_necessary": [r"^session_"], "analytics": [],
                         "functional": [], "marketing": []}),
        cache_path=tmp_path / "cookie-audit.json",
    )
    out = asyncio.run(agg.refresh_once())
    h = out["hosts"][0]
    c = h["cookies"][0]
    assert c["source"] == "http"
    assert c["category"] == "strictly_necessary"
    assert c["rgpd_violation"] is False
    assert c["httponly"] is True


def test_disabled_aggregator_returns_empty(tmp_path):
    agg = CookieAuditAggregator(
        {"enabled": False},
        cache_path=tmp_path / "cookie-audit.json",
    )
    out = asyncio.run(agg.refresh_once())
    assert out["enabled"] is False
    assert out["hosts"] == []


def test_aggregator_persists_cache(tmp_path):
    ledger = _write_ledger(tmp_path, [])
    ingest_dir = tmp_path / "ingest"
    ingest_dir.mkdir()
    cache = tmp_path / "cookie-audit.json"
    agg = CookieAuditAggregator(
        dict(CFG_BASE,
             ledger_path=str(ledger),
             ingest_dir=str(ingest_dir),
             classifier={"strictly_necessary": [], "analytics": [],
                         "functional": [], "marketing": []}),
        cache_path=cache,
    )
    asyncio.run(agg.refresh_once())
    assert cache.exists()
    data = json.loads(cache.read_text())
    assert "generated_at" in data
    assert data["enabled"] is True


def test_aggregator_current_reads_cache_if_no_in_memory(tmp_path):
    cache = tmp_path / "cookie-audit.json"
    cache.write_text(json.dumps({"enabled": True, "hosts": [{"vhost": "cached.example", "cookies": []}]}))
    agg = CookieAuditAggregator({"enabled": True}, cache_path=cache)
    cur = agg.current()
    assert cur["enabled"] is True
    assert cur["hosts"][0]["vhost"] == "cached.example"


def test_aggregator_handles_malformed_ledger_lines(tmp_path):
    ledger = tmp_path / "server.jsonl"
    ledger.write_text("not_json\n{}\n{\"vhost\":\"ok.example\",\"name\":\"a\",\"value_hash\":\"h\"}\n")
    ingest_dir = tmp_path / "ingest"
    ingest_dir.mkdir()
    agg = CookieAuditAggregator(
        dict(CFG_BASE,
             ledger_path=str(ledger),
             ingest_dir=str(ingest_dir),
             classifier={"strictly_necessary": [], "analytics": [],
                         "functional": [], "marketing": []}),
        cache_path=tmp_path / "cookie-audit.json",
    )
    out = asyncio.run(agg.refresh_once())
    hosts = [h["vhost"] for h in out["hosts"]]
    assert hosts == ["ok.example"]
