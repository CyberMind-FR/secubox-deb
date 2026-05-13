# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""Tests for api/webhook.py — HMAC, dispatcher, filters, lock."""
import hashlib
import hmac

import pytest

from webhook import verify_signature


def _sign(secret: bytes, body: bytes) -> str:
    return hmac.new(secret, body, hashlib.sha256).hexdigest()


def test_verify_signature_valid():
    secret = b"test-secret-32-bytes-of-entropy!!"
    body = b'{"hello": "world"}'
    sig = _sign(secret, body)
    assert verify_signature(secret, body, sig) is True


def test_verify_signature_wrong_secret_fails():
    body = b'{"hello": "world"}'
    sig = _sign(b"wrong-secret-padded-to-32-bytes!", body)
    assert verify_signature(b"correct-secret-padded-to-32!!!", body, sig) is False


def test_verify_signature_truncated_sig_fails():
    secret = b"test-secret-32-bytes-of-entropy!!"
    body = b'{"hello": "world"}'
    sig = _sign(secret, body)[:-2]
    assert verify_signature(secret, body, sig) is False


def test_verify_signature_empty_sig_fails():
    secret = b"test-secret-32-bytes-of-entropy!!"
    body = b'{"hello": "world"}'
    assert verify_signature(secret, body, "") is False


def test_load_secret_reads_file(tmp_path, monkeypatch):
    import webhook
    p = tmp_path / "secret"
    p.write_bytes(b"abc123\n")
    monkeypatch.setattr(webhook, "_secret_cache", None)
    s = webhook.load_secret(p)
    assert s == b"abc123"


def test_load_secret_missing_raises(tmp_path, monkeypatch):
    import webhook
    monkeypatch.setattr(webhook, "_secret_cache", None)
    p = tmp_path / "nope"
    with pytest.raises(FileNotFoundError):
        webhook.load_secret(p)


def test_load_secret_empty_raises(tmp_path, monkeypatch):
    import webhook
    monkeypatch.setattr(webhook, "_secret_cache", None)
    p = tmp_path / "empty"
    p.write_bytes(b"")
    with pytest.raises(ValueError):
        webhook.load_secret(p)


def test_load_secret_caches(tmp_path, monkeypatch):
    import webhook
    p = tmp_path / "secret"
    p.write_bytes(b"first\n")
    monkeypatch.setattr(webhook, "_secret_cache", None)
    s1 = webhook.load_secret(p)
    p.write_bytes(b"changed\n")
    s2 = webhook.load_secret(p)
    assert s1 == s2 == b"first"  # cache wins


def test_record_deploy_appends():
    import webhook
    webhook._deploys.clear()
    webhook._record_deploy({"site": "a", "from": "x", "to": "y"})
    assert len(webhook._deploys) == 1
    assert webhook._deploys[0]["site"] == "a"


def test_record_deploy_evicts_oldest_at_50():
    import webhook
    webhook._deploys.clear()
    for i in range(55):
        webhook._record_deploy({"site": f"s{i}"})
    assert len(webhook._deploys) == 50
    # oldest 5 are gone; first remaining is s5
    assert webhook._deploys[0]["site"] == "s5"
    assert webhook._deploys[-1]["site"] == "s54"


def test_list_deploys_returns_reversed():
    import webhook
    webhook._deploys.clear()
    webhook._record_deploy({"site": "a"})
    webhook._record_deploy({"site": "b"})
    out = webhook.list_deploys()
    assert out["count"] == 2
    assert out["deploys"][0]["site"] == "b"  # newest first
    assert out["deploys"][1]["site"] == "a"


def test_git_pull_returns_old_and_new_sha(tmp_path, monkeypatch):
    import webhook
    site = tmp_path / "site"
    site.mkdir()
    (site / ".git").mkdir()

    calls = []
    sha_iter = iter(["aaa1111", "bbb2222"])

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        class R:
            stdout = next(sha_iter) + "\n" if "rev-parse" in cmd else ""
            stderr = ""
            returncode = 0
        return R()

    monkeypatch.setattr(webhook.subprocess, "run", fake_run)
    old, new = webhook.git_pull(site, "main")
    assert old == "aaa1111"
    assert new == "bbb2222"
    # ensure the 4 expected git commands happened in order
    op_names = [c[3] for c in calls]
    assert op_names == ["rev-parse", "fetch", "reset", "rev-parse"]


def test_git_pull_timeout_propagates(tmp_path, monkeypatch):
    import webhook
    import subprocess
    site = tmp_path / "site"
    site.mkdir()
    (site / ".git").mkdir()

    def fake_run(cmd, **kwargs):
        if "fetch" in cmd:
            raise subprocess.TimeoutExpired(cmd, kwargs.get("timeout", 60))
        class R:
            stdout = "abc\n"; stderr = ""; returncode = 0
        return R()

    monkeypatch.setattr(webhook.subprocess, "run", fake_run)
    with pytest.raises(subprocess.TimeoutExpired):
        webhook.git_pull(site, "main")


def _payload(name="metablog-zkp", ref="refs/heads/main", default_branch="main"):
    return {
        "ref": ref,
        "repository": {"name": name, "default_branch": default_branch},
        "after": "abc1234",
    }


def test_classify_payload_accepts_default_branch_push():
    import webhook
    decision, info = webhook.classify_payload(_payload())
    assert decision == "accept"
    assert info["site"] == "zkp"
    assert info["branch"] == "main"


def test_classify_payload_rejects_non_metablog():
    import webhook
    decision, info = webhook.classify_payload(_payload(name="streamlit-foo"))
    assert decision == "skip"
    assert info["reason"] == "non-metablog"


def test_classify_payload_rejects_non_default_ref():
    import webhook
    decision, info = webhook.classify_payload(_payload(ref="refs/tags/v1.0.0"))
    assert decision == "skip"
    assert info["reason"] == "non-default-ref"


def test_classify_payload_rejects_feature_branch():
    import webhook
    decision, info = webhook.classify_payload(
        _payload(ref="refs/heads/feature/x", default_branch="main"))
    assert decision == "skip"
    assert info["reason"] == "non-default-ref"


def test_classify_payload_handles_master_default():
    import webhook
    decision, info = webhook.classify_payload(
        _payload(ref="refs/heads/master", default_branch="master"))
    assert decision == "accept"
    assert info["branch"] == "master"


def test_classify_payload_malformed_missing_repo():
    import webhook
    decision, info = webhook.classify_payload({"ref": "refs/heads/main"})
    assert decision == "malformed"


import asyncio


@pytest.mark.asyncio
async def test_site_lock_serializes_same_name():
    import webhook
    webhook._site_locks.clear()
    order = []

    async def critical(name: str, marker: str):
        lock = await webhook.site_lock(name)
        async with lock:
            order.append(f"{marker}-start")
            await asyncio.sleep(0.05)
            order.append(f"{marker}-end")

    await asyncio.gather(critical("zkp", "A"), critical("zkp", "B"))
    # whichever started first must finish before the other starts
    if order[0] == "A-start":
        assert order == ["A-start", "A-end", "B-start", "B-end"]
    else:
        assert order == ["B-start", "B-end", "A-start", "A-end"]


@pytest.mark.asyncio
async def test_site_lock_parallel_different_names():
    import webhook
    webhook._site_locks.clear()
    order = []

    async def critical(name: str, marker: str):
        lock = await webhook.site_lock(name)
        async with lock:
            order.append(f"{marker}-start")
            await asyncio.sleep(0.05)
            order.append(f"{marker}-end")

    await asyncio.gather(critical("zkp", "A"), critical("evolution", "B"))
    # different sites can overlap: starts come before either end
    assert order[:2] == sorted(order[:2])  # both starts first
    assert "A-end" in order
    assert "B-end" in order
