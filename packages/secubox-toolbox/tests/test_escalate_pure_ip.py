# SPDX-License-Identifier: LicenseRef-CMSD-1.0
from secubox_toolbox import escalate


def test_pure_ip_drop_gated_off_when_not_enforcing(tmp_path, monkeypatch):
    pure = tmp_path / "pure.txt"; pure.write_text("ga.trk\n")
    dropped = []
    monkeypatch.setattr(escalate, "_resolve_ips", lambda h: ["203.0.113.9"])
    monkeypatch.setattr(escalate, "_nft_add_blacklist",
                        lambda ip: dropped.append(ip) or True)
    n = escalate.pure_tracker_ip_drop(
        pure_path=str(pure), allowlist_path=str(tmp_path / "none.txt"),
        enforce=False, ip_drop=True)
    assert n == 0 and dropped == []


def test_pure_ip_drop_applies_non_cdn_only(tmp_path, monkeypatch):
    pure = tmp_path / "pure.txt"; pure.write_text("ga.trk\ncdn.trk\n")
    cdn = tmp_path / "cdn.txt"; cdn.write_text("104.16.0.0/13\n")
    dropped = []
    resolve = {"ga.trk": ["203.0.113.9"], "cdn.trk": ["104.16.1.2"]}
    monkeypatch.setattr(escalate, "_resolve_ips", lambda h: resolve.get(h, []))
    monkeypatch.setattr(escalate, "_nft_add_blacklist",
                        lambda ip: dropped.append(ip) or True)
    monkeypatch.setattr(escalate, "_audit", lambda msg: None)
    n = escalate.pure_tracker_ip_drop(
        pure_path=str(pure), allowlist_path=str(cdn),
        enforce=True, ip_drop=True)
    assert dropped == ["203.0.113.9"]
    assert n == 1
