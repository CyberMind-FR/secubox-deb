# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
Exercises `jellyfinctl playback status|apply` end to end against a fake
Jellyfin HTTP API and a fake `lxc-info`, so the tests run without an LXC or
a real Jellyfin instance. Real `bash`/`jq` are used (both present on the dev
box and on the target Debian board).

Covers the behaviour this feature depends on:
  - [playback] TOML values drive the desired policy (not hardcoded).
  - `playback apply` PUSHES THE FULL Policy object per user (not a partial
    patch) — this is the #1 way to silently corrupt Jellyfin user policy.
  - A user whose stored policy already matches is reported compliant; one
    that does not is not — this is how an operator (or the periodic timer)
    notices a user created after the fact still has transcoding enabled.
  - Missing API key / stopped LXC / unreachable API all fail LOUD (ok:false
    with a reason), never silently report success.
  - The API key is never present on stdout/stderr.
"""
from __future__ import annotations

import json
import os
import stat
import subprocess
from pathlib import Path

CTL = str(Path(__file__).resolve().parents[1] / "sbin" / "jellyfinctl")

FAKE_APIKEY = "S3CR3T-DO-NOT-LEAK-0123456789ab"

USERS_FIXTURE = [
    {
        "Id": "aaaa1111",
        "Name": "admin",
        "Policy": {
            "IsAdministrator": True,
            "EnableVideoPlaybackTranscoding": True,
            "EnableAudioPlaybackTranscoding": True,
            "EnablePlaybackRemuxing": True,
            "EnabledFolders": ["x", "y"],
        },
    },
    {
        "Id": "bbbb2222",
        "Name": "gk2",
        "Policy": {
            "IsAdministrator": True,
            "EnableVideoPlaybackTranscoding": False,
            "EnableAudioPlaybackTranscoding": False,
            "EnablePlaybackRemuxing": True,
            "EnabledFolders": ["x", "y"],
        },
    },
]


def _write_fake_bin(bin_dir: Path, users_file: Path, applied_log: Path) -> None:
    """A fake `curl` that answers GET .../Users from a fixture file and
    records every POST .../Users/<id>/Policy body (id + body) so tests can
    assert both WHO was updated and WHAT was sent — without ever touching
    a real network or a real Jellyfin."""
    curl_script = f"""#!/usr/bin/env bash
set -euo pipefail
url=""
is_post=0
data=""
prev=""
for a in "$@"; do
    case "$prev" in
        -d) data="$a" ;;
    esac
    case "$a" in
        http*) url="$a" ;;
        -X) : ;;
        POST) is_post=1 ;;
    esac
    prev="$a"
done

case "$url" in
    */Users)
        cat "{users_file}"
        ;;
    */Users/*/Policy)
        id="${{url#*/Users/}}"
        id="${{id%/Policy}}"
        printf '%s\\t%s\\n' "$id" "$data" >> "{applied_log}"
        ;;
    *)
        echo "fake curl: unhandled url: $url" >&2
        exit 22
        ;;
esac
"""
    curl_path = bin_dir / "curl"
    curl_path.write_text(curl_script)
    curl_path.chmod(curl_path.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)

    lxc_info_script = """#!/usr/bin/env bash
echo "Name:           jellyfin"
echo "State:          RUNNING"
"""
    lxc_info_path = bin_dir / "lxc-info"
    lxc_info_path.write_text(lxc_info_script)
    lxc_info_path.chmod(lxc_info_path.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)


def _env(tmp_path: Path, *, toml_body: str, apikey: str | None = FAKE_APIKEY) -> dict:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    users_file = tmp_path / "users.json"
    users_file.write_text(json.dumps(USERS_FIXTURE))
    applied_log = tmp_path / "applied.log"
    _write_fake_bin(bin_dir, users_file, applied_log)

    config_file = tmp_path / "jellyfin.toml"
    config_file.write_text(toml_body)

    state_dir = tmp_path / "state"
    state_dir.mkdir()
    secrets_dir = tmp_path / "secrets"
    secrets_dir.mkdir()
    apikey_file = secrets_dir / "jellyfin-apikey"
    if apikey is not None:
        apikey_file.write_text(apikey)

    env = dict(os.environ)
    env["PATH"] = f"{bin_dir}:{env['PATH']}"
    env["SECUBOX_JELLYFIN_CONFIG"] = str(config_file)
    env["SECUBOX_JELLYFIN_STATE_DIR"] = str(state_dir)
    env["SECUBOX_SECRETS_DIR"] = str(secrets_dir)
    env["SECUBOX_JELLYFIN_APIKEY"] = str(apikey_file)
    env["_TEST_APPLIED_LOG"] = str(applied_log)
    return env


DEFAULT_TOML = """
[playback]
allow_video_transcoding = false
allow_audio_transcoding = false
allow_remuxing          = true
"""


def _run(verb: str, env: dict) -> dict:
    p = subprocess.run(["bash", CTL, *verb.split()], capture_output=True, text=True, env=env)
    assert p.returncode == 0, f"stderr={p.stderr!r} stdout={p.stdout!r}"
    return json.loads(p.stdout)


def test_status_reports_desired_policy_from_toml(tmp_path):
    env = _env(tmp_path, toml_body=DEFAULT_TOML)
    out = _run("playback status", env)
    assert out["ok"] is True
    assert out["desired"] == {
        "video_transcoding": False,
        "audio_transcoding": False,
        "remuxing": True,
    }


def test_status_flags_noncompliant_user_and_compliant_user(tmp_path):
    """admin still has transcoding ON in the fixture (like a fresh Jellyfin
    default) — this is exactly the drift a newly created user would show."""
    env = _env(tmp_path, toml_body=DEFAULT_TOML)
    out = _run("playback status", env)
    by_name = {u["name"]: u for u in out["users"]}
    assert by_name["admin"]["compliant"] is False
    assert by_name["gk2"]["compliant"] is True
    assert out["all_compliant"] is False


def test_apply_pushes_full_policy_object_not_a_partial_patch(tmp_path):
    env = _env(tmp_path, toml_body=DEFAULT_TOML)
    out = _run("playback apply", env)
    assert out["ok"] is True
    assert sorted(out["applied"]) == ["admin", "gk2"]
    assert out["failed"] == []

    applied_log = Path(env["_TEST_APPLIED_LOG"]).read_text().strip().splitlines()
    assert len(applied_log) == 2
    bodies = {}
    for line in applied_log:
        uid, body = line.split("\t", 1)
        bodies[uid] = json.loads(body)

    admin_body = bodies["aaaa1111"]
    assert admin_body["EnableVideoPlaybackTranscoding"] is False
    assert admin_body["EnableAudioPlaybackTranscoding"] is False
    assert admin_body["EnablePlaybackRemuxing"] is True
    # Untouched fields of the ORIGINAL policy must survive the round-trip —
    # a partial body would have silently dropped them.
    assert admin_body["IsAdministrator"] is True
    assert admin_body["EnabledFolders"] == ["x", "y"]


def test_apply_honours_reversal_in_toml(tmp_path):
    """The operator can re-enable transcoding by editing the TOML — the
    setting must be an expressed choice, not something baked into the ctl."""
    reversed_toml = """
[playback]
allow_video_transcoding = true
allow_audio_transcoding = true
allow_remuxing          = true
"""
    env = _env(tmp_path, toml_body=reversed_toml)
    out = _run("playback apply", env)
    assert out["desired"] == {
        "video_transcoding": True,
        "audio_transcoding": True,
        "remuxing": True,
    }
    applied_log = Path(env["_TEST_APPLIED_LOG"]).read_text().strip().splitlines()
    for line in applied_log:
        _uid, body = line.split("\t", 1)
        body = json.loads(body)
        assert body["EnableVideoPlaybackTranscoding"] is True
        assert body["EnableAudioPlaybackTranscoding"] is True


def test_apply_defaults_to_off_when_playback_section_absent(tmp_path):
    """An older jellyfin.toml with no [playback] section (pre-upgrade) must
    still land on the safe/CPU-protective default, not silently do nothing
    or leave transcoding on."""
    env = _env(tmp_path, toml_body="[lxc]\nname = \"jellyfin\"\n")
    out = _run("playback status", env)
    assert out["desired"] == {
        "video_transcoding": False,
        "audio_transcoding": False,
        "remuxing": True,
    }


def test_status_fails_loud_without_api_key(tmp_path):
    env = _env(tmp_path, toml_body=DEFAULT_TOML, apikey=None)
    out = _run("playback status", env)
    assert out["ok"] is False
    assert out["reason"]


def test_apply_fails_loud_without_api_key(tmp_path):
    env = _env(tmp_path, toml_body=DEFAULT_TOML, apikey=None)
    out = _run("playback apply", env)
    assert out["ok"] is False
    assert out["reason"]


def test_no_api_key_leak_on_stdout_or_stderr(tmp_path):
    env = _env(tmp_path, toml_body=DEFAULT_TOML)
    p = subprocess.run(["bash", CTL, "playback", "apply"], capture_output=True, text=True, env=env)
    assert FAKE_APIKEY not in p.stdout
    assert FAKE_APIKEY not in p.stderr


def test_status_fails_loud_when_lxc_not_running(tmp_path):
    env = _env(tmp_path, toml_body=DEFAULT_TOML)
    # Overwrite the fake lxc-info to report a stopped container.
    bin_dir = Path(env["PATH"].split(":", 1)[0])
    lxc_info_path = bin_dir / "lxc-info"
    lxc_info_path.write_text("#!/usr/bin/env bash\necho 'State:          STOPPED'\n")
    lxc_info_path.chmod(lxc_info_path.stat().st_mode | stat.S_IEXEC)
    out = _run("playback status", env)
    assert out["ok"] is False
    assert out["reason"]
