# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
import json, os, subprocess, sys
from pathlib import Path

CTL = str(Path(__file__).resolve().parent.parent / "sbin" / "secubox-assistctl")
ANN = str(Path(__file__).resolve().parents[2] / "secubox-annuaire")
ASSIST = str(Path(__file__).resolve().parent.parent)


def _env(tmp_path):
    key = tmp_path / "node.key"; key.write_text("11" * 32)
    env = dict(os.environ)
    env.update(ANNUAIRE_KEY_PATH=str(key), ANNUAIRE_JOURNAL=str(tmp_path / "j.db"),
               ANNUAIRE_LIB=ANN, ASSIST_LIB=ASSIST,
               PYTHONPATH=os.pathsep.join([ANN, ASSIST, env.get("PYTHONPATH", "")]))
    return env


def test_offer_then_matches_lists(tmp_path):
    env = _env(tmp_path)
    r = subprocess.run([sys.executable, CTL, "offer", "--tags", "lora", "--ttl",
                        "3600"], env=env, capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    assert json.loads(r.stdout).get("offer_id")


def test_dryrun_writes_nothing(tmp_path):
    env = _env(tmp_path); env["DRYRUN"] = "1"
    r = subprocess.run([sys.executable, CTL, "request-open", "--tags", "lora",
                        "--ttl", "600", "--reason", "x"], env=env,
                       capture_output=True, text=True)
    assert json.loads(r.stdout).get("dryrun") is True


def test_match_accept_bad_side_returns_json_error(tmp_path):
    env = _env(tmp_path)
    r = subprocess.run([sys.executable, CTL, "match-accept", "off-a", "orq-b",
                        "bogus"], env=env, capture_output=True, text=True)
    assert r.returncode != 0
    assert "Traceback" not in r.stderr
    assert "usage:" not in r.stderr
    out = r.stderr.strip() or r.stdout.strip()
    payload = json.loads(out)
    assert "error" in payload


def test_join_does_not_leak_private_key(tmp_path):
    env = _env(tmp_path)
    jl = subprocess.run([sys.executable, CTL, "joinlink", "--for", "match-xyz",
                        "--ttl", "600"], env=env, capture_output=True, text=True)
    assert jl.returncode == 0, jl.stderr
    link = json.loads(jl.stdout)
    token = link["url"].rsplit("/", 1)[-1]

    r = subprocess.run([sys.executable, CTL, "join", token, "--hash",
                        link["token_hash"], "--expires-at", link["expires_at"],
                        "--pubkey", "abc123pub=", "--endpoint", "1.2.3.4:51820",
                        "--ip", "10.11.0.5"], env=env, capture_output=True,
                       text=True)
    assert r.returncode == 0, r.stderr
    assert "priv_hex" not in r.stdout
    for word in r.stdout.replace('"', ' ').split():
        stripped = word.strip(",{}[]:")
        assert not (len(stripped) == 64 and all(c in "0123456789abcdef"
                                                for c in stripped.lower())), (
            f"raw 64-hex secret leaked in join output: {stripped!r}")


def _joinlink_base_url(tmp_path, conf_body=None, extra_env=None):
    env = _env(tmp_path); env["DRYRUN"] = "1"
    if conf_body is not None:
        conf = tmp_path / "secubox.conf"; conf.write_text(conf_body)
        env["SECUBOX_CONF"] = str(conf)
    else:
        env["SECUBOX_CONF"] = str(tmp_path / "does-not-exist.conf")
    env.pop("ASSIST_BASE_URL", None)
    if extra_env:
        env.update(extra_env)
    r = subprocess.run([sys.executable, CTL, "joinlink", "--for", "m1", "--ttl", "600"],
                       env=env, capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    return json.loads(r.stdout)["base_url"]


def test_joinlink_base_url_derived_from_sso_cookie_domain(tmp_path):
    # a hostname.local link only works on the LAN; derive the public hub instead
    url = _joinlink_base_url(tmp_path, '[api]\nsso_cookie_domain = ".gk2.secubox.in"\n')
    assert url == "https://admin.gk2.secubox.in"


def test_joinlink_base_url_falls_back_to_local_without_domain(tmp_path):
    assert _joinlink_base_url(tmp_path, conf_body=None) == "https://assist.local"


def test_joinlink_base_url_env_override_wins(tmp_path):
    url = _joinlink_base_url(tmp_path, '[api]\nsso_cookie_domain = ".gk2.secubox.in"\n',
                             extra_env={"ASSIST_BASE_URL": "https://custom.example.org"})
    assert url == "https://custom.example.org"
