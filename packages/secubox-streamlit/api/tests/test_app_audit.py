import json
import subprocess
from pathlib import Path

CTL = Path(__file__).resolve().parents[2] / "sbin" / "streamlitctl"


def _audit(tmp_path, dirs=(), scripts=(), declared=()):
    apps = tmp_path / "apps"; apps.mkdir()
    conf = tmp_path / "streamlit.toml"
    conf.write_text("".join(f'[apps.{n}]\n' for n in declared))
    for name, main in dirs:
        d = apps / name; d.mkdir()
        if main:
            (d / main).write_text("import streamlit\n")
    for name in scripts:
        (apps / name).write_text("import streamlit\n")
    env = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
           "SECUBOX_STREAMLIT_APPS_PATH": str(apps),
           "SECUBOX_STREAMLIT_CONF": str(conf),
           "SECUBOX_STREAMLIT_IDLE_DIR": str(tmp_path / "idle"),
           "SECUBOX_STREAMLIT_PS_SOURCE": str(tmp_path / "ps.txt")}
    (tmp_path / "ps.txt").touch()
    r = subprocess.run(["bash", str(CTL), "app", "audit"],
                       capture_output=True, text=True, env=env, timeout=30)
    return json.loads(r.stdout)


def test_sees_bare_scripts_not_only_directories(tmp_path):
    """43 des 87 entrées de la board sont des scripts à plat, et 12 d'entre
    elles tournent. Les ignorer était la cause du mur vide."""
    out = _audit(tmp_path, dirs=[("avec_dir", "app.py")], scripts=["a_plat.py"])
    names = {a["name"]: a["shape"] for a in out["apps"]}
    assert names == {"avec_dir": "dir", "a_plat": "script"}


def test_flags_directory_without_entrypoint(tmp_path):
    out = _audit(tmp_path, dirs=[("vide", None)])
    app = out["apps"][0]
    assert app["entrypoint"] == ""
    assert "no-entrypoint" in app["issues"]


def test_flags_declared_but_missing(tmp_path):
    out = _audit(tmp_path, declared=["fantome"])
    ghost = [a for a in out["apps"] if a["name"] == "fantome"][0]
    assert "declared-missing" in ghost["issues"]


def test_flags_present_but_undeclared(tmp_path):
    out = _audit(tmp_path, scripts=["orphelin.py"])
    app = out["apps"][0]
    assert "not-declared" in app["issues"]


def test_running_is_read_from_the_process_source(tmp_path):
    apps = tmp_path / "apps"; apps.mkdir()
    (apps / "vivant.py").write_text("import streamlit\n")
    (tmp_path / "ps.txt").write_text("streamlit run vivant.py --server.port 8599\n")
    conf = tmp_path / "streamlit.toml"; conf.write_text("[apps.vivant]\n")
    env = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
           "SECUBOX_STREAMLIT_APPS_PATH": str(apps),
           "SECUBOX_STREAMLIT_CONF": str(conf),
           "SECUBOX_STREAMLIT_IDLE_DIR": str(tmp_path / "idle"),
           "SECUBOX_STREAMLIT_PS_SOURCE": str(tmp_path / "ps.txt")}
    r = subprocess.run(["bash", str(CTL), "app", "audit"],
                       capture_output=True, text=True, env=env, timeout=30)
    app = json.loads(r.stdout)["apps"][0]
    assert app["running"] is True
    assert app["port"] == 8599


def test_summary_counts_match_the_app_list(tmp_path):
    out = _audit(tmp_path, dirs=[("d1", "app.py"), ("d2", None)], scripts=["s1.py"])
    assert out["summary"]["total"] == len(out["apps"]) == 3
    assert out["summary"]["running"] == 0


def test_ps_lines_does_not_pin_lxc_attach_to_a_hardcoded_lxcpath(tmp_path):
    """Regression: _ps_lines() used to call `lxc-attach -P /var/lib/lxc/...`,
    a hardcoded path that doesn't match the board's real lxc.lxcpath
    (/data/lxc, configured in /etc/lxc/lxc.conf). That made every real
    process invisible, so the deployed audit reported 0 running apps out of
    66 while 15 were actually up. lxc-attach must be left to resolve its own
    lxc.lxcpath instead of being pinned here.

    This test doesn't fake a container (SECUBOX_STREAMLIT_PS_SOURCE is not
    set), it doubles the `lxc-attach` binary itself via PATH and inspects the
    argv it actually received — the constructed command, not a simulated
    ps output."""
    apps = tmp_path / "apps"; apps.mkdir()
    conf = tmp_path / "streamlit.toml"; conf.write_text("")

    fake_bin = tmp_path / "fakebin"; fake_bin.mkdir()
    call_log = tmp_path / "lxc-attach.args"
    fake_lxc_attach = fake_bin / "lxc-attach"
    fake_lxc_attach.write_text(
        "#!/bin/sh\n"
        'for a in "$@"; do printf \'%s\\n\' "$a" >> "$LXC_ATTACH_LOG"; done\n'
        "exit 0\n"
    )
    fake_lxc_attach.chmod(0o755)

    env = {"PATH": f"{fake_bin}:/usr/bin:/bin:/usr/sbin:/sbin",
           "LXC_ATTACH_LOG": str(call_log),
           "SECUBOX_STREAMLIT_APPS_PATH": str(apps),
           "SECUBOX_STREAMLIT_CONF": str(conf),
           "SECUBOX_STREAMLIT_IDLE_DIR": str(tmp_path / "idle")}
    # Deliberately no SECUBOX_STREAMLIT_PS_SOURCE: exercise the real
    # lxc-attach branch of _ps_lines().
    subprocess.run(["bash", str(CTL), "app", "audit"],
                    capture_output=True, text=True, env=env, timeout=30)

    assert call_log.exists(), "lxc-attach double was never invoked"
    argv = call_log.read_text().splitlines()
    assert "-P" not in argv


def test_running_process_matched_via_declared_path_not_filename_heuristic(tmp_path):
    """The central TOML links a declared app name to its script through a
    `path = "..."` field inside `[apps.NAME]` — verified on the board as the
    reliable name<->process link. A running process must be attributed to
    the declared name even when it doesn't match the filename-derived
    heuristic (_app_name_of_script), otherwise the same app shows up twice:
    once as declared-but-not-running and once as running-but-not-declared."""
    apps = tmp_path / "apps"; apps.mkdir()
    conf = tmp_path / "streamlit.toml"
    conf.write_text('[apps.metabolizer]\npath = "metabolizer_v2.py"\n')
    (tmp_path / "ps.txt").write_text(
        "streamlit run metabolizer_v2.py --server.port 8520\n")
    env = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
           "SECUBOX_STREAMLIT_APPS_PATH": str(apps),
           "SECUBOX_STREAMLIT_CONF": str(conf),
           "SECUBOX_STREAMLIT_IDLE_DIR": str(tmp_path / "idle"),
           "SECUBOX_STREAMLIT_PS_SOURCE": str(tmp_path / "ps.txt")}
    r = subprocess.run(["bash", str(CTL), "app", "audit"],
                       capture_output=True, text=True, env=env, timeout=30)
    out = json.loads(r.stdout)
    assert [a["name"] for a in out["apps"]] == ["metabolizer"]
    app = out["apps"][0]
    assert app["running"] is True
    assert app["port"] == 8520
