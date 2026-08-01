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
