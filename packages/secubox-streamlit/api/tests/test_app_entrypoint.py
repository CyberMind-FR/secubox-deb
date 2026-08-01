"""Tests for the widened entry-point detection in `streamlitctl app audit`
(#956). The old detection only looked for app.py/main.py/streamlit_app.py
at the app directory's root, which flagged 10 real, live apps on the board
as "no-entrypoint" — nearly leading to their deletion. Ground truth for
every scenario below was verified directly on the board (`ls -la
/srv/streamlit/apps/<app>/` inside the streamlit LXC):

  Photo_cloud_streamlit_main/  -> photo_cloud_streamlit.py   (single root .py)
  control/                     -> src/app.py                 (7 root .py,
                                   none conventional; resolved one level
                                   down via the conventional name in src/)
  yijing/, yijing_oracle/,
  yijing.bak.rolledback.*/     -> yijing-oracle/app.py        (.git + a
                                   single nested subdir, root has no .py)

This file also covers the inventory-pollution exclusions (__pycache__,
pages/, dotfiles) required alongside the widened detection.
"""
import json
import subprocess
from pathlib import Path

CTL = Path(__file__).resolve().parents[2] / "sbin" / "streamlitctl"


def _run_audit(tmp_path):
    conf = tmp_path / "streamlit.toml"
    conf.write_text("")
    env = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
           "SECUBOX_STREAMLIT_APPS_PATH": str(tmp_path / "apps"),
           "SECUBOX_STREAMLIT_CONF": str(conf),
           "SECUBOX_STREAMLIT_IDLE_DIR": str(tmp_path / "idle"),
           "SECUBOX_STREAMLIT_PS_SOURCE": str(tmp_path / "ps.txt")}
    (tmp_path / "ps.txt").touch()
    r = subprocess.run(["bash", str(CTL), "app", "audit"],
                        capture_output=True, text=True, env=env, timeout=30)
    assert r.returncode == 0, r.stderr
    return json.loads(r.stdout)


def _app(out, name):
    matches = [a for a in out["apps"] if a["name"] == name]
    assert matches, f"{name} missing from audit output: {out['apps']}"
    return matches[0]


# ─────────────────────────────────────────────────────────────────────
# Rule 1: conventional names still take priority
# ─────────────────────────────────────────────────────────────────────

def test_conventional_name_wins_even_with_other_py_files_present(tmp_path):
    """Regression guard: a conventional app.py must never be shadowed by
    the new fallback rules, even when other .py files sit alongside it."""
    apps = tmp_path / "apps"
    d = apps / "metabolizer"
    d.mkdir(parents=True)
    (d / "app.py").write_text("import streamlit\n")
    (d / "helpers.py").write_text("# not an entrypoint\n")
    out = _run_audit(tmp_path)
    app = _app(out, "metabolizer")
    assert app["entrypoint"] == "app.py"
    assert "no-entrypoint" not in app["issues"]
    assert app["entrypoint_candidates"] == 0


# ─────────────────────────────────────────────────────────────────────
# Rule 2: exactly one .py at the root, non-conventional name
# ─────────────────────────────────────────────────────────────────────

def test_single_non_conventional_root_script_is_the_entrypoint(tmp_path):
    """Board case: Photo_cloud_streamlit_main/photo_cloud_streamlit.py —
    one lonely, oddly-named .py file at the root."""
    apps = tmp_path / "apps"
    d = apps / "Photo_cloud_streamlit_main"
    d.mkdir(parents=True)
    (d / "photo_cloud_streamlit.py").write_text("import streamlit\n")
    (d / "README.md").write_text("readme\n")
    out = _run_audit(tmp_path)
    app = _app(out, "Photo_cloud_streamlit_main")
    assert app["entrypoint"] == "photo_cloud_streamlit.py"
    assert "no-entrypoint" not in app["issues"]


# ─────────────────────────────────────────────────────────────────────
# Rule 3: one level down, same two rules applied inside a single subdir
# ─────────────────────────────────────────────────────────────────────

def test_resolves_through_a_single_nested_subdir_with_conventional_name(tmp_path):
    """Board case: yijing/ (and its two siblings) hold a .git checkout and
    a single nested yijing-oracle/ directory containing the real app.py.
    The root itself has zero .py files."""
    apps = tmp_path / "apps"
    d = apps / "yijing"
    (d / ".git").mkdir(parents=True)
    (d / ".git" / "HEAD").write_text("ref: refs/heads/main\n")
    oracle = d / "yijing-oracle"
    oracle.mkdir()
    (oracle / "app.py").write_text("import streamlit\n")
    (oracle / "README.md").write_text("readme\n")
    out = _run_audit(tmp_path)
    app = _app(out, "yijing")
    assert app["entrypoint"] == "yijing-oracle/app.py"
    assert "no-entrypoint" not in app["issues"]


def test_resolves_through_a_single_nested_subdir_with_a_lone_py(tmp_path):
    """Same one-level-down search, but the subdir itself has no
    conventional name — just a single .py (rule 2 applied recursively)."""
    apps = tmp_path / "apps"
    d = apps / "control"
    d.mkdir(parents=True)
    for name in ["test_auth", "test_dashboard", "test_full_auth",
                 "test_login", "test_login_flow", "test_permissions",
                 "test_ubus"]:
        (d / f"{name}.py").write_text("# test helper, not an entrypoint\n")
    src = d / "src"
    src.mkdir()
    (src / "app.py").write_text("import streamlit\n")
    out = _run_audit(tmp_path)
    app = _app(out, "control")
    assert app["entrypoint"] == "src/app.py"
    assert "no-entrypoint" not in app["issues"]


def test_subdir_search_ignores_pages_and_pycache_and_dotdirs(tmp_path):
    """The one-level-down search must not wander into a pages/ (Streamlit
    multi-page convention) or __pycache__ subdir and mistake a stray
    single .py there for the app's entrypoint."""
    apps = tmp_path / "apps"
    d = apps / "multi_page_app"
    d.mkdir(parents=True)
    pages = d / "pages"
    pages.mkdir()
    (pages / "1_only_page.py").write_text("import streamlit\n")
    cache = d / "__pycache__"
    cache.mkdir()
    (cache / "app.cpython-311.pyc").write_text("binary\n")
    hidden = d / ".hidden"
    hidden.mkdir()
    (hidden / "app.py").write_text("import streamlit\n")
    out = _run_audit(tmp_path)
    app = _app(out, "multi_page_app")
    assert app["entrypoint"] == ""
    assert "no-entrypoint" in app["issues"]
    assert app["entrypoint_candidates"] == 0


# ─────────────────────────────────────────────────────────────────────
# Rule 4: ambiguity is reported, never guessed
# ─────────────────────────────────────────────────────────────────────

def test_ambiguous_root_py_files_are_flagged_with_candidate_count(tmp_path):
    """No conventional name, no single root .py, and no subdir resolves
    it either: don't guess, report the count for a human to decide."""
    apps = tmp_path / "apps"
    d = apps / "ambiguous"
    d.mkdir(parents=True)
    (d / "one.py").write_text("import streamlit\n")
    (d / "two.py").write_text("import streamlit\n")
    (d / "three.py").write_text("import streamlit\n")
    out = _run_audit(tmp_path)
    app = _app(out, "ambiguous")
    assert app["entrypoint"] == ""
    assert "no-entrypoint" in app["issues"]
    assert app["entrypoint_candidates"] == 3


def test_ambiguous_subdir_candidates_are_flagged_with_candidate_count(tmp_path):
    """Two different subdirs each resolve to their own single candidate:
    still ambiguous at the parent level, still must not guess."""
    apps = tmp_path / "apps"
    d = apps / "two_subdirs"
    d.mkdir(parents=True)
    sub_a = d / "variant_a"; sub_a.mkdir()
    (sub_a / "app.py").write_text("import streamlit\n")
    sub_b = d / "variant_b"; sub_b.mkdir()
    (sub_b / "run.py").write_text("import streamlit\n")
    out = _run_audit(tmp_path)
    app = _app(out, "two_subdirs")
    assert app["entrypoint"] == ""
    assert "no-entrypoint" in app["issues"]
    assert app["entrypoint_candidates"] == 2


def test_still_flags_a_truly_empty_directory(tmp_path):
    """Baseline regression: a directory with no .py anywhere (root or one
    level down) is still reported as no-entrypoint, with candidates=0."""
    apps = tmp_path / "apps"
    d = apps / "truly_empty"
    d.mkdir(parents=True)
    (d / "README.md").write_text("nothing here\n")
    out = _run_audit(tmp_path)
    app = _app(out, "truly_empty")
    assert app["entrypoint"] == ""
    assert "no-entrypoint" in app["issues"]
    assert app["entrypoint_candidates"] == 0


# ─────────────────────────────────────────────────────────────────────
# Part 2: __pycache__, pages, and dotfiles are excluded from the
# inventory entirely — never an app, never an anomaly.
# ─────────────────────────────────────────────────────────────────────

def test_pycache_at_apps_root_is_not_inventoried(tmp_path):
    apps = tmp_path / "apps"
    apps.mkdir()
    cache = apps / "__pycache__"
    cache.mkdir()
    (cache / "whatever.pyc").write_text("binary\n")
    out = _run_audit(tmp_path)
    names = {a["name"] for a in out["apps"]}
    assert "__pycache__" not in names
    assert out["summary"]["total"] == 0


def test_pages_at_apps_root_is_not_inventoried(tmp_path):
    """Board reality: pages/ under $APPS_PATH holds metabolizer's
    sub-pages (1_editor.py..4_settings.py, referenced by metabolizer.py).
    Treating it as its own (entrypoint-less) app is wrong and would risk
    it being proposed for deletion, breaking metabolizer."""
    apps = tmp_path / "apps"
    pages = apps / "pages"
    pages.mkdir(parents=True)
    for n in ["1_editor", "2_posts", "3_media", "4_settings"]:
        (pages / f"{n}.py").write_text("import streamlit\n")
    metabolizer = apps / "metabolizer"
    metabolizer.mkdir()
    (metabolizer / "app.py").write_text("import streamlit\n")
    out = _run_audit(tmp_path)
    names = {a["name"] for a in out["apps"]}
    assert "pages" not in names
    assert names == {"metabolizer"}


def test_dotdirs_at_apps_root_are_not_inventoried(tmp_path):
    apps = tmp_path / "apps"
    apps.mkdir()
    dotdir = apps / ".git"
    dotdir.mkdir()
    (dotdir / "HEAD").write_text("ref: refs/heads/main\n")
    out = _run_audit(tmp_path)
    names = {a["name"] for a in out["apps"]}
    assert ".git" not in names
    assert out["summary"]["total"] == 0
