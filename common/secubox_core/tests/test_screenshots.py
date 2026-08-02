import json
from datetime import datetime

import pytest
from secubox_core import screenshots


def test_png_and_meta_paths_are_scoped_under_the_key(tmp_path):
    assert screenshots.png_path(tmp_path, "myapp") == tmp_path / "myapp" / "screenshot.png"
    assert screenshots.meta_path(tmp_path, "myapp") == tmp_path / "myapp" / "screenshot.json"


@pytest.mark.parametrize("bad_key", ["", ".", "..", "a/b", "a\\b", "../escape"])
def test_rejects_keys_that_would_escape_their_directory(tmp_path, bad_key):
    with pytest.raises(ValueError):
        screenshots.png_path(tmp_path, bad_key)


def test_read_meta_is_empty_when_nothing_was_ever_recorded(tmp_path):
    assert screenshots.read_meta(tmp_path, "myapp") == {}


def test_read_meta_is_empty_on_corrupt_json(tmp_path):
    screenshots.meta_path(tmp_path, "myapp").parent.mkdir(parents=True)
    screenshots.meta_path(tmp_path, "myapp").write_text("{not json")
    assert screenshots.read_meta(tmp_path, "myapp") == {}


def test_read_meta_is_empty_when_json_is_not_an_object(tmp_path):
    screenshots.meta_path(tmp_path, "myapp").parent.mkdir(parents=True)
    screenshots.meta_path(tmp_path, "myapp").write_text("[1, 2, 3]")
    assert screenshots.read_meta(tmp_path, "myapp") == {}


def test_is_stale_when_never_captured(tmp_path):
    assert screenshots.is_stale(tmp_path, "myapp", "fp-1") is True


def test_record_success_writes_png_and_meta(tmp_path):
    meta = screenshots.record(tmp_path, "myapp", b"\x89PNG...", "fp-1", ok=True)

    assert screenshots.png_path(tmp_path, "myapp").read_bytes() == b"\x89PNG..."
    stored = screenshots.read_meta(tmp_path, "myapp")
    assert stored["fingerprint"] == "fp-1"
    assert stored["ok"] is True
    assert "captured_at" in stored
    # RFC 3339 : doit être parsable, tz-aware.
    parsed = datetime.fromisoformat(stored["captured_at"])
    assert parsed.tzinfo is not None
    assert meta == stored


def test_is_stale_false_once_recorded_with_matching_fingerprint(tmp_path):
    screenshots.record(tmp_path, "myapp", b"png-bytes", "fp-1", ok=True)
    assert screenshots.is_stale(tmp_path, "myapp", "fp-1") is False


def test_is_stale_true_when_fingerprint_changed(tmp_path):
    screenshots.record(tmp_path, "myapp", b"png-bytes", "fp-1", ok=True)
    assert screenshots.is_stale(tmp_path, "myapp", "fp-2") is True


def test_is_stale_true_after_a_failed_attempt_even_with_matching_fingerprint(tmp_path):
    """Un échec doit toujours redéclencher une tentative au prochain passage,
    même si la source n'a pas changé depuis — sinon une capture ratée reste
    bloquée indéfiniment sans jamais retenter."""
    screenshots.record(tmp_path, "myapp", b"png-bytes", "fp-1", ok=True)
    screenshots.record(tmp_path, "myapp", None, "fp-1", ok=False)
    assert screenshots.is_stale(tmp_path, "myapp", "fp-1") is True


def test_failed_capture_preserves_the_previous_png(tmp_path):
    """Règle impérative : une capture en échec conserve l'image précédente.
    Même si `png` est fourni (par erreur ou par appelant trop prudent), une
    tentative marquée `ok=False` ne doit jamais écraser le fichier existant."""
    screenshots.record(tmp_path, "myapp", b"good-render", "fp-1", ok=True)
    screenshots.record(tmp_path, "myapp", b"garbage-partial-render", "fp-2", ok=False)

    assert screenshots.png_path(tmp_path, "myapp").read_bytes() == b"good-render"
    stored = screenshots.read_meta(tmp_path, "myapp")
    assert stored["ok"] is False
    assert stored["fingerprint"] == "fp-2"


def test_failed_capture_with_no_prior_png_leaves_no_png_at_all(tmp_path):
    """Premier essai raté sur une clé neuve : aucun PNG ne doit apparaître —
    seul le fichier de métadonnées est écrit."""
    screenshots.record(tmp_path, "myapp", None, "fp-1", ok=False)

    assert not screenshots.png_path(tmp_path, "myapp").exists()
    stored = screenshots.read_meta(tmp_path, "myapp")
    assert stored["ok"] is False


def test_record_returns_the_metadata_it_wrote(tmp_path):
    meta = screenshots.record(tmp_path, "myapp", b"bytes", "fp-1", ok=True)
    assert meta == screenshots.read_meta(tmp_path, "myapp")


def test_png_write_is_atomic_no_stray_temp_files_left_behind(tmp_path):
    screenshots.record(tmp_path, "myapp", b"final-content", "fp-1", ok=True)
    app_dir = tmp_path / "myapp"
    names = sorted(p.name for p in app_dir.iterdir())
    assert names == ["screenshot.json", "screenshot.png"]


def test_written_png_is_group_and_world_readable_within_the_process_umask(tmp_path):
    """`tempfile.mkstemp()` (used internally by `_atomic_write_bytes`) always
    creates its file in 0600, bypassing the umask by design -- fine for a
    file only its own writer ever reads, but wrong here: the vignette is
    meant to be produced by a root timer and served by the aggregator
    running as `secubox`. Verified on the board: thumbnails were
    `-rw------- secubox secubox` -- harmless today only because producer
    and reader happen to be the same user; the moment a root-run producer
    lands, the aggregator can no longer read them. The write must end with
    an explicit, readable mode, still capped by whatever the process umask
    forbids."""
    import os
    import stat

    test_umask = 0o022
    original_umask = os.umask(test_umask)
    try:
        screenshots.record(tmp_path, "myapp", b"final-content", "fp-1", ok=True)
    finally:
        os.umask(original_umask)

    png_mode = stat.S_IMODE(screenshots.png_path(tmp_path, "myapp").stat().st_mode)
    meta_mode = stat.S_IMODE(screenshots.meta_path(tmp_path, "myapp").stat().st_mode)

    expected = 0o644 & ~test_umask
    assert png_mode == expected, (
        f"screenshot.png mode is {oct(png_mode)}, expected {oct(expected)} -- "
        "mkstemp's hardcoded 0600 must not survive the atomic replace"
    )
    assert meta_mode == expected, (
        f"screenshot.json mode is {oct(meta_mode)}, expected {oct(expected)}"
    )


def test_write_failure_never_leaves_a_partial_file_and_preserves_the_original(
        tmp_path, monkeypatch):
    """Simule un échec au milieu de l'écriture (ex. disque plein au moment du
    `fsync`) : le fichier cible doit rester exactement dans son état
    précédent, et aucun fichier temporaire ne doit traîner."""
    screenshots.record(tmp_path, "myapp", b"original-good-content", "fp-1", ok=True)

    def boom_fsync(_fd):
        raise OSError("disque plein (simulé)")

    monkeypatch.setattr(screenshots.os, "fsync", boom_fsync)

    with pytest.raises(OSError):
        screenshots.record(tmp_path, "myapp", b"new-content-that-should-not-land",
                           "fp-2", ok=True)

    # Le PNG cible n'a pas bougé : toujours l'ancien contenu complet.
    assert screenshots.png_path(tmp_path, "myapp").read_bytes() == b"original-good-content"
    # Aucun résidu de fichier temporaire dans le répertoire.
    app_dir = tmp_path / "myapp"
    leftovers = [p.name for p in app_dir.iterdir() if p.name.startswith(".tmp-")]
    assert leftovers == []


def test_meta_write_is_valid_json_with_expected_fields(tmp_path):
    screenshots.record(tmp_path, "myapp", b"x", "the-fingerprint", ok=True)
    raw = json.loads(screenshots.meta_path(tmp_path, "myapp").read_text())
    assert set(raw) == {"captured_at", "fingerprint", "ok"}
    assert raw["fingerprint"] == "the-fingerprint"


def test_different_keys_are_fully_isolated(tmp_path):
    screenshots.record(tmp_path, "app-a", b"a-bytes", "fp-a", ok=True)
    screenshots.record(tmp_path, "app-b", b"b-bytes", "fp-b", ok=True)

    assert screenshots.png_path(tmp_path, "app-a").read_bytes() == b"a-bytes"
    assert screenshots.png_path(tmp_path, "app-b").read_bytes() == b"b-bytes"
    assert screenshots.is_stale(tmp_path, "app-a", "fp-a") is False
    assert screenshots.is_stale(tmp_path, "app-b", "fp-wrong") is True
