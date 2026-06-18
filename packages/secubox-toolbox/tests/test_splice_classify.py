# tests/test_splice_classify.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
from secubox_toolbox import splice


def test_host_matches_exact_and_subdomain():
    pats = {"googlevideo.com", "fbcdn.net"}
    assert splice.host_matches("googlevideo.com", pats)
    assert splice.host_matches("r1---sn-x.googlevideo.com", pats)
    assert not splice.host_matches("notgooglevideo.com", pats)   # no false prefix
    assert not splice.host_matches("example.com", pats)


def test_should_splice_seed_and_learned():
    seed = {"googlevideo.com"}; learned = {"cdn.example.net"}; never = set()
    assert splice.should_splice("x.googlevideo.com", seed, learned, never)
    assert splice.should_splice("cdn.example.net", seed, learned, never)
    assert not splice.should_splice("news.example.com", seed, learned, never)


def test_never_wins():
    seed = {"evil-cdn.com"}; never = {"evil-cdn.com"}
    assert not splice.should_splice("evil-cdn.com", seed, set(), never)


def test_empty_sni_or_sets():
    assert not splice.should_splice("", {"a.com"}, set(), set())
    assert not splice.should_splice("a.com", set(), set(), set())


def test_load_seed_strips_comments(tmp_path):
    f = tmp_path / "seed.conf"
    f.write_text("# header\ngooglevideo.com  # yt\n\n  fbcdn.net\n")
    s = splice.load_splice_seed(str(f))
    assert s == {"googlevideo.com", "fbcdn.net"}
