# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

# tests/test_license_headers.py
"""Tests for scripts/license-headers.py.

The tool's filename contains a hyphen so it is loaded via
importlib.util.spec_from_file_location rather than a normal import.
"""
from __future__ import annotations

import importlib.util
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
_TOOL_PATH = REPO_ROOT / "scripts" / "license-headers.py"

_spec = importlib.util.spec_from_file_location("license_headers", _TOOL_PATH)
license_headers = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(license_headers)


def test_module_imports():
    assert hasattr(license_headers, "main")


EXPECTED_HASH_HEADER = (
    "# SPDX-License-Identifier: LicenseRef-CMSD-1.0\n"
    "# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>\n"
    "# Source-Disclosed License — All rights reserved except as expressly granted.\n"
    "# See LICENCE-CMSD-1.0.md for terms.\n"
)


def test_render_header_hash():
    assert license_headers.render_header("hash") == EXPECTED_HASH_HEADER


EXPECTED_SLASH_HEADER = (
    "// SPDX-License-Identifier: LicenseRef-CMSD-1.0\n"
    "// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>\n"
    "// Source-Disclosed License — All rights reserved except as expressly granted.\n"
    "// See LICENCE-CMSD-1.0.md for terms.\n"
)

EXPECTED_BLOCK_HEADER = (
    "/*\n"
    " * SPDX-License-Identifier: LicenseRef-CMSD-1.0\n"
    " * Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>\n"
    " * Source-Disclosed License — All rights reserved except as expressly granted.\n"
    " * See LICENCE-CMSD-1.0.md for terms.\n"
    " */\n"
)

EXPECTED_HTML_HEADER = (
    "<!--\n"
    "  SPDX-License-Identifier: LicenseRef-CMSD-1.0\n"
    "  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>\n"
    "  Source-Disclosed License — All rights reserved except as expressly granted.\n"
    "  See LICENCE-CMSD-1.0.md for terms.\n"
    "-->\n"
)


def test_render_header_slash():
    assert license_headers.render_header("slash") == EXPECTED_SLASH_HEADER


def test_render_header_block():
    assert license_headers.render_header("block") == EXPECTED_BLOCK_HEADER


def test_render_header_html():
    assert license_headers.render_header("html") == EXPECTED_HTML_HEADER


def test_detect_existing_none_on_empty():
    assert license_headers.detect_existing("") == "NONE"


def test_detect_existing_none_on_plain_code():
    assert license_headers.detect_existing("print('hello')\n") == "NONE"


def test_detect_existing_match_hash():
    text = EXPECTED_HASH_HEADER + "\nprint('hello')\n"
    assert license_headers.detect_existing(text) == "MATCH"


def test_detect_existing_match_slash():
    text = EXPECTED_SLASH_HEADER + "\nconsole.log('hi');\n"
    assert license_headers.detect_existing(text) == "MATCH"


def test_detect_existing_match_block():
    text = EXPECTED_BLOCK_HEADER + "\nint main(void) { return 0; }\n"
    assert license_headers.detect_existing(text) == "MATCH"


def test_detect_existing_match_html():
    text = EXPECTED_HTML_HEADER + "\n<html></html>\n"
    assert license_headers.detect_existing(text) == "MATCH"


def test_detect_existing_foreign_mit():
    text = "# SPDX-License-Identifier: MIT\nprint('hello')\n"
    assert license_headers.detect_existing(text) == "FOREIGN"


def test_detect_existing_foreign_gpl():
    text = "// SPDX-License-Identifier: GPL-2.0-or-later\nint x;\n"
    assert license_headers.detect_existing(text) == "FOREIGN"


def test_detect_existing_only_checks_first_10_lines():
    """A CMSD line buried deep in the file should NOT be treated as MATCH."""
    text = "\n".join(["# unrelated"] * 20) + "\n# SPDX-License-Identifier: LicenseRef-CMSD-1.0\n"
    assert license_headers.detect_existing(text) == "NONE"


def test_apply_python_plain():
    src = '"""Docstring."""\nprint("hi")\n'
    out = license_headers.apply(src, ".py")
    assert out == EXPECTED_HASH_HEADER + "\n" + src


def test_apply_python_idempotent():
    src = '"""Docstring."""\nprint("hi")\n'
    once = license_headers.apply(src, ".py")
    twice = license_headers.apply(once, ".py")
    assert once == twice


def test_apply_foreign_python_unchanged():
    src = "# SPDX-License-Identifier: MIT\nprint('x')\n"
    out = license_headers.apply(src, ".py")
    assert out == src


def test_apply_python_with_shebang():
    src = '#!/usr/bin/env python3\nprint("x")\n'
    out = license_headers.apply(src, ".py")
    assert out.startswith("#!/usr/bin/env python3\n")
    assert out.splitlines()[1] == "# SPDX-License-Identifier: LicenseRef-CMSD-1.0"


def test_apply_python_with_encoding():
    src = '# -*- coding: utf-8 -*-\nprint("x")\n'
    out = license_headers.apply(src, ".py")
    assert out.startswith("# -*- coding: utf-8 -*-\n")
    assert out.splitlines()[1] == "# SPDX-License-Identifier: LicenseRef-CMSD-1.0"


def test_apply_python_with_shebang_and_encoding():
    src = '#!/usr/bin/env python3\n# -*- coding: utf-8 -*-\nprint("x")\n'
    out = license_headers.apply(src, ".py")
    lines = out.splitlines()
    assert lines[0] == "#!/usr/bin/env python3"
    assert lines[1] == "# -*- coding: utf-8 -*-"
    assert lines[2] == "# SPDX-License-Identifier: LicenseRef-CMSD-1.0"


def test_apply_bash_with_shebang():
    src = '#!/usr/bin/env bash\nset -euo pipefail\necho "hi"\n'
    out = license_headers.apply(src, ".sh")
    assert out.startswith("#!/usr/bin/env bash\n")
    assert out.splitlines()[1] == "# SPDX-License-Identifier: LicenseRef-CMSD-1.0"


def test_apply_bash_without_shebang():
    src = 'echo "hi"\n'
    out = license_headers.apply(src, ".sh")
    assert out.startswith("# SPDX-License-Identifier: LicenseRef-CMSD-1.0\n")


def test_apply_bash_idempotent():
    src = '#!/usr/bin/env bash\nset -e\n'
    once = license_headers.apply(src, ".sh")
    twice = license_headers.apply(once, ".sh")
    assert once == twice


def test_apply_javascript():
    src = 'console.log("hi");\n'
    out = license_headers.apply(src, ".js")
    assert out == EXPECTED_SLASH_HEADER + "\n" + src


def test_apply_typescript():
    src = 'const x: number = 1;\n'
    out = license_headers.apply(src, ".ts")
    assert out == EXPECTED_SLASH_HEADER + "\n" + src


def test_apply_css():
    src = 'body { color: red; }\n'
    out = license_headers.apply(src, ".css")
    assert out == EXPECTED_BLOCK_HEADER + "\n" + src


def test_apply_c():
    src = 'int main(void) { return 0; }\n'
    out = license_headers.apply(src, ".c")
    assert out == EXPECTED_BLOCK_HEADER + "\n" + src


def test_apply_idempotent_all_styles():
    cases = [
        (".js", 'console.log("x");\n'),
        (".ts", 'const x = 1;\n'),
        (".css", 'a { color: red; }\n'),
        (".c", 'int x;\n'),
        (".h", '#pragma once\n'),
    ]
    for ext, src in cases:
        once = license_headers.apply(src, ext)
        twice = license_headers.apply(once, ext)
        assert once == twice, f"non-idempotent for {ext}"


def test_apply_html_no_doctype():
    src = '<html><body>hi</body></html>\n'
    out = license_headers.apply(src, ".html")
    assert out == EXPECTED_HTML_HEADER + "\n" + src


def test_apply_html_with_doctype():
    src = '<!DOCTYPE html>\n<html><body>hi</body></html>\n'
    out = license_headers.apply(src, ".html")
    lines = out.splitlines(keepends=True)
    assert lines[0] == "<!DOCTYPE html>\n"
    assert lines[1] == "<!--\n"
    assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in lines[2]


def test_apply_html_idempotent():
    src = '<!DOCTYPE html>\n<html></html>\n'
    once = license_headers.apply(src, ".html")
    twice = license_headers.apply(once, ".html")
    assert once == twice


def test_apply_markdown_plain():
    src = '# Title\n\nBody.\n'
    out = license_headers.apply(src, ".md")
    assert out == EXPECTED_HTML_HEADER + "\n" + src


def test_apply_markdown_with_frontmatter():
    src = '---\ntitle: Foo\n---\n\n# Body\n'
    out = license_headers.apply(src, ".md")
    lines = out.splitlines(keepends=True)
    assert lines[0] == "---\n"
    assert lines[1] == "title: Foo\n"
    assert lines[2] == "---\n"
    assert lines[3] == "<!--\n"


def test_apply_markdown_idempotent_with_frontmatter():
    src = '---\ntitle: Foo\n---\n\nBody.\n'
    once = license_headers.apply(src, ".md")
    twice = license_headers.apply(once, ".md")
    assert once == twice


def test_walk_finds_python(tmp_path):
    (tmp_path / "a.py").write_text("x = 1\n")
    (tmp_path / "b.txt").write_text("ignore me\n")
    result = list(license_headers.walk([tmp_path], enrolled=["**"]))
    assert tmp_path / "a.py" in result
    assert tmp_path / "b.txt" not in result


def test_walk_prunes_kernel_build(tmp_path):
    (tmp_path / "kernel-build").mkdir()
    (tmp_path / "kernel-build" / "a.c").write_text("int x;\n")
    (tmp_path / "real.c").write_text("int y;\n")
    result = list(license_headers.walk([tmp_path], enrolled=["**"]))
    assert tmp_path / "real.c" in result
    assert tmp_path / "kernel-build" / "a.c" not in result


def test_walk_prunes_node_modules(tmp_path):
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "lib.js").write_text("// vendor\n")
    (tmp_path / "src.js").write_text("// app\n")
    result = list(license_headers.walk([tmp_path], enrolled=["**"]))
    assert tmp_path / "src.js" in result
    assert tmp_path / "node_modules" / "lib.js" not in result


def test_walk_skips_minified(tmp_path):
    (tmp_path / "app.min.js").write_text("// min\n")
    (tmp_path / "app.js").write_text("// raw\n")
    result = list(license_headers.walk([tmp_path], enrolled=["**"]))
    assert tmp_path / "app.js" in result
    assert tmp_path / "app.min.js" not in result


def test_walk_respects_empty_allowlist(tmp_path):
    (tmp_path / "a.py").write_text("x = 1\n")
    result = list(license_headers.walk([tmp_path], enrolled=[]))
    assert result == []


def test_walk_respects_glob_allowlist(tmp_path):
    (tmp_path / "common").mkdir()
    (tmp_path / "common" / "a.py").write_text("x = 1\n")
    (tmp_path / "other").mkdir()
    (tmp_path / "other" / "b.py").write_text("y = 1\n")
    result = list(license_headers.walk([tmp_path], enrolled=["common/**"]))
    rel = sorted(p.relative_to(tmp_path).as_posix() for p in result)
    assert rel == ["common/a.py"]


def _write_enrolled(tmp_path: Path, patterns: list[str]) -> Path:
    f = tmp_path / "scripts" / "license-headers-enrolled.txt"
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text("\n".join(patterns) + "\n")
    return f


def test_main_check_clean_repo(tmp_path, monkeypatch):
    (tmp_path / ".git").mkdir()
    (tmp_path / "scripts").mkdir(exist_ok=True)
    _write_enrolled(tmp_path, ["**"])
    (tmp_path / "a.py").write_text(EXPECTED_HASH_HEADER + "\nx = 1\n")
    monkeypatch.chdir(tmp_path)
    rc = license_headers.main(["--check"])
    assert rc == 0


def test_main_check_dirty_repo(tmp_path, monkeypatch, capsys):
    (tmp_path / ".git").mkdir()
    (tmp_path / "scripts").mkdir(exist_ok=True)
    _write_enrolled(tmp_path, ["**"])
    (tmp_path / "a.py").write_text("x = 1\n")
    monkeypatch.chdir(tmp_path)
    rc = license_headers.main(["--check"])
    assert rc == 1
    out = capsys.readouterr().out
    assert "a.py" in out


def test_main_fix_writes_files(tmp_path, monkeypatch):
    (tmp_path / ".git").mkdir()
    (tmp_path / "scripts").mkdir(exist_ok=True)
    _write_enrolled(tmp_path, ["**"])
    f = tmp_path / "a.py"
    f.write_text("x = 1\n")
    monkeypatch.chdir(tmp_path)
    rc = license_headers.main(["--fix"])
    assert rc == 0
    text = f.read_text()
    assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in text


def test_main_list(tmp_path, monkeypatch, capsys):
    (tmp_path / ".git").mkdir()
    (tmp_path / "scripts").mkdir(exist_ok=True)
    _write_enrolled(tmp_path, ["**"])
    (tmp_path / "a.py").write_text("x = 1\n")
    monkeypatch.chdir(tmp_path)
    rc = license_headers.main(["--list"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "a.py" in out


def test_main_diff(tmp_path, monkeypatch, capsys):
    (tmp_path / ".git").mkdir()
    (tmp_path / "scripts").mkdir(exist_ok=True)
    _write_enrolled(tmp_path, ["**"])
    (tmp_path / "a.py").write_text("x = 1\n")
    monkeypatch.chdir(tmp_path)
    rc = license_headers.main(["--diff"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in out
    # File was not modified by --diff
    assert (tmp_path / "a.py").read_text() == "x = 1\n"


def test_main_modes_mutually_exclusive():
    rc = license_headers.main(["--check", "--fix"])
    assert rc == 2


def test_main_requires_a_mode():
    rc = license_headers.main([])
    assert rc == 2


def test_main_empty_allowlist_passes_check(tmp_path, monkeypatch):
    """An empty enrollment file means nothing is checked — Phase A initial state."""
    (tmp_path / ".git").mkdir()
    (tmp_path / "scripts").mkdir(exist_ok=True)
    _write_enrolled(tmp_path, [])
    (tmp_path / "a.py").write_text("x = 1\n")  # no header, but not enrolled
    monkeypatch.chdir(tmp_path)
    rc = license_headers.main(["--check"])
    assert rc == 0
