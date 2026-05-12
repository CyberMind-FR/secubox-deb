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
