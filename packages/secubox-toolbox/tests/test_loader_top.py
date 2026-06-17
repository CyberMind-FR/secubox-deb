# SPDX-License-Identifier: LicenseRef-CMSD-1.0
from secubox_toolbox import bundle


def test_loader_renders_top_bar():
    js = bundle.LOADER_JS
    assert "top:0" in js                       # banner pinned to top
    assert "bottom:0" not in js                # not a bottom bar anymore
    assert "paddingTop" in js                  # pushes content down
    assert "border-bottom:2px solid #148C66" in js  # divider now on the bottom edge


def test_loader_dismiss_resets_padding():
    js = bundle.LOADER_JS
    # dismiss must clear the body padding it added (no leftover gap)
    assert 'paddingTop = ""' in js or "paddingTop=''" in js or 'paddingTop = "0"' in js
