# SPDX-License-Identifier: LicenseRef-CMSD-1.0
from secubox_toolbox import bundle


def test_loader_renders_top_bar():
    js = bundle.LOADER_JS
    assert "top:0" in js                       # banner pinned to top
    assert "bottom:0" not in js                # not a bottom bar anymore
    assert "paddingTop" in js                  # pushes content down
    # #620 arcade redesign — the bottom-edge divider is now the tier accent
    # (colour derived from b.level at render time), not a fixed brand green.
    assert 'border-bottom:2px solid " + acc' in js  # divider on the bottom edge, tier-accent


def test_loader_dismiss_resets_padding():
    js = bundle.LOADER_JS
    # dismiss must clear the body padding it added (no leftover gap)
    assert 'paddingTop = ""' in js or "paddingTop=''" in js or 'paddingTop = "0"' in js
