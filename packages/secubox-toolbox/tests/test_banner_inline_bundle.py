# SPDX-License-Identifier: LicenseRef-CMSD-1.0
import sys, pathlib, importlib, re
ADDON_DIR = pathlib.Path(__file__).resolve().parents[1] / "mitmproxy_addons"
sys.path.insert(0, str(ADDON_DIR))
from mitmproxy.test import tflow  # noqa: E402


def test_attr_escape():
    import inject_banner
    assert inject_banner._attr_escape('a"b<c>&\'') == 'a&quot;b&lt;c&gt;&amp;&#39;'


def test_loader_script_inlines_bundle():
    import inject_banner; importlib.reload(inject_banner)
    out = inject_banner._loader_script(tflow.tflow()).decode("ascii", "ignore")
    assert 'src="/__toolbox/loader.js"' in out
    assert 'data-bundle="' in out                       # bundle inlined (no fetch needed)
    m = re.search(r'data-bundle="([^"]*)"', out)
    assert m and "&quot;" in m.group(1)                 # JSON quotes attr-escaped


def test_loader_js_uses_inline_then_fetch_fallback():
    from secubox_toolbox import bundle
    js = bundle.LOADER_JS
    assert "ds.bundle" in js and "JSON.parse" in js     # reads inlined bundle
    assert "setupReassert" in js                         # SPA re-assert present
    assert 'fetch("/__toolbox/bundle' in js              # fetch retained as fallback
