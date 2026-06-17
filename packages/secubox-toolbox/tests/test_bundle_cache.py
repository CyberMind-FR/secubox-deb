# SPDX-License-Identifier: LicenseRef-CMSD-1.0
from secubox_toolbox import bundle


def test_get_bundle_cache_keyed_by_is_wg(monkeypatch):
    bundle._cache.clear()
    wg = bundle.get_bundle("mh1", is_wg=True)
    r2 = bundle.get_bundle("mh1", is_wg=False)
    assert wg["report_url"] != r2["report_url"]
    assert wg["report_url"].startswith("https://kbin.gk2.secubox.in")
    assert r2["report_url"] == bundle.REPORT_URL_CAPTIVE
