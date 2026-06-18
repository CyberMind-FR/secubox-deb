# tests/test_filters_adlearn.py
from secubox_toolbox import filters
def test_ad_learn_default_true(monkeypatch, tmp_path):
    monkeypatch.setattr(filters, "FILTERS_PATH", str(tmp_path / "f.json"))
    assert filters.get_filters(force=True)["ad_learn"] is True
def test_ad_learn_set_bool(monkeypatch, tmp_path):
    monkeypatch.setattr(filters, "FILTERS_PATH", str(tmp_path / "f.json"))
    assert filters.set_filters({"ad_learn": False})["ad_learn"] is False
