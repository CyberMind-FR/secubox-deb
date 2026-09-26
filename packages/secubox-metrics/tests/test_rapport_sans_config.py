"""#1497 — une box neuve (aucune config [rapport.*]) n'expédie rien."""
import rapport_planifie as rp
import rapport_waf as rw


def test_planifie_sans_config_ne_part_pas(monkeypatch, tmp_path):
    monkeypatch.setattr(rp, "CONF", tmp_path / "absent.toml")
    c = rp.config_planifie()
    assert c["famille"] == "" and c["destinataire"] == ""
    # main sort proprement AVANT d'agréger quoi que ce soit.
    assert rp.main([]) == 0


def test_waf_sans_destinataire_ne_part_pas(monkeypatch, tmp_path):
    monkeypatch.setattr(rw, "CONF", tmp_path / "absent.toml")
    appels = []
    res = rw.executer_waf(lambda: appels.append("lu") or {"jours": [1]},
                          lambda *a: b"pdf", lambda *a: appels.append("envoi"))
    assert res["envoye"] is False and "destinataire" in res["raison"]
    assert appels == []


def test_waf_destinataire_configure(monkeypatch, tmp_path):
    conf = tmp_path / "m.toml"
    conf.write_text('[rapport.waf]\ndestinataire = "moi@box"\n')
    monkeypatch.setattr(rw, "CONF", conf)
    assert rw.config_waf()["destinataire"] == "moi@box"


def test_waf_main_sans_config_sort_avant_matplotlib(monkeypatch, tmp_path):
    monkeypatch.setattr(rw, "CONF", tmp_path / "absent.toml")
    assert rw.main([]) == 0
