from proxypac.rules import Rule, parse_rules_dir, compose

def test_parse_rules_dir(tmp_path):
    (tmp_path / "10-a.rules").write_text("# c\n*.onion socks5 10.10.0.1:9050\n\n")
    (tmp_path / "20-b.rules").write_text("bank.example direct\n")
    rules = parse_rules_dir(tmp_path)
    assert [(r.host, r.directive) for r in rules] == [
        ("*.onion", "SOCKS5 10.10.0.1:9050; DIRECT"),
        ("bank.example", "DIRECT"),
    ]
    assert all(r.source == "override" for r in rules)

def test_compose_precedence_override_beats_service():
    ov = [Rule("x.com", "DIRECT", "override")]
    svc = [Rule("x.com", "PROXY p; DIRECT", "service:1"), Rule("y.com", "PROXY p; DIRECT", "service:1")]
    tb = Rule("*", "PROXY t; DIRECT", "toolbox")
    out = compose(ov, svc, tb)
    # override wins for x.com; y.com from service; toolbox catch-all last
    assert out == [("x.com", "DIRECT"), ("y.com", "PROXY p; DIRECT"), ("*", "PROXY t; DIRECT")]

def test_compose_no_toolbox():
    assert compose([], [], None) == []
