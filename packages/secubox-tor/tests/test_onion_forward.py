from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
def test_onion_forward_targets_tor_dnsport_and_keeps_automap_range():
    c = (ROOT / "conf/unbound/secubox-onion-forward.conf").read_text()
    assert 'forward-zone:' in c and 'name: "onion."' in c
    assert '127.0.0.1@9053' in c
    # sinon Unbound strippe le range automap privé 10.192.0.0/10 :
    assert 'private-domain: "onion."' in c
