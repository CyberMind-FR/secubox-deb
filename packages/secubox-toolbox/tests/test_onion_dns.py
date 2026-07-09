from pathlib import Path
CONF = Path(__file__).resolve().parents[1] / "conf"
def test_dnsport_moved_off_avahi_5353():
    torrc = (CONF / "torrc-toolbox-egress.conf").read_text()
    assert "DNSPort 127.0.0.1:9053" in torrc
    assert "5353" not in torrc          # avahi owns 5353
def test_nft_redirect_targets_9053():
    nft = (CONF / "nft-toolbox-tor.nft").read_text()
    assert "redirect to :9053" in nft
    assert ":5353" not in nft
def test_unbound_onion_forward_zone_valid():
    conf = (CONF / "48-secubox-onion.conf").read_text()
    assert 'name: "onion."' in conf
    assert "forward-addr: 127.0.0.1@9053" in conf
