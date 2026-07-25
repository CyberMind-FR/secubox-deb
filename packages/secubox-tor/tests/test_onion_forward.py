from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
def test_onion_forward_targets_tor_dnsport_and_keeps_automap_range():
    c = (ROOT / "conf/unbound/secubox-onion-forward.conf").read_text()
    assert 'forward-zone:' in c and 'name: "onion."' in c
    assert '127.0.0.1@9053' in c
    # sinon Unbound strippe le range automap privé 10.192.0.0/10 :
    assert 'private-domain: "onion."' in c
    # Débloque le .onion : sans ça Unbound répond NXDOMAIN autoritaire
    # (blocage RFC 6761 special-use par défaut) et ne forwarde jamais.
    # Validé en live : ces deux directives sont indispensables.
    assert 'local-zone: "onion." transparent' in c
    # Tor DNSPort renvoie des réponses non signées → pas de validation DNSSEC :
    assert 'domain-insecure: "onion."' in c
