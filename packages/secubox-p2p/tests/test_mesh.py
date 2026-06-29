import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))  # repo package root
from api import mesh


def test_mesh_defaults():
    assert mesh.MESH_NETWORK == "10.10.0.0/24"
    assert mesh.MESH_PORT == 51822
    assert mesh.MESH_INTERFACE == "wg-mesh"


def test_subnet_overlap_detects_br_lxc():
    assert mesh.subnet_overlap("10.100.0.0/24") == "br-lxc"


def test_subnet_overlap_detects_partial_supernet():
    # a /16 that contains br-lxc must also be rejected
    assert mesh.subnet_overlap("10.100.0.0/16") == "br-lxc"


def test_subnet_overlap_clean_mesh_subnet():
    assert mesh.subnet_overlap("10.10.0.0/24") is None


def test_load_p2p_config_defaults_when_missing(tmp_path):
    cfg = mesh.load_p2p_config(tmp_path / "nope.toml")
    assert cfg["network"] == "10.10.0.0/24"
    assert cfg["listen_port"] == 51822
    assert cfg["interface"] == "wg-mesh"
    assert cfg["role"] == "satellite"
    assert cfg["master_endpoint"] is None


def test_load_p2p_config_reads_wireguard_section(tmp_path):
    p = tmp_path / "p2p.toml"
    p.write_text(
        "[wireguard]\n"
        'role = "master"\n'
        'listen_port = 51822\n'
        'network = "10.10.0.0/24"\n'
        'master_endpoint = "82.67.100.75:51822"\n'
    )
    cfg = mesh.load_p2p_config(p)
    assert cfg["role"] == "master"
    assert cfg["master_endpoint"] == "82.67.100.75:51822"


def test_allocate_mesh_ip_first_free_is_2():
    assert mesh.allocate_mesh_ip("10.10.0.0/24", []) == "10.10.0.2"


def test_allocate_mesh_ip_skips_taken_with_or_without_mask():
    got = mesh.allocate_mesh_ip("10.10.0.0/24", ["10.10.0.2/24", "10.10.0.3"])
    assert got == "10.10.0.4"


def test_allocate_mesh_ip_exhausted_raises():
    taken = [f"10.10.0.{n}" for n in range(2, 255)]
    import pytest
    with pytest.raises(RuntimeError):
        mesh.allocate_mesh_ip("10.10.0.0/24", taken)


def test_parse_wg_conf_extracts_interface_fields():
    text = (
        "[Interface]\n"
        "PrivateKey = ABC123=\n"
        "Address = 10.10.0.1/24\n"
        "ListenPort = 51822\n"
        "[Peer]\nPublicKey = X=\n"
    )
    got = mesh.parse_wg_conf(text)
    assert got == {"private_key": "ABC123=", "address": "10.10.0.1/24", "listen_port": 51822}


def test_render_wg_conf_master_with_roaming_peer():
    state = {
        "private_key": "PRIV=",
        "address": "10.10.0.1/24",
        "listen_port": 51822,
        "peers": [{"public_key": "PUB2=", "allowed_ips": "10.10.0.2/32"}],
    }
    out = mesh.render_wg_conf(state)
    assert "PrivateKey = PRIV=" in out
    assert "ListenPort = 51822" in out
    assert "AllowedIPs = 10.10.0.2/32" in out
    assert "Endpoint" not in out  # roaming peer => no Endpoint line


def test_render_wg_conf_satellite_with_endpoint_and_keepalive():
    state = {
        "private_key": "PRIV=", "address": "10.10.0.3/24", "listen_port": 51822,
        "peers": [{"public_key": "GK2=", "endpoint": "82.67.100.75:51822", "allowed_ips": "10.10.0.0/24"}],
    }
    out = mesh.render_wg_conf(state)
    assert "Endpoint = 82.67.100.75:51822" in out
    assert "PersistentKeepalive = 25" in out
