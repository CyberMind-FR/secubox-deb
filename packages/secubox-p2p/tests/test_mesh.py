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
