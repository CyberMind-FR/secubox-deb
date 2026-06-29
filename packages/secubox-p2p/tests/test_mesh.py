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
