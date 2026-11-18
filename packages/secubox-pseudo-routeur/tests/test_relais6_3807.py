# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Relais IPv6 par next hop Freebox (#3807). Tous les binaires système sont des faux posés en
tête de PATH (jamais le vrai systemctl/nft/ip/networkctl/sudo du poste de dev)."""
import json
import subprocess
from pathlib import Path

import pytest

RACINE = Path(__file__).resolve().parents[1]
CTL = RACINE / "sbin" / "pseudo-routeurctl"
FAUX = ("nft", "sysctl", "systemctl", "networkctl", "ip", "dnsmasq", "ping", "sudo", "systemd-run", "freeboxctl")

ROUTEUR = """
[relais_ipv6]
role = "routeur"
lan_if = "eth2"
prefixe = "2a01:e0a:dec:c4e0::/64"
adresse_fixe = "2a01:e0a:dec:c4e0::94/64"
passerelle_ll = "fe80::3a07:16ff:fe77:17d3"
routeur_ll = "fe80::250:43ff:fe84:252f"
dns = "2a01:e0a:dec:c4e0::200"
"""
REPLI = ROUTEUR.replace('role = "routeur"', 'role = "repli"') + 'sonde_cible = "2001:4860:4860::8888"\n'


def _env(tmp_path, conf=None, ping_ok=True, nft_c_ok=True, dnsmasq_ok=True, freebox_ok=True):
    b = tmp_path / "bin"
    b.mkdir(exist_ok=True)
    j = tmp_path / "appels.log"
    corps = {
        "nft": f'echo "nft $*" >> {j}; [ "$1" = "-c" ] && exit {0 if nft_c_ok else 1}; '
               f'[ "$1" = "list" ] && [ -e {tmp_path}/table ] && exit 0; [ "$1" = "list" ] && exit 1; '
               f'[ "$1" = "-f" ] && touch {tmp_path}/table; [ "$1" = "delete" ] && rm -f {tmp_path}/table; exit 0',
        "sysctl": f'echo "sysctl $*" >> {j}; echo 1',
        "systemctl": f'echo "systemctl $*" >> {j}; exit 0',
        "networkctl": f'echo "networkctl $*" >> {j}; [ "$1" = "status" ] && echo "     Network File: /etc/systemd/network/10-eth2.network"; exit 0',
        "ip": f'echo "ip $*" >> {j}; exit 0',
        "dnsmasq": f'echo "dnsmasq $*" >> {j}; exit {0 if dnsmasq_ok else 1}',
        "ping": f'echo "ping $*" >> {j}; exit {0 if ping_ok else 1}',
        "sudo": 'while [ "$1" = "-u" ] || [ "$1" = "-n" ]; do [ "$1" = "-u" ] && shift; shift; done; exec "$@"',
        "systemd-run": f'echo "systemd-run $*" >> {j}; exit 99',
        "freeboxctl": f'echo "freeboxctl $*" >> {j}; [ "$1" = "nexthop-lire" ] && echo \'{{"prefix": "2a01:e0a:dec:c4e0::/64", "next_hop": ""}}\'; exit {0 if freebox_ok else 1}',
    }
    assert set(corps) == set(FAUX)
    for nom, c in corps.items():
        (b / nom).write_text("#!/bin/sh\n" + c + "\n")
        (b / nom).chmod(0o755)
    toml = tmp_path / "pseudo-routeur.toml"
    if conf is not None:
        toml.write_text(conf)
    env = {"PATH": f"{b}:/usr/bin:/bin", "SECUBOX_PR_NFT": str(b / "nft"), "SECUBOX_PR_FREEBOXCTL": str(b / "freeboxctl"),
           "SECUBOX_PR_CONF": str(toml), "SECUBOX_PR_AUDIT_LOG": str(tmp_path / "audit.log"),
           "SECUBOX_PR_NETWORKD_DIR": str(tmp_path / "network"), "SECUBOX_PR_R6_NFT": str(tmp_path / "nftables.d" / "zz-secubox-relais6.nft"),
           "SECUBOX_PR_NFT_PERSIST": str(tmp_path / "nftables.d" / "zz-secubox-pseudo-routeur.nft"),
           "SECUBOX_PR_R6_DNSMASQ_CONF": str(tmp_path / "etc" / "relais6-ra.conf"),
           "SECUBOX_PR_R6_ETAT": str(tmp_path / "relais6-sonde.json"), "SECUBOX_SONDE_ETAT": str(tmp_path / "sonde.json")}
    return env, j


def _run(env, *args):
    return subprocess.run(["bash", str(CTL), *args], env=env, capture_output=True, text=True, timeout=30)


def _appels(j):
    return j.read_text() if j.exists() else ""


@pytest.mark.parametrize("verbe", ["relais6-preparer", "relais6-basculer", "relais6-etat", "relais6-sonde"])
@pytest.mark.parametrize("conf", [None, "lan_if = \"eth2\"\n", "[relais_ipv6]\nrole = \"\"\n"])
def test_sans_configuration_rien_ne_se_passe(tmp_path, verbe, conf):
    env, j = _env(tmp_path, conf)
    r = _run(env, verbe)
    assert r.returncode == 0, r.stderr
    assert not any(x in _appels(j) for x in ("nft -f", "networkctl reload", "systemctl", "freeboxctl nexthop-regler"))
    assert not (tmp_path / "network").exists() and not (tmp_path / "audit.log").exists()


def test_preparer_pose_les_trois_pieces(tmp_path):
    env, j = _env(tmp_path, ROUTEUR)
    r = _run(env, "relais6-preparer")
    assert r.returncode == 0, r.stderr
    dropin = (tmp_path / "network" / "10-eth2.network.d" / "zz-secubox-relais6.conf").read_text()
    assert "Address=2a01:e0a:dec:c4e0::94/64" in dropin and "Gateway=fe80::3a07:16ff:fe77:17d3" in dropin
    conf = (tmp_path / "etc" / "relais6-ra.conf").read_text()
    for ligne in ("port=0", "interface=eth2", "enable-ra", "no-dhcpv4-interface=eth2",
              "dhcp-range=::,constructor:eth2,ra-stateless,64", "ra-param=eth2,high,0",
              "dhcp-option=option6:dns-server,[2a01:e0a:dec:c4e0::200]"):
        assert ligne + "\n" in conf, ligne
    nft = (tmp_path / "nftables.d" / "zz-secubox-relais6.nft").read_text()
    assert 'oifname "eth2" icmpv6 type nd-redirect counter drop' in nft and "ip6 saddr 2a01:e0a:dec:c4e0::/64" in nft
    a = _appels(j)
    assert "networkctl reload" in a and "systemctl restart secubox-relais6-ra.service" in a and "nft -c -f" in a
    # jamais de lien coupe ni de MTU change
    assert " down" not in a and "mtu" not in a.lower() and "ip link" not in a
    assert "relais6_preparer" in (tmp_path / "audit.log").read_text()
    assert not list((tmp_path / "nftables.d").glob(".*tmp")) and not list((tmp_path / "etc").glob(".*tmp"))


@pytest.mark.parametrize("casse", ["nft_c_ok", "dnsmasq_ok"])
def test_preparer_n_ecrit_rien_si_la_validation_echoue(tmp_path, casse):
    env, j = _env(tmp_path, ROUTEUR, **{casse: False})
    r = _run(env, "relais6-preparer")
    assert r.returncode == 1
    assert not (tmp_path / "network").exists() and not (tmp_path / "etc" / "relais6-ra.conf").exists()
    assert not (tmp_path / "nftables.d" / "zz-secubox-relais6.nft").exists()
    assert not list((tmp_path / "nftables.d").glob(".*")) and not list((tmp_path / "etc").glob(".*"))


def test_preparer_refuse_sur_la_box_de_repli(tmp_path):
    env, j = _env(tmp_path, REPLI)
    assert _run(env, "relais6-preparer").returncode == 2
    assert not (tmp_path / "network").exists()


def test_retirer_retire_tout_et_est_idempotent(tmp_path):
    env, j = _env(tmp_path, ROUTEUR)
    assert _run(env, "relais6-preparer").returncode == 0
    r = _run(env, "relais6-retirer")
    assert r.returncode == 0, r.stderr
    assert json.loads(r.stdout)["modifie"] is True
    assert not (tmp_path / "network" / "10-eth2.network.d").exists()
    assert not (tmp_path / "etc" / "relais6-ra.conf").exists()
    assert not (tmp_path / "nftables.d" / "zz-secubox-relais6.nft").exists() and not (tmp_path / "table").exists()
    assert "systemctl disable --now secubox-relais6-ra.service" in _appels(j)
    r2 = _run(env, "relais6-retirer")
    assert r2.returncode == 0 and json.loads(r2.stdout)["modifie"] is False


def test_retirer_marche_meme_avec_un_toml_casse(tmp_path):
    env, j = _env(tmp_path, ROUTEUR)
    assert _run(env, "relais6-preparer").returncode == 0
    Path(env["SECUBOX_PR_CONF"]).write_text("[relais_ipv6\nrole=")
    assert _run(env, "relais6-retirer").returncode == 0
    assert not (tmp_path / "etc" / "relais6-ra.conf").exists()


@pytest.mark.parametrize("cle,valeur", [
    ("passerelle_ll", "fe80::1; reboot"), ("passerelle_ll", "2a01::1"), ("passerelle_ll", "fe80::1%eth0"),
    ("routeur_ll", "$(id)"), ("dns", "fe80::1"), ("dns", "ff02::1"), ("prefixe", "2a01:e0a:dec:c4e0::/56"),
    ("prefixe", "fd00::/64"), ("adresse_fixe", "2a01:e0a:dec:c4e1::94/64"), ("adresse_fixe", "2a01:e0a:dec:c4e0::94/64\nDNS=1.1.1.1"),
    ("lan_if", "eth2\"; drop"), ("role", "routeur2"),
])
def test_valeurs_invalides_refusees_avant_toute_ecriture(tmp_path, cle, valeur):
    lignes = [x for x in ROUTEUR.splitlines() if not x.startswith(cle + " =")]
    lignes.append(f"{cle} = {json.dumps(valeur)}")
    env, j = _env(tmp_path, "\n".join(lignes) + "\n")
    r = _run(env, "relais6-preparer")
    assert r.returncode == 2 and "refuse" in r.stderr
    assert not (tmp_path / "network").exists() and "nft" not in _appels(j)


def test_basculer_sonde_puis_regle_le_next_hop_et_arme(tmp_path):
    env, j = _env(tmp_path, REPLI)
    r = _run(env, "relais6-basculer")
    assert r.returncode == 0, r.stderr
    a = _appels(j)
    assert "ping -6 -c1 -W2 fe80::250:43ff:fe84:252f%eth2" in a and "ping -6 -c1 -W2 2001:4860:4860::8888" in a
    assert "freeboxctl nexthop-regler fe80::250:43ff:fe84:252f" in a
    assert "systemctl enable --now pseudo-routeur-relais6-sonde.timer" in a
    assert a.index("ping") < a.index("nexthop-regler")
    assert "relais6_basculer" in (tmp_path / "audit.log").read_text()


def test_basculer_refuse_si_le_routeur_ne_repond_pas(tmp_path):
    env, j = _env(tmp_path, REPLI, ping_ok=False)
    r = _run(env, "relais6-basculer")
    assert r.returncode == 2
    assert "nexthop-regler" not in _appels(j) and "systemctl" not in _appels(j)


def test_basculer_refuse_sur_le_routeur(tmp_path):
    env, j = _env(tmp_path, ROUTEUR)
    assert _run(env, "relais6-basculer").returncode == 2 and "freeboxctl" not in _appels(j)


@pytest.mark.parametrize("conf", [REPLI, None, "[relais_ipv6\ncasse"])
def test_revenir_part_toujours(tmp_path, conf):
    env, j = _env(tmp_path, conf, ping_ok=False)
    r = _run(env, "relais6-revenir")
    assert r.returncode == 0, r.stderr
    a = _appels(j)
    assert "freeboxctl nexthop-regler vide" in a and "systemctl disable --now pseudo-routeur-relais6-sonde.timer" in a


def test_revenir_echec_du_connecteur_sort_en_1(tmp_path):
    env, j = _env(tmp_path, REPLI, freebox_ok=False)
    assert _run(env, "relais6-revenir").returncode == 1


def test_sonde_sort_en_erreur_au_troisieme_echec(tmp_path):
    env, j = _env(tmp_path, REPLI, ping_ok=False)
    codes = [_run(env, "relais6-sonde").returncode for _ in range(3)]
    assert codes == [0, 0, 1]
    etat = json.loads((tmp_path / "relais6-sonde.json").read_text())
    assert etat["echecs_consecutifs"] == 3 and len(etat["historique"]) == 3
    assert "nexthop-regler" not in _appels(j)      # le retour vit dans son unite (OnFailure=)


def test_sonde_remet_a_zero_apres_un_succes(tmp_path):
    env, j = _env(tmp_path, REPLI, ping_ok=False)
    _run(env, "relais6-sonde")
    env2, _ = _env(tmp_path, REPLI, ping_ok=True)
    assert _run(env2, "relais6-sonde").returncode == 0
    assert json.loads((tmp_path / "relais6-sonde.json").read_text())["echecs_consecutifs"] == 0


def test_etat_repli_lit_le_next_hop(tmp_path):
    env, j = _env(tmp_path, REPLI)
    d = json.loads(_run(env, "relais6-etat").stdout)
    assert d["role"] == "repli" and d["next_hop_lu"] == {"prefix": "2a01:e0a:dec:c4e0::/64", "next_hop": ""}
    assert d["actif"] is False and d["sonde"]["armee"] is True


def test_etat_routeur(tmp_path):
    env, j = _env(tmp_path, ROUTEUR)
    _run(env, "relais6-preparer")
    d = json.loads(_run(env, "relais6-etat").stdout)
    assert d["role"] == "routeur" and d["table_nft"] and d["dropin_networkd"] and d["annonces_ra"]


def test_verbes_ecrivants_sortent_du_bac_a_sable():
    src = CTL.read_text()
    assert "retour-freebox|relais6-preparer|relais6-retirer|relais6-basculer|relais6-revenir)" in src


def test_unites_et_sudoers():
    sonde = (RACINE / "systemd" / "pseudo-routeur-relais6-sonde.service").read_text()
    assert "OnFailure=pseudo-routeur-relais6-retour.service" in sonde and "relais6-sonde" in sonde
    assert "relais6-revenir" in (RACINE / "systemd" / "pseudo-routeur-relais6-retour.service").read_text()
    assert "OnUnitActiveSec=60s" in (RACINE / "systemd" / "pseudo-routeur-relais6-sonde.timer").read_text()
    ra = (RACINE / "systemd" / "secubox-relais6-ra.service").read_text()
    assert "ConditionPathExists=/etc/secubox/relais6-ra.conf" in ra and "--conf-file=/etc/secubox/relais6-ra.conf" in ra
    sud = (RACINE / "sudoers" / "secubox-pseudo-routeur").read_text()
    assert "root ALL=(secubox-freebox) NOPASSWD: /usr/sbin/freeboxctl nexthop-lire, /usr/sbin/freeboxctl nexthop-regler *" in sud
    rules = (RACINE / "debian" / "rules").read_text()
    for u in ("secubox-relais6-ra.service", "pseudo-routeur-relais6-sonde.service", "pseudo-routeur-relais6-sonde.timer",
              "pseudo-routeur-relais6-retour.service"):
        assert u in rules
    assert "secubox-freebox (>= 0.8.4)" in (RACINE / "debian" / "control").read_text()


def test_sudoers_valide():
    import shutil
    if not shutil.which("visudo"):
        pytest.skip("visudo absent")
    r = subprocess.run(["visudo", "-cf", str(RACINE / "sudoers" / "secubox-pseudo-routeur")], capture_output=True, text=True, timeout=10)
    assert r.returncode == 0, r.stdout + r.stderr


def test_routes_api_gardees():
    from fastapi.testclient import TestClient
    from api import main
    c = TestClient(main.app)
    assert c.get("/relais6").status_code in (401, 403)
    for chemin in ("/relais6/basculer", "/relais6/revenir"):
        assert c.post(chemin).status_code in (401, 403)


def test_routes_api_relaient_le_ctl(monkeypatch):
    from fastapi.testclient import TestClient
    from secubox_core import auth
    from api import main
    vus = []

    def faux(*args, timeout=30):
        vus.append(args)
        if args[0] == "relais6-basculer":
            return 2, "", "refuse : le routeur ne repond pas"
        return 0, '{"role": "repli"}', ""
    monkeypatch.setattr(main, "_run_ctl", faux)
    main.app.dependency_overrides[auth.require_jwt] = lambda: {"sub": "admin"}
    try:
        c = TestClient(main.app)
        assert c.get("/relais6").json() == {"role": "repli"}
        r = c.post("/relais6/basculer")
        assert r.status_code == 409 and "routeur" in r.json()["erreur"]
        assert c.post("/relais6/revenir").json() == {"ok": True}
    finally:
        main.app.dependency_overrides.clear()
    assert [a[0] for a in vus] == ["relais6-etat", "relais6-basculer", "relais6-revenir"]
