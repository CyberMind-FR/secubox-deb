# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3419 — jamais de DHCP s'il existe déjà un serveur sur le segment ; une seule interface ne mène jamais au routeur."""
import importlib.machinery
import importlib.util
import re
import socket
import struct
import subprocess
import threading
from pathlib import Path

import pytest

PKG = Path(__file__).resolve().parents[1]
DEPOT = PKG.parents[1]
SONDE = PKG / "sbin" / "secubox-dhcp-sonde"
DETECT = PKG / "sbin" / "secubox-net-detect"
TEST_EXCEPTION = "packages/secubox-netmodes/tests/test_dhcp_sonde_3419.py::test_unites_garde_et_surveillance_durcies"


def _charger():
    chargeur = importlib.machinery.SourceFileLoader("dhcp_sonde", str(SONDE))
    spec = importlib.util.spec_from_loader("dhcp_sonde", chargeur)
    mod = importlib.util.module_from_spec(spec)
    chargeur.exec_module(mod)
    return mod


S = _charger()
MAC = bytes.fromhex("080027aabbcc")


def _offre(xid, serveur="192.168.1.254", offerte="192.168.1.50", type_msg=2):
    entete = struct.pack("!BBBBIHH4s4s4s4s16s64s128s", 2, 1, 6, 0, xid, 0, 0x8000, bytes(4),
                         socket.inet_aton(offerte), bytes(4), bytes(4), MAC + bytes(10), bytes(64), bytes(128))
    return entete + S.COOKIE + bytes([53, 1, type_msg, 54, 4]) + socket.inet_aton(serveur) + bytes([255])


# --- paquets -----------------------------------------------------------------------------------------------------------

def test_discover_sans_request_et_drapeau_broadcast():
    p = S.discover(MAC, 0x12345678)
    assert p[0] == 1 and struct.unpack("!I", p[4:8])[0] == 0x12345678
    assert struct.unpack("!H", p[10:12])[0] == 0x8000
    assert p[28:34] == MAC and p[236:240] == S.COOKIE
    assert bytes([53, 1, 1]) in p[240:]                        # DHCPDISCOVER
    assert bytes([53, 1, 3]) not in p[240:]                    # jamais de REQUEST : aucun bail pris
    assert b"\x32\x04" not in p[240:]                          # ni adresse demandée (option 50)


def test_lecture_d_offre():
    assert S.lire_offre(_offre(7), 7) == {"serveur": "192.168.1.254", "offerte": "192.168.1.50"}
    assert S.lire_offre(_offre(7), 8) is None                  # autre transaction
    assert S.lire_offre(_offre(7, type_msg=5), 7) is None      # un ACK n'est pas une offre
    assert S.lire_offre(b"\x02" * 100, 7) is None              # tronqué
    S.lire_offre(_offre(7)[:-3], 7)                            # option coupée : jamais d exception


def test_nos_propres_offres_ne_comptent_pas():
    offres = [{"serveur": "192.168.10.1", "offerte": "x"}, {"serveur": "192.168.1.254", "offerte": "y"}]
    assert S.tiers(offres, {"192.168.10.1"}) == [offres[1]]


def test_interfaces_de_la_configuration():
    textes = ["port=0\ninterface=br-lan\nbind-dynamic\n", "interface=lan2\n", "interface=br-lan\ninterface=$(x)\n"]
    assert S.interfaces_conf(textes) == ["br-lan", "lan2"]


# --- sonde réelle contre un faux serveur (boucle locale, ports non privilégiés) ---------------------------------------

def _faux_serveur(repondre=True):
    srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    srv.bind(("127.0.0.1", 0))
    srv.settimeout(5)
    recus = []

    def boucle():
        try:
            while True:
                paquet, src = srv.recvfrom(4096)
                recus.append(paquet)
                if repondre:
                    srv.sendto(_offre(struct.unpack("!I", paquet[4:8])[0]), src)
        except OSError:
            return

    threading.Thread(target=boucle, daemon=True).start()
    return srv, recus


@pytest.mark.parametrize("repond", [True, False])
def test_sonde_contre_un_faux_serveur(repond):
    srv, recus = _faux_serveur(repond)
    try:
        offres = S.sonder("lo", MAC, delai=1.0, cible=srv.getsockname(), ecoute=("127.0.0.1", 0), lier=False)
    finally:
        srv.close()
    assert recus and all(p[0] == 1 for p in recus)            # que des DISCOVER
    assert all(bytes([53, 1, 1]) in p[240:] for p in recus)
    assert offres == ([{"serveur": "192.168.1.254", "offerte": "192.168.1.50"}] if repond else [])


# --- décisions de garde et de surveillance -----------------------------------------------------------------------------

class Faux:
    def __init__(self, offres=None, erreur=None, forcer=False, actif=True, porteuse=True):
        self.offres, self.erreur, self.f, self.a, self.p = offres or [], erreur, forcer, actif, porteuse
        self.audits, self.arrets = [], 0

    ifaces = ["br-lan"]
    echec_arret = False

    def interfaces(self):
        return self.ifaces

    def locales(self):
        return {"192.168.10.1"}

    def porteuse(self, iface):
        return self.p

    def forcer(self):
        return self.f

    def auditer(self, action, detail):
        self.audits.append((action, detail))

    def sonder(self, iface):
        if self.erreur:
            raise S.SondeImpossible(self.erreur)
        return self.offres

    def actif(self):
        return self.a

    def arreter(self):
        self.audits.append(("<arret>", ""))
        self.arrets += 1
        if self.echec_arret:
            raise subprocess.CalledProcessError(1, ["systemctl", "stop"])


TIERS = [{"serveur": "192.168.1.254", "offerte": "192.168.1.50"}]


def test_garde_refuse_si_un_serveur_existe_et_audite():
    f = Faux(TIERS)
    assert S.garde(f) == 1
    assert f.audits[0][0] == "dhcp-tiers-refus" and "192.168.1.254" in f.audits[0][1]


def test_garde_laisse_passer_sans_serveur_tiers():
    f = Faux([{"serveur": "192.168.10.1", "offerte": "z"}])     # notre propre dnsmasq
    assert S.garde(f) == 0 and f.audits == []


def test_garde_sonde_impossible_refuse_par_prudence():
    f = Faux(erreur="port 68 pris")
    assert S.garde(f) == 1 and f.audits[0][0] == "dhcp-tiers-refus"


def test_garde_sans_porteuse_rien_a_sonder():
    assert S.garde(Faux(TIERS, porteuse=False)) == 0


def test_choix_force_de_l_administrateur_audite():
    f = Faux(TIERS, forcer=True)
    assert S.garde(f) == 0 and f.audits[0][0] == "dhcp-tiers-force"


def test_surveillance_arrete_le_dhcp_si_un_serveur_apparait():
    f = Faux(TIERS)
    assert S.surveiller(f) == 0
    assert f.arrets == 1 and [a for a, _ in f.audits] == ["dhcp-tiers-arret", "<arret>"]    # audité AVANT l'arrêt
    f = Faux(TIERS, actif=False)
    S.surveiller(f)
    assert f.arrets == 0 and f.audits == []
    f = Faux(TIERS, forcer=True)
    S.surveiller(f)
    assert f.arrets == 0 and f.audits[0][0] == "dhcp-tiers-force"


def test_fichier_de_forcage_refuse_s_il_n_est_pas_root(tmp_path, monkeypatch):
    f = tmp_path / "dhcp.toml"
    f.write_text("[sonde]\nforcer = true\n")
    monkeypatch.setattr(S, "FORCER", f)
    with pytest.raises(PermissionError):                       # fichier du testeur, pas de root
        S.force_par_admin()


def test_audit_ecrit_une_ligne_json(tmp_path):
    a = tmp_path / "audit.log"
    a.touch()
    S.auditer("dhcp-tiers-refus", "br-lan : 192.168.1.254", a)
    assert '"action": "dhcp-tiers-refus"' in a.read_text() and '"module": "netmodes"' in a.read_text()


# --- unités : jamais de boucle, garde avant le DHCP --------------------------------------------------------------------

def unite(nom):
    d = {}
    for ligne in (PKG / "debian" / nom).read_text().splitlines():
        ligne = ligne.strip()
        if ligne and ligne[0] not in "#;[" and "=" in ligne:
            k, v = ligne.split("=", 1)
            d.setdefault(k, []).append(v)
    return d


def test_lan_dhcp_garde_condition_et_relances_bornees():
    u = unite("secubox-lan-dhcp.service")
    assert u["ConditionPathExists"] == ["/var/lib/secubox-netmodes/lan-dhcp.conf"]
    assert u["Wants"] == ["secubox-lan-dhcp-surveille.timer"]
    burst, intervalle, pause = int(u["StartLimitBurst"][0]), int(u["StartLimitIntervalSec"][0]), int(u["RestartSec"][0])
    assert burst * pause < intervalle                          # la limite est atteinte : pas de boucle sans fin
    t = unite("secubox-lan-dhcp-surveille.timer")
    assert t["PartOf"] == ["secubox-lan-dhcp.service"]


def test_unites_garde_et_surveillance_durcies():
    for nom, verbe in (("secubox-lan-dhcp-garde.service", "garde"), ("secubox-lan-dhcp-surveille.service", "surveiller")):
        u = unite(nom)
        assert u["ExecStart"] == [f"/usr/sbin/secubox-dhcp-sonde {verbe}"]
        assert u["Type"] == ["oneshot"] and "Restart" not in u and "User" not in u
        for cle in ("NoNewPrivileges", "ProtectHome", "PrivateTmp", "ProtectKernelTunables", "ProtectControlGroups",
                    "RestrictSUIDSGID", "LockPersonality"):
            assert u[cle] == ["yes"], (nom, cle)
        assert u["ProtectSystem"] == ["strict"] and u["ReadWritePaths"] == ["/var/log/secubox"]
        assert u["UMask"] == ["0027"]
        assert set(u["CapabilityBoundingSet"][0].split()) == {"CAP_NET_RAW", "CAP_NET_BIND_SERVICE", "CAP_DAC_OVERRIDE"}
    regles = (DEPOT / ".claude" / "RULES-CODE.md").read_text()
    ligne = next(x for x in regles.splitlines() if "secubox-lan-dhcp-garde.service" in x)
    assert TEST_EXCEPTION in ligne
    rules = (PKG / "debian" / "rules").read_text()
    assert "install -m 0755 sbin/secubox-dhcp-sonde" in rules
    for n in ("secubox-lan-dhcp-garde", "secubox-lan-dhcp-surveille"):
        assert f"dh_installsystemd --name={n} --no-enable --no-start" in rules


def test_sonde_python_isole_stdlib():
    texte = SONDE.read_text()
    assert texte.startswith("#!/usr/bin/python3 -I\n")
    assert "shell=True" not in texte and "REQUEST" in texte
    assert subprocess.run(["python3", "-m", "py_compile", str(SONDE)], check=False, timeout=30).returncode == 0


# --- une seule interface : jamais le routeur ---------------------------------------------------------------------------

def _choisir(*args):
    code = DETECT.read_text().rsplit('main "$@"', 1)[0]
    r = subprocess.run(["bash", "-c", code + '\nchoisir_mode "$@"', "x", *args], capture_output=True, text=True,
                       check=True, timeout=30)
    return r.stdout.strip()


@pytest.mark.parametrize("args, attendu", [
    (("router", "full", "enp0s3", ""), "single"),             # VM ou PC à une seule carte
    (("router", "lite", "eth0", "eth0"), "single"),           # « LAN » = le WAN : pas distinct
    (("bridge", "full", "eth0", ""), "single"),
    (("router", "vm", "enp0s3", "enp0s8"), "single"),
    (("router", "full", "eth2", "lan0 lan1"), "router"),
    (("bridge", "full", "eth0", "eth1"), "bridge"),
    (("n-importe", "full", "eth0", "eth1"), "single"),
])
def test_mode_effectif(args, attendu):
    assert _choisir(*args) == attendu


def test_demarrage_sans_netplan_apply():
    texte = DETECT.read_text()
    bloc = texte.split("        generate)", 1)[1].split(";;", 1)[0]
    bloc = "\n".join(x for x in bloc.splitlines() if not x.lstrip().startswith("#"))
    assert "netplan generate" in bloc and "netplan apply" not in bloc
    assert re.search(r'mode=\$\(choisir_mode "\$demande"', texte)
    assert 'OUTPUT_JSON="/run/secubox/net-detect.json"' in texte


def test_arret_en_echec_audite():
    f = Faux(TIERS)
    f.echec_arret = True
    assert S.surveiller(f) == 1
    assert [a for a, _ in f.audits] == ["dhcp-tiers-arret", "<arret>", "dhcp-tiers-arret-echec"]


def test_garde_sans_interface_retenue_refuse():
    f = Faux()
    f.ifaces = []
    assert S.garde(f) == 1 and "aucune interface" in f.audits[0][1]
    f = Faux(forcer=True)
    f.ifaces = []
    assert S.garde(f) == 0 and f.audits[0][0] == "dhcp-tiers-force"


def test_audit_jamais_cree_par_la_sonde(tmp_path, capsys):
    a = tmp_path / "audit.log"
    S.auditer("dhcp-tiers-refus", "x", a)
    assert not a.exists() and "audit non écrit" in capsys.readouterr().err


def test_mac_de_sonde_aleatoire_localement_administree():
    macs = {S.mac_aleatoire() for _ in range(20)}
    assert len(macs) > 1
    assert all(len(m) == 6 and m[0] & 0x02 and not m[0] & 0x01 for m in macs)


def test_garde_rejouee_a_chaque_demarrage_y_compris_relance():
    u = unite("secubox-lan-dhcp.service")
    assert u["ExecStartPre"] == ["+/bin/systemctl start secubox-lan-dhcp-garde.service"]
    assert "Requires" not in u
    g = unite("secubox-lan-dhcp-garde.service")
    assert "RemainAfterExit" not in g and "Before" not in g    # retombe inactive : rejouée à chaque appel
