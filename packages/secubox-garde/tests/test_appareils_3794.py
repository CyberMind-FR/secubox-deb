# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3794 — registre d'appareils, déduction du nom, vue réseau et effecteurs de secubox-garde."""
import json
import sqlite3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from garde import appareils, base, effets, reseau  # noqa: E402

MAC = "aa:bb:cc:dd:ee:01"


def test_noms_adguard(tmp_path):
    f = tmp_path / "etat.json"
    f.write_text(json.dumps({"clients": [{"ip": "192.168.1.20", "mac": "AA:BB:CC:DD:EE:01", "nom": "TV salon"},
                                         {"ip": "192.168.1.21", "nom": ""}]}))
    assert appareils.noms_adguard(f) == {"192.168.1.20": "TV salon", MAC: "TV salon"}
    assert appareils.noms_adguard(tmp_path / "absent") == {}


def test_noms_nac(tmp_path):
    f = tmp_path / "devices.db"
    cx = sqlite3.connect(f)
    cx.execute("CREATE TABLE devices(mac TEXT PRIMARY KEY, ip TEXT, hostname TEXT)")
    cx.execute("INSERT INTO devices VALUES (?,?,?)", (MAC, "192.168.1.20", "box-tv"))
    cx.commit()
    cx.close()
    assert appareils.noms_nac(f) == {MAC: "box-tv", "192.168.1.20": "box-tv"}
    assert appareils.noms_nac(tmp_path / "absent.db") == {}


def test_noms_baux(tmp_path):
    d = tmp_path / "dnsmasq.leases"
    d.write_text(f"1800000000 {MAC} 192.168.1.20 portable 01:aa\n1800000000 aa:00:00:00:00:02 192.168.1.30 * *\n")
    k = tmp_path / "kea.csv"
    k.write_text("address,hwaddr,client_id,valid_lifetime,expire,subnet_id,fqdn_fwd,fqdn_rev,hostname,state\n"
                 "192.168.1.40,aa:00:00:00:00:03,,3600,1,1,0,0,imprimante.,0\n")
    assert appareils.noms_baux(d, k) == {MAC: "portable", "192.168.1.20": "portable",
                                         "aa:00:00:00:00:03": "imprimante", "192.168.1.40": "imprimante"}


def test_constructeur_et_ordre_des_sources(tmp_path):
    o = tmp_path / "oui.csv"
    o.write_text("Registry,Assignment,Organization Name,Organization Address\nMA-L,AABBCC,Fabricant SA,x\n")
    oui = appareils.constructeurs(o)
    n = appareils.Nommeur([{"192.168.1.20": "TV salon"}, {MAC: "box-tv"}], oui)
    assert n.nom("192.168.1.20", MAC) == "TV salon"
    assert n.nom("192.168.1.99", MAC) == "box-tv"
    assert appareils.Nommeur([], oui).nom("192.168.1.20", MAC) == f"Fabricant SA ({MAC})"
    assert appareils.Nommeur([], {}).nom("192.168.1.20", None) == "Appareil inconnu (192.168.1.20)"


def test_registre_un_appareil_toutes_adresses_et_fusion(tmp_path):
    db = base.ouvrir(tmp_path / "g.db")
    nom = appareils.Nommeur([{MAC: "TV salon"}]).nom
    appareils.mettre_a_jour(db, [("2a01:e0a::20", None)], nom, 100)       # IP seule : clé provisoire
    assert appareils.cle_de(db, "2a01:e0a::20", None) == "2a01:e0a::20"
    appareils.mettre_a_jour(db, [("192.168.1.20", MAC), ("2a01:e0a::20", MAC)], nom, 200)
    assert db.execute("SELECT cle, nom FROM appareils").fetchall() == [(MAC, "TV salon")]
    assert sorted(r[0] for r in db.execute("SELECT ip FROM appareil_ips WHERE cle=?", (MAC,))) == \
        ["192.168.1.20", "2a01:e0a::20"]
    # une IP reprise par un autre appareil quitte l'ancien
    appareils.mettre_a_jour(db, [("192.168.1.20", "aa:00:00:00:00:09")], nom, 300)
    assert [r[0] for r in db.execute("SELECT ip FROM appareil_ips WHERE cle=?", (MAC,))] == ["2a01:e0a::20"]
    assert appareils.adresses_actuelles(MAC, {"192.168.1.5": MAC, "192.168.1.6": "x"}) == ["192.168.1.5"]
    assert appareils.adresses_actuelles(MAC, {}, ["10.0.0.1"]) == ["10.0.0.1"]
    assert appareils.adresses_actuelles("2a01:db8::1:2:3:4", {}) == ["2a01:db8::1:2:3:4"]


def test_reseau_protegees_et_prefixes():
    sorties = {
        ("addr",): [{"ifname": "eth0", "addr_info": [
                        {"local": "192.168.1.128", "prefixlen": 24},
                        {"local": "2a01:e0a:1:2::128", "prefixlen": 64},
                        {"local": "2a01:e0a::1", "prefixlen": 32}]},
                    {"ifname": "wg-mesh", "addr_info": [{"local": "10.10.0.2", "prefixlen": 24}]}],
        ("route", "show", "default"): [{"gateway": "192.168.1.254"}],
        ("-6", "route", "show", "default"): [],
        ("neigh",): [{"dst": "10.0.3.50", "dev": "lxcbr0"}, {"dst": "192.168.1.20", "dev": "eth0"}],
    }
    protegees, prefixes = reseau.lire(lambda a: json.dumps(sorties[tuple(a)]))
    assert prefixes == ["2a01:e0a:1:2::/64"]
    for ip in ("192.168.1.128", "192.168.1.254", "10.0.3.50", "10.10.0.77"):
        assert protegees(ip)
    assert not protegees("192.168.1.20")


class _Ctl:
    def __init__(self, sortie):
        self.args, self.sortie = [], sortie

    def __call__(self, args):
        self.args.append(list(args))
        return self.sortie


def test_effets_ctl_et_audit(tmp_path):
    audit = tmp_path / "audit.log"
    audit.write_text("")            # posé par secubox-core ; garde n'y fait qu'ajouter (#3910)
    ctl = _Ctl('{"ok": true}')
    e = effets.Effets(audit=audit, ctl=ctl, horloge=lambda: 5)
    assert e.isoler("192.168.1.20", MAC, 99, "TV salon — infection")["ok"]
    assert e.fermer_evasion("192.168.1.20", None, ["b.example", "a.example"])["ok"]
    assert e.liberer("192.168.1.20")["ok"] and e.rouvrir("192.168.1.20")["ok"]
    assert ctl.args == [["quarantaine", "poser", "192.168.1.20", MAC, "99"],
                        ["evasion", "poser", "192.168.1.20", "-", "a.example,b.example"],
                        ["quarantaine", "lever", "192.168.1.20"], ["evasion", "lever", "192.168.1.20"]]
    lignes = [json.loads(x) for x in audit.read_text().splitlines()]
    assert lignes[0] == {"ts": 5, "module": "garde", "action": "isoler", "cible": "192.168.1.20",
                         "motif": "TV salon — infection", "resultat": "ok"}
    e2 = effets.Effets(audit=audit, ctl=_Ctl('{"ok": false, "erreur": "box inconnue"}'))
    assert e2.isoler("192.168.1.20", MAC, 99) == {"ok": False, "motif": "box inconnue"}


def test_effets_bannir(tmp_path):
    cle = tmp_path / "garde-ban.pem"
    cle.write_bytes(b"cle")
    vus = []

    def poster(sock, chemin, corps, entetes):
        vus.append((sock, chemin, json.loads(corps), entetes["Authorization"]))
        return reponses.pop(0)

    reponses = [(200, b'{"id": "x"}'), (409, b'{"detail": {"motif": "deja_actif"}}'),
                (409, b'{"detail": {"motif": "privee"}}')]
    e = effets.Effets(audit=tmp_path / "a.log", cle=cle, poster=poster,
                      frapper=lambda pem, corps, t: "JETON", horloge=lambda: 7)
    assert e.bannir("8.8.4.4", 14400, "intrusion : scan")["ok"]
    assert e.bannir("8.8.4.4", 14400, "m") == {"ok": True, "deja": True, "motif": "deja_actif"}
    assert e.bannir("8.8.4.4", 14400, "m")["ok"] is False
    assert vus[0] == ("/run/secubox/waf.sock", "/garde/ban",
                      {"geste": "ban", "cible": "8.8.4.4", "duree_s": 14400, "motif": "intrusion : scan"},
                      "Bearer JETON")
    e3 = effets.Effets(audit=tmp_path / "a.log", cle=tmp_path / "absente.pem", poster=poster)
    assert e3.bannir("8.8.4.4", 14400, "m")["ok"] is False


def test_effets_valident_avant_sudo(tmp_path):
    ctl = _Ctl('{"ok": true}')
    e = effets.Effets(audit=tmp_path / "a.log", ctl=ctl)
    assert not e.isoler("-1", MAC, 99)["ok"]
    assert not e.isoler("192.168.1.20", "--evil", 99)["ok"]
    assert not e.isoler("192.168.1.20", MAC, 0)["ok"]
    assert not e.fermer_evasion("192.168.1.20", None, ["-x.example"])["ok"]
    assert not e.fermer_evasion("192.168.1.20", None, ["a.example,b"])["ok"]
    assert not e.liberer("192.168.1.20; rm")["ok"]
    assert not e.bannir("--8.8.8.8", 14400, "m")["ok"]
    assert ctl.args == []
    assert e.isoler("2A01:E0A:0::20", MAC.upper(), 99)["ok"]
    assert ctl.args == [["quarantaine", "poser", "2a01:e0a::20", MAC, "99"]]


AIDE = Path(__file__).resolve().parent.parent / "lib" / "secubox-garde-acl-audit"


def _aide(tmp_path, cible):
    import subprocess
    bin_ = tmp_path / "bin"
    bin_.mkdir(exist_ok=True)
    trace = tmp_path / "trace"
    (bin_ / "setfacl").write_text(f'#!/bin/sh\necho "$@" >> {trace}\n')
    (bin_ / "setfacl").chmod(0o755)
    r = subprocess.run(["sh", str(AIDE), str(cible)], env={"PATH": f"{bin_}:/usr/bin:/bin"},
                       capture_output=True, text=True)
    return r.returncode, trace.read_text() if trace.exists() else ""


def test_aide_acl_fichier_ordinaire(tmp_path):
    f = tmp_path / "audit.log"
    f.write_text("")
    rc, trace = _aide(tmp_path, f)
    assert rc == 0 and trace.strip() == f"--physical -m u:secubox-garde:w -- {f}"


def test_aide_acl_refuse_un_lien(tmp_path):
    autre = tmp_path / "shadow"
    autre.write_text("")
    lien = tmp_path / "audit.log"
    lien.symlink_to(autre)
    rc, trace = _aide(tmp_path, lien)
    assert rc != 0 and trace == ""
    assert _aide(tmp_path, tmp_path / "absent")[0] != 0


def test_reseau_prefixe_plus_large_que_48_refuse():
    sorties = {
        ("addr",): [{"ifname": "eth0", "addr_info": [
                        {"local": "2a01:e0a:1::1", "prefixlen": 47},
                        {"local": "2a01:e0b:1::1", "prefixlen": 48}]}],
        ("route", "show", "default"): [], ("-6", "route", "show", "default"): [], ("neigh",): [],
    }
    _, prefixes = reseau.lire(lambda a: json.dumps(sorties[tuple(a)]))
    assert prefixes == ["2a01:e0b:1::/48"]
