# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Contrôleur netmodesctl du mode routeur (#3189) : racine tmp_path, faux système qui journalise chaque commande."""
import fcntl
import importlib.machinery
import importlib.util
import io
import json
import os
import re
import signal
import subprocess
import sys
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from api import routeur_ctl as rc
from api import routeur_fichiers as rf
from api.routeur_config import ErreurConfig
from api.routeur_rendu import CHEMINS, TABLE_NFT

SCRIPT = Path(__file__).resolve().parents[1] / "sbin" / "netmodesctl"
CFG42 = {"adresse": "192.168.42.1/24", "dhcp_debut": "192.168.42.100",
         "dhcp_fin": "192.168.42.199", "bail": "12h",
         "ports": ["lan0", "lan1", "lan2", "lan3"], "wan": "eth2"}
CFG50 = dict(CFG42, adresse="192.168.50.1/24", dhcp_debut="192.168.50.100", dhcp_fin="192.168.50.199")
# nginx -t hors du bac à sable de l'API (R4) : il ouvre /run/nginx.pid et ses journaux en écriture
NGINX_T = ["systemd-run", "--wait", "--pipe", "--collect", "--quiet", "/usr/sbin/nginx", "-t"]


def touche_nginx(a: list[str]) -> bool:
    return a[0] == "nginx" or "/usr/sbin/nginx" in a or a[-1] == "nginx.service"
TOML = "etc/secubox/netmodes/routeur.toml"
ARBRE = "var/lib/secubox-netmodes"
ETAT = ARBRE + "/routeur-etat.json"
SAUVEGARDES = ARBRE + "/sauvegardes"
AUDIT = "var/log/secubox/audit.log"
LISTE_INPUT = ["nft", "-j", "-a", "list", "chain", "inet", "filter", "input"]
NETPLAN_GK2 = """network:
  version: 2
  renderer: networkd
  ethernets:
    eth2:
      addresses: [192.168.1.200/24]
  bridges:
    br-lxc:
      addresses: [10.100.0.1/24]
"""
ANCIEN_PONT = "[Match]\nName=br-lan\n\n[Network]\nAddress=192.168.255.1/24\n"
# base de secubox-hardening : nftables.service recharge les fragments de /etc/nftables.d au démarrage
NFTABLES_CONF = '#!/usr/sbin/nft -f\nflush ruleset\ntable inet filter {\n}\n\ninclude "/etc/nftables.d/*.nft"\n'
BAUX_TEMPORAIRES = "1761530000 aa:bb:cc:dd:ee:01 192.168.42.150 pc-bureau *\n1761530100 aa:bb:cc:dd:ee:02 192.168.42.151 gk4 *\n"


def cp(argv, code=0, sortie="", erreur=""):
    return subprocess.CompletedProcess(argv, code, sortie, erreur)


class Faux:
    """Système simulé : journalise chaque commande et en tient l'effet (adresses, règles d'entrée, table, unités).
    Une commande inconnue fait échouer le test : le contrôleur ne lance rien d'imprévu."""

    def __init__(self, racine: Path, pont_existant: bool = True):
        self.racine = racine
        self.journal: list[list[str]] = []
        self.actifs = {"sbx-lan-dhcp.service", "unbound.service", "nginx.service"}
        self.adresses = {"lo": ["127.0.0.1/8", "192.168.255.1/32"], "eth2": ["192.168.1.200/24"],
                         "br-lxc": ["10.100.0.1/24"]}
        if pont_existant:
            self.adresses["br-lan"] = ["192.168.255.1/24", "192.168.42.1/24"]
        self.regles = [{"handle": 4, "comment": "secubox-hardening established"}, {"handle": 9},
                       {"handle": 12, "comment": "sbx-lan-temporaire-dhcp"},
                       {"handle": 13, "comment": "sbx-lan-temporaire-ping"}]
        self.prochain = 40
        self.table_lan = False
        self.echecs: dict[tuple, list] = {}
        self.crochets: dict[tuple, object] = {}
        self.etats: list = []                           # état du fichier d'état au moment de chaque commande
        self.pauses: list[float] = []                   # ctx.attendre : rien n'attend vraiment

    def attendre(self, secondes: float) -> None:
        self.pauses.append(secondes)

    def echouer(self, *prefixe, code=1, fois=None, erreur="échec simulé"):
        self.echecs[prefixe] = [code, fois, erreur]

    def sur(self, *prefixe, fonction):
        """Appelée avec argv avant l'effet de la commande : peut modifier l'état simulé ou lever."""
        self.crochets[prefixe] = fonction

    def __call__(self, argv):
        assert isinstance(argv, list) and all(isinstance(a, str) for a in argv), argv
        self.journal.append(list(argv))
        self.etats.append(self._etat())
        for prefixe, fonction in self.crochets.items():
            if tuple(argv[:len(prefixe)]) == prefixe:
                fonction(argv)
        for prefixe, regle in self.echecs.items():
            if tuple(argv[:len(prefixe)]) == prefixe and regle[1] != 0:
                if regle[1] is not None:
                    regle[1] -= 1
                return cp(argv, regle[0], "", regle[2])
        return self._effet(argv)

    def _etat(self):
        f = self.racine / ETAT
        try:
            return json.loads(f.read_text())["etat"] if f.exists() else None
        except (ValueError, KeyError, TypeError):
            return "illisible"

    def _entree(self, nom):
        return {"ifindex": 1, "ifname": nom, "addr_info": [
            {"family": "inet", "local": a.split("/")[0], "prefixlen": int(a.split("/")[1]), "scope": "global"}
            for a in self.adresses[nom]]}

    def _networks_br_lan(self):
        dossier = self.racine / "etc/systemd/network"
        for f in sorted(dossier.glob("*.network")) if dossier.is_dir() else []:
            texte = f.read_text()
            if "Name=br-lan" in texte:
                yield texte

    def _effet(self, a):
        if a == ["ip", "-j", "-4", "addr"]:
            return cp(a, 0, json.dumps([self._entree(n) for n in self.adresses] + [{}]))
        if a[:6] == ["ip", "-j", "-4", "addr", "show", "dev"]:
            if a[6] not in self.adresses:
                return cp(a, 1, "", f'Device "{a[6]}" does not exist.\n')
            return cp(a, 0, json.dumps([self._entree(a[6])]))
        if a[:3] == ["ip", "addr", "del"] and a[4] == "dev":
            if a[3] not in self.adresses.get(a[5], []):
                return cp(a, 2, "", "RTNETLINK answers: Cannot assign requested address\n")
            self.adresses[a[5]].remove(a[3])
            return cp(a)
        if a == ["ip", "link", "show", "dev", "br-lan"]:
            return cp(a, 0 if "br-lan" in self.adresses else 1)
        if a == ["ip", "link", "delete", "br-lan"]:
            return cp(a, 0) if self.adresses.pop("br-lan", None) is not None else cp(a, 1, "", "Cannot find device")
        if a[:3] == ["systemctl", "is-active", "--quiet"]:
            return cp(a, 0 if a[3] in self.actifs else 3)
        if a[:2] == ["systemctl", "stop"]:
            if a[2].endswith(".timer") and a[2] not in self.actifs:
                return cp(a, 5, "", f"Failed to stop {a[2]}: Unit {a[2]} not loaded.\n")
            self.actifs.discard(a[2])
            return cp(a)
        if a[:2] in (["systemctl", "restart"], ["systemctl", "enable"], ["systemctl", "reload"]):
            unite = a[3] if a[2:3] == ["--no-block"] and a[1] != "enable" else a[2]
            assert len(a) == (4 if a[2:3] == ["--no-block"] else 3), a
            if a[1] == "restart":
                self.actifs.add(unite)
            return cp(a)
        if a[:3] == ["systemctl", "disable", "--now"]:
            self.actifs.discard(a[3])
            return cp(a)
        if a == NGINX_T:
            return cp(a)
        if a[0] == "systemd-run":
            unite = next(x.split("=", 1)[1] for x in a if x.startswith("--unit="))
            self.actifs.add(unite + ".timer")
            return cp(a)
        if a == ["networkctl", "reload"]:
            if (self.racine / CHEMINS["netdev"].lstrip("/")).is_file():
                self.adresses.setdefault("br-lan", [])
            return cp(a)
        if a[:3] == ["networkctl", "reconfigure", "br-lan"]:
            for texte in self._networks_br_lan():
                for ligne in texte.splitlines():
                    if ligne.startswith("Address=") and "br-lan" in self.adresses:
                        if ligne[8:] not in self.adresses["br-lan"]:
                            self.adresses["br-lan"].append(ligne[8:])
            return cp(a)
        if a == LISTE_INPUT:
            regles = [{"rule": {"family": "inet", "table": "filter", "chain": "input", "handle": r["handle"],
                                **({"comment": r["comment"]} if "comment" in r else {}), "expr": []}}
                      for r in self.regles]
            return cp(a, 0, json.dumps({"nftables": [
                {"metainfo": {"version": "1.1.3", "json_schema_version": 1}},
                {"chain": {"family": "inet", "table": "filter", "name": "input", "handle": 1,
                           "type": "filter", "hook": "input", "prio": 0, "policy": "drop"}}] + regles}))
        if a[:7] == ["nft", "delete", "rule", "inet", "filter", "input", "handle"]:
            avant = len(self.regles)
            self.regles = [r for r in self.regles if r["handle"] != int(a[7])]
            return cp(a, 0 if len(self.regles) < avant else 1)
        if a[:3] == ["nft", "-c", "-f"] and len(a) == 4:
            assert Path(a[3]).is_file(), a
            return cp(a)
        if a[:2] == ["nft", "-f"] and len(a) == 3:
            texte = Path(a[2]).read_text()
            for ligne in texte.splitlines():
                if ligne.startswith("add rule inet filter input"):
                    self.prochain += 1
                    self.regles.append({"handle": self.prochain,
                                        "comment": re.search(r'comment "([^"]*)"', ligne).group(1)})
            if f"table inet {TABLE_NFT} {{" in texte:
                self.table_lan = True
            return cp(a)
        if a == ["nft", "list", "table", "inet", TABLE_NFT]:
            return cp(a, 0 if self.table_lan else 1)
        if a == ["nft", "delete", "table", "inet", TABLE_NFT]:
            present, self.table_lan = self.table_lan, False
            return cp(a, 0 if present else 1)
        if a == ["unbound-checkconf"]:
            return cp(a)
        raise AssertionError(f"commande inattendue : {a}")

    def regles_lan(self):
        return [r for r in self.regles if r.get("comment", "").startswith("secubox netmodes lan")]


class Horloge:
    def __init__(self):
        self.t = datetime(2026, 10, 26, 12, 0, 0, tzinfo=timezone.utc)

    def __call__(self):
        self.t += timedelta(minutes=1)
        return self.t


def preparer_racine(r: Path, gk2: bool = True) -> Path:
    for d in ("run/lock", "var/log/secubox", "etc/nginx/secubox-lan-geo.d", "etc/systemd/network",
              "etc/netplan", "proc/sys/net/ipv4"):
        (r / d).mkdir(parents=True, exist_ok=True)
    (r / "proc/sys/net/ipv4/ip_forward").write_text("1\n")
    (r / "etc/netplan/00-secubox.yaml").write_text(NETPLAN_GK2)
    (r / "etc/nftables.conf").write_text(NFTABLES_CONF)
    if gk2:
        (r / "etc/systemd/network/10-br-lan.network").write_text(ANCIEN_PONT)
        (r / "run/sbx-lan-dhcp-42.leases").write_text(BAUX_TEMPORAIRES)
    return r


@pytest.fixture(autouse=True)
def umask_022():
    # umask 0002 du poste : les contrôles de droits (C1) verraient des dossiers de test inscriptibles par le groupe
    ancien = os.umask(0o022)
    yield
    os.umask(ancien)


@pytest.fixture
def racine(tmp_path):
    return preparer_racine(tmp_path / "racine")


@pytest.fixture
def faux(racine):
    return Faux(racine)


@pytest.fixture
def ctx(racine, faux):
    return rc.Contexte(racine=racine, executer=faux, maintenant=Horloge(), attendre=faux.attendre)


@pytest.fixture
def neuf(tmp_path):
    """Carte neuve : ni pont, ni LAN temporaire, ni ancien 10-br-lan.network."""
    r = preparer_racine(tmp_path / "neuve", gk2=False)
    f = Faux(r, pont_existant=False)
    f.actifs.discard("sbx-lan-dhcp.service")
    f.regles = [r_ for r_ in f.regles if not r_.get("comment", "").startswith("sbx-lan")]
    return r, f, rc.Contexte(racine=r, executer=f, maintenant=Horloge(), attendre=f.attendre)


def instantane(r: Path) -> dict:
    """Tous les fichiers de la racine, sauf le journal d'audit et les verrous."""
    return {str(p.relative_to(r)): p.read_bytes() for p in sorted(r.rglob("*"))
            if p.is_file() and not p.is_symlink() and p.relative_to(r).as_posix() != AUDIT
            and not p.relative_to(r).as_posix().startswith("run/lock/")}


def geo_vide(r: Path) -> bool:
    """Fragment géo neutre : présent (nginx l'inclut nommément), 0644, rien que des commentaires."""
    f = r / CHEMINS["geo"].lstrip("/")
    return (f.is_file() and not f.is_symlink() and (f.stat().st_mode & 0o777) == 0o644
            and f.read_text().strip() != "" and all(x.startswith("#") for x in f.read_text().splitlines()))


def hors_sauvegardes(fichiers: dict) -> dict:
    return {k: v for k, v in fichiers.items() if not k.startswith(SAUVEGARDES)}


def audits(r: Path) -> list[dict]:
    f = r / AUDIT
    return [json.loads(x) for x in f.read_text().splitlines()] if f.exists() else []


def etat_fichier(r: Path) -> dict:
    return json.loads((r / ETAT).read_text())


def normaliser(journal):
    return [[x if not x.startswith("--description=") else "--description=…" for x in a] for a in journal]


def tenir(chemin: Path) -> int:
    fd = os.open(chemin, os.O_CREAT | os.O_RDWR, 0o600)
    fcntl.flock(fd, fcntl.LOCK_EX)
    return fd


# --- appliquer : ordre, garde eth*, refus ---------------------------------------------------------------------------------

def test_ordre_des_etapes(ctx, faux, racine):
    nft = str(racine / CHEMINS["nft"].lstrip("/"))
    rc.appliquer(ctx, CFG42, "admin")
    assert normaliser(faux.journal) == [
        ["ip", "-j", "-4", "addr"],                                                    # 2
        ["systemctl", "is-active", "--quiet", "pseudo-routeur-sonde.timer"],           # 3
        ["systemctl", "is-active", "--quiet", "dnsmasq.service"],
        ["ip", "-j", "-4", "addr", "show", "dev", "lo"],
        ["nft", "-c", "-f", nft],                                                      # 6
        ["unbound-checkconf"],
        NGINX_T,                                                                       # hors bac à sable
        ["networkctl", "reload"],                                                      # 7
        ["networkctl", "reconfigure", "br-lan", "lan0", "lan1", "lan2", "lan3"],
        ["systemctl", "is-active", "--quiet", "sbx-lan-dhcp.service"],                 # 8
        ["systemctl", "stop", "sbx-lan-dhcp.service"],
        LISTE_INPUT,
        ["nft", "delete", "rule", "inet", "filter", "input", "handle", "12"],
        ["nft", "delete", "rule", "inet", "filter", "input", "handle", "13"],
        ["ip", "-j", "-4", "addr", "show", "dev", "br-lan"],
        ["ip", "addr", "del", "192.168.255.1/24", "dev", "br-lan"],
        LISTE_INPUT,                                                                   # 9
        ["nft", "-f", nft],
        ["systemctl", "restart", "unbound.service"],                                   # 10
        ["systemctl", "enable", "secubox-lan-dhcp.service"],                           # 11
        ["systemctl", "restart", "secubox-lan-dhcp.service"],
        ["systemctl", "is-active", "--quiet", "secubox-lan-dhcp.service"],             # Type=exec : resté actif
        ["systemctl", "is-active", "--quiet", "secubox-lan-dhcp.service"],
        ["systemctl", "reload", "nginx.service"],                                      # 12
        ["systemctl", "stop", "secubox-netmodes-retour.timer"],                        # 13
        ["systemd-run", "--unit=secubox-netmodes-retour", "--on-active=180", "--collect", "--description=…",
         "/usr/sbin/netmodesctl", "routeur-retour", "minuteur"],
        ["systemctl", "is-active", "--quiet", "secubox-netmodes-retour.timer"],        # état rendu
        ["systemctl", "is-active", "--quiet", "secubox-lan-dhcp.service"],
        ["ip", "-j", "-4", "addr", "show", "dev", "br-lan"],
    ]
    assert faux.pauses == [rc.PAUSE_DHCP]                                          # deux relevés, une pause
    # garde armée dès la première écriture (I1) : rien pendant les refus, « en_attente » dès la validation
    i = faux.journal.index(["nft", "-c", "-f", nft])
    assert faux.etats[:i] == [None] * i
    assert set(faux.etats[i:]) == {"en_attente"}


def test_fichiers_poses(ctx, racine):
    sortie = rc.appliquer(ctx, CFG42, "admin")
    for cle, chemin in CHEMINS.items():
        p = racine / chemin.lstrip("/")
        assert p.is_file(), cle
        assert oct(p.stat().st_mode & 0o777) == oct(0o644), cle
    toml = racine / TOML
    assert 'adresse = "192.168.42.1/24"' in toml.read_text()
    assert oct(toml.stat().st_mode & 0o777) == oct(0o640)
    assert oct((racine / ETAT).stat().st_mode & 0o777) == oct(0o640)
    assert not (racine / "etc/systemd/network/10-br-lan.network").exists()         # mis de côté (sauvegardé)
    assert sortie["etat"] == "en_attente" and sortie["delai_confirmation"] == 180
    assert sortie["config"]["adresse"] == "192.168.42.1/24"
    assert sortie["adresses_pont"] == ["192.168.42.1/24"]
    assert sortie["minuteur_actif"] is True and sortie["dhcp_actif"] is True


def test_aucune_commande_ne_nomme_eth(ctx, faux, racine):
    rc.appliquer(ctx, CFG42, "admin")
    assert 'oifname "eth2"' in (racine / CHEMINS["nft"].lstrip("/")).read_text()     # l'exception porte bien sur le fichier
    rc.confirmer(ctx, "admin")
    rc.retour(ctx, "admin")
    assert faux.journal
    for argv in faux.journal:
        if (argv[:3] == ["nft", "-c", "-f"] and len(argv) == 4) or (argv[:2] == ["nft", "-f"] and len(argv) == 3):
            continue
        for a in argv:
            assert not re.search(r"eth[0-2]", a), argv


def instantane_et_refus(ctx, racine, attendu):
    avant = instantane(racine)
    with pytest.raises(rc.Refus, match=attendu):
        rc.appliquer(ctx, CFG42, "admin")
    assert instantane(racine) == avant
    assert not (racine / SAUVEGARDES).exists()
    assert audits(racine)[-1]["action"] == "appliquer-refus"


def test_refus_netplan_declare_br_lan(ctx, racine, faux):
    (racine / "etc/netplan/50-lan.yaml").write_text(
        "network:\n  version: 2\n  bridges:\n    br-lan:\n      interfaces: [lan0, lan1]\n")
    instantane_et_refus(ctx, racine, "netplan.*br-lan|br-lan.*netplan")
    assert not any(a[0] == "networkctl" for a in faux.journal)


def test_refus_netplan_illisible(ctx, racine):
    (racine / "etc/netplan/60-casse.yaml").write_text("network: [\n  : :\n")
    instantane_et_refus(ctx, racine, "60-casse.yaml")


def test_refus_pseudo_routeur_actif(ctx, racine, faux):
    faux.actifs.add("pseudo-routeur-sonde.timer")
    instantane_et_refus(ctx, racine, "pseudo-routeur")


def test_refus_ip_forward_0(ctx, racine):
    (racine / "proc/sys/net/ipv4/ip_forward").write_text("0\n")
    instantane_et_refus(ctx, racine, "ip_forward")


def test_refus_dnsmasq_service_actif(ctx, racine, faux):
    faux.actifs.add("dnsmasq.service")
    instantane_et_refus(ctx, racine, "dnsmasq.service")


@pytest.mark.parametrize("lo", [["127.0.0.1/8", "192.168.255.1/24"], ["127.0.0.1/8"]])
def test_refus_255_sans_lo_32(ctx, racine, faux, lo):
    faux.adresses["lo"] = lo
    instantane_et_refus(ctx, racine, "lo.*/32")


def test_refus_reseau_deja_porte(ctx, racine):
    avant = instantane(racine)
    with pytest.raises(ErreurConfig, match="192.168.1.0/24"):
        rc.appliquer(ctx, dict(CFG42, adresse="192.168.1.1/24", dhcp_debut="192.168.1.100",
                               dhcp_fin="192.168.1.199"), "admin")
    assert instantane(racine) == avant
    assert not (racine / SAUVEGARDES).exists()


def test_occupe(ctx, racine, faux):
    avant = instantane(racine)
    fd = tenir(racine / "run/lock/secubox-netmodes.lock")
    try:
        with pytest.raises(rc.Occupe):
            rc.appliquer(ctx, CFG42, "admin")
        with pytest.raises(rc.Occupe):
            rc.confirmer(ctx, "admin")
        with pytest.raises(rc.Occupe):
            rc.retour(ctx, "admin")
    finally:
        os.close(fd)
    assert faux.journal == []
    assert instantane(racine) == avant
    assert not (racine / SAUVEGARDES).exists()


def test_refus_si_application_en_attente(ctx, racine):
    rc.appliquer(ctx, CFG42, "admin")
    avant = instantane(racine)
    with pytest.raises(rc.Refus, match="confirmation"):
        rc.appliquer(ctx, CFG50, "admin")
    assert instantane(racine) == avant


def test_verrou_unbound_tenu(ctx, racine, faux, monkeypatch):
    monkeypatch.setattr(rc, "DELAI_VERROU_UNBOUND", 0.3)
    fd = tenir(racine / "run/lock/secubox-dns-lan.lock")
    try:
        with pytest.raises(rc.Refus, match="Unbound"):
            rc.appliquer(ctx, CFG42, "admin")
    finally:
        os.close(fd)
    assert not (racine / CHEMINS["nft"].lstrip("/")).exists()
    assert (racine / "etc/systemd/network/10-br-lan.network").read_text() == ANCIEN_PONT
    assert not any(a[0] == "networkctl" for a in faux.journal)


def test_lien_symbolique_refuse(ctx, racine, tmp_path):
    cible = tmp_path / "ailleurs.conf"
    cible.write_text("intouchable\n")
    lien = racine / CHEMINS["dhcp"].lstrip("/")
    lien.parent.mkdir(parents=True)
    lien.symlink_to(cible)
    with pytest.raises(rc.Refus, match="lien symbolique"):
        rc.appliquer(ctx, CFG42, "admin")
    assert cible.read_text() == "intouchable\n"
    assert lien.is_symlink()


# --- validation, bascule, reprise -----------------------------------------------------------------------------------------

def test_validation_nft_echoue_restaure(ctx, racine, faux):
    rc.appliquer(ctx, CFG42, "admin")
    rc.confirmer(ctx, "admin")
    avant = instantane(racine)
    faux.journal.clear()
    faux.echouer("nft", "-c")
    with pytest.raises(rc.Refus, match="nft"):
        rc.appliquer(ctx, CFG50, "admin")
    assert hors_sauvegardes(instantane(racine)) == hors_sauvegardes(avant)        # fichiers d'avant restaurés
    assert "192.168.42.1/24" in (racine / TOML).read_text()
    assert etat_fichier(racine)["etat"] == "actif"
    assert not any(a[0] in ("networkctl", "systemd-run") for a in faux.journal)
    assert audits(racine)[-1]["action"] == "appliquer-echec"


def test_validation_premiere_application_restaure(neuf):
    r, f, ctx = neuf
    avant = instantane(r)
    f.echouer("unbound-checkconf")
    with pytest.raises(rc.Refus, match="unbound-checkconf"):
        rc.appliquer(ctx, CFG42, "admin")
    apres = hors_sauvegardes(instantane(r))
    assert apres.pop(CHEMINS["geo"].lstrip("/")) is not None and geo_vide(r)   # absent avant : remis vide, pas supprimé
    assert apres == avant
    assert not (r / ETAT).exists()


def test_echec_apres_bascule_revient(ctx, racine, faux):
    faux.echouer("systemctl", "restart", "unbound.service", fois=1)
    with pytest.raises(rc.Echec, match="unbound"):
        rc.appliquer(ctx, CFG42, "admin")
    actions = [(a["action"], a["acteur"]) for a in audits(racine)]
    assert ("appliquer-echec", "admin") in actions and ("retour", "echec") in actions
    assert etat_fichier(racine)["etat"] == "inactif"
    assert (racine / "etc/systemd/network/10-br-lan.network").read_text() == ANCIEN_PONT
    for cle, chemin in CHEMINS.items():
        if cle != "geo":
            assert not (racine / chemin.lstrip("/")).exists()
    assert geo_vide(racine)                                                     # jamais supprimé : include de nginx
    assert not (racine / TOML).exists()
    assert not any(a[0] == "systemd-run" and a != NGINX_T for a in faux.journal)    # aucun minuteur armé


def test_reprise_lan_temporaire(ctx, racine, faux):
    rc.appliquer(ctx, CFG42, "admin")
    j = faux.journal
    assert ["systemctl", "stop", "sbx-lan-dhcp.service"] in j
    assert ["nft", "delete", "rule", "inet", "filter", "input", "handle", "12"] in j
    assert ["nft", "delete", "rule", "inet", "filter", "input", "handle", "13"] in j
    assert ["ip", "addr", "del", "192.168.255.1/24", "dev", "br-lan"] in j
    assert ["ip", "addr", "del", "192.168.42.1/24", "dev", "br-lan"] not in j
    assert not [r for r in faux.regles if r.get("comment", "").startswith("sbx-lan-temporaire")]
    assert [r["handle"] for r in faux.regles][:2] == [4, 9]                        # règles de base intactes
    assert (racine / "var/lib/misc/dnsmasq.leases").read_text() == BAUX_TEMPORAIRES


def test_baux_existants_conserves(ctx, racine):
    baux = racine / "var/lib/misc/dnsmasq.leases"
    baux.parent.mkdir(parents=True)
    baux.write_text("1761539999 aa:bb:cc:dd:ee:09 192.168.42.160 nac *\n")
    rc.appliquer(ctx, CFG42, "admin")
    assert "nac" in baux.read_text() and "gk4" not in baux.read_text()


def test_idempotent(ctx, racine, faux):
    rc.appliquer(ctx, CFG42, "admin")
    rc.confirmer(ctx, "admin")
    premieres = [r["handle"] for r in faux.regles_lan()]
    assert len(premieres) == 3
    faux.journal.clear()
    rc.appliquer(ctx, CFG42, "admin")
    rc.confirmer(ctx, "admin")
    j = faux.journal
    i_nft = j.index(["nft", "-f", str(racine / CHEMINS["nft"].lstrip("/"))])
    suppressions = [int(a[7]) for a in j[:i_nft] if a[:7] == ["nft", "delete", "rule", "inet", "filter", "input", "handle"]]
    assert suppressions == premieres
    assert len(faux.regles_lan()) == 3                                             # un seul jeu de règles


def test_geo_absente(ctx, racine, faux):
    (racine / "etc/nginx/secubox-lan-geo.d").rmdir()
    rc.appliquer(ctx, CFG42, "admin")
    assert not any(touche_nginx(a) for a in faux.journal)
    assert not (racine / "etc/nginx/secubox-lan-geo.d").exists()
    assert "geo-absente" in [a["action"] for a in audits(racine)]


# --- minuteur, confirmation, retour ---------------------------------------------------------------------------------------

def test_minuteur_puis_confirmer(ctx, racine, faux):
    rc.appliquer(ctx, CFG42, "admin")
    run = [a for a in faux.journal if a[0] == "systemd-run" and a != NGINX_T]
    assert len(run) == 1
    assert "--unit=secubox-netmodes-retour" in run[0] and "--on-active=180" in run[0]
    assert run[0][-3:] == ["/usr/sbin/netmodesctl", "routeur-retour", "minuteur"]
    assert etat_fichier(racine)["etat"] == "en_attente"
    faux.journal.clear()
    sortie = rc.confirmer(ctx, "autre-admin")
    assert faux.journal[0] == ["systemctl", "stop", "secubox-netmodes-retour.timer"]
    assert sortie["etat"] == "actif" and sortie["minuteur_actif"] is False
    e = etat_fichier(racine)
    assert e["etat"] == "actif" and e["acteur"] == "autre-admin"
    assert ("confirmer", "autre-admin") in [(a["action"], a["acteur"]) for a in audits(racine)]


def test_confirmer_hors_attente_refuse(ctx, faux):
    with pytest.raises(rc.Refus, match="confirmer"):
        rc.confirmer(ctx, "admin")
    assert faux.journal == []


def test_minuteur_echu_apres_confirmation_ne_revient_pas(ctx, racine, faux):
    rc.appliquer(ctx, CFG42, "admin")
    rc.confirmer(ctx, "admin")
    avant = instantane(racine)
    faux.journal.clear()
    rc.retour(ctx, "minuteur")
    assert instantane(racine) == avant
    assert not any(a[0] in ("networkctl", "nft") for a in faux.journal)
    assert audits(racine)[-1]["action"] == "retour-ignore"


def test_retour_minuteur_en_attente(ctx, racine, faux):
    rc.appliquer(ctx, CFG42, "admin")
    rc.retour(ctx, "minuteur")
    assert etat_fichier(racine)["etat"] == "inactif"
    assert ("retour", "minuteur") in [(a["action"], a["acteur"]) for a in audits(racine)]


def test_retour_gk2_remet_l_ancien_pont(ctx, racine, faux):
    rc.appliquer(ctx, CFG42, "admin")
    faux.journal.clear()
    sortie = rc.retour(ctx, "admin")
    assert (racine / "etc/systemd/network/10-br-lan.network").read_text() == ANCIEN_PONT
    for cle, chemin in CHEMINS.items():
        if cle != "geo":
            assert not (racine / chemin.lstrip("/")).exists()
    assert geo_vide(racine)                                                     # jamais supprimé : include de nginx
    j = faux.journal
    assert j[:2] == [["networkctl", "reload"],
                     ["networkctl", "reconfigure", "br-lan", "lan0", "lan1", "lan2", "lan3"]]
    assert ["ip", "link", "delete", "br-lan"] not in j
    assert ["nft", "delete", "table", "inet", TABLE_NFT] in j
    assert faux.regles_lan() == []
    assert ["systemctl", "restart", "unbound.service"] in j
    assert ["systemctl", "disable", "--now", "secubox-lan-dhcp.service"] in j
    assert ["systemctl", "reload", "nginx.service"] in j
    assert ["systemctl", "stop", "secubox-netmodes-retour.timer"] in j
    assert sortie["etat"] == "inactif"
    assert "192.168.255.1/24" in faux.adresses["br-lan"]


def test_retour_premiere_application(neuf):
    r, f, ctx = neuf
    rc.appliquer(ctx, CFG42, "admin")
    assert f.table_lan and "br-lan" in f.adresses
    f.journal.clear()
    sortie = rc.retour(ctx, "admin")
    for cle, chemin in CHEMINS.items():
        if cle != "geo":
            assert not (r / chemin.lstrip("/")).exists()
    assert geo_vide(r)                                                     # jamais supprimé : include de nginx
    assert not (r / TOML).exists()
    j = f.journal
    assert ["ip", "link", "delete", "br-lan"] in j
    assert ["nft", "delete", "table", "inet", TABLE_NFT] in j
    assert ["systemctl", "disable", "--now", "secubox-lan-dhcp.service"] in j
    assert not any(a[:2] == ["networkctl", "reconfigure"] for a in j)
    assert "br-lan" not in f.adresses and not f.table_lan
    assert sortie["etat"] == "inactif" and etat_fichier(r)["etat"] == "inactif"


def test_retour_vers_config_precedente(ctx, racine, faux):
    rc.appliquer(ctx, CFG42, "admin")
    rc.confirmer(ctx, "admin")
    rc.appliquer(ctx, CFG50, "admin")
    faux.journal.clear()
    sortie = rc.retour(ctx, "admin")
    assert "192.168.42.1/24" in (racine / TOML).read_text()
    assert ["nft", "-f", str(racine / CHEMINS["nft"].lstrip("/"))] in faux.journal
    assert ["systemctl", "restart", "secubox-lan-dhcp.service"] in faux.journal
    assert sortie["etat"] == "actif"


def test_retour_apres_validations_echouees(ctx, racine, faux):
    """Les sauvegardes des applications refusées à la validation ne masquent pas celle de la dernière application."""
    rc.appliquer(ctx, CFG42, "admin")
    rc.confirmer(ctx, "admin")
    reference = etat_fichier(racine)["sauvegarde"]
    faux.echouer("nft", "-c", fois=4)
    for _ in range(4):
        with pytest.raises(rc.Refus):
            rc.appliquer(ctx, CFG50, "admin")
    assert (racine / SAUVEGARDES / reference).is_dir()                             # protégée de l'élagage
    assert len(list((racine / SAUVEGARDES).iterdir())) == 5
    sortie = rc.retour(ctx, "admin")
    assert sortie["etat"] == "inactif" and sortie["sauvegarde"] == reference
    assert (racine / "etc/systemd/network/10-br-lan.network").read_text() == ANCIEN_PONT
    assert not (racine / TOML).exists()


def test_sauvegarde_du_fichier_d_etat_non_fiable(ctx, racine, faux, tmp_path):
    rc.appliquer(ctx, CFG42, "admin")
    rc.confirmer(ctx, "admin")
    piege = tmp_path / "piege" / "etc/systemd/network"
    piege.mkdir(parents=True)
    (piege / "10-br-lan.network").write_text("[Match]\nName=eth2\n")
    e = etat_fichier(racine)
    for falsifiee in ("../../../../piege", "/etc", "20261026T120000Z/../.."):
        (racine / ETAT).write_text(json.dumps(dict(e, sauvegarde=falsifiee)))
        rc.retour(ctx, "admin")
        assert (racine / "etc/systemd/network/10-br-lan.network").read_text() == ANCIEN_PONT


def test_retour_sans_sauvegarde_refuse(ctx, faux):
    with pytest.raises(rc.Refus, match="sauvegarde"):
        rc.retour(ctx, "admin")


def test_retour_si_en_attente(ctx, racine, faux):
    rc.appliquer(ctx, CFG42, "admin")
    faux.journal.clear()
    sortie = rc.retour_si_en_attente(ctx)
    assert sortie["etat"] == "inactif"
    assert ["networkctl", "reload"] in faux.journal
    assert ("retour", "demarrage") in [(a["action"], a["acteur"]) for a in audits(racine)]

    rc.appliquer(ctx, CFG42, "admin")
    rc.confirmer(ctx, "admin")
    avant = instantane(racine)
    faux.journal.clear()
    assert rc.retour_si_en_attente(ctx) == {"etat": "actif"}
    assert faux.journal == []
    assert instantane(racine) == avant


# --- état, sauvegardes, audit ---------------------------------------------------------------------------------------------

def test_etat_inactif(ctx):
    e = rc.etat(ctx)
    assert e["etat"] == "inactif" and e["config"] is None and e["sauvegarde"] is None
    assert e["minuteur_actif"] is False and e["dhcp_actif"] is False
    assert e["adresses_pont"] == ["192.168.255.1/24", "192.168.42.1/24"]
    assert "erreur" not in e


def test_etat_config_invalide(ctx, racine):
    t = racine / TOML
    t.parent.mkdir(parents=True)
    t.write_text("[lan\nadresse = \n")
    e = rc.etat(ctx)
    assert e["etat"] == "config_invalide"
    assert "TOML" in e["erreur"] and e["config"] is None
    json.dumps(e)


def test_etat_fichier_d_etat_illisible(ctx, racine):
    (racine / ETAT).parent.mkdir(parents=True)
    (racine / ETAT).write_text("{pas du json")
    e = rc.etat(ctx)
    assert e["etat"] == "config_invalide" and "état" in e["erreur"]


def test_quatre_sauvegardes(ctx, racine):
    for _ in range(5):
        rc.appliquer(ctx, CFG42, "admin")
        rc.confirmer(ctx, "admin")
    dossiers = sorted(p.name for p in (racine / SAUVEGARDES).iterdir())
    assert len(dossiers) == 4
    assert all(re.fullmatch(r"\d{8}T\d{6}Z", d) for d in dossiers)
    premiere = racine / SAUVEGARDES / dossiers[-1]
    assert json.loads((premiere / "absents.json").read_text())                     # liste des chemins absents
    assert (premiere / TOML).is_file()


def test_sauvegarde_contenu(ctx, racine):
    rc.appliquer(ctx, CFG42, "admin")
    (d,) = list((racine / SAUVEGARDES).iterdir())
    assert (d / "etc/systemd/network/10-br-lan.network").read_text() == ANCIEN_PONT
    absents = json.loads((d / "absents.json").read_text())
    assert set(absents) == set(CHEMINS.values()) | {"/etc/secubox/netmodes/routeur.toml"}


def test_audit_format(ctx, racine):
    rc.appliquer(ctx, CFG42, "admin")
    rc.confirmer(ctx, "admin")
    rc.retour(ctx, "admin")
    lignes = (racine / AUDIT).read_text().splitlines()
    assert lignes
    for ligne in lignes:
        a = json.loads(ligne)
        assert set(a) == {"ts", "module", "action", "acteur", "detail"}
        assert re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", a["ts"])
        assert a["module"] == "netmodes" and isinstance(a["detail"], str) and a["detail"]
    assert [a["action"] for a in audits(racine)] == ["appliquer", "confirmer", "retour"]


def test_audit_inscriptible_ne_bloque_pas(ctx, racine, capsys):
    (racine / "var/log/secubox").rmdir()
    rc.appliquer(ctx, CFG42, "admin")
    assert "audit non écrit" in capsys.readouterr().err
    assert etat_fichier(racine)["etat"] == "en_attente"


@pytest.mark.parametrize("acteur", ["a b", "", "x" * 65, "admin\n", "../root", "é"])
def test_acteur_invalide_bibliotheque(ctx, faux, acteur):
    with pytest.raises(rc.Refus, match="acteur"):
        rc.appliquer(ctx, CFG42, acteur)
    assert faux.journal == []


# --- netmodesctl ----------------------------------------------------------------------------------------------------------

@pytest.fixture
def cli():
    loader = importlib.machinery.SourceFileLoader("netmodesctl_test", str(SCRIPT))
    spec = importlib.util.spec_from_loader("netmodesctl_test", loader)
    m = importlib.util.module_from_spec(spec)
    loader.exec_module(m)
    return m


def sortie_json(capsys):
    return json.loads(capsys.readouterr().out)


def test_cli_acteur_invalide(cli, ctx, faux, racine, capsys):
    avant = instantane(racine)
    assert cli.main(["routeur-confirmer", "a b"], ctx=ctx) == 2
    assert "acteur" in sortie_json(capsys)["erreur"]
    assert faux.journal == [] and instantane(racine) == avant


@pytest.mark.parametrize("argv", [[], ["inconnu"], ["routeur-etat", "admin"], ["routeur-appliquer"],
                                  ["routeur-retour", "x" * 65], ["routeur-confirmer", "admin\n"],
                                  ["routeur-retour-demarrage", "admin"], ["routeur-confirmer", "a", "b"]])
def test_cli_usage(cli, ctx, faux, capsys, argv):
    assert cli.main(argv, ctx=ctx) == 2
    assert sortie_json(capsys)["erreur"]
    assert faux.journal == []


def test_cli_non_root(cli, ctx, faux, capsys, monkeypatch):
    monkeypatch.setattr(cli, "_est_root", lambda: False)
    assert cli.main(["routeur-etat"], ctx=ctx) == 1
    assert "root" in sortie_json(capsys)["erreur"]
    assert faux.journal == []


def test_cli_verbes_et_codes(cli, ctx, racine, capsys, monkeypatch):
    monkeypatch.setattr(cli, "_est_root", lambda: True)
    assert cli.main(["routeur-etat"], ctx=ctx) == 0
    assert sortie_json(capsys)["etat"] == "inactif"
    entree = io.BytesIO(json.dumps(CFG42).encode())
    assert cli.main(["routeur-appliquer", "admin"], ctx=ctx, entree=entree) == 0
    assert sortie_json(capsys)["etat"] == "en_attente"
    assert cli.main(["routeur-appliquer", "admin"], ctx=ctx, entree=io.BytesIO(json.dumps(CFG50).encode())) == 3
    assert "confirmation" in sortie_json(capsys)["erreur"]
    assert cli.main(["routeur-confirmer", "admin"], ctx=ctx) == 0
    assert sortie_json(capsys)["etat"] == "actif"
    assert cli.main(["routeur-retour-demarrage"], ctx=ctx) == 0
    assert sortie_json(capsys) == {"etat": "actif"}
    for brut in (b"{pas du json", b"[1, 2]", json.dumps(dict(CFG42, adresse="10.100.0.1/24")).encode(),
                 b" " * (64 * 1024 + 1)):
        assert cli.main(["routeur-appliquer", "admin"], ctx=ctx, entree=io.BytesIO(brut)) == 3
        assert sortie_json(capsys)["erreur"]
    fd = tenir(racine / "run/lock/secubox-netmodes.lock")
    try:
        assert cli.main(["routeur-retour", "admin"], ctx=ctx) == 4
        assert sortie_json(capsys)["erreur"]
    finally:
        os.close(fd)
    assert cli.main(["routeur-retour", "admin"], ctx=ctx) == 0
    assert sortie_json(capsys)["etat"] == "inactif"


def test_cli_echec_systeme_code_1(cli, ctx, faux, capsys, monkeypatch):
    monkeypatch.setattr(cli, "_est_root", lambda: True)
    faux.echouer("networkctl", "reload", fois=1)
    assert cli.main(["routeur-appliquer", "admin"], ctx=ctx, entree=io.BytesIO(json.dumps(CFG42).encode())) == 1
    assert "networkctl" in sortie_json(capsys)["erreur"]


def test_cli_processus_reel_code_2():
    r = subprocess.run([sys.executable, str(SCRIPT), "routeur-confirmer", "a b"],
                       capture_output=True, text=True, timeout=30, check=False)
    assert r.returncode == 2
    assert json.loads(r.stdout)["erreur"]


def test_cli_entete_et_executable():
    texte = SCRIPT.read_text()
    assert texte.startswith("#!/usr/bin/python3")
    assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in texte
    assert os.access(SCRIPT, os.X_OK)
    assert "shell=True" not in texte and "environ" not in texte


# --- relecture : C1 arbre root seul ---------------------------------------------------------------------------------------

def mode(p: Path) -> int:
    return p.stat().st_mode & 0o777


def test_arbre_root_seul(ctx, racine):
    rc.appliquer(ctx, CFG42, "admin")
    assert mode(racine / ARBRE) == 0o700
    assert mode(racine / SAUVEGARDES) == 0o700
    assert mode(racine / ETAT) == 0o640
    dhcp = racine / CHEMINS["dhcp"].lstrip("/")
    assert dhcp.parent == racine / ARBRE and mode(dhcp) == 0o644


def test_ancetre_inscriptible_refuse_rien_restaure(ctx, racine, faux):
    rc.appliquer(ctx, CFG42, "admin")
    rc.confirmer(ctx, "admin")
    os.chmod(racine / "var/lib", 0o775)
    avant = instantane(racine)
    faux.journal.clear()
    with pytest.raises(rc.Refus, match="inscriptible"):
        rc.retour(ctx, "admin")
    assert instantane(racine) == avant and faux.journal == []
    assert audits(racine)[-1]["action"] == "chemin-refuse"
    with pytest.raises(rc.Refus, match="inscriptible"):
        rc.appliquer(ctx, CFG50, "admin")
    assert instantane(racine) == avant
    e = rc.etat(ctx)
    assert e["etat"] == "config_invalide" and "inscriptible" in e["erreur"]


def test_arbre_preexistant_non_sur(ctx, racine):
    (racine / ARBRE).mkdir(parents=True)
    os.chmod(racine / ARBRE, 0o770)
    avant = instantane(racine)
    with pytest.raises(rc.Refus, match="inscriptible"):
        rc.appliquer(ctx, CFG42, "admin")
    assert instantane(racine) == avant and not (racine / SAUVEGARDES).exists()


def test_arbre_lien_symbolique(ctx, racine, tmp_path):
    ailleurs = tmp_path / "ailleurs"
    ailleurs.mkdir()
    (racine / "var/lib").mkdir(parents=True, exist_ok=True)
    (racine / ARBRE).symlink_to(ailleurs)
    with pytest.raises(rc.Refus, match="lien symbolique"):
        rc.appliquer(ctx, CFG42, "admin")
    assert list(ailleurs.iterdir()) == []


def test_arbre_autre_proprietaire(ctx, racine, monkeypatch):
    monkeypatch.setattr(os, "geteuid", lambda: os.getuid() + 1)   # les fichiers du test ne sont plus « à nous »
    with pytest.raises(rc.Refus, match="appartient"):
        rc.appliquer(ctx, CFG42, "admin")
    assert not (racine / SAUVEGARDES).exists()


def test_creer_dossiers_refuse_un_dossier_preexistant_non_sur(tmp_path):
    (tmp_path / "a").mkdir()
    os.chmod(tmp_path / "a", 0o777)
    with pytest.raises(rf.CheminNonSur):
        rf.creer_dossiers(tmp_path / "a" / "b", 0o700, racine=tmp_path)
    assert not (tmp_path / "a" / "b").exists()


# --- relecture : I1 garde armée dès la première écriture ------------------------------------------------------------------

def test_etat_en_attente_des_le_premier_fichier(ctx, racine, faux, monkeypatch):
    vus = []
    ecrire = rf.ecrire
    geres = {str(racine / c.lstrip("/")) for c in (*CHEMINS.values(), "/" + TOML)}

    def espion(chemin, *args, **kwargs):
        if str(chemin) in geres and not vus:
            f = racine / ETAT
            vus.append(json.loads(f.read_text()) if f.exists() else None)
        return ecrire(chemin, *args, **kwargs)

    monkeypatch.setattr(rf, "ecrire", espion)
    au_reload = []

    def panne(argv):
        au_reload.append(json.loads((racine / ETAT).read_text()))
        raise RuntimeError("panne simulée à l'étape 7")

    faux.sur("networkctl", "reload", fonction=panne)
    with pytest.raises(RuntimeError, match="étape 7"):
        rc.appliquer(ctx, CFG42, "admin")
    (nom,) = [d.name for d in (racine / SAUVEGARDES).iterdir()]
    assert vus[0]["etat"] == "en_attente" and vus[0]["sauvegarde"] == nom
    assert au_reload[0]["etat"] == "en_attente" and au_reload[0]["sauvegarde"] == nom


def test_exception_inattendue_etape_9_revient(ctx, racine, faux):
    nft = str(racine / CHEMINS["nft"].lstrip("/"))
    appels = []

    def panne(argv):
        if argv == ["nft", "-f", nft] and not appels:
            appels.append(argv)
            raise RuntimeError("panne simulée à l'étape 9")

    faux.sur("nft", "-f", fonction=panne)
    with pytest.raises(RuntimeError, match="étape 9"):
        rc.appliquer(ctx, CFG42, "admin")
    assert etat_fichier(racine)["etat"] == "inactif"
    assert (racine / "etc/systemd/network/10-br-lan.network").read_text() == ANCIEN_PONT
    for cle, chemin in CHEMINS.items():
        if cle != "geo":
            assert not (racine / chemin.lstrip("/")).exists()
    assert geo_vide(racine)                                                     # jamais supprimé : include de nginx
    actions = [(a["action"], a["acteur"]) for a in audits(racine)]
    assert ("appliquer-echec", "admin") in actions and ("retour", "echec") in actions


def test_refus_de_validation_remet_l_etat_d_avant(ctx, racine, faux):
    rc.appliquer(ctx, CFG42, "admin")
    rc.confirmer(ctx, "admin")
    avant = (racine / ETAT).read_bytes()
    faux.echouer("unbound-checkconf", fois=1)
    with pytest.raises(rc.Refus):
        rc.appliquer(ctx, CFG50, "admin")
    assert (racine / ETAT).read_bytes() == avant


def test_signaux_ignores_pendant_bascule_et_retour(ctx, faux):
    signaux = (signal.SIGTERM, signal.SIGHUP, signal.SIGINT)
    avant = [signal.getsignal(s) for s in signaux]
    vus = []
    faux.sur("networkctl", "reload", fonction=lambda argv: vus.append([signal.getsignal(s) for s in signaux]))
    rc.appliquer(ctx, CFG42, "admin")
    assert [signal.getsignal(s) for s in signaux] == avant
    rc.retour(ctx, "admin")
    assert len(vus) == 2 and all(v == [signal.SIG_IGN] * 3 for v in vus)
    assert [signal.getsignal(s) for s in signaux] == avant


def test_cli_exception_inattendue_code_1(cli, ctx, racine, faux, capsys, monkeypatch):
    monkeypatch.setattr(cli, "_est_root", lambda: True)
    faux.sur("nft", "-f", fonction=lambda argv: (_ for _ in ()).throw(RuntimeError("panne simulée")))
    code = cli.main(["routeur-appliquer", "admin"], ctx=ctx, entree=io.BytesIO(json.dumps(CFG42).encode()))
    assert code == 1
    assert "RuntimeError" in sortie_json(capsys)["erreur"]


# --- relecture : I2 sauvegardes ordonnées par séquence ---------------------------------------------------------------------

def test_horloge_en_retard_sur_les_sauvegardes(racine, faux):
    futur = Horloge()
    futur.t = datetime(2030, 1, 1, tzinfo=timezone.utc)
    ctx_futur = rc.Contexte(racine=racine, executer=faux, maintenant=futur, attendre=faux.attendre)
    for _ in range(4):
        rc.appliquer(ctx_futur, CFG42, "admin")
        rc.confirmer(ctx_futur, "admin")
    ctx = rc.Contexte(racine=racine, executer=faux, maintenant=Horloge(), attendre=faux.attendre)   # horloge en 2026
    sortie = rc.appliquer(ctx, CFG50, "admin")
    nom = sortie["sauvegarde"]
    assert nom.startswith("2026") and (racine / SAUVEGARDES / nom).is_dir()
    assert len([d for d in (racine / SAUVEGARDES).iterdir() if d.is_dir()]) == 4
    rc.retour(ctx, "admin")                                                    # revient à la config de 2030 (42)
    assert "192.168.42.1/24" in (racine / TOML).read_text()


def test_sauvegarde_porte_une_sequence(ctx, racine):
    for _ in range(2):
        rc.appliquer(ctx, CFG42, "admin")
        rc.confirmer(ctx, "admin")
    sequences = sorted(int((d / "sequence").read_text()) for d in (racine / SAUVEGARDES).iterdir())
    assert sequences == [1, 2]


# --- relecture : M1 adresse déjà retirée par networkd ---------------------------------------------------------------------

def test_adresse_deja_retiree_par_networkd(ctx, racine, faux):
    def networkd_plus_rapide(argv):
        if argv[3] in faux.adresses.get("br-lan", []):
            faux.adresses["br-lan"].remove(argv[3])

    faux.sur("ip", "addr", "del", fonction=networkd_plus_rapide)
    sortie = rc.appliquer(ctx, CFG42, "admin")
    assert sortie["etat"] == "en_attente"
    i = faux.journal.index(["ip", "addr", "del", "192.168.255.1/24", "dev", "br-lan"])
    assert faux.journal[i + 1] == ["ip", "-j", "-4", "addr", "show", "dev", "br-lan"]     # relu avant de tolérer
    assert "retour" not in [a["action"] for a in audits(racine)]


@pytest.mark.parametrize("code, erreur", [(2, "RTNETLINK answers: Cannot assign requested address"),
                                          (2, "RTNETLINK answers: Operation not permitted"),
                                          (1, "Cannot assign requested address")])
def test_ip_addr_del_echec_reel_fatal(ctx, racine, faux, code, erreur):
    faux.echouer("ip", "addr", "del", code=code, erreur=erreur)                # l'adresse reste en place
    with pytest.raises(rc.Echec, match="ip addr del"):
        rc.appliquer(ctx, CFG42, "admin")
    assert ("retour", "echec") in [(a["action"], a["acteur"]) for a in audits(racine)]


# --- relecture : M4 le minuteur et le démarrage attendent le verrou --------------------------------------------------------

def tenir_puis_lacher(chemin: Path, duree: float) -> threading.Thread:
    pret = threading.Event()

    def tenir_():
        fd = tenir(chemin)
        pret.set()
        time.sleep(duree)
        os.close(fd)

    t = threading.Thread(target=tenir_)
    t.start()
    pret.wait()
    return t


@pytest.mark.parametrize("appel", [lambda ctx: rc.retour(ctx, "minuteur"), rc.retour_si_en_attente])
def test_retour_automatique_attend_le_verrou(ctx, racine, appel):
    rc.appliquer(ctx, CFG42, "admin")
    t = tenir_puis_lacher(racine / "run/lock/secubox-netmodes.lock", 0.4)
    try:
        sortie = appel(ctx)
    finally:
        t.join()
    assert sortie["etat"] == "inactif"


def test_retour_automatique_abandonne_apres_le_delai(ctx, racine, monkeypatch):
    rc.appliquer(ctx, CFG42, "admin")
    monkeypatch.setattr(rc, "DELAI_VERROU_RETOUR", 0.3)
    fd = tenir(racine / "run/lock/secubox-netmodes.lock")
    try:
        with pytest.raises(rc.Occupe):
            rc.retour(ctx, "minuteur")
        debut = time.monotonic()
        with pytest.raises(rc.Occupe):
            rc.retour(ctx, "admin")                                            # un humain : réponse immédiate
        assert time.monotonic() - debut < 0.2
    finally:
        os.close(fd)
    assert etat_fichier(racine)["etat"] == "en_attente"


# --- suivi T8 : nginx inclut le fragment géo nommément, il ne disparaît jamais ---------------------------------------------

def test_geo_absent_de_la_sauvegarde_remis_vide(ctx, racine, faux):
    geo = racine / CHEMINS["geo"].lstrip("/")
    assert geo.parent.is_dir() and not geo.exists()
    rc.appliquer(ctx, CFG42, "admin")
    (d,) = list((racine / SAUVEGARDES).iterdir())
    assert CHEMINS["geo"] in json.loads((d / "absents.json").read_text())
    assert "192.168.42.0/24 1;" in geo.read_text()
    faux.journal.clear()
    rc.retour(ctx, "admin")
    assert geo_vide(racine)
    assert ["systemctl", "reload", "nginx.service"] in faux.journal


def test_geo_dossier_absent_rien(ctx, racine, faux):
    (racine / "etc/nginx/secubox-lan-geo.d").rmdir()
    rc.appliquer(ctx, CFG42, "admin")
    rc.retour(ctx, "admin")
    faux.echouer("nft", "-c", fois=1)
    with pytest.raises(rc.Refus):
        rc.appliquer(ctx, CFG42, "admin")
    assert not (racine / "etc/nginx/secubox-lan-geo.d").exists()
    assert not any(touche_nginx(a) for a in faux.journal)


# --- revue T7 : nginx -t hors du bac à sable, retour au démarrage sans attendre une unité ordonnée après lui --------------

def test_nginx_t_hors_bac_a_sable_et_refus(ctx, racine, faux):
    """nginx -t passe par systemd-run (contexte de PID 1) : dans l'espace de montage de l'API, /run/nginx.pid et
    /var/log/nginx sont en lecture seule et il échouerait toujours. Un refus reste un refus, fichiers remis."""
    rc.appliquer(ctx, CFG42, "admin")
    rc.confirmer(ctx, "admin")
    avant = instantane(racine)
    faux.journal.clear()
    faux.echouer(*NGINX_T, code=1, fois=1, erreur="nginx: [emerg] unexpected end of file\n")
    with pytest.raises(rc.Refus, match="nginx -t refuse la configuration : nginx: \\[emerg\\] unexpected"):
        rc.appliquer(ctx, CFG50, "admin")
    assert NGINX_T in faux.journal
    assert not any(a[:2] == ["nginx", "-t"] for a in faux.journal)
    assert hors_sauvegardes(instantane(racine)) == hors_sauvegardes(avant)        # fichiers d'avant restaurés
    assert etat_fichier(racine)["etat"] == "actif"
    assert not any(a[0] == "networkctl" or "--unit=secubox-netmodes-retour" in a for a in faux.journal)


def _deux_applications_dont_la_seconde_en_attente(ctx, faux):
    rc.appliquer(ctx, CFG42, "admin")
    rc.confirmer(ctx, "admin")
    rc.appliquer(ctx, CFG50, "admin")                       # en attente : la sauvegarde contient le DHCP de CFG42
    faux.journal.clear()
    faux.pauses.clear()


def test_retour_au_demarrage_ne_bloque_pas_sur_le_dhcp_ni_nginx(ctx, racine, faux):
    """secubox-netmodes-retour-boot est ordonné AVANT secubox-lan-dhcp : un `systemctl restart` bloquant du DHCP
    attendrait la fin de l'unité qui l'attend (blocage jusqu'au délai de 120 s, retour faussement incomplet). Au
    démarrage, les relances partent sans attendre ; le DHCP démarre après, sur la configuration remise."""
    _deux_applications_dont_la_seconde_en_attente(ctx, faux)
    sortie = rc.retour_si_en_attente(ctx)
    assert sortie["etat"] == "actif"
    assert ["systemctl", "restart", "--no-block", "secubox-lan-dhcp.service"] in faux.journal
    assert ["systemctl", "reload", "--no-block", "nginx.service"] in faux.journal
    assert not any(a[:2] in (["systemctl", "restart"], ["systemctl", "reload"]) and "--no-block" not in a
                   and a[-1] in ("secubox-lan-dhcp.service", "nginx.service") for a in faux.journal)
    assert "192.168.42.1" in (racine / CHEMINS["dhcp"].lstrip("/")).read_text()
    assert faux.pauses == []                                                    # rien n'attend une unité ordonnée après


@pytest.mark.parametrize("acteur", ["admin", "minuteur"])
def test_retour_hors_demarrage_attend_les_relances(ctx, faux, acteur):
    """Hors démarrage, le retour attend chaque relance pour signaler un échec (retour incomplet)."""
    _deux_applications_dont_la_seconde_en_attente(ctx, faux)
    rc.retour(ctx, acteur)
    assert ["systemctl", "restart", "secubox-lan-dhcp.service"] in faux.journal
    assert ["systemctl", "reload", "nginx.service"] in faux.journal
    assert not any("--no-block" in a for a in faux.journal)
    i = faux.journal.index(["systemctl", "restart", "secubox-lan-dhcp.service"])   # resté actif, vérifié
    assert faux.journal[i + 1:i + 3] == [["systemctl", "is-active", "--quiet", "secubox-lan-dhcp.service"]] * 2


# --- relecture finale : I1 TOML édité à la main avec un octet non UTF-8 ---------------------------------------------------

TOML_LATIN1 = (b'[lan]\nadresse = "192.168.42.1/24"\ndhcp_debut = "192.168.42.100"\ndhcp_fin = "192.168.42.199"\n'
               b"# r\xe9seau du bureau\n")


def test_etat_toml_non_utf8_config_invalide(cli, ctx, racine, capsys, monkeypatch):
    rc.appliquer(ctx, CFG42, "admin")
    (racine / TOML).write_bytes(TOML_LATIN1)
    e = rc.etat(ctx)
    assert e["etat"] == "config_invalide" and "UTF-8" in e["erreur"] and e["config"] is None
    json.dumps(e)
    monkeypatch.setattr(cli, "_est_root", lambda: True)
    assert cli.main(["routeur-etat"], ctx=ctx) == 0                              # plus de trace, plus de 502
    assert sortie_json(capsys)["etat"] == "config_invalide"


@pytest.mark.parametrize("appel", [lambda ctx: rc.retour(ctx, "minuteur"), rc.retour_si_en_attente])
def test_toml_non_utf8_le_retour_automatique_aboutit(ctx, racine, faux, appel):
    """Le retour ne dépend jamais de la lecture du TOML courant : illisible, tous les ports du LAN sont reconfigurés
    (appliqué sur lan0 lan1 seulement : lan2 et lan3 ne viennent que du repli)."""
    rc.appliquer(ctx, dict(CFG42, ports=["lan0", "lan1"]), "admin")
    (racine / TOML).write_bytes(TOML_LATIN1)
    faux.journal.clear()
    sortie = appel(ctx)
    assert sortie["etat"] == "inactif" and etat_fichier(racine)["etat"] == "inactif"
    assert not (racine / TOML).exists()
    assert (racine / "etc/systemd/network/10-br-lan.network").read_text() == ANCIEN_PONT
    assert ["networkctl", "reconfigure", "br-lan", "lan0", "lan1", "lan2", "lan3"] in faux.journal
    assert [a["action"] for a in audits(racine)][-1] == "retour"


# --- relecture finale : I3 le fragment nft n'est rechargé au démarrage que par l'inclusion de nftables.conf ---------------

@pytest.mark.parametrize("contenu", [
    None,                                                                      # absent
    "#!/usr/sbin/nft -f\nflush ruleset\ntable inet filter {\n}\n",            # sans inclusion
    '#include "/etc/nftables.d/*.nft"\n',                                      # commentée
    '# include "/etc/nftables.d/*.nft"\n',
    'include "/etc/secubox/hardening/nft-site.d/*.nft"\n',                     # un autre dossier
    'include "/etc/nftables.d/autre.nft"\n',
])
def test_refus_sans_inclusion_de_nftables_d(ctx, racine, faux, contenu):
    conf = racine / "etc/nftables.conf"
    if contenu is None:
        conf.unlink()
    else:
        conf.write_text(contenu)
    instantane_et_refus(ctx, racine, "nftables.conf")
    assert not any(a[0] == "networkctl" for a in faux.journal)


@pytest.mark.parametrize("ligne", [
    'include "/etc/nftables.d/*.nft"',
    "include '/etc/nftables.d/*.nft'",
    "   include\t  /etc/nftables.d/*.nft   ",
    'include "/etc/nftables.d/*.nft"   # services des paquets',
    'include "/etc/nftables.d/*"',
])
def test_inclusion_de_nftables_d_toleree(ctx, racine, ligne):
    (racine / "etc/nftables.conf").write_text(f"flush ruleset\n{ligne}\n")
    assert rc.appliquer(ctx, CFG42, "admin")["etat"] == "en_attente"


# --- relecture finale : I4 l'ancien 10-br-lan.network n'est mis de côté que s'il ne vise que br-lan ------------------------

@pytest.mark.parametrize("texte", [
    ANCIEN_PONT,
    "# pont fait main\n[Match]\n  Name = br-lan  \n\n[Network]\nAddress=192.168.255.1/24\n",
])
def test_ancien_pont_exact_mis_de_cote(ctx, racine, texte):
    ancien = racine / "etc/systemd/network/10-br-lan.network"
    ancien.write_text(texte)
    rc.appliquer(ctx, CFG42, "admin")
    assert not ancien.exists()
    rc.retour(ctx, "admin")
    assert ancien.read_text() == texte


@pytest.mark.parametrize("match", [
    "Name=br-lan eth2",                                                        # supprimé, networkd reconfigurerait le WAN
    "Name=eth2 br-lan",
    "Name=br-*",
    "Name=br-lan\nName=eth2",                                                  # deux lignes : listes concaténées
    "Name=br-lan\nMACAddress=f0:ad:4e:27:88:9b",                               # autre clé de correspondance
    "Name=br-lan\nType=bridge",
    "Name=eth2",
    "",                                                                        # [Match] vide : toutes les interfaces
])
def test_ancien_pont_non_exact_refuse(ctx, racine, faux, match):
    (racine / "etc/systemd/network/10-br-lan.network").write_text(
        f"[Match]\n{match}\n\n[Network]\nAddress=192.168.255.1/24\n")
    instantane_et_refus(ctx, racine, "10-br-lan.network")
    assert not any(a[0] == "networkctl" for a in faux.journal)


def test_ancien_pont_change_apres_les_refus_prealables(ctx, racine, faux):
    """Modifié entre les refus préalables et la pose : refus sous la garde, fichiers et état d'avant remis."""
    ancien = racine / "etc/systemd/network/10-br-lan.network"
    piege = "[Match]\nName=br-lan eth2\n"
    faux.sur("ip", "-j", "-4", "addr", "show", "dev", "lo", fonction=lambda argv: ancien.write_text(piege))
    with pytest.raises(rc.Refus, match="10-br-lan.network"):
        rc.appliquer(ctx, CFG42, "admin")
    assert ancien.read_text() == piege
    assert not (racine / ETAT).exists() and not (racine / TOML).exists()
    assert not any(a[0] == "networkctl" for a in faux.journal)
    assert audits(racine)[-1]["action"] == "appliquer-echec"


# --- relecture finale : I6 Unbound n'est redémarré que si son drop-in change --------------------------------------------

REDEMARRER_UNBOUND = ["systemctl", "restart", "unbound.service"]


def test_unbound_inchange_pas_de_redemarrage(ctx, racine, faux):
    """Même sous-réseau, bail différent : le drop-in Unbound est identique, le DNS de toute la box n'est pas coupé."""
    rc.appliquer(ctx, CFG42, "admin")
    rc.confirmer(ctx, "admin")
    unbound = (racine / CHEMINS["unbound"].lstrip("/")).read_bytes()
    faux.journal.clear()
    rc.appliquer(ctx, dict(CFG42, bail="30m"), "admin")
    assert "30m" in (racine / CHEMINS["dhcp"].lstrip("/")).read_text()
    assert (racine / CHEMINS["unbound"].lstrip("/")).read_bytes() == unbound
    assert REDEMARRER_UNBOUND not in faux.journal
    assert ["systemctl", "restart", "secubox-lan-dhcp.service"] in faux.journal
    assert "Unbound inchangé" in audits(racine)[-1]["detail"]
    faux.journal.clear()
    rc.retour(ctx, "admin")                                                    # restauré identique : pas de coupure
    assert "12h" in (racine / CHEMINS["dhcp"].lstrip("/")).read_text()
    assert REDEMARRER_UNBOUND not in faux.journal
    assert "Unbound inchangé" in audits(racine)[-1]["detail"]


def test_unbound_change_redemarre(ctx, racine, faux):
    rc.appliquer(ctx, CFG42, "admin")
    rc.confirmer(ctx, "admin")
    faux.journal.clear()
    rc.appliquer(ctx, CFG50, "admin")                                          # nouvelle adresse : nouvelle écoute
    assert faux.journal.count(REDEMARRER_UNBOUND) == 1
    faux.journal.clear()
    rc.retour(ctx, "admin")                                                    # retour à 192.168.42.1
    assert "interface: 192.168.42.1" in (racine / CHEMINS["unbound"].lstrip("/")).read_text()
    assert faux.journal.count(REDEMARRER_UNBOUND) == 1


def test_unbound_inchange_echec_de_bascule_sans_redemarrage(ctx, racine, faux):
    """Bascule en échec avec un drop-in inchangé : le retour automatique ne coupe pas non plus le DNS."""
    rc.appliquer(ctx, CFG42, "admin")
    rc.confirmer(ctx, "admin")
    faux.journal.clear()
    faux.echouer("networkctl", "reconfigure", fois=1)
    with pytest.raises(rc.Echec, match="networkctl"):
        rc.appliquer(ctx, dict(CFG42, bail="30m"), "admin")
    assert ("retour", "echec") in [(a["action"], a["acteur"]) for a in audits(racine)]
    assert REDEMARRER_UNBOUND not in faux.journal


# --- relecture finale : I7 dnsmasq doit rester actif après sa relance (Type=exec) ----------------------------------------

EST_ACTIF_DHCP = ("systemctl", "is-active", "--quiet", "secubox-lan-dhcp.service")


def test_dhcp_jamais_actif_echec_et_retour(ctx, racine, faux):
    """Refus AppArmor ou port 67 pris : dnsmasq boucle en auto-restart, `restart` a pourtant rendu 0. Échec d'étape,
    retour automatique, aucun minuteur armé."""
    faux.echouer(*EST_ACTIF_DHCP, code=3, erreur="")
    with pytest.raises(rc.Echec, match="secubox-lan-dhcp.service n'est pas resté actif"):
        rc.appliquer(ctx, CFG42, "admin")
    assert faux.pauses == [rc.PAUSE_DHCP] * (rc.RELEVES_DHCP - 1)
    assert sum(faux.pauses) <= 5.0
    actions = [(a["action"], a["acteur"]) for a in audits(racine)]
    assert ("appliquer-echec", "admin") in actions and ("retour", "echec") in actions
    assert etat_fichier(racine)["etat"] == "inactif"
    assert (racine / "etc/systemd/network/10-br-lan.network").read_text() == ANCIEN_PONT
    assert not any("--unit=secubox-netmodes-retour" in a for a in faux.journal)


def test_dhcp_actif_puis_tombe(ctx, racine, faux):
    """Vu actif juste après l'exec, puis mort (auto-restart) : un seul relevé ne suffit pas."""
    vus = []

    def meurt_apres_le_premier_releve(argv):
        vus.append(argv)
        if len(vus) == 2:
            faux.actifs.discard("secubox-lan-dhcp.service")

    faux.sur(*EST_ACTIF_DHCP, fonction=meurt_apres_le_premier_releve)
    with pytest.raises(rc.Echec, match="secubox-lan-dhcp.service n'est pas resté actif"):
        rc.appliquer(ctx, CFG42, "admin")
    assert ("retour", "echec") in [(a["action"], a["acteur"]) for a in audits(racine)]
    assert etat_fichier(racine)["etat"] == "inactif"


def test_dhcp_actif_en_retard_accepte(ctx, racine, faux):
    faux.echouer(*EST_ACTIF_DHCP, code=3, fois=2, erreur="")                 # « activating » deux relevés durant
    sortie = rc.appliquer(ctx, CFG42, "admin")
    assert sortie["etat"] == "en_attente"
    assert faux.pauses == [rc.PAUSE_DHCP] * 3
    assert "retour" not in [a["action"] for a in audits(racine)]


def test_retour_dhcp_jamais_actif_retour_incomplet(ctx, racine, faux):
    """Hors démarrage, un DHCP restauré qui ne reste pas actif rend le retour incomplet (signalé, pas tu)."""
    rc.appliquer(ctx, CFG42, "admin")
    rc.confirmer(ctx, "admin")
    rc.appliquer(ctx, CFG50, "admin")
    faux.echouer(*EST_ACTIF_DHCP, code=3, erreur="")
    with pytest.raises(rc.Echec, match="retour incomplet : DHCP : secubox-lan-dhcp.service n'est pas resté actif"):
        rc.retour(ctx, "admin")
    assert "192.168.42.1/24" in (racine / TOML).read_text()                     # la restauration a eu lieu
    assert etat_fichier(racine)["etat"] == "actif"
