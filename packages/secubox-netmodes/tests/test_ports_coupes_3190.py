# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3190 — couper et rétablir un port du switch (contrôleur netmodesctl).

Leçon de gk2 (2026-10-26) : un .network de préfixe plus bas gagne pour un même lien (premier trouvé dans l'ordre
lexical) : 04-secubox-port-<port>-coupe.network ([Match] Name=<port>, [Link] ActivationPolicy=down) sort le port du pont
et le baisse ; retiré, `networkctl reload` puis `networkctl reconfigure <port>` le rendent au 05 (Bridge=br-lan). Jamais
une commande qui nomme eth* ou br-lan ; le résultat est relu (`ip -j link show dev <port>`), jamais supposé.
Review Focus 4 : un port coupé ne fait ni échouer, ni recréer le pont d'une réapplication du mode routeur, ni du retour.
Arbitrage du contrôleur : une coupure est une décision de l'administrateur, indépendante du mode routeur ; elle survit à
tout retour (même vers « inactif ») et `port-retablir` est permis en tout mode. Rétabli : br-lan pour maître si le mode
routeur est actif ET le port dans le pont configuré, sinon port UP (au besoin `ip link set dev <port> up`)."""
import io
import json
import os
import re
import signal
import subprocess
import sys
from pathlib import Path
from unittest import mock

import pytest

import secubox_core.config as _cfg

_cfg._CONFIG = {"global": {}, "api": {"socket_dir": "/tmp/secubox", "jwt_secret": "test"}, "auth": {"users": {}}}
with mock.patch("pathlib.Path.mkdir"):
    from api import reseau_api  # noqa: E402

from api import routeur_ctl as rc  # noqa: E402
from api.routeur_config import PORTS_LAN  # noqa: E402
from api.routeur_rendu import CHEMINS  # noqa: E402
from test_routeur_ctl_3189 import (  # noqa: E402
    CFG42, CFG50, PORTS, SCRIPT, TOML, Faux, Horloge, audits, cp, etat_fichier, injecter_horloge_verrou, instantane,
    preparer_racine, tenir,
)

COUPE = "etc/systemd/network/04-secubox-port-{}-coupe.network"
RELOAD = ["networkctl", "reload"]
SUPPRIMER = ["ip", "link", "delete", "br-lan"]
LECTURES_ETAT = [["systemctl", "is-active", "--quiet", "secubox-netmodes-retour.timer"],
                 ["systemctl", "is-active", "--quiet", "secubox-lan-dhcp.service"],
                 ["ip", "-j", "-4", "addr", "show", "dev", "br-lan"]]
VERBES = ["port_couper", "port_retablir"]
LEVER = ["ip", "link", "set", "dev", "lan1", "up"]
NETPLAN_LAN1 = "run/systemd/network/10-netplan-lan1.network"           # posé par netplan sur gk2 (lan1: optional)


def contenu_coupe(port: str) -> str:
    return ("# SPDX-License-Identifier: LicenseRef-CMSD-1.0\n# GÉNÉRÉ par secubox-netmodes\n"
            f"# {port} coupé (netmodesctl port-couper) : hors du pont et baissé ; netmodesctl port-retablir le rétablit\n"
            f"[Match]\nName={port}\n\n[Link]\nActivationPolicy=down\n")


def reconfigurer(port: str) -> list[str]:
    return ["networkctl", "reconfigure", port]


def lien(port: str) -> list[str]:
    return ["ip", "-j", "link", "show", "dev", port]


def action(verbe: str) -> str:
    return verbe.replace("_", "-")


class FauxPorts(Faux):
    """networkd simulé, en plus : 04-secubox-port-<port>-coupe.network gagne sur le 05 pour ce port (hors du pont,
    baissé) ; retiré, le port n'est relevé que si un autre .network le vise (05 du mode routeur, 10-netplan-<port> de
    gk2) : sinon networkd le laisse baissé, seul `ip link set dev <port> up` le relève."""

    def __init__(self, racine: Path, **kw):
        super().__init__(racine, **kw)
        self.baisses: set[str] = set()
        self.coupe_ignoree = False                      # networkd n'applique pas le 04 : le port reste au pont, UP
        self.retour_refuse = False                      # networkd ne reprend pas le port rétabli

    def _coupe(self, port: str) -> bool:
        return (self.racine / COUPE.format(port)).is_file()

    def _declare(self, port: str) -> bool:
        """Un .network autre qu'un fichier de coupure vise le port ([Match] Name=…)."""
        for dossier in ("etc/systemd/network", "run/systemd/network"):
            d = self.racine / dossier
            for f in sorted(d.glob("*.network")) if d.is_dir() else []:
                if re.fullmatch(r"04-secubox-port-lan[0-3]-coupe\.network", f.name):
                    continue
                if any(x.startswith("Name=") and port in x[5:].split() for x in f.read_text().splitlines()):
                    return True
        return False

    def _asservir(self, port: str) -> None:
        if self._coupe(port) and not self.coupe_ignoree:
            self.maitres.pop(port, None)
            self.baisses.add(port)
            return
        if port in self.baisses:
            if self.retour_refuse or not self._declare(port):
                return                                  # aucun .network ne le vise : networkd le laisse baissé
            self.baisses.discard(port)
        super()._asservir(port)

    def _effet(self, a):
        if a[:4] == ["ip", "link", "set", "dev"]:
            assert len(a) == 6 and a[4] in PORTS and a[5] == "up", a      # le port seul, jamais eth* ni br-lan
            self.baisses.discard(a[4])
            return cp(a)
        return super()._effet(a)

    def _lien(self, port: str) -> dict:
        e = super()._lien(port)
        if port in self.baisses:                        # administrativement baissé : ni UP, ni porteuse
            e["flags"] = ["BROADCAST", "MULTICAST"]
            e["operstate"] = "DOWN"
        return e


@pytest.fixture(autouse=True)
def umask_022():
    ancien = os.umask(0o022)                            # contrôles de droits de l'arbre root seul (voir test_routeur_ctl)
    yield
    os.umask(ancien)


@pytest.fixture
def racine(tmp_path):
    return preparer_racine(tmp_path / "racine")


@pytest.fixture
def faux(racine):
    return FauxPorts(racine)


@pytest.fixture
def verrou_instantane(monkeypatch):
    """Attente du verrou (2 s pour une action humaine, #3190) déroulée sur une horloge injectée."""
    return injecter_horloge_verrou(monkeypatch)


@pytest.fixture
def ctx(racine, faux):
    return rc.Contexte(racine=racine, executer=faux, maintenant=Horloge(), attendre=faux.attendre,
                       monotone=faux.monotone)


@pytest.fixture
def actif(ctx, faux):
    """Mode routeur appliqué et confirmé (CFG42, les quatre ports) ; journal et pauses remis à zéro."""
    rc.appliquer(ctx, CFG42, "admin")
    rc.confirmer(ctx, "admin")
    faux.journal.clear()
    faux.pauses.clear()
    return ctx


def asservis(faux) -> set[str]:
    return {p for p, m in faux.maitres.items() if m == "br-lan"}


def sans_eth_ni_br_lan(journal) -> None:
    """Les commandes d'une action de port : jamais eth*, jamais br-lan."""
    for argv in journal:
        for a in argv:
            assert not re.search(r"eth[0-9]", a) and "br-lan" not in a, argv


def coupe(racine: Path, port: str) -> Path:
    return racine / COUPE.format(port)


def test_constantes_et_contrat_avec_le_lecteur():
    assert rc.FICHIER_COUPE == "/etc/systemd/network/04-secubox-port-{port}-coupe.network"
    assert (rc.DELAI_PORT, rc.PAUSE_PORT) == (15.0, 1.0)
    noms = [Path(rc.FICHIER_COUPE.format(port=p)).name for p in PORTS_LAN]
    assert reseau_api.ports_coupes(noms) == set(PORTS_LAN)                  # lu par /reseau/ports (tâche 1)
    assert Path(rc.FICHIER_COUPE).parent == reseau_api.RESEAU_D
    # premier trouvé dans l'ordre lexical : le 04 gagne sur le 05 qui met le port au pont
    assert all(n < Path(CHEMINS["ports"]).name for n in noms)


# --- couper ------------------------------------------------------------------------------------------------------------

def test_couper_lan1(actif, racine, faux):
    sortie = rc.port_couper(actif, "lan1", "admin")
    f = coupe(racine, "lan1")
    assert f.read_text() == contenu_coupe("lan1")
    assert f.stat().st_mode & 0o777 == 0o644                                 # lu par systemd-networkd
    assert faux.journal == [RELOAD, reconfigurer("lan1"), lien("lan1"), *LECTURES_ETAT]
    sans_eth_ni_br_lan(faux.journal[:3])                                    # puis l'état rendu, lecture seule
    assert not any(re.search(r"eth[0-9]", a) for argv in faux.journal for a in argv)
    assert "lan1" not in faux.maitres and "lan1" in faux.baisses
    assert asservis(faux) == {"lan0", "lan2", "lan3"}
    assert faux.pauses == []                                                # constaté au premier relevé
    assert sortie["etat"] == "actif" and sortie["ports_coupes"] == ["lan1"]
    a = audits(racine)[-1]
    assert (a["action"], a["acteur"]) == ("port-couper", "admin") and "lan1" in a["detail"]


def test_couper_deux_fois_reste_coupe(actif, racine, faux):
    rc.port_couper(actif, "lan1", "admin")
    faux.journal.clear()
    assert rc.port_couper(actif, "lan1", "admin")["ports_coupes"] == ["lan1"]
    assert coupe(racine, "lan1").read_text() == contenu_coupe("lan1")
    assert faux.journal[:3] == [RELOAD, reconfigurer("lan1"), lien("lan1")]


def test_coupure_non_constatee_fichier_retire_echec(actif, racine, faux):
    faux.coupe_ignoree = True
    with pytest.raises(rc.Echec, match=r"lan1 n'est pas coupé après 15 s .*maître br-lan"):
        rc.port_couper(actif, "lan1", "admin")
    assert not coupe(racine, "lan1").exists()                              # état d'avant : pas de fichier
    assert faux.pauses == [rc.PAUSE_PORT] * 15
    j = faux.journal
    assert j[:3] == [RELOAD, reconfigurer("lan1"), lien("lan1")]
    assert j.count(lien("lan1")) == 16
    assert j[-2:] == [RELOAD, reconfigurer("lan1")]                         # networkd relit l'état remis
    sans_eth_ni_br_lan(j)
    assert faux.maitres["lan1"] == "br-lan"
    a = audits(racine)[-1]
    assert a["action"] == "port-couper-echec" and "remis" in a["detail"]
    assert etat_fichier(racine)["etat"] == "actif"


def test_coupure_partielle_port_encore_up_echec(actif, racine, faux, monkeypatch):
    """Sorti du pont mais pas baissé : ce n'est pas une coupure, même sans câble (état DOWN, drapeau UP)."""
    def hors_du_pont_mais_up(port):
        if faux._coupe(port):
            faux.maitres.pop(port, None)                                    # jamais baissé
        else:
            FauxPorts._asservir(faux, port)

    lien_d_origine = faux._lien

    def sans_cable(port):
        e = lien_d_origine(port)
        if port == "lan1" and "UP" in e["flags"]:
            e["operstate"] = "DOWN"                                         # l'état seul ne suffit pas
        return e

    monkeypatch.setattr(faux, "_asservir", hors_du_pont_mais_up)
    monkeypatch.setattr(faux, "_lien", sans_cable)
    with pytest.raises(rc.Echec, match=r"lan1 n'est pas coupé après 15 s : maître aucun, UP, état DOWN"):
        rc.port_couper(actif, "lan1", "admin")
    assert not coupe(racine, "lan1").exists()
    assert faux.maitres["lan1"] == "br-lan"                                 # remis au pont


def test_networkctl_en_echec_fichier_retire(actif, racine, faux):
    faux.echouer("networkctl", "reconfigure", fois=1)
    with pytest.raises(rc.Echec, match="networkctl reconfigure lan1"):
        rc.port_couper(actif, "lan1", "admin")
    assert not coupe(racine, "lan1").exists()
    assert faux.journal == [RELOAD, reconfigurer("lan1"), RELOAD, reconfigurer("lan1")]
    assert audits(racine)[-1]["action"] == "port-couper-echec"


def test_remise_incomplete_dite(actif, racine, faux):
    faux.coupe_ignoree = True
    faux.echouer("networkctl", "reload", fois=None)
    with pytest.raises(rc.Echec, match="remise INCOMPLÈTE"):
        rc.port_couper(actif, "lan1", "admin")
    assert not coupe(racine, "lan1").exists()
    assert "INCOMPLÈTE" in audits(racine)[-1]["detail"]


# --- rétablir ----------------------------------------------------------------------------------------------------------

def test_retablir_supprime_le_fichier(actif, racine, faux):
    rc.port_couper(actif, "lan1", "admin")
    faux.journal.clear()
    sortie = rc.port_retablir(actif, "lan1", "admin")
    assert not coupe(racine, "lan1").exists()
    assert faux.journal == [RELOAD, reconfigurer("lan1"), lien("lan1"), *LECTURES_ETAT]
    sans_eth_ni_br_lan(faux.journal[:3])
    assert faux.maitres["lan1"] == "br-lan" and "lan1" not in faux.baisses
    assert sortie["ports_coupes"] == []
    a = audits(racine)[-1]
    assert (a["action"], a["acteur"]) == ("port-retablir", "admin") and "lan1" in a["detail"]


def test_retablissement_non_constate_fichier_remis(actif, racine, faux):
    rc.port_couper(actif, "lan1", "admin")
    avant = coupe(racine, "lan1").read_bytes()
    faux.retour_refuse = True
    faux.journal.clear()
    with pytest.raises(rc.Echec, match=r"lan1 n'est pas rétabli après 15 s"):
        rc.port_retablir(actif, "lan1", "admin")
    assert coupe(racine, "lan1").read_bytes() == avant                     # état d'avant : coupé
    assert faux.pauses == [rc.PAUSE_PORT] * 15
    assert faux.journal[-2:] == [RELOAD, reconfigurer("lan1")]
    sans_eth_ni_br_lan(faux.journal)
    assert "lan1" not in faux.maitres and "lan1" in faux.baisses
    assert audits(racine)[-1]["action"] == "port-retablir-echec"


def test_retablir_un_port_non_coupe_le_reprend(actif, racine, faux):
    assert rc.port_retablir(actif, "lan2", "admin")["ports_coupes"] == []
    assert faux.journal[:3] == [RELOAD, reconfigurer("lan2"), lien("lan2")]
    assert not coupe(racine, "lan2").exists()


# --- refus : rien n'est touché -----------------------------------------------------------------------------------------

@pytest.mark.parametrize("verbe", VERBES)
@pytest.mark.parametrize("port", ["eth2", "eth0", "eth1", "lan4", "br-lan", "br-lxc", "", "lan1 ", "LAN1", "lan1\n",
                                  "../lan1", None, ["lan1"]])
def test_port_hors_liste_refuse(actif, racine, faux, verbe, port):
    avant = instantane(racine)
    with pytest.raises(rc.Refus, match="port"):
        getattr(rc, verbe)(actif, port, "admin")
    assert faux.journal == [] and instantane(racine) == avant


def test_couper_en_mode_inactif_refuse(ctx, racine, faux):
    avant = instantane(racine)
    with pytest.raises(rc.Refus, match="mode routeur"):
        rc.port_couper(ctx, "lan1", "admin")
    assert faux.journal == [] and instantane(racine) == avant
    a = audits(racine)[-1]
    assert (a["action"], a["acteur"]) == ("port-couper-refus", "admin")


def test_couper_en_attente_refuse(ctx, racine, faux):
    rc.appliquer(ctx, CFG42, "admin")
    faux.journal.clear()
    avant = instantane(racine)
    with pytest.raises(rc.Refus, match="mode routeur"):
        rc.port_couper(ctx, "lan1", "admin")
    assert faux.journal == [] and instantane(racine) == avant


def test_couper_hors_du_pont_configure_refuse(ctx, racine, faux):
    rc.appliquer(ctx, dict(CFG42, ports=["lan0", "lan3"]), "admin")
    rc.confirmer(ctx, "admin")
    faux.journal.clear()
    avant = instantane(racine)
    with pytest.raises(rc.Refus, match="lan1 n'est pas un port du pont"):
        rc.port_couper(ctx, "lan1", "admin")
    assert faux.journal == [] and instantane(racine) == avant


# --- arbitrage : une coupure survit à tout retour, se rétablit en tout mode ---------------------------------------------

def test_retour_a_inactif_garde_la_coupure(actif, racine, faux):
    rc.port_couper(actif, "lan1", "admin")
    sortie = rc.retour(actif, "admin")
    assert sortie["etat"] == "inactif" and sortie["ports_coupes"] == ["lan1"]
    assert coupe(racine, "lan1").read_text() == contenu_coupe("lan1")
    assert "lan1" in faux.baisses and "lan1" not in faux.maitres


def test_retablir_en_mode_inactif_sans_netplan_leve_le_port(actif, racine, faux):
    """Plus aucun .network ne vise lan1 : networkd le laisse baissé, `ip link set dev lan1 up` le relève."""
    rc.port_couper(actif, "lan1", "admin")
    rc.retour(actif, "admin")
    faux.journal.clear()
    sortie = rc.port_retablir(actif, "lan1", "admin")
    assert sortie["etat"] == "inactif" and sortie["ports_coupes"] == []
    assert not coupe(racine, "lan1").exists()
    assert faux.journal == [RELOAD, reconfigurer("lan1"), lien("lan1"), LEVER, lien("lan1"), *LECTURES_ETAT]
    sans_eth_ni_br_lan(faux.journal[:5])
    assert "lan1" not in faux.baisses
    a = audits(racine)[-1]
    assert a["action"] == "port-retablir" and "hors du pont" in a["detail"] and "ip link set up" in a["detail"]


def test_retablir_en_mode_inactif_avec_netplan(actif, racine, faux):
    """netplan vise encore lan1 (gk2 : lan1 optional) : networkd le relève lui-même, aucune commande de plus."""
    rc.port_couper(actif, "lan1", "admin")
    rc.retour(actif, "admin")
    f = racine / NETPLAN_LAN1
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text("[Match]\nName=lan1\n\n[Network]\nLinkLocalAddressing=ipv6\n")
    faux.journal.clear()
    assert rc.port_retablir(actif, "lan1", "admin")["ports_coupes"] == []
    assert LEVER not in faux.journal
    assert faux.journal[:4] == [RELOAD, reconfigurer("lan1"), lien("lan1"), lien("lan1")]
    assert "lan1" not in faux.baisses


def test_retablir_un_port_retire_du_pont(actif, racine, faux):
    """Coupé puis retiré de la configuration du pont : rétabli vérifié UP, sans br-lan pour maître."""
    rc.port_couper(actif, "lan1", "admin")
    rc.appliquer(actif, dict(CFG42, ports=["lan0", "lan2", "lan3"]), "admin")
    rc.confirmer(actif, "admin")
    faux.journal.clear()
    sortie = rc.port_retablir(actif, "lan1", "admin")
    assert sortie["etat"] == "actif" and sortie["ports_coupes"] == []
    assert LEVER in faux.journal
    assert "lan1" not in faux.baisses and "lan1" not in faux.maitres          # UP, pas au pont
    assert asservis(faux) == {"lan0", "lan2", "lan3"}


def test_retablir_en_attente(actif, racine, faux):
    """Application en attente de confirmation : rétabli vérifié UP (networkd l'a remis au pont par le 05)."""
    rc.port_couper(actif, "lan1", "admin")
    rc.appliquer(actif, dict(CFG42, bail="30m"), "admin")
    faux.journal.clear()
    assert rc.port_retablir(actif, "lan1", "admin")["etat"] == "en_attente"
    assert LEVER not in faux.journal
    assert faux.maitres["lan1"] == "br-lan" and "lan1" not in faux.baisses


def test_retablir_configuration_illisible(actif, racine, faux):
    rc.port_couper(actif, "lan1", "admin")
    (racine / TOML).write_text("[lan\n")
    faux.journal.clear()
    assert rc.port_retablir(actif, "lan1", "admin")["ports_coupes"] == []
    assert faux.journal[:3] == [RELOAD, reconfigurer("lan1"), lien("lan1")]


def test_lever_en_echec_fichier_remis(actif, racine, faux):
    rc.port_couper(actif, "lan1", "admin")
    rc.retour(actif, "admin")
    avant = coupe(racine, "lan1").read_bytes()
    faux.echouer("ip", "link", "set", fois=1)
    faux.journal.clear()
    with pytest.raises(rc.Echec, match="ip link set dev lan1 up"):
        rc.port_retablir(actif, "lan1", "admin")
    assert coupe(racine, "lan1").read_bytes() == avant
    assert faux.journal[-2:] == [RELOAD, reconfigurer("lan1")]
    assert "lan1" in faux.baisses
    assert audits(racine)[-1]["action"] == "port-retablir-echec"


def test_leve_mais_jamais_up_echec(actif, racine, faux):
    rc.port_couper(actif, "lan1", "admin")
    rc.retour(actif, "admin")
    faux.echouer("ip", "link", "set", code=0, fois=1)                       # accepté, sans effet
    faux.journal.clear()
    faux.pauses.clear()
    with pytest.raises(rc.Echec, match=r"lan1 n'est pas rétabli après 15 s : maître aucun, baissé.*attendu : UP"):
        rc.port_retablir(actif, "lan1", "admin")
    assert faux.pauses == [rc.PAUSE_PORT] * 15
    assert coupe(racine, "lan1").is_file()


@pytest.mark.parametrize("verbe", VERBES)
@pytest.mark.parametrize("acteur", ["a b", "", "x" * 65, "admin\n", "../root"])
def test_acteur_invalide(actif, racine, faux, verbe, acteur):
    with pytest.raises(rc.Refus, match="acteur"):
        getattr(rc, verbe)(actif, "lan1", acteur)
    assert faux.journal == []


@pytest.mark.parametrize("verbe", VERBES)
def test_occupe(actif, racine, faux, verbe, verrou_instantane):
    fd = tenir(racine / "run/lock/secubox-netmodes.lock")
    try:
        with pytest.raises(rc.Occupe):
            getattr(rc, verbe)(actif, "lan1", "admin")
    finally:
        os.close(fd)
    assert faux.journal == []


def test_lien_symbolique_refuse(actif, racine, faux, tmp_path):
    cible = tmp_path / "ailleurs.network"
    cible.write_text("[Match]\nName=eth2\n")
    coupe(racine, "lan1").symlink_to(cible)
    with pytest.raises(rc.Refus, match="lien symbolique"):
        rc.port_couper(actif, "lan1", "admin")
    assert faux.journal == [] and cible.read_text() == "[Match]\nName=eth2\n"


def test_signaux_ignores_pendant_l_action(actif, faux):
    vus = []
    faux.sur("networkctl", "reload", fonction=lambda argv: vus.append(signal.getsignal(signal.SIGTERM)))
    rc.port_couper(actif, "lan1", "admin")
    assert vus == [signal.SIG_IGN]
    assert signal.getsignal(signal.SIGTERM) is not signal.SIG_IGN


# --- Review Focus 4 : port coupé puis mode routeur réappliqué ----------------------------------------------------------

def test_reappliquer_avec_un_port_coupe_a_la_main(actif, racine, faux):
    """Sans exclusion des ports coupés, l'attente du pont échouait après 30 s et l'application revenait en arrière."""
    coupe(racine, "lan1").write_text(contenu_coupe("lan1"))
    faux.maitres.pop("lan1")
    faux.baisses.add("lan1")
    sortie = rc.appliquer(actif, dict(CFG42, bail="30m"), "admin")
    assert sortie["etat"] == "en_attente"
    assert "retour" not in [a["action"] for a in audits(racine)]
    assert faux.pauses == [rc.PAUSE_DHCP]                                   # pont prêt sans attendre lan1


def test_reappliquer_avec_un_port_coupe(actif, racine, faux):
    rc.port_couper(actif, "lan1", "admin")
    faux.journal.clear()
    sortie = rc.appliquer(actif, dict(CFG42, bail="30m"), "admin")
    assert sortie["etat"] == "en_attente" and sortie["ports_coupes"] == ["lan1"]
    assert SUPPRIMER not in faux.journal                                    # un port coupé ne fait pas recréer le pont
    assert faux.pauses == [rc.PAUSE_DHCP]
    assert coupe(racine, "lan1").read_text() == contenu_coupe("lan1")       # la coupure survit à l'application
    assert "lan1" in faux.baisses and asservis(faux) == {"lan0", "lan2", "lan3"}
    assert rc.confirmer(actif, "admin")["etat"] == "actif"


def test_tous_les_ports_coupes_application(actif, racine, faux):
    """Aucun port attendu : le pont doit seulement être UP et porter son adresse (sonde de la revue)."""
    for p in PORTS:
        rc.port_couper(actif, p, "admin")
    faux.journal.clear()
    faux.pauses.clear()
    sortie = rc.appliquer(actif, dict(CFG42, bail="30m"), "admin")
    assert sortie["etat"] == "en_attente" and sortie["ports_coupes"] == list(PORTS)
    assert SUPPRIMER not in faux.journal and faux.pauses == [rc.PAUSE_DHCP]
    assert asservis(faux) == set() and faux.baisses == set(PORTS)


def test_nouvelle_adresse_avec_un_port_coupe(actif, racine, faux):
    rc.port_couper(actif, "lan1", "admin")
    faux.journal.clear()
    assert rc.appliquer(actif, CFG50, "admin")["etat"] == "en_attente"
    assert SUPPRIMER in faux.journal                                        # fichiers du pont changés : recréé
    assert "lan1" in faux.baisses and asservis(faux) == {"lan0", "lan2", "lan3"}
    assert faux.adresses["br-lan"] == ["192.168.50.1/24"]


@pytest.mark.parametrize("appel", [lambda ctx: rc.retour(ctx, "admin"), lambda ctx: rc.retour(ctx, "minuteur"),
                                   rc.retour_si_en_attente])
def test_retour_avec_un_port_coupe(actif, racine, faux, appel):
    rc.port_couper(actif, "lan1", "admin")
    rc.appliquer(actif, CFG50, "admin")
    faux.journal.clear()
    faux.pauses.clear()
    sortie = appel(actif)
    assert sortie["etat"] == "actif"
    assert "INCOMPLET" not in audits(racine)[-1]["detail"]
    assert rc.PAUSE_PONT not in faux.pauses                                 # pont prêt sans attendre lan1
    assert faux.adresses["br-lan"] == ["192.168.42.1/24"]
    assert "lan1" in faux.baisses and asservis(faux) == {"lan0", "lan2", "lan3"}
    assert coupe(racine, "lan1").is_file()


def test_retour_sur_pont_inchange_ne_le_recree_pas(actif, racine, faux):
    rc.port_couper(actif, "lan1", "admin")
    rc.appliquer(actif, dict(CFG42, bail="30m"), "admin")
    faux.journal.clear()
    assert rc.retour(actif, "admin")["etat"] == "actif"
    assert SUPPRIMER not in faux.journal


# --- état --------------------------------------------------------------------------------------------------------------

def test_etat_ports_coupes(actif, racine, faux):
    assert rc.etat(actif)["ports_coupes"] == []
    rc.port_couper(actif, "lan3", "admin")
    rc.port_couper(actif, "lan1", "admin")
    for etranger in ("04-secubox-port-eth2-coupe.network", "04-secubox-port-lan4-coupe.network",
                     "04-secubox-port-lan2.network", "05-secubox-port-lan2-coupe.network"):
        (racine / "etc/systemd/network" / etranger).write_text("[Match]\nName=x\n")
    assert rc.ports_coupes(actif) == {"lan1", "lan3"}
    assert rc.etat(actif)["ports_coupes"] == ["lan1", "lan3"]
    rc.port_retablir(actif, "lan3", "admin")
    assert rc.etat(actif)["ports_coupes"] == ["lan1"]
    json.dumps(rc.etat(actif))


def test_etat_inactif_sans_port_coupe(ctx):
    assert rc.etat(ctx)["ports_coupes"] == []


# --- netmodesctl -------------------------------------------------------------------------------------------------------

@pytest.fixture
def cli():
    import importlib.machinery
    import importlib.util
    loader = importlib.machinery.SourceFileLoader("netmodesctl_ports_test", str(SCRIPT))
    spec = importlib.util.spec_from_loader("netmodesctl_ports_test", loader)
    m = importlib.util.module_from_spec(spec)
    loader.exec_module(m)
    return m


def sortie_json(capsys):
    return json.loads(capsys.readouterr().out)


def test_cli_constantes(cli):
    assert cli.AVEC_PORT == ("port-couper", "port-retablir", "port-isoler", "port-rattacher")
    assert cli.PORTS == PORTS_LAN == PORTS


@pytest.mark.parametrize("argv", [["port-couper", "eth2", "admin"], ["port-couper", "eth0", "admin"],
                                  ["port-couper", "lan4", "admin"], ["port-retablir", "br-lan", "admin"],
                                  ["port-couper", "admin", "lan1"], ["port-couper", "lan1"], ["port-retablir"],
                                  ["port-couper", "lan1", "admin", "x"], ["port-couper", "lan1", "a b"],
                                  ["port-retablir", "lan1", "x" * 65], ["port-couper", "lan1 ", "admin"]])
def test_cli_port_refuse_avant_tout(cli, ctx, faux, racine, capsys, argv):
    """Code 2 avant même le contrôle root (le test ne tourne pas en root) : port validé par liste blanche d'abord."""
    avant = instantane(racine)
    assert cli.main(argv, ctx=ctx) == 2
    assert sortie_json(capsys)["erreur"]
    assert faux.journal == [] and instantane(racine) == avant


def test_cli_port_verbes_et_codes(cli, ctx, racine, faux, capsys, monkeypatch, verrou_instantane):
    monkeypatch.setattr(cli, "_est_root", lambda: True)
    assert cli.main(["port-couper", "lan1", "admin"], ctx=ctx) == 3                 # mode routeur inactif
    assert "mode routeur" in sortie_json(capsys)["erreur"]
    rc.appliquer(ctx, CFG42, "admin")
    rc.confirmer(ctx, "admin")
    assert cli.main(["port-couper", "lan1", "admin"], ctx=ctx) == 0
    assert sortie_json(capsys)["ports_coupes"] == ["lan1"]
    fd = tenir(racine / "run/lock/secubox-netmodes.lock")
    try:
        assert cli.main(["port-retablir", "lan1", "admin"], ctx=ctx) == 4
        assert sortie_json(capsys)["erreur"]
    finally:
        os.close(fd)
    faux.retour_refuse = True
    assert cli.main(["port-retablir", "lan1", "admin"], ctx=ctx) == 1
    assert "rétabli" in sortie_json(capsys)["erreur"]
    faux.retour_refuse = False
    assert cli.main(["port-retablir", "lan1", "admin"], ctx=ctx) == 0
    assert sortie_json(capsys)["ports_coupes"] == []


def test_cli_processus_reel_port_refuse():
    r = subprocess.run([sys.executable, str(SCRIPT), "port-couper", "eth2", "admin"],
                       capture_output=True, text=True, timeout=30, check=False)
    assert r.returncode == 2
    assert "port" in json.loads(r.stdout)["erreur"]


def test_cli_usage_cite_les_verbes_de_port(cli, ctx, capsys):
    assert cli.main(["inconnu"], ctx=ctx) == 2
    erreur = sortie_json(capsys)["erreur"]
    assert "port-couper" in erreur and "port-retablir" in erreur
    assert "port-couper <port> <acteur>" in SCRIPT.read_text()


def test_entree_standard_ignoree(cli, ctx, faux, capsys, monkeypatch):
    """Les verbes de port ne lisent rien sur l'entrée standard."""
    monkeypatch.setattr(cli, "_est_root", lambda: True)
    rc.appliquer(ctx, CFG42, "admin")
    rc.confirmer(ctx, "admin")
    entree = io.BytesIO(b"{}")
    assert cli.main(["port-couper", "lan2", "admin"], ctx=ctx, entree=entree) == 0
    assert entree.tell() == 0
