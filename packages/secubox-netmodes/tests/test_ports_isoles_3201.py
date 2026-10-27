# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3201 — isoler un port du switch et le rendre au LAN (contrôleur netmodesctl).

Un port isolé sort du pont par 04-secubox-port-<port>-isole.network (préfixe plus bas que le 05 qui le met au pont) et
porte son /24 de la réserve 192.168.248.0/22, avec le DHCP (fragment de dnsmasq) et le DNS (Unbound, écoute posée
d'avance) de la box, Internet seul (table nft du port). Jamais une commande qui nomme eth* ou br-lan ; le résultat est
relu (`ip -j link show dev <port>`, `ip -j -4 addr show dev <port>`), jamais supposé. Toute erreur, même imprévue, remet
les trois fichiers d'avant, networkd, le pare-feu et le DHCP du LAN (Review Focus 4). Review Focus 1 : un port isolé ne
fait ni échouer, ni recréer le pont d'une réapplication du mode routeur, ni d'un retour."""
import json
import os
import re
import signal
import subprocess
import sys
from pathlib import Path

import pytest

from api import isolement as iso
from api import routeur_ctl as rc
from api.routeur_rendu import CHEMINS
from test_ports_coupes_3190 import (
    LECTURES_ETAT, RELOAD, SUPPRIMER, FauxPorts, asservis, contenu_coupe, coupe, lien, reconfigurer,
)
from test_routeur_ctl_3189 import (
    CFG42, CFG50, LISTE_INPUT, PORTS, SCRIPT, TOML, Horloge, audits, cp, instantane, preparer_racine,
)

DHCP = "secubox-lan-dhcp.service"
DHCP_ACTIF = ["systemctl", "is-active", "--quiet", DHCP]
RELANCER_DHCP = ["systemctl", "restart", DHCP]
TOUTES_ADRESSES = ["ip", "-j", "-4", "addr"]
LEVER = ["ip", "link", "set", "dev", "lan2", "up"]
TABLE = "secubox_netmodes_isole_lan2"
MOTIF_UNBOUND = ("Unbound n'écoute pas encore les passerelles des ports isolés : réappliquer le mode routeur "
                 "(Unbound redémarre, 2 à 4 min sans DNS) puis isoler")
# drop-in d'Unbound d'avant 1.6.0 : n'écoute pas les passerelles des ports isolés
UNBOUND_ANCIEN = "server:\n    ip-freebind: yes\n    interface: 192.168.42.1\n    access-control: 192.168.42.0/24 allow\n"


def fichier(racine: Path, cle: str, port: str = "lan2") -> Path:
    return racine / iso.CHEMINS[cle].format(port=port).lstrip("/")


def adresses_port(port: str) -> list[str]:
    return ["ip", "-j", "-4", "addr", "show", "dev", port]


def regles_isolees(faux, port: str = "lan2") -> list[dict]:
    return [r for r in faux.regles if r.get("comment", "").startswith(f"secubox netmodes isole {port}")]


class FauxIsoles(FauxPorts):
    """networkd et nft simulés, en plus : 04-secubox-port-<port>-isole.network sort le port du pont, le lève et y pose
    sa passerelle (le 04 « coupe » gagne sur lui : ordre lexical) ; retiré, networkd lâche le port, baissé, que seul un
    autre .network (05 du mode routeur) ou `ip link set dev <port> up` relève. Tables nft des ports tenues à part."""

    def __init__(self, racine: Path, **kw):
        super().__init__(racine, **kw)
        self.isoles: set[str] = set()
        self.tables: set[str] = set()

    def _isole(self, port: str) -> bool:
        return fichier(self.racine, "network", port).is_file()

    def _asservir(self, port: str) -> None:
        if self._isole(port) and not self._coupe(port):
            self.maitres.pop(port, None)
            self.baisses.discard(port)
            self.adresses[port] = [str(iso.passerelle(port))]
            self.isoles.add(port)
            return
        if port in self.isoles:                         # fichier retiré : networkd lâche le port, baissé
            self.isoles.discard(port)
            self.adresses.pop(port, None)
            self.baisses.add(port)
        super()._asservir(port)

    def _effet(self, a):
        if a[:4] in (["nft", "list", "table", "inet"], ["nft", "delete", "table", "inet"]) \
                and a[4].startswith("secubox_netmodes_isole_"):
            assert len(a) == 5, a
            present = a[4] in self.tables
            if a[1] == "delete":
                self.tables.discard(a[4])
            return cp(a, 0 if present else 1)
        r = super()._effet(a)
        if a[:2] == ["nft", "-f"] and r.returncode == 0:
            self.tables |= set(re.findall(r"^table inet (secubox_netmodes_isole_lan[0-3]) \{", Path(a[2]).read_text(),
                                          re.M))
        return r


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
    return FauxIsoles(racine)


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


def lecture(argv: list[str]) -> bool:
    """Commande de lecture seule, permise aux gardes."""
    return argv[:2] in (["systemctl", "is-active"], ["ip", "-j"])


def sans_eth_ni_br_lan(journal) -> None:
    """Aucune commande ne nomme eth* ni br-lan ; seules exceptions : `nft -c -f`/`nft -f` d'un fichier généré, et la
    lecture de l'état rendu (`ip -j -4 addr show dev br-lan`)."""
    for argv in journal:
        if argv[:2] == ["nft", "-f"] or argv[:3] == ["nft", "-c", "-f"] or argv == LECTURES_ETAT[-1]:
            continue
        for a in argv:
            assert not re.search(r"eth[0-9]", a) and "br-lan" not in a, argv


# --- isoler ------------------------------------------------------------------------------------------------------------

def test_isoler_ordre_des_commandes(actif, racine, faux):
    nft = str(fichier(racine, "nft"))
    sortie = rc.port_isoler(actif, "lan2", "admin")
    assert faux.journal == [
        DHCP_ACTIF, TOUTES_ADRESSES,                                        # gardes : lectures seules
        ["nft", "-c", "-f", nft],
        RELOAD, reconfigurer("lan2"),                                       # le port seul, jamais br-lan
        LISTE_INPUT, ["nft", "-f", nft],
        RELANCER_DHCP, DHCP_ACTIF, DHCP_ACTIF,
        lien("lan2"), adresses_port("lan2"),                                # relu, pas supposé
        *LECTURES_ETAT]
    rendu = iso.rendre("lan2", "eth2")
    for cle in ("network", "dhcp", "nft"):
        f = fichier(racine, cle)
        assert f.read_text() == rendu[cle], cle
        assert f.stat().st_mode & 0o777 == 0o644, cle
    assert (racine / "var/lib/secubox-netmodes/dhcp.d").stat().st_mode & 0o777 == 0o700   # arbre root seul
    assert faux.pauses == [rc.PAUSE_DHCP]
    assert "lan2" in faux.isoles and "lan2" not in faux.maitres and asservis(faux) == {"lan0", "lan1", "lan3"}
    assert faux.adresses["lan2"] == ["192.168.250.1/24"]
    assert {r["comment"] for r in regles_isolees(faux)} == {
        "secubox netmodes isole lan2 dhcp", "secubox netmodes isole lan2 dns", "secubox netmodes isole lan2 dns-tcp"}
    assert faux.tables == {TABLE}
    assert sortie["etat"] == "actif" and sortie["ports_isoles"] == ["lan2"] and sortie["ports_coupes"] == []
    a = audits(racine)[-1]
    assert (a["action"], a["acteur"]) == ("port-isoler", "admin")
    assert "lan2" in a["detail"] and "192.168.250.0/24" in a["detail"]


def test_isoler_deux_ports(actif, racine, faux):
    rc.port_isoler(actif, "lan2", "admin")
    sortie = rc.port_isoler(actif, "lan0", "admin")
    assert sortie["ports_isoles"] == ["lan0", "lan2"]
    assert faux.adresses["lan0"] == ["192.168.248.1/24"] and faux.tables == {TABLE, "secubox_netmodes_isole_lan0"}
    assert len(regles_isolees(faux, "lan2")) == 3 and len(regles_isolees(faux, "lan0")) == 3


def _en_attente(ctx, racine, faux):
    rc.appliquer(ctx, dict(CFG42, bail="30m"), "admin")


def _hors_du_pont(ctx, racine, faux):
    rc.appliquer(ctx, dict(CFG42, ports=["lan0", "lan1", "lan3"]), "admin")
    rc.confirmer(ctx, "admin")


def _toml_illisible(ctx, racine, faux):
    (racine / TOML).write_text("[lan\n")


def _coupe(ctx, racine, faux):
    rc.port_couper(ctx, "lan2", "admin")


def _deja_isole(ctx, racine, faux):
    rc.port_isoler(ctx, "lan2", "admin")


def _dhcp_arrete(ctx, racine, faux):
    faux.actifs.discard(DHCP)


def _sans_inclusion_nft(ctx, racine, faux):
    (racine / "etc/nftables.conf").write_text("#!/usr/sbin/nft -f\nflush ruleset\n")


def _unbound_ancien(ctx, racine, faux):
    (racine / CHEMINS["unbound"].lstrip("/")).write_text(UNBOUND_ANCIEN)


def _reseau_porte_par_eth2(ctx, racine, faux):
    faux.adresses["eth2"] = ["192.168.250.20/24"]


@pytest.mark.parametrize("preparer, motif", [
    (_en_attente, "le mode routeur est « en_attente »"),
    (_hors_du_pont, "lan2 n'est pas un port du pont"),
    (_toml_illisible, "configuration du mode routeur illisible"),
    (_coupe, "lan2 est coupé"),
    (_deja_isole, "lan2 est déjà isolé"),
    (_dhcp_arrete, "secubox-lan-dhcp.service n'est pas actif"),
    (_sans_inclusion_nft, "n'inclut pas /etc/nftables.d"),
    (_unbound_ancien, "Unbound n'écoute pas encore"),
    (_reseau_porte_par_eth2, r"192\.168\.250\.0/24 .*eth2"),
], ids=["en-attente", "hors-du-pont", "toml-illisible", "coupe", "deja-isole", "dhcp-arrete", "sans-inclusion-nft",
        "unbound-ancien", "reseau-porte-par-eth2"])
def test_isoler_refus_sans_commande(actif, racine, faux, preparer, motif):
    preparer(actif, racine, faux)
    faux.journal.clear()
    avant = instantane(racine)
    with pytest.raises(rc.Refus, match=motif):
        rc.port_isoler(actif, "lan2", "admin")
    assert all(lecture(a) for a in faux.journal), faux.journal               # ni networkctl, ni nft, ni restart
    assert instantane(racine) == avant                                      # aucun fichier posé
    a = audits(racine)[-1]
    assert (a["action"], a["acteur"]) == ("port-isoler-refus", "admin") and re.search(motif, a["detail"])


@pytest.mark.parametrize("drop_in", [UNBOUND_ANCIEN, None])
def test_isoler_unbound_ancien_message(actif, racine, faux, drop_in):
    """Review Focus 3 : isolement demandé juste après l'installation de 1.6.0, avant toute réapplication."""
    f = racine / CHEMINS["unbound"].lstrip("/")
    if drop_in is None:
        f.unlink()
    else:
        f.write_text(drop_in)
    with pytest.raises(rc.Refus) as e:
        rc.port_isoler(actif, "lan2", "admin")
    assert str(e.value) == MOTIF_UNBOUND
    assert "réappliquer le mode routeur" in str(e.value)
    assert not any(fichier(racine, cle).exists() for cle in iso.CHEMINS)


@pytest.mark.parametrize("verbe", ["port_isoler", "port_rattacher"])
@pytest.mark.parametrize("port", ["eth2", "eth0", "br-lan", "lan4", "", "lan2 ", None])
def test_port_hors_liste_refuse(actif, racine, faux, verbe, port):
    avant = instantane(racine)
    with pytest.raises(rc.Refus, match="port refusé"):
        getattr(rc, verbe)(actif, port, "admin")
    assert faux.journal == [] and instantane(racine) == avant


def test_isoler_dhcp_ko_remet_tout(actif, racine, faux):
    """Review Focus 4 : dnsmasq ne repart pas après l'isolement (`is-active` toujours en échec après la relance)."""
    faux.sur("systemctl", "restart", DHCP,
             fonction=lambda argv: faux.echouer("systemctl", "is-active", "--quiet", DHCP, code=3))
    with pytest.raises(rc.Echec, match="n'est pas resté actif") as e:
        rc.port_isoler(actif, "lan2", "admin")
    assert not any(fichier(racine, cle).exists() for cle in iso.CHEMINS)  # fichiers d'avant : absents
    assert regles_isolees(faux) == [] and faux.tables == set()             # règles et table supprimées
    j = faux.journal
    premiere = j.index(RELANCER_DHCP)
    remise = j[premiere + 1:]
    assert reconfigurer("lan2") in remise                                   # networkd relit l'état remis
    assert ["nft", "list", "table", "inet", TABLE] in remise and ["nft", "delete", "table", "inet", TABLE] in remise
    assert remise.index(RELANCER_DHCP) > remise.index(reconfigurer("lan2"))  # DHCP du LAN relancé après la remise
    sans_eth_ni_br_lan(j)
    assert faux.maitres["lan2"] == "br-lan" and "lan2" not in faux.adresses  # rendu au pont
    assert "remise INCOMPLÈTE" in str(e.value) and "DHCP" in str(e.value)   # le DHCP du LAN reste en panne : dit
    a = audits(racine)[-1]
    assert a["action"] == "port-isoler-echec" and "INCOMPLÈTE" in a["detail"]


def test_isoler_dhcp_ko_puis_repart_sur_l_etat_d_avant(actif, racine, faux):
    """Fragment refusé par dnsmasq : remis sans le fragment, le DHCP du LAN repart ; la remise est complète."""
    relances = []

    def relance(argv):
        relances.append(argv)
        if len(relances) == 1:
            faux.echouer("systemctl", "is-active", "--quiet", DHCP, code=3)
        else:
            faux.echecs.pop(("systemctl", "is-active", "--quiet", DHCP))

    faux.sur("systemctl", "restart", DHCP, fonction=relance)
    with pytest.raises(rc.Echec, match="n'est pas resté actif") as e:
        rc.port_isoler(actif, "lan2", "admin")
    assert len(relances) == 2 and "INCOMPLÈTE" not in str(e.value) and "remis" in str(e.value)
    assert faux.journal[-2:] == [DHCP_ACTIF, DHCP_ACTIF]                   # relu actif après la remise
    assert not any(fichier(racine, cle).exists() for cle in iso.CHEMINS)
    assert audits(racine)[-1]["action"] == "port-isoler-echec"


def test_isoler_exception_imprevue_remet_tout(actif, racine, faux):
    appels = []

    def panne(argv):
        appels.append(argv)
        if len(appels) == 1:
            raise RuntimeError("networkd simulé en panne")

    faux.sur("networkctl", "reconfigure", fonction=panne)
    with pytest.raises(RuntimeError, match="networkd simulé en panne"):
        rc.port_isoler(actif, "lan2", "admin")
    assert not any(fichier(racine, cle).exists() for cle in iso.CHEMINS)
    assert appels == [reconfigurer("lan2")] * 2                             # rejoué par la remise
    j = faux.journal
    assert j[j.index(reconfigurer("lan2")) + 1:] == [
        RELOAD, reconfigurer("lan2"), LISTE_INPUT, ["nft", "list", "table", "inet", TABLE],
        RELANCER_DHCP, DHCP_ACTIF, DHCP_ACTIF]
    assert regles_isolees(faux) == [] and faux.tables == set()
    assert faux.maitres["lan2"] == "br-lan" and "lan2" not in faux.adresses
    a = audits(racine)[-1]
    assert a["action"] == "port-isoler-echec" and "RuntimeError" in a["detail"]


def test_isoler_non_constate_remet_tout(actif, racine, faux, monkeypatch):
    """networkd n'applique pas le fichier : le port reste au pont, la passerelle n'est jamais vue."""
    monkeypatch.setattr(faux, "_isole", lambda port: False)
    with pytest.raises(rc.Echec, match=r"lan2 n'est pas isolé après 15 s : maître br-lan.*192\.168\.250\.1/24 absente"):
        rc.port_isoler(actif, "lan2", "admin")
    assert faux.pauses == [rc.PAUSE_DHCP] + [rc.PAUSE_PORT] * 15 + [rc.PAUSE_DHCP]   # DHCP, port, DHCP remis relu
    assert faux.journal.count(adresses_port("lan2")) == 16
    assert not any(fichier(racine, cle).exists() for cle in iso.CHEMINS)
    assert regles_isolees(faux) == [] and faux.tables == set()


def test_isoler_restes_d_avant_remis(actif, racine, faux):
    """Un fragment DHCP et un .nft d'un essai précédent (sans .network) : remis tels quels, le .nft rechargé."""
    reste_dhcp, reste_nft = "# reste dhcp\n", f"table inet {TABLE}\ndelete table inet {TABLE}\n"
    fichier(racine, "dhcp").parent.mkdir(mode=0o700)
    fichier(racine, "dhcp").write_text(reste_dhcp)
    fichier(racine, "nft").parent.mkdir(exist_ok=True)
    fichier(racine, "nft").write_text(reste_nft)
    faux.echouer("nft", "-c", "-f", fois=1)
    with pytest.raises(rc.Echec, match="nft -c -f"):
        rc.port_isoler(actif, "lan2", "admin")
    assert fichier(racine, "dhcp").read_text() == reste_dhcp and fichier(racine, "nft").read_text() == reste_nft
    assert not fichier(racine, "network").exists()
    assert ["nft", "-f", str(fichier(racine, "nft"))] in faux.journal      # .nft d'avant remis, rechargé


def test_signaux_ignores_pendant_l_isolement(actif, faux):
    vus = []
    faux.sur("networkctl", "reload", fonction=lambda argv: vus.append(signal.getsignal(signal.SIGTERM)))
    rc.port_isoler(actif, "lan2", "admin")
    assert vus == [signal.SIG_IGN]
    assert signal.getsignal(signal.SIGTERM) is not signal.SIG_IGN


# --- rendre au LAN (rattacher) -----------------------------------------------------------------------------------------

def test_rattacher_ordre_et_au_pont(actif, racine, faux):
    rc.port_isoler(actif, "lan2", "admin")
    handles = [r["handle"] for r in regles_isolees(faux)]
    faux.journal.clear()
    faux.pauses.clear()
    sortie = rc.port_rattacher(actif, "lan2", "admin")
    assert faux.journal == [
        RELOAD, reconfigurer("lan2"),
        LISTE_INPUT, *[["nft", "delete", "rule", "inet", "filter", "input", "handle", str(h)] for h in handles],
        ["nft", "list", "table", "inet", TABLE], ["nft", "delete", "table", "inet", TABLE],
        DHCP_ACTIF, RELANCER_DHCP, DHCP_ACTIF, DHCP_ACTIF,
        lien("lan2"),
        *LECTURES_ETAT]
    assert not any(fichier(racine, cle).exists() for cle in iso.CHEMINS)
    assert fichier(racine, "dhcp").parent.is_dir()                          # dossier des fragments gardé
    assert faux.maitres["lan2"] == "br-lan" and "lan2" not in faux.adresses
    assert regles_isolees(faux) == [] and faux.tables == set()
    assert sortie["ports_isoles"] == [] and sortie["etat"] == "actif"
    a = audits(racine)[-1]
    assert (a["action"], a["acteur"]) == ("port-rattacher", "admin") and "lan2" in a["detail"]


def test_rattacher_hors_mode_routeur_leve(actif, racine, faux):
    """L'isolement survit au retour vers « inactif » ; rendu au LAN, plus aucun .network ne vise lan2 : networkd le
    laisse baissé, `ip link set dev lan2 up` le relève. DHCP arrêté : pas relancé."""
    rc.port_isoler(actif, "lan2", "admin")
    assert rc.retour(actif, "admin")["ports_isoles"] == ["lan2"]
    assert fichier(racine, "network").is_file()
    faux.journal.clear()
    sortie = rc.port_rattacher(actif, "lan2", "admin")
    assert sortie["etat"] == "inactif" and sortie["ports_isoles"] == []
    j = faux.journal
    assert RELANCER_DHCP not in j and j.count(DHCP_ACTIF) == 2              # relevé, pas relancé (et l'état rendu)
    assert j[j.index(DHCP_ACTIF) + 1:j.index(DHCP_ACTIF) + 4] == [lien("lan2"), LEVER, lien("lan2")]
    assert "lan2" not in faux.baisses and "lan2" not in faux.maitres
    a = audits(racine)[-1]
    assert a["action"] == "port-rattacher" and "ip link set up" in a["detail"]


def test_rattacher_un_reste_d_isolement(actif, racine, faux):
    """Un .nft resté seul (sans .network) : le port n'est pas « isolé », mais rendre au LAN nettoie le reste."""
    fichier(racine, "nft").write_text(iso.rendre("lan2", "eth2")["nft"])
    assert rc.ports_isoles(actif) == set()
    assert rc.port_rattacher(actif, "lan2", "admin")["ports_isoles"] == []
    assert not fichier(racine, "nft").exists()


def test_rattacher_refus_non_isole(actif, racine, faux):
    avant = instantane(racine)
    with pytest.raises(rc.Refus, match="lan2 n'est pas isolé"):
        rc.port_rattacher(actif, "lan2", "admin")
    assert faux.journal == [] and instantane(racine) == avant
    a = audits(racine)[-1]
    assert (a["action"], a["acteur"]) == ("port-rattacher-refus", "admin")


def test_rattacher_refus_coupe_et_isole(actif, racine, faux):
    """État fait main (couper refuse un port isolé, isoler un port coupé) : rien n'est deviné."""
    coupe(racine, "lan2").write_text(contenu_coupe("lan2"))
    fichier(racine, "network").write_text(iso.rendre("lan2", "eth2")["network"])
    avant = instantane(racine)
    with pytest.raises(rc.Refus) as e:
        rc.port_rattacher(actif, "lan2", "admin")
    assert "04-secubox-port-lan2-coupe.network" in str(e.value) and "04-secubox-port-lan2-isole.network" in str(e.value)
    assert faux.journal == [] and instantane(racine) == avant
    assert audits(racine)[-1]["action"] == "port-rattacher-refus"


def test_rattacher_echec_remet_l_isolement(actif, racine, faux):
    rc.port_isoler(actif, "lan2", "admin")
    avant = {cle: fichier(racine, cle).read_bytes() for cle in iso.CHEMINS}
    faux.retour_refuse = True                                               # networkd ne reprend pas le port
    faux.journal.clear()
    with pytest.raises(rc.Echec, match=r"lan2 n'est pas rendu au LAN après 15 s"):
        rc.port_rattacher(actif, "lan2", "admin")
    assert {cle: fichier(racine, cle).read_bytes() for cle in iso.CHEMINS} == avant
    assert fichier(racine, "dhcp").stat().st_mode & 0o777 == 0o644
    j = faux.journal
    k = len(j) - 1 - j[::-1].index(reconfigurer("lan2"))                    # la remise
    assert j[k - 1:] == [RELOAD, reconfigurer("lan2"), LISTE_INPUT, ["nft", "list", "table", "inet", TABLE],
                         ["nft", "-f", str(fichier(racine, "nft"))], RELANCER_DHCP, DHCP_ACTIF, DHCP_ACTIF]
    assert "lan2" in faux.isoles and faux.tables == {TABLE} and len(regles_isolees(faux)) == 3
    assert audits(racine)[-1]["action"] == "port-rattacher-echec"


# --- gardes croisées ---------------------------------------------------------------------------------------------------

def test_couper_et_retablir_refusent_un_port_isole(actif, racine, faux):
    rc.port_isoler(actif, "lan2", "admin")
    faux.journal.clear()
    avant = instantane(racine)
    with pytest.raises(rc.Refus, match="lan2 est isolé : le rendre au LAN d'abord"):
        rc.port_couper(actif, "lan2", "admin")
    assert audits(racine)[-1]["action"] == "port-couper-refus"
    with pytest.raises(rc.Refus, match="lan2 est isolé, pas coupé : « Rendre au LAN » le rattache au pont"):
        rc.port_retablir(actif, "lan2", "admin")
    assert audits(racine)[-1]["action"] == "port-retablir-refus"
    assert faux.journal == [] and instantane(racine) == avant


def test_retablir_refuse_un_port_coupe_et_isole(actif, racine, faux):
    coupe(racine, "lan2").write_text(contenu_coupe("lan2"))
    fichier(racine, "network").write_text(iso.rendre("lan2", "eth2")["network"])
    with pytest.raises(rc.Refus, match="lan2 est isolé, pas coupé"):
        rc.port_retablir(actif, "lan2", "admin")
    assert faux.journal == [] and coupe(racine, "lan2").is_file()


# --- Review Focus 1 : port isolé puis mode routeur réappliqué ou retour ------------------------------------------------

def test_reappliquer_ignore_un_port_isole(actif, racine, faux):
    rc.port_isoler(actif, "lan2", "admin")
    assert "lan2" not in faux.maitres
    assert rc._ports_non_asservis(actif, ("lan0", "lan1", "lan2", "lan3")) == []
    assert rc._pont_a_recreer(actif, False, PORTS) is False
    faux.journal.clear()
    faux.pauses.clear()
    sortie = rc.appliquer(actif, dict(CFG42, bail="30m"), "admin")
    assert sortie["etat"] == "en_attente" and sortie["ports_isoles"] == ["lan2"]
    assert SUPPRIMER not in faux.journal and faux.pauses == [rc.PAUSE_DHCP]  # pont prêt sans attendre lan2
    assert "lan2" in faux.isoles and asservis(faux) == {"lan0", "lan1", "lan3"}
    assert rc.confirmer(actif, "admin")["etat"] == "actif"


def test_retour_avec_un_port_isole(actif, racine, faux):
    rc.port_isoler(actif, "lan2", "admin")
    rc.appliquer(actif, CFG50, "admin")
    faux.pauses.clear()
    assert rc.retour(actif, "admin")["etat"] == "actif"
    assert "INCOMPLET" not in audits(racine)[-1]["detail"]
    assert rc.PAUSE_PONT not in faux.pauses
    assert "lan2" in faux.isoles and fichier(racine, "network").is_file()
    assert len(regles_isolees(faux)) == 3 and faux.tables == {TABLE}        # le retour ne touche pas au port isolé


# --- état --------------------------------------------------------------------------------------------------------------

def test_etat_ports_isoles(actif, racine, faux):
    assert rc.etat(actif)["ports_isoles"] == []
    rc.port_isoler(actif, "lan3", "admin")
    rc.port_isoler(actif, "lan1", "admin")
    for etranger in ("04-secubox-port-eth2-isole.network", "04-secubox-port-lan4-isole.network",
                     "04-secubox-port-lan2.network", "05-secubox-port-lan2-isole.network"):
        (racine / "etc/systemd/network" / etranger).write_text("[Match]\nName=x\n")
    assert rc.ports_isoles(actif) == {"lan1", "lan3"}
    assert rc.etat(actif)["ports_isoles"] == ["lan1", "lan3"]
    rc.port_rattacher(actif, "lan3", "admin")
    assert rc.etat(actif)["ports_isoles"] == ["lan1"]
    json.dumps(rc.etat(actif))


def test_etat_inactif_sans_port_isole(ctx):
    assert rc.etat(ctx)["ports_isoles"] == []


# --- jamais eth*, jamais br-lan ----------------------------------------------------------------------------------------

def test_aucune_commande_ne_nomme_eth_ni_br_lan(actif, racine, faux):
    journaux = []

    def action(appel):
        faux.journal.clear()
        try:
            appel()
        except (rc.Echec, RuntimeError):
            pass
        journaux.append(list(faux.journal))

    action(lambda: rc.port_isoler(actif, "lan2", "admin"))
    action(lambda: rc.port_rattacher(actif, "lan2", "admin"))
    faux.sur("systemctl", "restart", DHCP,
             fonction=lambda argv: faux.echouer("systemctl", "is-active", "--quiet", DHCP, code=3, fois=6))
    action(lambda: rc.port_isoler(actif, "lan2", "admin"))                  # échec, remise
    faux.crochets.clear()
    action(lambda: rc.port_isoler(actif, "lan2", "admin"))
    rc.retour(actif, "admin")
    action(lambda: rc.port_rattacher(actif, "lan2", "admin"))               # hors mode routeur : levé
    assert LEVER in journaux[-1]
    for journal in journaux:
        assert journal
        sans_eth_ni_br_lan(journal)


# --- netmodesctl -------------------------------------------------------------------------------------------------------

@pytest.fixture
def cli():
    import importlib.machinery
    import importlib.util
    loader = importlib.machinery.SourceFileLoader("netmodesctl_isoles_test", str(SCRIPT))
    spec = importlib.util.spec_from_loader("netmodesctl_isoles_test", loader)
    m = importlib.util.module_from_spec(spec)
    loader.exec_module(m)
    return m


def sortie_json(capsys):
    return json.loads(capsys.readouterr().out)


def test_cli_verbes(cli, actif, racine, faux, capsys, monkeypatch):
    assert cli.AVEC_PORT == ("port-couper", "port-retablir", "port-isoler", "port-rattacher")
    monkeypatch.setattr(cli, "_est_root", lambda: True)
    assert cli.main(["port-isoler", "lan2", "admin"], ctx=actif) == 0
    assert sortie_json(capsys)["ports_isoles"] == ["lan2"]
    assert cli.main(["port-isoler", "lan2", "admin"], ctx=actif) == 3                # déjà isolé : refus
    assert "déjà isolé" in sortie_json(capsys)["erreur"]
    faux.retour_refuse = True
    assert cli.main(["port-rattacher", "lan2", "admin"], ctx=actif) == 1             # échec, remis
    assert "rendu au LAN" in sortie_json(capsys)["erreur"]
    faux.retour_refuse = False
    assert cli.main(["port-rattacher", "lan2", "admin"], ctx=actif) == 0
    assert sortie_json(capsys)["ports_isoles"] == []
    assert cli.main(["port-rattacher", "lan2", "admin"], ctx=actif) == 3             # n'est plus isolé
    assert sortie_json(capsys)["erreur"] == "lan2 n'est pas isolé"
    assert cli.main(["inconnu"], ctx=actif) == 2
    assert "{port-couper|port-retablir|port-isoler|port-rattacher} <port> <acteur>" in sortie_json(capsys)["erreur"]
    texte = SCRIPT.read_text()
    assert "port-isoler <port> <acteur>" in texte and "port-rattacher <port> <acteur>" in texte


@pytest.mark.parametrize("argv", [["port-isoler", "eth2", "admin"], ["port-isoler", "br-lan", "admin"],
                                  ["port-rattacher", "eth0", "admin"], ["port-isoler", "lan4", "admin"],
                                  ["port-isoler", "lan2"], ["port-rattacher", "lan2", "a b"],
                                  ["port-isoler", "lan2", "admin", "x"]])
def test_cli_port_refuse_sans_controleur(cli, ctx, faux, racine, capsys, monkeypatch, argv):
    """Code 2 avant même le contrôle root, sans importer le contrôleur : port validé par liste blanche d'abord."""
    monkeypatch.setattr(cli, "_controleur", lambda: pytest.fail("contrôleur importé"))
    avant = instantane(racine)
    assert cli.main(argv, ctx=ctx) == 2
    assert sortie_json(capsys)["erreur"]
    assert faux.journal == [] and instantane(racine) == avant


def test_cli_processus_reel_port_isoler_eth2():
    r = subprocess.run([sys.executable, str(SCRIPT), "port-isoler", "eth2", "admin"],
                       capture_output=True, text=True, timeout=30, check=False)
    assert r.returncode == 2
    assert "port refusé" in json.loads(r.stdout)["erreur"]
