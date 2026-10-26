# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3189 — pont br-lan de gk2 (2026-10-26) : après `networkctl reload` (qui crée le netdev), `networkctl reconfigure
br-lan lan0..lan3` a fait journaliser à networkd « br-lan: Failed to create netdev: File exists » ; son netdev est passé
en échec, lan0/lan3 sont restés « configuring » sans jamais être asservis (pont DOWN, LAN mort), et le contrôleur a
déclaré la bascule réussie. Idem sur un pont fait main : networkd n'asservit qu'à un netdev qu'il a créé.

Désormais : jamais `reconfigure br-lan` ; br-lan (et lui seul) supprimé avant `reload` quand les fichiers du pont
changent ; le résultat est relu (ports asservis, adresse, pont UP) au lieu de croire les codes de retour."""
import os
import re

import pytest

from api import routeur_ctl as rc
from test_routeur_ctl_3189 import (
    ANCIEN_PONT, CFG42, CFG50, PORTS, Faux, Horloge, audits, etat_fichier, preparer_racine,
)


@pytest.fixture(autouse=True)
def umask_022():
    ancien = os.umask(0o022)                        # contrôles de droits de l'arbre root seul (voir test_routeur_ctl)
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
    return rc.Contexte(racine=racine, executer=faux, maintenant=Horloge(), attendre=faux.attendre,
                       monotone=faux.monotone)


@pytest.fixture
def neuf(tmp_path):
    r = preparer_racine(tmp_path / "neuve", gk2=False)
    f = Faux(r, pont_existant=False)
    f.actifs.discard("sbx-lan-dhcp.service")
    f.regles = [r_ for r_ in f.regles if not r_.get("comment", "").startswith("sbx-lan")]
    return r, f, rc.Contexte(racine=r, executer=f, maintenant=Horloge(), attendre=f.attendre, monotone=f.monotone)


SUPPRIMER = ["ip", "link", "delete", "br-lan"]
RELOAD = ["networkctl", "reload"]
RECONFIGURER_PORTS = ["networkctl", "reconfigure", *PORTS]
ASSERVIS = ["ip", "-j", "link", "show", "master", "br-lan"]
P = 2.0                                             # relevé du pont toutes les 2 s, 30 s au plus


def asservis(faux) -> set[str]:
    return {p for p, m in faux.maitres.items() if m == "br-lan"}


def sans_eth(journal) -> None:
    for argv in journal:
        if (argv[:3] == ["nft", "-c", "-f"] and len(argv) == 4) or (argv[:2] == ["nft", "-f"] and len(argv) == 3):
            continue                                # seule exception : le fichier généré nomme le WAN
        for a in argv:
            assert not re.search(r"eth[0-9]", a), argv


def jamais_reconfigure_br_lan(journal) -> None:
    assert not any(a[:2] == ["networkctl", "reconfigure"] and "br-lan" in a for a in journal)


def test_constantes():
    assert (rc.PAUSE_PONT, rc.DELAI_PONT) == (P, 30)


# --- appliquer ---------------------------------------------------------------------------------------------------------

def test_pont_fait_main_supprime_avant_reload(ctx, racine, faux):
    """Rejeu de gk2 : br-lan fait main (LAN temporaire), ports asservis à la main. Supprimé AVANT reload : networkd crée
    son propre pont et y asservit les ports ; sans cela, « File exists » et LAN mort."""
    sortie = rc.appliquer(ctx, CFG42, "admin")
    assert sortie["etat"] == "en_attente"
    j = faux.journal
    assert j.index(SUPPRIMER) < j.index(RELOAD) < j.index(RECONFIGURER_PORTS) < j.index(ASSERVIS)
    assert j.count(SUPPRIMER) == 1
    assert not faux.netdev_en_echec and faux.pont_networkd
    assert asservis(faux) == set(PORTS)
    assert faux.adresses["br-lan"] == ["192.168.42.1/24"]
    assert faux.pauses == [rc.PAUSE_DHCP]                                       # pont prêt au premier relevé
    jamais_reconfigure_br_lan(j)
    sans_eth(j)


def test_carte_neuve_pont_cree_par_networkd(neuf):
    r, f, ctx = neuf
    rc.appliquer(ctx, CFG42, "admin")
    assert SUPPRIMER not in f.journal                                           # rien à supprimer
    assert ["ip", "link", "show", "dev", "br-lan"] in f.journal
    assert f.pont_networkd and asservis(f) == set(PORTS)
    assert f.adresses["br-lan"] == ["192.168.42.1/24"]


def test_fichiers_du_pont_inchanges_pas_de_suppression(ctx, racine, faux):
    """Seul le bail change : le pont de networkd est gardé (aucune coupure du LAN), le résultat est quand même relu."""
    rc.appliquer(ctx, CFG42, "admin")
    rc.confirmer(ctx, "admin")
    faux.journal.clear()
    rc.appliquer(ctx, dict(CFG42, bail="30m"), "admin")
    j = faux.journal
    assert SUPPRIMER not in j
    # revue I1 : le pont est d'abord relu (ses ports ont-ils br-lan pour maître ?), avant reload
    assert j.index(["ip", "link", "show", "dev", "br-lan"]) < j.index(ASSERVIS) < j.index(RELOAD)
    assert RECONFIGURER_PORTS in j
    jamais_reconfigure_br_lan(j)


# --- revue I1 : un br-lan que networkd n'a pas (ou plus) en main, fichiers du pont inchangés -------------------------

def _netdev_en_echec_sous_un_pont_confirme(ctx, faux):
    """Rejeu de la revue : pont confirmé, puis netdev de networkd en échec, ports sans maître (LAN mort)."""
    rc.appliquer(ctx, CFG42, "admin")
    rc.confirmer(ctx, "admin")
    faux.netdev_en_echec = True
    faux.maitres.clear()
    faux.journal.clear()
    faux.pauses.clear()


def test_pont_sans_ports_asservis_fichiers_inchanges_recree(ctx, racine, faux):
    """Réapplication du seul bail sur un netdev en échec : sans cela, pas de suppression, échec après 30 s, retour vers
    des fichiers identiques déclaré réussi avec un LAN toujours mort, et toute application suivante échouait pareil."""
    _netdev_en_echec_sous_un_pont_confirme(ctx, faux)
    sortie = rc.appliquer(ctx, dict(CFG42, bail="30m"), "admin")
    assert sortie["etat"] == "en_attente"
    j = faux.journal
    assert j.index(ASSERVIS) < j.index(SUPPRIMER) < j.index(RELOAD)
    assert not faux.netdev_en_echec and asservis(faux) == set(PORTS)
    assert faux.pauses == [rc.PAUSE_DHCP]                                       # pont prêt sans attendre 30 s
    assert "retour" not in [a["action"] for a in audits(racine)]
    jamais_reconfigure_br_lan(j)
    sans_eth(j)


def test_retour_pont_sans_ports_asservis_fichiers_inchanges_recree(ctx, racine, faux):
    """Même règle au retour : un .netdev reste, les fichiers du pont ne changent pas, mais ses ports n'ont pas br-lan
    pour maître (configuration restaurée relue) : supprimé, recréé par networkd."""
    rc.appliquer(ctx, CFG42, "admin")
    rc.confirmer(ctx, "admin")
    rc.appliquer(ctx, dict(CFG42, bail="30m"), "admin")
    faux.netdev_en_echec = True
    faux.maitres.clear()
    faux.journal.clear()
    sortie = rc.retour(ctx, "admin")
    assert sortie["etat"] == "actif"
    j = faux.journal
    assert j.index(SUPPRIMER) < j.index(RELOAD)
    assert asservis(faux) == set(PORTS)
    assert "INCOMPLET" not in audits(racine)[-1]["detail"]


# --- revue : br-lan doit être UP (sonde de la revue) -----------------------------------------------------------------

@pytest.mark.parametrize("drapeaux, reussit", [
    (["NO-CARRIER", "BROADCAST", "MULTICAST", "UP"], True),                     # aucun poste : UP, sans porteuse
    (["BROADCAST", "MULTICAST"], False),                                        # pont DOWN, adresse et ports présents
])
def test_pont_up(ctx, racine, faux, drapeaux, reussit):
    faux.porteuse = set()
    entree = faux._entree

    def drapeaux_du_pont(nom):
        e = entree(nom)
        if nom == "br-lan":
            e["flags"] = drapeaux
        return e

    faux._entree = drapeaux_du_pont
    if reussit:
        assert rc.appliquer(ctx, CFG42, "admin")["etat"] == "en_attente"
    else:
        with pytest.raises(rc.Echec, match="br-lan n'est pas UP"):
            rc.appliquer(ctx, CFG42, "admin")


def test_nouvelle_adresse_pont_recree(ctx, racine, faux):
    rc.appliquer(ctx, CFG42, "admin")
    rc.confirmer(ctx, "admin")
    faux.journal.clear()
    rc.appliquer(ctx, CFG50, "admin")
    j = faux.journal
    assert j.index(SUPPRIMER) < j.index(RELOAD)
    assert faux.adresses["br-lan"] == ["192.168.50.1/24"] and asservis(faux) == set(PORTS)


def test_ports_sans_porteuse_mais_asservis_succes(ctx, racine, faux):
    faux.porteuse = set()                                                       # aucun poste branché
    sortie = rc.appliquer(ctx, CFG42, "admin")
    assert sortie["etat"] == "en_attente"
    assert faux.pauses == [rc.PAUSE_DHCP]
    assert "retour" not in [a["action"] for a in audits(racine)]


def test_asservissement_en_retard_accepte(ctx, racine, faux):
    faux.asservir = False
    releves = []

    def networkd_finit_par_asservir(argv):
        releves.append(argv)
        if len(releves) == 4:
            faux.asservir = True
            for p in PORTS:
                faux._asservir(p)

    faux.sur(*ASSERVIS, fonction=networkd_finit_par_asservir)
    sortie = rc.appliquer(ctx, CFG42, "admin")
    assert sortie["etat"] == "en_attente"
    assert faux.pauses == [P] * 3 + [rc.PAUSE_DHCP]


def _echec_et_retour(ctx, racine, faux, motif):
    with pytest.raises(rc.Echec, match=motif):
        rc.appliquer(ctx, CFG42, "admin")
    actions = [(a["action"], a["acteur"]) for a in audits(racine)]
    assert ("appliquer-echec", "admin") in actions and ("retour", "echec") in actions
    assert etat_fichier(racine)["etat"] == "inactif"
    assert (racine / "etc/systemd/network/10-br-lan.network").read_text() == ANCIEN_PONT
    assert not any("--unit=secubox-netmodes-retour" in a for a in faux.journal)   # aucun minuteur armé
    assert ["systemctl", "enable", "secubox-lan-dhcp.service"] not in faux.journal  # rien après l'étape 7
    jamais_reconfigure_br_lan(faux.journal)
    sans_eth(faux.journal)


def test_ports_jamais_asservis_echec_et_retour(ctx, racine, faux):
    """Le symptôme de gk2 (ports « configuring » à jamais) n'est plus déclaré réussi : échec d'étape, retour."""
    faux.asservir = False
    _echec_et_retour(ctx, racine, faux, r"br-lan n'est pas prêt après 30 s : lan0 non asservi")
    assert faux.pauses == [P] * 15


def test_port_avec_porteuse_non_asservi_echec(ctx, racine, faux):
    faux.ports_refuses = {"lan3"}
    _echec_et_retour(ctx, racine, faux, r"lan3 non asservi à br-lan \(porteuse présente\)")


def test_port_sans_porteuse_non_asservi_echec(ctx, racine, faux):
    faux.ports_refuses = {"lan2"}
    _echec_et_retour(ctx, racine, faux, r"lan2 non asservi à br-lan \(sans porteuse\)")


def test_netdev_en_echec_echec_et_retour(ctx, racine, faux):
    """networkd ne crée pas son pont (netdev en échec : pont DOWN, sans adresse, ports jamais asservis)."""
    faux.creation_refusee = True
    _echec_et_retour(ctx, racine, faux, "br-lan n'est pas prêt après 30 s : br-lan absent")
    # le pont fait main de gk2 a été supprimé et seul un .network le déclare : le retour ne le tait pas
    assert "INCOMPLET : réseau : br-lan absent" in audits(racine)[-1]["detail"]


def test_adresse_absente_echec_et_retour(ctx, racine, faux):
    faux.adresse_networkd = False
    _echec_et_retour(ctx, racine, faux, r"192\.168\.42\.1/24 absente de br-lan")


# --- retour ------------------------------------------------------------------------------------------------------------

def test_retour_netdev_restant_pont_recree(ctx, racine, faux):
    """Retour vers une application précédente : notre .netdev reste, les fichiers du pont changent. br-lan supprimé avant
    reload, networkd le recrée avec l'adresse restaurée et y asservit les ports."""
    rc.appliquer(ctx, CFG42, "admin")
    rc.confirmer(ctx, "admin")
    rc.appliquer(ctx, CFG50, "admin")
    faux.journal.clear()
    rc.retour(ctx, "admin")
    j = faux.journal
    assert j.index(SUPPRIMER) < j.index(RELOAD) < j.index(RECONFIGURER_PORTS)
    assert faux.adresses["br-lan"] == ["192.168.42.1/24"] and asservis(faux) == set(PORTS)
    assert not faux.netdev_en_echec
    jamais_reconfigure_br_lan(j)


def test_retour_netdev_restant_fichiers_inchanges_pont_garde(ctx, racine, faux):
    rc.appliquer(ctx, CFG42, "admin")
    rc.confirmer(ctx, "admin")
    rc.appliquer(ctx, dict(CFG42, bail="30m"), "admin")
    faux.journal.clear()
    rc.retour(ctx, "admin")
    assert SUPPRIMER not in faux.journal
    assert RECONFIGURER_PORTS in faux.journal
    assert asservis(faux) == set(PORTS)


def test_retour_gk2_seul_un_network_reste_pont_garde(ctx, racine, faux):
    """Aucun .netdev ne reste (l'ancien pont de gk2 n'était déclaré que par un .network) : networkd ne saurait pas le
    recréer, br-lan est gardé ; reload lui rend 192.168.255.1/24."""
    rc.appliquer(ctx, CFG42, "admin")
    faux.journal.clear()
    rc.retour(ctx, "admin")
    assert SUPPRIMER not in faux.journal
    assert "192.168.255.1/24" in faux.adresses["br-lan"]
    jamais_reconfigure_br_lan(faux.journal)


def test_retour_carte_neuve_pont_supprime(neuf):
    r, f, ctx = neuf
    rc.appliquer(ctx, CFG42, "admin")
    f.journal.clear()
    rc.retour(ctx, "admin")
    assert f.journal.index(RELOAD) < f.journal.index(SUPPRIMER)                 # aucun fichier ne le déclare plus
    assert "br-lan" not in f.adresses and asservis(f) == set()
    assert not any(a[:2] == ["networkctl", "reconfigure"] for a in f.journal)
    assert ASSERVIS not in f.journal                                            # aucun routeur.toml : rien à relire


# --- revue I3 : le retour relit le pont de la configuration restaurée -------------------------------------------------

@pytest.mark.parametrize("appel", [lambda ctx: rc.retour(ctx, "admin"), lambda ctx: rc.retour(ctx, "minuteur"),
                                   rc.retour_si_en_attente])
def test_retour_pont_non_recree_incomplet(ctx, racine, faux, appel):
    """networkd ne recrée pas br-lan après suppression et reload : le retour ne se dit plus réussi, LAN mort."""
    rc.appliquer(ctx, CFG42, "admin")
    rc.confirmer(ctx, "admin")
    rc.appliquer(ctx, CFG50, "admin")
    faux.creation_refusee = True
    faux.journal.clear()
    faux.pauses.clear()
    with pytest.raises(rc.Echec, match="retour incomplet : réseau : br-lan n'est pas prêt après 30 s : br-lan absent"):
        appel(ctx)
    assert etat_fichier(racine)["etat"] == "actif"                             # état calculé, inchangé
    assert "INCOMPLET : réseau : br-lan n'est pas prêt" in audits(racine)[-1]["detail"]
    assert faux.pauses[:15] == [P] * 15
    assert ["systemctl", "restart", "--no-block", "unbound.service"] in faux.journal    # les étapes suivantes ont lieu


def test_retour_pont_relu_avec_la_configuration_restauree(ctx, racine, faux):
    rc.appliquer(ctx, CFG42, "admin")
    rc.confirmer(ctx, "admin")
    rc.appliquer(ctx, CFG50, "admin")
    faux.journal.clear()
    rc.retour(ctx, "admin")
    j = faux.journal
    assert j.index(RECONFIGURER_PORTS) < j.index(ASSERVIS)                      # relu après le réseau
    assert faux.adresses["br-lan"] == ["192.168.42.1/24"]                      # adresse restaurée vérifiée


def test_retour_pont_en_echec_apres_bascule_incomplet(ctx, racine, faux):
    """Bascule en échec au pont, puis networkd refuse aussi de recréer le pont restauré : le retour le dit."""
    rc.appliquer(ctx, CFG42, "admin")
    rc.confirmer(ctx, "admin")
    faux.journal.clear()
    faux.asservir = False                                                       # bascule : ports jamais asservis
    with pytest.raises(rc.Echec, match="retour INCOMPLET : réseau : br-lan n'est pas prêt"):
        rc.appliquer(ctx, CFG50, "admin")


def test_cycle_complet_jamais_br_lan_reconfigure_ni_eth(ctx, racine, faux):
    rc.appliquer(ctx, CFG42, "admin")
    rc.confirmer(ctx, "admin")
    rc.appliquer(ctx, CFG50, "admin")
    rc.retour(ctx, "minuteur")
    rc.appliquer(ctx, CFG50, "admin")
    rc.retour_si_en_attente(ctx)
    jamais_reconfigure_br_lan(faux.journal)
    sans_eth(faux.journal)
    assert {a[3] if a[:3] == ["ip", "link", "delete"] else None for a in faux.journal} <= {None, "br-lan"}
