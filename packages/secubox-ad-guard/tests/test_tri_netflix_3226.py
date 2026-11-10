# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3226 — tri Netflix par insistance au niveau DNS (TV en Wi-Fi, non routée par la box)."""
import importlib.machinery
import importlib.util
import os
from pathlib import Path

import pytest

from api import dnstv, dnstv_tri as T

from test_dnstv_auto_rendu import charger_ctl, faux  # noqa: E402

S1 = "ipv6-c164-cdg001-ix.1.oca.nflxvideo.net"
S2 = "ipv6-c185-cdg001-ix.1.oca.nflxvideo.net"
ETAT = {"actif": True, "clients": [{"ip": "192.168.1.95", "nom": "TV banc", "mode": "auto", "mac": "38:07:16:93:4e:95"},
                                   {"ip": "2a01:e0a::1", "nom": "TV banc", "mode": "auto"},
                                   {"ip": "192.168.1.9", "nom": "Autre", "mode": "observe"}],
        "tri_netflix": {"appareils": ["tv-banc"]}}


# --- logique pure ----------------------------------------------------------------------------------------------------

def test_insistance_secondes_distinctes_dans_la_fenetre():
    i = T.Insistance(seuil=3, fenetre_s=20)
    assert not i.voir("tv-banc", S1, 100, True)
    assert not i.voir("tv-banc", S1, 100, True)            # AAAA de la même tentative : même seconde, compte une fois
    assert not i.voir("tv-banc", S1, 104, True)
    assert i.voir("tv-banc", S1, 109, True)                 # 3e seconde distincte en 20 s : demande
    assert not i.voir("tv-banc", S1, 110, True)             # au plus une demande toutes les 10 s


def test_abandon_ou_requete_lente_ne_demande_rien():
    i = T.Insistance(seuil=3, fenetre_s=20)
    assert not i.voir("tv-banc", S2, 100, True)             # demandé une fois puis abandonné : la publicité
    assert not i.voir("tv-banc", S2, 130, True)
    assert not i.voir("tv-banc", S2, 160, True)             # trois fois, mais jamais dans la même fenêtre


def test_seuls_les_serveurs_video_refuses_comptent():
    i = T.Insistance(seuil=2, fenetre_s=20)
    for nom in ("logs.netflix.com", "oca.nflxvideo.net", "x.oca.nflxvideo.net.evil.com", "a..1.oca.nflxvideo.net"):
        assert not i.voir("tv-banc", nom, 1, True) and not i.voir("tv-banc", nom, 2, True)
    assert not i.voir("tv-banc", S1, 1, False) and not i.voir("tv-banc", S1, 2, False)   # autorisé : rien à demander


def test_validation_du_reglage():
    assert T.valider({"appareils": ["tv-banc"]}) == {"appareils": ["tv-banc"], "seuil": 3, "fenetre_s": 20, "duree_s": 10800,
                                                      "serveurs": 2, "fenetre_zone_s": 30, "ouverture_s": 180}
    for mauvais in ({"appareils": ["TV banc"]}, {"appareils": [], "seuil": 1}, {"appareils": [], "duree_s": 10},
                    {"appareils": [], "inconnu": 1}, {"appareils": "tv-banc"}):
        with pytest.raises(T.ErreurTri):
            T.valider(mauvais)


@pytest.mark.parametrize("nom", ["tv-banc__" + S1 + "\n", "tv-banc\n__" + S1, "tv-banc__../../etc/passwd", "tv-banc__" + S1 + "/x", "../x__" + S1, "tv-banc_" + S1,
                                 "tv-banc__logs.netflix.com", "TV__" + S1])
def test_nom_de_demande_hostile_refuse(nom):
    assert T.lire_demande(nom) is None


def test_depot_et_lecture_de_demande(tmp_path):
    assert T.deposer_demande("tv-banc", S1, tmp_path) and T.deposer_demande("tv-banc", S1, tmp_path)   # idempotent
    assert [T.lire_demande(p.name) for p in tmp_path.iterdir()] == [("tv-banc", S1)]
    assert not T.deposer_demande("tv-banc", "logs.netflix.com", tmp_path)


def test_autorisations_echeances_et_zones():
    a = {}
    assert T.autoriser(a, "tv-banc", S1, 600, maintenant=1000) is True
    assert T.autoriser(a, "tv-banc", S1, 600, maintenant=1100) is False          # prolongé, déjà posé
    assert a["tv-banc"][S1] == 1700
    lignes = T.zones_vue("tv-banc", ETAT, a, maintenant=1200)
    assert lignes == ['    local-zone: "oca.nflxvideo.net." always_nxdomain', f'    local-zone: "{S1}." transparent']
    assert T.echus(a, maintenant=1700) == [("tv-banc", S1)] and a["tv-banc"] == {}
    assert T.zones_vue("autre", ETAT, a) == []                                  # appareil non trié : rien
    assert T.charger_autorises({"tv-banc": {S1: 5, "evil\n.com": 9}, "../x": {S1: 1}}) == {"tv-banc": {S1: 5}}


# --- état et rendu Unbound ------------------------------------------------------------------------------------------------

def test_etat_garde_le_reglage_et_rendu_dans_la_vue_auto():
    e = dnstv.valider_etat(ETAT)
    assert e["tri_netflix"]["appareils"] == ["tv-banc"]
    assert "tri_netflix" not in dnstv.valider_etat({k: v for k, v in ETAT.items() if k != "tri_netflix"})
    out = dnstv.rendre_unbound(ETAT, {}, None, tri_autorises={"tv-banc": {S1: 4_000_000_000}})
    bloc = out.split('name: "sbx-tv-auto-tv-banc"')[1].split("view:")[0]
    assert 'local-zone: "oca.nflxvideo.net." always_nxdomain' in bloc and f'local-zone: "{S1}." transparent' in bloc
    autre = dnstv.rendre_unbound({**ETAT, "tri_netflix": {"appareils": []}}, {}, None)
    assert "nflxvideo" not in autre


# --- dnsfeed : de la ligne du journal à la demande ---------------------------------------------------------------------

def _dnsfeed():
    chemin = Path(__file__).resolve().parents[1] / "sbin" / "secubox-adguard-dnsfeed"
    loader = importlib.machinery.SourceFileLoader("sbx_dnsfeed", str(chemin))
    spec = importlib.util.spec_from_loader("sbx_dnsfeed", loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


def test_dnsfeed_depose_une_demande_sur_insistance(tmp_path, monkeypatch):
    feed = _dnsfeed()
    lignes = []
    for ts in (1000, 1004, 1009):
        lignes.append(f"[{ts}] unbound[1:0] info: oca.nflxvideo.net. always_nxdomain 192.168.1.95@4242 {S1}. A IN")
        lignes.append(f"[{ts}] unbound[1:0] info: reply: 192.168.1.95 {S1}. A IN NXDOMAIN 0.0 0 40")
    lignes.append(f"[1010] unbound[1:0] info: oca.nflxvideo.net. always_nxdomain 192.168.1.9@4242 {S2}. A IN")
    deposes = []

    class Magasin:
        def ajouter(self, lot, exclus):
            return len(lot)

        def purger(self, jours):
            return 0

    tri = lambda: ({"192.168.1.95": "tv-banc"}, T.Insistance(3, 20))   # noqa: E731
    feed.suivre(lignes, Magasin(), dnstv.Classifieur({}), recharger=lambda: dnstv.Classifieur({}),
                locales=lambda: set(), tri=tri, deposer=lambda s, n: deposes.append((s, n)))
    assert deposes == [("tv-banc", S1)]                                        # l'appareil non trié n'est jamais touché


# --- contrôleur root ---------------------------------------------------------------------------------------------------

def test_tri_appliquer_pose_revalide_et_purge(tmp_path, monkeypatch):
    control = faux(tmp_path, "unbound-control")
    ctl = charger_ctl(monkeypatch, tmp_path, control)
    dnstv.ecrire_etat(ETAT, tmp_path)
    demandes = tmp_path / "demandes"
    demandes.mkdir()
    T.deposer_demande("tv-banc", S1, demandes)
    T.deposer_demande("autre", S2, demandes)                                  # appareil non trié : refusé
    os.symlink("/etc/passwd", demandes / f"tv-banc__{S2}")                     # lien : retiré, jamais suivi
    (demandes / "un-dossier").mkdir()                                        # dossier planté : retiré, pas de boucle
    assert ctl.tri_appliquer(demandes) == 0
    appels = (tmp_path / "unbound-control.log").read_text()
    assert f"view_local_zone_add sbx-tv-auto-tv-banc {S1}. transparent" in appels and S2 not in appels
    assert list(demandes.iterdir()) == []
    autorises = ctl._tri_autorises()
    assert S1 in autorises["tv-banc"]
    # Échéance passée : la zone est retirée à la passe suivante.
    autorises["tv-banc"][S1] = 1
    ctl._tri_sauver(autorises)
    ctl.tri_appliquer(demandes)
    assert f"view_local_zone_remove sbx-tv-auto-tv-banc {S1}." in (tmp_path / "unbound-control.log").read_text()
    assert ctl._tri_autorises()["tv-banc"] == {}


def test_tri_inactif_si_le_filtrage_est_coupe(tmp_path, monkeypatch):
    control = faux(tmp_path, "unbound-control")
    ctl = charger_ctl(monkeypatch, tmp_path, control)
    dnstv.ecrire_etat({**ETAT, "actif": False}, tmp_path)
    demandes = tmp_path / "demandes"
    demandes.mkdir()
    T.deposer_demande("tv-banc", S1, demandes)
    ctl.tri_appliquer(demandes)
    assert not (tmp_path / "unbound-control.log").exists()


# --- API ---------------------------------------------------------------------------------------------------------------

def test_route_tri_et_mac_gardee(tmp_path, monkeypatch):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from api import dnstv_routes as RT
    monkeypatch.setattr(dnstv, "DOSSIER_ETAT", tmp_path)
    monkeypatch.setattr(RT, "_ctl", lambda action: {"ok": True})
    dnstv.ecrire_etat({k: v for k, v in ETAT.items() if k != "tri_netflix"}, tmp_path)
    app = FastAPI()
    app.include_router(RT.router)
    app.dependency_overrides[RT.require_jwt] = lambda: {"sub": "admin"}
    c = TestClient(app)
    r = c.post("/adblock-tv/tri-netflix", json={"appareil": "tv-banc", "actif": True})
    assert r.status_code == 200 and r.json()["tri_netflix"]["appareils"] == ["tv-banc"]
    assert c.post("/adblock-tv/tri-netflix", json={"appareil": "autre", "actif": True}).status_code == 409   # pas en auto
    assert c.post("/adblock-tv/tri-netflix", json={"appareil": "../x", "actif": True}).status_code == 422
    assert c.post("/adblock-tv/tri-netflix", json={"appareil": "tv-banc", "actif": False}).json()["tri_netflix"]["appareils"] == []
    # Redéclarer une adresse existante garde sa MAC (ancre du suivi des nouvelles adresses).
    assert c.post("/adblock-tv/clients", json={"ip": "192.168.1.95", "nom": "TV banc", "mode": "auto"}).status_code == 200
    e, _ = dnstv.lire_etat(tmp_path) if "dossier" in dnstv.lire_etat.__code__.co_varnames else dnstv.lire_etat()
    assert next(x for x in e["clients"] if x["ip"] == "192.168.1.95")["mac"] == "38:07:16:93:4e:95"


def test_dossier_des_demandes_remplace_par_un_lien_refuse(tmp_path, monkeypatch):
    control = faux(tmp_path, "unbound-control")
    ctl = charger_ctl(monkeypatch, tmp_path, control)
    dnstv.ecrire_etat(ETAT, tmp_path)
    cible = tmp_path / "precieux"
    cible.mkdir()
    (cible / "fichier").write_text("x")
    os.symlink(cible, tmp_path / "demandes")
    ctl.tri_appliquer(tmp_path / "demandes")
    assert (cible / "fichier").exists()                                        # rien effacé à travers le lien


def test_plafond_de_poses_par_passe(tmp_path, monkeypatch):
    control = faux(tmp_path, "unbound-control")
    ctl = charger_ctl(monkeypatch, tmp_path, control)
    dnstv.ecrire_etat(ETAT, tmp_path)
    demandes = tmp_path / "demandes"
    demandes.mkdir()
    for i in range(40):
        T.deposer_demande("tv-banc", f"ipv6-c{i}-cdg001-ix.1.oca.nflxvideo.net", demandes)
    ctl.tri_appliquer(demandes)
    appels = (tmp_path / "unbound-control.log").read_text().splitlines()
    assert len([a for a in appels if "view_local_zone_add" in a]) == T.MAX_POSES and list(demandes.iterdir()) == []


def test_etat_illisible_vide_quand_meme_les_demandes(tmp_path, monkeypatch):
    control = faux(tmp_path, "unbound-control")
    ctl = charger_ctl(monkeypatch, tmp_path, control)
    (tmp_path / "etat.json").write_text("{pas du json")
    demandes = tmp_path / "demandes"
    demandes.mkdir()
    T.deposer_demande("tv-banc", S1, demandes)
    assert ctl.tri_appliquer(demandes) == 0 and list(demandes.iterdir()) == []


def test_unite_root_durcie_et_dossier_root():
    ici = Path(__file__).resolve().parents[1] / "debian"
    unite = (ici / "secubox-ad-guard-tri.service").read_text()
    for d in ("UMask=0027", "NoNewPrivileges=yes", "ProtectSystem=strict", "RestrictAddressFamilies=AF_UNIX", "IPAddressDeny=any"):
        assert d in unite, d
    assert "d /run/secubox/ad-guard-tri 1730 root secubox -" in (ici / "secubox-ad-guard-tri.tmpfiles").read_text()
    assert "TriggerLimitBurst" in (ici / "secubox-ad-guard-tri.path").read_text()
    assert "secubox-ad-guard-tri.path" in (ici / "prerm").read_text()


# --- règle « par zone » : rafale de serveurs nouveaux (relevé réel du 10/11) ---------------------------------------------

C = "ipv6-c{}-cdg001-ix.1.oca.nflxvideo.net"


def test_demarrage_d_episode_ouvre_la_zone_pub_isolee_reste_refusee():
    i = T.Insistance()
    # Démarrage d'épisode observé à 13:26 : c211, puis c219 9 s plus tard (refusés, une seule demande chacun).
    assert i.rafale("tv-banc", C.format(211), 1000, True) == []
    assert i.rafale("tv-banc", C.format(211), 1000, True) == []          # AAAA de la même tentative : même serveur
    assert i.rafale("tv-banc", C.format(219), 1009, True) == [T.OUVRIR]
    # Pendant l'ouverture : chaque serveur résolu est demandé (l'épisode reste servi après la fermeture).
    assert i.rafale("tv-banc", C.format(222), 1053, False) == [C.format(222)]
    assert i.rafale("tv-banc", C.format(223), 1009 + 181, False) == []   # ouverture finie : rien
    # En pleine lecture, une pub = UN serveur nouveau isolé : refusé, pas d'ouverture.
    assert i.rafale("tv-banc", C.format(185), 2000, True) == []
    assert i.rafale("tv-banc", C.format(164), 2700, True) == []          # la suivante, 12 min plus tard : toujours isolée


def test_reglage_par_zone_borne_et_compatible():
    assert T.reglage({"tri_netflix": {"appareils": ["tv-banc"], "seuil": 3, "fenetre_s": 20, "duree_s": 10800}})["ouverture_s"] == 180
    with pytest.raises(T.ErreurTri):
        T.valider({"appareils": [], "serveurs": 1})
    assert T.lire_demande("tv-banc__ouvrir") == ("tv-banc", T.OUVRIR) and T.lire_demande("tv-banc__ouvrirx") is None


def test_rendu_sans_refus_de_zone_pendant_l_ouverture():
    lignes = T.zones_vue("tv-banc", ETAT, {"tv-banc": {S1: 4_000_000_000}}, maintenant=100, ouvertures={"tv-banc": 200})
    assert lignes == [f'    local-zone: "{S1}." transparent']
    assert T.zones_vue("tv-banc", ETAT, {}, maintenant=300, ouvertures={"tv-banc": 200})[0].endswith("always_nxdomain")


def test_controleur_ouvre_puis_referme_la_zone(tmp_path, monkeypatch):
    control = faux(tmp_path, "unbound-control")
    ctl = charger_ctl(monkeypatch, tmp_path, control)
    dnstv.ecrire_etat(ETAT, tmp_path)
    demandes = tmp_path / "demandes"
    demandes.mkdir()
    T.deposer_demande("tv-banc", T.OUVRIR, demandes)
    ctl.tri_appliquer(demandes)
    log = (tmp_path / "unbound-control.log").read_text()
    assert "view_local_zone_remove sbx-tv-auto-tv-banc oca.nflxvideo.net." in log
    assert ctl._tri_ouvertures()["tv-banc"] > 0
    ctl._tri_sauver_json("tri-ouvertures.json", {"tv-banc": 1})          # ouverture échue
    ctl.tri_appliquer(demandes)
    assert "view_local_zone_add sbx-tv-auto-tv-banc oca.nflxvideo.net. always_nxdomain" in (tmp_path / "unbound-control.log").read_text()
    assert ctl._tri_ouvertures() == {}
