# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""Premier Pas (#1522) : profil, plan, application. Rien ne touche le système :
l'exécuteur est un faux qui enregistre les commandes."""
import copy
import sys
import tomllib
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from premier_pas import moteur as M, profil as P  # noqa: E402

EXEMPLE = Path(__file__).resolve().parents[1] / "exemples" / "profil.toml"
CONNUS = ["full", "lite"]
EMPREINTE = "$argon2id$v=19$m=65536,t=3,p=4$c2FsdHNhbHQ$aGFzaGhhc2hoYXNoaGFzaA"


@pytest.fixture
def complet():
    p = tomllib.loads(EXEMPLE.read_text())
    p["admin"]["mot_de_passe"] = EMPREINTE
    return p


@pytest.fixture
def isole(tmp_path, monkeypatch):
    monkeypatch.setattr(M, "ETAT", tmp_path / "etat.json")
    monkeypatch.setattr(M, "JOURNAL", tmp_path / "pp.log")
    monkeypatch.setattr(M, "SECUBOX_CONF", tmp_path / "secubox.conf")
    monkeypatch.setattr(M, "MAJAUTO_DROPIN", tmp_path / "heure.conf")
    monkeypatch.setattr(M, "_pose_empreinte_admin", lambda e: None)
    return tmp_path


def test_l_horloge_passe_avant_l_administrateur():
    # L'enrôlement TOTP dépend de l'heure (#1497) : l'ordre est une garantie.
    assert P.ETAPES.index("horloge") < P.ETAPES.index("admin")


def test_l_exemple_livre_attend_seulement_le_mot_de_passe():
    ex = P.examine(tomllib.loads(EXEMPLE.read_text()), CONNUS)
    assert ex.manquantes == ["admin"] and not ex.erreurs
    assert ex.premiere_etape == "admin"


def test_profil_complet(complet):
    assert P.examine(complet, CONNUS).complet


@pytest.mark.parametrize("mdp", ["secubox", "Motdepasse1234!", "$2b$12$bcrypt"])
def test_jamais_de_mot_de_passe_en_clair(complet, mdp):
    complet["admin"]["mot_de_passe"] = mdp
    ex = P.examine(complet, CONNUS)
    assert "admin" in ex.erreurs and not ex.complet


@pytest.mark.parametrize("section,cle,valeur,etape", [
    ("box", "nom", "GK 3!", "nom"),
    ("reseau", "mode", "wifi", "reseau"),
    ("reseau", "domaine", "pas un domaine", "reseau"),
    ("services", "profil", "inexistant", "services"),
    ("maillage", "jeton", "court", "maillage"),
    ("apt", "heure", "25:00", "majs"),
])
def test_valeurs_fausses_refusees(complet, section, cle, valeur, etape):
    complet[section][cle] = valeur
    assert etape in P.examine(complet, CONNUS).erreurs


def test_lan_seul_sans_domaine(complet):
    complet["reseau"] = {"mode": "lan"}
    assert P.examine(complet, CONNUS).complet


def test_profil_vide_reprend_au_nom():
    ex = P.examine({}, CONNUS)
    assert ex.premiere_etape == "nom" and not ex.complet


def test_plan_pilote_les_outils_existants(complet):
    argvs = [a.argv for a in M.plan(complet) if a.argv]
    assert ["/usr/sbin/secubox-renommer", "gk3"] in argvs
    assert ["secubox-net-detect", "apply", "router"] in argvs
    assert ["secubox-profilectl", "apply", "--profile", "full", "--yes"] in argvs
    assert ["sbx-mesh-join", "192.168.1.200", "e70e1f79f9b9cd4179950117ce5f78c2"] in argvs
    # L'ordre suit les étapes.
    etapes = [a.etape for a in M.plan(complet)]
    assert etapes == sorted(etapes, key=P.ETAPES.index)


def test_appliquer_tout_puis_marqueur(complet, isole):
    vues = []
    r = M.appliquer(complet, lambda argv: (vues.append(argv) or (0, "")), CONNUS, isole / "fait")
    assert r.ok and (isole / "fait").exists()
    assert (isole / "secubox.conf").read_text().count("gk3.secubox.in") == 2
    assert "03:00" in (isole / "heure.conf").read_text()


def test_premiere_erreur_arrete_tout_et_pas_de_marqueur(complet, isole):
    vues = []

    def exe(argv):
        vues.append(argv)
        return (1, "boom") if argv[0] == "secubox-net-detect" else (0, "")
    r = M.appliquer(complet, exe, CONNUS, isole / "fait")
    assert not r.ok and r.echec == "reseau" and r.reprendre == "reseau"
    assert not (isole / "fait").exists()
    assert not any(a[0] == "secubox-profilectl" for a in vues)   # rien après l'échec


def test_incomplet_n_applique_rien(isole):
    vues = []
    r = M.appliquer({"box": {"nom": "gk3"}}, lambda a: (vues.append(a) or (0, "")), CONNUS, isole / "fait")
    assert not r.ok and r.reprendre == "horloge" and vues == []


def test_domaine_edite_sans_perdre_le_reste(complet, isole):
    (isole / "secubox.conf").write_text('# garde-moi\n[global]\nhostname = "x"\n\n[api]\njwt_secret = "s"\n')
    M._ecrit_conf("gk3.secubox.in")
    t = (isole / "secubox.conf").read_text()
    assert "# garde-moi" in t and 'jwt_secret = "s"' in t
    assert 'domain = "gk3.secubox.in"' in t and 'sso_cookie_domain = ".gk3.secubox.in"' in t
    M._ecrit_conf(None)                                   # LAN seul : retiré
    assert "sso_cookie_domain" not in (isole / "secubox.conf").read_text()


def test_source_ligne_noyau(tmp_path):
    f = tmp_path / "p.toml"
    f.write_text("")
    assert M.cherche_profil(f"quiet secubox.profil={f}") == f


# ── Fuseau horaire (#1542) ─────────────────────────────────────────────────

def test_fuseau_propose_paris_si_utc(tmp_path):
    tz = tmp_path / "timezone"
    tz.write_text("Etc/UTC\n")
    assert P.fuseau_propose(tz) == "Europe/Paris"
    tz.write_text("America/Montreal\n")
    assert P.fuseau_propose(tz) == "America/Montreal"
    assert P.fuseau_propose(tmp_path / "absent") == "Europe/Paris"


def test_fuseaux_liste_region_ville():
    z = P.fuseaux()
    assert "Europe/Paris" in z
    assert not any(x.startswith(("Etc/", "posix/")) for x in z)


def test_garder_les_modules_actuels_n_appelle_pas_profilectl(complet):
    p = complet
    p["services"]["profil"] = P.GARDER
    assert P.examine(p, profils_connus=["full"]).complet
    actions = M.plan(p)
    s = [a for a in actions if a.etape == "services"]
    assert len(s) == 1 and s[0].argv is None and s[0].fn is None


def test_cause_d_echec_lisible():
    sortie = "▶️ start eye-remote\n❌ gitea : systemctl enable secubox-gitea.service → rc=1 (masked)\n" + "\n".join(f"↩ rollback m{i}" for i in range(80))
    c = M.cause(sortie)
    assert "gitea" in c and "masked" in c
    assert M.cause("tout va bien\nsauf la fin") == "tout va bien · sauf la fin"


def test_maillage_reessaie_le_temps_que_le_reseau_revienne(complet, tmp_path, monkeypatch):
    monkeypatch.setattr(M, "ETAT", tmp_path / "etat.json")
    monkeypatch.setattr(M, "JOURNAL", tmp_path / "journal.log")
    monkeypatch.setattr(M.time, "sleep", lambda s: None)
    monkeypatch.setattr(M, "_pose_empreinte_admin", lambda e: None)
    monkeypatch.setattr(M, "_ecrit_conf", lambda d: None)
    monkeypatch.setattr(M, "_majauto", lambda a, h: None)
    p = complet
    p["maillage"] = {"mode": "rejoindre", "rejoindre": "192.168.1.200", "jeton": "ab" * 32}
    appels = []
    def executeur(argv):
        appels.append(argv[0])
        if argv[0] == "sbx-mesh-join" and appels.count("sbx-mesh-join") < 3:
            return 1, "✗ FAILED to join mesh"
        return 0, ""
    r = M.appliquer(p, executeur, profils_connus=["full"], marqueur=tmp_path / "fait")
    assert r.ok, r.detail
    assert appels.count("sbx-mesh-join") == 3


def test_premier_pas_utilise_secubox_renommer(complet):
    """#3126 D3, #3242 : un seul renommage, celui de secubox-core (hosts 127.0.1.1, secubox.conf, hostnamectl, Avahi,
    audit, retour arrière) ; premier-pas ne garde ni sa copie (_renomme) ni hostnamectl ni la relance d'Avahi."""
    nom = [a for a in M.plan(complet) if a.etape == "nom"]
    assert len(nom) == 1 and nom[0].argv == ["/usr/sbin/secubox-renommer", "gk3"] and nom[0].fn is None
    assert not nom[0].souple
    assert not any(a.argv and a.argv[0] == "hostnamectl" for a in M.plan(complet))
    assert not hasattr(M, "_renomme") and not hasattr(M, "_avahi_nouveau_nom") and not hasattr(M, "HOSTS")
    controle = (Path(__file__).resolve().parents[1] / "debian" / "control").read_text()
    assert "secubox-core (>= 1.8.10~)" in controle


# ── #2306 : l'étape réseau sans `secubox-net-detect` ─────────────────────────────────────────────
def test_lan_sans_l_outil_conserve_le_reseau_existant(complet, monkeypatch):
    complet["reseau"] = {"mode": "lan"}
    monkeypatch.setattr(M, "NET_DETECT", Path("/nonexistent/secubox-net-detect"))
    r = [a for a in M.plan(complet) if a.etape == "reseau"][0]
    assert r.argv is None and r.fn is M._reseau_existant_conserve and "conservé" in r.quoi


def test_lan_avec_l_outil_garde_la_commande(complet, tmp_path, monkeypatch):
    complet["reseau"] = {"mode": "lan"}
    outil = tmp_path / "secubox-net-detect"
    outil.write_text("#!/bin/sh\n")
    outil.chmod(0o755)
    monkeypatch.setattr(M, "NET_DETECT", outil)
    assert ["secubox-net-detect", "apply", "single"] in [a.argv for a in M.plan(complet) if a.argv]


def test_routeur_et_pont_sans_l_outil_echouent_en_le_disant(complet, isole, monkeypatch):
    monkeypatch.setattr(M, "NET_DETECT", Path("/nonexistent/secubox-net-detect"))
    def exe(argv):
        return (127, "[Errno 2] No such file or directory: 'secubox-net-detect'") if argv[0] == "secubox-net-detect" else (0, "")
    r = M.appliquer(complet, exe, CONNUS, isole / "fait")                       # `complet` = mode routeur
    assert not r.ok and r.echec == "reseau" and "secubox-net-detect" in r.detail and not (isole / "fait").exists()


def test_le_reseau_existant_exige_une_route_par_defaut():
    M._reseau_existant_conserve("default via 10.0.2.2 dev enp0s3 proto dhcp\n")      # passe
    with pytest.raises(RuntimeError, match="aucune route par défaut"):
        M._reseau_existant_conserve("")
    with pytest.raises(RuntimeError, match="aucune route par défaut"):
        M._reseau_existant_conserve("10.0.2.0/24 dev enp0s3 scope link\n")


# ── #2495 : un défaut d'horloge est dit mais n'arrête pas la première installation ─────────────────────────────────────────────────────
def test_ntp_absent_est_un_avertissement_et_l_assistant_continue(complet, isole):
    vues = []

    def exe(argv):
        vues.append(argv)
        return (1, "Failed to set ntp: NTP not supported") if argv[:2] == ["timedatectl", "set-ntp"] else (0, "")
    r = M.appliquer(complet, exe, CONNUS, isole / "fait")
    assert r.ok and (isole / "fait").exists()                                   # avant : « Arrêt à l'étape Horloge », box inutilisable
    assert len(r.avertissements) == 1 and "horloge" in r.avertissements[0] and "NTP not supported" in r.avertissements[0]
    assert any(a[0] == "secubox-profilectl" for a in vues)                      # les étapes suivantes ont bien été jouées


def test_un_echec_non_souple_arrete_toujours(complet, isole):
    r = M.appliquer(complet, lambda a: (1, "boom") if a[0] == "/usr/sbin/secubox-renommer" else (0, ""), CONNUS, isole / "fait")
    assert not r.ok and r.echec == "nom" and not (isole / "fait").exists() and r.avertissements == []


def test_seule_l_etape_ntp_est_souple(complet):
    souples = [a.quoi for a in M.plan(complet) if a.souple]
    assert souples == ["synchronisation NTP"]                                    # tout le reste reste bloquant : on ne masque pas un vrai défaut


@pytest.mark.parametrize("nom", ["admin", "www", "secubox", "localhost", "SECUBOX"])
def test_nom_reserve_refuse_des_le_profil(complet, nom):
    """M10 (R-L2-36) : secubox-renommer refuse ces noms (code 3) ; le profil les refuse avant toute application, à
    l'étape « nom », au lieu d'un échec au milieu de l'assistant."""
    complet["box"]["nom"] = nom
    ex = P.examine(complet, CONNUS)
    assert "nom" in ex.erreurs and "réservé" in ex.erreurs["nom"] and not ex.complet
    assert P.NOMS_RESERVES == frozenset({"admin", "www", "secubox", "localhost"})
