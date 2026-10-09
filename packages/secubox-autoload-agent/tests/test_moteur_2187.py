# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2187 : moteur de provisioning — étapes ordonnées, reprise, idempotence, refus par défaut, entrées du réseau jamais exécutées."""
import json
import os
import stat
import sys
from pathlib import Path

import pytest

ICI = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ICI))
sys.path.insert(0, str(ICI.parent / "secubox-premier-pas"))
from autoload_agent import moteur as M, tunnel as T  # noqa: E402
from premier_pas import provision as V  # noqa: E402

CLE_BOX = "P" * 43 + "="
TUNNEL = {"endpoint": "admin.gk2.secubox.in:51830", "serveur_cle_pub": "S" * 43 + "=", "adresse": "10.64.0.2/32", "hub": "10.64.0.1/32"}
SIMULATION = "Inst secubox-core (1.0 SecuBox)\nInst secubox-ad-guard (1.8.0 SecuBox)\nInst secubox-lite (1.0.42 SecuBox)\nConf secubox-core\n"


class FauxExecuteur:
    def __init__(self, echec_sur=None):
        self.appels, self.echec_sur = [], echec_sur

    def __call__(self, argv, **kw):
        self.appels.append((list(argv), kw))

        class R:
            pass
        r = R()
        r.returncode, r.stdout, r.stderr = 0, "", ""
        if self.echec_sur and self.echec_sur(argv):
            r.returncode, r.stderr = 100, "échec simulé"
        elif argv[:2] == ["apt-get", "-s"] or (len(argv) > 3 and "-s" in argv and argv[0] == "apt-get"):
            r.stdout = SIMULATION
        return r

    def commandes(self):
        return [" ".join(a) for a, _ in self.appels]


class FauxEnroleur:
    def __init__(self, reponse=None, erreur=None):
        self.reponse, self.erreur, self.appels = reponse, erreur, []

    def __call__(self, jeton, serie, cle_pub, infra):
        self.appels.append((jeton, serie, cle_pub, infra))
        if self.erreur:
            raise self.erreur
        return self.reponse if self.reponse is not None else {"tunnel": TUNNEL, "client": "client-042", "profil": "lite"}


@pytest.fixture
def monde(tmp_path, monkeypatch):
    secrets = tmp_path / "secrets"
    secrets.mkdir(mode=0o700)
    (secrets / "autoload-jeton").write_text("a" * 32 + "\n")
    os.chmod(secrets / "autoload-jeton", 0o600)
    reponses = tmp_path / "reponses.toml"
    reponses.write_text("""
[box]
nom = "client-042"
langue = "fr"
clavier = "fr"
fuseau = "Europe/Paris"
ntp = true
[admin]
mot_de_passe = "$argon2id$v=19$m=65536,t=3,p=4$c2FsdHNhbHQ$aGFzaGhhc2hoYXNoaGFzaA"
totp = "enroler"
[reseau]
mode = "routeur"
domaine = "client042.secubox.in"
[services]
profil = "lite"
[maillage]
mode = "plus_tard"
[apt]
auto = true
heure = "03:00"
[provision]
mode = "auto"
jeton = "ref:/etc/secubox/secrets/autoload-jeton"
""", encoding="utf-8")
    sig, ring = tmp_path / "reponses.toml.sig", tmp_path / "trousseau.gpg"
    sig.write_bytes(b"sig"); ring.write_bytes(b"ring")
    monkeypatch.setattr(V, "verifier_signature", lambda f, s, t, gpgv="gpgv": None)               # la signature a ses propres tests (#2184)
    ex, en = FauxExecuteur(), FauxEnroleur()
    cfg = M.Config(reponses=reponses, signature=sig, trousseau=ring, racine_secrets=secrets, etat=tmp_path / "etat" / "etat.json",
                   cle_wg=secrets / "wg.key", conf_wg=tmp_path / "wg.conf", rapport=tmp_path / "rapport.json")
    monkeypatch.setattr(T, "assurer_cle", lambda *a, **k: CLE_BOX)
    monkeypatch.setattr(T, "monter", lambda reponse, *a, **k: ex(["wg-monter", json.dumps(reponse)], timeout=30))
    return type("Monde", (), {"cfg": cfg, "ex": ex, "en": en, "tmp": tmp_path, "secrets": secrets})


def moteur(m, valideur=lambda plan: True, enroleur=None, executeur=None):
    return M.Moteur(m.cfg, executeur=executeur or m.ex, enroleur=enroleur or m.en, valideur=valideur)


def test_parcours_complet_dans_l_ordre(monde):
    r = moteur(monde).run()
    assert r.ok and r.etape is None
    assert monde.en.appels == [("a" * 32, None, CLE_BOX, "admin.gk2.secubox.in")]
    cmds = monde.ex.commandes()
    i_sim = next(i for i, c in enumerate(cmds) if c.startswith("apt-get -s") or " -s " in c)
    i_inst = next(i for i, c in enumerate(cmds) if c.startswith("apt-get") and "install" in c and " -s " not in c)
    i_tun = next(i for i, c in enumerate(cmds) if c.startswith("wg-monter"))
    i_app = next(i for i, c in enumerate(cmds) if "profilectl" in c and "apply" in c)
    assert i_tun < i_sim < i_inst < i_app, cmds
    assert any("premier-pasctl" in c and "appliquer" in c for c in cmds)
    assert json.loads(monde.cfg.etat.read_text())["fait"] is True


def test_le_parcours_installe_le_meta_paquet_du_profil_et_rien_d_autre(monde):
    moteur(monde).run()
    inst = [a for a, _ in monde.ex.appels if a[0] == "apt-get" and "install" in a and "-s" not in a][0]
    assert inst[-1] == "secubox-lite" and "-y" in inst
    assert all(isinstance(a, list) for a, _ in monde.ex.appels) and all(kw.get("timeout") for _, kw in monde.ex.appels)


def test_le_valideur_recoit_le_plan_et_son_refus_arrete_avant_toute_installation(monde):
    vu = []
    r = moteur(monde, valideur=lambda plan: vu.append(plan) or False).run()
    assert not r.ok and r.etape == "validation"
    assert "secubox-ad-guard" in vu[0].paquets and vu[0].profil == "lite" and vu[0].mode == "auto"
    assert not any(c.startswith("apt-get") and "install" in c and " -s " not in c for c in monde.ex.commandes())


def test_sans_valideur_explicite_le_defaut_refuse(monde):
    r = M.Moteur(monde.cfg, executeur=monde.ex, enroleur=monde.en).run()
    assert not r.ok and r.etape == "validation"                          # tant que #2188 ne fournit pas le sien : refus


def test_reprise_apres_un_echec_d_installation(monde):
    m = moteur(monde, executeur=FauxExecuteur(echec_sur=lambda a: a[0] == "apt-get" and "install" in a and "-s" not in a))
    r = m.run()
    assert not r.ok and r.etape == "installation"
    etat = json.loads(monde.cfg.etat.read_text())
    assert etat["faites"] == ["reponses", "cle", "enrolement", "tunnel", "plan", "validation"] and not etat.get("fait")
    ok_ex = FauxExecuteur()
    r2 = moteur(monde, executeur=ok_ex).run()
    assert r2.ok
    assert monde.en.appels and len(monde.en.appels) == 1                  # l'enrôlement n'est pas rejoué : le jeton est à usage unique
    assert not any(c.startswith("wg-monter") for c in ok_ex.commandes())


def test_un_second_passage_ne_refait_rien(monde):
    moteur(monde).run()
    n = len(monde.ex.appels)
    r = moteur(monde).run()
    assert r.ok and len(monde.ex.appels) == n and len(monde.en.appels) == 1


def test_enrolement_refuse_arrete_avant_le_tunnel(monde):
    r = moteur(monde, enroleur=FauxEnroleur(erreur=M.EnrolementRefuse("jeton refusé"))).run()
    assert not r.ok and r.etape == "enrolement" and "jeton refusé" in r.detail
    assert not any(c.startswith("wg-monter") for c in monde.ex.commandes())


def test_reponse_de_tunnel_hostile_jamais_ecrite(monde, monkeypatch):
    mauvais = {"tunnel": dict(TUNNEL, endpoint="evil.com:1"), "client": "c", "profil": "lite"}
    monte = []
    import autoload_agent.tunnel as TT
    monkeypatch.setattr(TT, "monter", lambda reponse, *a, **k: (TT.valider(reponse, *(a[2:3] or [])), monte.append(reponse)))     # le vrai validateur, sans système
    r = moteur(monde, enroleur=FauxEnroleur(mauvais)).run()
    assert not r.ok and r.etape == "tunnel" and not monte


def test_profil_hors_liste_refuse(monde):
    monde.cfg.reponses.write_text(monde.cfg.reponses.read_text().replace('profil = "lite"', 'profil = "actuel"'))
    r = moteur(monde).run()
    assert not r.ok and r.etape == "plan" and "profil" in r.detail


def test_nom_de_paquet_hostile_dans_la_simulation_refuse(monde):
    class Hostile(FauxExecuteur):
        def __call__(self, argv, **kw):
            r = super().__call__(argv, **kw)
            if "-s" in argv:
                r.stdout = "Inst secubox-core (1)\nInst ; rm -rf / (1)\nInst -oAPT::x=1 (1)\n"
            return r
    r = moteur(monde, executeur=Hostile()).run()
    assert not r.ok and r.etape == "plan"


def test_reponses_non_signees_ou_invalides_arretent_tout(monde, monkeypatch):
    def refuse(*a, **k):
        raise V.SignatureInvalide("signature refusée")
    monkeypatch.setattr(V, "verifier_signature", refuse)
    r = moteur(monde).run()
    assert not r.ok and r.etape == "reponses" and not monde.en.appels and not monde.ex.appels


def test_jeton_dans_un_fichier_lisible_par_tous_refuse(monde):
    os.chmod(monde.secrets / "autoload-jeton", 0o644)
    r = moteur(monde).run()
    assert not r.ok and r.etape == "enrolement" and not monde.en.appels


def test_jeton_hors_du_dossier_des_secrets_refuse(monde):
    monde.cfg.reponses.write_text(monde.cfg.reponses.read_text().replace("ref:/etc/secubox/secrets/autoload-jeton", "ref:/etc/secubox/secrets/../../passwd"))
    r = moteur(monde).run()
    assert not r.ok and r.etape == "reponses"


def test_l_etat_est_prive_et_ne_contient_aucun_secret(monde):
    moteur(monde).run()
    assert stat.S_IMODE(monde.cfg.etat.stat().st_mode) == 0o600
    brut = monde.cfg.etat.read_text() + (monde.cfg.rapport.read_text() if monde.cfg.rapport.exists() else "")
    assert "a" * 32 not in brut and "argon2" not in brut


def test_le_rapport_liste_ce_qui_a_ete_fait(monde):
    moteur(monde).run()
    rap = json.loads(monde.cfg.rapport.read_text())
    assert rap["client"] == "client-042" and rap["profil"] == "lite" and "secubox-ad-guard" in rap["paquets"] and rap["tunnel"]["adresse"] == "10.64.0.2/32"


# ── intégration avec le client (#2187, #2188, #2189) ─────────────────────────────────────────────────────
def test_une_infrastructure_injoignable_arrete_le_parcours_qui_reprendra_plus_tard(monde):
    def panne(jeton, serie, cle_pub, infra):
        raise OSError("infrastructure injoignable")
    r = moteur(monde, enroleur=panne).run()
    assert not r.ok and r.etape == "enrolement" and "indisponible" in r.detail
    assert json.loads(monde.cfg.etat.read_text())["faites"] == ["reponses", "cle"]
    assert moteur(monde).run().ok                                         # elle revient : le parcours reprend à l'enrôlement


def test_le_rapporteur_suit_chaque_etape_puis_termine(monde):
    vus = []
    m = M.Moteur(monde.cfg, executeur=monde.ex, enroleur=monde.en, valideur=lambda p: True, rapporteur=lambda *a: vus.append(a))
    assert m.run().ok
    assert [v[1] for v in vus][:-1] == sorted({v[1] for v in vus[:-1]})     # le nombre d'étapes faites ne fait que croître
    assert vus[-1][1:] == (len(M.ETAPES), len(M.ETAPES), True) and all(v[2] == len(M.ETAPES) for v in vus)
    assert {v[0] for v in vus} >= {"cle", "enrolement", "tunnel", "plan", "validation", "installation", "application"}


def test_un_rapporteur_en_panne_n_arrete_jamais_le_parcours(monde):
    def casse(*a):
        raise OSError("tunnel pas encore monté")
    assert M.Moteur(monde.cfg, executeur=monde.ex, enroleur=monde.en, valideur=lambda p: True, rapporteur=casse).run().ok


def test_la_fabrique_de_valideur_recoit_les_reponses_signees(monde):
    vus = []

    def fabrique(reponses):
        vus.append(reponses["provision"]["mode"])
        return lambda plan: True
    assert M.Moteur(monde.cfg, executeur=monde.ex, enroleur=monde.en, fabrique_valideur=fabrique).run().ok
    assert vus == ["auto"]


def test_un_valideur_explicite_prime_sur_la_fabrique(monde):
    appels = []
    assert not M.Moteur(monde.cfg, executeur=monde.ex, enroleur=monde.en, valideur=lambda p: False, fabrique_valideur=lambda r: appels.append(1) or (lambda p: True)).run().ok
    assert appels == []
