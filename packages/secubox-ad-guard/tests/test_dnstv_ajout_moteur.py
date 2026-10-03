# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#1959 : le moteur enchaîne ajout automatique, règles, agrégation et application ; le contrôleur audite les appareils ajoutés."""
import importlib.machinery
import importlib.util
import json
import time
from pathlib import Path

import pytest

from api import dnstv, dnstv_auto as M, dnstv_profil as P, dnstv_regles as R
from test_dnstv_auto_moteur import Rep, classer, coupure, charger, regle_en_essai, REGLAGE  # noqa: F401
from test_dnstv_auto_rendu import charger_ctl, faux

MAC = "38:07:16:94:fb:5b"
V6 = "2a01:e0a:dec:c4e0:4951:bf00:df87:2c57"
SERVICES = "fwmrm.net FreeWheel publicite\nftven.fr France_Télévisions contenu\nyouboranqs01.com NPAW qualite_video\n"
SEED = "videos-pub.ftv-publicite.fr\nc.2mdn.net\n"


def charger_script(monkeypatch, tmp_path, etat):
    listes = tmp_path / "listes"
    listes.mkdir(exist_ok=True)
    (listes / "services.txt").write_text(SERVICES)
    (listes / "profil-tv-base.txt").write_text("# version: t\n" + SEED)
    monkeypatch.setattr(dnstv, "DOSSIER_ETAT", tmp_path)
    monkeypatch.setattr(dnstv, "DOSSIER_LISTES", listes)
    dnstv.ecrire_etat(etat, tmp_path)
    chemin = Path(__file__).resolve().parents[1] / "sbin" / "secubox-adguard-auto"
    loader = importlib.machinery.SourceFileLoader("sbx_tv_auto_1959", str(chemin))
    spec = importlib.util.spec_from_loader("sbx_tv_auto_1959", loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


def lancer(mod, sudo, maintenant, voisins=None):
    return mod.main(sudo=sudo, maintenant=maintenant, voisins=lambda: voisins if voisins is not None else {"192.168.1.128": MAC, V6: MAC},
                    locales=lambda: {"192.168.1.200"}, passerelles=lambda: {"192.168.1.254"})


def donnees_tv(tmp_path, t):
    """Deux jours de requêtes d'une TV : insertion publicitaire + deux services de contenu, sur les deux adresses."""
    evts = []
    for ip in ("192.168.1.128", V6):
        for dom, n in (("7cd77.v.fwmrm.net", 4), ("cloudreplay.ftven.fr", 10), ("infinity.youboranqs01.com", 5)):
            evts += [dnstv.Evenement(t - 600 + i, ip, dom, "A", "NOERROR", "ALLOWED") for i in range(n)]
    dnstv.Magasin(tmp_path / "dnstv.db").ajouter([(e, "") for e in evts])


def test_un_appareil_detecte_est_ajoute_avec_ses_regles_de_base_et_le_controleur_est_appele(monkeypatch, tmp_path):
    t = int(time.time())
    mod = charger_script(monkeypatch, tmp_path, {"actif": True, "ajout_auto": True, "clients": []})
    donnees_tv(tmp_path, t)
    appels = []
    assert lancer(mod, lambda: appels.append(1) or Rep(), t) == 0
    etat, _ = dnstv.lire_etat(tmp_path)
    assert {c["nom"] for c in etat["clients"]} == {"TV fb5b"} and {c["ip"] for c in etat["clients"]} == {"192.168.1.128", V6}
    assert R.charger(tmp_path).actives("tv-fb5b") == ["c.2mdn.net", "videos-pub.ftv-publicite.fr"]
    assert appels == [1] and A_suivi(tmp_path)["ajouts"] == [t]


def A_suivi(tmp_path):
    from api import dnstv_ajout
    return dnstv_ajout.charger_suivi(tmp_path)


def test_ajout_auto_desactive_n_ecrit_rien_et_n_appelle_pas_le_controleur(monkeypatch, tmp_path):
    t = int(time.time())
    mod = charger_script(monkeypatch, tmp_path, {"actif": True, "ajout_auto": False, "clients": [{"ip": "192.168.1.95", "nom": "TV banc", "mode": "observe"}]})
    donnees_tv(tmp_path, t)
    avant = (tmp_path / "etat.json").read_bytes()
    appels = []
    assert lancer(mod, lambda: appels.append(1) or Rep(), t) == 0
    assert (tmp_path / "etat.json").read_bytes() == avant and appels == [] and not (tmp_path / "regles.json").exists()


def test_deux_passages_dans_la_meme_heure_n_ajoutent_qu_un_appareil(monkeypatch, tmp_path):
    t = int(time.time())
    mod = charger_script(monkeypatch, tmp_path, {"actif": True, "ajout_auto": True, "clients": []})
    donnees_tv(tmp_path, t)
    appels = []
    lancer(mod, lambda: appels.append(1) or Rep(), t)
    mac2, ip2 = "aa:bb:cc:dd:ee:ff", "192.168.1.129"
    dnstv.Magasin(tmp_path / "dnstv.db").ajouter([(dnstv.Evenement(t - 300 + i, ip2, d, "A", "NOERROR", "ALLOWED"), "") for d in ("7cd77.v.fwmrm.net", "cloudreplay.ftven.fr", "x.youboranqs01.com") for i in range(8)])
    lancer(mod, lambda: appels.append(1) or Rep(), t + 600, voisins={"192.168.1.128": MAC, V6: MAC, ip2: mac2})
    etat, _ = dnstv.lire_etat(tmp_path)
    assert {c["nom"] for c in etat["clients"]} == {"TV fb5b"}                      # le second attend l'heure écoulée
    lancer(mod, lambda: appels.append(1) or Rep(), t + 3700, voisins={"192.168.1.128": MAC, V6: MAC, ip2: mac2})
    etat, _ = dnstv.lire_etat(tmp_path)
    assert {c["nom"] for c in etat["clients"]} == {"TV fb5b", "TV eeff"}


def test_agregation_candidats_aux_autres_appareils_jamais_actifs_et_profil_ecrit(monkeypatch, tmp_path):
    t = int(time.time())
    mod = charger_script(monkeypatch, tmp_path, {"actif": True, "clients": [{"ip": "192.168.1.95", "nom": "TV a", "mode": "auto"},
                                                                          {"ip": "192.168.1.96", "nom": "TV b", "mode": "auto"},
                                                                          {"ip": "192.168.1.97", "nom": "TV c", "mode": "auto"}]})
    r = R.Regles()
    for app in ("tv-a", "tv-b"):
        rid = r.proposer(app, "pub.example.com", 50, "faible", t - 100, origine="admin")["id"]
        r.transiter(rid, "essai", "admin", "", t - 100)
        r.transiter(rid, "confirme", "admin", "ok", t - 90)
    R.ecrire(r, tmp_path)
    appels = []
    assert lancer(mod, lambda: appels.append(1) or Rep(), t, voisins={}) == 0
    apres = R.charger(tmp_path)
    c = [x for x in apres.liste() if x["appareil"] == "tv-c"]
    assert [x["etat"] for x in c] == ["candidat"] and apres.actives("tv-c") == []
    assert "pub.example.com" in P.charger_agrege(tmp_path)
    assert appels == []                                                          # un simple candidat ne demande aucune application


def test_echec_du_controleur_apres_un_ajout_laisse_l_application_due(monkeypatch, tmp_path):
    t = int(time.time())
    mod = charger_script(monkeypatch, tmp_path, {"actif": True, "ajout_auto": True, "clients": []})
    donnees_tv(tmp_path, t)
    assert lancer(mod, lambda: Rep(1), t) == 1
    assert (tmp_path / ".a-appliquer").exists()
    appels = []
    assert lancer(mod, lambda: appels.append(1) or Rep(), t + 60) == 0 and appels == [1] and not (tmp_path / ".a-appliquer").exists()


def test_passerelles_lit_la_route_par_defaut():
    class Rj:
        stdout = '[{"dst":"default","gateway":"192.168.1.254","dev":"eth2"}]'
    assert dnstv.passerelles(executer=lambda *a, **k: Rj()) == {"192.168.1.254"}

    def echec(*a, **k):
        raise OSError
    assert dnstv.passerelles(executer=echec) == set()


def test_reglage_depuis_lit_les_nouveaux_seuils(tmp_path):
    toml = tmp_path / "ad-guard.toml"
    toml.write_text("[adblock_tv_auto]\nmax_par_jour = 5\ndelai_s = 120\nretrait_jours = 3\nmin_declencheurs = 9\nmin_services = 3\nmin_appareils_agreg = 4\n")
    r = M.reglage_depuis({"auto_essai": False}, toml)
    assert (r.max_par_jour, r.delai_s, r.retrait_jours, r.min_declencheurs, r.min_services, r.min_appareils_agreg) == (5, 120, 3, 9, 3, 4)
    toml.write_text("[adblock_tv_auto]\nmax_par_jour = -1\ndelai_s = \"x\"\n")
    assert M.reglage_depuis({}, toml).max_par_jour == 3                             # valeur invalide : défaut


def test_le_controleur_audite_les_appareils_ajoutes_et_retires(monkeypatch, tmp_path):
    faux(tmp_path, "checkconf")
    mod = charger_ctl(monkeypatch, tmp_path, faux(tmp_path, "unbound-control"))
    dnstv.ecrire_etat({"actif": True, "clients": [{"ip": "192.168.1.95", "nom": "TV banc", "mode": "auto"}]}, tmp_path)
    mod.appliquer()
    dnstv.ecrire_etat({"actif": True, "clients": [{"ip": "192.168.1.95", "nom": "TV banc", "mode": "auto"},
                                                  {"ip": "192.168.1.128", "nom": "TV fb5b", "mode": "auto", "mac": MAC, "origine": "auto", "ajoute": 1800000000, "preuve": "12 requêtes vers fwmrm.net"}]}, tmp_path)
    mod.regles_appliquer()
    audit = (tmp_path / "audit.log").read_text()
    assert "appareil" in audit and "TV fb5b" in audit and "192.168.1.128" in audit and "origine=auto" in audit and "fwmrm.net" in audit
    dnstv.ecrire_etat({"actif": True, "clients": [{"ip": "192.168.1.95", "nom": "TV banc", "mode": "auto"}]}, tmp_path)
    mod.regles_appliquer()
    assert "- 192.168.1.128 retiré du périmètre" in (tmp_path / "audit.log").read_text()


def test_le_controleur_audite_l_activation_de_l_ajout_automatique_et_le_mode_par_defaut(monkeypatch, tmp_path):
    faux(tmp_path, "checkconf")
    mod = charger_ctl(monkeypatch, tmp_path, faux(tmp_path, "unbound-control"))
    base = {"actif": True, "clients": [{"ip": "192.168.1.95", "nom": "TV banc", "mode": "auto"}]}
    dnstv.ecrire_etat(base, tmp_path)
    mod.appliquer()
    dnstv.ecrire_etat(dict(base, ajout_auto=True, mode_defaut="observe"), tmp_path)
    mod.regles_appliquer()
    audit = (tmp_path / "audit.log").read_text()
    assert '"action": "ajout_auto"' in audit and "actif=True" in audit and "mode_defaut=observe" in audit
