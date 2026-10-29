# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""waf-profils-fusion (#3193) : les services et vhosts LIVRÉS absents de la box
arrivent ; rien de ce que l'opérateur a posé n'est touché.

/etc/secubox/waf/vhost_profiles.json est un conffile modifié à l'exécution (cases
anti-robots du panneau Vhost, vhosts ajoutés comme git.maegia.tv) : avec
--force-confold la version livrée n'arrivait jamais, et le service livekit de
la Visio (#3193) serait resté inconnu de la box.
"""

import importlib.machinery
import importlib.util
import json
import re
import subprocess
from pathlib import Path

import pytest

RACINE = Path(__file__).resolve().parents[1]
CHEMIN = RACINE / "scripts" / "waf-profils-fusion"
_loader = importlib.machinery.SourceFileLoader("waf_profils_fusion", str(CHEMIN))
_spec = importlib.util.spec_from_loader("waf_profils_fusion", _loader)
fusion = importlib.util.module_from_spec(_spec)
_loader.exec_module(fusion)

PAQUET = RACINE.parents[1]
POSTINST = PAQUET / "debian" / "postinst"
RULES = PAQUET / "debian" / "rules"
LIVRE_REEL = RACINE / "config" / "vhost_profiles.json"

LIVEKIT = {
    "_note": "signalisation LiveKit",
    "legit_paths": ["^/rtc(/v1)?(/validate)?$"],
    "suppress_categories": ["credential_harvest"],
}


def livre_minimal():
    return {
        "_comment": "livré",
        "services": {
            "gitea": {"legit_paths": ["^/api/v1/"]},
            "livekit": LIVEKIT,
        },
        "vhosts": {
            "gitea.gk2.secubox.in": "gitea",
            "livekit.gk1.secubox.in": "livekit",
            "livekit.gk2.secubox.in": "livekit",
        },
        "suppress_categories": ["scanners", "recon_crawler"],
        "anti_robots": ["gitea.gk2.secubox.in"],
    }


def box_gk2():
    """Copie de la box : ancienne version livrée + retouches de l'opérateur."""
    return {
        "_comment": "commentaire de l'opérateur",
        "services": {
            # Service retouché localement : il doit rester tel quel.
            "gitea": {"_note": "local", "legit_paths": ["^/api/v1/", "^/local/"]},
        },
        "vhosts": {
            "gitea.gk2.secubox.in": "gitea",
            "git.maegia.tv": "gitea",           # vhost ajouté par l'opérateur
        },
        "suppress_categories": ["scanners"],    # liste globale de l'opérateur
        "_comment_anti_robots": "#1216",
        "anti_robots": ["git.maegia.tv"],       # case cochée dans le panneau
    }


def poser(tmp_path, livre, vivant, mode=0o644):
    pl = tmp_path / "livre.json"
    pv = tmp_path / "waf" / "vhost_profiles.json"
    pv.parent.mkdir()
    pl.write_text(json.dumps(livre, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    pv.write_text(json.dumps(vivant, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    pv.chmod(mode)
    return pl, pv, tmp_path / "audit.log"


def lancer(monkeypatch, pl, pv, audit, *extra):
    monkeypatch.setattr("sys.argv", ["waf-profils-fusion", "--livre", str(pl), "--vivant", str(pv),
                                     "--audit", str(audit), *extra])
    return fusion.main()


# ── fusionne() : la règle, sans disque ──────────────────────────────────────

def test_ajoute_service_et_vhosts_absents():
    neuf, services, vhosts, _ = fusion.fusionne(livre_minimal(), box_gk2())
    assert services == ["livekit"]
    assert vhosts == ["livekit.gk1.secubox.in", "livekit.gk2.secubox.in"]
    assert neuf["services"]["livekit"] == LIVEKIT
    assert neuf["vhosts"]["livekit.gk1.secubox.in"] == "livekit"


def test_preserve_les_ajouts_locaux_et_les_valeurs_de_l_operateur():
    box = box_gk2()
    neuf, _, _, _ = fusion.fusionne(livre_minimal(), box)
    assert neuf["services"]["gitea"] == box["services"]["gitea"]      # jamais écrasé
    assert neuf["vhosts"]["git.maegia.tv"] == "gitea"
    assert neuf["anti_robots"] == ["git.maegia.tv"]                    # jamais touché
    assert neuf["suppress_categories"] == ["scanners"]                 # jamais touché
    assert neuf["_comment"] == "commentaire de l'opérateur"
    assert neuf["_comment_anti_robots"] == "#1216"
    # Toutes les clés de la box gardent leur valeur ; seules des clés s'ajoutent.
    for cle, val in box.items():
        if cle not in ("services", "vhosts"):
            assert neuf[cle] == val
    for nom, val in box["services"].items():
        assert neuf["services"][nom] == val
    for hote, val in box["vhosts"].items():
        assert neuf["vhosts"][hote] == val


def test_n_ecrase_jamais_un_vhost_existant_meme_ecrit_autrement():
    box = box_gk2()
    box["services"]["visio-locale"] = {"legit_paths": ["^/x$"]}
    box["vhosts"]["LiveKit.GK1.secubox.in"] = "visio-locale"   # sbxwaf normalise la casse
    neuf, _, vhosts, _ = fusion.fusionne(livre_minimal(), box)
    assert "livekit.gk1.secubox.in" not in neuf["vhosts"]
    assert neuf["vhosts"]["LiveKit.GK1.secubox.in"] == "visio-locale"
    assert vhosts == ["livekit.gk2.secubox.in"]


def test_vhost_livre_vers_un_service_introuvable_n_est_pas_ajoute():
    # sbxwaf refuse TOUT le fichier si un vhost renvoie à un service inconnu
    # (phase G entière désactivée) : la fusion ne doit jamais l'introduire.
    livre = livre_minimal()
    livre["vhosts"]["orphelin.example"] = "inexistant"
    neuf, _, vhosts, _ = fusion.fusionne(livre, box_gk2())
    assert "orphelin.example" not in neuf["vhosts"] and "orphelin.example" not in vhosts


def test_rien_a_ajouter_rend_la_copie_identique():
    box = box_gk2()
    box["services"]["livekit"] = {"legit_paths": ["^/rtc$"]}   # version locale, différente
    box["vhosts"].update({"livekit.gk1.secubox.in": "livekit", "livekit.gk2.secubox.in": "livekit"})
    neuf, services, vhosts, _ = fusion.fusionne(livre_minimal(), box)
    assert (services, vhosts) == ([], [])
    assert neuf == box
    assert neuf["services"]["livekit"] == {"legit_paths": ["^/rtc$"]}


# ── php_services (#3257) ────────────────────────────────────────────────────

def livre_php():
    livre = livre_minimal()
    livre["services"]["nextcloud"] = {"legit_paths": []}
    livre["services"]["roundcube"] = {"legit_paths": []}
    livre["php_services"] = ["nextcloud", "roundcube"]
    return livre


def test_fusion_ajoute_php_services(tmp_path, monkeypatch):
    pl, pv, audit = poser(tmp_path, livre_php(), box_gk2())
    assert lancer(monkeypatch, pl, pv, audit) == 10
    neuf = json.loads(pv.read_text(encoding="utf-8"))
    assert neuf["php_services"] == ["nextcloud", "roundcube"]
    assert "php_services ajoutés : nextcloud, roundcube" in audit.read_text(encoding="utf-8")


def test_fusion_garde_php_services_de_la_box():
    box = box_gk2()
    box["php_services"] = ["nextcloud", "perso"]
    neuf, _, _, php = fusion.fusionne(livre_php(), box)
    assert neuf["php_services"] == ["nextcloud", "perso", "roundcube"]
    assert php == ["roundcube"]


def test_fusion_php_service_inconnu_ignore():
    livre = livre_minimal()
    livre["php_services"] = ["fantome"]
    neuf, _, _, php = fusion.fusionne(livre, box_gk2())
    assert php == [] and "php_services" not in neuf


def test_fusion_rien_a_faire_php(tmp_path, monkeypatch):
    box = box_gk2()
    box["services"].update({"livekit": LIVEKIT, "nextcloud": {"legit_paths": []},
                            "roundcube": {"legit_paths": []}})
    box["vhosts"].update({"livekit.gk1.secubox.in": "livekit", "livekit.gk2.secubox.in": "livekit"})
    box["php_services"] = ["nextcloud", "roundcube"]
    pl, pv, audit = poser(tmp_path, livre_php(), box)
    octets, ino = pv.read_bytes(), pv.stat().st_ino
    assert lancer(monkeypatch, pl, pv, audit) == 0
    assert pv.read_bytes() == octets and pv.stat().st_ino == ino and not audit.exists()


def test_fusion_php_liste_malformee_refusee():
    box = box_gk2()
    box["php_services"] = "nextcloud"
    with pytest.raises(fusion.Refus):
        fusion.fusionne(livre_php(), box)


# ── main() : disque, atomicité, audit ───────────────────────────────────────

def test_ecrit_atomiquement_garde_le_mode_et_audite(tmp_path, monkeypatch):
    pl, pv, audit = poser(tmp_path, livre_minimal(), box_gk2(), mode=0o640)
    avant = pv.stat()
    assert lancer(monkeypatch, pl, pv, audit) == 10
    apres = pv.stat()
    assert apres.st_ino != avant.st_ino                       # remplacé par rename, pas réécrit en place
    assert (apres.st_mode & 0o7777) == 0o640
    assert (apres.st_uid, apres.st_gid) == (avant.st_uid, avant.st_gid)
    neuf = json.loads(pv.read_text(encoding="utf-8"))
    assert neuf["services"]["livekit"] == LIVEKIT
    assert neuf["anti_robots"] == ["git.maegia.tv"]
    assert [p.name for p in pv.parent.iterdir()] == ["vhost_profiles.json"]   # aucun temporaire laissé
    lignes = audit.read_text(encoding="utf-8").splitlines()
    assert len(lignes) == 1
    ligne = json.loads(lignes[0])
    assert set(ligne) == {"ts", "module", "action", "acteur", "detail"}
    assert (ligne["module"], ligne["action"], ligne["acteur"]) == ("waf", "profils-fusion", "root")
    assert re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", ligne["ts"])
    assert "livekit" in ligne["detail"] and "livekit.gk1.secubox.in" in ligne["detail"]


def test_idempotent_second_passage_sans_ecriture_ni_audit(tmp_path, monkeypatch):
    pl, pv, audit = poser(tmp_path, livre_minimal(), box_gk2())
    assert lancer(monkeypatch, pl, pv, audit) == 10
    octets, ino = pv.read_bytes(), pv.stat().st_ino
    assert lancer(monkeypatch, pl, pv, audit) == 0
    assert pv.read_bytes() == octets and pv.stat().st_ino == ino
    assert len(audit.read_text(encoding="utf-8").splitlines()) == 1   # pas de seconde ligne


def test_rien_qui_manque_ne_touche_a_rien(tmp_path, monkeypatch):
    box = box_gk2()
    box["services"]["livekit"] = LIVEKIT
    box["vhosts"].update({"livekit.gk1.secubox.in": "livekit", "livekit.gk2.secubox.in": "livekit"})
    pl, pv, audit = poser(tmp_path, livre_minimal(), box)
    octets, ino, mtime = pv.read_bytes(), pv.stat().st_ino, pv.stat().st_mtime_ns
    assert lancer(monkeypatch, pl, pv, audit) == 0
    assert pv.read_bytes() == octets
    assert (pv.stat().st_ino, pv.stat().st_mtime_ns) == (ino, mtime)
    assert not audit.exists()


def test_refuse_une_cible_lien_symbolique(tmp_path, monkeypatch):
    pl, pv, audit = poser(tmp_path, livre_minimal(), box_gk2())
    cible = tmp_path / "ailleurs.json"
    cible.write_bytes(pv.read_bytes())
    pv.unlink()
    pv.symlink_to(cible)
    octets = cible.read_bytes()
    assert lancer(monkeypatch, pl, pv, audit) == 1
    assert pv.is_symlink() and cible.read_bytes() == octets
    assert not audit.exists()


def test_refuse_un_dossier_lien_symbolique(tmp_path, monkeypatch):
    pl, pv, audit = poser(tmp_path, livre_minimal(), box_gk2())
    vrai = tmp_path / "vrai-dossier"
    pv.parent.rename(vrai)
    pv.parent.symlink_to(vrai)
    octets = (vrai / pv.name).read_bytes()
    assert lancer(monkeypatch, pl, pv, audit) == 1
    assert (vrai / pv.name).read_bytes() == octets
    assert not audit.exists()


def test_json_local_invalide_refuse_sans_rien_ecrire(tmp_path, monkeypatch):
    pl, pv, audit = poser(tmp_path, livre_minimal(), box_gk2())
    pv.write_text("{ pas du json", encoding="utf-8")
    assert lancer(monkeypatch, pl, pv, audit) == 1
    assert pv.read_text(encoding="utf-8") == "{ pas du json"
    assert not audit.exists()


def test_services_local_mal_forme_refuse(tmp_path, monkeypatch):
    box = box_gk2()
    box["services"] = ["pas", "un", "objet"]
    pl, pv, audit = poser(tmp_path, livre_minimal(), box)
    octets = pv.read_bytes()
    assert lancer(monkeypatch, pl, pv, audit) == 1
    assert pv.read_bytes() == octets


def test_copie_livree_absente_rien_a_faire(tmp_path, monkeypatch):
    pl, pv, audit = poser(tmp_path, livre_minimal(), box_gk2())
    pl.unlink()
    octets = pv.read_bytes()
    assert lancer(monkeypatch, pl, pv, audit) == 0
    assert pv.read_bytes() == octets and not audit.exists()


def test_copie_de_la_box_absente_rien_a_faire(tmp_path, monkeypatch):
    # Pas de fichier sur la box : dpkg le pose (conffile). La fusion ne crée rien.
    pl, pv, audit = poser(tmp_path, livre_minimal(), box_gk2())
    pv.unlink()
    assert lancer(monkeypatch, pl, pv, audit) == 0
    assert not pv.exists() and not audit.exists()


def test_essai_a_blanc(tmp_path, monkeypatch):
    pl, pv, audit = poser(tmp_path, livre_minimal(), box_gk2())
    octets = pv.read_bytes()
    assert lancer(monkeypatch, pl, pv, audit, "--dry-run") == 10
    assert pv.read_bytes() == octets and not audit.exists()


def test_copie_livree_reelle_sur_une_box_d_avant(tmp_path, monkeypatch):
    """Le fichier réellement livré, fusionné dans une box d'avant #3193."""
    livre = json.loads(LIVRE_REEL.read_text(encoding="utf-8"))
    box = json.loads(LIVRE_REEL.read_text(encoding="utf-8"))
    del box["services"]["livekit"]
    for h in [h for h, s in box["vhosts"].items() if s == "livekit"]:
        del box["vhosts"][h]
    box["vhosts"]["git.maegia.tv"] = "gitea"
    box["anti_robots"] = ["git.maegia.tv"]
    pl, pv, audit = poser(tmp_path, livre, box)
    assert lancer(monkeypatch, pl, pv, audit) == 10
    neuf = json.loads(pv.read_text(encoding="utf-8"))
    assert neuf["services"]["livekit"]["suppress_categories"] == ["credential_harvest"]
    for h in ("livekit.gk1.secubox.in", "livekit.gk2.secubox.in", "livekit.gk3.secubox.in"):
        assert neuf["vhosts"][h] == "livekit"
    assert neuf["anti_robots"] == ["git.maegia.tv"] and neuf["vhosts"]["git.maegia.tv"] == "gitea"
    assert "credential_harvest" not in neuf["suppress_categories"]
    for hote, service in neuf["vhosts"].items():
        assert service in neuf["services"], hote
    assert lancer(monkeypatch, pl, pv, audit) == 0


# ── paquet : installation et appel par le postinst ──────────────────────────

def test_rules_installe_l_outil_et_la_copie_de_reference():
    texte = RULES.read_text(encoding="utf-8")
    assert "composants/waf/scripts/waf-profils-fusion debian/secubox-waf-ng/usr/sbin/waf-profils-fusion" in texte
    # La copie de référence suit tout composants/waf/config vers /usr/share/secubox/waf.
    assert "cp -r composants/waf/config/. debian/secubox-waf-ng/usr/share/secubox/waf/" in texte


def test_postinst_fusionne_avant_le_redemarrage_unique_du_moteur():
    texte = POSTINST.read_text(encoding="utf-8")
    appel = texte.index("/usr/sbin/waf-profils-fusion")
    redemarrage = texte.index("systemctl restart secubox-waf-ng.service")
    # sbxwaf ne lit --vhost-profiles qu'au démarrage : la fusion doit précéder le
    # redémarrage (inconditionnel en configure) de la section 6, qui le lui fait
    # relire. Aucun redémarrage supplémentaire n'est ajouté.
    assert appel < redemarrage
    assert texte.count("restart secubox-waf-ng") == 1
    assert texte.index("configure)") < appel < texte.index("abort-upgrade|")


def test_postinst_posix():
    subprocess.run(["sh", "-n", str(POSTINST)], check=True, timeout=30, capture_output=True, text=True)
