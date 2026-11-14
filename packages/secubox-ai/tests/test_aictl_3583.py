# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Contrôleur root secubox-aictl et unités (#3583). Le script est chargé par chemin (fonctions importées) ; aucun
privilège : chemins redirigés par les variables R2, identités et root simulés, systemctl remplacé par un faux qui
journalise ses appels."""
import importlib.machinery
import importlib.util
import io
import json
import math
import os
import stat
import struct
import sys
import time
from pathlib import Path

import pytest

PAQUET = Path(__file__).resolve().parents[1]
SCRIPT = PAQUET / "sbin" / "secubox-aictl"
SYSTEMD = PAQUET / "systemd"


def _charger():
    if "secubox_aictl_teste" in sys.modules:
        return sys.modules["secubox_aictl_teste"]
    chargeur = importlib.machinery.SourceFileLoader("secubox_aictl_teste", str(SCRIPT))
    spec = importlib.util.spec_from_loader("secubox_aictl_teste", chargeur)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["secubox_aictl_teste"] = mod
    chargeur.exec_module(mod)
    return mod


# ── GGUF synthétique (architecture llama : 114 688 octets de cache par jeton, 448 Mo pour 4 096 jetons) ──

def _s(t):
    b = t.encode()
    return struct.pack("<Q", len(b)) + b


def _kv(cle, valeur):
    if isinstance(valeur, str):
        return _s(cle) + struct.pack("<I", 8) + _s(valeur)
    return _s(cle) + struct.pack("<II", 4, valeur)


LLAMA = {"general.architecture": "llama", "llama.block_count": 28, "llama.attention.head_count_kv": 8,
         "llama.attention.key_length": 128, "llama.attention.value_length": 128}
PAR_JETON = 114688


def ecrire_gguf(chemin, meta=LLAMA):
    corps = b"".join(_kv(k, v) for k, v in meta.items())
    chemin.write_bytes(b"GGUF" + struct.pack("<IQQ", 3, 0, len(meta)) + corps)
    chemin.chmod(0o640)
    return chemin


# ── environnement simulé ──

class Env:
    def __init__(self, ctl, tmp_path, monkeypatch):
        self.ctl, self.tmp, self.mp = ctl, tmp_path, monkeypatch
        self.etat = tmp_path / "etat"
        self.modeles = self.etat / "modeles"
        self.modeles.mkdir(parents=True)
        self.run = tmp_path / "run"
        self.conf = tmp_path / "ai.toml"
        (tmp_path / "secrets").mkdir()
        self.cle = tmp_path / "secrets" / "ai" / "distant.key"
        self.audit = tmp_path / "audit.log"
        self.journal = tmp_path / "systemctl.log"
        self.unite = tmp_path / "unite.etat"
        self.meminfo = tmp_path / "meminfo"
        for nom, val in (("SECUBOX_AI_ETAT", self.etat), ("SECUBOX_AI_RUN", self.run), ("SECUBOX_AI_CONF", self.conf),
                         ("SECUBOX_AI_CLE", self.cle), ("SECUBOX_AI_AUDIT", self.audit)):
            monkeypatch.setenv(nom, str(val))
        uid, gid = os.getuid(), os.getgid()
        self.ids = {"racine": uid, "gid_racine": gid, "api": uid, "gid_ai": gid, "gid_moteur": gid}
        self.identites_reelles = ctl._identites
        monkeypatch.setattr(ctl, "_identites", lambda: dict(self.ids))
        monkeypatch.setattr(ctl, "_root", lambda: True)
        monkeypatch.setattr(ctl, "PROPRIETAIRE_CONFIG", uid)
        monkeypatch.setattr(ctl, "MEMINFO", str(self.meminfo))
        monkeypatch.setattr(ctl, "DROPIN_API", tmp_path / "secubox-ai.service.d")
        monkeypatch.setattr(ctl, "RESOLV", tmp_path / "resolv.conf")     # absent : jamais celui du poste de test
        monkeypatch.setattr(ctl, "PAS_PRET", 0.01)
        monkeypatch.setattr(ctl, "DELAI_PRET", 0.5)
        faux = tmp_path / "systemctl"
        faux.write_text(f"""#!/bin/sh
printf '%s\\n' "$*" >> '{self.journal}'
case "$1" in
  show) cat '{self.unite}' 2>/dev/null || echo inactive ;;
  start) echo "${{FAUX_ETAT_APRES_START:-active}}" > '{self.unite}' ;;
  stop) echo inactive > '{self.unite}' ;;
esac
exit 0
""")
        faux.chmod(0o755)
        monkeypatch.setattr(ctl, "SYSTEMCTL", str(faux))
        # Le moteur répond dès que l'unité est « active ».
        monkeypatch.setattr(ctl, "sante_moteur", lambda delai=2.0: self.etat_unite() == "active")
        # Chaque état publié est aussi noté dans le journal du faux systemctl (ordre des opérations, R18).
        ecrire = ctl.ecrire_etat

        def ecrire_note(etat, message=""):
            with open(self.journal, "a") as f:
                sock = (self.run / "moteur.sock").exists()
                f.write(f"ETAT {etat}{' (socket présente)' if sock else ''}\n")
            ecrire(etat, message)

        monkeypatch.setattr(ctl, "ecrire_etat", ecrire_note)
        self.memoire(8000)
        self.prefs('[moteur]\nmodele = "m.gguf"\n')
        ctl.preparer_dossiers()

    def etat_unite(self):
        return self.unite.read_text().strip() if self.unite.exists() else "inactive"

    def memoire(self, mo):
        self.meminfo.write_text(f"MemTotal:       8000000 kB\nMemFree:  1000 kB\nMemAvailable:   {int(mo * 1024)} kB\n")

    def appels(self):
        return self.journal.read_text().splitlines() if self.journal.exists() else []

    def etat_publie(self):
        return json.loads((self.run / "moteur-etat.json").read_text())

    def audits(self):
        return [json.loads(x) for x in self.audit.read_text().splitlines()] if self.audit.exists() else []

    def modele(self, nom="m.gguf"):
        return ecrire_gguf(self.modeles / nom)

    def prefs(self, texte):
        (self.etat / "preferences.toml").write_text(texte)


@pytest.fixture
def ctl():
    return _charger()


@pytest.fixture
def env(ctl, tmp_path, monkeypatch):
    return Env(ctl, tmp_path, monkeypatch)


# ── démarrage : mémoire, contexte, MemoryMax ──

def test_memoire_insuffisante_code_4_et_aucune_unite_demarree(ctl, env, capsys):
    env.modele()
    env.prefs('[moteur]\nmodele = "m.gguf"\n')
    env.memoire(900)                       # 900 − 512 = 388 Mo < 448 Mo (cache du contexte minimal) + poids
    assert ctl.executer_action("demarrer", "root") == 4
    appels = env.appels()
    assert not any(a.startswith(("start", "set-property", "restart")) for a in appels)
    assert not (env.run / "moteur.env").exists()
    e = env.etat_publie()
    assert e["etat"] == "refus_memoire" and "mémoire insuffisante" in e["message"]
    assert "moteur distant" in e["message"] and e["horodatage"] > time.time() - 60
    assert "mémoire insuffisante" in capsys.readouterr().err
    assert env.audits()[-1]["issue"] == "refus_memoire"


def test_seuil_de_refus_exact(ctl, env):
    f = env.modele()
    besoin = f.stat().st_size / 1024 ** 2 + PAR_JETON * 4096 / 1024 ** 2
    env.memoire(512 + besoin - 1)
    assert ctl.executer_action("demarrer", "root") == 4
    env.memoire(512 + besoin + 1)
    assert ctl.executer_action("demarrer", "root") == 0


def test_demarrer_env_memorymax_puis_start_et_pret(ctl, env):
    f = env.modele()
    env.prefs('[moteur]\nmodele = "m.gguf"\n')
    env.memoire(2000)
    assert ctl.executer_action("demarrer", "root") == 0
    poids = f.stat().st_size / 1024 ** 2
    # Contexte automatique : poids + cache + 300 Mo tiennent dans MemAvailable − 512 Mo.
    ctx = int((2000 - 512 - 300 - poids) * 1024 ** 2 // PAR_JETON) // 1024 * 1024
    memmax = math.ceil(poids + PAR_JETON * ctx / 1024 ** 2 + 300)
    assert ctx == 10240 and memmax <= 2000 - 512
    env_txt = (env.run / "moteur.env").read_text()
    assert env_txt == f"MODELE={env.modeles / 'm.gguf'}\nCTX={ctx}\nMEMMAX={memmax}M\n"
    assert stat.S_IMODE((env.run / "moteur.env").stat().st_mode) == 0o640
    appels = env.appels()
    i_prop = appels.index(f"set-property --runtime secubox-ai-moteur.service MemoryMax={memmax}M")
    assert i_prop < appels.index("start secubox-ai-moteur.service")
    e = env.etat_publie()
    assert e["etat"] == "pret"
    assert stat.S_IMODE((env.run / "moteur-etat.json").stat().st_mode) == 0o640
    assert env.audits()[-1].items() >= {"issue": "pret", "contexte": ctx, "memoire_max_mo": memmax}.items()


def test_contexte_borne_a_32768_et_contexte_manuel_jamais_au_dela_de_l_auto(ctl, env):
    env.modele()
    env.memoire(64000)
    assert ctl.executer_action("demarrer", "root") == 0
    assert "CTX=32768\n" in (env.run / "moteur.env").read_text()
    ctl.executer_action("arreter", "root")
    env.prefs('[moteur]\nmodele = "m.gguf"\ncontexte = 8192\n')
    assert ctl.executer_action("demarrer", "root") == 0
    assert "CTX=8192\n" in (env.run / "moteur.env").read_text()
    ctl.executer_action("arreter", "root")
    env.memoire(2000)                      # l'automatique tombe à 10 240 : le réglage manuel 16 384 est ramené
    env.prefs('[moteur]\nmodele = "m.gguf"\ncontexte = 16384\n')
    assert ctl.executer_action("demarrer", "root") == 0
    assert "CTX=10240\n" in (env.run / "moteur.env").read_text()


def test_redemarrer_arrete_l_ancien_moteur_avant_de_publier_demarrage(ctl, env):
    env.modele()
    env.unite.write_text("active\n")
    (env.run / "moteur.sock").write_text("")          # socket de l'ancien moteur
    assert ctl.executer_action("redemarrer", "api") == 0
    appels = env.appels()
    i_stop = appels.index("stop secubox-ai-moteur.service")
    i_dem = appels.index("ETAT demarrage")             # socket retirée : pas de « (socket présente) »
    i_start = appels.index("start secubox-ai-moteur.service")
    assert i_stop < i_dem < i_start < appels.index("ETAT pret")
    assert not any(a.startswith("ETAT") for a in appels[:i_stop])


def test_arreter_publie_arrete_et_retire_la_socket(ctl, env):
    env.unite.write_text("active\n")
    (env.run / "moteur.sock").write_text("")
    assert ctl.executer_action("arreter", "root") == 0
    assert "stop secubox-ai-moteur.service" in env.appels()
    assert not (env.run / "moteur.sock").exists()
    assert env.etat_publie()["etat"] == "arrete"


def test_demarrer_deja_actif_ne_relance_rien(ctl, env):
    env.modele()
    env.unite.write_text("active\n")
    assert ctl.executer_action("demarrer", "root") == 0
    assert not any(a.startswith(("start", "stop", "set-property")) for a in env.appels())


def test_occupe_code_5(ctl, env):
    env.modele()
    with ctl.Verrou():
        assert ctl.executer_action("demarrer", "root") == 5
    assert "start secubox-ai-moteur.service" not in env.appels()


def test_moteur_tombe_au_chargement_erreur_publiee(ctl, env, monkeypatch):
    env.modele()
    monkeypatch.setenv("FAUX_ETAT_APRES_START", "failed")
    assert ctl.executer_action("demarrer", "root") == 1
    e = env.etat_publie()
    assert e["etat"] == "erreur" and "arrêté au chargement" in e["message"]


def test_aucun_modele_erreur_sans_demarrage(ctl, env):
    assert ctl.executer_action("demarrer", "root") == 1
    assert env.etat_publie()["etat"] == "erreur"
    assert "start secubox-ai-moteur.service" not in env.appels()


def test_entete_illisible_erreur_sans_demarrage(ctl, env):
    (env.modeles / "m.gguf").write_bytes(b"pas un gguf" * 10)
    (env.modeles / "m.gguf").chmod(0o640)
    assert ctl.executer_action("demarrer", "root") == 1
    assert "illisible" in env.etat_publie()["message"]
    assert "start secubox-ai-moteur.service" not in env.appels()


# ── choix du modèle : rien de ce qu'écrit le compte de l'API n'est suivi ──

def test_preference_valide_retenue(ctl, env):
    env.modele("pref.gguf")
    env.modele(ctl.MODELE_DEFAUT)
    env.prefs('[moteur]\nmodele = "pref.gguf"\n')
    assert ctl.executer_action("demarrer", "root") == 0
    assert f"MODELE={env.modeles / 'pref.gguf'}\n" in (env.run / "moteur.env").read_text()


def test_modele_lien_refuse_repli_sur_la_configuration(ctl, env):
    vrai = ecrire_gguf(env.tmp / "ailleurs.gguf")
    (env.modeles / "lien.gguf").symlink_to(vrai)
    env.modele("conf.gguf")
    env.conf.write_text('[moteur_local]\nmodele = "conf.gguf"\n')
    env.conf.chmod(0o644)
    env.prefs('[moteur]\nmodele = "lien.gguf"\n')
    assert ctl.executer_action("demarrer", "root") == 0
    assert f"MODELE={env.modeles / 'conf.gguf'}\n" in (env.run / "moteur.env").read_text()


@pytest.mark.parametrize("nom", ["../etat/m.gguf", "m.txt", "mmproj-x-f16.gguf", "m-00001-of-00002.gguf"])
def test_nom_de_modele_invalide_ignore(ctl, env, nom):
    env.modele(ctl.MODELE_DEFAUT)
    env.prefs(f'[moteur]\nmodele = "{nom}"\n')
    assert ctl.executer_action("demarrer", "root") == 0
    assert f"MODELE={env.modeles / ctl.MODELE_DEFAUT}\n" in (env.run / "moteur.env").read_text()


def test_preferences_en_lien_ignorees(ctl, env):
    env.modele("pref.gguf")
    env.modele(ctl.MODELE_DEFAUT)
    autre = env.tmp / "autre.toml"
    autre.write_text('[moteur]\nmodele = "pref.gguf"\n')
    (env.etat / "preferences.toml").unlink()
    (env.etat / "preferences.toml").symlink_to(autre)
    assert ctl.executer_action("demarrer", "root") == 0
    assert f"MODELE={env.modeles / ctl.MODELE_DEFAUT}\n" in (env.run / "moteur.env").read_text()


def test_modele_d_un_autre_proprietaire_refuse(ctl, env):
    env.modele()
    env.ids["api"] = os.getuid() + 1
    env.ids["racine"] = os.getuid() + 2           # ni l'API ni root : refusé (dossiers compris)
    with pytest.raises(ctl.Echec):
        ctl.choisir_modele(env.ids, ctl.CONFIG_DEFAUT)


def test_configuration_inscriptible_par_le_groupe_refusee(ctl, env):
    env.conf.write_text("[moteur_local]\nmodele = \"x.gguf\"\n")
    env.conf.chmod(0o664)
    with pytest.raises(ctl.Refus):
        ctl.charger_conf()


def test_regles_de_nom_identiques_a_l_api(ctl):
    from api import reglages

    assert ctl.NOM_MODELE.pattern == reglages.NOM_MODELE.pattern
    assert ctl.CONFIG_DEFAUT == reglages.CONFIG_DEFAUT and ctl.MODELE_DEFAUT == reglages.DEFAUTS["moteur"]["modele"]
    for nom in ("a.gguf", "mmproj-a-f16.gguf", "a_mtp-q8.gguf", "a-00001-of-00003.gguf", "draft-x.gguf"):
        assert ctl._genre_modele(nom) == (reglages.genre_fichier(nom) == "modele")


# ── clé du moteur distant ──

class _Entree:
    def __init__(self, octets):
        self.buffer = io.BytesIO(octets)

    def isatty(self):
        return False


def test_cle_distante_lue_sur_stdin_ecrite_0640_jamais_affichee(ctl, env, monkeypatch, capsys):
    cle = "sk-gk0-" + "a1B2" * 12
    monkeypatch.setattr(sys, "stdin", _Entree((cle + "\n").encode()))
    assert ctl.cmd_cle_distante() == 0
    assert env.cle.read_text() == cle + "\n"
    assert stat.S_IMODE(env.cle.stat().st_mode) == 0o640
    assert stat.S_IMODE(env.cle.parent.stat().st_mode) == 0o750
    sortie = capsys.readouterr()
    assert cle not in sortie.out and cle not in sortie.err
    assert cle not in env.audit.read_text() and env.audits()[-1]["issue"] == "posee"
    assert not [p for p in env.cle.parent.iterdir() if p.name != "distant.key"]   # aucun temporaire laissé


@pytest.mark.parametrize("entree", [b"", b"\n", b"   \n", b"ab cd\n", b"cl\xc3\xa9\n", b"a\x01b\n", b"x" * 5000])
def test_cle_vide_ou_invalide_refusee_rien_ecrit(ctl, env, monkeypatch, capsys, entree):
    monkeypatch.setattr(sys, "stdin", _Entree(entree))
    assert ctl.cmd_cle_distante() == 2
    assert not env.cle.exists()
    if entree.strip():
        sortie = capsys.readouterr()
        assert entree.strip().decode("latin-1") not in sortie.out + sortie.err


def test_cle_remplacee_atomiquement(ctl, env, monkeypatch):
    for cle in ("premiere-cle", "seconde-cle"):
        monkeypatch.setattr(sys, "stdin", _Entree(cle.encode()))
        assert ctl.cmd_cle_distante() == 0
    assert env.cle.read_text() == "seconde-cle\n"


# ── demandes de l'API ──

@pytest.fixture
def executees(ctl, env, monkeypatch):
    faites = []
    monkeypatch.setattr(ctl, "executer_action", lambda action, acteur, attendre=False: faites.append(action) or 0)
    return faites


def _deposer(env, nom, age=0.0):
    f = env.run / "demandes" / nom
    f.write_text("")
    if age:
        t = time.time() - age
        os.utime(f, (t, t))
    return f


def test_demande_au_nom_invalide_ignoree_et_tracee(ctl, env, executees, capsys):
    _deposer(env, "bidon.demande")
    _deposer(env, "demarrer.demande.x")
    assert ctl.traiter_demandes() == 0
    assert executees == []
    assert sorted(os.listdir(env.run / "demandes")) == []
    traces = [a for a in env.audits() if a["evenement"] == "demande"]
    assert {a["nom"] for a in traces} == {"bidon.demande", "demarrer.demande.x"}
    assert all(a["issue"] == "ignoree" for a in traces)
    assert "nom invalide" in capsys.readouterr().err


def test_une_demande_par_passage_la_plus_ancienne_d_abord(ctl, env, executees):
    _deposer(env, "arreter.demande", age=30)
    _deposer(env, "demarrer.demande")
    assert ctl.traiter_demandes() == 0
    assert executees == ["arreter"]
    assert os.listdir(env.run / "demandes") == ["demarrer.demande"]
    assert ctl.traiter_demandes() == 0
    assert executees == ["arreter", "demarrer"] and os.listdir(env.run / "demandes") == []


def test_demande_lien_ou_d_un_autre_compte_refusee(ctl, env, executees):
    cible = env.tmp / "cible"
    cible.write_text("")
    (env.run / "demandes" / "demarrer.demande").symlink_to(cible)
    assert ctl.traiter_demandes() == 0
    assert executees == [] and cible.exists()
    assert env.audits()[-1].items() >= {"issue": "refusee", "nom": "demarrer.demande"}.items()
    _deposer(env, "arreter.demande")
    env.ids["api"] = os.getuid() + 1                # déposée par le moteur, ou tout autre compte du groupe
    assert ctl.traiter_demandes() == 0
    assert executees == [] and env.audits()[-1]["detail"] == "propriétaire inattendu"


def test_temporaire_de_l_api_attendu_puis_purge(ctl, env, executees):
    _deposer(env, ".demarrer.abc123.tmp")
    _deposer(env, ".arreter.vieux.tmp", age=600)
    assert ctl.traiter_demandes() == 0
    assert os.listdir(env.run / "demandes") == [".demarrer.abc123.tmp"]
    assert executees == []


def test_depot_de_l_api_reel_traite(ctl, env, executees, monkeypatch):
    """La demande telle que la dépose moteurs.deposer_demande (Tâche 4) est reconnue."""
    from api import moteurs

    moteurs.deposer_demande("redemarrer")
    assert ctl.traiter_demandes() == 0
    assert executees == ["redemarrer"]


# ── preparer : dossiers et adresses LAN de l'API (R13) ──

def test_dossiers_d_execution_modes_et_lien_ecarte(ctl, env):
    assert stat.S_IMODE(env.run.stat().st_mode) == 0o1770
    assert stat.S_IMODE((env.run / "demandes").stat().st_mode) == 0o1770
    assert stat.S_IMODE((env.run / "ctl").stat().st_mode) == 0o700
    (env.run / "demandes").rmdir()
    piege = env.tmp / "piege"
    piege.mkdir()
    (env.run / "demandes").symlink_to(piege)
    ctl.preparer_dossiers()
    assert (env.run / "demandes").is_dir() and not (env.run / "demandes").is_symlink()
    assert stat.S_IMODE(piege.stat().st_mode) != 0o1770       # jamais suivi
    assert any(p.name.startswith(".demandes.ecarte-") for p in env.run.iterdir())


def test_preparer_rouvre_les_seules_adresses_lan_de_la_configuration(ctl, env, monkeypatch):
    env.conf.write_text('[gk2]\nmenaces_url = "https://admin.gk2.secubox.in/api/v1"\n'
                        'sources_url = "https://hall.gk2.secubox.in/api/v1/zia/objets"\n'
                        '[distant]\nurl = "http://192.168.1.30:8090"\n'
                        '[searxng]\nurl = "http://10.100.0.85:8888"\n')
    env.conf.chmod(0o644)
    resolus = {"admin.gk2.secubox.in": {"192.168.1.20", "203.0.113.5", "fd00::20"},
               "hall.gk2.secubox.in": {"127.0.0.1", "169.254.169.254"}}
    monkeypatch.setattr(ctl, "resoudre", lambda h: resolus[h])
    assert ctl.cmd_preparer() == 0
    texte = (ctl.DROPIN_API / "50-adresses.conf").read_text()
    lignes = [x for x in texte.splitlines() if x.startswith("IPAddressAllow")]
    assert lignes == ["IPAddressAllow=10.100.0.85/32 192.168.1.20/32 192.168.1.30/32 fd00::20/128"]
    assert "[Service]" in texte
    assert env.appels().count("daemon-reload") == 1
    assert ctl.cmd_preparer() == 0                     # inchangé : pas de nouvelle relecture de systemd
    assert env.appels().count("daemon-reload") == 1
    refus = [a for a in env.audits() if a["evenement"] == "preparer"][-1]["refus"]
    assert any("127.0.0.1" in r for r in refus) and any("169.254.169.254" in r for r in refus)


def test_drop_in_sans_adresse_ne_remet_pas_la_liste_a_zero(ctl):
    texte = ctl.texte_dropin([])
    assert "IPAddressAllow" not in texte and "[Service]" in texte


def test_preparer_nom_non_resolu_et_configuration_refusee(ctl, env, monkeypatch):
    env.conf.write_text('[gk2]\nmenaces_url = "https://inconnu.example/api"\nsources_url = ""\n')
    env.conf.chmod(0o644)

    def echoue(h):
        raise OSError("non résolu")

    monkeypatch.setattr(ctl, "resoudre", echoue)
    assert ctl.cmd_preparer() == 0
    assert "IPAddressAllow" not in (ctl.DROPIN_API / "50-adresses.conf").read_text()
    env.conf.chmod(0o666)
    assert ctl.cmd_preparer() == 2
    assert "IPAddressAllow" not in (ctl.DROPIN_API / "50-adresses.conf").read_text()


# ── ligne de commande ──

def test_usage_et_privileges(ctl, env, monkeypatch, capsys):
    assert ctl.main(["inconnu"]) == 2
    assert ctl.main(["etat", "--bidon"]) == 2
    assert ctl.main(["demarrer", "--json"]) == 2
    monkeypatch.setattr(ctl, "_root", lambda: False)
    for verbe in ("demarrer", "arreter", "redemarrer", "preparer", "cle-distante", "demandes"):
        assert ctl.main([verbe]) == 2
    capsys.readouterr()
    assert ctl.main(["etat", "--json"]) == 0
    vue = json.loads(capsys.readouterr().out)
    assert vue["unite"] == "inactive" and vue["socket"] is False


# ── unités systemd ──

def _unite(nom):
    texte = (SYSTEMD / nom).read_text()
    assert texte.startswith("# SPDX-License-Identifier: LicenseRef-CMSD-1.0")
    cles = {}
    for ligne in texte.splitlines():
        if "=" in ligne and not ligne.startswith("#"):
            k, v = ligne.split("=", 1)
            cles.setdefault(k.strip(), []).append(v.strip())
    return cles


SOCLE = {"NoNewPrivileges": "yes", "ProtectSystem": "strict", "ProtectHome": "yes", "PrivateTmp": "yes",
         "PrivateDevices": "yes", "ProtectKernelTunables": "yes", "ProtectKernelModules": "yes",
         "ProtectKernelLogs": "yes", "ProtectControlGroups": "yes", "ProtectClock": "yes",
         "ProtectHostname": "yes", "RestrictSUIDSGID": "yes", "RestrictNamespaces": "yes",
         "RestrictRealtime": "yes", "LockPersonality": "yes", "SystemCallArchitectures": "native"}


def test_unite_api(ctl):
    u = _unite("secubox-ai.service")
    for k, v in SOCLE.items():
        assert u[k] == [v], k
    assert u["User"] == ["secubox-ai"] and u["UMask"] == ["0027"] and u["CapabilityBoundingSet"] == [""]
    assert u["AppArmorProfile"] == ["secubox-ai-api"]
    assert u["RestrictAddressFamilies"] == ["AF_UNIX AF_INET AF_INET6"]
    assert u["IPAddressDeny"] == ["localhost link-local multicast 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 "
                                  "100.64.0.0/10 fc00::/7 fe80::/10"]
    assert u["IPAddressAllow"] == ["127.0.0.1/32"]     # le résolveur de la box (Unbound), le reste par preparer
    assert any("--uds /run/secubox/ai.sock" in x for x in u["ExecStart"])
    assert "+/bin/rm -f /run/secubox/ai.sock" in u["ExecStartPre"]
    assert "secubox-ai-preparer.service" in " ".join(u["After"]) and "RuntimeDirectory" not in u


def test_unite_moteur(ctl):
    u = _unite("secubox-ai-moteur.service")
    for k, v in SOCLE.items():
        assert u[k] == [v], k
    assert u["User"] == ["secubox-ai-moteur"] and u["Group"] == ["secubox-ai"] and u["UMask"] == ["0007"]
    # -np 1 : une seule place, le budget mémoire (cache du contexte) est calculé pour une.
    assert u["ExecStart"] == ["/usr/lib/secubox/zia-llm/llama-server -m ${MODELE} -c ${CTX} -np 1 -t 4 --jinja "
                              "--no-webui --host /run/secubox-ai/moteur.sock"]
    assert u["EnvironmentFile"] == ["/run/secubox-ai/moteur.env"]
    assert u["IPAddressDeny"] == ["any"] and u["PrivateNetwork"] == ["yes"]
    assert u["RestrictAddressFamilies"] == ["AF_UNIX"] and u["CapabilityBoundingSet"] == [""]
    assert u["BindReadOnlyPaths"] == ["/var/lib/secubox/ai/modeles"]
    assert "/etc/secubox/secrets" in " ".join(u["InaccessiblePaths"])
    assert u["MemorySwapMax"] == ["0"] and "\n[Install]" not in (SYSTEMD / "secubox-ai-moteur.service").read_text()


def test_unites_demandes_et_preparer(ctl):
    p = _unite("secubox-ai-demandes.path")
    assert p["PathExistsGlob"] == ["/run/secubox-ai/demandes/*.demande"]
    assert p["Unit"] == ["secubox-ai-demandes.service"]
    s = _unite("secubox-ai-demandes.service")
    assert s["Type"] == ["oneshot"] and s["ExecStart"] == ["/usr/sbin/secubox-aictl demandes"]
    assert s["IPAddressDeny"] == ["any"] and s["RestrictAddressFamilies"] == ["AF_UNIX"]
    assert s["NoNewPrivileges"] == ["yes"] and s["ProtectSystem"] == ["strict"]
    r = _unite("secubox-ai-preparer.service")
    assert r["Type"] == ["oneshot"] and r["ExecStart"] == ["/usr/sbin/secubox-aictl preparer"]
    assert "secubox-ai.service" in " ".join(r["Before"])


# ── relecture de la Tâche 13 : borne d'audit, dépôt jamais bloqué, délai de chargement ──

def test_rafale_de_noms_invalides_audit_borne_et_resume(ctl, env, executees):
    for i in range(50):
        _deposer(env, f"x{i:02d}.demande")
    assert ctl.traiter_demandes() == 0
    assert os.listdir(env.run / "demandes") == [] and executees == []
    traces = [a for a in env.audits() if a["evenement"] == "demande"]
    detail = [a for a in traces if a["issue"] in ("ignoree", "refusee")]
    resume = [a for a in traces if a["issue"] == "ignorees"]
    assert len(detail) == ctl.AUDIT_MAX_PASSAGE == 20
    assert len(resume) == 1 and resume[0]["nombre"] == 50


def test_ecartes_purges_apres_une_heure(ctl, env, executees):
    d = env.run / "demandes"
    for nom, age in ((".ecarte.vieux", 7200), (".ecarte.recent", 10)):
        (d / nom).mkdir()
        (d / nom / "dedans").write_text("x")
        t = time.time() - age
        os.utime(d / nom, (t, t))
    lien = d / ".ecarte.lien"
    cible = env.tmp / "a-garder"
    cible.mkdir()
    (cible / "f").write_text("x")
    lien.symlink_to(cible)
    t = time.time() - 7200
    os.utime(lien, (t, t), follow_symlinks=False)
    assert ctl.traiter_demandes() == 0
    assert sorted(os.listdir(d)) == [".ecarte.recent"]
    assert (cible / "f").exists()                 # jamais suivi


def test_moteur_ne_voit_ni_le_depot_ni_le_verrou(ctl):
    u = _unite("secubox-ai-moteur.service")
    masques = " ".join(u["InaccessiblePaths"]).split()
    assert "/run/secubox-ai/demandes" in masques and "/run/secubox-ai/ctl" in masques


def test_erreur_avant_consommation_la_demande_est_retiree(ctl, env, executees, monkeypatch, capsys):
    _deposer(env, "demarrer.demande")

    def casse():
        raise KeyError("secubox-ai")              # compte absent : paquet mal configuré

    monkeypatch.setattr(ctl, "preparer_dossiers", casse)
    assert ctl.traiter_demandes() == 0
    assert os.listdir(env.run / "demandes") == [] and executees == []
    assert env.audits()[-1].items() >= {"evenement": "demande", "issue": "erreur"}.items()
    assert "Traceback" not in capsys.readouterr().err


def test_cle_distante_dossier_des_secrets_absent_message_clair(ctl, env, monkeypatch, capsys):
    (env.tmp / "secrets").rmdir()
    monkeypatch.setattr(sys, "stdin", _Entree(b"une-cle-valide\n"))
    assert ctl.cmd_cle_distante() == 1
    err = capsys.readouterr().err
    assert "absent" in err and "une-cle-valide" not in err
    assert not env.cle.exists()


def test_main_compte_absent_message_clair(ctl, env, monkeypatch, capsys):
    monkeypatch.setattr(ctl, "_identites", env.identites_reelles)
    monkeypatch.setattr(ctl, "COMPTE_API", "compte-inexistant-3583")
    for verbe in ("demarrer", "preparer"):
        assert ctl.main([verbe]) == 1
        err = capsys.readouterr().err
        assert "compte" in err and "non configuré" in err and "Traceback" not in err


def test_delai_de_chargement_depasse_le_moteur_est_arrete(ctl, env, monkeypatch):
    env.modele()
    monkeypatch.setattr(ctl, "sante_moteur", lambda delai=2.0: False)    # ne répond jamais
    monkeypatch.setattr(ctl, "DELAI_PRET", 0.1)
    assert ctl.executer_action("demarrer", "root") == 1
    appels = env.appels()
    assert appels.index("start secubox-ai-moteur.service") < appels.index("stop secubox-ai-moteur.service")
    assert appels.index("stop secubox-ai-moteur.service") < appels.index("ETAT erreur")
    assert env.etat_unite() == "inactive"
    assert "ne répond pas" in env.etat_publie()["message"] and "arrêté" in env.etat_publie()["message"]


# ── revue finale : aucun cycle d'ordre à l'amorçage (C1) ──

def test_path_des_demandes_sans_ordre_sur_preparer(ctl):
    # .path (Before=paths.target) après preparer (After=basic.target, qui suit paths.target) : cycle à l'amorçage.
    p = _unite("secubox-ai-demandes.path")
    assert "secubox-ai-preparer.service" not in " ".join(p.get("After", []))
    r = _unite("secubox-ai-preparer.service")
    assert "secubox-ai-demandes.path" not in " ".join(r.get("Before", []))
    # Le service des demandes reste ordonné après la préparation (dossiers d'exécution créés).
    assert "secubox-ai-preparer.service" in " ".join(_unite("secubox-ai-demandes.service")["After"])


def test_systemd_analyze_sans_cycle_d_ordre(ctl, tmp_path):
    import re
    import shutil
    import subprocess
    if not shutil.which("systemd-analyze"):
        pytest.skip("systemd-analyze absent")
    for f in SYSTEMD.iterdir():
        # Binaires absents du poste de test : remplacés par /bin/true (seul l'ordre est vérifié ici).
        texte = re.sub(r"^(ExecStart(?:Pre|Post)?=[+-]*)\S+", r"\1/bin/true", f.read_text(), flags=re.M)
        (tmp_path / f.name).write_text(texte)
    noms = " ".join(f.name for f in SYSTEMD.iterdir())
    (tmp_path / "test-ai.target").write_text(f"[Unit]\nDescription=t\nWants=basic.target paths.target {noms}\n")
    sortie = subprocess.run(["systemd-analyze", "verify", "--man=no", "./test-ai.target"], cwd=tmp_path,
                            capture_output=True, text=True, timeout=60)
    texte = sortie.stdout + sortie.stderr
    assert "ordering cycle" not in texte, texte


# ── revue finale : premier modèle (I3) ──

def test_modele_par_defaut_du_catalogue(ctl):
    import tomllib
    from api import modeles, reglages
    fichiers = {m["fichier"] for m in modeles.CATALOGUE}
    conf = tomllib.loads((PAQUET / "conf" / "ai.toml.example").read_text())
    assert conf["moteur_local"]["modele"] == "Llama-3.2-3B-Instruct-Q4_K_M.gguf"
    assert conf["moteur_local"]["modele"] in fichiers
    assert ctl.MODELE_DEFAUT == reglages.DEFAUTS["moteur"]["modele"] == conf["moteur_local"]["modele"]


def test_aucun_modele_installe(ctl, env):
    env.prefs("")
    with pytest.raises(ctl.Echec, match="aucun modèle local installé : téléchargez-en un"):
        ctl.choisir_modele(env.ids, ctl.CONFIG_DEFAUT)


def test_modele_installe_mais_pas_active(ctl, env):
    env.prefs("")
    env.modele("Qwen_Qwen3-0.6B-Q4_K_M.gguf")       # téléchargé, jamais activé, ni défaut ni préférence
    (env.modeles / "mmproj-x-f16.gguf").write_bytes(b"GGUF")
    with pytest.raises(ctl.Echec, match="modèle installé mais pas activé : activez-le dans l'onglet Modèles"):
        ctl.choisir_modele(env.ids, ctl.CONFIG_DEFAUT)


def test_seule_une_annexe_n_est_pas_un_modele_installe(ctl, env):
    env.prefs("")
    (env.modeles / "mmproj-x-f16.gguf").write_bytes(b"GGUF")
    with pytest.raises(ctl.Echec, match="aucun modèle local installé"):
        ctl.choisir_modele(env.ids, ctl.CONFIG_DEFAUT)


# ── revue finale : résolveurs de /etc/resolv.conf rouverts à l'API (gk3 résout par gk2) ──

def test_preparer_rouvre_les_resolveurs_prives_de_resolv_conf(ctl, env, monkeypatch):
    resolv = env.tmp / "resolv.conf"
    resolv.write_text("# généré\nsearch lan\nnameserver 192.168.1.200 # gk2\nnameserver 127.0.0.1\n"
                      "nameserver 9.9.9.9\nnameserver fd00::53\nnameserver fe80::1%eth0\nnameserver pas-une-ip\n"
                      "options edns0\n")
    monkeypatch.setattr(ctl, "RESOLV", resolv)
    env.conf.write_text('[gk2]\nmenaces_url = "http://192.168.1.20/api/v1"\nsources_url = ""\n')
    env.conf.chmod(0o644)
    assert ctl.cmd_preparer() == 0
    texte = (ctl.DROPIN_API / "50-adresses.conf").read_text()
    lignes = [x for x in texte.splitlines() if x.startswith("IPAddressAllow")]
    # Publique (9.9.9.9) déjà joignable, boucle déjà permise par l'unité, lien local jamais.
    assert lignes == ["IPAddressAllow=192.168.1.20/32 192.168.1.200/32 fd00::53/128"]
    refus = [a for a in env.audits() if a["evenement"] == "preparer"][-1]["refus"]
    assert any("fe80::1" in r for r in refus) and any("pas-une-ip" in r for r in refus)


def test_preparer_resolveurs_meme_si_la_configuration_est_refusee(ctl, env, monkeypatch):
    resolv = env.tmp / "resolv.conf"
    resolv.write_text("nameserver 192.168.1.200\n")
    monkeypatch.setattr(ctl, "RESOLV", resolv)
    env.conf.write_text('[gk2]\nmenaces_url = "http://192.168.1.20/api/v1"\n')
    env.conf.chmod(0o666)                                  # inscriptible par tous : configuration refusée
    assert ctl.cmd_preparer() == 2
    assert "IPAddressAllow=192.168.1.200/32\n" in (ctl.DROPIN_API / "50-adresses.conf").read_text()


def test_preparer_sans_resolv_conf(ctl, env, monkeypatch):
    monkeypatch.setattr(ctl, "RESOLV", env.tmp / "absent")
    env.conf.write_text('[gk2]\nmenaces_url = "http://192.168.1.20/api/v1"\nsources_url = ""\n')
    env.conf.chmod(0o644)
    assert ctl.cmd_preparer() == 0
    assert "IPAddressAllow=192.168.1.20/32\n" in (ctl.DROPIN_API / "50-adresses.conf").read_text()


def test_controleur_sans_cache_ecrit_par_root():
    # -B : root n'écrit jamais de __pycache__ (ni à côté du script, ni dans /usr/lib/secubox/ai) ; -I : isolé.
    assert SCRIPT.read_text().splitlines()[0] == "#!/usr/bin/python3 -IB"


def test_format_retire_jamais_servi_par_le_controleur(ctl):
    assert not ctl.nom_modele_valide("Llama-3.2-3B-Instruct-Q4_0_8_8.gguf")
    assert not ctl.nom_modele_valide("x.q4_0_4_4.gguf")
    assert ctl.nom_modele_valide("Llama-3.2-3B-Instruct-Q4_0.gguf")
