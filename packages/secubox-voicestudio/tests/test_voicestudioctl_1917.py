# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""voicestudioctl : configuration, réveil, publication, clé, audit (#1917) — sans toucher à un vrai LXC."""
import importlib.machinery
import importlib.util
import io
import json
import re
import stat
import tarfile
import tomllib
from pathlib import Path

import pytest

PKG = Path(__file__).resolve().parents[1]
loader = importlib.machinery.SourceFileLoader("voicestudioctl_t", str(PKG / "sbin" / "voicestudioctl"))
spec = importlib.util.spec_from_loader("voicestudioctl_t", loader)
c = importlib.util.module_from_spec(spec)
loader.exec_module(c)


class Rep:
    def __init__(self, rc=0, out="", err=""):
        self.returncode, self.stdout, self.stderr = rc, out, err


class LxcFaux:
    """Simule lxc-info / start / stop / attach / systemctl / ip ; l'état évolue comme un vrai conteneur."""
    def __init__(self, etat="STOPPED", adresses=" 2: eth0 inet 192.168.1.9/24 ...", ancien_actif=False):
        self.etat, self.appels, self.entrees, self.adresses = etat, [], [], adresses
        self.ancien_actif = ancien_actif

    def __call__(self, cmd, **k):
        self.appels.append(list(cmd))
        self.entrees.append(k.get("input"))
        if cmd[0] == "lxc-info":
            return Rep(0, self.etat) if self.etat != "ABSENT" else Rep(1)
        if cmd[0] == "lxc-start":
            self.etat = "RUNNING"
            return Rep(0)
        if cmd[0] == "lxc-stop":
            self.etat = "STOPPED"
            return Rep(0)
        if cmd[0] == "ip":
            return Rep(0, self.adresses)
        if cmd[0] == "systemctl" and cmd[1] == "is-active":
            if cmd[2] == c.ANCIENNE_UNITE:
                return Rep(0 if self.ancien_actif else 3, "active\n" if self.ancien_actif else "inactive\n")
            return Rep(0, "active\n")
        return Rep(0)

    def verbes(self):
        return [a[0] for a in self.appels]


@pytest.fixture(autouse=True)
def bac_a_sable(tmp_path, monkeypatch):
    conf = tmp_path / "voicestudio.toml"
    conf.write_text((PKG / "conf" / "voicestudio.toml").read_text())
    for nom, valeur in {
        "CONF": conf, "CONF_DEFAUT": PKG / "conf" / "voicestudio.toml",
        "CLE": tmp_path / "secrets" / "api_key", "ETAT": tmp_path / "etat.json",
        "MARQUE_INSTALLE": tmp_path / ".prov", "AUDIT": tmp_path / "audit.log",
        "SAUVEGARDES": tmp_path / "sauv", "DROPIN_DIR": tmp_path / "systemd",
        "VOLUME_PODMAN": tmp_path / "volume-podman", "VERROU": tmp_path / "verrou.lock", "NFT_DIR": tmp_path / "nft",
    }.items():
        monkeypatch.setattr(c, nom, valeur)
    (tmp_path / "lxc").mkdir()
    ecrit = c.charger()
    ecrit["lxc"]["chemin"] = str(tmp_path / "lxc")
    c.ecrire_toml("lxc", "chemin", str(tmp_path / "lxc"))
    c.ecrire_toml("lxc", "donnees", str(tmp_path / "donnees"))
    return tmp_path


# ── configuration ────────────────────────────────────────────────────────────
def test_le_toml_livre_est_valide_et_epingle():
    d = tomllib.loads((PKG / "conf" / "voicestudio.toml").read_text())
    assert len(d["source"]["commit"]) == 40
    assert len(d["source"]["sha256"]) == 64
    assert d["lxc"]["mode"] in c.MODES
    assert d["moteur"]["asr"] in c.ASR_ADMIS
    assert d["reseau"]["publier"] == []


def test_ecrire_toml_remplace_une_cle_et_garde_les_commentaires(bac_a_sable):
    c.ecrire_toml("lxc", "memoire", "6G")
    t = c.CONF.read_text()
    assert 'memoire = "6G"' in t
    assert "# SecuBox-Deb :: VoiceStudio" in t                  # commentaires préservés
    assert tomllib.loads(t)["lxc"]["memoire"] == "6G"
    assert tomllib.loads(t)["lxc"]["ip"] == "10.100.0.230"       # le reste n'a pas bougé


def test_ecrire_toml_ajoute_une_cle_absente_dans_la_bonne_section(bac_a_sable):
    c.CONF.write_text("[lxc]\nnom = \"x\"\n\n[moteur]\nasr = \"a\"\n")
    c.ecrire_toml("lxc", "mode", "demande")
    d = tomllib.loads(c.CONF.read_text())
    assert d["lxc"]["mode"] == "demande" and d["moteur"]["asr"] == "a"


def test_ecrire_toml_cree_la_section_manquante(bac_a_sable):
    c.CONF.write_text("[lxc]\nnom = \"x\"\n")
    c.ecrire_toml("reseau", "publier", ["192.168.1.9", "10.10.0.5"])
    assert tomllib.loads(c.CONF.read_text())["reseau"]["publier"] == ["192.168.1.9", "10.10.0.5"]


def test_fichier_de_conf_cree_en_0640(bac_a_sable):
    c.ecrire_toml("lxc", "mode", "demande")
    assert stat.S_IMODE(c.CONF.stat().st_mode) == 0o640


@pytest.mark.parametrize("cle,valeur", [
    ("asr", "Systran/faster-whisper-base"), ("memoire", "4G"), ("memoire", "2048M"),
    ("cpu_poids", "50"), ("mode", "demande"), ("inactivite_s", "900"),
])
def test_valeurs_admises(cle, valeur):
    c.valider_config(cle, valeur)


@pytest.mark.parametrize("cle,valeur", [
    ("asr", "evil/model; rm -rf /"), ("asr", "Systran/faster-whisper-base\nX=1"),
    ("memoire", "4G; reboot"), ("memoire", "0G"), ("memoire", "99G"), ("memoire", "512M"),
    ("cpu_poids", "0"), ("cpu_poids", "99999"), ("cpu_poids", "50 "),
    ("mode", "toujours"), ("inactivite_s", "10"), ("inactivite_s", "-5"),
    ("inconnue", "x"),
])
def test_valeurs_refusees(cle, valeur):
    with pytest.raises(c.Erreur):
        c.valider_config(cle, valeur)


def test_config_ecrit_le_toml_et_laudit(bac_a_sable):
    run = LxcFaux("STOPPED")
    assert c.cmd_config("mode", "demande", run) == 0
    assert tomllib.loads(c.CONF.read_text())["lxc"]["mode"] == "demande"
    assert "config mode=demande" in c.AUDIT.read_text()


def test_config_asr_pousse_le_modele_dans_le_lxc_et_redemarre_le_moteur(bac_a_sable):
    run = LxcFaux("RUNNING")
    c.cmd_config("asr", "Systran/faster-whisper-small", run)
    attaches = [a for a in run.appels if a[0] == "lxc-attach"]
    assert attaches and "faster-whisper-small" in " ".join(attaches[-1])
    assert "restart voicestudio.service" in " ".join(attaches[-1])


# ── LXC et mandataire ────────────────────────────────────────────────────────
def test_bloc_lxc_permanent_et_demande():
    cfg = c.charger()
    assert "lxc.start.auto = 1" in c.bloc_lxc(cfg)
    cfg["lxc"]["mode"] = "demande"
    assert "lxc.start.auto = 0" in c.bloc_lxc(cfg)
    assert "lxc.cgroup2.memory.max = 4G" in c.bloc_lxc(cfg)


def test_appliquer_lxc_remplace_le_bloc_sans_le_dupliquer(bac_a_sable):
    cfg = c.charger()
    f = Path(c.lxc_chemin(cfg)) / "voicestudio" / "config"
    f.parent.mkdir(parents=True)
    f.write_text("lxc.net.0.type = veth\n" + c.bloc_lxc(cfg) + "lxc.mount.entry = /x app/x none bind 0 0\n")
    c.ecrire_toml("lxc", "mode", "demande")
    c.ecrire_toml("lxc", "memoire", "2G")
    assert c.appliquer_lxc(c.charger())
    t = f.read_text()
    assert t.count(c.MARQUE_DEBUT) == 1 and t.count(c.MARQUE_FIN) == 1
    assert "lxc.start.auto = 0" in t and "memory.max = 2G" in t
    assert "lxc.net.0.type = veth" in t and "lxc.mount.entry" in t       # le reste est intact


def test_appliquer_lxc_sans_conteneur_ne_fait_rien():
    assert c.appliquer_lxc(c.charger()) is False


def test_socket_ecoute_les_adresses_publiees_et_toujours_le_loopback():
    cfg = c.charger()
    cfg["reseau"]["publier"] = ["192.168.1.9", "10.10.0.5"]
    s = c.contenu_socket(cfg)
    assert "ListenStream=192.168.1.9:3900" in s and "ListenStream=10.10.0.5:3900" in s
    assert "ListenStream=127.0.0.1:3900" in s
    assert "ListenStream=\n" in s                         # remise à zéro de la liste du paquet
    assert "0.0.0.0" not in s                              # jamais d'écoute sur toutes les interfaces


def test_service_permanent_ne_rendort_jamais_le_lxc():
    s = c.contenu_service(c.charger())
    assert "10.100.0.230:3900" in s
    assert "voicestudioctl sleep" not in s and "exit-idle-time" not in s


def test_service_demande_rendort_apres_inactivite():
    cfg = c.charger()
    cfg["lxc"]["mode"] = "demande"
    cfg["lxc"]["inactivite_s"] = 600
    s = c.contenu_service(cfg)
    assert "--exit-idle-time=600s" in s and "voicestudioctl sleep" in s


def test_appliquer_n_ecrit_les_dropins_qu_une_fois(bac_a_sable):
    run = LxcFaux()
    r1 = c.appliquer(run)
    assert r1["mandataire"] is True
    systemd = lambda: [a for a in run.appels if a[0] == "systemctl"]          # noqa: E731
    appels = len(systemd())
    r2 = c.appliquer(run)
    assert r2["mandataire"] is False and len(systemd()) == appels    # idempotent : pas de rechargement systemd


def test_reveil_demarre_le_lxc_endormi_et_attend_la_sante():
    run = LxcFaux("STOPPED")
    reps = iter([{"ok": False}, {"ok": False}, {"ok": False}, {"ok": True}])
    horloge = iter(range(0, 1000, 2))
    assert c.reveiller(c.charger(), run=run, sante_fn=lambda _c: next(reps),
                       dormir=lambda s: None, maintenant=lambda: next(horloge)) is True
    assert "lxc-start" in run.verbes()


def test_reveil_deja_en_service_ne_demarre_rien():
    run = LxcFaux("RUNNING")
    assert c.reveiller(c.charger(), run=run, sante_fn=lambda _c: {"ok": True}) is True
    assert "lxc-start" not in run.verbes()


def test_reveil_abandonne_apres_le_delai():
    run = LxcFaux("RUNNING")
    horloge = iter(range(0, 10000, 50))
    assert c.reveiller(c.charger(), run=run, sante_fn=lambda _c: {"ok": False},
                       dormir=lambda s: None, maintenant=lambda: next(horloge), delai=100) is False


def test_reveil_lxc_absent_echoue_sans_tenter_de_demarrer():
    run = LxcFaux("ABSENT")
    assert c.reveiller(c.charger(), run=run, sante_fn=lambda _c: {"ok": False}) is False
    assert "lxc-start" not in run.verbes()


def test_sommeil_arrete_un_lxc_actif_et_ignore_un_lxc_arrete():
    run = LxcFaux("RUNNING")
    assert c.endormir(c.charger(), run) and run.etat == "STOPPED"
    run.appels.clear()
    assert c.endormir(c.charger(), run) and "lxc-stop" not in run.verbes()


def test_stop_coupe_le_mandataire_puis_le_lxc(bac_a_sable):
    run = LxcFaux("RUNNING")
    assert c.cmd_stop(run) == 0
    stops = [a for a in run.appels if a[0] == "systemctl" and a[1] == "stop"]
    assert [a[2] for a in stops] == [c.SERVICE_PUB, c.SOCKET_PUB]
    assert run.etat == "STOPPED"


# ── publication ──────────────────────────────────────────────────────────────
def test_publier_accepte_une_adresse_de_la_box(bac_a_sable):
    run = LxcFaux()
    assert c.cmd_publier(["192.168.1.9"], run) == 0
    assert tomllib.loads(c.CONF.read_text())["reseau"]["publier"] == ["192.168.1.9"]
    assert "ListenStream=192.168.1.9:3900" in (c.DROPIN_DIR / f"{c.SOCKET_PUB}.d" / "adresses.conf").read_text()
    assert "publier 192.168.1.9" in c.AUDIT.read_text()


@pytest.mark.parametrize("adresse", ["8.8.8.8", "0.0.0.0", "192.168.1.9; reboot", "abc", "192.168.1", "::1"])
def test_publier_refuse_une_adresse_etrangere(adresse):
    with pytest.raises(c.Erreur):
        c.cmd_publier([adresse], LxcFaux())


def test_publier_vide_ne_laisse_que_le_loopback(bac_a_sable):
    c.cmd_publier([], LxcFaux())
    assert tomllib.loads(c.CONF.read_text())["reseau"]["publier"] == []


# ── clé d'API ────────────────────────────────────────────────────────────────
def test_la_cle_est_creee_en_0600_dans_un_repertoire_0700():
    assert c.creer_cle() is True
    assert stat.S_IMODE(c.CLE.stat().st_mode) == 0o600
    assert stat.S_IMODE(c.CLE.parent.stat().st_mode) == 0o700
    assert len(c.lire_cle()) >= 40


def test_la_cle_existante_n_est_jamais_ecrasee_par_init():
    c.creer_cle()
    avant = c.lire_cle()
    assert c.creer_cle() is False and c.lire_cle() == avant


def test_renouveler_change_la_cle_la_pousse_et_laudite(bac_a_sable, capsys):
    c.creer_cle()
    avant = c.lire_cle()
    run = LxcFaux("RUNNING")
    assert c.cmd_cle_renouveler(run) == 0
    nouvelle = c.lire_cle()
    assert nouvelle != avant and capsys.readouterr().out.strip() == nouvelle
    assert any(f"OMNIVOICE_API_KEY={nouvelle}" in (e or "") for e in run.entrees)   # poussée par stdin
    assert nouvelle not in c.AUDIT.read_text()               # la clé n'entre JAMAIS dans l'audit
    assert "cle-renouvelee" in c.AUDIT.read_text()


def test_la_cle_n_est_jamais_passee_en_argument(bac_a_sable):
    """Un argument se lit dans `ps` : la clé voyage par stdin seulement."""
    c.creer_cle()
    run = LxcFaux("RUNNING")
    c.pousser_cle(c.charger(), run)
    assert all(c.lire_cle() not in " ".join(a) for a in run.appels)


def test_pousser_cle_lxc_arrete_est_remis_a_plus_tard():
    c.creer_cle()
    assert c.pousser_cle(c.charger(), LxcFaux("STOPPED")) is False


# ── état ─────────────────────────────────────────────────────────────────────
def test_etat_lxc_arrete(bac_a_sable):
    e = c.etat_complet(LxcFaux("STOPPED"))
    assert e["lxc"] == "STOPPED" and e["moteur"] is False and e["mode"] == "permanent"
    assert e["commit"] == c.charger()["source"]["commit"][:12]
    assert "cle" not in e and not any("api_key" in k for k in e)      # aucun secret dans l'état


def test_etat_lxc_en_marche_et_moteur_sain(bac_a_sable):
    e = c.etat_complet(LxcFaux("RUNNING"), sante_fn=lambda _c: {"ok": True, "http": 200})
    assert e["moteur"] is True and e["http"] == 200


def test_etat_distingue_demarrage_et_panne(bac_a_sable):
    e = c.etat_complet(LxcFaux("RUNNING"), sante_fn=lambda _c: {"ok": False, "http": 503, "demarrage": True})
    assert e["moteur"] is False and e["demarrage"] is True


def test_etat_sans_privilege_retombe_sur_le_cache(bac_a_sable):
    """Sous `secubox`, lxc-info ne voit pas le conteneur : on ne conclut pas « absent »."""
    c.memoriser_etat("RUNNING")
    e = c.etat_complet(LxcFaux("ABSENT"))
    assert e["lxc"] == "RUNNING" and e["source"] == "cache"


def test_etat_compte_la_taille_des_donnees(bac_a_sable):
    d = Path(c.donnees(c.charger()))
    d.mkdir()
    (d / "voix.bin").write_bytes(b"x" * 2 * 1048576)
    assert c.etat_complet(LxcFaux("STOPPED"))["donnees_mo"] == 2.0


# ── sauvegarde et migration ──────────────────────────────────────────────────
def test_sauvegarde_exclut_les_modeles_et_garde_les_voix(bac_a_sable):
    d = Path(c.donnees(c.charger()))
    (d / "huggingface" / "hub").mkdir(parents=True)
    (d / "huggingface" / "hub" / "modele.bin").write_bytes(b"gros")
    (d / "voices").mkdir()
    (d / "voices" / "lexie.wav").write_bytes(b"voix")
    import sqlite3
    base = sqlite3.connect(d / "omnivoice.db")
    base.execute("create table voix(nom text)")
    base.execute("insert into voix values ('lexie')")
    base.commit()
    base.close()
    assert c.cmd_sauvegarde() == 0
    [archive] = list(c.SAUVEGARDES.glob("voicestudio-*.tar.gz"))
    noms = tarfile.open(archive).getnames()
    assert noms.count("omnivoice_data/omnivoice.db") == 1 and "omnivoice_data/voices/lexie.wav" in noms
    with tarfile.open(archive) as t:                       # la copie archivée est une base SQLite lisible
        t.extract("omnivoice_data/omnivoice.db", path=c.SAUVEGARDES / "x", filter="data")
    lecture = sqlite3.connect(c.SAUVEGARDES / "x" / "omnivoice_data" / "omnivoice.db")
    assert lecture.execute("select nom from voix").fetchall() == [("lexie",)]
    lecture.close()
    assert not any("huggingface/hub" in n for n in noms)
    assert stat.S_IMODE(archive.stat().st_mode) == 0o600
    assert stat.S_IMODE(c.SAUVEGARDES.stat().st_mode) == 0o700


def test_sauvegarde_ne_garde_que_les_dernieres(bac_a_sable):
    d = Path(c.donnees(c.charger()))
    d.mkdir()
    c.SAUVEGARDES.mkdir(parents=True)
    for i in range(6):
        (c.SAUVEGARDES / f"voicestudio-2026010{i}T000000Z.tar.gz").write_bytes(b"x")
    c.cmd_sauvegarde()
    assert len(list(c.SAUVEGARDES.glob("voicestudio-*.tar.gz"))) == c.SAUVEGARDES_GARDEES


def test_sauvegarde_sans_donnees_est_une_erreur_claire():
    with pytest.raises(c.Erreur):
        c.cmd_sauvegarde()


def test_migration_reprend_le_volume_et_ne_le_supprime_pas(bac_a_sable, monkeypatch):
    v = c.VOLUME_PODMAN
    v.mkdir()
    (v / "omnivoice.db").write_bytes(b"sqlite")
    (v / "voices").mkdir()
    (v / "voices" / "a.wav").write_bytes(b"a")
    chowns = []
    monkeypatch.setattr(c.os, "lchown", lambda p, u, g: chowns.append((p, u, g)))
    run = LxcFaux()
    real = c.subprocess.run

    def run_cp(cmd, **k):
        return real(cmd, **k) if cmd[0] == "cp" else run(cmd, **k)
    assert c.cmd_migrer_podman(run_cp) == 0
    cible = c.donnees(c.charger())
    assert (cible / "omnivoice.db").read_bytes() == b"sqlite" and (cible / "voices" / "a.wav").exists()
    assert (v / "omnivoice.db").exists()                                  # l'original reste
    assert chowns and all(u >= c.UID_BASE for _, u, _g in chowns)       # propriété décalée sur l'idmap
    assert not any(a[0] == "podman" for a in run.appels)                # jamais de pilotage podman


def test_migration_ne_fait_rien_si_les_donnees_existent(bac_a_sable):
    c.VOLUME_PODMAN.mkdir()
    cible = c.donnees(c.charger())
    cible.mkdir()
    (cible / c.MARQUE_MIGRATION).write_text("fait")
    run = LxcFaux()
    assert c.cmd_migrer_podman(run) == 0
    assert not any(a[0] in ("podman", "cp") for a in run.appels)


def test_migration_sans_volume_podman_est_un_non_evenement():
    assert c.cmd_migrer_podman(LxcFaux()) == 0


# ── porte du panneau (« api ») ───────────────────────────────────────────────
def appeler_api(requete) -> tuple[int, dict]:
    import contextlib
    sortie = io.StringIO()
    with contextlib.redirect_stdout(sortie):
        rc = c.cmd_api(requete if isinstance(requete, str) else json.dumps(requete))
    return rc, json.loads(sortie.getvalue())


def test_api_refuse_une_action_hors_liste_blanche():
    rc, r = appeler_api({"action": "rm"})
    assert rc == 1 and r["ok"] is False


def test_api_refuse_du_json_invalide():
    assert appeler_api("pas du json")[0] == 1
    assert appeler_api("[1,2]")[0] == 1


def test_api_ne_connait_pas_les_commandes_dangereuses():
    for interdite in ("migrer-podman", "reinstaller", "install", "wake", "sleep", "appliquer"):
        assert interdite not in c.ACTIONS_API


def test_api_cle_apercu_ne_revele_pas_la_cle():
    c.creer_cle()
    rc, r = appeler_api({"action": "cle-apercu"})
    assert rc == 0 and r["presente"] is True
    assert c.lire_cle() not in json.dumps(r) and "…" in r["apercu"]


def test_api_config_valide_les_valeurs():
    rc, r = appeler_api({"action": "config", "cle": "memoire", "valeur": "4G; reboot"})
    assert rc == 1 and r["ok"] is False


def test_api_publier_refuse_un_type_inattendu():
    rc, r = appeler_api({"action": "publier", "adresses": "192.168.1.9"})
    assert rc == 1 and r["ok"] is False
    rc, r = appeler_api({"action": "publier", "adresses": [1, 2]})
    assert rc == 1


def test_api_audite_l_administrateur_et_non_secubox(bac_a_sable, monkeypatch):
    monkeypatch.setattr(c.subprocess, "run", LxcFaux())
    appeler_api({"action": "config", "cle": "mode", "valeur": "demande", "par": "gandalf"})
    assert "by=gandalf" in c.AUDIT.read_text()


def test_api_ignore_un_nom_d_administrateur_suspect(bac_a_sable, monkeypatch):
    monkeypatch.setattr(c.subprocess, "run", LxcFaux())
    monkeypatch.setenv("SUDO_USER", "secubox")
    appeler_api({"action": "config", "cle": "mode", "valeur": "demande", "par": "x\nvoicestudio forged"})
    assert "forged" not in c.AUDIT.read_text()


def test_api_status_rend_du_json(bac_a_sable, monkeypatch):
    monkeypatch.setattr(c.subprocess, "run", LxcFaux("STOPPED"))
    rc, r = appeler_api({"action": "status"})
    assert rc == 0 and r["lxc"] == "STOPPED"


# ── migration de la configuration (ancien schéma podman) ─────────────────────
ANCIEN = """# SecuBox-Deb :: VoiceStudio (#1649)
image    = "ghcr.io/debpalash/voicestudio:stable"
empreinte = "sha256:588fe119082bb97e722f5e53fe7b0fe1a406885bf72a4c60889d3d03376d7768"
publier  = ["192.168.1.9", "10.10.0.5"]
memoire  = "4g"
asr      = "Systran/faster-whisper-base"
"""


def test_migrer_conf_cree_le_defaut_quand_rien_n_existe():
    c.CONF.unlink()
    assert c.cmd_migrer_conf() == 0
    assert tomllib.loads(c.CONF.read_text())["lxc"]["nom"] == "voicestudio"


def test_migrer_conf_reprend_les_adresses_publiees_de_l_ancien_schema():
    """gk2 joint le moteur de gk3 par 10.10.0.5 : les perdre couperait Lexie."""
    c.CONF.write_text(ANCIEN)
    assert c.cmd_migrer_conf() == 0
    d = tomllib.loads(c.CONF.read_text())
    assert d["reseau"]["publier"] == ["192.168.1.9", "10.10.0.5"]
    assert d["lxc"]["memoire"] == "4G"                      # « 4g » podman → « 4G » cgroup
    assert d["moteur"]["asr"] == "Systran/faster-whisper-base"
    assert "image" not in d and "empreinte" not in d and d["source"]["commit"]
    assert c.CONF.with_name(c.CONF.name + ".avant-lxc").read_text() == ANCIEN     # l'ancien est gardé
    assert "migrer-conf publier=192.168.1.9,10.10.0.5" in c.AUDIT.read_text()


def test_migrer_conf_ecarte_une_valeur_inexploitable():
    c.CONF.write_text(ANCIEN.replace('"4g"', '"beaucoup"').replace("faster-whisper-base", "evil"))
    c.cmd_migrer_conf()
    d = tomllib.loads(c.CONF.read_text())
    assert d["lxc"]["memoire"] == "4G" and d["moteur"]["asr"] == "Systran/faster-whisper-base"   # défauts


def test_migrer_conf_ne_touche_pas_a_un_fichier_deja_au_nouveau_schema():
    c.ecrire_toml("lxc", "mode", "demande")
    avant = c.CONF.read_text()
    c.cmd_migrer_conf()
    assert c.CONF.read_text() == avant
    assert not c.CONF.with_name(c.CONF.name + ".avant-lxc").exists()


def test_migrer_conf_est_idempotent():
    c.CONF.write_text(ANCIEN)
    c.cmd_migrer_conf()
    apres = c.CONF.read_text()
    c.cmd_migrer_conf()
    assert c.CONF.read_text() == apres


# ── bascule depuis podman ────────────────────────────────────────────────────
def lxc_present(bac):
    cfg = c.charger()
    (Path(c.lxc_chemin(cfg)) / "voicestudio").mkdir(parents=True, exist_ok=True)


def test_basculer_arrete_l_ancien_avant_de_copier_puis_demarre_le_lxc(bac_a_sable, monkeypatch):
    c.VOLUME_PODMAN.mkdir()
    (c.VOLUME_PODMAN / "omnivoice.db").write_bytes(b"sqlite")
    monkeypatch.setattr(c.os, "lchown", lambda *a: None)
    run = LxcFaux("RUNNING")
    reel = c.subprocess.run
    ordre = []

    def suivi(cmd, **k):
        ordre.append(cmd[0] if cmd[0] != "systemctl" else " ".join(cmd[:3]))
        return reel(cmd, **k) if cmd[0] == "cp" else run(cmd, **k)
    monkeypatch.setattr(c, "sante", lambda cfg, *a, **k: {"ok": True, "http": 200})
    c.creer_cle()
    assert c.cmd_basculer(suivi) == 0
    assert ordre.index("systemctl stop secubox-voicestudio.service") < ordre.index("cp")
    assert "lxc-stop" in ordre and ordre.index("lxc-stop") < ordre.index("cp")        # pas de copie sous le moteur
    assert (c.donnees(c.charger()) / "omnivoice.db").read_bytes() == b"sqlite"
    assert (c.VOLUME_PODMAN / "omnivoice.db").exists()                              # rien n'est supprimé
    assert "basculer ok" in c.AUDIT.read_text()


def test_basculer_sans_lxc_ne_touche_pas_a_l_ancien_moteur(bac_a_sable):
    c.VOLUME_PODMAN.mkdir()
    run = LxcFaux("ABSENT")
    with pytest.raises(c.Erreur):
        c.cmd_basculer(run)
    assert not any(a[0] in ("podman",) or a[:2] == ["systemctl", "stop"] for a in run.appels)


def test_basculer_dit_l_echec_et_garde_le_volume(bac_a_sable, monkeypatch, capsys):
    c.VOLUME_PODMAN.mkdir()
    (c.VOLUME_PODMAN / "omnivoice.db").write_bytes(b"sqlite")
    monkeypatch.setattr(c.os, "lchown", lambda *a: None)
    monkeypatch.setattr(c, "DELAI_REVEIL", 0)
    monkeypatch.setattr(c, "sante", lambda cfg, *a, **k: {"ok": False, "http": 0})
    run = LxcFaux("STOPPED")
    reel = c.subprocess.run
    c.creer_cle()
    rc = c.cmd_basculer(lambda cmd, **k: reel(cmd, **k) if cmd[0] == "cp" else run(cmd, **k))
    assert rc == 1 and "INTACT" in capsys.readouterr().err
    assert (c.VOLUME_PODMAN / "omnivoice.db").exists() and "basculer echec" in c.AUDIT.read_text()


def test_basculer_sans_ancien_moteur_demarre_simplement_le_lxc(bac_a_sable, monkeypatch):
    monkeypatch.setattr(c, "sante", lambda cfg, *a, **k: {"ok": True, "http": 200})
    c.creer_cle()
    run = LxcFaux("RUNNING")
    assert c.cmd_basculer(run) == 0
    assert not any(a[0] == "podman" for a in run.appels)


def test_migrer_podman_refuse_de_copier_sous_un_moteur_qui_tourne(bac_a_sable):
    """Une base SQLite copiée pendant qu'on y écrit est une base corrompue."""
    c.VOLUME_PODMAN.mkdir()
    (c.VOLUME_PODMAN / "omnivoice.db").write_bytes(b"sqlite")
    with pytest.raises(c.Erreur, match="tourne encore"):
        c.cmd_migrer_podman(LxcFaux(ancien_actif=True))
    assert not (c.donnees(c.charger()) / "omnivoice.db").exists()


def test_le_code_livre_ne_pilote_jamais_podman():
    """Pas de `podman …` dans le ctl : l'arrêt de l'ancien moteur passe par systemd seulement."""
    import re
    src = (PKG / "sbin" / "voicestudioctl").read_text()
    assert not re.search(r"""\[\s*["']podman["']|podman\s+(run|stop|rm|exec|ps|pull|inspect)""", src)


def test_appliquer_ne_demarre_pas_un_socket_inactif(bac_a_sable):
    """Installer ne doit pas ouvrir le port 3900 sans moteur derrière (ni échouer si l'ancien le tient)."""
    run = LxcFaux()
    base = run.__call__

    def inactif(cmd, **k):
        if cmd[:2] == ["systemctl", "is-active"] and cmd[2] == c.SOCKET_PUB:
            run.appels.append(list(cmd))
            return Rep(3, "inactive\n")
        return base(cmd, **k)
    c.appliquer(inactif)
    assert ["systemctl", "restart", c.SOCKET_PUB] not in run.appels
    assert ["systemctl", "daemon-reload"] in run.appels


def test_changer_de_mode_relance_le_mandataire_en_marche(bac_a_sable):
    run = LxcFaux()
    c.appliquer(run)
    run.appels.clear()
    c.ecrire_toml("lxc", "mode", "demande")
    c.appliquer(run)
    assert ["systemctl", "try-restart", c.SERVICE_PUB] in run.appels
    run.appels.clear()
    c.appliquer(run)                                     # rien n'a changé : on ne relance rien
    assert not any(a[0] == "systemctl" and a[1] in ("restart", "try-restart") for a in run.appels)


# ── moteur : première mise en service, clé renouvelée pendant le sommeil ─────
def test_assurer_moteur_ecrit_la_cle_par_stdin_et_demarre_le_moteur_s_il_est_arrete():
    c.creer_cle()
    run = LxcFaux("RUNNING")
    assert c.assurer_moteur(c.charger(), run, dormir=lambda s: None) is True
    [attache] = [a for a in run.appels if a[0] == "lxc-attach"]
    script = attache[-1]
    assert "cmp -s /etc/voicestudio.env.new /etc/voicestudio.env" in script
    assert "systemctl restart voicestudio.service" in script             # clé changée -> relance
    assert "systemctl is-active -q voicestudio.service || systemctl start voicestudio.service" in script
    assert f"OMNIVOICE_API_KEY={c.lire_cle()}" in run.entrees[-1]
    assert c.lire_cle() not in " ".join(attache)                          # jamais en argument


def test_assurer_moteur_retente_tant_que_le_lxc_ne_repond_pas_puis_le_dit(capsys):
    c.creer_cle()
    n = {"v": 0}

    def run(cmd, **k):
        n["v"] += 1
        return Rep(1 if cmd[0] == "lxc-attach" else 0)
    assert c.assurer_moteur(c.charger(), run, dormir=lambda s: None) is False
    assert n["v"] == 10 and "ne répond pas" in capsys.readouterr().err


def test_le_reveil_prepare_le_moteur_avant_d_attendre_la_sante():
    """Régression : LXC déjà actif après install, moteur jamais lancé -> on attendait 240 s pour rien."""
    ordre = []
    run = LxcFaux("RUNNING")
    sante = iter([{"ok": False}, {"ok": False}, {"ok": True}])
    horloge = iter(range(0, 1000, 2))

    def prep(cfg, r, dormir):
        ordre.append("preparer")
    assert c.reveiller(c.charger(), run=run, sante_fn=lambda _c: (ordre.append("sante"), next(sante))[1],
                       dormir=lambda s: None, maintenant=lambda: next(horloge), preparer=prep) is True
    assert ordre.index("preparer") < len(ordre) - 1 and ordre[:2] == ["sante", "preparer"]


def test_renouveler_pendant_le_sommeil_ecrit_sur_l_hote_et_laisse_le_reveil_pousser(bac_a_sable):
    c.creer_cle()
    avant = c.lire_cle()
    run = LxcFaux("STOPPED")
    c.cmd_cle_renouveler(run)
    assert c.lire_cle() != avant and not any(a[0] == "lxc-attach" for a in run.appels)
    # Au réveil, assurer_moteur voit la clé changée (cmp) et relance le moteur avec la nouvelle.
    run.etat = "RUNNING"
    c.assurer_moteur(c.charger(), run, dormir=lambda s: None)
    assert f"OMNIVOICE_API_KEY={c.lire_cle()}" in run.entrees[-1]


# ── exclusion mutuelle ───────────────────────────────────────────────────────
def test_deux_commandes_mutantes_ne_s_executent_pas_ensemble(bac_a_sable):
    import fcntl
    c.VERROU.parent.mkdir(parents=True, exist_ok=True)
    fd = open(c.VERROU, "w")
    fcntl.flock(fd, fcntl.LOCK_EX)                      # une installation « en cours »
    try:
        with pytest.raises(c.Erreur, match="autre opération"):
            c.cmd_config("mode", "demande", LxcFaux())
        with pytest.raises(c.Erreur, match="autre opération"):
            c.cmd_install(LxcFaux())
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        fd.close()
    assert c.cmd_config("mode", "demande", LxcFaux()) == 0          # le verrou est rendu


def test_le_verrou_est_reentrant_install_basculer_start(bac_a_sable, monkeypatch):
    monkeypatch.setattr(c, "sante", lambda cfg, *a, **k: {"ok": True, "http": 200})
    c.creer_cle()
    assert c.cmd_basculer(LxcFaux("RUNNING")) == 0     # basculer -> start : pas d'auto-blocage


def test_le_verrou_est_rendu_apres_une_erreur(bac_a_sable):
    with pytest.raises(c.Erreur):
        c.cmd_config("mode", "toujours", LxcFaux())
    assert c.cmd_config("mode", "demande", LxcFaux()) == 0


# ── publication : jamais une adresse publique ────────────────────────────────
@pytest.mark.parametrize("adresse", ["8.8.8.8", "82.67.100.75", "1.1.1.1", "0.0.0.0", "224.0.0.1"])
def test_publier_refuse_toute_adresse_publique(adresse):
    with pytest.raises(c.Erreur):
        c.cmd_publier([adresse], LxcFaux(adresses=f" 2: wan inet {adresse}/24 ..."))


@pytest.mark.parametrize("adresse", ["192.168.1.9", "10.10.0.5", "172.16.4.2", "100.64.1.1"])
def test_publier_accepte_lan_maillage_et_cgnat(bac_a_sable, adresse):
    assert c.cmd_publier([adresse], LxcFaux(adresses=f" 2: eth0 inet {adresse}/24 ...")) == 0


def test_une_adresse_publique_heritee_du_toml_n_ouvre_pas_de_socket(capsys):
    cfg = c.charger()
    cfg["reseau"]["publier"] = ["82.67.100.75", "192.168.1.9"]
    s = c.contenu_socket(cfg)
    assert "82.67.100.75" not in s and "192.168.1.9:3900" in s
    assert "ignorée" in capsys.readouterr().err


# ── configuration illisible : on s'arrête, on ne retombe pas sur les défauts ─
def test_un_toml_invalide_arrete_appliquer_au_lieu_d_effacer_les_adresses(bac_a_sable):
    c.cmd_publier(["192.168.1.9"], LxcFaux())
    c.CONF.write_text("[reseau\npublier = [")
    with pytest.raises(c.Erreur, match="invalide"):
        c.appliquer(LxcFaux())
    assert "192.168.1.9" in (c.DROPIN_DIR / f"{c.SOCKET_PUB}.d" / "adresses.conf").read_text()   # drop-in intact


def test_un_socket_qui_ne_se_relance_pas_est_dit(bac_a_sable, capsys):
    run = LxcFaux()
    base = run.__call__

    def refuse(cmd, **k):
        if cmd[:2] == ["systemctl", "restart"] and cmd[2] == c.SOCKET_PUB:
            run.appels.append(list(cmd))
            return Rep(1, "", "Address already in use")
        return base(cmd, **k)
    c.appliquer(refuse)
    c.ecrire_toml("reseau", "publier", ["192.168.1.9"])
    r = c.appliquer(refuse)
    assert r.get("mandataire_ok") is False and "port 3900" in capsys.readouterr().err


# ── migration atomique ───────────────────────────────────────────────────────
def test_une_copie_interrompue_ne_laisse_aucune_migration_a_moitie(bac_a_sable, monkeypatch):
    c.VOLUME_PODMAN.mkdir()
    (c.VOLUME_PODMAN / "omnivoice.db").write_bytes(b"sqlite")
    run = LxcFaux()
    reel = c.subprocess.run

    def cp_en_echec(cmd, **k):
        if cmd[0] == "cp":
            Path(cmd[-1]).mkdir(parents=True)
            (Path(cmd[-1]) / "omnivoice.db").write_bytes(b"tronq")
            return Rep(1, "", "No space left on device")
        return run(cmd, **k) if cmd[0] != "cp" else reel(cmd, **k)
    with pytest.raises(c.Erreur, match="copie du volume échouée"):
        c.cmd_migrer_podman(cp_en_echec)
    cible = c.donnees(c.charger())
    assert not cible.exists() and not Path(str(cible) + ".migration").exists()      # rien de tronqué ni de résiduel


def test_la_migration_decale_uid_et_gid_chacun_pour_son_compte(bac_a_sable, monkeypatch):
    c.VOLUME_PODMAN.mkdir()
    (c.VOLUME_PODMAN / "omnivoice.db").write_bytes(b"x")
    vus = []
    monkeypatch.setattr(c.os, "lchown", lambda p, u, g: vus.append((u, g)))
    reel_lstat = c.os.lstat

    class St:
        def __init__(self, st, u, g):
            self._st, self.st_uid, self.st_gid = st, u, g

        def __getattr__(self, nom):
            return getattr(self._st, nom)
    monkeypatch.setattr(c.os, "lstat", lambda p: St(reel_lstat(p), 0, 100999) if str(p).endswith("omnivoice.db")
                        else St(reel_lstat(p), 0, 0))
    run = LxcFaux()
    reel = c.subprocess.run
    c.cmd_migrer_podman(lambda cmd, **k: reel(cmd, **k) if cmd[0] == "cp" else run(cmd, **k))
    assert (c.UID_BASE, c.UID_BASE) in vus                 # 0/0 -> 100000/100000
    assert (c.UID_BASE, 100999) in vus                     # uid décalé, gid déjà dans l'idmap : inchangé


def test_la_migration_met_de_cote_une_base_vierge_au_lieu_de_l_ecraser(bac_a_sable, monkeypatch):
    c.VOLUME_PODMAN.mkdir()
    (c.VOLUME_PODMAN / "omnivoice.db").write_bytes(b"reelle")
    cible = c.donnees(c.charger())
    cible.mkdir()
    (cible / "omnivoice.db").write_bytes(b"vierge")        # le LXC a démarré une fois
    monkeypatch.setattr(c.os, "lchown", lambda *a: None)
    run = LxcFaux()
    reel = c.subprocess.run
    c.cmd_migrer_podman(lambda cmd, **k: reel(cmd, **k) if cmd[0] == "cp" else run(cmd, **k))
    assert (cible / "omnivoice.db").read_bytes() == b"reelle" and (cible / c.MARQUE_MIGRATION).exists()
    assert (Path(str(cible) + ".avant-migration") / "omnivoice.db").read_bytes() == b"vierge"


def test_migrer_refuse_si_le_lxc_tourne(bac_a_sable):
    c.VOLUME_PODMAN.mkdir()
    with pytest.raises(c.Erreur, match="LXC tourne"):
        c.cmd_migrer_podman(LxcFaux("RUNNING"))


def test_basculer_ne_copie_rien_si_l_ancien_moteur_tient_le_port(bac_a_sable, monkeypatch):
    c.VOLUME_PODMAN.mkdir()
    (c.VOLUME_PODMAN / "omnivoice.db").write_bytes(b"x")
    monkeypatch.setattr(c, "_port_libre", lambda *a: False)
    run = LxcFaux("RUNNING")
    with pytest.raises(c.Erreur, match="tient encore le port"):
        c.cmd_basculer(run)
    assert not (c.donnees(c.charger()) / c.MARQUE_MIGRATION).exists() and "lxc-stop" not in run.verbes()


def test_basculer_relance_l_ancienne_unite_en_cas_d_echec(bac_a_sable, monkeypatch):
    c.VOLUME_PODMAN.mkdir()
    (c.VOLUME_PODMAN / "omnivoice.db").write_bytes(b"x")
    monkeypatch.setattr(c, "_port_libre", lambda *a: True)
    monkeypatch.setattr(c, "DELAI_REVEIL", 0)
    monkeypatch.setattr(c, "sante", lambda cfg, *a, **k: {"ok": False, "http": 0})
    monkeypatch.setattr(c.os, "lchown", lambda *a: None)
    run = LxcFaux("STOPPED")
    reel = c.subprocess.run
    c.creer_cle()
    rc = c.cmd_basculer(lambda cmd, **k: reel(cmd, **k) if cmd[0] == "cp" else run(cmd, **k))
    assert rc == 1 and ["systemctl", "start", c.ANCIENNE_UNITE] in run.appels


# ── état : cache de la taille, provisionnement ───────────────────────────────
def test_la_taille_des_donnees_n_est_pas_recalculee_a_chaque_affichage(bac_a_sable, monkeypatch):
    d = Path(c.donnees(c.charger()))
    d.mkdir()
    (d / "a.bin").write_bytes(b"x" * 1048576)
    n = {"v": 0}
    reel = c.taille_mo
    monkeypatch.setattr(c, "taille_mo", lambda p: (n.__setitem__("v", n["v"] + 1), reel(p))[1])
    c.etat_complet(LxcFaux("STOPPED"))
    c.etat_complet(LxcFaux("STOPPED"))
    assert n["v"] == 1


def test_l_etat_annonce_le_provisionnement_en_cours(bac_a_sable):
    run = LxcFaux("RUNNING")
    base = run.__call__

    def prov(cmd, **k):
        if cmd[:2] == ["systemctl", "is-active"] and cmd[2] == c.UNITE_PROVISION:
            run.appels.append(list(cmd))
            return Rep(0, "activating\n")
        return base(cmd, **k)
    assert c.etat_complet(prov)["provisionnement"] == "activating"


def test_memoriser_etat_ne_perd_pas_le_cache_de_taille(bac_a_sable):
    c._ecrit({"taille": {"mo": 12.0, "ts": 9999999999}})
    c.memoriser_etat("RUNNING")
    d = json.loads(c.ETAT.read_text())
    assert d["taille"]["mo"] == 12.0 and d["dernier_etat"] == "RUNNING"


def test_le_mandataire_rendort_en_root_et_le_service_n_a_pas_besoin_de_root():
    cfg = c.charger()
    cfg["lxc"]["mode"] = "demande"
    assert "ExecStopPost=+/usr/sbin/voicestudioctl sleep" in c.contenu_service(cfg)


# ── pare-feu : le mandataire écoute sur l'hôte, donc sous la chaîne d'entrée en DROP ──────────────
class NftFaux(LxcFaux):
    """nft list / insert / delete : une chaîne d'entrée qui garde les règles comme le ferait nftables."""
    def __init__(self, table="filter", **kw):
        super().__init__(**kw)
        self.table, self.regles = table, []

    def __call__(self, cmd, **k):
        if cmd[0] != "nft":
            return super().__call__(cmd, **k)
        self.appels.append(list(cmd))
        if cmd[1] in ("list", "-a") and cmd[-3] == "inet":
            if cmd[-2] != self.table:
                return Rep(1, "", "No such file or directory")
            return Rep(0, "\n".join(f"{r} # handle {i + 10}" for i, r in enumerate(self.regles)))
        if cmd[1] == "list":
            return Rep(0 if cmd[4] == self.table else 1, "chain input {}")
        if cmd[1] == "insert":
            # nftables ré-affiche le commentaire entre guillemets : on restitue ce format réel.
            self.regles.insert(0, " ".join(cmd[6:-1]) + ' "' + cmd[-1] + '"')
            return Rep(0)
        if cmd[1] == "delete":
            h = int(cmd[-1]) - 10
            self.regles.pop(h)
            return Rep(0)
        return Rep(0)


def test_la_regle_ne_vise_que_les_adresses_publiees_depuis_des_sources_privees():
    cfg = c.charger()
    cfg["reseau"]["publier"] = ["192.168.1.9", "10.10.0.5"]
    r = c.regle_nft(cfg)
    assert "ip daddr { 10.10.0.5, 192.168.1.9 }" in r and "tcp dport 3900 accept" in r
    assert "ip saddr { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 }" in r
    assert 'comment "secubox-voicestudio"' in r
    assert not re.search(r"(?<![\d.])0\.0\.0\.0(?![\d.])", r) and "iifname" not in r


def test_rien_de_publie_rien_d_ouvert():
    cfg = c.charger()
    assert c.regle_nft(cfg) is None and "insert rule" not in c.contenu_nft(cfg)


def test_une_adresse_publique_heritee_n_ouvre_aucune_regle():
    cfg = c.charger()
    cfg["reseau"]["publier"] = ["82.67.100.75"]
    assert c.regle_nft(cfg) is None


def test_le_fichier_charge_au_demarrage_declare_la_table_avant_d_y_inserer():
    cfg = c.charger()
    cfg["reseau"]["publier"] = ["192.168.1.9"]
    f = c.contenu_nft(cfg)
    assert f.index("table inet filter") < f.index("insert rule inet filter input")     # additif : ne peut pas faire échouer le chargement
    assert "flush" not in f and "policy" not in f and "hook" not in f


def test_appliquer_pose_la_regle_vivante_et_ecrit_le_fichier(bac_a_sable):
    c.ecrire_toml("reseau", "publier", ["192.168.1.9", "10.10.0.5"])
    run = NftFaux()
    res = c.appliquer(run)
    assert res["pare_feu"]["vivante"] is True and len(run.regles) == 1
    assert "tcp dport 3900 accept" in run.regles[0] and "secubox-voicestudio" in run.regles[0]
    assert "insert rule inet filter input" in (c.NFT_DIR / c.NFT_FICHIER).read_text()


def test_changer_publier_retire_l_ancienne_regle_avant_la_nouvelle(bac_a_sable):
    c.ecrire_toml("reseau", "publier", ["192.168.1.9", "10.10.0.5"])
    run = NftFaux()
    c.appliquer(run)
    c.ecrire_toml("reseau", "publier", ["10.10.0.5"])
    c.appliquer(run)
    assert len(run.regles) == 1 and "192.168.1.9" not in run.regles[0]       # aucune adresse ouverte derrière soi


def test_appliquer_deux_fois_ne_duplique_pas_la_regle(bac_a_sable):
    c.ecrire_toml("reseau", "publier", ["192.168.1.9"])
    run = NftFaux()
    c.appliquer(run)
    c.appliquer(run)
    c.appliquer(run)
    assert len(run.regles) == 1


def test_la_regle_ne_touche_pas_aux_regles_des_autres(bac_a_sable):
    c.ecrire_toml("reseau", "publier", ["192.168.1.9"])
    run = NftFaux()
    run.regles = ['tcp dport 22 accept', 'iifname "wg-mesh" tcp dport 53 accept comment "secubox-noms"']
    c.appliquer(run)
    assert len(run.regles) == 3 and 'tcp dport 22 accept' in run.regles
    assert not any(a[:3] == ["nft", "flush", "chain"] or "flush" in a for a in run.appels if a[0] == "nft")


def test_sur_une_box_non_redemarree_la_table_est_l_ancienne(bac_a_sable):
    """gk3 chargeait encore `secubox_filter` : la règle vivante doit y aller, le fichier visant la base unifiée."""
    c.ecrire_toml("reseau", "publier", ["192.168.1.9"])
    run = NftFaux(table="secubox_filter")
    c.appliquer(run)
    assert len(run.regles) == 1
    assert ["nft", "insert", "rule", "inet", "secubox_filter", "input"] == [a for a in run.appels if a[:2] == ["nft", "insert"]][0][:6]


def test_sans_chaine_d_entree_on_le_dit_et_on_ecrit_quand_meme_le_fichier(bac_a_sable, capsys):
    c.ecrire_toml("reseau", "publier", ["192.168.1.9"])
    run = NftFaux(table="autre")
    res = c.appliquer(run)
    assert res["pare_feu"]["vivante"] is False and "chaîne d'entrée" in capsys.readouterr().err
    assert (c.NFT_DIR / c.NFT_FICHIER).exists()


def test_nft_absent_ne_fait_pas_tomber_appliquer(bac_a_sable, capsys):
    c.ecrire_toml("reseau", "publier", ["192.168.1.9"])
    base = LxcFaux()

    def sans_nft(cmd, **k):
        if cmd[0] == "nft":
            raise FileNotFoundError(2, "No such file or directory")
        return base(cmd, **k)
    res = c.appliquer(sans_nft)
    assert res["pare_feu"]["vivante"] is False and "nft indisponible" in capsys.readouterr().err


def test_une_regle_refusee_par_nft_est_dite(bac_a_sable, capsys):
    c.ecrire_toml("reseau", "publier", ["192.168.1.9"])
    run = NftFaux()
    base = run.__call__

    def refuse(cmd, **k):
        if cmd[:2] == ["nft", "insert"]:
            run.appels.append(list(cmd))
            return Rep(1, "", "Error: syntax")
        return base(cmd, **k)
    res = c.appliquer(refuse)
    assert res["pare_feu"]["vivante"] is False and "refusée" in capsys.readouterr().err


def test_pare_feu_ferme_retire_la_regle_et_le_fichier(bac_a_sable):
    c.ecrire_toml("reseau", "publier", ["192.168.1.9"])
    run = NftFaux()
    c.appliquer(run)
    assert c.cmd_pare_feu_ferme(run) == 0
    assert run.regles == [] and not (c.NFT_DIR / c.NFT_FICHIER).exists()


def test_la_regle_est_passee_a_nft_sans_shell(bac_a_sable):
    c.ecrire_toml("reseau", "publier", ["192.168.1.9"])
    run = NftFaux()
    c.appliquer(run)
    [ins] = [a for a in run.appels if a[:2] == ["nft", "insert"]]
    assert ins[-1] == "secubox-voicestudio" and "accept" in ins and '"' not in " ".join(ins)


def test_la_bascule_retire_les_regles_de_transfert_de_l_ancien_executeur(bac_a_sable, monkeypatch):
    c.VOLUME_PODMAN.mkdir()
    (c.VOLUME_PODMAN / "omnivoice.db").write_bytes(b"x")
    monkeypatch.setattr(c.os, "lchown", lambda *a: None)
    monkeypatch.setattr(c, "_port_libre", lambda *a: True)
    monkeypatch.setattr(c, "sante", lambda cfg, *a, **k: {"ok": True, "http": 200})
    c.creer_cle()
    run = NftFaux("secubox_filter", etat="RUNNING")
    reel = c.subprocess.run
    run.regles = ['ip daddr 10.88.0.0/16 tcp dport 3900 ct status dnat accept comment "secubox-voicestudio"', "tcp dport 22 accept"]
    c.cmd_basculer(lambda cmd, **k: reel(cmd, **k) if cmd[0] == "cp" else run(cmd, **k))
    assert not any("10.88.0.0/16" in r for r in run.regles) and "tcp dport 22 accept" in run.regles


def test_la_migration_laisse_les_donnees_en_0750(bac_a_sable, monkeypatch):
    c.VOLUME_PODMAN.mkdir()
    (c.VOLUME_PODMAN / "omnivoice.db").write_bytes(b"x")
    monkeypatch.setattr(c.os, "lchown", lambda *a: None)
    run = LxcFaux()
    reel = c.subprocess.run
    c.cmd_migrer_podman(lambda cmd, **k: reel(cmd, **k) if cmd[0] == "cp" else run(cmd, **k))
    assert stat.S_IMODE(c.donnees(c.charger()).stat().st_mode) == 0o750
