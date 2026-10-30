# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3005 : adresses rémanentes des appareils et ré-application amortie.

L'application nocturne prenait la table de voisinage du moment (`ip -j neigh`) : un appareil assigné absent à 04:00 retombait dans `defaut`
toute la journée. Le démon d'alimentation tient maintenant `remanence.json` (adresse → dernier MAC vu, date), que le contrôleur fusionne avec
la table de voisinage ; une adresse nouvelle d'un appareil assigné dépose `appliquer.demande`, au plus une fois par fenêtre d'amortissement."""
import json
import os
import stat
import time

import pytest

from webfilter import catalogue, remanence

from .test_ctl import CONF, Faux, banc, config, ecrire_config, lancer, source  # noqa: F401  (banc : fixture)

A, B = "aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02"
JOUR = 86400
T0 = 1_791_000_000
RET = 14 * JOUR
AMORTI = 30 * 60


# ---------- historique (démon) ----------

def test_observer_retient_les_adresses_vues_et_les_ecrit_atomiquement(tmp_path):
    h = remanence.observer({}, {A: ["192.168.1.3", "2a01:db8::3"], B: ["192.168.1.9"]}, {"192.168.1.3", "2a01:db8::3"}, T0)
    assert h["adresses"] == {"192.168.1.3": {"mac": A, "vu": T0}, "2a01:db8::3": {"mac": A, "vu": T0}}      # B jamais vu dans le journal
    f = tmp_path / remanence.FICHIER
    remanence.ecrire(f, h)
    assert stat.S_IMODE(f.stat().st_mode) == 0o640 and [p.name for p in tmp_path.iterdir()] == [remanence.FICHIER]
    assert remanence.lire_fichier(f) == h


def test_retention_l_adresse_reste_puis_expire():
    h = remanence.observer({}, {A: ["192.168.1.3"]}, {"192.168.1.3"}, T0)
    h = remanence.observer(h, {A: ["192.168.42.192"]}, {"192.168.42.192"}, T0 + 13 * JOUR)               # vu ailleurs : l'ancienne reste
    h = remanence.purger(h, RET, T0 + 13 * JOUR)
    assert set(h["adresses"]) == {"192.168.1.3", "192.168.42.192"}
    assert remanence.fusionner({}, h, RET, T0 + 13 * JOUR) == {A: ["192.168.1.3", "192.168.42.192"]}
    plus_tard = T0 + RET + 1
    assert remanence.fusionner({}, h, RET, plus_tard) == {A: ["192.168.42.192"]}                          # expirée après la durée
    assert set(remanence.purger(h, RET, plus_tard)["adresses"]) == {"192.168.42.192"}


def test_conflict_le_dernier_vu_gagne_jamais_deux_mac():
    h = remanence.observer({}, {A: ["192.168.1.3"]}, {"192.168.1.3"}, T0)
    h = remanence.observer(h, {B: ["192.168.1.3"]}, {"192.168.1.3"}, T0 + 3600)                          # bail réattribué
    assert h["adresses"]["192.168.1.3"]["mac"] == B
    assert remanence.fusionner({}, h, RET, T0 + 7200) == {B: ["192.168.1.3"]}
    # la table de voisinage du moment compte pour « maintenant » : elle l'emporte sur l'historique
    assert remanence.fusionner({A: ["192.168.1.3"]}, h, RET, T0 + 7200) == {A: ["192.168.1.3"]}


def test_lecture_tolerante_d_un_historique_hostile(tmp_path):
    f = tmp_path / remanence.FICHIER
    for brut in ("", "[]", "{", '{"adresses": {"pas-une-ip": {"mac": "aa:bb:cc:dd:ee:01", "vu": 1}}}',
                 '{"adresses": {"192.168.1.3": {"mac": "ZZ", "vu": 1}}}', '{"adresses": {"192.168.1.3": {"mac": "aa:bb:cc:dd:ee:01", "vu": "x"}}}',
                 '{"adresses": {"fe80::1": {"mac": "aa:bb:cc:dd:ee:01", "vu": 1}}}'):
        f.write_text(brut)
        assert remanence.lire_fichier(f)["adresses"] == {}
    f.write_bytes(b"{" + b" " * (remanence.MAX_OCTETS + 1) + b"}")
    assert remanence.lire_fichier(f)["adresses"] == {}
    assert remanence.lire_fichier(tmp_path / "absent.json") == {"demande": 0, "adresses": {}}


def test_historique_borne():
    voisins = {f"aa:bb:cc:dd:{i // 256:02x}:{i % 256:02x}": [f"10.{i // 65536}.{i // 256 % 256}.{i % 256}"] for i in range(remanence.MAX_ADRESSES + 50)}
    h = remanence.observer({}, voisins, {a for v in voisins.values() for a in v}, T0)
    assert len(remanence.purger(h, RET, T0)["adresses"]) == remanence.MAX_ADRESSES


# ---------- ré-application amortie (démon) ----------

def _etat(tmp_path, appareils=(A,)):
    d = tmp_path / "etat"
    d.mkdir(exist_ok=True)
    (d / "config.json").write_text(json.dumps({"version": 1, "profils": {}, "appareils": {m: {"profil": "adultes"} for m in appareils}}))
    return d


def _passe(d, voisins, vus, carte, t, dns=None):
    return remanence.passe(d, voisins, vus, carte, RET, AMORTI, dns_etat=dns or (d.parent / "dns-etat.json"), maintenant=t)


CARTE_NUIT = {"adresses": {"192.168.42.192": {"mac": A}}}


def test_adresse_nouvelle_d_un_appareil_assigne_depose_une_seule_demande_dans_la_fenetre(tmp_path):
    d = _etat(tmp_path)
    assert _passe(d, {A: ["192.168.1.3"]}, {"192.168.1.3"}, CARTE_NUIT, T0) is True
    assert (d / "appliquer.demande").is_file()
    (d / "appliquer.demande").unlink()                                                          # le contrôleur l'a consommée
    assert _passe(d, {A: ["192.168.1.3"]}, {"192.168.1.3"}, CARTE_NUIT, T0 + 300) is False     # déjà signalée
    assert _passe(d, {A: ["192.168.1.4"]}, {"192.168.1.4"}, CARTE_NUIT, T0 + 600) is False     # nouvelle, mais dans la fenêtre
    assert not (d / "appliquer.demande").exists()
    assert _passe(d, {A: ["192.168.1.4"]}, {"192.168.1.4"}, CARTE_NUIT, T0 + AMORTI + 1) is True   # fenêtre passée : reprise
    h = remanence.lire_fichier(d / remanence.FICHIER)
    assert set(h["adresses"]) == {"192.168.1.3", "192.168.1.4"} and h["demande"] == T0 + AMORTI + 1


def test_adresse_deja_dans_la_carte_ne_demande_rien(tmp_path):
    d = _etat(tmp_path)
    assert _passe(d, {A: ["192.168.42.192"]}, {"192.168.42.192"}, CARTE_NUIT, T0) is False
    assert not (d / "appliquer.demande").exists()


def test_appareil_non_assigne_inchange(tmp_path):
    d = _etat(tmp_path, appareils=())
    assert _passe(d, {B: ["192.168.1.9"]}, {"192.168.1.9"}, CARTE_NUIT, T0) is False
    assert not (d / "appliquer.demande").exists()
    assert remanence.lire_fichier(d / remanence.FICHIER)["adresses"]["192.168.1.9"]["mac"] == B           # retenu pour trancher les conflits


def test_adresse_de_la_carte_reprise_par_un_autre_appareil_redemande(tmp_path):
    """Bail réattribué : l'adresse appliquée pour A sert maintenant B — la vue de A ne doit pas lui rester."""
    d = _etat(tmp_path, appareils=(A,))
    assert _passe(d, {B: ["192.168.42.192"]}, {"192.168.42.192"}, CARTE_NUIT, T0) is True


def test_pas_de_demande_pendant_une_application_en_cours(tmp_path):
    d = _etat(tmp_path)
    (d / remanence.MARQUEUR).write_text(str(T0))
    os.utime(d / remanence.MARQUEUR, (T0, T0))
    assert _passe(d, {A: ["192.168.1.3"]}, {"192.168.1.3"}, CARTE_NUIT, T0 + 60) is False
    assert not (d / "appliquer.demande").exists()
    (d / remanence.MARQUEUR).unlink()                                                           # application terminée : reprise au passage suivant
    assert _passe(d, {A: ["192.168.1.3"]}, {"192.168.1.3"}, CARTE_NUIT, T0 + 360) is True


def test_marqueur_perime_n_empeche_rien(tmp_path):
    d = _etat(tmp_path)
    (d / remanence.MARQUEUR).write_text("")
    vieux = T0 - remanence.EN_COURS_MAX_S - 1
    os.utime(d / remanence.MARQUEUR, (vieux, vieux))                                            # contrôleur tué : le marqueur ne bloque pas à vie
    assert _passe(d, {A: ["192.168.1.3"]}, {"192.168.1.3"}, CARTE_NUIT, T0) is True


def test_pas_de_demande_pendant_une_compilation_dns_listes(tmp_path):
    d = _etat(tmp_path)
    dns = tmp_path / "dns-etat.json"
    dns.write_text(json.dumps({"etat": "en-cours", "t": T0 - 60}))
    assert _passe(d, {A: ["192.168.1.3"]}, {"192.168.1.3"}, CARTE_NUIT, T0, dns=dns) is False
    dns.write_text(json.dumps({"etat": "applique", "t": T0}))
    assert _passe(d, {A: ["192.168.1.3"]}, {"192.168.1.3"}, CARTE_NUIT, T0 + 300, dns=dns) is True


def test_demande_deja_deposee_n_est_pas_doublee(tmp_path):
    d = _etat(tmp_path)
    (d / "appliquer.demande").write_text("")
    avant = (d / "appliquer.demande").stat().st_ino
    assert _passe(d, {A: ["192.168.1.3"]}, {"192.168.1.3"}, CARTE_NUIT, time.time()) is False      # création exclusive : l'existante suffit
    assert (d / "appliquer.demande").stat().st_ino == avant
    assert "signale" in remanence.lire_fichier(d / remanence.FICHIER)["adresses"]["192.168.1.3"]   # l'application en attente la lira


# ---------- contrôleur : la carte reprend les adresses rémanentes ----------

def test_le_controleur_garde_l_adresse_d_un_appareil_assigne_absent_a_04h(banc):  # noqa: F811
    ecrire_config(banc, config())
    h = remanence.observer({}, {A: ["192.168.1.3"]}, {"192.168.1.3"}, int(time.time()) - 3 * JOUR)
    remanence.ecrire(banc / "etat" / remanence.FICHIER, h)
    lancer(banc, Faux(voisins={A: ["192.168.42.192"]}))                                         # à 04:00 seule l'adresse de la nuit est visible
    txt = source(banc).read_text()
    assert "access-control-view: 192.168.1.3/32 wf-" in txt and "access-control-view: 192.168.42.192/32 wf-" in txt
    carte = json.loads((banc / "etat" / "carte.json").read_text())
    assert carte["adresses"]["192.168.1.3"]["mac"] == A


def test_le_controleur_ignore_une_adresse_expiree_ou_reprise(banc):  # noqa: F811
    ecrire_config(banc, config())
    maintenant = int(time.time())
    h = remanence.observer({}, {A: ["192.168.1.3"]}, {"192.168.1.3"}, maintenant - 15 * JOUR)          # au-delà des 14 jours par défaut
    h = remanence.observer(h, {A: ["192.168.1.7"]}, {"192.168.1.7"}, maintenant - JOUR)
    h = remanence.observer(h, {B: ["192.168.1.7"]}, {"192.168.1.7"}, maintenant - 600)                 # puis réattribuée à B
    remanence.ecrire(banc / "etat" / remanence.FICHIER, h)
    lancer(banc, Faux(voisins={A: ["192.168.42.192"]}))
    txt = source(banc).read_text()
    assert "192.168.1.3/32" not in txt and "192.168.1.7/32" not in txt


def test_le_controleur_pose_et_retire_le_marqueur(banc):  # noqa: F811
    ecrire_config(banc, config())
    vu = []

    class Espion(Faux):
        def voisins(self):
            vu.append((banc / "etat" / remanence.MARQUEUR).exists())
            return super().voisins()
    lancer(banc, Espion())
    assert vu == [True] and not (banc / "etat" / remanence.MARQUEUR).exists()


def test_historique_lien_symbolique_ignore(banc, tmp_path):  # noqa: F811
    ecrire_config(banc, config())
    ailleurs = tmp_path / "ailleurs.json"
    remanence.ecrire(ailleurs, remanence.observer({}, {A: ["192.168.1.3"]}, {"192.168.1.3"}, int(time.time())))
    (banc / "etat" / remanence.FICHIER).symlink_to(ailleurs)
    r = lancer(banc, Faux())
    assert r["statut"] == "applique" and "192.168.1.3/32" not in source(banc).read_text()


# ---------- configuration ----------

def test_cles_de_conf_par_defaut_et_bornes(tmp_path):
    f = tmp_path / "w.toml"
    sans = CONF.replace("[appareils]\nretention_jours = 14\nreapplication_min = 30\n", "")
    assert "[appareils]" not in sans
    f.write_text(sans)                                                                          # conf d'avant #3005 : valeurs par défaut
    c = catalogue.charger_config(f)
    assert (c.retention_jours, c.reapplication_min) == (14, 30)
    assert catalogue.appareils(f) == (14, 30)
    f.write_text(sans + "\n[appareils]\nretention_jours = 3\nreapplication_min = 60\n")
    assert catalogue.appareils(f) == (3, 60) and catalogue.charger_config(f).retention_jours == 3
    for mauvais in ("retention_jours = -1", "retention_jours = 400", "reapplication_min = 1", "reapplication_min = true", "inconnue = 1"):
        f.write_text(sans + f"\n[appareils]\n{mauvais}\n")
        with pytest.raises(catalogue.ErreurCatalogue):
            catalogue.appareils(f)


def test_conf_livree_documente_les_cles():
    assert "[appareils]" in CONF and "retention_jours = 14" in CONF and "reapplication_min = 30" in CONF


# ---------- câblage : démon, profils AppArmor ----------

def test_le_demon_tient_l_historique_a_chaque_publication_des_connus():
    from .test_ctl import RACINE
    txt = (RACINE / "sbin" / "secubox-webfilter-feed").read_text()
    assert "remanence.passe(" in txt and "catalogue.appareils(" in txt


def test_apparmor_autorise_le_marqueur_l_historique_et_l_etat_de_dns_listes():
    from .test_ctl import RACINE
    aa = (RACINE / "apparmor" / "secubox-webfilter").read_text()
    ctl_bloc = aa.split("/usr/sbin/secubox-webfilter-ctl {", 1)[1].split("\n}", 1)[0]
    feed_bloc = aa.split("/usr/sbin/secubox-webfilter-feed {", 1)[1].split("\n}", 1)[0]
    assert "/var/lib/secubox/webfilter/application.en-cours rw," in ctl_bloc
    assert "/var/lib/secubox/webfilter/remanence.json r," in ctl_bloc
    assert "/var/lib/secubox-dns-listes/etat.json r," in feed_bloc
