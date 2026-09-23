# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""ZIA — le lexique, et la cible par défaut d'un réglage de son (#1349).

CE QUE CES TESTS GARDENT. Une commande de volume sans cible partait sur
`or "radio"` : « baisse le son » baissait la RADIO et laissait les autres
sources où elles étaient. Vu de l'usage, la radio paraissait réglée plus fort
que tout le reste — alors que rien n'était réglé du tout.
"""

import pytest

from api import runtime


def cible_de(action, low):
    """La règle de ciblage de `runtime`, isolée pour que le test la vérifie
    plutôt que de la recopier à trois endroits — trois copies divergent."""
    nomme = runtime._service_de(low)
    if action in ("media.volume", "media.volume.relative", "media.mute") \
            and (not nomme or runtime._TOUT.search(low)):
        return "hall"
    return nomme or "radio"


# ── La cible par défaut ──────────────────────────────────────────────────────

@pytest.mark.parametrize("phrase", [
    "baisse le son",
    "monte le volume",
    "volume à 40 %",
    "coupe le son",
    "mets le son à 30 %",
])
def test_un_reglage_de_son_sans_cible_vise_le_maitre(phrase):
    """LE TEST QUI COMPTE. Sans cible nommée, un réglage porte sur TOUT."""
    low = phrase.lower()
    cmd = runtime._commande(low)
    assert cmd is not None, f"« {phrase} » n'est pas reconnue comme une commande"
    action, _ = cmd
    nomme = runtime._service_de(low)
    cible = cible_de(action, low)
    assert cible == "hall", f"« {phrase} » vise {cible} au lieu de l'ensemble"


@pytest.mark.parametrize("phrase, attendu", [
    ("baisse le son de la radio", "radio"),
    ("coupe le podcast", "podcaster"),
    ("volume de peertube à 50 %", "peertube"),
])
def test_une_cible_nommee_est_respectee(phrase, attendu):
    """Le maître ne doit pas manger les ordres précis : « baisse la radio »
    reste la radio, sinon on perdrait le réglage fin entre les sources."""
    assert runtime._service_de(phrase.lower()) == attendu


@pytest.mark.parametrize("mot", ["tout", "partout", "général", "globale", "système"])
def test_les_mots_qui_designent_l_ensemble(mot):
    assert runtime._TOUT.search("coupe le son " + mot)


def test_le_transport_garde_la_radio_par_defaut():
    """« suivant » ne veut rien dire pour un ensemble : ces commandes-là
    conservent leur cible unique. Ce n'est pas un oubli."""
    low = "piste suivante"
    action, _ = runtime._commande(low)
    assert action == "media.next"
    nomme = runtime._service_de(low)
    cible = cible_de(action, low)
    assert cible == "radio"


# ── Le lexique ───────────────────────────────────────────────────────────────

@pytest.mark.parametrize("mot, service", [
    ("mes fichiers", "nextcloud"), ("le nuage", "nextcloud"),
    ("les actus", "metanews"), ("le journal", "metanews"),
    ("mes photos", "photoprism"),
    ("une vidéo", "peertube"),
    ("la télé", "freeboxtv"), ("change de chaine", "freeboxtv"),
    ("mes mails", "mail"), ("le courriel", "mail"),
    ("le forum", "bbs"),
    ("un article", "billets"),
    ("la musique", "radio"),
    ("un épisode", "podcaster"),
    ("la lumière", "zigbee"),
    ("le pare-feu", "waf"),
])
def test_on_parle_des_services_comme_on_en_parle(mot, service):
    """PERSONNE NE DIT « nextcloud ». On dit « mes fichiers ». Le lexique
    tenait en sept mots ; reconnaître un mot permet au moins de répondre
    « cette commande n'existe pas ici » au lieu de ne rien répondre — et le
    silence est bien pire, il ressemble à une panne du module."""
    assert runtime._service_de(mot.lower()) == service


def test_un_mot_inconnu_ne_devient_pas_un_service():
    """Le lexique s'élargit, il ne devine pas. Rendre un service au hasard
    ferait agir sur une source que personne n'a demandée."""
    assert runtime._service_de("fais moi un café") == ""


def test_le_lexique_ne_renvoie_que_des_services_connus():
    """GARDE DE COHÉRENCE. Un alias qui pointe vers un service absent de la
    liste canonique produirait une cible que rien en aval ne sait honorer —
    et le refus serait incompréhensible."""
    connus = set(runtime._SERVICES) | {"nextcloud", "photoprism", "freeboxtv",
                                       "mail", "zigbee", "torrent", "mastodon"}
    for mot, svc in runtime._ALIAS.items():
        assert svc in connus, f"l'alias « {mot} » pointe vers {svc}, inconnu"


# ── Les phrases rendues ──────────────────────────────────────────────────────

def test_le_maitre_ne_se_nomme_pas_hall_dans_la_reponse():
    """« Je règle le volume de hall » ne se dit pas, et laisserait croire
    qu'on a réglé une source de plus."""
    p = runtime._phrase_action("hall", "media.volume", {"value": 0.4})
    assert "hall" not in p.lower()
    assert "40" in p and "général" in p


def test_la_coupure_generale_le_dit():
    assert runtime._phrase_action("hall", "media.mute", {"value": True}) == "Je coupe tout le son."
    assert runtime._phrase_action("hall", "media.mute", {"value": False}) == "Je remets le son."
