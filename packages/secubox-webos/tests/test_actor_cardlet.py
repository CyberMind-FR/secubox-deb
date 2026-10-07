# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""Carte Actor Intelligence façon infographie : données réelles seulement, échelle de score, échappement, pas de valeur inventée."""
from pathlib import Path

HTML = (Path(__file__).resolve().parents[1] / "www" / "hall" / "cardlets" / "actor.html").read_text()


def test_les_quatre_couches_de_la_maquette():
    for ident in ("d-vue", "d-even", "d-acteurs", "d-profil", "d-defense"):
        assert f'id="{ident}"' in HTML
    assert HTML.count("{label:'") == 5


def test_echelle_de_score_a_cinq_paliers_et_trois_tuiles():
    for nom in ("Faible risque", "À surveiller", "Suspect", "Probable attaque", "Très critique"):
        assert nom in HTML
    for tuile in ("t-crit", "t-susp", "t-obs"):
        assert f'id="{tuile}"' in HTML


def test_six_crans_de_reponse_gradues():
    for c in ("Observer", "Delay", "Challenge", "Tarpit", "Deny", "Quarantine"):
        assert f'"{c}"' in HTML


def test_donnees_reelles_seulement_et_sonde_chargee():
    assert 'src="../sonde.js"' in HTML
    assert "/api/v1/actor/stats" in HTML and "/api/v1/actor/actors" in HTML
    assert "Math.random" not in HTML


def test_les_valeurs_serveur_sont_echappees_avant_innerhtml():
    # un identifiant ou une heure ne doivent jamais entrer bruts dans le HTML construit
    assert "'+a.id+'" not in HTML and "'+a.first+'" not in HTML and "'+a.last+'" not in HTML
    assert "esc(a.id)" in HTML and "esc(a.first)" in HTML and "esc(a.last)" in HTML
    assert "function esc(" in HTML and "function num(" in HTML and "&#39;" in HTML


def test_sans_session_on_ne_montre_pas_de_chiffres_inventes():
    assert "Ouvre une session pour voir le détail des acteurs." in HTML


def test_carte_du_monde_top_pays_et_derniers_evenements():
    assert 'id="carte"' in HTML and "Top pays" in HTML and "Derniers événements" in HTML
    assert "/api/v1/actor/overview" in HTML
    # le fond de carte (Natural Earth, domaine public) est embarqué : aucune ressource externe
    assert "http://" not in HTML and "https://" not in HTML.replace("https://secubox.in", "")


def test_la_fiche_a_ses_trois_onglets_et_une_courbe_24h():
    for o in ("data-o=", "Techniques", "Réponse", "Activité (24 h)", "activite_acteurs"):
        assert o in HTML


def test_l_aperçu_n_est_demande_qu_avec_une_session():
    # comme la liste des acteurs : jamais à vide, sonde.js fermerait la carte
    assert "sessionOk()" in HTML and HTML.index("sessionOk()") < HTML.index("/api/v1/actor/overview")


def test_les_heures_des_evenements_sont_en_heure_locale():
    assert "function heureLocale(" in HTML and "toLocaleTimeString" in HTML and "esc(heureLocale(e))" in HTML


def test_moteur_absent_ou_en_demarrage_est_dit_clairement():
    assert "en démarrage ou injoignable" in HTML and "nouvel essai automatique" in HTML


def test_mode_compact_quand_la_carte_est_embarquee():
    # le groupe Sécurité n'offre que ~240 px : en-tête sur une ligne, pas de titres de section, tuiles et carte resserrées
    assert "embed" in HTML and "classList.add('emb')" in HTML
    for regle in (".emb .h .tt small", ".emb .sec-t", ".emb .tile", ".emb .carte svg"):
        assert regle in HTML, regle
    assert "white-space:nowrap" in HTML.split(".h .tt b")[1].split("}")[0], "le titre ne passe pas sur deux lignes"


def test_les_blocs_d_une_couche_ne_retrecissent_pas():
    assert ".slice>*{flex:0 0 auto}" in HTML


# ── Même score que la page admin (un seul barème) ───────────────────────────────────────────────────────────────────────────────────
def test_la_carte_utilise_le_score_de_la_page_admin_pas_la_priorite_brute():
    # la `priority` de l'API plafonne à ~45 sur cette box : elle ne sépare rien (0 critique, 0 suspect, tout « observé »). La page admin calcule un score
    # (adresses, pays, bans, continuité) ; la carte du Hall doit raconter la même chose.
    assert "function score(" in HTML
    for terme in ("Math.log2(", "s.countries", "num(a.bans)", "v.continuity", "v.persistence", "v.automation"):
        assert terme in HTML, terme
    assert "num(a.priority)" not in HTML, "plus aucun usage de la priorité brute pour classer"


def test_les_memes_seuils_que_la_page_admin():
    page = (Path(__file__).resolve().parents[2] / "secubox-waf-ng" / "www" / "actor" / "index.html")
    if page.exists():
        src = page.read_text()
        assert "n>=70" in src and "n>=45" in src
    assert "p>=70" in HTML and "p>=45" in HTML, "tuiles critiques ≥ 70, suspects ≥ 45 (comme palierScore de la page admin)"
