<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# SADE ACTIVE v1 — plan d'implémentation

> **Pour les agents :** sous-skill requis : superpowers:subagent-driven-development (recommandé) ou
> superpowers:executing-plans, tâche par tâche. Les étapes sont des cases à cocher (`- [ ]`).

**But :** ouvrir le mode ACTIVE de SADE. En ACTIVE, le code bannit lui-même les propositions d'actord du « cas sûr » ;
tout le reste passe toujours par la file d'approbation.

**Architecture :** un exécuteur minuté (`secubox-soc-sade-auto.timer`, toutes les 2 min) lit `/proposals` d'actord. Il
garde les propositions du cas sûr et réclame chaque décision dans `defense.db` (audit avant geste). Il bannit par
`sudo -n /usr/sbin/wafctl ban <ip> <durée>`, le verbe que le WAF accorde déjà au compte `secubox` : `wafctl` refait en
root ses gardes (privé, plages protégées, box, pairs). Au-delà de 20 adresses bannies automatiquement sur l'heure
glissante, l'exécuteur repasse le mode en OBSERVE. La façade et la page ouvrent le bouton ACTIVE et montrent le
compteur.

**Pile :** Python 3 (secubox-soc, FastAPI déjà en place), SQLite (`defense.db`), systemd (service oneshot + minuterie),
sudo (verbe `wafctl ban` existant), page `www/soc/defense.html`.

**Spec :** `docs/superpowers/specs/2026-11-20-sade-active-defense-design.md` (§ Réconciliation, § Échelle, § Garde-fous,
§ Déploiement progressif : étape 3 = ACTIVE au banc).

## Contraintes globales

- Cas sûr, toutes conditions réunies : geste `ban` (mode actord `DENY`) ; score de **60 à 94** inclus ; 1 à **8**
  adresses ; toutes publiques et hors protégés (liste blanche en base, passerelles, pairs du maillage) via
  `defense._adresse_interdite` ; liste blanche lisible.
- Durée appliquée : `min(ttl_s or 14400, 86400)` secondes (14400 = durée par défaut du WAF, comme l'approbation manuelle sans durée ; ruling T2), passée à wafctl sous la forme `"<n>s"`. L'empreinte reste
  celle de la proposition (`defense.empreinte`), sans changement.
- Plafond : **20 adresses** bannies par `sade-auto` sur 3600 s glissantes. Si un lot le dépasserait, rien n'est banni
  dans ce lot et le mode repasse à `observe`, `par = "sade-auto"`, avec un audit `sade-auto-plafond`.
- Jamais en automatique : score ≥ 95 (bande `incident`), score inconnu, geste autre que `ban`, proposition de
  secubox-ai/V2. Ces cas restent dans la file d'approbation.
- Opérateur des décisions automatiques : `"sade-auto"`. Audit : `sade-auto-demande` (via `reclamer`, AVANT le geste),
  `sade-auto-resultat` (après), `sade-auto-plafond`. Une proposition écartée n'est pas auditée : elle reste visible
  dans la file.
- Refus de wafctl (garde root) : la décision est conclue `refuse` (ré-armable après 24 h), jamais retentée à chaque
  passage.
- En ACTIVE, l'approbation manuelle reste ouverte (`/approve` et `/refuse` agissent en `reactive` ET en `active`).
  `aggressive` reste fermé (`gestes_non_livres`).
- Le mode par défaut reste `observe` : aucune box ne passe en ACTIVE à l'installation.
- Version `secubox-soc 1.10.0-1~trixie1` ; en-tête SPDX CMSD-1.0 sur tout fichier neuf ; README et changelog à jour ;
  exception écrite dans `.claude/RULES-CODE.md` § 10 pour l'unité (`NoNewPrivileges=no`, sudo `wafctl ban`).
- Commits `type: message (ref #3839)`, sans ligne d'attribution.

## Points d'attention en revue

1. actord injoignable ou `/proposals` illisible : aucun geste, aucun changement de mode, sortie 0 (simple passage
   manqué) — test `test_actord_muet_rien`.
2. `defense.db` illisible ou audit en échec : aucun geste — `test_base_ou_audit_indisponible_rien`.
3. Mode changé en cours de passage (un administrateur repasse en OBSERVE) : `reclamer` lève `ModeRefuse`, le
   passage s'arrête sans bannir le reste — `test_mode_change_pendant_le_passage`.
4. Proposition déjà bannie automatiquement au passage précédent : `DejaTraitee`, ni second ban ni nouvel audit —
   `test_pas_de_double_ban`.
5. wafctl refuse une adresse (protégée côté root) : décision `refuse`, aucun nouvel essai au passage suivant —
   `test_refus_wafctl_conclu_refuse`.

---

### Task 1 : état — mode ACTIVE ouvert, réclamation par mode, compteur automatique

**Fichiers :**
- Modifier : `packages/secubox-soc/api/defense_etat.py` (`MODES_OUVERTS`, `reclamer`, nouvelle `bans_auto_depuis`)
- Modifier : `packages/secubox-soc/api/defense.py` (`_traiter` : mode accepté)
- Test : `packages/secubox-soc/tests/test_sade_active_etat.py`

**Interfaces :**
- Produit : `MODES_OUVERTS = ("observe", "reactive", "active")` ;
  `reclamer(..., ligne_audit: str, modes: Tuple[str, ...] = ("reactive",)) -> int` (lève `ModeRefuse` si le mode
  courant n'est pas dans `modes`) ; `bans_auto_depuis(secondes: int, maintenant: Optional[float] = None) -> int`, soit
  le nombre d'ADRESSES (cible découpée sur `,`) des décisions `par = 'sade-auto'`, dans l'état `applique` ou
  `en_cours`, avec `demande_ts` dans la fenêtre (lève `EtatIndisponible`).

- [ ] **Étape 1 : écrire les tests qui échouent**

```python
def test_active_ouvert_aggressive_ferme(etat):
    defense_etat.changer_mode("active", "admin")
    assert defense_etat.mode_courant() == "active"
    with pytest.raises(PermissionError):
        defense_etat.changer_mode("aggressive", "admin")

def test_reclamer_respecte_les_modes(etat):
    defense_etat.changer_mode("active", "admin")
    with pytest.raises(defense_etat.ModeRefuse):
        defense_etat.reclamer("a" * 64, "ACT-1", "ban", "203.0.113.5", 70, 3600, "x", "en_cours", "sade-test")
    g = defense_etat.reclamer("a" * 64, "ACT-1", "ban", "203.0.113.5", 70, 3600, "sade-auto", "en_cours",
                              "sade-auto-demande", modes=("active",))
    assert g == 1

def test_bans_auto_compte_les_adresses_de_l_heure(etat):
    # deux décisions sade-auto (1 + 2 adresses) dans l'heure, une d'un administrateur, une vieille de 2 h
    ...
    assert defense_etat.bans_auto_depuis(3600) == 3

def test_approbation_manuelle_ouverte_en_active(faux, client, admin):   # via /defense/approve, simuler=True
    ...  # mode active : 200 "simule", et non 409 "mode"
```

- [ ] **Étape 2 :** `pytest tests/test_sade_active_etat.py -v` → ÉCHEC (`active` refusé).
- [ ] **Étape 3 :** implémenter. Dans `_traiter`, `mode not in ("reactive", "active")` ⇒ 409 `mode` ; l'appel à
  `reclamer` passe `modes=("reactive", "active")`. Le message d'erreur devient « n'agit qu'en REACTIVE ou ACTIVE ».
- [ ] **Étape 4 :** `pytest tests -q` → tout passe (les tests existants qui attendaient un 409 pour `active` sont
  mis à jour : `active` est désormais accepté, `aggressive` reste refusé).
- [ ] **Étape 5 :** commit `feat(soc): SADE, mode ACTIVE ouvert, réclamation par mode, compteur auto (ref #3839)`.

### Task 2 : exécuteur `sade_auto` (cas sûr, plafond, wafctl)

**Fichiers :**
- Créer : `packages/secubox-soc/api/sade_auto.py`
- Test : `packages/secubox-soc/tests/test_sade_auto.py`

**Interfaces :**
- Consomme : `defense._lire_propositions`, `defense._propositions`, `defense._proteges(entetes={}, appelant=[])`,
  `defense._adresse_interdite`, `defense._champs`, `defense_etat.reclamer(..., modes=("active",))`,
  `defense_etat.conclure`, `defense_etat.bans_auto_depuis`, `defense_etat.changer_mode`, `defense_etat.ecrire_audit`.
- Produit : `PLAFOND_HEURE = 20`, `TTL_AUTO_MAX_S = 86400`, `SCORE_MIN, SCORE_MAX = 60, 94`, `ADRESSES_AUTO_MAX = 8`,
  `OPERATEUR = "sade-auto"` ; `cas_sur(p: dict, proteges: list) -> Tuple[bool, str]` (motif : `ok`, `geste`,
  `score`, `sans_adresse`, `trop_d_adresses`, `adresse_protegee`) ; `executer() -> Dict[str, Any]`, qui rend
  `{"mode", "bannies": [...], "ecartees": int, "plafond": bool, "erreur": Optional[str]}` ; `main() -> int`, qui
  rend toujours 0 sauf exception imprévue. `_wafctl_ban(ip: str, duree: str) -> Tuple[bool, str]` est le SEUL point
  d'exécution : `subprocess.run(["sudo", "-n", "/usr/sbin/wafctl", "ban", ip, duree], timeout=30)`.

- [ ] **Étape 1 : écrire les tests qui échouent** (faux `substrat.lire`, `_wafctl_ban` remplacé, base temporaire
  `SECUBOX_SOC_DEFENSE_DB`, audit temporaire) :

```python
def test_cas_sur_bornes():
    assert cas_sur(prop(score=60), []) == (True, "ok") and cas_sur(prop(score=94), []) == (True, "ok")
    assert cas_sur(prop(score=59), [])[1] == "score" and cas_sur(prop(score=95), [])[1] == "score"
    assert cas_sur(prop(score=None), [])[1] == "score"
    assert cas_sur(prop(geste="quarantaine"), [])[1] == "geste"
    assert cas_sur(prop(ips=[]), [])[1] == "sans_adresse"
    assert cas_sur(prop(ips=[f"203.0.113.{i}" for i in range(9)]), [])[1] == "trop_d_adresses"
    assert cas_sur(prop(ips=["192.168.1.10"]), [])[1] == "adresse_protegee"

def test_hors_active_rien():            # mode reactive : aucun appel à wafctl, aucune décision
def test_ban_sur_avec_duree_bornee():   # ttl 7 j ⇒ wafctl reçoit "86400s" ; décision applique, par sade-auto ;
                                        # audit sade-auto-demande AVANT l'appel, sade-auto-resultat après
def test_plafond_repasse_en_observe():  # 19 adresses déjà dans l'heure + lot de 2 ⇒ aucun ban, mode observe,
                                        # audit sade-auto-plafond
def test_actord_muet_rien():
def test_base_ou_audit_indisponible_rien():
def test_mode_change_pendant_le_passage():
def test_pas_de_double_ban():
def test_refus_wafctl_conclu_refuse():
def test_incident_95_reste_dans_la_file():   # score 97 : ni ban ni décision ; /proposals le montre « validation_humaine »
```

- [ ] **Étape 2 :** `pytest tests/test_sade_auto.py -v` → ÉCHEC (module absent).
- [ ] **Étape 3 :** implémenter `api/sade_auto.py`. Ordre d'un passage : mode (`active`, sinon sortie) → propositions
  (illisibles ⇒ sortie) → protégés (illisibles ⇒ sortie) → filtrage `cas_sur` → pour chaque retenue : contrôle du
  plafond (`bans_auto_depuis(3600) + len(ips) > 20` ⇒ `changer_mode("observe", "sade-auto")`, audit
  `sade-auto-plafond`, arrêt) → `reclamer(..., "sade-auto", "en_cours", "sade-auto-demande " + _champs(...),
  modes=("active",))` (`DejaTraitee` ⇒ suivante ; `ModeRefuse` ⇒ arrêt) → `_wafctl_ban` par adresse, arrêt au
  premier échec → `conclure` (`applique`, ou `refuse` si wafctl a refusé une adresse) → audit `sade-auto-resultat`.
  Un ban partiel suit `_traiter` : décision `en_attente`, résultat qui nomme les adresses déjà bannies.
- [ ] **Étape 4 :** `pytest tests -q` → tout passe.
- [ ] **Étape 5 :** commit `feat(soc): SADE ACTIVE, exécuteur automatique du cas sûr (ref #3839)`.

### Task 3 : unité minutée, sudo, paquet

**Fichiers :**
- Créer : `packages/secubox-soc/debian/secubox-soc-sade-auto.service`, `packages/secubox-soc/debian/secubox-soc-sade-auto.timer`
- Modifier : `packages/secubox-soc/debian/rules` (installer les deux unités), `debian/postinst`
  (`systemctl enable --now secubox-soc-sade-auto.timer`), `debian/prerm` (`disable --now` timer, `stop` service),
  `debian/changelog` (1.10.0-1~trixie1), `README.md` (§ Modes, § Données et audit), `.claude/RULES-CODE.md` § 10
- Test : `packages/secubox-soc/tests/test_sade_auto_paquet.py`

**Interfaces :**
- Unité : `Type=oneshot`, `User=secubox`, `Group=secubox`, `WorkingDirectory=/usr/lib/secubox/soc`,
  `ExecStart=/usr/bin/python3 -m api.sade_auto`, `TimeoutStartSec=5min`, `NoNewPrivileges=no` (sudo `wafctl ban`,
  exception § 10), `ProtectSystem=strict`, `ReadWritePaths=/var/lib/secubox/soc /var/log/secubox`, `ProtectHome`,
  `PrivateTmp`, `UMask=0027`. Minuterie : `OnBootSec=3min`, `OnCalendar=*:0/2`, `Persistent=false`.
  Le sudoers n'est pas modifié : `SBX_WAF_BANMANUEL` (secubox-waf-ng) accorde déjà `wafctl ban *` à `secubox`.

- [ ] **Étape 1 : test qui échoue :** l'unité porte exactement les directives ci-dessus ; `rules` installe les deux
  unités ; `postinst` active la minuterie ; `prerm` l'arrête ; l'exception § 10 nomme `secubox-soc-sade-auto.service`.
- [ ] **Étape 2 :** `pytest tests/test_sade_auto_paquet.py -v` → ÉCHEC.
- [ ] **Étape 3 :** écrire unités, `rules`, `postinst`, `prerm`, changelog, README, exception § 10.
- [ ] **Étape 4 :** `pytest tests -q` → tout passe ; `dpkg-buildpackage -us -uc -b -d` → le `.deb` contient les deux
  unités (`dpkg -c`).
- [ ] **Étape 5 :** commit `feat(soc): SADE ACTIVE, minuterie de l'exécuteur et paquet 1.10.0 (ref #3839)`.

### Task 4 : façade et page — bouton ACTIVE et compteur

**Fichiers :**
- Modifier : `packages/secubox-soc/api/defense.py` (`/policies` : bloc `auto`)
- Modifier : `packages/secubox-soc/www/soc/defense.html` (bouton ACTIVE, confirmation, carte Seuils, file)
- Test : `packages/secubox-soc/tests/test_sade_active_vue.py`

**Interfaces :**
- `/policies` ajoute `"auto": {"plafond_heure": 20, "bans_derniere_heure": int | None, "score": [60, 94],
  "ttl_max_s": 86400, "adresses_max": 8}` (`None` si la base est illisible, jamais 0).
- `/proposals` : une décision dont `par` vaut `sade-auto` porte `"auto": true`, et la page affiche « appliqué
  automatiquement ».

- [ ] **Étape 1 : tests qui échouent :** `/policies` porte le bloc `auto` (et `None` si la base est illisible) ; le
  bouton `data-mode="active"` n'est plus `disabled` ; `TEXTES_MODE.active` contient « 20 par heure » et « retour en
  OBSERVE » ; `aggressive` reste `disabled`.
- [ ] **Étape 2 :** `pytest tests/test_sade_active_vue.py -v` → ÉCHEC.
- [ ] **Étape 3 :** implémenter. Texte de confirmation : « Passer en ACTIVE : les propositions sûres d'actord (score
  60 à 94, adresse publique, ban de 24 h au plus) seront bannies automatiquement, 20 par heure au plus ; au-delà,
  retour en OBSERVE. Le reste attend votre validation. » Carte Seuils : ligne « Bans automatiques : n / 20 sur
  l'heure ». Le clic sur ACTIVE suit le même chemin confirmé que REACTIVE.
- [ ] **Étape 4 :** `pytest tests -q` → tout passe ; contrôler la syntaxe du script de la page avec `node --check`.
- [ ] **Étape 5 :** commit `feat(soc): SADE, bouton ACTIVE et compteur des bans automatiques (ref #3839)`.

### Task 5 : banc gk6, mesure, puis gk2 sur accord

- [ ] PR, fusion, `scripts/apt-publier.sh`, installation par apt sur **gk6** (maître de test), gk1 et gk3. gk2
  reçoit le paquet mais reste en `reactive`. Sur gk2, l'agrégateur est relancé, et un seul redémarrage groupé suffit.
- [ ] Sur gk6, vérifier que l'unité tourne (`systemctl list-timers secubox-soc-sade-auto.timer`), qu'en `observe`
  elle ne fait rien (audit vide de `sade-auto-*`), puis passer en ACTIVE par la page **avec l'accord du
  propriétaire**.
- [ ] Relevé après 24 h sur gk6 : bans automatiques (`sade-auto-resultat`), écartées, plafond atteint ou non, faux
  positifs (adresse légitime bannie) signalés par le propriétaire. Consigner dans `HISTORY.md`.
- [ ] ACTIVE sur gk2 **uniquement sur accord explicite du propriétaire** après ce relevé.
