# Détecteur d'intrusion, d'évasion et d'infection (secubox-garde) — plan

> **Pour les agents :** sous-compétence REQUISE : superpowers:subagent-driven-development (recommandé) ou
> superpowers:executing-plans, tâche par tâche. Étapes en cases à cocher (`- [ ]`).

**But :** un module `secubox-garde` qui lit les détecteurs existants, décide seul (ban, quarantaine DNS, fermeture d'évasion),
applique par les mécanismes existants et prévient (webapp, courriel, SMS Free Mobile).

**Architecture :** `secubox-garde` = orchestrateur Python (FastAPI sur `/run/secubox/garde.sock`, utilisateur `secubox-garde`,
SQLite `/var/lib/secubox/garde/garde.db`, TOML `/etc/secubox/garde.toml`). Une **politique pure** (`politique.py`, sans E/S)
transforme des signaux en décisions ; des **sources** lisent les fichiers des capteurs ; des **effecteurs** appellent le WAF (nouveau
geste `garde-ban`) et le ctl root d'ad-guard (nouveaux verbes `quarantaine`, `evasion`) ; des **notificateurs** envoient courriel et
SMS. Un minuteur lance un passage par minute.

**Pile :** Python 3.11+ (trixie), FastAPI, SQLite, `secubox_core` (auth, courriel, compte_service), nftables via sbxwaf, Unbound.

**Spec :** `docs/superpowers/specs/2026-11-18-detecteur-intrusion-design.md` ; maquette approuvée :
https://claude.ai/artifact/UAHZoqPfPiEiSG9qWzaM2G

## Contraintes globales

- `AGENTS.md` : socket Unix, utilisateur dédié, AppArmor enforce, aucun secret dans le code (`/etc/secubox/secrets/garde-sms`, 0600),
  chaque décision dans `/var/log/secubox/audit.log` (append-only), nftables seulement, LXC seulement, SPDX CMSD-1.0 sur tout fichier.
- Version `X.Y.Z-1~trixie1`, `debian/compat` 13, `Standards-Version: 4.6.2`, `postinst` `systemctl enable --now`, `prerm` `systemctl stop`.
- Gardes d'API : lecture `require_lecture` ; toute action (libérer, débannir, réglages, test d'envoi) `require_jwt`.
- Relais seul d'abord : aucune tâche n'exige que la box route le trafic.
- Valeurs fixées par la spec : ban 4 h (14 400 s), ×4 par récidive sur 7 j, plafond 30 j (2 592 000 s) ; quarantaine 24 h ;
  non-récidive 7 j après libération ; 3 quarantaines simultanées au plus ; 1 SMS par appareil et par heure ; résumé des bans par
  heure ; rafale = plus de 50 bans en 10 min.
- Jamais d'action sur : adresses privées/ULA/lien-local, maillage (`10.100.0.0/16`, plage wg-mesh lue dans la config), Freebox
  (passerelle par défaut), adresses de la box et de ses LXC.
- Signes seuls jamais suivis d'action : `dga`, `high_rate` (dérive de débit) ; ils sont enregistrés « signalé ».
- Jamais `git stash` ; un worktree par issue ; déploiement par apt (`scripts/apt-publier.sh`), gk7 d'abord, gk2 ensuite.

## Révisions de la spec imposées par l'existant (repérage du 18/11)

- L'`ai-ban` existant n'accepte en `auto` que des blocs /24 (≥ 20 adresses déjà bannies), 24 h au plus : inutilisable. **Tâche 5**
  ajoute un geste `garde-ban` (compte de service `garde`, portée `garde-ban`) : une adresse publique seule, 3 600 à 2 592 000 s.
- Les alertes DNS (`/var/lib/secubox/dns-guard/alerts.jsonl`) portent `client_ip`, pas de MAC : la MAC vient de la table des voisins.
- Le capteur DPI n'écrit que dans actord ; garde lit `/run/secubox/actord-propositions.json` (`propositions[].ips`, `raison`).
- Le courriel passe par `secubox_core/courriel.py` vers le MTA `10.100.0.10:25` (LXC mail de gk2, joignable par le maillage).

## Points de vigilance (non couverts par les tests unitaires, à tester où indiqué)

1. Une TV dont l'IP change pendant sa quarantaine (bail DHCP) : la quarantaine suit la MAC → **Tâche 7** `test_quarantaine_suit_la_mac`.
2. Le fichier d'alertes tourne ou est tronqué : la lecture incrémentale ne relit pas tout ni ne saute → **Tâche 4** `test_rotation_alertes`.
3. Pas de WAN : les SMS restent en file et partent au retour, sans doublon → **Tâche 2** `test_file_sms_rejouee_sans_doublon`.
4. Redémarrage de la box : les décisions en cours sont réappliquées avec leur fin d'origine, les échues levées → **Tâche 7** `test_rapprochement_demarrage`.
5. Rafale de faux positifs (capteur déréglé) : au-delà de 3 quarantaines, alerte unique, aucune 4e → **Tâche 3** `test_plafond_quarantaines`.

---

### Tâche 1 : squelette du paquet secubox-garde

**Fichiers :** créer `packages/secubox-garde/` sur le modèle de `packages/secubox-status/` :
`api/__init__.py`, `api/main.py` (router `APIRouter(prefix="/api/v1/garde")`, `GET /health` ouvert, `GET /etat` `require_lecture`),
`garde/__init__.py`, `garde/base.py`, `conf/garde.toml`, `apparmor/secubox-garde`, `nginx/garde.conf`, `menu.d/7xx-garde.json`
(numéro libre voisin de status), `debian/{changelog,control,postinst,prerm,postrm,rules,secubox.yaml,source/format,compat}`,
`debian/secubox-garde.service`, `debian/secubox-garde-passage.service`, `debian/secubox-garde-passage.timer` (OnUnitActiveSec=60s),
`README.md`, `tests/test_base_3794.py`.

**Interfaces produites :**
- `garde.base.ouvrir(chemin: Path) -> sqlite3.Connection` : crée le schéma si absent (WAL). Tables :
  `decisions(id TEXT PK, menace TEXT CHECK IN ('infection','evasion','intrusion','signale'), cible TEXT, mac TEXT, ip TEXT,
  motif TEXT, signe TEXT, debut INT, fin INT, etat TEXT CHECK IN ('active','levee','echue'), leve_par TEXT, notifie TEXT)`,
  `positions(source TEXT PK, inode INT, offset INT)`, `liberations(mac TEXT, signe TEXT, jusqua INT, PRIMARY KEY(mac,signe))`,
  `file_notifs(id INTEGER PK, canal TEXT, cle TEXT, texte TEXT, cree INT, essais INT, envoye INT)`, `recidives(ip TEXT PK, n INT, dernier INT)`.
- `garde.base.reglages(chemin: Path = Path("/etc/secubox/garde.toml")) -> dict` avec défauts : `{"automatique": True,
  "courriel": "", "sms_utilisateur": "", "sms_bans": False, "quarantaines_max": 3, "rafale_bans": 50}`.

- [ ] Test `test_schema_cree_et_idempotent` : `ouvrir()` deux fois sur `tmp_path/"g.db"` → les 5 tables existent, aucune erreur.
- [ ] Test `test_reglages_defauts_et_fichier_absent` : chemin inexistant → dict de défauts ci-dessus ; TOML partiel → défauts complétés.
- [ ] Lancer `pytest packages/secubox-garde/tests -q` → échec (module absent). Implémenter. Relancer → succès.
- [ ] `postinst` : `adduser --system --ingroup secubox … secubox-garde` (comme status), `install -d -o secubox-garde -m 0750
  /var/lib/secubox/garde`, TOML semé une fois 0640 root:secubox, `systemctl enable --now secubox-garde.service
  secubox-garde-passage.timer`. Unité API : `User=secubox-garde`, `RuntimeDirectory` non utilisé (socket dans `/run/secubox`,
  cf. mémoire RuntimeDirectory), `AppArmorProfile=secubox-garde`, `ProtectSystem=strict`, `ReadWritePaths=/var/lib/secubox/garde`.
- [ ] `dpkg-buildpackage -us -uc -b` dans le paquet → `.deb` produit, `lintian` sans erreur.
- [ ] Commit `feat(garde): squelette du module (ref #3794)`.

### Tâche 2 : notifications (courriel, SMS Free Mobile, file d'attente)

**Fichiers :** créer `garde/notifs.py`, `tests/test_notifs_3794.py`.

**Interfaces :**
- Consomme : `garde.base.ouvrir`, `secubox_core.courriel` (fonction d'envoi existante ; lire sa signature).
- Produit :
  - `mettre_en_file(db, canal: Literal["courriel","sms"], cle: str, texte: str, maintenant: int) -> bool` — False si un SMS de même
    `cle` (= MAC ou "bans") a été mis en file depuis moins de 3 600 s (1 SMS par appareil et par heure) ; le courriel n'est pas limité.
  - `vider_file(db, reglages: dict, envoyer_sms: Callable[[str,str,str],bool], envoyer_courriel: Callable[[str,str,str],bool],
    maintenant: int) -> dict` → `{"envoyes": n, "en_attente": m}` ; essais plafonnés à 48 puis abandon journalisé.
  - `sms_free(utilisateur: str, cle: str, texte: str, http=urllib) -> bool` : `GET https://smsapi.free-mobile.fr/sendmsg?user=…&pass=…&msg=…`
    (paramètres encodés), True sur 200, False sinon ; jamais la clé dans un journal.
  - `lire_cle_sms(chemin=Path("/etc/secubox/secrets/garde-sms")) -> str` : contenu nettoyé, "" si absent.
  - `expediteur() -> str` : `f"{nom_du_noeud}@secubox.in"` (nom via `secubox_core.auth.nom_box_locale()`).

- [ ] Tests : `test_sms_un_par_appareil_et_par_heure` (2e mise en file même MAC à +60 s → False ; à +3 601 s → True) ;
  `test_file_sms_rejouee_sans_doublon` (envoyer_sms renvoie False puis True : 1er vidage en_attente=1, 2e envoyes=1, 3e envoyes=0) ;
  `test_sms_free_url_et_cle_absente_du_journal` (faux http capture l'URL : contient `user=12345678` et `msg=` encodé ; `caplog` ne
  contient pas la clé) ; `test_expediteur_nom_du_noeud` (nom monkeypatché "gk2" → "gk2@secubox.in").
- [ ] Échec, implémentation, succès. Commit `feat(garde): notifications courriel et SMS Free Mobile (ref #3794)`.

### Tâche 3 : politique (pure, sans E/S)

**Fichiers :** créer `garde/politique.py`, `tests/test_politique_3794.py`.

**Interfaces :**
- Produit :
  - `@dataclass Signal(source: str, type: str, ip: str, mac: str|None, domaine: str, regle: str, ts: int)` ; `type` ∈
    `malicious, dga, tunneling, high_rate, exfiltration, doh, intrusion`.
  - `@dataclass Decision(menace: str, cible: str, mac: str|None, ip: str, motif: str, signe: str, debut: int, fin: int)`.
  - `decider(signaux: list[Signal], actives: list[Decision], liberations: dict[tuple[str,str],int], recidives: dict[str,int],
    protegees: Callable[[str],bool], reglages: dict, maintenant: int) -> tuple[list[Decision], list[str]]` → (nouvelles
    décisions, alertes texte).
- Règles (de la spec) :
  - `intrusion` : IP publique non `protegees` → ban, durée `min(14400 * 4**n, 2592000)` où `n` = récidives sur 7 j.
  - `evasion` : `doh` ou `tunneling` d'un appareil → menace `evasion`, signe = type, fin = maintenant+86 400 (revue).
  - `infection` : `malicious` seul suffit ; sinon ≥ 2 types distincts parmi `{dga, exfiltration, malicious}` pour la même MAC/IP en
    3 600 s ; signe = types triés joints par `+`.
  - `dga` ou `high_rate` seuls → Decision `signale` (fin = debut), jamais d'effet.
  - Aucune nouvelle décision pour une cible déjà active de même menace ; aucune infection pour `(mac, signe)` libéré avant `jusqua`.
  - Plus de `quarantaines_max` infections actives : aucune nouvelle, une alerte « comportement de masse anormal » (une fois).
  - `reglages["automatique"] is False` : décisions renvoyées en `signale` (prévenir seulement).
- [ ] Tests, un par règle : `test_malicious_seul_isole`, `test_dga_seul_signale_sans_action`, `test_deux_familles_en_une_heure`,
  `test_deux_familles_espacees_de_deux_heures_signale`, `test_ban_duree_croissante_et_plafond` (n=0 → 14 400 ; n=2 → 230 400 ;
  n=9 → 2 592 000), `test_jamais_adresse_privee_ni_maillage` (192.168.1.5, 10.100.0.3, fd00::1 → aucune décision),
  `test_liberee_pas_de_nouvelle_quarantaine_7j`, `test_plafond_quarantaines` (3 actives + 1 nouvelle → 0 décision, 1 alerte),
  `test_mode_alerte_seule`, `test_tunnel_est_evasion_pas_infection`.
- [ ] Échec, implémentation, succès. Commit `feat(garde): politique de décision (ref #3794)`.

### Tâche 4 : sources (alertes DNS, propositions actord, voisins)

**Fichiers :** créer `garde/sources.py`, `tests/test_sources_3794.py`.

**Interfaces :**
- Produit :
  - `lire_alertes_dns(db, chemin=Path("/var/lib/secubox/dns-guard/alerts.jsonl"), voisins: dict[str,str]) -> list[Signal]` :
    incrémental par `positions` (inode + offset ; inode changé ou taille < offset → reprise à 0) ; une ligne invalide est ignorée ;
    `type` repris tel quel, `regle` = `details.rule`, `ts` depuis `timestamp`.
  - `lire_propositions(chemin=Path("/run/secubox/actord-propositions.json")) -> list[Signal]` : un Signal `intrusion` par IP de
    `propositions[].ips`, `regle` = `raison` ; fichier absent → [].
  - `signaux_doh(evenements_dns: Iterable[dict], noms_doh: set[str], voisins) -> list[Signal]` : un Signal `doh` par client qui
    résout un nom de `resolveurs-doh.txt` (chargé par `dnstv_dpi.charger_resolveurs()` d'ad-guard, réutilisé par import ou relu).
    Source des requêtes : journal DNS par client d'ad-guard (`dnstv_recents` / magasin d'événements, choisir celui lisible sans root
    et le nommer dans le README).
  - `voisins(ip_neigh=("ip","-j","neigh")) -> dict[str,str]` : IP → MAC (états REACHABLE/STALE/DELAY), sortie JSON de `ip`.
- [ ] Tests : `test_alertes_incrementales` (2 lignes, lecture, +1 ligne, relecture → 1 signal) ; `test_rotation_alertes` (fichier
  remplacé, inode différent → relu depuis 0, aucun doublon des anciennes) ; `test_ligne_invalide_ignoree` ;
  `test_propositions_vers_signaux` ; `test_voisins_json` (sortie `ip -j neigh` fixe → dict) ; `test_doh_par_client`.
- [ ] Échec, implémentation, succès. Commit `feat(garde): lecture des capteurs (ref #3794)`.

### Tâche 5 : WAF — geste `garde-ban` (secubox-waf-ng)

**Fichiers :** modifier `packages/secubox-waf-ng/composants/waf/api/gestes_ia.py` (route, modèle, plafonds),
`common/secubox_core/compte_service.py:67-69` (compte `garde`, portée `garde-ban`), `wafctl` (verbe `cle-garde-ban` sur le modèle
de `cle-ai-ban`), tests du composant.

**Interfaces :**
- Produit : `POST /api/v1/waf/garde/ban`, corps `{"geste":"ban","cible":"<IPv4|IPv6 publique seule>","duree_s":3600..2592000,
  "motif":"≤200"}` (champs en trop refusés), jeton EdDSA `sub="garde"`, `portee="garde-ban"`, mêmes règles que ai-ban (aud, jti
  unique, corps haché, 60 s). Applique par le MÊME chemin que l'ai-ban (ensembles `waf_ban`/`waf_ban6` avec timeout, ligne dans
  `bans.jsonl`), audit `/var/lib/secubox/waf/garde-ban.jsonl` + `/var/log/secubox/audit.log`. Plafonds `{"heure":120,"jour":1000}`.
  Réponse 200 `{id, cible, fin, audit}` ; 409 `{"detail":{"motif"}}`.
- Consomme côté garde (Tâche 7) : `secubox_core.compte_service.frapper_jeton(cle_privee_pem, "garde", aud, corps, maintenant)`.
- [ ] Tests : `test_garde_ban_ip_publique` ; `test_garde_ban_refuse_privee_ula_bloc` (192.168.0.1, fd00::1, 1.2.3.0/24 → 409) ;
  `test_garde_ban_duree_hors_bornes` ; `test_garde_ban_jeton_portee_ai_ban_refuse` ; `test_garde_ban_plafond_heure` ;
  `test_garde_ban_audite`.
- [ ] Monter la version de secubox-waf-ng. Échec, implémentation, succès (suite du composant entière). Commit
  `feat(waf): geste garde-ban pour secubox-garde (ref #3794)`.

### Tâche 6 : ad-guard — verbes `quarantaine` et `evasion` (root ctl)

**Fichiers :** modifier `packages/secubox-ad-guard/api/dnstv.py` (état + `rendre_unbound()`), `sbin/secubox-adguard-tv`
(verbes), `sudoers.d/secubox-adguard-tv` (utilisateur `secubox-garde`, verbes `quarantaine`, `evasion` seulement), tests.

**Interfaces :**
- Produit (ctl, sortie JSON `{"ok":bool,…}`) :
  - `secubox-adguard-tv quarantaine poser <ip> <mac|-> <fin_epoch>` / `quarantaine lever <ip|mac>` ;
  - `secubox-adguard-tv evasion poser <ip> <mac|-> <nom>[,<nom>…]` / `evasion lever <ip|mac>`.
  - État : `etat.json` clés `quarantaines: [{ip, mac, fin}]`, `evasions: [{ip, mac, noms}]`, validées (IP par `IP_SURE_RE`,
    noms par `valider_domaine`, au plus 16 entrées chacune).
  - `rendre_unbound()` : un client en quarantaine reçoit la vue `sbx-quarantaine-<slug>` : `local-zone: "." redirect` +
    `local-data` A/AAAA vers l'adresse de la box, sauf la liste indispensable en `local-zone: "<nom>" transparent`
    (`secubox.in`, `ntp.org`, `pool.ntp.org`, `time.android.com`, `time.apple.com`, `connectivitycheck.gstatic.com`) **plus** les
    `local-zone` always_nxdomain de son profil TV Privacy s'il en a un (#3674 : conservé). Un client en évasion garde sa vue et
    reçoit en plus `local-zone: "<nom>" always_refuse` pour chaque nom.
  - Lever restaure la vue précédente (la vue est recalculée depuis l'état, rien n'est mémorisé à part).
- [ ] Tests : `test_quarantaine_vue_redirect_et_indispensables` ; `test_quarantaine_garde_profil_tv` ; `test_lever_rend_la_vue_dorigine`
  (rendu identique à avant pose) ; `test_evasion_refuse_les_noms` ; `test_ip_invalide_refusee` ; `test_sudoers_garde_verbes_limites`.
- [ ] Monter la version d'ad-guard. Suite ad-guard complète verte (attention : ne pas toucher `www/tv-privacy/index.html`, empreinte
  CSP). Commit `feat(ad-guard): quarantaine et fermeture d'évasion par appareil (ref #3794)`.

### Tâche 7 : moteur (passage, effecteurs, rapprochement)

**Fichiers :** créer `garde/moteur.py`, `garde/effets.py`, `sbin/secubox-garde-passage` (point d'entrée du minuteur), tests.

**Interfaces :**
- Consomme : Tâches 2 à 6.
- Produit :
  - `effets.bannir(ip, duree_s, motif) -> dict` (appel du geste `garde-ban` sur la socket du WAF, clé privée
    `/etc/secubox/secrets/garde-ban.pem`) ; `effets.isoler(ip, mac, fin)`, `effets.liberer(ip, mac)`, `effets.fermer_evasion(ip,
    mac, noms)`, `effets.rouvrir(ip, mac)` (sudo `secubox-adguard-tv …`). Chacun écrit une ligne JSON dans
    `/var/log/secubox/audit.log` (`{"ts","module":"garde","action","cible","motif","resultat"}`).
  - `moteur.passage(db, reglages, sources, effets, notifs, maintenant) -> dict` : lit les sources, `decider`, applique,
    enregistre, met en file les notifications (infection/évasion : SMS + courriel immédiats ; intrusion : compteur pour le résumé
    horaire, SMS si rafale), lève les décisions échues (infection : réévaluation — si aucun nouveau signal du même appareil depuis
    la décision, lever ; sinon prolonger de 24 h), vide la file de notifications.
  - `moteur.rapprocher(db, effets, maintenant)` : appelé au démarrage du service ; réapplique les décisions `active` non échues
    (fin d'origine), marque `echue` les autres.
  - Une quarantaine est identifiée par la MAC quand elle est connue : si l'IP de la MAC change (voisins), `effets.liberer(ancienne)` puis
    `effets.isoler(nouvelle)`.
- [ ] Tests (effets et sources simulés) : `test_passage_infection_isole_et_previent` ; `test_passage_intrusion_resume_horaire` ;
  `test_rafale_bans_envoie_un_sms` ; `test_reevaluation_24h_leve_ou_prolonge` ; `test_quarantaine_suit_la_mac` ;
  `test_rapprochement_demarrage` ; `test_echec_effet_pas_de_decision_active` (effet en erreur → décision non enregistrée active,
  alerte journalisée).
- [ ] AppArmor : lecture `alerts.jsonl`, `actord-propositions.json`, `/etc/secubox/secrets/garde-*` r ; exécution `ip`, `sudo` ;
  écriture `/var/lib/secubox/garde/**`, `/var/log/secubox/audit.log` a. Unité passage : `User=secubox-garde`,
  `SupplementaryGroups` nécessaires à la lecture des fichiers (vérifier leurs droits sur gk7 et le noter).
- [ ] Échec, implémentation, succès. Commit `feat(garde): moteur de décision et d'application (ref #3794)`.

### Tâche 8 : API et page /garde/

**Fichiers :** modifier `api/main.py` ; créer `www/garde/index.html` (Aurora, conforme à la maquette approuvée et à
`.claude/AURORA-REFERENCE.md`), `tests/test_api_3794.py`, `tests/test_page_garde_3794.py` (Playwright, comme ad-guard).

**Interfaces (API) :**
- `GET /api/v1/garde/etat` (`require_lecture`) → `{"tuiles":{isoles,evasions,bannis,recidivistes,notifs_24h,en_attente},
  "actives":[Decision…], "automatique":bool}` ;
- `GET /api/v1/garde/historique?heures=24` (`require_lecture`) ;
- `POST /api/v1/garde/liberer` `{id}`, `POST /api/v1/garde/rouvrir` `{id}`, `POST /api/v1/garde/debannir` `{ip}` (`require_jwt`) :
  appliquent par `effets`, enregistrent `liberations` (7 j) et l'audit ;
- `GET|POST /api/v1/garde/reglages` (POST `require_jwt`) : `automatique`, `courriel`, `sms_utilisateur`, `sms_bans` ; la clé SMS
  est écrite par `POST /api/v1/garde/cle-sms` (`require_jwt`) via le ctl root (jamais relue par l'API) ;
- `POST /api/v1/garde/tester` `{canal}` (`require_jwt`).
- Page de quarantaine : servie pour l'adresse de la box en HTTP. **Étape de repérage d'abord** : sur gk7, vérifier ce que répond
  aujourd'hui `curl -H 'Host: inconnu.example' http://<ip box>/` depuis le LAN (HAProxy → sbxwaf « unrouted ») ; puis déclarer
  la réponse par le mécanisme déclaratif de routes (`secubox-waf-route` / `haproxy.toml`, jamais à la main) vers un fichier
  statique `www/garde/isole.html` (texte de la maquette, sans bouton). Consigner la voie retenue dans le README.
- [ ] Tests API : gardes (`liberer` sans jeton → 401 ; lecture avec `require_lecture`) ; `test_liberer_enregistre_7j` ;
  `test_reglages_sans_cle_dans_reponse`. Tests page : rendu des tuiles et des cartes, « Libérer » demande confirmation, aucun
  débordement horizontal à 420 et 1 400 px, CSP stricte par empreinte.
- [ ] Échec, implémentation, succès. Commit `feat(garde): API et page de la garde (ref #3794)`.

### Tâche 9 : livraison (gk7 puis gk2)

- [ ] `relecteur-securite` sur le diff complet de la branche ; corriger les constats bloquants.
- [ ] Construire et publier les trois paquets (`secubox-garde`, `secubox-waf-ng`, `secubox-ad-guard`) par `scripts/apt-publier.sh`.
- [ ] gk7 d'abord : installer, poser la clé `garde-ban` (`wafctl cle-garde-ban`), régler courriel + SMS par la page, « Envoyer un
  test » (SMS et courriel reçus par le propriétaire). Vérifier : un domaine de la liste malveillante résolu depuis un appareil de
  test → isolement, page d'explication, SMS, courriel ; « Libérer » rend la vue d'origine.
- [ ] gk2 ensuite (prod, `df -h /` d'abord) ; surveiller 24 h les bans et l'absence de quarantaine à tort.
- [ ] Suivi : `HISTORY.md`, `WIP.md`, README des trois paquets ; `closes #3794` seulement après une journée sans anomalie.
