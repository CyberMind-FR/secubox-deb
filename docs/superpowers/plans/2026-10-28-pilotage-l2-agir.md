<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Pilotage distant — Livraison L2 « Agir » : plan d'implémentation

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or
> superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal :** depuis le maître, agir sur une box (redémarrer, mettre à niveau, piloter un service, renommer,
renouveler les secrets), ouvrir une session de support consentie, et suivre tout cela en temps réel — sous les
règles « care-safe » : confirmation sur le maître pour ce qui coupe ou efface, accord du détenteur sur une box
cliente, mode « mains liées » réglé sur la box, audit des deux côtés.

**Architecture :** L2 s'appuie sur L1 (agent, canal, contrôleur). L'agent reste non root : chaque action passe par
un ctl root borné sur la box, `secubox-pilotagectl`, appelé par sudo (patron « ctl + sudoers » du dépôt), qui
valide son argv, écrit l'audit local et lance les opérations longues sous `systemd-run`. La politique (mains liées,
box cliente, consentement) est décidée **sur la box** par le ctl, jamais seulement par le maître. Les Operate sont
asynchrones : réponse « acceptée » puis progression et résultat en `Notify`. Le maître relaie ces événements à la
page en direct (flux `text/event-stream` lu par `fetch`).

**Tech Stack :** Go 1.22 (agent), Bash ou Python 3 (ctl root, au choix du bâtisseur, testé), FastAPI, SQLite,
systemd, sudoers, AppArmor.

**Spec :** `docs/superpowers/specs/2026-10-28-pilotage-distant-design.md` (décisions 9 à 14, D3 renommage unique,
D4 actions, support et temps réel, D6, L2). **Prérequis :** plan L1 livré
(`docs/superpowers/plans/2026-10-28-pilotage-l1-voir.md`) ; `secubox-renouvelle-secrets` ≥ 1.8.7 (#3243).

## Global Constraints

- Toutes celles du plan L1 (paquets, versions, Go stdlib, sockets Unix, `require_jwt`, audit, SPDX, nft).
- L'agent **ne devient jamais root** : seule voie d'action = `sudo -n /usr/sbin/secubox-pilotagectl <verbe> …`,
  règle sudoers à argv borné, `NoNewPrivileges=no` sur l'unité de l'agent uniquement pour ce sudo (comme
  `secubox-assist`), et rien d'autre en sudo.
- Verbes du ctl (liste fermée) : `reboot`, `maj-paquets`, `service <demarrer|arreter|redemarrer> <unité>`,
  `renommer <nom>`, `renouveler-secrets`, `support <ouvrir|fermer> <id>`, `consentement <accepter|refuser> <id>`
  (**local seulement**), `mains-liees <on|off>` (**local seulement**), `ancre-verifier`, `politique <action>`.
- Unités pilotables : `^secubox-[a-z0-9][a-z0-9@.-]{0,62}\.(service|timer)$`, jamais `secubox-pilotage-agent`
  (l'agent ne se coupe pas lui-même) ni une unité « protégée » de `/etc/secubox/modules.d/*.toml` (`protected = true`).
- Nom de box : libellé DNS `^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`.
- **Mains liées** (fichier `/etc/secubox/pilotage/mains-liees`, posé et retiré seulement par
  `secubox-pilotagectl mains-liees` lancé en local, root) : tout Operate est refusé sauf
  `Device.X_SECUBOX_Releve.Mesurer()` ; aucune session de support ne s'ouvre ; chaque bascule est auditée et
  notifiée au maître.
- **Box cliente** (agent relié par `wg-autoload`) : `Reboot`, `MettreAJour`, `Service` (arrêter, redémarrer),
  `Renommer`, `Renouveler` exigent l'**accord du détenteur** sur la box (consentement en attente, valable 24 h,
  accepté ou refusé par `secubox-pilotagectl consentement …` en local) ; la lecture et les relevés restent libres.
- **Box du propriétaire** : le maître agit librement ; pour `Reboot`, `Service arreter`, `Renouveler`, `Renommer`,
  la page exige de retaper le nom de la box (confirmation forte côté maître, vérifiée par l'API).
- **Support** : ouvert depuis le maître, accepté sur la box (local), durée bornée (défaut **30 min**, maximum
  **4 h**), révocable des deux côtés, audité ; il donne le catalogue d'actions et la vue en direct, **pas de shell**.
- Opérations longues (`maj-paquets`, `renouveler-secrets`) : `systemd-run --collect --unit=secubox-pilotage-op-<job>`
  sans délai imposé (règle « jamais de timeout sur apt »), progression lue dans le journal de l'unité.
- Audit : sur la box, le ctl écrit chaque demande, refus, consentement et résultat dans
  `/var/log/secubox/audit.log` ; sur le maître, chaque demande et chaque résultat reçu. Champs : box, action,
  acteur (admin du maître), job, résultat ; jamais une valeur secrète.

## Review Focus

- Un administrateur relance l'action pendant qu'elle tourne : une seule opération longue à la fois par box, la
  seconde est refusée avec le job en cours. Test : `test_ctl_une_operation_longue_a_la_fois` (Task 1).
- Le canal tombe au milieu d'une mise à niveau : l'opération continue sur la box (systemd-run), le résultat est
  renvoyé à la reconnexion. Test : `TestAgentRenvoieLeResultatApresReconnexion` (Task 3).
- Mains liées posées pendant qu'une action attend un consentement : le consentement en attente est annulé.
  Test : `test_mains_liees_annule_les_consentements` (Task 1).
- Nom de box déjà pris dans le maillage ou réservé (`admin`, `www`, `secubox`) : refus avant tout changement local.
  Test : `test_renommer_refuse_un_nom_pris` (Task 5).
- Navigateur fermé pendant le flux temps réel : le contrôleur libère l'abonnement, pas de fuite. Test :
  `test_flux_libere_a_la_deconnexion` (Task 7).

---

### Task 1 : ctl root de la box et politique

**Files :** Create `packages/secubox-pilotage-agent/sbin/secubox-pilotagectl`, `sudoers.d/secubox-pilotage-agent`,
`tests/test_pilotagectl.py`.

**Interfaces :**
- Produces : `secubox-pilotagectl <verbe> …` → code 0 et une ligne JSON sur la sortie
  (`{"ok": true, "job": "<id>"}`, `{"ok": false, "refus": "mains liées" | "consentement requis" | …}`), code 2
  pour un argv invalide. `politique <action>` rend `{"autorise": bool, "consentement": bool, "raison": "…"}`
  d'après : mains liées, réseau de la box (`wg-autoload` → cliente), verbe.
  Racine substituable par `SBX_RACINE` **seulement si** l'appelant est root et la variable non vide (même règle
  que `secubox-renouvelle-secrets`).

- [ ] **Step 1 : tests qui échouent**
```python
def test_argv_invalide_rend_2(): ...                # "service redemarrer ../etc" → 2
def test_unite_protegee_refusee(): ...              # secubox-auth protected → refus
def test_agent_ne_se_coupe_pas(): ...               # service arreter secubox-pilotage-agent.service → refus
def test_mains_liees_refuse_tout_sauf_releve(): ...
def test_cliente_exige_un_consentement(): ...       # politique reboot sur box wg-autoload → consentement True
def test_mains_liees_annule_les_consentements(): ...
def test_ctl_une_operation_longue_a_la_fois(): ...
def test_audit_sans_valeur_secrete(): ...
```
- [ ] **Step 2 :** FAIL. **Step 3 :** implémenter (ctl + règle sudoers à argv `secubox-pilotagectl *` avec
  validation complète dans le ctl, comme `secubox-appstorectl`). **Step 4 :** PASS. **Step 5 :** commit.

### Task 2 : vérification de l'ancre (D1, reportée de L1)

**Files :** Modify `sbin/secubox-pilotagectl` (verbe `ancre-verifier`) ; agent `internal/canal/client.go`.

**Interfaces :** `ancre-verifier` compare la clé publique WireGuard du pair qui porte l'adresse du maître
(`wg show <iface> allowed-ips`) à `cle_publique` de `/etc/secubox/p2p/ancre-maitre.json` (box du propriétaire) ;
rend `{"ok": bool}`. L'agent l'appelle au démarrage et toutes les heures ; échec → il coupe le canal, notifie à la
reconnexion suivante qui réussit, et ne traite aucun Operate tant que l'ancre n'est pas vérifiée. Box cliente :
ancre = `hub.pub` d'Auto-Load posé à l'enrôlement (chemin à relever dans `secubox-autoload-agent`).

- [ ] Tests : `test_ancre_conforme`, `test_ancre_differente_refuse`, `TestAgentSansAncreNeFaitRien`. FAIL → impl → PASS → commit.

### Task 3 : Operate asynchrones dans l'agent

**Files :** agent `internal/operations/operations.go` (+ tests) ; Modify `internal/canal/client.go`.

**Interfaces :**
- Commandes acceptées : `Device.Reboot()`, `Device.X_SECUBOX_Packages.MettreAJour()`,
  `Device.X_SECUBOX_Services.Agir()` `{"unite", "action"}`, `Device.X_SECUBOX_Nom.Renommer()` `{"nom"}`,
  `Device.X_SECUBOX_Secrets.Renouveler()`, `Device.X_SECUBOX_Support.Ouvrir()` `{"id", "duree_min"}`,
  `Device.X_SECUBOX_Support.Fermer()` `{"id"}`, plus `Releve.Mesurer()` de L1.
- `OPERATE_RESP` immédiat : `{"etat": "accepte"|"consentement"|"refuse", "job": "<id>", "raison": "…"}` ;
  puis `NOTIFY` `X_SECUBOX_OperationProgress {job, etape, pct}` et `X_SECUBOX_OperationDone {job, rc, resume}`.
- Les résultats non remis (canal coupé) sont gardés en mémoire (au plus 50) et renvoyés à la reconnexion.

- [ ] Tests : `TestOperateRefuseSousMainsLiees`, `TestOperateCliente_Consentement`,
  `TestAgentRenvoieLeResultatApresReconnexion`, `TestOperateInconnuRefuse`. FAIL → impl → PASS → commit.

### Task 4 : consentement et mains liées en local

**Files :** Modify `sbin/secubox-pilotagectl` ; Create `sbin/secubox-pilotage` (commande locale, root,
lisible par un humain) ; tests.

**Interfaces :** `secubox-pilotage etat` (connexion au maître, mains liées, consentements en attente, support
ouvert), `secubox-pilotage consentements`, `secubox-pilotage accepter|refuser <id>`,
`secubox-pilotage mains-liees on|off`, `secubox-pilotage support fermer`. Chaque bascule : audit local +
`NOTIFY X_SECUBOX_HandsTied {etat}` ou `X_SECUBOX_Consent {id, decision}`.

- [ ] Tests : affichage, acceptation, refus, expiration à 24 h, bascule mains liées. FAIL → impl → PASS → commit.

### Task 5 : renommage unique (D3, corrige aussi #3242)

**Files :** Create `packages/secubox-core/sbin/secubox-renommer` (+ tests) ; Modify
`packages/secubox-system/api/main.py` (route `POST /settings` : le nom passe par un ctl root qui appelle
`secubox-renommer`, code de retour lu, erreur rendue) ; Modify `packages/secubox-premier-pas/premier_pas/moteur.py`
(`_renomme` + `hostnamectl` + Avahi remplacés par l'appel à `secubox-renommer`).

**Interfaces :** `secubox-renommer <nom>` (root) : `/etc/hosts` (127.0.1.1), `secubox.conf` (`hostname`),
`hostnamectl set-hostname`, `systemctl try-restart avahi-daemon`, audit `box_renommee {ancien, nouveau}` ; refus
d'un nom invalide, réservé (`admin`, `www`, `secubox`, `localhost`) ou déjà pris au maillage (liste lue dans
`/var/lib/secubox/p2p/peers.json` côté box si présente, sinon refusée par le maître). Côté maître, après
`X_SECUBOX_OperationDone` d'un `Renommer`, le contrôleur émet un code `sbx-mesh-invite --code --nom <nouveau>`
et l'envoie par `Device.X_SECUBOX_Maillage.Rejoindre()` `{"code"}` ; le code ne figure dans aucun journal
(transit dans le tunnel seulement) ; le maître renomme le pair au retour (#3213).

- [ ] Tests : `test_renommer_ecrit_hosts_conf_et_hostname`, `test_renommer_refuse_un_nom_pris`,
  `test_settings_rend_l_echec`, `test_premier_pas_utilise_secubox_renommer`, `test_code_jamais_journalise`.
  FAIL → impl → PASS → versions montées (core, system, premier-pas) → commit `(ref #3126, ref #3242)`.

### Task 6 : actions sur le contrôleur

**Files :** Modify `packages/secubox-pilotage/api/main.py`, `pilotage/stockage.py` (table `operations`) ; tests.

**Interfaces :** `POST /api/v1/pilotage/boxes/{nom}/actions/{action}` (`require_jwt`), corps
`{"args": {...}, "confirmation": "<nom de la box>"}` — `confirmation` exigée pour `reboot`, `service-arreter`,
`renouveler`, `renommer` sur une box du propriétaire (400 sinon) ; `GET /api/v1/pilotage/operations?nom=` ;
`POST /api/v1/pilotage/boxes/{nom}/support` `{"duree_min"}` et `DELETE …/support/{id}`. Audit maître
`pilotage_action {box, action, acteur, job}` et `pilotage_action_resultat {job, rc}`.

- [ ] Tests : confirmation manquante → 400 ; box cliente → état « consentement » renvoyé tel quel ; support
  borné à 240 min ; audit écrit. FAIL → impl → PASS → commit.

### Task 7 : temps réel vers la page

**Files :** Modify `packages/secubox-pilotage/api/main.py` (route `GET /api/v1/pilotage/boxes/{nom}/flux`) ;
`pilotage/diffusion.py` (abonnements) ; tests.

**Interfaces :** réponse `text/event-stream` (lue côté page par `fetch` + `ReadableStream`, l'en-tête
`Authorization` restant possible) ; événements `notify`, `operation`, `etat` ; battement toutes les 15 s ; au plus
**4** flux par administrateur ; abonnement libéré à la déconnexion.

- [ ] Tests : `test_flux_recoit_les_notifications`, `test_flux_libere_a_la_deconnexion`, `test_flux_limite_par_admin`.
  FAIL → impl → PASS → commit.

### Task 8 : page de la box dans la Flotte

**Files :** Modify `packages/secubox-annuaire/www/fleet/index.html` (vue détaillée d'une box du panneau
Pilotage) ; tests statiques.

**Interfaces :** boutons d'action (désactivés sous mains liées, libellés « en attente de l'accord du détenteur »
sur une box cliente), champ « retapez le nom de la box » pour les actions fortes, journal des opérations,
progression en direct, ouverture et fermeture du support ; XSS-strict, charte Aurora.

- [ ] Tests : boutons absents sous mains liées ; confirmation exigée ; aucune donnée en `innerHTML`. FAIL → impl → PASS → commit.

### Task 9 : un seul catalogue d'actions (assist)

**Files :** Modify `packages/secubox-assist/` (catalogue retiré, sessions redirigées vers le support du pilotage),
README, tests.

**Interfaces :** le catalogue de `secubox-assist` (`catalog.py`) n'est plus la référence : ses actions sont
servies par `secubox-pilotagectl` ; les routes de session d'assist rendent 410 avec un lien vers
`/api/v1/pilotage/…/support`. Rien n'est supprimé sur les box sans que le paquet ait été mis à niveau.

- [ ] Tests : routes d'assist → 410 ; plus d'import de `catalog.py` côté démon. FAIL → impl → PASS → commit.

### Task 10 : banc et déploiement

- [ ] gk5 (propriétaire) : redémarrage depuis la page, retour en ligne notifié ; `service redemarrer` d'un module ;
  mise à niveau suivie en direct ; renommage aller-retour (gk5 → gk5b → gk5) avec mise à jour du maillage ;
  mains liées posées en local → toute action refusée, relevé encore possible.
- [ ] lgm-ebin (cliente) : `reboot` demandé → « consentement » ; accepté en local → exécuté ; refusé → audit.
- [ ] Support ouvert 30 min, fermé depuis la box, audit des deux côtés.
- [ ] Publication par `scripts/apt-publier.sh`, HISTORY.md, WIP.md, PR vers master.
