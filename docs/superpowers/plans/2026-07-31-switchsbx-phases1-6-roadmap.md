# SwitchSBX — Feuille de route des phases 1 à 6

**Date :** 2026-07-31 · **Spec :** [`2026-07-31-switchsbx-design.md`](../specs/2026-07-31-switchsbx-design.md)
**Phase 0 :** [`2026-07-31-switchsbx-phase0-colmatage.md`](2026-07-31-switchsbx-phase0-colmatage.md) — plan exécutable complet

---

## Pourquoi ce document n'est pas sept plans détaillés

Les phases 3 à 6 dépendent de prérequis non tranchés — le domaine stable qui servira de `RP ID` WebAuthn, et la faisabilité du plugin `androidx.credentials` en WebView Capacitor. Écrire aujourd'hui des étapes TDD pour elles produirait des instructions qu'il faudrait jeter. Chaque phase ci-dessous porte donc son périmètre, ses fichiers, ses tâches et ses **critères de sortie** ; elle devient un plan complet — au format de la phase 0 — quand ses prérequis sont levés.

Les phases 0 et 1 sont indépendantes de SwitchSBX et livrent de la valeur seules. Les phases 2 à 6 se suivent.

---

## Phase 1 — Le rôle entre dans le jeton

**Problème.** Le JWT ne porte que `sub`/`iat`/`exp`/`jti`. Sur ~112 fichiers utilisant `require_jwt`, **4** vérifient un rôle : tout compte authentifié dispose en pratique des pouvoirs admin sur presque tous les modules.

**Périmètre.** `common/secubox_core/auth.py` (ajout de `role` et `policy_version` aux jetons émis, nouvelle dépendance `require_role`), puis application module par module.

**Tâches.**
1. `create_token()` lit le rôle depuis `user_store` et l'inscrit dans le jeton ; `_validate_token()` le revérifie contre le magasin à chaque requête — un jeton ne doit pas porter un rôle révoqué depuis.
2. `require_role("admin")` dans `secubox_core`, construit au-dessus de `require_jwt`.
3. Inventaire des endpoints à pouvoir root : `grep -rl "sudo\|subprocess" packages/*/api/`. Ce sont eux qui passent en premier.
4. Application par lots de 10 modules, un commit par lot, en commençant par les modules à `ctl` privilégié.
5. Les 4 modules qui vérifient déjà un rôle à la main (`auth`, `dpi`, `peertube`, `portal`) basculent sur `require_role` — supprimer la logique dupliquée.

**Prérequis.** Phase 0 tâche 1 (le paramètre `scope` de `require_jwt`).

**Critères de sortie.**
- Un compte `role: user` reçoit 403 sur tout endpoint d'administration.
- Aucun module ne relit le rôle à la main.
- Un test paramétré balaie tous les endpoints `POST`/`DELETE` et échoue si l'un accepte un rôle `user`.

**Risque.** C'est la phase la plus susceptible de casser l'exploitation courante : un endpoint marqué admin par erreur bloque un usage légitime. Déployer avec un mode « journaliser au lieu de refuser » pendant une semaine avant d'appliquer.

---

## Phase 2 — Registre d'appareils et daemon

**Périmètre.** Nouveau paquet `secubox-switchsbx`. Aucune décision n'en dépend encore : on constitue la donnée et on valide le mécanisme d'instantané.

**Fichiers.**
- `packages/secubox-switchsbx/switchsbx/registry.py` — SQLite, schéma `Device` de la spec §3
- `packages/secubox-switchsbx/switchsbx/snapshot.py` — écriture de l'instantané JSON, double-buffer 4R
- `common/secubox_core/switchsbx.py` — lecteur d'instantané côté bibliothèque, rechargement `inotify`
- `packages/secubox-switchsbx/debian/` — unité systemd, utilisateur dédié, profil AppArmor
- `packages/secubox-switchsbx/sbin/switchsbxctl` — CLI privilégiée (le panel délègue, ne fait rien en processus)

**Tâches.**
1. Schéma SQLite + migrations, avec les champs de la spec §3.
2. Écriture de l'instantané en double-buffer `active/` / `shadow/` / `rollback/R1..R4`.
3. Lecteur côté `secubox_core` : parsé une fois, rechargé sur `inotify`, *fail-closed* si illisible.
4. `switchsbxctl device list|show|admit|promote|revoke`, sudoers cadré au paquet.
5. Banc de mesure : latence de lecture de l'instantané sous 1 000 appareils.

**Critères de sortie.**
- Le daemon tourne sous son propre utilisateur, `NoNewPrivileges`, AppArmor en `enforce`.
- Tuer le daemon ne change aucune décision (il n'y en a pas encore) et ne casse aucun module.
- Un instantané corrompu fait tomber le lecteur en *fail-closed*, prouvé par test.
- La lecture reste une recherche en table : latence mesurée et consignée.

---

## Phase 3 — Enrôlement

**Prérequis bloquants.**
- **Domaine stable** pour le `RP ID` WebAuthn. Un changement de domaine invalide tous les credentials. À trancher avant d'écrire une ligne.
- **Faisabilité WebView.** Valider `androidx.credentials` en plugin natif Capacitor plutôt que l'API web dans la WebView, et produire l'`assetlinks.json`.

**Périmètre.** Compagnon (PWA + APK) et daemon.

**Tâches.**
1. Plugin natif Capacitor exposant `create()` / `get()` WebAuthn au JS du Compagnon.
2. Écran d'enrôlement : scan du QR imprimé, création du credential, `POST /switchsbx/enroll`.
3. QR parrainé — reprendre le mécanisme du spec du 2026-07-30 (jeton court à usage unique, encodeur JS embarqué, **emoji au centre**, aucun CDN), amendé : le parrainage vaut admission en VISITOR, la promotion USER reste admin.
4. File d'admission dans la webui admin, affichant **l'attestation** pour que l'admin distingue une clé matérielle d'une clé simulée.
5. Limite de débit d'enrôlement par box, journalisation de chaque tentative.
6. Rotation du secret d'enrôlement depuis la webui.

**Critères de sortie.**
- Un appareil neuf passe de `PENDING` à `VISITOR` après une action admin tracée dans `admitted_by`.
- Un appareil `PENDING` n'atteint que sa page d'attente — vérifié par test.
- Le QR imprimé ne contient aucune configuration WireGuard.
- Une clé auto-attestée est admissible mais plafonnée en confiance.

---

## Phase 4 — PKI

**Périmètre.** CA dédiée, émission liée au credential, mTLS optionnel sur HAProxy.

**Tâches.**
1. CA SwitchSBX dans `/etc/secubox/switchsbx/ca/`, clé 0600 propriété du daemon. **Jamais la CA MITM `ca-wg`** — elle est distribuée à tous les clients.
2. Émission : le hash de la CSR est signé comme challenge WebAuthn ; la box vérifie que la CSR émane du détenteur du credential.
3. TTL 24 h, renouvellement en tâche de fond à mi-vie (~12 h), exigeant une assertion WebAuthn.
4. Liste de révocation dans l'instantané — ni OCSP ni CRL, sans valeur ici.
5. mTLS HAProxy pour APK natif et navigateur desktop ; l'empreinte du certificat passe en en-tête aux applications.
6. Promotion `VISITOR → USER` : l'utilisateur s'authentifie, l'admin confirme, `promoted_by` est tracé.

**Critères de sortie.**
- Un certificat non lié à un credential est refusé à l'émission.
- Un appareil dont la clé matérielle ne peut plus signer voit son certificat expirer et retombe en VISITOR.
- HAProxy valide le certificat **une fois par connexion**, pas par requête — vérifié sous keep-alive.

---

## Phase 5 — Moteur de décision

**Périmètre.** La fonction pure `evaluate(evidence) → Decision` et ses points d'application.

**Tâches.**
1. `switchsbx.evaluate()` — fonction pure, sans E/S, testée par la table de vérité de la spec §9.
2. **Mode observation d'abord** : le moteur journalise ce qu'il *aurait* décidé, sans rien appliquer. Indispensable pour ne pas se verrouiller hors de la box.
3. Application progressive — d'abord le périmètre VISITOR (kabinet MITM seul), puis les vhosts.
4. Points d'application : `require_jwt`, cible `auth_request` de nginx, routage sbxwaf.
5. Garde-fou de performance dans la CI : assertion de latence sur le chemin chaud.

**Critères de sortie.**
- La table de vérité passe intégralement.
- Une semaine d'observation sans divergence entre décision journalisée et comportement réel.
- Daemon arrêté : les décisions continuent sur le dernier instantané.

---

## Phase 6 — Risque et confinement

**Périmètre.** `risk_level`, CONFINED automatique, STEP_UP, zone réseau confinée.

**Tâches.**
1. Calcul asynchrone de `risk_level` (`low`/`elevated`/`high`) à partir des signaux **déjà produits** : bascule LAN ↔ tunnel ↔ WAN, attestation auto-signée, bannissement `secubox-nac` ou `sbxwaf`, certificat proche expiration, ancienneté du dernier STEP_UP.
2. `high` → CONFINED automatique ; `elevated` → STEP_UP sur actions sensibles seulement, jamais sur la lecture.
3. STEP_UP = assertion WebAuthn `userVerification: required` ; fraîcheur dans `last_step_up`, propagée par l'instantané.
4. Zone CONFINED en nftables : l'IP WireGuard est restreinte au kabinet MITM et à la page de demande de certificat.
5. Réconciliation avec `secubox-nac` — un appareil banni par MAC doit être `high` côté SwitchSBX.

**Critères de sortie.**
- Un ADMIN en contexte inhabituel retombe au périmètre VISITOR sans perdre son rôle en base.
- Un STEP_UP réussi lève le confinement immédiatement.
- Le risque n'est jamais calculé dans une requête — vérifié par profilage.

---

## Récapitulatif des prérequis

| Prérequis | Bloque | Échéance |
|---|---|---|
| Domaine stable pour le `RP ID` | Phase 3 | avant tout code d'enrôlement |
| `androidx.credentials` en WebView validé | Phase 3 | début de phase 3 |
| Sort de `secubox-portal` (supprimé ou frontend seul) | Phase 1 | au plus tard fin phase 1 |
| Vérification d'attestation hors ligne (racines Google) | Phase 3 | repli auto-attesté acceptable |
