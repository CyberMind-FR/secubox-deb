<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# SwitchSBX — moteur de confiance appareil/utilisateur — Design

**Date :** 2026-07-31 · **Statut :** design validé, prêt pour plan d'implémentation
**Amende :** `2026-07-30-companion-qr-and-wireguard-design.md` (§1 QR pairing — voir §12)

---

## 0. Résumé

SwitchSBX répond à une question que SecuBox ne sait pas poser aujourd'hui : *à qui,
sur quel appareil, dans quel contexte, accorde-t-on quoi ?* Le système actuel réduit
cela à un booléen `authenticated`. SwitchSBX le remplace par une **décision** —
rôle, périmètre, obligations — calculée à partir de preuves indépendantes.

Trois choix structurent le design :

- **L'appareil devient un objet de première classe**, ancré dans une clé matérielle
  (WebAuthn/TEE), et joint les quatre espaces de noms aujourd'hui disjoints du projet.
- **Deux barrières humaines** — un admin admet l'appareil, un admin confirme la
  promotion — chacune tracée. Le confort vient du parrainage, pas du relâchement.
- **La performance prime** : le chemin chaud ne fait aucune E/S, aucun IPC, aucun
  calcul. Tout le reste est repoussé hors requête.

---

## 1. Constat — l'état du code au 2026-07-31

`grep -ri switchsbx` sur le dépôt ne retourne rien : le module n'existe pas. Ce que
l'analyse a établi, en revanche, dépasse le simple « pas encore fait ».

### 1.1 Ce qui manque structurellement

Il n'existe **aucun objet « appareil »**. Les identifiants vivent dans quatre espaces
de noms qui ne se joignent jamais : un peer WireGuard est une chaîne, un client NAC
est une MAC, un utilisateur est un `username`, une session est un `jti`.

Il n'existe **aucune infrastructure de certificat client**. La recherche
`ssl_client|crt-list|ca-file|verify required|mtls` sur tout le dépôt est vide.
`secubox-certs` gère du TLS **serveur** (certbot), pas de l'identité client.

Le **« pairing » du Compagnon n'en est pas un** : c'est un login mot de passe dont le
token est scellé localement sous un PIN ([`auth.js:44`](../../../secubox-companion/www/core/auth.js),
[`store.js:49`](../../../secubox-companion/www/core/store.js)). Aucune clé d'appareil,
aucun enregistrement côté box. Une session Compagnon est indiscernable d'un `curl`.

### 1.2 Failles actives à corriger en préalable

Ces quatre points ne sont pas des écarts vis-à-vis de la cible : ce sont des
vulnérabilités du code en production. Elles conditionnent l'ordre du plan (§10).

**(A) Les jetons de scope sont acceptés comme jetons d'accès complets.**
`_validate_token()` ne lit jamais le claim `scope`
([`auth.py:128-143`](../../../common/secubox_core/auth.py)). Le seul garde-fou est
`_session_validator`, dont le **défaut est permissif** (`lambda jti: True`,
[`auth.py:32`](../../../common/secubox_core/auth.py)) et que **seul** `secubox-auth`
remplace ([`main.py:220`](../../../packages/secubox-auth/api/main.py)). L'agrégateur
monte **113 modules dans un seul interpréteur**, et `auth` en fait partie : son
`set_session_validator()` protège donc tout ce processus. Restent **44 modules routés
par nginx vers leur socket dédiée**, qui gardent le défaut permissif.
Conséquences sur ces 44 modules :

- Le `mfa_token`, émis *avant* vérification TOTP
  ([`main.py:303`](../../../packages/secubox-auth/api/main.py)), y ouvre un accès
  complet pendant 300 s — **contournement du 2FA avec le seul mot de passe**.
- Le `setup_token`, émis contre un mot de passe **vide** dès que
  `must_change_password` est vrai ([`main.py:288-291`](../../../packages/secubox-auth/api/main.py)),
  y ouvre 15 minutes d'accès complet — **sans aucun mot de passe**.
- La révocation (logout, `revoke_session`, changement de mot de passe) y est
  **sans effet** : ces processus ne lisent jamais `sessions.json`.

**(B) `secubox-certs` n'a aucune authentification.** Le module importe `Depends` mais
n'appelle `require_jwt` nulle part. `POST /issue`
([`main.py:464`](../../../packages/secubox-certs/api/main.py)) et
`DELETE /revoke/{domain}` ([`main.py:595`](../../../packages/secubox-certs/api/main.py))
sont ouverts. Le fichier nginx du paquet n'ajoute aucun `auth_request`, et le snippet
proxy commun applique `Access-Control-Allow-Origin: *` — donc atteignable en
cross-origin depuis n'importe quel site visité sur le LAN. *Vérifié au niveau paquet ;
l'existence d'un garde compensatoire en production sur gk2 n'a pas été contrôlée.*

**(C) `secubox-portal` est une seconde pile d'authentification concurrente.** Elle
pointe sur le même `/etc/secubox/users.json`
([`main.py:52`](../../../packages/secubox-portal/api/main.py)) dans un **format
incompatible** (dict plat vs schéma v2) : toute écriture écrase le magasin canonique
et rétrograde argon2 → **SHA-256 non salé**. Elle crée un compte `admin` / mot de
passe `secubox` par défaut si le fichier manque
([`main.py:166-176`](../../../packages/secubox-portal/api/main.py)), et signe ses
jetons avec le **même secret partagé**, avec un `jti` — donc acceptés par les 44
modules au validateur permissif.

**(D) Le rôle n'est pas dans le token.** Le JWT ne porte que `sub`/`iat`/`exp`/`jti`.
Sur ~112 fichiers utilisant `require_jwt`, **4** vérifient un rôle. En pratique, tout
compte authentifié dispose des pouvoirs admin sur presque tous les modules. **Le mode
USER par défaut n'est donc pas sûr aujourd'hui.**

### 1.3 Un défaut de performance sur le chemin chaud

`_validate_token()` appelle `user_store.is_enabled()`
([`auth.py:141`](../../../common/secubox_core/auth.py)), qui exécute
`json.loads(USERS_PATH.read_text())` ([`user_store.py:32`](../../../common/secubox_core/user_store.py))
**sans aucun cache**. Chaque requête authentifiée, dans l'agrégateur comme dans chacun
des 44 processus dédiés, relit
et reparse intégralement `/etc/secubox/users.json`. Coût non mesuré à ce jour ; à
chiffrer en phase 0.

---

## 2. Modèle de rôles

Quatre états, un drapeau.

```text
[QR imprimé]        PENDING     identité créée, appareil inerte
  → admission    →  VISITOR     kabinet MITM + demande de certificat, rien d'autre
  → promotion    →  USER        vhosts applicatifs, pinless
                    ADMIN       administration

CONFINED = drapeau porté par la décision, jamais un rôle stocké
```

**CONFINED n'est pas un rôle.** Un ADMIN confiné reste ADMIN dans le registre ; sa
décision effective porte `role: ADMIN, confined: true`, ce qui ramène son périmètre à
celui du VISITOR jusqu'au STEP_UP. On ne perd jamais l'information « qui est cette
personne » en la dégradant, et le retour est trivial.

Les rôles `SERVICE` et `DEVICE` évoqués initialement sont **abandonnés** : aucun
besoin identifié, et un rôle non utilisé est un rôle mal testé.

### 2.1 Le périmètre VISITOR

Volontairement minimal, car il sert à **deux** rôles (visiteur et confiné) :

- navigation web via le **kabinet MITM du toolbox** (le bénéfice offert avant
  authentification) ;
- la page de demande de certificat utilisateur ;
- rien d'autre. **Pas de catalogue de services** : un appareil non promu n'apprend
  rien de ce que la box héberge.

### 2.2 Les deux barrières

| Transition | Qui décide | Trace |
|---|---|---|
| PENDING → VISITOR (QR imprimé) | un ADMIN | `admitted_by` |
| — → VISITOR (QR parrainé) | un USER authentifié, parrainage direct | `admitted_by` = parrain |
| VISITOR → USER | un ADMIN, après authentification de la personne | `promoted_by` |

Le parrainage n'ouvre que le périmètre à faible enjeu. **La promotion USER, qui donne
accès aux vhosts, reste dans tous les cas une décision admin.**

---

## 3. Modèle de données

```text
Device
  device_id          dérivé du credential_id WebAuthn
  credential_id      identifiant WebAuthn (RP ID = domaine stable de la box)
  cose_key           clé publique COSE ; la privée ne quitte jamais le TEE
  attestation        hardware | self-attested   → plafonne le niveau de confiance
  cert_fingerprint   certificat client courant ; nul tant que PENDING
  state              PENDING | VISITOR | USER | ADMIN
  owner              username ; non nul dès VISITOR (WebAuthn lie box × utilisateur)
  wg_peer            clé publique WireGuard associée, si tunnel
  nac_mac            adresse MAC côté secubox-nac, si vue sur le LAN
  risk_level         low | elevated | high   (précalculé par le daemon)
  last_step_up       horodatage de la dernière assertion à vérification utilisateur
  trust_since / admitted_by / promoted_by / policy_version
```

`Device` est de fait **`Device × User`** : WebAuthn crée un credential par couple
(box, utilisateur), donc un téléphone familial partagé entre deux comptes produit
naturellement deux entrées. Aucune modélisation supplémentaire n'est nécessaire.

**Deux magasins.** Le daemon détient l'autorité dans une base **SQLite**
(`/var/lib/secubox/switchsbx/registry.db`) — cohérent avec la préférence SQLite du
projet et adapté à la file d'admission. La bibliothèque lit un **instantané JSON**
(`snapshot.json` : appareils actifs, empreintes révoquées, politique) produit par le
daemon et surveillé par `inotify`. Aucun processus consommateur n'ouvre SQLite : pas de
contention de verrous.

L'instantané suit le **double-buffer 4R** imposé par le projet (`active/`, `shadow/`,
`rollback/R1..R4`) : une politique qui verrouillerait tout le monde dehors se restaure
en une commande.

---

## 4. Enrôlement — deux transports, une machine à états

### 4.1 QR imprimé — démarrage à froid

Le QR collé sur le boîtier porte l'URL d'enrôlement (domaine stable = RP ID),
l'identifiant de la box, et un secret d'enrôlement propre à la box, **rotatable
depuis la webui**. Il confère le droit de *demander*, rien d'autre.

Il ne contient **pas** de configuration WireGuard : un voisin qui photographie
l'étiquette ne doit pas obtenir le tunnel. Le tunnel vient après l'admission.

Cérémonie :

1. Scan → le Compagnon ouvre l'URL d'enrôlement.
2. `navigator.credentials.create()` (ou `androidx.credentials` en natif) → clé générée
   **dans le TEE**, attestation collectée.
3. `POST /switchsbx/enroll` {secret du QR, clé publique COSE, attestation} → le daemon
   crée un `Device` en **PENDING**. L'appareil n'obtient qu'une page « en attente ».
4. L'admin voit la demande dans sa webui, **avec l'attestation** — il sait donc si la
   clé est matérielle ou simulée. Il admet → **VISITOR**. Tunnel WireGuard et kabinet
   MITM s'ouvrent.
5. Le visiteur demande son certificat, s'authentifie avec son compte, l'admin
   confirme → **USER**.

Le débit d'enrôlement est limité par box (anti-flood) et chaque tentative est
journalisée.

### 4.2 QR parrainé — confort entre appareils

Conforme au spec du 2026-07-30 : un Compagnon déjà authentifié demande un jeton
d'appairage court à usage unique et l'affiche en QR (encodeur JS embarqué, **emoji au
centre**, aucun CDN). L'appareil neuf le scanne, exécute les mêmes étapes 2-3, et
passe **directement en VISITOR** avec le parrain journalisé comme `admitted_by`.

La promotion USER reste soumise à confirmation admin.

### 4.3 Pourquoi WebAuthn et pas un coffre chiffré

Le coffre actuel du Compagnon dérive une clé AES-GCM d'un PIN par PBKDF2-SHA256,
150 000 itérations ([`store.js:49`](../../../secubox-companion/www/core/store.js)).
Avec un PIN à 4 chiffres, un attaquant détenant le blob teste 10 000 candidats —
ordre de grandeur : quelques milliards de compressions SHA-256, soit une durée
négligeable sur GPU. **Le coffre ne protège de rien contre qui a extrait le fichier**,
et remplacer AES par OpenPGP au même endroit ne changerait rien : GPG est un format,
pas une frontière matérielle.

Ce qui rend une clé inviolable, c'est qu'elle **ne soit jamais un fichier**. WebAuthn
couvre les trois cibles avec une seule API : Android Keystore/StrongBox (APK), Secure
Enclave (PWA iOS), TPM/Hello/Touch ID (desktop). Et il résout quatre points du design
d'un coup : `device_key_proof_valid` devient une preuve vérifiable ; le **pinless**
cesse d'être un abus de langage (biométrie, clé jamais exposée) ; « non exportable »
devient vrai ; le **STEP_UP** a un geste concret (`userVerification: required`).

Limites assumées : sur un appareil rooté et déjà compromis, l'attaquant ne vole pas la
clé mais peut s'en servir tant qu'il tient l'appareil — c'est ce que l'attestation et
le confinement automatique servent à contenir.

---

## 5. PKI

**CA dédiée** dans `/etc/secubox/switchsbx/ca/`, clé 0600 propriété du daemon.
**Jamais la CA MITM** (`ca-wg`) : celle-là est distribuée à tous les clients ; la
réutiliser reviendrait à donner le pouvoir de forger des identités à quiconque la vole.

**Liaison certificat ↔ appareil** : le hash de la CSR est signé comme challenge
WebAuthn. La box vérifie que la CSR émane bien du détenteur du credential.
`certificate_bound_to_device` devient vérifiable, pas déclaratif.

**TTL 24 h, renouvellement en tâche de fond à mi-vie (~12 h).** Le renouvellement
exige une assertion WebAuthn : tant que l'appareil est sain, il est invisible — c'est
cela, le pinless. Dès que la clé matérielle ne peut plus signer, le certificat expire
et l'appareil retombe en VISITOR. L'expiration devient un mécanisme de sûreté. Un
appareil actif ne rencontre jamais l'expiration ; seul celui resté plusieurs jours
inutilisé redemande une biométrie au réveil.

**Deux niveaux de preuve d'appareil**, parce que le mTLS depuis une PWA mobile est
pénible (iOS et Android gèrent mal les certificats client en WebView) :

| Cible | Preuve | Application |
|---|---|---|
| APK natif, navigateur desktop | **mTLS** | HAProxy tranche au bord |
| PWA / iOS | WebAuthn + session liée au credential | bibliothèque |

Les deux valent `device_key_proof_valid` ; le mTLS pèse davantage dans le niveau de
confiance.

---

## 6. Architecture d'exécution — taillée pour la latence

**Approche retenue : hybride bibliothèque + daemon.** La bibliothèque tranche seule
tout ce qui est vérifiable localement. Le daemon ne détient que ce qui exige un état
central. Un daemon sur le chemin de chaque requête reproduirait le SPOF que le projet
a déjà payé cher avec l'agrégateur.

**Règle unique : le chemin chaud ne fait aucune E/S, aucun IPC, aucun calcul.**

| Étage | Fréquence | Où |
|---|---|---|
| Validation du certificat client | 1× par **connexion** TLS | HAProxy, en C |
| Vérification JWT (HS256) | par requête | bibliothèque, en mémoire |
| Recherche appareil → rôle + périmètre | par requête | dict en mémoire |
| Contrôle du périmètre | par requête | comparaison d'ensembles |
| Scoring de risque | asynchrone | daemon |
| Assertion WebAuthn | enrôlement, renouvellement, STEP_UP | client |

Le **mTLS est l'option la plus rapide** : HAProxy valide le certificat pendant la
poignée de main — une fois par connexion, pas par requête — et transmet l'empreinte en
en-tête. Avec le keep-alive, des dizaines de requêtes partagent une validation. Côté
application, la preuve se réduit à lire un en-tête.

Le **risque est précalculé** : le daemon écrit `risk_level` par appareil dans
l'instantané, la bibliothèque le lit comme un champ. C'est le pattern double-cache
déjà imposé par le projet aux dashboards, appliqué à la décision d'accès.

L'**instantané est parsé une fois**, au démarrage, rechargé uniquement sur événement
`inotify`. Le même traitement s'applique à `users.json`, ce qui corrige au passage le
défaut §1.3 pour tous les modules.

**Dégradation :**

- daemon arrêté ⇒ les décisions continuent sur le dernier instantané ; seules les
  admissions, promotions et révocations sont gelées ;
- instantané illisible ⇒ **fail-closed** sur le périmètre VISITOR, jamais ouverture.
  C'est l'inverse exact du défaut actuel `lambda jti: True`.

**Points d'application** : `require_jwt` (API), cible `auth_request` de nginx (vhosts),
sbxwaf (routage), nftables (confinement réseau). Aucun nouveau saut réseau.

---

## 7. Risque, CONFINED, STEP_UP

**Trois niveaux discrets** — `low` / `elevated` / `high` — et non un score continu : un
seuil numérique est indémontrable devant un évaluateur CSPN, trois états se testent
exhaustivement.

Signaux, tous **déjà produits par le dépôt**, sans nouveau capteur :

- changement de contexte réseau (bascule LAN ↔ tunnel ↔ WAN, nouveau préfixe source)
- attestation `self-attested` au lieu de `hardware`
- appareil banni ou dézoné côté `secubox-nac`, IP bannie par `sbxwaf`
- certificat proche de l'expiration, ou renouvellement échoué
- ancienneté du dernier STEP_UP

**Mapping :** `high` déclenche le CONFINED automatique. `elevated` n'exige un STEP_UP
que sur les actions sensibles — pas sur la lecture, sinon le mécanisme devient une
nuisance qu'on finira par désactiver.

**STEP_UP = assertion WebAuthn avec `userVerification: required`.** Exigé pour : lever
un confinement, promouvoir un rôle, admettre un appareil, faire tourner un secret,
ajouter un peer WireGuard. Sa fraîcheur vit dans `last_step_up` côté daemon et transite
par l'instantané — la bibliothèque compare deux horodatages, on évite de réémettre un
JWT à chaque élévation.

---

## 8. Hors périmètre

Exclusions explicites, pour que le plan ne dérive pas :

- rôles `SERVICE` / `DEVICE`
- score de risque continu, apprentissage automatique
- fédération de confiance entre boxes du mesh (le mesh existe ; c'est un autre projet)
- OCSP / CRL — avec un TTL de 24 h et une liste de révocations dans l'instantané, une
  infrastructure de révocation en ligne ne s'achète rien
- remplacement du JWT — on l'augmente, pas de big bang
- carte OpenPGP pour la promotion ADMIN — piste crédible, pas un engagement. GPG garde
  une place légitime en **récupération** (sauvegarde chiffrée du registre), pas comme
  coffre d'appareil.

---

## 9. Stratégie de test

**Le cœur est une table de vérité** preuves → décision : fonction pure, sans E/S, donc
exhaustive et instantanée.

| Preuves | Décision attendue |
|---|---|
| cert valide + lié + risk low + USER | ALLOW, périmètre USER |
| cert valide + lié + risk high + ADMIN | ALLOW, `confined: true`, périmètre VISITOR |
| cert valide + risk elevated + action sensible | STEP_UP |
| cert expiré ou renouvellement échoué | périmètre VISITOR |
| empreinte révoquée | DENY |
| appareil PENDING | DENY sauf page d'attente |
| instantané illisible | périmètre VISITOR (fail-closed) |

**Quatre tests de non-régression** figent les failles §1.2 — ils doivent **échouer sur
le code d'aujourd'hui** : jeton de scope accepté comme accès complet ; validateur de
session permissif par défaut ; API `secubox-certs` sans authentification ; écriture de
`secubox-portal` sur `users.json`.

**Test de dégradation :** daemon tué ⇒ décisions maintenues ; instantané corrompu ⇒
VISITOR, jamais ouverture.

**Garde-fou de performance :** assertion de latence sur le chemin chaud dans la CI, pour
qu'une régression casse le build au lieu de se découvrir en production.

Environnement : `.venv` du dépôt, exécution **par répertoire** (collision de
`pytest.ini`). Les tests CSPN vont dans `tests/cspn/`.

---

## 10. Plan de migration

Séquencé pour que **la valeur de sécurité arrive avant l'architecture**. Les phases 0
et 1 sont indépendantes de SwitchSBX et peuvent partir immédiatement.

**Phase 0 — Colmatage.** Rejet des jetons porteurs d'un `scope` dans
`_validate_token()` ; `require_jwt` gagne un paramètre `scope` explicite. Validateur
de session par défaut → `False` (*fail-closed*) + **magasin de sessions partagé**
fourni par `secubox_core`, pour que les 44 modules dédiés valident et révoquent réellement.
Ce magasin réutilise le mécanisme d'instantané de la §6 — `sessions.json` écrit par
`secubox-auth`, lu une fois et rechargé sur `inotify` par chaque module — plutôt qu'un
appel IPC par requête. Il préfigure ainsi l'instantané SwitchSBX de la phase 2.
`require_jwt` sur toute l'API `secubox-certs`. Neutralisation de la pile d'auth de
`secubox-portal` (au minimum : interdiction d'écrire dans `users.json`). `limit_req`
sur `/api/v1/auth/login` + verrouillage par compte. Mise en cache de `users.json`
(§1.3), avec mesure avant/après.

**Phase 1 — Rôle dans le token.** Ajout de `role` et `policy_version` au JWT,
`require_role()` dans `secubox_core`, application par lots en commençant par les
modules à pouvoir root.

**Phase 2 — Registre et daemon.** `secubox-switchsbx` : SQLite, instantané JSON,
`inotify`, double-buffer 4R. Aucune décision n'en dépend encore — on constitue la
donnée.

**Phase 3 — Enrôlement.** WebAuthn côté Compagnon (plugin natif `androidx.credentials`
pour l'APK, API web pour la PWA), QR imprimé et QR parrainé, file d'admission dans la
webui admin, transition PENDING → VISITOR.

**Phase 4 — PKI.** CA SwitchSBX, émission liée au credential, mTLS optionnel sur
HAProxy, promotion VISITOR → USER.

**Phase 5 — Moteur de décision.** Branché d'abord en **mode observation** — il
journalise ce qu'il *aurait* décidé sans appliquer. Indispensable pour ne pas se
verrouiller hors de la box. Puis application progressive, périmètre VISITOR d'abord.

**Phase 6 — Risque et confinement.** `risk_level`, CONFINED automatique, STEP_UP, zone
réseau confinée en nftables.

---

## 11. Prérequis et décisions différées

**Prérequis bloquant : un domaine stable pour la box.** WebAuthn exige un `RP ID`
fixe ; un changement de domaine invalide tous les credentials. Cela touche directement
le problème connu du domaine Hub canonique et doit être tranché **avant la phase 3**.

**Attestation hors ligne.** Vérifier une attestation Android suppose d'embarquer les
racines Google et de gérer la révocation. Repli prévu : accepter le mode
`self-attested`, admis mais à confiance plafonnée — ce qui s'intègre naturellement
puisque l'admission reste manuelle.

**WebAuthn en WebView Capacitor** demande un `assetlinks.json` et une origine
correctement liée. Le chemin robuste est le plugin natif plutôt que l'API web dans la
WebView ; à valider en début de phase 3.

**Sort de `secubox-portal`.** La phase 0 neutralise sa pile d'auth. Reste à décider
s'il est supprimé ou réduit à un frontend sans logique d'authentification — décision
attendue au plus tard en phase 1.

---

## 12. Relation avec le spec du 2026-07-30

`2026-07-30-companion-qr-and-wireguard-design.md` §1 décrit un QR d'appairage émis par
un Compagnon authentifié, dont la redemption donnait immédiatement un device token.

Ce spec **le conserve comme second transport d'invitation** (§4.2), avec ses décisions
de rendu (encodeur JS embarqué, emoji central, aucun CDN) et son exigence de
journalisation CSPN. Le parrainage vaut admission : l'appareil scanné passe directement
en VISITOR.

Deux amendements :

1. Le jeton d'appairage ne confère plus qu'un périmètre **VISITOR** (kabinet MITM), et
   non un accès applicatif. La promotion USER reste une décision admin.
2. L'appareil doit générer un credential WebAuthn matériel pendant la cérémonie ; le
   jeton d'appairage seul ne suffit plus à créer une identité d'appareil.

Le §2 du spec du 2026-07-30 (tunnel WireGuard, delegate puis embed) est **inchangé** —
SwitchSBX consomme le tunnel, il ne le redéfinit pas.
