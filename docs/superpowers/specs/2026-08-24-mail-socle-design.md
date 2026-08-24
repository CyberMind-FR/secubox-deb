<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Spec — Socle Mail SecuBox (assainissement)

**Statut** : design validé (brainstorming), prêt pour plan d'implémentation.
**Audit source** : [docs/dossiers/mail-stack-audit.md](../../dossiers/mail-stack-audit.md)
**Date** : 2026-08-24

## Objectif

Assainir le socle de la stack mail déployée pour qu'il corresponde à son
diagramme d'architecture et débloque proprement les deux features net-new à
venir (rapatriement/clone, UI Sieve). Quatre chantiers : **Maildir**,
**Sieve/ManageSieve**, **ClamAV optionnel**, **réconciliation/assainissement**.

## Hors périmètre (specs séparés, plus tard)

- **Rapatriement + boîte clone** (import/mirror/migration depuis Gmail/Outlook/OVH).
- **UI de gestion des règles Sieve** (éditeur par utilisateur). Ce spec ACTIVE
  Pigeonhole/ManageSieve ; il ne livre PAS d'éditeur.

## Contexte vérifié (état board gk2, 2026-08-24)

- **Topologie** : LXC `mail` (10.100.0.10, Postfix 3.7.11 + Dovecot 2.3.19.1 +
  Rspamd), `roundcube` (10.100.0.12), `horde` (STOPPED). Volume persistant
  `/data/volumes/mail` (mappé `/var/*` dans le LXC via idmap ; `vmail` = uid 105000).
- **Comptes** : 2 seulement — `gk2@secubox.in`, `mastodon@secubox.in` —
  **boîtes vides** (`/var/mail` = 4K, aucun mbox, aucun `~/mail`). → aucune
  donnée de courrier à migrer.
- **DÉRIVE CRITIQUE** : la source `secubox-mail/lib/mail/install.sh`
  `configure_dovecot()` écrit déjà `mail_location = maildir:/var/vmail/%d/%n` et
  `protocols = imap pop3 lmtp`. **Mais le board tourne
  `mail_location = mbox:~/mail:INBOX=/var/mail/%u`** — un dovecot.conf hérité,
  jamais ré-appliqué. Le socle Maildir est donc une **réconciliation de dérive**,
  pas une migration de données.
- **Sieve** : `mail_plugins` vide, pas de protocole `sieve`, pas de `:4190`. Absent.
- **ClamAV** : `clamav-daemon` inactif. **DKIM** : ✅ Rspamd `dkim_signing`.
- **Versions** : `secubox-mail 2.7.0`, `secubox-mail-lxc 2.2.1`,
  `secubox-webmail 2.2.0` — source == board (dérive de config uniquement).
- **Actionneur** : `secubox-mail/sbin/mailctl` (déjà : components, access,
  dns-setup, user-repair, ssl-status via `$DATA_PATH/ssl/fullchain.pem`). Point
  d'extension naturel pour les nouveaux gestes.

## Contraintes globales (Global Constraints)

- **Source-first, aucune édition live** : tout passe par le paquet (`.deb`),
  jamais de `scp`/édition sur le board. Chaque action live consignée dans l'issue.
- **Backup avant tout geste destructif** : `tar` de `/data/volumes/mail` (au
  moins `vmail` + `config` + dovecot.conf) horodaté sous `$DATA_PATH/backups/`
  AVANT toute bascule. Rollback documenté et testé.
- **Idempotence** : chaque geste (`configure_dovecot`, activation Sieve, flag
  antivirus) réexécutable sans casser un état déjà correct.
- **postinst préserve l'état runtime** : ne PAS clobber `/etc/secubox/mail.toml`
  ni le dovecot.conf du LXC si déjà corrects ; try-restart, pas restart aveugle.
- **Semver** : `secubox-mail-lxc` 2.2.1 → **2.3.0** (Maildir+Sieve+antivirus) ;
  `secubox-mail` 2.7.0 → **2.8.0** (toml paramétrable + mailctl ssl + autoconfig).
  Le dépôt doit dépasser le board avant build.
- **TDD** où le code le permet (libs bash via `bats`, api Python via `pytest`) ;
  activations config validées en intégration sur gk2 (backup→staged→valider→rollback).
- **CSPN** : secrets hors code (`/etc/secubox/secrets/`, 600, owner dédié) ;
  journalisation des gestes sensibles ; séparation de privilèges (le LXC tourne
  déjà non-root, uid mappé).

---

## Chantier A — Bascule Maildir (réconciliation de dérive)

**Constat** : source déjà en Maildir, board dérivé en mbox, boîtes vides.

**Design** :
1. Nouveau geste `mailctl maildir-reconcile` (idempotent) :
   - Sauvegarde le dovecot.conf courant du LXC + `tar` `vmail` sous `backups/`.
   - Détecte le `mail_location` courant (`doveconf -h mail_location`).
   - Si `mbox*` : ré-applique la config Maildir de `configure_dovecot`
     (`maildir:/var/vmail/%d/%n`), crée les `Maildir` des comptes existants
     (`doveadm mailbox create` / structure vide), redémarre Dovecot.
   - Si déjà `maildir*` : no-op (log « déjà conforme »).
   - **Filet** : si un mbox NON vide est détecté (futur), convertir par
     `dsync`/`doveadm` avant bascule au lieu de créer une boîte vide.
2. `configure_dovecot()` reste la source de vérité ; `postinst`/upgrade
   l'applique via `mailctl maildir-reconcile` **sans** écraser un état déjà Maildir.

**Fichiers** : `secubox-mail/sbin/mailctl` (geste), `secubox-mail/lib/mail/install.sh`
(`configure_dovecot` inchangé, appelé par le geste), `secubox-mail-lxc/debian/postinst`
(appel idempotent au geste sur upgrade).

**Validation** : `doveconf -h mail_location` = `maildir:/var/vmail/%d/%n` ;
mail de test livré → `~/Maildir/new/…` présent ; IMAP fetch OK pour les 2 comptes.
**Rollback** : restaurer dovecot.conf + `vmail` depuis le backup, redémarrer Dovecot.

---

## Chantier B — Activation Sieve / ManageSieve

**Design** :
1. Paquets LXC : `dovecot-sieve` + `dovecot-managesieved` (ajoutés à la liste
   d'install du LXC, cf. `install.sh` ligne ~60).
2. `configure_dovecot()` étendu :
   - `protocols = imap pop3 lmtp sieve`
   - `mail_plugins = $mail_plugins sieve` (sur le service lmtp/lda)
   - bloc `protocol sieve { }` + `service managesieve-login { inet_listener sieve { port = 4190 } }`
   - `plugin { sieve = file:~/sieve;active=~/.dovecot.sieve }`
3. **Sieve global par défaut** (`/var/vmail/sieve/default.sieve` +
   `sieve_default`) : range le spam marqué par Rspamd (`X-Spam` /
   `X-Spamd-Result`) dans `Junk`. Compilé (`sievec`) à l'install.
4. Geste `mailctl sieve enable|status` (idempotent) : installe paquets, applique
   la config, compile le sieve par défaut, redémarre Dovecot, ouvre `:4190`.
5. **Accès `:4190`** : exposé sur l'IP LXC pour le futur consommateur (UI). Pas
   de route publique dans ce spec ; ManageSieve reste LAN/LXC. (Le spec UI
   décidera de l'exposition.)

**Fichiers** : `secubox-mail/lib/mail/install.sh` (liste paquets + configure_dovecot),
`secubox-mail/sbin/mailctl` (geste `sieve`), `secubox-mail-lxc` (build du LXC),
nouveau `secubox-mail/config/sieve/default.sieve`.

**Validation** : `ss -tlnp | grep 4190` dans le LXC ; `doveconf protocols` inclut
`sieve` ; login ManageSieve (`doveadm sieve` / test client) ; mail spam de test →
filé dans `Junk`. **Tests** : `bats` sur la fonction de génération de config
(assert protocols/plugins/port présents).

---

## Chantier C — ClamAV optionnel (drapeau off par défaut)

**Design** :
1. TOML : nouveau bloc
   ```toml
   [mail.antivirus]
   enabled = false        # true → clamav-daemon + freshclam + Rspamd antivirus
   ```
2. Geste `mailctl antivirus on|off|status` :
   - `on` : installe `clamav-daemon` + `clamav-freshclam` dans le LXC, active le
     module Rspamd `antivirus` pointant le socket clamav
     (`/var/run/clamav/clamd.ctl`), `freshclam` initial, redémarre rspamd.
   - `off` (défaut) : n'installe rien / désactive le module Rspamd antivirus.
   - Idempotent, honore le drapeau TOML au provisioning.
3. `install.sh`/`postinst` : lit le drapeau ; off par défaut → aucun coût.

**Fichiers** : `secubox-mail/config/mail.toml` (bloc), `secubox-mail/sbin/mailctl`
(geste `antivirus`), `secubox-mail/lib/mail/install.sh` (branchement conditionnel),
Rspamd `local.d/antivirus.conf` (livré, activé par le geste).

**Validation** : off → `clamav-daemon` absent/inactif, pas de coût ; on →
`freshclam` a des signatures, Rspamd `antivirus` actif, EICAR de test rejeté/tagué.

---

## Chantier D — Assainissement (dérive config + SSL + autoconfig)

**Design** :
1. **Dérive `mail.toml`** : template paramétrable — `domain` déduit du board (pas
   `secubox.local` en dur), `enabled` en **bool** (pas `"true"`), `lxc_path`
   configurable. `postinst` **préserve** un `/etc/secubox/mail.toml` existant
   (merge des clés manquantes seulement, jamais d'écrasement des valeurs live).
2. **`mailctl ssl setup|renew`** : geste + **timer systemd**
   (`secubox-mail-ssl-renew.timer`, hebdo + jitter) qui renouvelle le cert LE
   `mail.secubox.in` via acme.sh/certbot, le déploie vers `$DATA_PATH/ssl/`
   (fullchain+privkey) **et** le store HAProxy, puis recharge dovecot+postfix
   (dans le LXC) et HAProxy (hôte). Rollback : conserver l'ancien cert horodaté.
3. **Empaquetage dérive #1114** : livrer dans le paquet ce qui n'existe qu'en live —
   `autoconfig/config-v1.1.xml` (nginx hôte, RFC 6186) et les enregistrements
   SRV `_imaps/_submission` (Unbound split-horizon `97-secubox-split-horizon.conf`).
   Idempotent, ne casse pas la conf Unbound existante.

**Fichiers** : `secubox-mail/config/mail.toml` + template, `secubox-mail/debian/postinst`
(merge non-destructif), `secubox-mail/sbin/mailctl` (`ssl setup|renew`),
`secubox-mail/debian/` (timer+service systemd), `secubox-mail/nginx/` (autoconfig
vhost), `secubox-mail/config/unbound/` (SRV split-horizon).

**Validation** : réinstall `apt` ne change pas `domain=gk2.secubox.in` ;
`systemctl list-timers | grep mail-ssl` présent ; `curl` autoconfig 200 ;
`dig SRV _imaps._tcp.secubox.in @unbound` répond.

---

## Décomposition en paquets & versions

| Paquet | De → Vers | Porte |
|--------|-----------|-------|
| `secubox-mail-lxc` | 2.2.1 → **2.3.0** | build LXC : dovecot-sieve/managesieved, appel réconciliation Maildir au postinst |
| `secubox-mail` | 2.7.0 → **2.8.0** | `mailctl` (maildir-reconcile, sieve, antivirus, ssl), toml paramétrable, sieve par défaut, timer ssl, autoconfig/SRV |

## Plan de test (ordre de sûreté sur gk2)

1. **Backup** `/data/volumes/mail` (vmail+config+dovecot.conf) horodaté.
2. Build + install `secubox-mail-lxc 2.3.0` puis `secubox-mail 2.8.0`.
3. `mailctl maildir-reconcile` → valider Maildir + fetch IMAP des 2 comptes.
4. `mailctl sieve enable` → valider `:4190` + spam→Junk.
5. Vérifier ClamAV **off** = aucun coût ; test ponctuel `mailctl antivirus on` puis `off`.
6. `mailctl ssl renew` à blanc + timer armé ; autoconfig/SRV répondent.
7. Rollback répété une fois pour prouver le filet.
8. Sync apt, commit changelog.

## Risques & parades

| Risque | Parade |
|--------|--------|
| Bascule Maildir casse l'accès des 2 comptes | Boîtes vides + backup + rollback testé ; `doveadm` crée les Maildir |
| Ré-appliquer configure_dovecot clobbe une conf live correcte | Geste idempotent : détecte l'état, no-op si conforme |
| Activation Sieve perturbe la remise LMTP | Staged ; valider remise normale AVANT d'ajouter le sieve par défaut |
| Timer SSL déploie un cert cassé | Déploiement atomique + garde l'ancien horodaté + reload seulement si validé |
| `postinst` écrase la dérive board voulue | Merge non-destructif (clés manquantes uniquement) |

## Questions résiduelles (à confirmer, non bloquantes)

1. `mail.maegia.tv` (présent en HAProxy, absent des domaines mailbox) : alias,
   relais, ou amorce multi-tenant ? — n'affecte pas ce spec, à cadrer au rapatriement.
2. Layout Maildir : `maildir:/var/vmail/%d/%n` (source) confirmé comme cible.
