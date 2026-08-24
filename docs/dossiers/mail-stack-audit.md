<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Audit de la stack Mail SecuBox — état déployé (gk2)

**Date** : 2026-08-24 · **But** : cartographier l'existant AVANT de spécifier les
deux pièces net-new du diagramme « Mail + Sieve + Rapatriement + Clone + Relay »
(rapatriement/clone, et gestion Sieve). Sonde en lecture seule sur gk2
(192.168.1.200). Aucune modification.

---

## 1. Topologie déployée (3 LXC + hôte)

| Élément | Adresse | État | Rôle |
|---------|---------|------|------|
| LXC `mail` | 10.100.0.10 | **RUNNING** (autostart) | MTA/MDA : Postfix 3.7.11 + Dovecot 2.3.19.1 + Rspamd |
| LXC `roundcube` | 10.100.0.12 | **RUNNING** (autostart) | Webmail Roundcube |
| LXC `horde` | — | **STOPPED** (no autostart) | Webmail Horde (dormant / scale-to-zero) |
| Hôte HAProxy | — | live | TLS 1.3 frontal : `webmail.gk2`, `rspamd.gk2`, `mail.maegia.tv` |
| Hôte Unbound | — | live | split-horizon `97-secubox-split-horizon.conf` (SRV autoconfig) |
| Hôte nginx | — | live | `autoconfig/config-v1.1.xml` (Thunderbird/RFC 6186) |

**Paquets** (source == board, aucune dérive de version) :
`secubox-mail 2.7.0`, `secubox-mail-lxc 2.2.1`, `secubox-webmail 2.2.0`,
`secubox-webmail-lxc 2.2.0`. `secubox-smtp-relay 1.1.0` existe en source mais
**n'est PAS installé** — le relais sortant est le Postfix du LXC mail (587/465).

---

## 2. Le diagramme vs la réalité

| Boîte du diagramme | Réalité déployée | Verdict |
|--------------------|------------------|---------|
| 3.1 Réception SMTP — Postfix | Postfix 3.7.11, submission 587 + smtps 465 | ✅ **existe** |
| 3.2 Stockage — Dovecot IMAP/POP3 | Dovecot 2.3.19, imaps 993 / pop3s 995 / imap 143 / pop3 110 | ✅ **existe** |
| 3.1 Anti-spam — Rspamd | Rspamd actif, greylist, bayes autolearn, ratelimit 200/h/user | ✅ **existe** |
| 3.1 Anti-virus — ClamAV | **inactive** (`clamav-daemon` = inactive) | ⚠️ **inactif** |
| DKIM/SPF/DMARC | Rspamd `dkim_signing` configuré (local.d) | ✅ **existe** (via Rspamd, pas OpenDKIM) |
| 3.3 Filtrage SIEVE / Pigeonhole | `mail_plugins` VIDE, `protocols = imap lmtp pop3` (pas `sieve`), **pas de :4190**, 0 script `.sieve` | ❌ **absent** |
| 4. Boîte clone locale | — | ❌ **absent** |
| 2. Rapatriement (IMPORT/MIRROR/MIGRATION) | `fetchmail`/`getmail`/`imapsync`/`mbsync` absents du LXC | ❌ **absent (greenfield)** |
| 5. Relay / sortie SMTP | Postfix submission 587/465 (SASL + TLS) | ✅ **existe** (pas via secubox-smtp-relay) |
| 6. Accès — IMAP/POP3/SMTP/Webmail | 993/995/587/465/143/110 + Roundcube + autoconfig | ✅ **existe** |

**Deux boîtes « présentes » sur le diagramme sont en fait vides** : Filtrage
SIEVE et Anti-virus ClamAV. Les traiter comme acquises fausserait les specs.

---

## 3. Stockage & comptes — le point dur

- **Format = mbox** : `mail_location = mbox:~/mail:INBOX=/var/mail/%u`.
  **Ce n'est PAS du Maildir.** Conséquences directes pour le rapatriement :
  - mbox verrouille tout le fichier par écriture → concurrence IMAP médiocre,
    destination hostile à `imapsync` (un import massif y est lent et risqué).
  - Pas de fichier-par-message → pas de dédup/reprise fine, pas de flags fiables.
  - **Recommandation** : toute boîte destinataire d'un rapatriement doit être en
    **Maildir**. Migration mbox→Maildir à cadrer AVANT ou DANS le spec rapatriement.
- **Base d'auth** : passdb flat file `scheme=SHA512-CRYPT /etc/mail-config/users`.
  userdb `auth-userdb` (socket). Nombre de comptes provisionnés **non confirmé**
  (la sonde a rendu 0 — soit fichier vide, soit chemin différent ; à lever).
- **Domaines virtuels** : `virtual_mailbox_domains = secubox.in gk2.secubox.in`.
  `mail.maegia.tv` apparaît côté HAProxy mais **pas** en domaine mailbox local —
  à clarifier (alias ? relais ? multi-tenant à venir ?).

---

## 4. Accès, transport, provisioning client

- **Ports (LXC mail)** : 993 imaps, 995 pop3s, 587 submission, 465 smtps,
  143 imap, 110 pop3. **Pas de 4190 (ManageSieve)**.
- **TLS** : cert Let's Encrypt `mail.secubox.in` posé (session #1114 :
  `/data/volumes/mail/ssl/`, + store HAProxy). Renouvellement auto : `mailctl
  ssl setup` reste à câbler (noté comme dette).
- **Autoconfig** : `config-v1.1.xml` (RFC 6186 / Thunderbird) servi par nginx
  hôte ; SRV `_imaps/_submission` dans Unbound split-horizon + autorité Gandi
  (session #1114). Dérive live à empaqueter.

---

## 5. Filtrage — Rspamd oui, Sieve non

- **Rspamd** : greylist, bayes autolearn, ratelimit sortant, DKIM signing,
  whitelist SPF/DKIM. UI `rspamd.gk2.secubox.in`. C'est le moteur anti-spam +
  signature. Solide.
- **Sieve/Pigeonhole** : **inactif**. Activer la gestion de règles par
  utilisateur (le « 3.3 » du diagramme) exige d'abord :
  1. installer `dovecot-sieve` + `dovecot-managesieved` dans le LXC ;
  2. `protocols = ... sieve` + `mail_plugins = ... sieve` ;
  3. service ManageSieve (:4190) + route d'accès (client / webmail) ;
  4. seulement ensuite : éditeur de règles (fileinto/addflag/redirect/vacation).
  → « gestion Sieve » n'est donc pas « juste une UI » : c'est activation + UI.

---

## 6. Dérive de configuration (board vs source)

| Clé | Source (`config/mail.toml`) | Board (`/etc/secubox/mail.toml`) |
|-----|------------------------------|----------------------------------|
| `domain` | `secubox.local` | `gk2.secubox.in` |
| `lxc_path` | `/var/lib/lxc` | `/data/lxc` |
| `enabled` | `true` (bool) | `"true"` (string) |

Dérive de config uniquement (pas de code). À réconcilier quand un spec mail
touchera le paquet — sinon un `apt` réinstall pourrait réécrire ces valeurs.

---

## 7. Implications pour les deux specs net-new

### A. Rapatriement + boîte clone (greenfield)
- **Pré-requis dur** : Maildir (§3). Sans quoi l'import est fragile.
- **Briques à choisir** : moteur de sync (`imapsync` one-shot vs `mbsync`/isync
  pour miroir continu), vault creds externes chiffré (OAuth2 Gmail/Outlook +
  mot de passe app), ordonnanceur (timers systemd), machine à états des 4 modes
  (IMPORT/MIRROR/MIGRATION/RELAY), API + UI d'état, journalisation 4R.
- **Intégration** : la boîte clone = boîte locale Dovecot normale → héritera
  Rspamd/DKIM et (plus tard) Sieve. Le RELAY sortant existe déjà (587/465).
- **Sécurité/légal** : creds tiers = secrets (`/etc/secubox/secrets/`, 600,
  owner dédié). OAuth2 préféré au mot de passe. Jamais de recopie de contenu
  protégé hors du périmètre du propriétaire du compte.

### B. Gestion Sieve (active d'abord, puis UI)
- Activation Pigeonhole + ManageSieve (§5) AVANT toute UI de règles.
- Indépendant du rapatriement ; améliore l'existant seul.

### Séquencement recommandé
1. **(court) Réconciliation + activations** : Maildir, ClamAV (décider on/off),
   Sieve/ManageSieve, dérive config, `mailctl ssl setup`. Assainit le socle.
2. **Rapatriement + clone** : le gros morceau, sur socle Maildir.
3. **Gestion Sieve (UI)** : sur Pigeonhole activé.

---

## 8. Questions ouvertes à lever avec l'utilisateur
1. Nombre réel de comptes/boîtes en service (sonde = 0) et où (`/etc/mail-config/users` ?).
2. `mail.maegia.tv` : alias, relais, ou premier signe de multi-tenant ?
3. ClamAV : on l'active (anti-virus réel) ou on l'assume abandonné (le retirer du récit) ?
4. Rapatriement — mode PRIMAIRE visé (IMPORT ponctuel ? MIRROR continu ? MIGRATION avec bascule MX ?) : ça dimensionne le moteur.
5. Fournisseurs sources visés en premier (Gmail OAuth2 ? OVH/IMAP+mdp ? Outlook/Graph ?).
