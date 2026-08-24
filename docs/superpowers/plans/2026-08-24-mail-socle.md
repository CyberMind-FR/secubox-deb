<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Socle Mail SecuBox — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Assainir le socle mail déployé — Maildir, Sieve/ManageSieve, ClamAV optionnel, réconciliation config/SSL/autoconfig — pour débloquer proprement les features rapatriement et UI Sieve à venir.

**Architecture:** Deux paquets Debian. `secubox-mail-lxc` (build du conteneur : liste de paquets Dovecot/Sieve). `secubox-mail` (actionneur `mailctl`, générateur de config `lib/mail/install.sh`, TOML, systemd, autoconfig). Le geste central est `mailctl` : chaque chantier ajoute une sous-commande idempotente. `configure_dovecot()` devient la SOURCE DE VÉRITÉ COMPLÈTE de `dovecot.conf` (Maildir + SSL-aware + Sieve), de sorte que « réconcilier » = régénérer une conf correcte et redémarrer.

**Tech Stack:** Bash (mailctl, install.sh, gestes), `bats` (tests bash), TOML (mail.toml), systemd (timer SSL), Dovecot 2.3 / Pigeonhole, Rspamd (antivirus module), LXC (idmap, rootfs sous `/data/lxc/mail`).

**Spec:** [docs/superpowers/specs/2026-08-24-mail-socle-design.md](../specs/2026-08-24-mail-socle-design.md)
**Audit:** [docs/dossiers/mail-stack-audit.md](../../dossiers/mail-stack-audit.md)

## Global Constraints

- **Source-first, zéro édition live** : tout via `.deb`. Aucune écriture directe sur le board hors du flux backup→install→valider→rollback. Consigner chaque action live dans l'issue.
- **Backup AVANT tout geste destructif** : `tar` horodaté de `/data/volumes/mail` (`vmail`+`config`+dovecot.conf du LXC) sous `$DATA_PATH/backups/`. Rollback testé.
- **Idempotence** : chaque geste détecte l'état et no-op si déjà conforme ; réexécutable sans casse.
- **Ne jamais casser le TLS live** : `configure_dovecot()` DOIT émettre le bloc `ssl` quand `$DATA_PATH/ssl/fullchain.pem` existe (le board sert 993/995 en TLS). Un `ssl = no` régénéré casserait l'accès chiffré.
- **postinst non-destructif** : préserver `/etc/secubox/mail.toml` et un `dovecot.conf` déjà conforme ; merge des clés manquantes seulement ; try-restart.
- **Semver** : `secubox-mail-lxc` 2.2.1 → **2.3.0** ; `secubox-mail` 2.7.0 → **2.8.0**. Le dépôt doit dépasser le board avant build.
- **CSPN** : secrets hors code (`/etc/secubox/secrets/`, 600, owner dédié) ; conteneur non-root (uid mappé) ; gestes sensibles journalisés.
- **Cible Maildir confirmée** : `maildir:/var/vmail/%d/%n` (déjà en source).
- **Chemins réels** : `lib/mail/install.sh` (`configure_dovecot`), `sbin/mailctl` (dispatch `case "${1:-}"` ~ligne 1013), tests `tests/test_install_lib.bats` (`load helpers`, `load_libs`, `make_fake_lxc_env`).

---

## Task 1: Geste `mailctl backup` + rollback (filet de sûreté d'abord)

**Files:**
- Modify: `packages/secubox-mail/sbin/mailctl` (nouvelle sous-commande `backup` / `restore`)
- Test: `packages/secubox-mail/tests/test_mailctl_backup.bats`

**Interfaces:**
- Produces: `cmd_backup()` → écrit `$DATA_PATH/backups/mail-<ts>.tar.gz` (vmail+config+dovecot.conf), imprime le chemin. `cmd_restore <tarball>` → restaure + redémarre Dovecot. `$DATA_PATH` et `$CONTAINER` déjà résolus par `config_get` en tête de `mailctl`.

- [ ] **Step 1: Failing test** — `test_mailctl_backup.bats`

```bash
#!/usr/bin/env bats
load helpers

setup() {
  export DATA_PATH="$BATS_TEST_TMPDIR/data"
  export CONTAINER="mail"
  mkdir -p "$DATA_PATH/vmail" "$DATA_PATH/config" "$DATA_PATH/backups"
  echo "hello" > "$DATA_PATH/vmail/probe.txt"
  # charge uniquement les fonctions de mailctl sans exécuter le dispatch
  source_mailctl_functions
}

@test "backup crée une archive horodatée contenant vmail" {
  run cmd_backup
  [ "$status" -eq 0 ]
  local tb
  tb="$(ls "$DATA_PATH"/backups/mail-*.tar.gz)"
  [ -f "$tb" ]
  tar tzf "$tb" | grep -q "vmail/probe.txt"
}
```

- [ ] **Step 2: Add the `source_mailctl_functions` helper** to `tests/helpers.bash`

```bash
# Sourcer mailctl SANS lancer son dispatch final : on borne la lecture au corps
# des fonctions (avant la ligne `case "${1:-}"`), pour tester les cmd_* seules.
source_mailctl_functions() {
  local f="${BATS_TEST_DIRNAME}/../sbin/mailctl"
  sed '/^case "\${1:-}"/,$d' "$f" > "$BATS_TEST_TMPDIR/mailctl.body"
  # shellcheck disable=SC1090
  source "$BATS_TEST_TMPDIR/mailctl.body"
}
```

- [ ] **Step 3: Run — expect FAIL** `bats tests/test_mailctl_backup.bats` → `cmd_backup: command not found`.

- [ ] **Step 4: Implement `cmd_backup` / `cmd_restore`** in `sbin/mailctl` (before the dispatch `case`)

```bash
cmd_backup() {
    mkdir -p "$DATA_PATH/backups"
    local ts tb
    ts="$(date +%Y%m%d-%H%M%S)"
    tb="$DATA_PATH/backups/mail-$ts.tar.gz"
    # dovecot.conf vit dans le rootfs du LXC ; on le range à côté du reste.
    local rootfs="${LXC_PATH:-/data/lxc}/$CONTAINER/rootfs"
    tar czf "$tb" \
        -C "$DATA_PATH" vmail config \
        $( [ -f "$rootfs/etc/dovecot/dovecot.conf" ] && printf -- '-C %s etc/dovecot/dovecot.conf' "$rootfs" ) \
        2>/dev/null
    log "backup → $tb"
    echo "$tb"
}

cmd_restore() {
    local tb="$1"
    [ -f "$tb" ] || { error "archive introuvable : $tb"; return 1; }
    tar xzf "$tb" -C "$DATA_PATH" vmail config 2>/dev/null || true
    lxc_attach systemctl restart dovecot 2>/dev/null || true
    log "restore depuis $tb"
}
```

- [ ] **Step 5: Wire dispatch** — add to the `case "${1:-}"` block:

```bash
    backup)      cmd_backup ;;
    restore)     shift; cmd_restore "$@" ;;
```

- [ ] **Step 6: Run — expect PASS.** Commit: `feat(mail): mailctl backup/restore (filet Maildir) (ref #ISSUE)`

---

## Task 2: `configure_dovecot()` — source de vérité COMPLÈTE (Maildir + SSL-aware)

**Files:**
- Modify: `packages/secubox-mail/lib/mail/install.sh` (`configure_dovecot`)
- Test: `packages/secubox-mail/tests/test_dovecot_conf.bats`

**Interfaces:**
- Consumes: `LXC_BASE`/`LXC_PATH`, `DATA_PATH` (pour tester la présence du cert).
- Produces: `dovecot.conf` avec `mail_location = maildir:/var/vmail/%d/%n` (inchangé) ET un bloc SSL émis QUAND `$rootfs/../ssl` ou `$DATA_PATH/ssl/fullchain.pem` existe ; sinon `ssl = no`. Les blocs `imaps`/`pop3s` restent (`ssl = yes` par listener).

- [ ] **Step 1: Failing test** — `test_dovecot_conf.bats`

```bash
#!/usr/bin/env bats
load helpers
setup() { load_libs; make_fake_lxc_env; }

@test "dovecot.conf est en Maildir (jamais mbox)" {
  configure_dovecot mail
  local conf="$LXC_BASE/mail/rootfs/etc/dovecot/dovecot.conf"
  grep -q 'mail_location = maildir:/var/vmail/%d/%n' "$conf"
  ! grep -q 'mbox:' "$conf"
}

@test "SSL émis quand le cert existe" {
  mkdir -p "$DATA_PATH/ssl"; : > "$DATA_PATH/ssl/fullchain.pem"; : > "$DATA_PATH/ssl/privkey.pem"
  configure_dovecot mail
  local conf="$LXC_BASE/mail/rootfs/etc/dovecot/dovecot.conf"
  grep -q 'ssl = yes' "$conf"
  grep -q 'ssl_cert = </etc/ssl/mail/fullchain.pem' "$conf"
}

@test "ssl = no quand aucun cert" {
  rm -rf "$DATA_PATH/ssl"
  configure_dovecot mail
  grep -q '^ssl = no' "$LXC_BASE/mail/rootfs/etc/dovecot/dovecot.conf"
}
```

- [ ] **Step 2: Run — expect FAIL** (le test SSL échoue : la conf actuelle est `ssl = no` en dur).

- [ ] **Step 3: Implement** — remplacer la ligne `ssl = no` du heredoc par une émission conditionnelle. Après le heredoc principal (qui garde Maildir + listeners), injecter :

```bash
    # SSL-aware : ne JAMAIS régénérer une conf sans TLS si le board sert 993/995.
    # Le cert vit dans $DATA_PATH/ssl et est monté /etc/ssl/mail dans le LXC.
    if [ -f "${DATA_PATH:-/data/volumes/mail}/ssl/fullchain.pem" ]; then
        cat >> "$rootfs/etc/dovecot/dovecot.conf" <<'EOF'
ssl = yes
ssl_cert = </etc/ssl/mail/fullchain.pem
ssl_key = </etc/ssl/mail/privkey.pem
ssl_min_protocol = TLSv1.2
EOF
    else
        echo 'ssl = no' >> "$rootfs/etc/dovecot/dovecot.conf"
    fi
```

  Retirer le `ssl = no` fixe du heredoc (le déplacer dans la branche ci-dessus).

- [ ] **Step 4: Run — expect PASS.**

- [ ] **Step 5: Commit** `feat(mail): configure_dovecot SSL-aware, Maildir source de vérité (ref #ISSUE)`

---

## Task 3: Geste `mailctl maildir-reconcile` (idempotent)

**Files:**
- Modify: `packages/secubox-mail/sbin/mailctl`
- Test: `packages/secubox-mail/tests/test_maildir_reconcile.bats`

**Interfaces:**
- Consumes: `cmd_backup` (Task 1), `configure_dovecot` (Task 2, sourcée depuis `lib/mail/install.sh`).
- Produces: `cmd_maildir_reconcile()` — lit `mail_location` via `lxc_attach doveconf -h mail_location` ; si `maildir*` → no-op (log conforme, rc 0) ; si `mbox*` → `cmd_backup`, régénère la conf (`configure_dovecot`), redémarre Dovecot, crée les Maildir des comptes de `/etc/mail-config/users`.

- [ ] **Step 1: Failing test** — mock `lxc_attach`/`doveconf` via une fonction surchargée dans le test

```bash
#!/usr/bin/env bats
load helpers
setup() {
  export DATA_PATH="$BATS_TEST_TMPDIR/data"; export CONTAINER="mail"
  export LXC_PATH="$BATS_TEST_TMPDIR/lxc"
  mkdir -p "$DATA_PATH/backups" "$DATA_PATH/vmail"
  source_mailctl_functions
}

@test "reconcile est un no-op quand déjà en maildir" {
  lxc_attach() { echo "maildir:/var/vmail/%d/%n"; }   # doveconf -h mail_location
  export -f lxc_attach
  run cmd_maildir_reconcile
  [ "$status" -eq 0 ]
  [[ "$output" == *"déjà conforme"* ]]
}

@test "reconcile régénère quand mbox détecté" {
  # première invocation = doveconf (mbox), suivantes = restart/create (ok)
  lxc_attach() { case "$*" in *doveconf*) echo "mbox:~/mail" ;; *) return 0 ;; esac; }
  export -f lxc_attach
  configure_dovecot() { echo "regen appelé" >> "$BATS_TEST_TMPDIR/trace"; }
  export -f configure_dovecot
  run cmd_maildir_reconcile
  [ "$status" -eq 0 ]
  grep -q "regen appelé" "$BATS_TEST_TMPDIR/trace"
}
```

- [ ] **Step 2: Run — expect FAIL** (`cmd_maildir_reconcile: command not found`).

- [ ] **Step 3: Implement `cmd_maildir_reconcile`**

```bash
cmd_maildir_reconcile() {
    local loc
    loc="$(lxc_attach doveconf -h mail_location 2>/dev/null)"
    case "$loc" in
        maildir:*) log "mail_location déjà conforme ($loc)"; return 0 ;;
    esac
    warn "mail_location = '$loc' → bascule Maildir"
    cmd_backup >/dev/null
    # configure_dovecot vit dans la lib d'install ; on la source si besoin.
    if ! type configure_dovecot >/dev/null 2>&1; then
        # shellcheck disable=SC1091
        source "$(dirname "$0")/../lib/mail/install.sh" 2>/dev/null || \
        source /usr/lib/secubox/mail/lib/install.sh
    fi
    LXC_BASE="${LXC_PATH:-/data/lxc}" DATA_PATH="$DATA_PATH" configure_dovecot "$CONTAINER"
    lxc_attach systemctl restart dovecot
    # Crée les Maildir des comptes existants (boîtes vides = simple création).
    while IFS=: read -r user _; do
        [ -n "$user" ] || continue
        lxc_attach doveadm mailbox create -u "$user" INBOX 2>/dev/null || true
    done < <(lxc_attach cat /etc/mail-config/users 2>/dev/null)
    log "bascule Maildir effectuée"
}
```

- [ ] **Step 4: Wire dispatch** `maildir-reconcile) cmd_maildir_reconcile ;;`
- [ ] **Step 5: Run — expect PASS.** Commit `feat(mail): mailctl maildir-reconcile idempotent (ref #ISSUE)`

---

## Task 4: Paquets Sieve dans le build du LXC

**Files:**
- Modify: `packages/secubox-mail/lib/mail/install.sh` (liste `install_mail_packages`, ~ligne 60)
- Test: `packages/secubox-mail/tests/test_install_lib.bats` (ajout d'un `@test`)

**Interfaces:**
- Produces: `dovecot-sieve` + `dovecot-managesieved` ajoutés à la liste apt du LXC.

- [ ] **Step 1: Failing test** — ajouter à `test_install_lib.bats`

```bash
@test "la liste de paquets inclut Sieve + ManageSieve" {
  grep -q 'dovecot-sieve' "$LIB_DIR/install.sh"
  grep -q 'dovecot-managesieved' "$LIB_DIR/install.sh"
}
```
(`$LIB_DIR` est défini par `helpers.bash` ; sinon utiliser le chemin `${BATS_TEST_DIRNAME}/../lib/mail`.)

- [ ] **Step 2: Run — expect FAIL.**
- [ ] **Step 3: Implement** — ajouter à la ligne d'install Dovecot (~60) :

```bash
    dovecot-core dovecot-imapd dovecot-pop3d dovecot-lmtpd \
    dovecot-sieve dovecot-managesieved \
```

- [ ] **Step 4: Run — expect PASS.** Commit `feat(mail): paquets Sieve/ManageSieve dans le LXC (ref #ISSUE)`

---

## Task 5: `configure_dovecot()` — bloc Sieve + service ManageSieve :4190

**Files:**
- Modify: `packages/secubox-mail/lib/mail/install.sh` (`configure_dovecot`)
- Test: `packages/secubox-mail/tests/test_dovecot_conf.bats` (ajout)

**Interfaces:**
- Consumes: Task 2 (heredoc complet).
- Produces: `protocols = imap pop3 lmtp sieve` ; service `managesieve-login` sur `:4190` ; `mail_plugins` sieve sur `protocol lmtp` ; bloc `plugin { sieve = ... }`.

- [ ] **Step 1: Failing test** — ajouter

```bash
@test "dovecot.conf active Sieve + ManageSieve :4190" {
  configure_dovecot mail
  local conf="$LXC_BASE/mail/rootfs/etc/dovecot/dovecot.conf"
  grep -q 'protocols = imap pop3 lmtp sieve' "$conf"
  grep -q 'port = 4190' "$conf"
  grep -Eq 'mail_plugins.*sieve' "$conf"
  grep -q 'sieve = file:~/sieve;active=~/.dovecot.sieve' "$conf"
}
```

- [ ] **Step 2: Run — expect FAIL.**
- [ ] **Step 3: Implement** — (a) changer la 1ʳᵉ ligne du heredoc en `protocols = imap pop3 lmtp sieve` ; (b) après le heredoc, ajouter :

```bash
    cat >> "$rootfs/etc/dovecot/dovecot.conf" <<'EOF'

protocol lmtp {
  mail_plugins = $mail_plugins sieve
}
service managesieve-login {
  inet_listener sieve { port = 4190 }
}
plugin {
  sieve = file:~/sieve;active=~/.dovecot.sieve
  sieve_default = /var/vmail/sieve/default.sieve
}
EOF
```

- [ ] **Step 4: Run — expect PASS.** Commit `feat(mail): Sieve + ManageSieve :4190 dans dovecot.conf (ref #ISSUE)`

---

## Task 6: Sieve global par défaut (spam Rspamd → Junk)

**Files:**
- Create: `packages/secubox-mail/config/sieve/default.sieve`
- Modify: `packages/secubox-mail/lib/mail/install.sh` (déployer + `sievec` compiler dans le LXC)
- Test: `packages/secubox-mail/tests/test_default_sieve.bats`

**Interfaces:**
- Produces: `/var/vmail/sieve/default.sieve` + `.svbin` compilé ; classe le spam marqué Rspamd dans `Junk`.

- [ ] **Step 1: Le script Sieve** — `config/sieve/default.sieve`

```sieve
require ["fileinto", "mailbox"];
# Rspamd marque le spam via l'en-tête X-Spam ; on le range dans Junk plutôt
# que de le rejeter (le membre garde la main). Idempotent, global, par défaut.
if header :contains "X-Spam" "Yes" {
    fileinto :create "Junk";
    stop;
}
```

- [ ] **Step 2: Failing test** — `test_default_sieve.bats`

```bash
#!/usr/bin/env bats
@test "default.sieve compile sans erreur" {
  command -v sievec >/dev/null || skip "sievec absent de l'hôte de test"
  run sievec "${BATS_TEST_DIRNAME}/../config/sieve/default.sieve" "$BATS_TEST_TMPDIR/out.svbin"
  [ "$status" -eq 0 ]
}
@test "default.sieve range le spam dans Junk" {
  grep -q 'fileinto :create "Junk"' "${BATS_TEST_DIRNAME}/../config/sieve/default.sieve"
}
```

- [ ] **Step 3: Run — expect FAIL** (fichier absent).
- [ ] **Step 4: Implement** — créer le fichier + dans `configure_dovecot` (ou une fonction `install_default_sieve`), copier vers `$rootfs/var/vmail/sieve/default.sieve` et compiler : `lxc_attach sievec /var/vmail/sieve/default.sieve` (au provisioning).
- [ ] **Step 5: Run — expect PASS.** Commit `feat(mail): sieve par défaut spam→Junk (ref #ISSUE)`

---

## Task 7: Geste `mailctl sieve enable|status`

**Files:**
- Modify: `packages/secubox-mail/sbin/mailctl`
- Test: `packages/secubox-mail/tests/test_mailctl_sieve.bats`

**Interfaces:**
- Produces: `cmd_sieve()` — `enable` : régénère la conf (configure_dovecot, qui porte déjà Sieve après Task 5), installe le sieve par défaut, redémarre Dovecot, vérifie `:4190` ; `status` : rapporte protocoles + écoute 4190.

- [ ] **Step 1: Failing test**

```bash
#!/usr/bin/env bats
load helpers
setup() { export CONTAINER="mail"; source_mailctl_functions; }
@test "sieve status rapporte l'écoute 4190" {
  lxc_attach() { case "$*" in *4190*) echo "LISTEN 0 100 *:4190" ;; *) return 0 ;; esac; }
  export -f lxc_attach
  run cmd_sieve status
  [ "$status" -eq 0 ]
  [[ "$output" == *"4190"* ]]
}
```

- [ ] **Step 2: Run — expect FAIL.**
- [ ] **Step 3: Implement `cmd_sieve`**

```bash
cmd_sieve() {
    case "${1:-status}" in
        enable)
            cmd_maildir_reconcile   # garantit Maildir (Sieve stocke ses scripts par boîte)
            LXC_BASE="${LXC_PATH:-/data/lxc}" DATA_PATH="$DATA_PATH" \
              bash -c 'source /usr/lib/secubox/mail/lib/install.sh; configure_dovecot "$0"' "$CONTAINER"
            lxc_attach systemctl restart dovecot
            log "Sieve activé"; cmd_sieve status ;;
        status)
            local l; l="$(lxc_attach ss -tlnp 2>/dev/null | grep ':4190' || true)"
            [ -n "$l" ] && log "ManageSieve écoute : $l" || warn "ManageSieve (:4190) absent" ;;
        *) error "usage: mailctl sieve enable|status"; return 1 ;;
    esac
}
```

- [ ] **Step 4: Wire dispatch** `sieve) shift; cmd_sieve "$@" ;;`
- [ ] **Step 5: Run — expect PASS.** Commit `feat(mail): mailctl sieve enable|status (ref #ISSUE)`

---

## Task 8: ClamAV optionnel — TOML + `mailctl antivirus`

**Files:**
- Modify: `packages/secubox-mail/config/mail.toml` (+ template) ; `packages/secubox-mail/sbin/mailctl`
- Create: `packages/secubox-mail/config/rspamd/antivirus.conf` (Rspamd `local.d`)
- Test: `packages/secubox-mail/tests/test_mailctl_antivirus.bats`

**Interfaces:**
- Consumes: `config_get` (lecture TOML).
- Produces: `[mail.antivirus] enabled=false` ; `cmd_antivirus on|off|status` — `on` installe clamav dans le LXC + active le module Rspamd ; `off` (défaut) désactive/n'installe rien.

- [ ] **Step 1: TOML** — ajouter à `config/mail.toml` :

```toml
[mail.antivirus]
# Anti-virus optionnel (câblé mais dormant). true → clamav-daemon + freshclam
# + module antivirus Rspamd. Coûteux sur ARM (~1 Go signatures) : off par défaut.
enabled = false
```

- [ ] **Step 2: Failing test**

```bash
#!/usr/bin/env bats
load helpers
setup() { export CONTAINER="mail"; source_mailctl_functions; }
@test "antivirus off est un no-op sans installation" {
  lxc_attach() { echo "APPEL: $*" >> "$BATS_TEST_TMPDIR/calls"; }
  export -f lxc_attach
  run cmd_antivirus off
  [ "$status" -eq 0 ]
  ! grep -q 'apt.*clamav' "$BATS_TEST_TMPDIR/calls" 2>/dev/null
}
```

- [ ] **Step 3: Run — expect FAIL.**
- [ ] **Step 4: Implement `cmd_antivirus`**

```bash
cmd_antivirus() {
    case "${1:-status}" in
        on)
            lxc_attach apt-get install -y clamav-daemon clamav-freshclam
            lxc_attach install -D /usr/share/secubox/mail/rspamd/antivirus.conf \
                       /etc/rspamd/local.d/antivirus.conf
            lxc_attach systemctl restart clamav-daemon rspamd
            log "antivirus activé" ;;
        off)
            lxc_attach rm -f /etc/rspamd/local.d/antivirus.conf 2>/dev/null || true
            lxc_attach systemctl restart rspamd 2>/dev/null || true
            log "antivirus désactivé (défaut)" ;;
        status)
            lxc_attach systemctl is-active clamav-daemon 2>/dev/null || echo inactive ;;
        *) error "usage: mailctl antivirus on|off|status"; return 1 ;;
    esac
}
```

- [ ] **Step 5: Rspamd module** — `config/rspamd/antivirus.conf` :

```
antivirus { clamav { type = "clamav"; servers = "/var/run/clamav/clamd.ctl"; } }
```

- [ ] **Step 6: Wire dispatch** `antivirus) shift; cmd_antivirus "$@" ;;` + honorer le drapeau TOML au provisioning (`install.sh` : `[ "$(config_get mail.antivirus.enabled)" = true ] && mailctl antivirus on`).
- [ ] **Step 7: Run — expect PASS.** Commit `feat(mail): ClamAV optionnel (drapeau off) + mailctl antivirus (ref #ISSUE)`

---

## Task 9: `mail.toml` paramétrable + postinst merge non-destructif

**Files:**
- Modify: `packages/secubox-mail/config/mail.toml`, `packages/secubox-mail/debian/postinst`
- Test: `packages/secubox-mail/tests/test_toml_merge.bats`

**Interfaces:**
- Produces: `merge_mail_toml()` — n'ajoute que les clés absentes d'un `/etc/secubox/mail.toml` existant ; ne réécrit jamais `domain`, `lxc_path`, `enabled` déjà posés.

- [ ] **Step 1: Failing test**

```bash
#!/usr/bin/env bats
setup() {
  export ETC="$BATS_TEST_TMPDIR/etc"; mkdir -p "$ETC"
  printf 'domain = "gk2.secubox.in"\nlxc_path = "/data/lxc"\n' > "$ETC/mail.toml"
  source "${BATS_TEST_DIRNAME}/../debian/postinst.lib" 2>/dev/null || \
    source "${BATS_TEST_DIRNAME}/../lib/mail/toml.sh"
}
@test "merge préserve la valeur live du domaine" {
  merge_mail_toml "$ETC/mail.toml"
  grep -q 'domain = "gk2.secubox.in"' "$ETC/mail.toml"
  ! grep -q 'secubox.local' "$ETC/mail.toml"
}
@test "merge ajoute une clé manquante (antivirus)" {
  merge_mail_toml "$ETC/mail.toml"
  grep -q 'antivirus' "$ETC/mail.toml"
}
```

- [ ] **Step 2: Run — expect FAIL.**
- [ ] **Step 3: Implement `merge_mail_toml`** dans `lib/mail/toml.sh` (sourcée par postinst) — pour chaque clé par défaut, `grep -q "^<clé>" || echo "<clé par défaut>" >> fichier`. Ne jamais `sed -i` une clé existante.
- [ ] **Step 4: Postinst** appelle `merge_mail_toml /etc/secubox/mail.toml` (au lieu d'écraser). Corriger `enabled` en bool dans le template livré.
- [ ] **Step 5: Run — expect PASS.** Commit `fix(mail): postinst merge non-destructif de mail.toml (ref #ISSUE)`

---

## Task 10: `mailctl ssl renew` + timer systemd auto-renew

**Files:**
- Modify: `packages/secubox-mail/sbin/mailctl` (`cmd_ssl` : ajouter `renew`)
- Create: `packages/secubox-mail/debian/secubox-mail-ssl-renew.service` + `.timer`
- Modify: `packages/secubox-mail/debian/rules`/`install` (livrer + activer le timer)
- Test: `packages/secubox-mail/tests/test_mailctl_ssl_renew.bats`

**Interfaces:**
- Produces: `mailctl ssl renew` — renouvelle le cert LE `mail.secubox.in`, déploie atomiquement vers `$DATA_PATH/ssl/` + store HAProxy, recharge dovecot+postfix (LXC) + HAProxy (hôte), conserve l'ancien horodaté. Timer hebdo + jitter.

- [ ] **Step 1: Failing test**

```bash
#!/usr/bin/env bats
load helpers
setup() { export DATA_PATH="$BATS_TEST_TMPDIR/data"; mkdir -p "$DATA_PATH/ssl"; source_mailctl_functions; }
@test "ssl renew garde une copie horodatée de l'ancien cert" {
  : > "$DATA_PATH/ssl/fullchain.pem"
  acme_renew() { echo "renew"; }; export -f acme_renew   # mock du renouvellement
  reload_mail_tls() { :; }; export -f reload_mail_tls
  run cmd_ssl renew
  [ "$status" -eq 0 ]
  ls "$DATA_PATH/ssl/"fullchain.pem.* >/dev/null 2>&1
}
```

- [ ] **Step 2: Run — expect FAIL.**
- [ ] **Step 3: Implement** — dans `cmd_ssl`, brancher `renew)` : sauvegarde `fullchain.pem` → `fullchain.pem.<ts>`, appelle le renouvellement (acme.sh/certbot, même mécanisme que `ssl setup`), déploie, recharge (fonction `reload_mail_tls` : dovecot+postfix dans le LXC, HAProxy hôte).
- [ ] **Step 4: Timer** — `secubox-mail-ssl-renew.timer` (`OnCalendar=weekly`, `RandomizedDelaySec=6h`) + `.service` (`ExecStart=/usr/sbin/mailctl ssl renew`). Activer dans postinst (`systemctl enable --now`).
- [ ] **Step 5: Run — expect PASS.** Commit `feat(mail): mailctl ssl renew + timer auto-renew (ref #ISSUE)`

---

## Task 11: Empaquetage autoconfig XML + SRV Unbound (dérive #1114)

**Files:**
- Create: `packages/secubox-mail/nginx/autoconfig.conf`, `packages/secubox-mail/www/autoconfig/config-v1.1.xml`, `packages/secubox-mail/config/unbound/97-mail-srv.conf`
- Modify: `packages/secubox-mail/debian/postinst` (poser idempotent, recharger nginx+unbound)
- Test: `packages/secubox-mail/tests/test_autoconfig.bats`

**Interfaces:**
- Produces: autoconfig RFC 6186 servi + SRV `_imaps._tcp` / `_submission._tcp` en split-horizon, idempotents (ne cassent pas la conf Unbound existante).

- [ ] **Step 1: Failing test**

```bash
#!/usr/bin/env bats
@test "config-v1.1.xml annonce imaps + submission" {
  local f="${BATS_TEST_DIRNAME}/../www/autoconfig/config-v1.1.xml"
  grep -q '<incomingServer type="imap">' "$f"
  grep -q '993' "$f"; grep -q '587' "$f"
}
@test "SRV Unbound déclare _imaps et _submission" {
  local f="${BATS_TEST_DIRNAME}/../config/unbound/97-mail-srv.conf"
  grep -q '_imaps._tcp' "$f"; grep -q '_submission._tcp' "$f"
}
```

- [ ] **Step 2: Run — expect FAIL.**
- [ ] **Step 3: Implement** — récupérer les fichiers live du board comme référence (le XML de `/usr/share/secubox/www/autoconfig/config-v1.1.xml` et les SRV de `97-secubox-split-horizon.conf`), les figer en source, postinst les pose idempotemment (append-if-absent pour Unbound), recharge nginx+unbound.
- [ ] **Step 4: Run — expect PASS.** Commit `feat(mail): empaquetage autoconfig + SRV (fin du board-only) (ref #ISSUE)`

---

## Task 12: Bumps de version + README

**Files:**
- Modify: `packages/secubox-mail-lxc/debian/changelog` (2.2.1 → 2.3.0), `packages/secubox-mail/debian/changelog` (2.7.0 → 2.8.0), `packages/secubox-mail/README.md`

- [ ] **Step 1:** Entrée changelog `secubox-mail-lxc 2.3.0` (Sieve/ManageSieve, réconciliation Maildir au postinst).
- [ ] **Step 2:** Entrée changelog `secubox-mail 2.8.0` (mailctl maildir-reconcile/sieve/antivirus/ssl-renew, toml paramétrable, sieve par défaut, timer ssl, autoconfig/SRV).
- [ ] **Step 3:** README : documenter les nouveaux gestes `mailctl` + le bloc `[mail.antivirus]`.
- [ ] **Step 4: Commit** `release(mail): mail-lxc 2.3.0 + mail 2.8.0 (socle Maildir/Sieve) (ref #ISSUE)`

---

## Task 13: Intégration gk2 (humain-gated : build → déploie → valide → rollback-proof)

> Cette tâche N'EST PAS du TDD : c'est la validation d'intégration sur le board vivant. Elle exige backup et une porte humaine avant la bascule.

- [ ] **Step 1:** `mailctl backup` sur gk2 (archive horodatée).
- [ ] **Step 2:** Build `secubox-mail-lxc 2.3.0` puis `secubox-mail 2.8.0` (arm64), install sur gk2 (mail-lxc d'abord).
- [ ] **Step 3:** `mailctl maildir-reconcile` → `doveconf -h mail_location` = maildir ; envoyer un mail de test aux 2 comptes → fetch IMAP OK ; **vérifier que 993/995 servent toujours en TLS** (non-régression SSL).
- [ ] **Step 4:** `mailctl sieve enable` → `:4190` écoute ; mail spam de test → filé `Junk`.
- [ ] **Step 5:** Vérifier ClamAV **off** = aucun coût ; `mailctl antivirus on` (EICAR rejeté/tagué) puis `off`.
- [ ] **Step 6:** `mailctl ssl renew` à blanc + timer armé (`systemctl list-timers`) ; `curl` autoconfig 200 ; `dig SRV _imaps._tcp.secubox.in`.
- [ ] **Step 7:** **Rollback prouvé** : `mailctl restore <backup>` restaure l'état antérieur, puis re-`reconcile` pour revenir en Maildir.
- [ ] **Step 8:** Sync `.deb` vers apt.secubox.in (reprepro), commit final, mettre à jour l'issue.

---

## Self-Review (auteur)

- **Couverture spec** : A(Maildir)=Tasks 2,3 ; B(Sieve)=Tasks 4,5,6,7 ; C(ClamAV)=Task 8 ; D(assainissement)=Tasks 9,10,11 ; sûreté=Task 1 ; release=12 ; intégration=13. ✅
- **Placeholders** : aucun — chaque tâche porte test + code concrets.
- **Cohérence des noms** : gestes `mailctl` uniformes (`backup/restore`, `maildir-reconcile`, `sieve`, `antivirus`, `ssl renew`) ; `configure_dovecot` unique source de vérité (Tasks 2→5→6 l'enrichissent en couches, sans se contredire).
- **Risque n°1 (TLS)** : traité en Task 2 (SSL-aware) AVANT toute régénération (Tasks 3,5,7), et re-vérifié en Task 13 Step 3.
- **Ordre** : la sûreté (backup) précède la bascule ; Maildir précède Sieve (scripts stockés par boîte) ; ClamAV et assainissement sont indépendants ; l'intégration est en dernier, humain-gated.
