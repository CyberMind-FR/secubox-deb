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

@test "dovecot.conf active Sieve + ManageSieve :4190 quand le plugin est présent" {
  mkdir -p "$LXC_BASE/mail/rootfs/usr/bin"
  : > "$LXC_BASE/mail/rootfs/usr/bin/sievec"
  configure_dovecot mail
  local conf="$LXC_BASE/mail/rootfs/etc/dovecot/dovecot.conf"
  grep -q 'protocols = imap pop3 lmtp sieve' "$conf"
  grep -q 'port = 4190' "$conf"
  grep -Eq 'mail_plugins.*sieve' "$conf"
  grep -q 'sieve = file:~/sieve;active=~/.dovecot.sieve' "$conf"
}

@test "dovecot.conf N'active PAS Sieve quand le plugin est absent du rootfs" {
  configure_dovecot mail
  local conf="$LXC_BASE/mail/rootfs/etc/dovecot/dovecot.conf"
  grep -q 'protocols = imap pop3 lmtp$' "$conf"
  ! grep -q 'port = 4190' "$conf"
  ! grep -Eq 'mail_plugins.*sieve' "$conf"
  ! grep -q 'service managesieve-login' "$conf"
}
