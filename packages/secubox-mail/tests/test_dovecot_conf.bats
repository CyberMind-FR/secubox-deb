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
