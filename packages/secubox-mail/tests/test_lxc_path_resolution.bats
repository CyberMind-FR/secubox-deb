#!/usr/bin/env bats
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Régression #1169 : LXC_PATH DOIT venir du TOML (lxc_path), pas d'une valeur
# héritée par les libs sourcées. users.sh pose LXC_PATH="/data/lxc/mailserver"
# (ancien nom de conteneur) ; sans résolution TOML, les gestes qui écrivent dans
# le rootfs visent /data/lxc/mailserver/mail/rootfs au lieu de /data/lxc/mail/rootfs
# et deviennent des no-op silencieux (bug remonté à la bascule board réelle).
load helpers

setup() {
  export CONFIG_FILE="$BATS_TEST_TMPDIR/mail.toml"
  printf 'domain = "gk2.secubox.in"\nlxc_path = "/data/lxc"\ncontainer = "mail"\n' > "$CONFIG_FILE"
}

@test "LXC_PATH est résolu depuis le TOML, écrasant une valeur héritée" {
  # simule la fuite de users.sh
  export LXC_PATH="/data/lxc/mailserver"
  source_mailctl_functions
  [ "$LXC_PATH" = "/data/lxc" ]
}

@test "rootfs visé = /data/lxc/mail/rootfs (pas mailserver)" {
  export LXC_PATH="/data/lxc/mailserver"
  source_mailctl_functions
  # ce que maildir-reconcile passera à configure_dovecot
  local base="${LXC_PATH:-/data/lxc}"
  [ "$base/$CONTAINER/rootfs" = "/data/lxc/mail/rootfs" ]
}

@test "défaut /var/lib/lxc quand le TOML n'a pas lxc_path" {
  printf 'domain = "x"\ncontainer = "mail"\n' > "$CONFIG_FILE"
  unset LXC_PATH
  source_mailctl_functions
  [ "$LXC_PATH" = "/var/lib/lxc" ]
}
