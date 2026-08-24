#!/usr/bin/env bats
# SecuBox-Deb :: mail :: merge_mail_toml non-destructif (#1169 task 9)

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

@test "merge préserve lxc_path" {
  merge_mail_toml "$ETC/mail.toml"
  grep -q 'lxc_path = "/data/lxc"' "$ETC/mail.toml"
  ! grep -q '/var/lib/lxc' "$ETC/mail.toml"
}

@test "merge est idempotent (2e passage n'ajoute rien de plus)" {
  merge_mail_toml "$ETC/mail.toml"
  cp "$ETC/mail.toml" "$BATS_TEST_TMPDIR/after-first.toml"
  merge_mail_toml "$ETC/mail.toml"
  diff "$BATS_TEST_TMPDIR/after-first.toml" "$ETC/mail.toml"
}
