#!/usr/bin/env bats
# #1178 : Rspamd câblé en milter → X-Spam-Status, consommé par le sieve par défaut.
@test "milter_headers émet x-spam-status" {
  grep -q 'x-spam-status' "${BATS_TEST_DIRNAME}/../templates/rspamd/local.d/milter_headers.conf"
}
@test "default.sieve matche X-Spam-Status (ce que Rspamd émet)" {
  grep -q 'X-Spam-Status' "${BATS_TEST_DIRNAME}/../config/sieve/default.sieve"
  grep -q 'fileinto :create "Junk"' "${BATS_TEST_DIRNAME}/../config/sieve/default.sieve"
}
@test "mailctl dispatche le sous-geste rspamd milter" {
  grep -q 'milter)' "${BATS_TEST_DIRNAME}/../sbin/mailctl"
  grep -q 'smtpd_milters=inet:127.0.0.1:11332' "${BATS_TEST_DIRNAME}/../sbin/mailctl"
}
