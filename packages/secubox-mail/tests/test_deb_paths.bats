#!/usr/bin/env bats
# Build the .deb and assert every lib/mail/*.sh ships under the right path.
# Phase 1 lesson: debian/rules drift silently misses files.

@test "secubox-mail .deb ships every lib/mail/*.sh helper" {
    local deb
    deb=$(ls -t "${BATS_TEST_DIRNAME}/../../"secubox-mail_*_all.deb 2>/dev/null | head -1)
    [ -n "$deb" ] || skip "no .deb built yet (run dpkg-buildpackage first)"
    local files
    files=$(dpkg-deb -c "$deb" | awk '{print $6}')
    for stub in lxc.sh install.sh migrate.sh rspamd.sh users.sh toml.sh; do
        echo "$files" | grep -qE "/usr/lib/secubox/mail/lib/${stub}\$" \
            || { echo "MISSING in deb: $stub"; return 1; }
    done
}
