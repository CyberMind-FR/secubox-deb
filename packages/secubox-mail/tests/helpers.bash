# SecuBox-Deb :: mail :: bats shared fixtures (Phase 1).
# Sourced by tests/*.bats via `load helpers`.

load_libs() {
    local pkg_root="${BATS_TEST_DIRNAME}/.."
    # shellcheck source=/dev/null
    source "${pkg_root}/lib/mail/lxc.sh"
    # shellcheck source=/dev/null
    source "${pkg_root}/lib/mail/install.sh"
    # shellcheck source=/dev/null
    source "${pkg_root}/lib/mail/migrate.sh"
    source "${pkg_root}/lib/mail/rspamd.sh"
}

make_fake_lxc_env() {
    export LXC_BASE="$BATS_TEST_TMPDIR/lxc"
    export DATA_PATH="$BATS_TEST_TMPDIR/data-volumes-mail"
    mkdir -p "$LXC_BASE" "$DATA_PATH"
}
