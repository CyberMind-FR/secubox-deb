#!/usr/bin/env bats
load helpers
setup() { load_libs; make_fake_lxc_env; }

@test "rspamd.sh sources cleanly" {
    [ "$(type -t install_rspamd)" = "function" ]
    [ "$(type -t configure_rspamd_milter)" = "function" ]
    [ "$(type -t configure_rspamd_controller)" = "function" ]
    [ "$(type -t configure_rspamd_dkim)" = "function" ]
    [ "$(type -t configure_rspamd_postfix_milter)" = "function" ]
    [ "$(type -t rspamd_keygen)" = "function" ]
    [ "$(type -t rspamd_dns_records)" = "function" ]
    [ "$(type -t rspamd_purge_legacy)" = "function" ]
}
