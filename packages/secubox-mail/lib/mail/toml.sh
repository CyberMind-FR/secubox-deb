#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

# SecuBox-Deb :: mail :: postinst-safe, non-destructive mail.toml merge.
# Sourced library — do not execute directly.
#
# merge_mail_toml() appends default keys/sections that are missing from an
# existing /etc/secubox/mail.toml — it NEVER rewrites a key that is already
# present (no `sed -i`, no truncation). A live `domain = "gk2.secubox.in"`
# or `lxc_path = "/data/lxc"` set by the operator survives a package upgrade
# untouched, even though the shipped template still defaults to
# `secubox.local` / `/var/lib/lxc` for fresh installs.

# Return 0 if root-level `key = ` is present anywhere in the file *before*
# any `[mail.<subsection>]` header (i.e. in the implicit root / [mail]
# table). Files with no section headers at all (as produced by early
# installs, or by test fixtures) are entirely "root". This keeps the root
# `enabled` distinct from `[mail.antivirus].enabled` / `[mail.rspamd]`
# keys, which share the same key name in a different section.
_toml_root_has_key() {
    local file="$1" key="$2"
    awk -v key="$key" '
        /^\[mail\./ { exit }
        $0 ~ "^" key " *=" { found=1; exit }
        END { exit !found }
    ' "$file"
}

# Return 0 if `[section]` (e.g. "mail.antivirus") exists in the file.
_toml_has_section() {
    local file="$1" section="$2"
    grep -q "^\[${section}\]" "$file" 2>/dev/null
}

# Append `key = default` to the file iff no root-level key of that name
# already exists. Never touches an existing line.
_toml_add_root_key() {
    local file="$1" key="$2" default="$3"
    _toml_root_has_key "$file" "$key" || echo "${key} = ${default}" >> "$file"
}

# Append a whole `[section]` block iff that section header is entirely
# absent. Existing sections (and their keys) are left untouched — this
# never edits an already-present section, it only ever adds a missing one.
_toml_add_section_if_missing() {
    local file="$1" section="$2"
    shift 2
    if ! _toml_has_section "$file" "$section"; then
        {
            echo ''
            echo "[${section}]"
            local line
            for line in "$@"; do
                echo "$line"
            done
        } >> "$file"
    fi
}

# merge_mail_toml <path>: non-destructive merge of the package's default
# keys/sections into an existing mail.toml. Only ever appends what is
# absent; idempotent (a second run adds nothing new).
merge_mail_toml() {
    local toml="$1"
    [ -f "$toml" ] || return 1

    # Root [mail] keys.
    _toml_add_root_key "$toml" "enabled"      "true"
    _toml_add_root_key "$toml" "domain"       '"secubox.local"'
    _toml_add_root_key "$toml" "hostname"     '"mail"'
    _toml_add_root_key "$toml" "container"    '"mail"'
    _toml_add_root_key "$toml" "lxc_ip"       '"10.100.0.10"'
    _toml_add_root_key "$toml" "lxc_bridge"   '"br-lxc"'
    _toml_add_root_key "$toml" "lxc_gateway"  '"10.100.0.1"'
    _toml_add_root_key "$toml" "lxc_path"     '"/var/lib/lxc"'
    _toml_add_root_key "$toml" "data_path"    '"/data/volumes/mail"'
    _toml_add_root_key "$toml" "webmail_url"  '"https://webmail.gk2.secubox.in"'
    _toml_add_root_key "$toml" "horde_url"    '"https://horde.gk2.secubox.in"'
    _toml_add_root_key "$toml" "ssl_provider" '"acme"'
    _toml_add_root_key "$toml" "acme_email"   '""'

    # Sub-sections — added as whole blocks only if entirely absent, so an
    # existing section (with operator-edited keys inside) is never touched.
    _toml_add_section_if_missing "$toml" "mail.rspamd" \
        'greylist = true' \
        'bayes_autolearn = true' \
        'ratelimit_outbound = "200/h/user"' \
        'web_ui = true' \
        'web_ui_host = "rspamd.gk2.secubox.in"'

    _toml_add_section_if_missing "$toml" "mail.antivirus" \
        'enabled = false'
}
