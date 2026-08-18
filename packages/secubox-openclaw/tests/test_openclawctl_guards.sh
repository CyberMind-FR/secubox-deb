#!/bin/bash
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

# Exercises openclawctl's injection guards via the hidden __guard entrypoint.
set -u
CTL="$(dirname "$0")/../sbin/openclawctl"
fail=0
ok()  { "$CTL" __guard "$1" "$2" >/dev/null 2>&1 && echo "PASS accept $1 '$2'" || { echo "FAIL should-accept $1 '$2'"; fail=1; }; }
no()  { "$CTL" __guard "$1" "$2" >/dev/null 2>&1 && { echo "FAIL should-reject $1 '$2'"; fail=1; } || echo "PASS reject $1 '$2'"; }
ok target "example.com";        ok target "192.168.1.10"; ok target "10.0.0.0/24"; ok target "a@b.com"
no target 'a;rm -rf /';         no target 'a b';          no target "$(printf 'a\nb')"
no target '-f/etc/hostname';    no target '-iL/tmp/x'
# NB: 'a@-f/etc/hostname' PASSES _valid_target as a whole (email-shaped, starts
# alphanumeric). The flag-injection defense for the email arm is cmd_scan
# re-validating the post-@ segment ('-f/etc/hostname') with _valid_target
# before it reaches the container. Whole-string check below documents this:
ok target 'a@-f/etc/hostname';  no target "${_email_dom:=-f/etc/hostname}"
ok scanid "a1b2c3d4";           no scanid "XYZ";          no scanid "a1b2c3d4e5"
ok type domain; ok type ip; ok type email; ok type dns; ok type whois; ok type certs; ok type ports; no type pwn
exit $fail
